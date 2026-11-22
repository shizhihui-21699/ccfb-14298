<?php
/**
 * TypeWatch Parser — recursive descent producing array AST nodes.
 * Every node: ['kind' => ..., 'line' => n, ...].
 * Covers the practical PHP subset needed for security analysis.
 */
final class Parser {
    private array $toks;
    private int $pos = 0;

    public function __construct(array $tokens) { $this->toks = $tokens; }

    public static function parseCode(string $code): array {
        return (new self(Lexer::tokenize($code)))->parseProgram();
    }

    // ---------- token helpers ----------
    private function peek(int $off = 0): array { return $this->toks[$this->pos + $off] ?? ['type' => Lexer::EOF, 'value' => null, 'line' => ($this->toks[count($this->toks)-1] ?? ['line'=>1])['line']]; }
    private function next(): array { $t = $this->peek(); if ($t['type'] !== Lexer::EOF) $this->pos++; return $t; }
    private function is(string $type): bool { return $this->peek()['type'] === $type; }
    private function isAny(array $types): bool { return in_array($this->peek()['type'], $types, true); }
    private function expect(string $type): array {
        $t = $this->peek();
        if ($t['type'] !== $type) {
            throw new \RuntimeException("Parse error: expected {$type}, got {$t['type']} ('{$t['value']}') at line {$t['line']}");
        }
        return $this->next();
    }
    private function skipSemicolon(): void {
        if ($this->is(';')) { $this->next(); }
        elseif ($this->is('}')) { /* allowed */ }
        elseif ($this->is(Lexer::EOF) || $this->is('T_CLOSE_TAG')) { /* allowed */ }
        else { $this->recover(); }
    }
    private function recover(): void {
        while (!$this->isAny([';', '}', Lexer::EOF, 'T_CLOSE_TAG'])) $this->next();
        if ($this->is(';')) $this->next();
    }

    // Skip optional type declarations in params / properties.
    private function skipType(): void {
        if ($this->is('?')) $this->next();
        if ($this->isAny(['T_ARRAY', 'T_CALLABLE', 'T_STRING', 'T_STATIC', 'T_SELF', 'T_PARENT'])) {
            $this->next();
            while ($this->isAny(['T_NS_SEPARATOR', 'T_STRING'])) $this->next();
            if ($this->is('T_NS_SEPARATOR')) $this->next();
        }
    }

    // ---------- program / statements ----------
    public function parseProgram(): array {
        $stmts = [];
        while (!$this->is(Lexer::EOF)) {
            if ($this->is('T_CLOSE_TAG')) { $this->next(); continue; }
            if ($this->is('T_OPEN_TAG')) { $this->next(); continue; }
            $before = $this->pos;
            try {
                $s = $this->parseStatement();
                if ($s !== null) $stmts[] = $s;
            } catch (\Throwable $e) {
                $stmts[] = ['kind' => 'parseerror', 'line' => $this->peek()['line'], 'msg' => $e->getMessage()];
                $this->recover();
            }
            if ($this->pos === $before) $this->next(); // hard guarantee of progress
        }
        return ['kind' => 'program', 'stmts' => $stmts, 'line' => 1];
    }

    private function parseStatement(): ?array {
        $t = $this->peek();
        switch ($t['type']) {
            case ';': $this->next(); return null;
            case '{': return $this->parseBlock();
            case 'T_IF': return $this->parseIf();
            case 'T_WHILE': return $this->parseWhile(false);
            case 'T_DO': return $this->parseWhile(true);
            case 'T_FOR': return $this->parseFor();
            case 'T_FOREACH': return $this->parseForeach();
            case 'T_SWITCH': return $this->parseSwitch();
            case 'T_TRY': return $this->parseTry();
            case 'T_RETURN':
                $this->next();
                $expr = $this->isAny([';', '}']) ? null : $this->parseExpression();
                $this->skipSemicolon();
                return ['kind' => 'return', 'expr' => $expr, 'line' => $t['line']];
            case 'T_ECHO':
                $this->next();
                $exprs = [$this->parseExpression()];
                while ($this->is(',')) { $this->next(); $exprs[] = $this->parseExpression(); }
                $this->skipSemicolon();
                return ['kind' => 'echo', 'exprs' => $exprs, 'line' => $t['line']];
            case 'T_BREAK': case 'T_CONTINUE':
                $this->next();
                $depth = 1;
                if ($this->is('T_LNUMBER')) { $depth = (int)$this->next()['value']; }
                $this->skipSemicolon();
                return ['kind' => strtolower(substr($t['type'], 2)), 'depth' => $depth, 'line' => $t['line']];
            case 'T_THROW':
                $this->next();
                $expr = $this->parseExpression();
                $this->skipSemicolon();
                return ['kind' => 'throw', 'expr' => $expr, 'line' => $t['line']];
            case 'T_GLOBAL':
                $this->next();
                $vars = [];
                do { if ($this->is('T_VARIABLE')) $vars[] = $this->next()['value']; } while ($this->is(',') && $this->next());
                $this->skipSemicolon();
                return ['kind' => 'global', 'vars' => $vars, 'line' => $t['line']];
            case 'T_STATIC':
                if ($this->peek(1)['type'] === 'T_FUNCTION') return $this->parseClosure(true);
                $this->next();
                $vars = [];
                do {
                    if ($this->is('T_VARIABLE')) {
                        $name = $this->next()['value'];
                        $default = null;
                        if ($this->is('=')) { $this->next(); $default = $this->parseExpression(); }
                        $vars[] = ['name' => $name, 'default' => $default];
                    }
                } while ($this->is(',') && $this->next());
                $this->skipSemicolon();
                return ['kind' => 'static', 'vars' => $vars, 'line' => $t['line']];
            case 'T_UNSET':
                $this->next(); $this->expect('(');
                $exprs = [];
                if (!$this->is(')')) {
                    do { $exprs[] = $this->parseExpression(); } while ($this->is(',') && $this->next());
                }
                $this->expect(')'); $this->skipSemicolon();
                return ['kind' => 'unset', 'exprs' => $exprs, 'line' => $t['line']];
            case 'T_FUNCTION':
                if ($this->peek(1)['type'] === 'T_STRING') return $this->parseFunction();
                return $this->parseClosure(false);
            case 'T_CLASS': case 'T_TRAIT': case 'T_INTERFACE': case 'T_ENUM':
                return $this->parseClass();
            case 'T_ABSTRACT': case 'T_FINAL': case 'T_READONLY':
                $this->next();
                return $this->parseClass();
            case 'T_NAMESPACE':
                $this->next();
                while (!$this->isAny([';', '{', Lexer::EOF])) $this->next();
                if ($this->isAny([';', '{'])) $this->next();
                if ($t['type'] === 'T_NAMESPACE' && $this->wasBrace()) { /* bracketed ns: skip to matching } handled loosely */ }
                return null;
            case 'T_USE': case 'T_DECLARE':
                $this->next();
                if ($t['type'] === 'T_DECLARE' && $this->is('(')) {
                    $d = 1; $this->next();
                    while ($d > 0 && !$this->is(Lexer::EOF)) { if ($this->is('(')) $d++; elseif ($this->is(')')) $d--; $this->next(); }
                }
                while (!$this->isAny([';', '{', Lexer::EOF])) $this->next();
                if ($this->isAny([';', '{'])) $this->next();
                return null;
            case 'T_CONST':
                $this->next();
                while (!$this->isAny([';', Lexer::EOF])) $this->next();
                $this->skipSemicolon();
                return null;
            case 'T_GOTO':
                $this->next(); $this->next(); $this->skipSemicolon(); return null;
            default:
                if ($t['type'] === 'T_STRING' && $this->peek(1)['type'] === ':') {
                    $this->next(); $this->next(); return null; // label
                }
                $expr = $this->parseExpression();
                $this->skipSemicolon();
                return ['kind' => 'expr', 'expr' => $expr, 'line' => $t['line']];
        }
    }

    private function wasBrace(): bool { return false; }

    private function parseBlock(): array {
        $line = $this->expect('{')['line'];
        $stmts = [];
        while (!$this->isAny(['}', Lexer::EOF])) {
            try { $s = $this->parseStatement(); if ($s !== null) $stmts[] = $s; }
            catch (\Throwable $e) { $stmts[] = ['kind'=>'parseerror','line'=>$this->peek()['line'],'msg'=>$e->getMessage()]; $this->recover(); }
        }
        $this->expect('}');
        return ['kind' => 'block', 'stmts' => $stmts, 'line' => $line];
    }

    private function parseIf(): array {
        $t = $this->next(); // T_IF
        $this->expect('(');
        $cond = $this->parseExpression();
        $this->expect(')');
        $body = $this->is('{') ? $this->parseBlock() : $this->parseStatement();
        $elseifs = [];
        $else = null;
        while ($this->is('T_ELSEIF')) {
            $this->next(); $this->expect('(');
            $c = $this->parseExpression();
            $this->expect(')');
            $b = $this->is('{') ? $this->parseBlock() : $this->parseStatement();
            $elseifs[] = ['cond' => $c, 'body' => $b];
        }
        if ($this->is('T_ELSE')) {
            $this->next();
            $else = $this->is('{') ? $this->parseBlock() : $this->parseStatement();
        }
        return ['kind' => 'if', 'cond' => $cond, 'body' => $body, 'elseifs' => $elseifs, 'else' => $else, 'line' => $t['line']];
    }

    private function parseWhile(bool $do): array {
        $t = $this->next();
        if ($do) {
            $body = $this->is('{') ? $this->parseBlock() : $this->parseStatement();
            $this->expect('T_WHILE'); $this->expect('(');
            $cond = $this->parseExpression();
            $this->expect(')'); $this->skipSemicolon();
            return ['kind' => 'while', 'do' => true, 'cond' => $cond, 'body' => $body, 'line' => $t['line']];
        }
        $this->expect('(');
        $cond = $this->parseExpression();
        $this->expect(')');
        $body = $this->is('{') ? $this->parseBlock() : $this->parseStatement();
        return ['kind' => 'while', 'do' => false, 'cond' => $cond, 'body' => $body, 'line' => $t['line']];
    }

    private function parseFor(): array {
        $t = $this->next();
        $this->expect('(');
        $init = []; $cond = []; $update = [];
        if (!$this->is(';')) { do { $init[] = $this->parseExpression(); } while ($this->is(',') && $this->next()); }
        $this->expect(';');
        if (!$this->is(';')) { do { $cond[] = $this->parseExpression(); } while ($this->is(',') && $this->next()); }
        $this->expect(';');
        if (!$this->is(')')) { do { $update[] = $this->parseExpression(); } while ($this->is(',') && $this->next()); }
        $this->expect(')');
        $body = $this->is('{') ? $this->parseBlock() : $this->parseStatement();
        return ['kind' => 'for', 'init' => $init, 'cond' => $cond, 'update' => $update, 'body' => $body, 'line' => $t['line']];
    }

    private function parseForeach(): array {
        $t = $this->next();
        $this->expect('(');
        $expr = $this->parseExpression();
        $this->expect('T_AS');
        $key = null; $byRef = false;
        if ($this->is('T_VARIABLE') && $this->peek(1)['type'] === 'T_DOUBLE_ARROW') {
            $key = ['kind' => 'variable', 'name' => $this->next()['value'], 'line' => $t['line']];
            $this->next(); // =>
        }
        if ($this->is('&')) { $byRef = true; $this->next(); }
        $value = $this->parseExpression();
        $this->expect(')');
        $body = $this->is('{') ? $this->parseBlock() : $this->parseStatement();
        return ['kind' => 'foreach', 'expr' => $expr, 'key' => $key, 'value' => $value, 'byRef' => $byRef, 'body' => $body, 'line' => $t['line']];
    }

    private function parseSwitch(): array {
        $t = $this->next();
        $this->expect('(');
        $expr = $this->parseExpression();
        $this->expect(')');
        $this->expect('{');
        $cases = [];
        while (!$this->isAny(['}', Lexer::EOF])) {
            if ($this->is('T_CASE')) {
                $this->next();
                $cond = $this->parseExpression();
                $this->expect(':');
                $stmts = [];
                while (!$this->isAny(['T_CASE', 'T_DEFAULT', '}', Lexer::EOF])) {
                    $s = $this->parseStatement();
                    if ($s !== null) $stmts[] = $s;
                }
                $cases[] = ['cond' => $cond, 'stmts' => $stmts, 'line' => $t['line']];
            } elseif ($this->is('T_DEFAULT')) {
                $this->next(); $this->expect(':');
                $stmts = [];
                while (!$this->isAny(['T_CASE', 'T_DEFAULT', '}', Lexer::EOF])) {
                    $s = $this->parseStatement();
                    if ($s !== null) $stmts[] = $s;
                }
                $cases[] = ['cond' => null, 'stmts' => $stmts, 'line' => $t['line']];
            } else {
                $this->next();
            }
        }
        $this->expect('}');
        return ['kind' => 'switch', 'expr' => $expr, 'cases' => $cases, 'line' => $t['line']];
    }

    private function parseTry(): array {
        $t = $this->next();
        $body = $this->parseBlock();
        $catches = [];
        while ($this->is('T_CATCH')) {
            $this->next(); $this->expect('(');
            $types = [];
            do {
                if ($this->isAny(['T_STRING', 'T_NS_SEPARATOR'])) $types[] = $this->next()['value'];
                while ($this->isAny(['T_NS_SEPARATOR', 'T_STRING'])) $this->next();
            } while ($this->is('|') && $this->next());
            $var = $this->is('T_VARIABLE') ? $this->next()['value'] : null;
            $this->expect(')');
            $cb = $this->parseBlock();
            $catches[] = ['types' => $types, 'var' => $var, 'body' => $cb];
        }
        $finally = null;
        if ($this->is('T_FINALLY')) { $this->next(); $finally = $this->parseBlock(); }
        return ['kind' => 'try', 'body' => $body, 'catches' => $catches, 'finally' => $finally, 'line' => $t['line']];
    }

    private function parseParams(): array {
        $this->expect('(');
        $params = [];
        if (!$this->is(')')) {
            do {
                $p = ['name' => null, 'default' => null, 'byRef' => false, 'variadic' => false, 'line' => $this->peek()['line']];
                if ($this->is('T_ELLIPSIS')) { $p['variadic'] = true; $this->next(); }
                if ($this->is('&')) { $p['byRef'] = true; $this->next(); }
                $this->skipType();
                if ($this->is('T_VARIABLE')) $p['name'] = $this->next()['value'];
                if ($this->is('=')) { $this->next(); $p['default'] = $this->parseExpression(); }
                $params[] = $p;
            } while ($this->is(',') && $this->next());
        }
        $this->expect(')');
        return $params;
    }

    private function parseFunction(): array {
        $t = $this->next(); // T_FUNCTION
        $ref = false;
        if ($this->is('&')) { $ref = true; $this->next(); }
        $name = $this->expect('T_STRING')['value'];
        $params = $this->parseParams();
        $this->skipReturnType();
        $body = $this->is('{') ? $this->parseBlock() : ($this->is(';') ? $this->next() : null);
        return ['kind' => 'func', 'name' => $name, 'params' => $params, 'body' => $body, 'ref' => $ref, 'line' => $t['line'], 'static' => false];
    }

    private function skipReturnType(): void {
        if ($this->is(':')) {
            $this->next();
            if ($this->is('?')) $this->next();
            while (!$this->isAny(['{', ';', Lexer::EOF])) {
                if ($this->is('T_NS_SEPARATOR') || $this->is('T_STRING') || $this->is('T_ARRAY') || $this->is('T_CALLABLE') || $this->is('|') || $this->is('&') || $this->is('T_STATIC') || $this->is('T_SELF') || $this->is('T_PARENT')) $this->next();
                else break;
            }
        }
    }

    private function parseClosure(bool $static): array {
        $t = $this->next(); // T_FUNCTION (T_STATIC already consumed by caller only via parseStatement; handle both)
        if ($t['type'] === 'T_STATIC') $this->expect('T_FUNCTION');
        $ref = $this->is('&') && (bool)$this->next();
        $params = $this->parseParams();
        $this->skipReturnType();
        $uses = [];
        if ($this->is('T_USE')) {
            $this->next(); $this->expect('(');
            do {
                $r = $this->is('&') && (bool)$this->next();
                if ($this->is('T_VARIABLE')) $uses[] = ['name' => $this->next()['value'], 'byRef' => $r];
            } while ($this->is(',') && $this->next());
            $this->expect(')');
        }
        $body = $this->parseBlock();
        return ['kind' => 'closure', 'params' => $params, 'uses' => $uses, 'body' => $body, 'line' => $t['line']];
    }

    private function parseClass(): array {
        $t = $this->next();
        $name = $this->is('T_STRING') ? $this->next()['value'] : null;
        if ($this->is('T_EXTENDS')) { $this->next(); $this->skipClassList(); }
        if ($this->is('T_IMPLEMENTS')) { $this->next(); $this->skipClassList(); }
        $this->expect('{');
        $methods = [];
        while (!$this->isAny(['}', Lexer::EOF])) {
            if ($this->isAny(['T_PUBLIC', 'T_PROTECTED', 'T_PRIVATE', 'T_STATIC', 'T_ABSTRACT', 'T_FINAL', 'T_READONLY', 'T_VAR', '?'])) {
                $mods = [];
                while ($this->isAny(['T_PUBLIC','T_PROTECTED','T_PRIVATE','T_STATIC','T_ABSTRACT','T_FINAL','T_READONLY','T_VAR','?'])) $mods[] = $this->next()['type'];
                $this->skipType();
                if ($this->is('T_FUNCTION')) {
                    $m = $this->parseFunction();
                    $m['static'] = in_array('T_STATIC', $mods, true);
                    $m['visibility'] = in_array('T_PRIVATE', $mods, true) ? 'private' : (in_array('T_PROTECTED', $mods, true) ? 'protected' : 'public');
                    $methods[] = $m;
                } else {
                    // property / typed member — consume to ';'
                    while (!$this->isAny([';', Lexer::EOF])) $this->next();
                    $this->skipSemicolon();
                }
            } elseif ($this->is('T_CONST')) {
                $this->next();
                while (!$this->isAny([';', Lexer::EOF])) $this->next();
                $this->skipSemicolon();
            } elseif ($this->is('T_FUNCTION')) {
                $methods[] = $this->parseFunction();
            } else {
                $this->recover();
            }
        }
        $this->expect('}');
        return ['kind' => 'class', 'name' => $name, 'methods' => $methods, 'line' => $t['line']];
    }

    private function skipClassList(): void {
        while (!$this->isAny(['{', Lexer::EOF])) {
            if ($this->isAny(['T_STRING', 'T_NS_SEPARATOR'])) { $this->next(); continue; }
            if ($this->is(',')) { $this->next(); continue; }
            break;
        }
    }

    // ---------- expressions (Pratt) ----------
    private const PREC = [
        'T_LOGICAL_OR' => 1, 'T_LOGICAL_XOR' => 2, 'T_LOGICAL_AND' => 3,
        '=' => 5, 'T_PLUS_EQUAL' => 5, 'T_MINUS_EQUAL' => 5, 'T_MUL_EQUAL' => 5,
        'T_DIV_EQUAL' => 5, 'T_CONCAT_EQUAL' => 5, 'T_MOD_EQUAL' => 5,
        'T_AND_EQUAL' => 5, 'T_OR_EQUAL' => 5, 'T_XOR_EQUAL' => 5,
        'T_POW_EQUAL' => 5, 'T_SL_EQUAL' => 5, 'T_SR_EQUAL' => 5, 'T_COALESCE_EQUAL' => 5,
        'T_COALESCE' => 6,
        '?' => 7,
        'T_BOOLEAN_OR' => 8, 'T_BOOLEAN_AND' => 9,
        '|' => 10, '^' => 11, '&' => 12,
        'T_IS_EQUAL' => 13, 'T_IS_NOT_EQUAL' => 13, 'T_IS_IDENTICAL' => 13, 'T_IS_NOT_IDENTICAL' => 13,
        '<' => 14, '>' => 14, 'T_IS_SMALLER_OR_EQUAL' => 14, 'T_IS_GREATER_OR_EQUAL' => 14, 'T_SPACESHIP' => 14,
        'T_SL' => 15, 'T_SR' => 15,
        '+' => 16, '-' => 16, '.' => 16,
        '*' => 17, '/' => 17, '%' => 17,
        'T_INSTANCEOF' => 19,
        'T_POW' => 20,
    ];

    public function parseExpression(int $minPrec = 0): array {
        $left = $this->parseUnary();
        while (true) {
            $t = $this->peek();
            // postfix
            if (in_array($t['type'], ['(', 'T_OBJECT_OPERATOR', 'T_NULLSAFE_OBJECT_OPERATOR', 'T_DOUBLE_COLON', '['], true)) {
                $left = $this->parsePostfix($left);
                continue;
            }
            if ($t['type'] === 'T_INC' || $t['type'] === 'T_DEC') {
                $this->next();
                $left = ['kind' => 'unary', 'op' => $t['value'], 'expr' => $left, 'prefix' => false, 'line' => $t['line']];
                continue;
            }
            if ($t['type'] === '?') {
                if (self::PREC['?'] < $minPrec) break;
                $this->next();
                if ($this->is(':')) { // elvis
                    $this->next();
                    $r = $this->parseExpression(self::PREC['?']);
                    $left = ['kind' => 'ternary', 'cond' => $left, 'iftrue' => null, 'iffalse' => $r, 'line' => $t['line']];
                } else {
                    $m = $this->parseExpression(self::PREC['?']);
                    $this->expect(':');
                    $r = $this->parseExpression(self::PREC['?']);
                    $left = ['kind' => 'ternary', 'cond' => $left, 'iftrue' => $m, 'iffalse' => $r, 'line' => $t['line']];
                }
                continue;
            }
            $prec = self::PREC[$t['type']] ?? null;
            if ($prec === null || $prec < $minPrec) break;
            $this->next();
            if (in_array($t['type'], ['=','T_PLUS_EQUAL','T_MINUS_EQUAL','T_MUL_EQUAL','T_DIV_EQUAL','T_CONCAT_EQUAL','T_MOD_EQUAL','T_AND_EQUAL','T_OR_EQUAL','T_XOR_EQUAL','T_POW_EQUAL','T_SL_EQUAL','T_SR_EQUAL','T_COALESCE_EQUAL'], true)) {
                $right = $this->parseExpression($prec); // right assoc
                $left = ['kind' => 'assign', 'op' => $t['value'], 'target' => $left, 'expr' => $right, 'line' => $t['line']];
            } elseif ($t['type'] === 'T_COALESCE') {
                $right = $this->parseExpression($prec);
                $left = ['kind' => 'coalesce', 'left' => $left, 'right' => $right, 'line' => $t['line']];
            } elseif ($t['type'] === 'T_INSTANCEOF') {
                $right = $this->parseUnary();
                $left = ['kind' => 'instanceof', 'expr' => $left, 'class' => $right, 'line' => $t['line']];
            } else {
                $right = $this->parseExpression($prec + 1);
                $left = ['kind' => 'binary', 'op' => $t['value'], 'left' => $left, 'right' => $right, 'line' => $t['line']];
            }
        }
        return $left;
    }

    private function parseUnary(): array {
        $t = $this->peek();
        if (in_array($t['type'], ['T_INT_CAST','T_DOUBLE_CAST','T_STRING_CAST','T_BOOL_CAST','T_ARRAY_CAST','T_OBJECT_CAST','T_UNSET_CAST'], true)) {
            $this->next();
            return ['kind' => 'cast', 'cast' => trim($t['value'], "() \t\n"), 'expr' => $this->parseUnary(), 'line' => $t['line']];
        }
        if (in_array($t['type'], ['!', '-', '+', '~', '&', '@', 'T_BOOLEAN_AND'], true) || $t['type'] === 'T_INC' || $t['type'] === 'T_DEC') {
            $this->next();
            // & on expression = reference, treat as no-op wrapper
            if ($t['type'] === '&') return $this->parseUnary();
            return ['kind' => 'unary', 'op' => $t['value'], 'expr' => $this->parseUnary(), 'prefix' => true, 'line' => $t['line']];
        }
        if ($t['type'] === 'T_PRINT' || $t['type'] === 'T_EXIT' || $t['type'] === 'T_DIE' || $t['type'] === 'T_INCLUDE' || $t['type'] === 'T_INCLUDE_ONCE' || $t['type'] === 'T_REQUIRE' || $t['type'] === 'T_REQUIRE_ONCE') {
            $this->next();
            if ($t['type'] === 'T_EXIT' || $t['type'] === 'T_DIE') {
                if ($this->is('(')) { $this->next(); if (!$this->is(')')) $this->parseExpression(); $this->expect(')'); }
                return ['kind' => 'exit', 'line' => $t['line']];
            }
            return ['kind' => 'unary', 'op' => $t['value'], 'expr' => $this->parseUnary(), 'prefix' => true, 'line' => $t['line']];
        }
        if ($t['type'] === 'T_CLONE') { $this->next(); return ['kind' => 'clone', 'expr' => $this->parseUnary(), 'line' => $t['line']]; }
        if ($t['type'] === 'T_NEW') return $this->parseNew();
        if ($t['type'] === 'T_FN') return $this->parseArrowFn();
        if ($t['type'] === 'T_MATCH') return $this->parseMatch();
        if ($t['type'] === 'T_ISSET' || $t['type'] === 'T_EMPTY') {
            $kind = strtolower(substr($t['type'], 2));
            $this->next(); $this->expect('(');
            $exprs = [$this->parseExpression()];
            while ($this->is(',') && $this->next()) $exprs[] = $this->parseExpression();
            $this->expect(')');
            return ['kind' => $kind, 'exprs' => $exprs, 'line' => $t['line']];
        }
        return $this->parsePrimary();
    }

    private function parseNew(): array {
        $t = $this->next();
        $class = null;
        if ($this->is('T_STRING') || $this->is('T_STATIC') || $this->is('T_SELF') || $this->is('T_VARIABLE')) {
            $class = ['kind' => 'name', 'parts' => [$this->next()['value']], 'line' => $t['line']];
            while ($this->is('T_NS_SEPARATOR')) { $this->next(); if ($this->is('T_STRING')) $class['parts'][] = $this->next()['value']; }
        }
        $args = [];
        if ($this->is('(')) $args = $this->parseArgs();
        return ['kind' => 'new', 'class' => $class, 'args' => $args, 'line' => $t['line']];
    }

    private function parseArrowFn(): array {
        $t = $this->next(); // T_FN
        $params = $this->parseParams();
        $this->skipReturnType();
        $this->expect('T_DOUBLE_ARROW');
        $body = $this->parseExpression(self::PREC['?']);
        return ['kind' => 'arrowfn', 'params' => $params, 'body' => $body, 'line' => $t['line']];
    }

    private function parseMatch(): array {
        $t = $this->next();
        $this->expect('(');
        $cond = $this->parseExpression();
        $this->expect(')');
        $this->expect('{');
        $arms = [];
        while (!$this->isAny(['}', Lexer::EOF])) {
            if ($this->is('T_DEFAULT')) {
                $this->next(); $this->expect('T_DOUBLE_ARROW');
                $body = $this->parseExpression();
                $arms[] = ['conds' => null, 'body' => $body];
            } else {
                $conds = [$this->parseExpression()];
                while ($this->is(',') && $this->next()) $conds[] = $this->parseExpression();
                $this->expect('T_DOUBLE_ARROW');
                $body = $this->parseExpression();
                $arms[] = ['conds' => $conds, 'body' => $body];
            }
            if (!$this->is(',')) break;
            $this->next();
        }
        $this->expect('}');
        return ['kind' => 'match', 'expr' => $cond, 'arms' => $arms, 'line' => $t['line']];
    }

    private function parsePostfix(array $node): array {
        $t = $this->peek();
        if ($t['type'] === '(') {
            return ['kind' => 'call', 'func' => $node, 'args' => $this->parseArgs(), 'line' => $t['line']];
        }
        if ($t['type'] === '[') {
            $this->next();
            $dim = null;
            if (!$this->is(']')) $dim = $this->parseExpression();
            $this->expect(']');
            return ['kind' => 'arrayfetch', 'var' => $node, 'dim' => $dim, 'line' => $t['line']];
        }
        if ($t['type'] === 'T_OBJECT_OPERATOR' || $t['type'] === 'T_NULLSAFE_OBJECT_OPERATOR') {
            $this->next();
            $name = $this->isAny(['T_STRING', 'T_VARIABLE']) ? $this->next()['value'] : null;
            if ($this->is('(')) {
                return ['kind' => 'methodcall', 'obj' => $node, 'name' => $name, 'args' => $this->parseArgs(), 'line' => $t['line']];
            }
            return ['kind' => 'propfetch', 'obj' => $node, 'name' => $name, 'line' => $t['line']];
        }
        if ($t['type'] === 'T_DOUBLE_COLON') {
            $this->next();
            $name = $this->isAny(['T_STRING', 'T_VARIABLE', 'T_STATIC', 'T_SELF', 'T_PARENT']) ? $this->next()['value'] : null;
            if ($this->is('(')) {
                return ['kind' => 'staticcall', 'class' => $node, 'name' => $name, 'args' => $this->parseArgs(), 'line' => $t['line']];
            }
            return ['kind' => 'staticprop', 'class' => $node, 'name' => $name, 'line' => $t['line']];
        }
        return $node;
    }

    private function parseArgs(): array {
        $this->expect('(');
        $args = [];
        if (!$this->is(')')) {
            do {
                $unpack = false;
                if ($this->is('T_ELLIPSIS')) { $unpack = true; $this->next(); }
                $args[] = ['value' => $this->parseExpression(), 'unpack' => $unpack];
            } while ($this->is(',') && $this->next());
        }
        $this->expect(')');
        return $args;
    }

    private function parsePrimary(): array {
        $t = $this->peek();
        switch ($t['type']) {
            case 'T_LNUMBER':
                $this->next();
                return ['kind' => 'int', 'value' => (int)str_replace('_', '', $t['value']), 'raw' => $t['value'], 'line' => $t['line']];
            case 'T_DNUMBER':
                $this->next();
                return ['kind' => 'float', 'value' => (float)str_replace('_', '', $t['value']), 'line' => $t['line']];
            case 'T_CONSTANT_ENCAPSED_STRING':
                $this->next();
                $raw = $t['value'];
                $quote = $raw[0] ?? "'";
                return ['kind' => 'string', 'value' => $quote === "'"
                    ? $this->decodeSingleQuoted($raw)
                    : stripcslashes(substr($raw, 1, -1)), 'line' => $t['line']];
            case 'T_TJ_DQ_STRING':
                $this->next();
                return $this->parseDqString($t['value'], $t['line']);
            case 'T_VARIABLE':
                $this->next();
                return ['kind' => 'variable', 'name' => $t['value'], 'line' => $t['line']];
            case 'T_TRUE': case 'T_FALSE':
                $this->next();
                return ['kind' => 'bool', 'value' => $t['type'] === 'T_TRUE', 'line' => $t['line']];
            case 'T_NULL':
                $this->next();
                return ['kind' => 'null', 'line' => $t['line']];
            case 'T_STRING':
                $this->next();
                $parts = [$t['value']];
                if ($this->is('T_NS_SEPARATOR')) {
                    while ($this->is('T_NS_SEPARATOR')) {
                        $this->next();
                        if ($this->is('T_STRING')) $parts[] = $this->next()['value'];
                    }
                    return ['kind' => 'name', 'parts' => $parts, 'line' => $t['line']];
                }
                return ['kind' => 'constfetch', 'name' => $t['value'], 'line' => $t['line']];
            case 'T_STATIC': case 'T_SELF': case 'T_PARENT':
                $this->next();
                return ['kind' => 'name', 'parts' => [$t['value']], 'line' => $t['line']];
            case 'T_ARRAY':
                $this->next();
                return $this->parseArrayBody(')');
            case '[':
                return $this->parseArrayBody(']');
            case '(':
                $this->next();
                if ($this->is('T_LIST')) { $this->next(); $this->expect(')'); }
                $e = $this->parseExpression();
                $this->expect(')');
                return $e;
            case 'T_LIST':
                $this->next();
                return $this->parseArrayBody(')');
            case 'T_FUNCTION':
                return $this->parseClosure(false);
            case Lexer::EOF:
                throw new \RuntimeException("Unexpected EOF at line {$t['line']}");
            default:
                // Unknown token: emit placeholder so recovery can continue.
                $this->next();
                return ['kind' => 'unknown', 'token' => $t['type'], 'line' => $t['line']];
        }
    }

    private function parseArrayBody(string $close): array {
        $line = $this->peek()['line'];
        $this->next(); // [ or T_ARRAY
        $items = [];
        if (!$this->is($close)) {
            do {
                if ($this->is($close)) break;
                $unpack = $this->is('T_ELLIPSIS') && (bool)$this->next();
                $val = $this->parseExpression();
                $key = null;
                if ($this->is('T_DOUBLE_ARROW')) {
                    $this->next();
                    $key = $val;
                    $val = $this->parseExpression();
                }
                $items[] = ['key' => $key, 'value' => $val, 'unpack' => $unpack];
            } while ($this->is(',') && $this->next());
        }
        $this->expect($close);
        return ['kind' => 'array', 'items' => $items, 'line' => $line];
    }

    private function decodeSingleQuoted(string $raw): string {
        $body = substr($raw, 1, -1);
        return strtr($body, ["\\'" => "'", '\\\\' => '\\']);
    }

    /**
     * Lightweight parse of double-quoted / heredoc content into literal + variable parts.
     * Anything we cannot model becomes an 'unknown' part (treated conservatively as tainted later).
     */
    private function parseDqString(string $raw, int $line): array {
        // Strip surrounding quotes when present (heredoc bodies have none).
        if (strlen($raw) >= 2 && $raw[0] === '"' && $raw[-1] === '"') {
            $body = substr($raw, 1, -1);
            $body = stripcslashes($body);
        } else {
            $body = $raw;
        }
        $parts = [];
        $offset = 0;
        $pattern = '/\{\$([A-Za-z_]\w*)((?:\[[^\]\[]+\]|->\w+)*)\}|\$([A-Za-z_]\w*)(?:\[([^\]\[]+)\])?/';
        if (!preg_match_all($pattern, $body, $mm, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
            return ['kind' => 'dstring', 'parts' => [['kind' => 'string', 'value' => $body, 'line' => $line]], 'unknown' => false, 'line' => $line];
        }
        foreach ($mm as $m) {
            $pos = $m[0][1];
            if ($pos > $offset) $parts[] = ['kind' => 'string', 'value' => substr($body, $offset, $pos - $offset), 'line' => $line];
            $varName = $m[1][0] !== '' ? $m[1] : ($m[3][0] !== '' ? $m[3] : null);
            $node = ['kind' => 'variable', 'name' => $varName[0], 'line' => $line];
            $chain = $m[2][0] !== '' ? $m[2][0] : '';
            $bracket = $m[4][0] ?? '';
            if ($bracket !== '') {
                $dim = trim($bracket);
                if (preg_match("/^'(.*)'$|^\"(.*)\"$/", $dim, $dm)) $dim = $dm[1] ?? $dm[2];
                $node = ['kind' => 'arrayfetch', 'var' => $node, 'dim' => ['kind' => 'string', 'value' => $dim, 'line' => $line], 'line' => $line];
            } elseif ($chain !== '') {
                if (preg_match_all('/\[([^\]\[]+)\]|->(\w+)/', $chain, $cm, PREG_SET_ORDER)) {
                    foreach ($cm as $c) {
                        if (!empty($c[1])) {
                            $dim = trim($c[1]);
                            if (preg_match("/^'(.*)'$|^\"(.*)\"$/", $dim, $dm)) $dim = $dm[1] ?? $dm[2];
                            $node = ['kind' => 'arrayfetch', 'var' => $node, 'dim' => ['kind' => 'string', 'value' => $dim, 'line' => $line], 'line' => $line];
                        } else {
                            $node = ['kind' => 'propfetch', 'obj' => $node, 'name' => $c[2], 'line' => $line];
                        }
                    }
                }
            }
            $parts[] = $node;
            $offset = $pos + strlen($m[0][0]);
        }
        if ($offset < strlen($body)) $parts[] = ['kind' => 'string', 'value' => substr($body, $offset), 'line' => $line];
        return ['kind' => 'dstring', 'parts' => $parts, 'unknown' => false, 'line' => $line];
    }
}
