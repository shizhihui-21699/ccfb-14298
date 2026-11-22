<?php
/**
 * TaintAnalyzer — flow-insensitive may-taint analysis over the TypeWatch AST.
 *
 * Sources: $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER/php://input, filter_input(),
 *          getallheaders(), apache_request_headers()
 * Sinks  : loose equality, in_array/array_search without strict mode,
 *          strcmp-family comparisons, loose switch()
 */
final class TaintAnalyzer {
    public const SUPERGLOBALS = ['_GET','_POST','_REQUEST','_COOKIE','_SERVER','_FILES','_ENV','HTTP_RAW_POST_DATA'];

    /** Functions whose return value preserves taint from the indicated argument (0-based). */
    private const PASSTHROUGH = [
        'trim'=>0,'ltrim'=>0,'rtrim'=>0,'substr'=>0,'substr_replace'=>0,'mb_substr'=>0,
        'strtolower'=>0,'strtoupper'=>0,'mb_strtolower'=>0,'mb_strtoupper'=>0,
        'str_replace'=>2,'str_ireplace'=>2,'substr_count'=>0,'str_pad'=>0,
        'str_repeat'=>0,'strrev'=>0,'ucfirst'=>0,'lcfirst'=>0,'ucwords'=>0,
        'htmlspecialchars'=>0,'htmlspecialchars_decode'=>0,'htmlentities'=>0,'html_entity_decode'=>0,
        'addslashes'=>0,'addcslashes'=>0,'stripslashes'=>0,'stripcslashes'=>0,
        'nl2br'=>0,'wordwrap'=>0,'chunk_split'=>0,'str_split'=>0,'count_chars'=>0,
        'sprintf'=>null,'vsprintf'=>1,'implode'=>1,'join'=>1,'strtr'=>0,'strtok'=>0,
        'preg_replace'=>2,'preg_filter'=>2,'preg_replace_callback'=>2,
        'number_format'=>0,'chr'=>0,'ord'=>0,'intval'=>0,'floatval'=>0,'doubleval'=>0,
        'strval'=>0,'boolval'=>0,'settype'=>0,'abs'=>0,'round'=>0,'floor'=>0,'ceil'=>0,
        'base64_encode'=>0,'base64_decode'=>0,'rawurlencode'=>0,'urlencode'=>0,
        'rawurldecode'=>0,'urldecode'=>0,'http_build_query'=>0,
        'json_encode'=>0,'json_decode'=>0,'serialize'=>0,'unserialize'=>0,
        'utf8_encode'=>0,'utf8_decode'=>0,'iconv'=>2,'mb_convert_encoding'=>0,
        'bin2hex'=>0,'hex2bin'=>0,
        'md5'=>0,'sha1'=>0,'hash'=>1,'crc32'=>0,'md5_file'=>0,'sha1_file'=>0,
        'crypt'=>0,'password_hash'=>0,'hash_hmac'=>2,
        'array_map'=>1,'array_filter'=>0,'array_values'=>0,'array_keys'=>0,
        'array_merge'=>null,'array_combine'=>1,'array_slice'=>0,'array_flip'=>0,
        'array_reverse'=>0,'array_unique'=>0,'array_pad'=>0,
        'str_getcsv'=>0,'explode'=>1,'preg_split'=>1,
        'mb_substr_count'=>0,'mb_strcut'=>0,'mb_strimwidth'=>0,
        'str_contains'=>0,'str_starts_with'=>0,'str_ends_with'=>0,
        'gmmktime'=>null,'mktime'=>null,
    ];

    /** strcmp-family: return 0 when strings are equal — classic PHP7 array-bypass targets. */
    public const STRCMP_FAMILY = ['strcmp','strncmp','strcasecmp','strncasecmp','substr_compare','strcoll'];

    /** Validation/query functions: results do not carry the input taint as a value. */
    private const PREDICATE_FUNCS = [
        'is_string','is_int','is_integer','is_long','is_float','is_double','is_numeric',
        'is_array','is_bool','is_scalar','is_null','isset','empty','defined','gettype',
        'strlen','mb_strlen','preg_match','filter_has_var','array_key_exists','in_array',
        'ctype_digit','ctype_alnum','ctype_alpha','is_countable','str_contains','str_starts_with','str_ends_with',
    ];

    /** @var array<string, TaintTerm> */
    private array $vars = [];
    /** @var FuncSummary[] */
    private array $funcs = [];
    /** @var FuncSummary[] */
    private array $methods = [];
    /** @var array<string, TaintTerm> memoized function summaries keyed name#depth */
    private array $cache = [];
    private array $findings = [];
    private string $currentFile = '';
    private int $callDepth = 0;
    private array $callStack = [];
    /** @var TaintTerm[] return accumulator for the function currently being analyzed */
    private array $returns = [];
    /**
     * Literal argument bindings for the active user-function call chain.
     * Each frame maps parameter name => literal AST node supplied at the call site.
     * @var array<int, array<string, array>>
     */
    private array $literalArgStack = [];

    // ---------------------------------------------------------------
    // Entry points
    // ---------------------------------------------------------------
    public function analyzeFile(string $path, array $ast): void {
        $this->currentFile = $path;
        $this->collectDefinitions($ast);
    }

    public function finalizeAnalysis(): array {
        // Global-scope analysis happens per file; function bodies are analyzed lazily.
        return $this->findings;
    }

    public function analyzeProgramStmts(string $path, array $stmts): void {
        $this->currentFile = $path;
        $this->collectDefinitions(['kind' => 'block', 'stmts' => $stmts]);
        $this->walkStmts($stmts, []);
    }

    public function getFunctions(): array { return $this->funcs; }
    public function getMethods(): array { return $this->methods; }
    public function getFindings(): array { return $this->findings; }
    public function currentFilePath(): string { return $this->currentFile; }

    private function collectDefinitions(array $node): void {
        $stmts = $node['stmts'] ?? [];
        foreach ($stmts as $s) {
            if (($s['kind'] ?? '') === 'func') {
                $this->funcs[strtolower($s['name'])] = new FuncSummary(
                    $s['name'], array_map(fn($p) => $p['name'], $s['params']),
                    $s['body'], $s['line']
                );
            } elseif (($s['kind'] ?? '') === 'class') {
                foreach ($s['methods'] ?? [] as $m) {
                    $sum = new FuncSummary(
                        $m['name'], array_map(fn($p) => $p['name'], $m['params']),
                        $m['body'], $m['line'], $m['static'] ?? false, (string)($s['name'] ?? '')
                    );
                    $this->methods[strtolower($m['name'])] = $sum;
                }
            } elseif (($s['kind'] ?? '') === 'block') {
                $this->collectDefinitions($s);
            }
        }
    }

    // ---------------------------------------------------------------
    // Statement walking (sink detection + assignments)
    // ---------------------------------------------------------------
    private function walkStmts(array $stmts, array $scope): void {
        foreach ($stmts as $s) {
            $this->walkStmt($s, $scope);
        }
    }

    private function walkStmt(array $s, array $scope): void {
        switch ($s['kind'] ?? '') {
            case 'block':
                $this->walkStmts($s['stmts'], $scope);
                break;
            case 'if':
                $this->checkCondition($s['cond'], $scope);
                $this->walkStmt($s['body'], $scope);
                foreach ($s['elseifs'] ?? [] as $ei) { $this->checkCondition($ei['cond'], $scope); $this->walkStmt($ei['body'], $scope); }
                if ($s['else']) $this->walkStmt($s['else'], $scope);
                break;
            case 'while':
                $this->checkCondition($s['cond'], $scope);
                $this->walkStmt($s['body'], $scope);
                break;
            case 'for':
                foreach ($s['init'] ?? [] as $e) $this->resolve($e, $scope);
                foreach ($s['cond'] ?? [] as $e) $this->checkCondition($e, $scope);
                foreach ($s['update'] ?? [] as $e) $this->resolve($e, $scope);
                $this->walkStmt($s['body'], $scope);
                break;
            case 'foreach':
                $this->resolve($s['expr'], $scope);
                $this->walkStmt($s['body'], $scope);
                break;
            case 'switch':
                $this->checkSwitch($s, $scope);
                break;
            case 'try':
                $this->walkStmt($s['body'], $scope);
                foreach ($s['catches'] ?? [] as $c) $this->walkStmt($c['body'], $scope);
                if ($s['finally']) $this->walkStmt($s['finally'], $scope);
                break;
            case 'return':
                if (!empty($s['expr'])) $this->returns[] = $this->resolve($s['expr'], $scope);
                break;
            case 'expr':
                $this->resolve($s['expr'], $scope);
                break;
            case 'echo':
                foreach ($s['exprs'] ?? [] as $e) $this->resolve($e, $scope);
                break;
            case 'throw':
                $this->resolve($s['expr'], $scope);
                break;
            case 'unset':
            case 'global':
            case 'static':
                foreach ($s['exprs'] ?? $s['vars'] ?? [] as $e) {
                    if (is_array($e)) $this->resolve($e, $scope);
                }
                break;
            default:
                // match/closure/unknown: best effort via contained expressions
                if (isset($s['expr']) && is_array($s['expr'])) $this->resolve($s['expr'], $scope);
        }
    }

    private function checkCondition(array $expr, array $scope): void {
        // ! (==) etc.
        if ($expr['kind'] === 'unary' && in_array($expr['op'], ['!'], true)) {
            $this->checkCondition($expr['expr'], $scope);
            return;
        }
        if ($expr['kind'] === 'binary') {
            $op = $expr['op'];
            if (in_array($op, ['==','!=','<>'], true)) {
                if ($this->isStrcmpCall($expr['left'])) {
                    $this->recordStrcmp($expr['left'], $scope, $op === '!=' || $op === '<>');
                } elseif ($this->isStrcmpCall($expr['right'])) {
                    $this->recordStrcmp($expr['right'], $scope, $op === '!=' || $op === '<>');
                } else {
                    $this->recordLooseEquality($expr, $scope, $op === '!=' || $op === '<>');
                }
            } elseif (in_array($op, ['&&','||','and','or'], true)) {
                $this->checkCondition($expr['left'], $scope);
                $this->checkCondition($expr['right'], $scope);
            }
            return;
        }
        if ($expr['kind'] === 'call') {
            $name = $this->callName($expr);
            if ($name !== null && in_array(strtolower($name), self::STRCMP_FAMILY, true)) {
                $this->recordStrcmp($expr, $scope, false);
            }
            if ($name !== null && in_array(strtolower($name), ['in_array', 'array_search'], true)) {
                $this->handleInArray($expr, $scope, 0, strtolower($name));
            }
        }
    }

    private function isStrcmpCall(array $node): bool {
        if (($node['kind'] ?? '') !== 'call') return false;
        $name = $this->callName($node);
        return $name !== null && in_array(strtolower($name), self::STRCMP_FAMILY, true);
    }

    private function checkSwitch(array $s, array $scope): void {
        $subject = $this->resolve($s['expr'], $scope);
        foreach ($s['cases'] ?? [] as $case) {
            if ($case['cond'] === null) continue;
            $caseTerm = $this->resolve($case['cond'], $scope);
            if ($subject->tainted || $caseTerm->tainted) {
                $this->makeFinding('loose_switch', $s['line'],
                    'switch() compares subject against cases with PHP loose rules (==)',
                    $subject, $caseTerm, ['inverted' => false, 'code' => 'switch']);
            }
            $this->walkStmts($case['stmts'] ?? [], $scope);
        }
    }

    // ---------------------------------------------------------------
    // Sink recorders
    // ---------------------------------------------------------------
    private function recordLooseEquality(array $expr, array $scope, bool $inverted): void {
        $l = $this->resolve($expr['left'], $scope);
        $r = $this->resolve($expr['right'], $scope);
        // skip self comparisons and two literals
        if (!$l->tainted && !$r->tainted) return;
        $this->makeFinding('loose_equality', $expr['line'],
            "Loose comparison ({$expr['op']}) between possibly user-controlled values",
            $l, $r, ['inverted' => $inverted, 'code' => $expr['op'], 'node' => $expr]);
    }

    private function recordStrcmp(array $expr, array $scope, bool $inverted): void {
        $args = $expr['args'];
        if (count($args) < 2) return;
        $l = $this->resolve($args[0]['value'], $scope);
        $r = $this->resolve($args[1]['value'], $scope);
        if (!$l->tainted && !$r->tainted) return;
        $this->makeFinding('strcmp_compare', $expr['line'],
            'strcmp-family result used as equality guard (returns 0 on equal)',
            $l, $r, ['inverted' => $inverted, 'code' => 'strcmp', 'func' => strtolower($this->callName($expr) ?? 'strcmp')]);
    }

    private function makeFinding(string $type, int $line, string $msg, TaintTerm $a, TaintTerm $b, array $extra = []): array {
        $f = [
            'type' => $type,
            'file' => $this->currentFile,
            'line' => $line,
            'message' => $msg,
            'left' => $a->toArray(),
            'right' => $b->toArray(),
            'dataflow' => $this->dataflow($a, $b),
        ];
        $f = array_merge($f, $extra);
        unset($f['node']); // AST node is not part of the report
        $sig = $type . '|' . $this->currentFile . '|' . $line . '|' .
               json_encode($a->sources) . '|' . json_encode($b->sources) . '|' .
               ($f['code'] ?? '') . '|' . ($f['func'] ?? '');
        if (!isset($this->seen[$sig])) {
            $this->seen[$sig] = true;
            $this->findings[] = $f;
        }
        return $f;
    }
    private array $seen = [];

    private function dataflow(TaintTerm $a, TaintTerm $b): array {
        $steps = [];
        foreach ([$a, $b] as $idx => $term) {
            if (!$term->tainted) continue;
            $side = $idx === 0 ? 'left' : 'right';
            foreach ($term->sources as $src) {
                $steps[] = ['side' => $side, 'from' => $src, 'vars' => $term->vars, 'transforms' => $term->transforms];
            }
        }
        return $steps;
    }

    // ---------------------------------------------------------------
    // Expression resolution -> TaintTerm
    // ---------------------------------------------------------------
    public function resolve(array $node, array $scope = [], int $depth = 0): TaintTerm {
        if ($depth > 12) return TaintTerm::unknown();
        switch ($node['kind']) {
            case 'int':
            case 'float':
            case 'bool':
            case 'null':
            case 'string':
                return TaintTerm::literal($node);
            case 'dstring':
                $merged = TaintTerm::clean(['string']);
                $anyTaint = false;
                foreach ($node['parts'] as $p) {
                    $pt = $this->resolve($p, $scope, $depth + 1);
                    if ($pt->tainted) $anyTaint = true;
                    $merged = TaintTerm::merge($merged, $pt);
                }
                if (!$anyTaint) return TaintTerm::literal(['kind' => 'string', 'value' => '', 'line' => $node['line']]);
                return $merged->setTypes(['string'])->withTransform('interpolate', $node['line']);
            case 'array':
                $merged = TaintTerm::clean(['array']);
                foreach ($node['items'] as $it) {
                    $vt = $this->resolve($it['value'], $scope, $depth + 1);
                    $merged = TaintTerm::merge($merged, $vt);
                }
                return $merged;
            case 'variable':
                return $this->resolveVariable($node, $scope);
            case 'arrayfetch':
                return $this->resolveArrayFetch($node, $scope, $depth);
            case 'assign':
                return $this->resolveAssign($node, $scope, $depth);
            case 'cast':
                $inner = $this->resolve($node['expr'], $scope, $depth + 1);
                $map = ['int'=>'int','integer'=>'int','float'=>'float','double'=>'float','real'=>'float',
                        'string'=>'string','bool'=>'bool','boolean'=>'bool','array'=>'array','object'=>'object','unset'=>'null'];
                $type = $map[strtolower($node['cast'])] ?? 'mixed';
                if (!$inner->tainted) {
                    return TaintTerm::clean([$type]);
                }
                return $inner->setTypes([$type])->withTransform('cast:' . $type, $node['line'], "({$node['cast']}) ...");
            case 'unary':
                if (in_array($node['op'], ['++','--'], true)) {
                    $t = $this->resolve($node['expr'], $scope, $depth + 1);
                    return $t->withTransform('unary:' . $node['op'], $node['line']);
                }
                return $this->resolve($node['expr'], $scope, $depth + 1);
            case 'binary':
                return $this->resolveBinary($node, $scope, $depth);
            case 'ternary':
                $this->checkCondition($node['cond'], $scope);
                $a = $node['iftrue'] ? $this->resolve($node['iftrue'], $scope, $depth + 1) : $this->resolve($node['cond'], $scope, $depth + 1);
                $b = $this->resolve($node['iffalse'], $scope, $depth + 1);
                return TaintTerm::merge($a, $b);
            case 'coalesce':
                $a = $this->resolve($node['left'], $scope, $depth + 1);
                $b = $this->resolve($node['right'], $scope, $depth + 1);
                return TaintTerm::merge($a, $b);
            case 'call':
                return $this->resolveCall($node, $scope, $depth);
            case 'methodcall':
            case 'staticcall':
                return $this->resolveMethodCall($node, $scope, $depth);
            case 'propfetch':
                // object properties are unknown; taint not propagated statically
                return TaintTerm::unknown();
            case 'closure':
            case 'arrowfn':
                return TaintTerm::unknown(['closure']);
            case 'new':
                return TaintTerm::unknown(['object']);
            case 'instanceof':
            case 'isset':
            case 'empty':
                return TaintTerm::clean(['bool']);
            case 'clone':
                return $this->resolve($node['expr'], $scope, $depth + 1);
            case 'constfetch':
            case 'name':
            case 'staticprop':
            case 'exit':
            case 'unknown':
            default:
                return TaintTerm::unknown();
        }
    }

    private function resolveVariable(array $node, array $scope): TaintTerm {
        $name = $node['name'];
        $key = '$' . $name;
        if (in_array($name, self::SUPERGLOBALS, true)) {
            return TaintTerm::source('$_' . substr($name, 1) . ' (superglobal)', null, ['array']);
        }
        if (isset($scope[$key])) return $scope[$key];
        return $this->vars[$key] ?? TaintTerm::unknown();
    }

    /**
     * Resolve a parameter variable back to its literal call-site argument when available,
     * e.g. hash($algo, ...) inside a wrapper called as computeDigest('md5', $x).
     */
    private function literalBindingFor(string $varName): ?array {
        if (!$this->literalArgStack) return null;
        $frame = $this->literalArgStack[array_key_last($this->literalArgStack)];
        return $frame[$varName] ?? null;
    }

    private function resolveArrayFetch(array $node, array $scope, int $depth): TaintTerm {
        // Direct superglobal access: $_GET['x']
        if ($node['var']['kind'] === 'variable' && in_array($node['var']['name'], self::SUPERGLOBALS, true)) {
            $sg = $node['var']['name'];
            $key = $this->keyString($node['dim']);
            $label = '$_' . substr($sg, 1) . ($key !== null ? "[" . $this->exportKey($key) . "]" : '[...]');
            return TaintTerm::source($label, $key);
        }
        $base = $this->resolve($node['var'], $scope, $depth + 1);
        if (!$base->tainted) {
            // array fetch on a clean array: clean unless it is the superglobal handled above
            return TaintTerm::unknown();
        }
        $key = $this->keyString($node['dim']);
        return $base->withTransform('arrayfetch', $node['line'], $key !== null ? "['{$key}']" : '[...]');
    }

    private function resolveAssign(array $node, array $scope, int $depth): TaintTerm {
        $rhs = $this->resolve($node['expr'], $scope, $depth + 1);
        $target = $node['target'];
        if ($node['op'] !== '=') {
            // compound assignment merges with previous value
            $prev = $this->resolve($target, $scope, $depth + 1);
            $rhs = TaintTerm::merge($prev, $rhs)->withTransform('assign:' . trim($node['op'], '='), $node['line']);
        }
        if ($target['kind'] === 'variable') {
            $key = '$' . $target['name'];
            $stored = $rhs->tainted ? $rhs->addVar($key) : $rhs;
            if (isset($scope[$key]) || $this->inFunctionScope($scope)) {
                $scope[$key] = isset($scope[$key]) ? TaintTerm::merge($scope[$key], $stored) : $stored;
                $this->bindScope($scope);
            }
            if (isset($this->vars[$key])) {
                $this->vars[$key] = TaintTerm::merge($this->vars[$key], $stored);
            } else {
                $this->vars[$key] = $stored;
            }
            return $stored;
        }
        if ($target['kind'] === 'arrayfetch') {
            // $arr['k'] = rhs — taint the array itself
            if ($target['var']['kind'] === 'variable') {
                $key = '$' . $target['var']['name'];
                if (isset($this->vars[$key])) $this->vars[$key] = TaintTerm::merge($this->vars[$key], $rhs);
                else $this->vars[$key] = $rhs->addVar($key);
            }
            return $rhs;
        }
        return $rhs;
    }

    private bool $inFunction = false;
    private function inFunctionScope(array $scope): bool { return $this->inFunction; }
    private function bindScope(array $scope): void { /* scope is passed by value; functions use dedicated local maps below */ }

    private function resolveBinary(array $node, array $scope, int $depth): TaintTerm {
        $op = $node['op'];
        $l = $this->resolve($node['left'], $scope, $depth + 1);
        $r = $this->resolve($node['right'], $scope, $depth + 1);

        if (in_array($op, ['==','!=','<>','===','!==','<','>','<=','>=','<=>'], true)) {
            // Sink recording lives in checkCondition() at statement level to avoid duplicates.
            return TaintTerm::clean(['bool']);
        }
        if (in_array($op, ['&&','||','and','or'], true)) return TaintTerm::clean(['bool']);

        $merged = TaintTerm::merge($l, $r);
        if ($op === '.') return $merged->setTypes(['string'])->withTransform('concat', $node['line']);
        if (in_array($op, ['+','-','*','/','%','**'], true)) {
            return $merged->setTypes(array_values(array_intersect($merged->types, ['int','float'])) ?: ['int','float'])
                          ->withTransform('arith:' . $op, $node['line']);
        }
        if (in_array($op, ['&','|','^','<<','>>'], true)) return $merged->withTransform('bitop:' . $op, $node['line']);
        return $merged;
    }

    // ---------------------------------------------------------------
    // Calls: built-ins + user functions (interprocedural)
    // ---------------------------------------------------------------
    private function resolveCall(array $node, array $scope, int $depth): TaintTerm {
        $name = $this->callName($node);

        // Sink-style built-ins.
        if ($name !== null) {
            $lower = strtolower($name);
            if (in_array($lower, ['in_array','array_search'], true)) {
                return $this->handleInArray($node, $scope, $depth, $lower);
            }
            if (in_array($lower, self::STRCMP_FAMILY, true)) {
                // Only a finding when used as a condition; record generic taint either way.
                $args = $node['args'];
                if (count($args) >= 2) {
                    $l = $this->resolve($args[0]['value'], $scope, $depth + 1);
                    $r = $this->resolve($args[1]['value'], $scope, $depth + 1);
                    if ($l->tainted || $r->tainted) {
                        return TaintTerm::merge($l, $r)->setTypes(['int'])->withTransform($lower, $node['line']);
                    }
                }
                return TaintTerm::clean(['int']);
            }
            // User-defined function takes precedence over the generic built-in table.
            if (isset($this->funcs[$lower])) {
                $argTerms = [];
                foreach ($node['args'] as $a) $argTerms[] = $this->resolve($a['value'], $scope, $depth + 1);
                return $this->summarizeUserCall($this->funcs[$lower], $argTerms, $depth, $node['line'], $node['args']);
            }
            return $this->handleBuiltin($lower, $node, $scope, $depth);
        }
        // Dynamic call $f(...)
        foreach ($node['args'] as $a) $this->resolve($a['value'], $scope, $depth + 1);
        return TaintTerm::unknown();
    }

    private function handleInArray(array $node, array $scope, int $depth, string $func): TaintTerm {
        $args = $node['args'];
        if (count($args) < 2) return TaintTerm::clean(['bool']);
        $needle = $this->resolve($args[0]['value'], $scope, $depth + 1);
        $haystack = $this->resolve($args[1]['value'], $scope, $depth + 1);
        $strict = false;
        if (isset($args[2])) {
            $st = $this->resolve($args[2]['value'], $scope, $depth + 1);
            $strict = ($st->literal !== null && ($st->literal['kind'] ?? '') === 'bool' && $st->literal['value'] === true);
        }
        if (!$strict && $needle->tainted) {
            $this->makeFinding('in_array_loose', $node['line'],
                "{$func}() runs in loose-comparison mode (third argument is not true)",
                $needle, $haystack, ['inverted' => false, 'code' => $func, 'strict' => false, 'node' => $node]);
        }
        return TaintTerm::clean([$func === 'in_array' ? 'bool' : 'mixed']);
    }

    private function handleBuiltin(string $lower, array $node, array $scope, int $depth): TaintTerm {
        $argTerms = [];
        foreach ($node['args'] as $a) $argTerms[] = $this->resolve($a['value'], $scope, $depth + 1);

        // ---- direct request sources ----
        if ($lower === 'filter_input') {
            // filter_input(type, var_name, ...) — the named request value
            $key = isset($node['args'][1]) ? $this->keyString($node['args'][1]['value']) : null;
            return TaintTerm::source("filter_input(...," . ($key !== null ? "'{$key}'" : '...') . ")", $key);
        }
        if (in_array($lower, ['getallheaders','apache_request_headers'], true)) {
            return TaintTerm::source($lower . '()', null, ['array']);
        }
        if (in_array($lower, self::PREDICATE_FUNCS, true)) {
            return TaintTerm::clean(['bool','int']);
        }
        if ($lower === 'filter_var' || $lower === 'filter_input_array' || $lower === 'filter_var_array') {
            // filter_var may sanitize but commonly returns the request-derived string
            $base = $argTerms[0] ?? TaintTerm::unknown();
            return $base->tainted ? $base->withTransform($lower, $node['line']) : TaintTerm::unknown();
        }
        if ($lower === 'hash' || $lower === 'hash_file') {
            // hash('md5', $data): preserve the algorithm name in the transform for VersionRules.
            $base = $argTerms[1] ?? TaintTerm::unknown();
            $algo = isset($node['args'][0]) ? $this->keyString($node['args'][0]['value']) : null;
            if ($algo === null && isset($node['args'][0]['value']['kind']) &&
                $node['args'][0]['value']['kind'] === 'variable') {
                $bound = $this->literalBindingFor($node['args'][0]['value']['name']);
                if ($bound !== null) $algo = $this->keyString($bound);
            }
            if ($base->tainted) {
                return $base->withTransform($algo ? 'hash:' . strtolower($algo) : 'hash', $node['line'],
                    $algo ? "hash('{$algo}', ...)" : 'hash(...)');
            }
            // Clean hash output still records the digest transform for comparison analysis.
            return TaintTerm::clean(['string'])->withTransform(
                $algo ? 'hash:' . strtolower($algo) : 'hash', $node['line'],
                $algo ? "hash('{$algo}', ...)" : 'hash(...)');
        }
        if ($lower === 'compact') {
            $merged = TaintTerm::clean(['array']);
            foreach ($argTerms as $at) $merged = TaintTerm::merge($merged, $at);
            return $merged;
        }
        if (in_array($lower, ['array_map','array_filter','usort','uasort','uksort'], true)) {
            // taint carried by the data argument (last relevant array)
            $data = $argTerms[1] ?? ($argTerms[0] ?? TaintTerm::unknown());
            return $data->tainted ? $data->withTransform($lower, $node['line']) : TaintTerm::clean(['array']);
        }
        if (in_array($lower, ['count','sizeof','intval','strlen','mb_strlen'], true)) {
            if ($lower === 'count' || $lower === 'sizeof') return TaintTerm::clean(['int']);
            $base = $argTerms[0] ?? TaintTerm::unknown();
            return $base->tainted ? $base->setTypes(['int'])->withTransform($lower, $node['line']) : TaintTerm::clean(['int']);
        }
        if (array_key_exists($lower, self::PASSTHROUGH)) {
            $idx = self::PASSTHROUGH[$lower];
            if ($idx === null) {
                // any-argument passthrough (sprintf, array_merge, ...)
                $merged = TaintTerm::clean();
                foreach ($argTerms as $at) $merged = TaintTerm::merge($merged, $at);
                return $merged->tainted ? $merged->withTransform($lower, $node['line']) : TaintTerm::unknown();
            }
            $base = $argTerms[$idx] ?? TaintTerm::unknown();
            // Hash functions record their transform even on clean input, so that a later
            // comparison can recognize both operands as hash digests.
            if (!$base->tainted && in_array($lower, ['md5', 'sha1', 'sha256', 'crc32', 'crypt'], true)) {
                return TaintTerm::clean(['string'])->withTransform($lower, $node['line']);
            }
            return $base->tainted ? $base->withTransform($lower, $node['line']) : TaintTerm::unknown();
        }
        // Unknown built-in: assume clean return.
        return TaintTerm::unknown();
    }

    private function resolveMethodCall(array $node, array $scope, int $depth): TaintTerm {
        foreach ($node['args'] ?? [] as $a) $this->resolve($a['value'], $scope, $depth + 1);
        $name = strtolower((string)($node['name'] ?? ''));
        if ($name !== '' && isset($this->methods[$name])) {
            $argTerms = [];
            foreach ($node['args'] ?? [] as $a) $argTerms[] = $this->resolve($a['value'], $scope, $depth + 1);
            return $this->summarizeUserCall($this->methods[$name], $argTerms, $depth, $node['line']);
        }
        return TaintTerm::unknown();
    }

    private function summarizeUserCall(FuncSummary $fn, array $argTerms, int $depth, int $line, array $rawArgs = []): TaintTerm {
        if ($fn->body === null) return TaintTerm::unknown();
        if ($depth >= 8) return TaintTerm::unknown();
        $guard = strtolower($fn->name) . ':' . $depth;
        if (in_array($guard, $this->callStack, true)) return TaintTerm::unknown(); // recursion guard

        // Build local scope from parameters; missing params become clean unknowns.
        $local = [];
        $literalFrame = [];
        foreach ($fn->paramNames as $i => $pname) {
            $key = '$' . $pname;
            if (isset($argTerms[$i])) {
                $local[$key] = $argTerms[$i]->addVar($key);
            } else {
                $local[$key] = TaintTerm::unknown()->addVar($key);
            }
            // Remember literal call-site arguments so nested built-ins (e.g. hash($algo, ...))
            // can recover values that static parameter names cannot provide.
            if (isset($rawArgs[$i]['value']['kind']) &&
                in_array($rawArgs[$i]['value']['kind'], ['string', 'int', 'float', 'bool'], true)) {
                $literalFrame[$pname] = $rawArgs[$i]['value'];
                $local[$key] = TaintTerm::literal($rawArgs[$i]['value'])->addVar($key);
            }
        }
        $savedVars = $this->vars;
        $savedReturns = $this->returns;
        $savedIn = $this->inFunction;
        $this->vars = array_merge($this->vars, $local);
        $this->returns = [];
        $this->inFunction = true;
        $this->callStack[] = $guard;
        $this->literalArgStack[] = $literalFrame;
        $captured = [];
        try {
            $this->walkStmts($fn->body['stmts'] ?? [], $local);
            $captured = $this->returns;
        } finally {
            array_pop($this->literalArgStack);
            array_pop($this->callStack);
            $this->inFunction = $savedIn;
            $this->vars = $savedVars;
            $this->returns = $savedReturns;
        }
        if (!$captured) return TaintTerm::unknown();
        $merged = TaintTerm::clean();
        foreach ($captured as $rt) $merged = TaintTerm::merge($merged, $rt);
        // A function that only returns compile-time constants propagates its literal
        // (e.g. loadKnownToken(): return '0e123...';).
        if (!$merged->tainted && count($captured) === 1 && $captured[0]->literal !== null) {
            $merged = TaintTerm::literal($captured[0]->literal);
        }
        return $merged->withTransform('call:' . strtolower($fn->name), $line, $fn->name . '()');
    }

    public function resolveUserFunctionCall(string $name, array $argTerms, int $depth = 0): TaintTerm {
        $lower = strtolower($name);
        if (!isset($this->funcs[$lower])) return TaintTerm::unknown();
        return $this->summarizeUserCall($this->funcs[$lower], $argTerms, $depth, 0);
    }

    // ---------------------------------------------------------------
    // Small utilities
    // ---------------------------------------------------------------
    private function callName(array $callNode): ?string {
        $f = $callNode['func'] ?? null;
        if ($f && $f['kind'] === 'constfetch') return $f['name'];
        if ($f && $f['kind'] === 'name') return implode('\\', $f['parts']);
        return null;
    }

    public function keyString(?array $dimNode): ?string {
        if ($dimNode === null) return null;
        if ($dimNode['kind'] === 'string') return $dimNode['value'];
        if ($dimNode['kind'] === 'int') return (string)$dimNode['value'];
        return null;
    }

    private function exportKey(string $key): string {
        return preg_match('/^[A-Za-z0-9_\-]+$/', $key) ? $key : (string)json_encode($key);
    }

    /** Analyze a previously collected user function body from the driver (used for entry-point scanning). */
    public function analyzeFunctionBody(FuncSummary $fn): void {
        if ($fn->body === null) return;
        $local = [];
        foreach ($fn->paramNames as $i => $pname) {
            $local['$' . $pname] = TaintTerm::param($i, $pname);
        }
        $saved = $this->vars; $savedR = $this->returns; $savedIn = $this->inFunction;
        $this->vars = array_merge($this->vars, $local);
        $this->returns = [];
        $this->inFunction = true;
        try { $this->walkStmts($fn->body['stmts'] ?? [], $local); }
        finally { $this->vars = $saved; $this->returns = $savedR; $this->inFunction = $savedIn; }
    }
}
