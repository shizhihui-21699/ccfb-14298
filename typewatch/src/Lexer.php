<?php
/**
 * TypeWatch Lexer — hand-written PHP tokenizer.
 * Produces tokens of shape [type, value, line].
 */
final class Lexer {
    public const EOF = 'EOF';

    private const KEYWORDS = [
        'abstract','and','array','as','break','callable','case','catch','class','clone',
        'const','continue','declare','default','die','do','echo','else','elseif','empty',
        'enddeclare','endfor','endforeach','endif','endswitch','endwhile','enum','extends',
        'final','finally','fn','for','foreach','function','global','goto','if','implements',
        'include','include_once','instanceof','insteadof','interface','isset','list','match',
        'namespace','new','or','print','private','protected','public','readonly','require',
        'require_once','return','static','switch','throw','trait','try','unset','use','var',
        'while','xor','yield','from','true','false','null','parent','self',
    ];

    private const CASTS = [
        'int'=>'T_INT_CAST','integer'=>'T_INT_CAST',
        'float'=>'T_DOUBLE_CAST','double'=>'T_DOUBLE_CAST','real'=>'T_DOUBLE_CAST',
        'string'=>'T_STRING_CAST','bool'=>'T_BOOL_CAST','boolean'=>'T_BOOL_CAST',
        'array'=>'T_ARRAY_CAST','object'=>'T_OBJECT_CAST','unset'=>'T_UNSET_CAST',
        'binary'=>'T_STRING_CAST',
    ];

    private const MULTI = [
        '==='=>'T_IS_IDENTICAL','!=='=>'T_IS_NOT_IDENTICAL','=='=>'T_IS_EQUAL',
        '!='=>'T_IS_NOT_EQUAL','<>'=>'T_IS_NOT_EQUAL','<='=>'T_IS_SMALLER_OR_EQUAL',
        '>='=>'T_IS_GREATER_OR_EQUAL','<=>'=>'T_SPACESHIP','->'=>'T_OBJECT_OPERATOR',
        '?->'=>'T_NULLSAFE_OBJECT_OPERATOR','=>'=>'T_DOUBLE_ARROW','::'=>'T_DOUBLE_COLON',
        '??'=>'T_COALESCE','??='=>'T_COALESCE_EQUAL','++'=>'T_INC','--'=>'T_DEC',
        '**'=>'T_POW','**='=>'T_POW_EQUAL','...'=>'T_ELLIPSIS','&&'=>'T_BOOLEAN_AND',
        '||'=>'T_BOOLEAN_OR','<<'=>'T_SL','>>'=>'T_SR','<<='=>'T_SL_EQUAL','>>='=>'T_SR_EQUAL',
        '+='=>'T_PLUS_EQUAL','-='=>'T_MINUS_EQUAL','*='=>'T_MUL_EQUAL','/='=>'T_DIV_EQUAL',
        '.='=>'T_CONCAT_EQUAL','%='=>'T_MOD_EQUAL','&='=>'T_AND_EQUAL','|='=>'T_OR_EQUAL',
        '^='=>'T_XOR_EQUAL','='=>'=','.'=>'.','+'=>'+','-'=>'-','*'=>'*','/'=>'/','%'=>'%',
        '<'=>'<','>'=>'>','!'=>'!','&'=>'&','|'=>'|','^'=>'^','~'=>'~','?'=>'?',':'=>':',
        ';'=>';','{'=>'{','}'=>'}','('=>'(',')'=>')','['=>'[',']'=>']','@'=>'@',
        ','=>',','\\'=>'T_NS_SEPARATOR',
    ];

    public static function tokenize(string $code): array {
        $tokens = [];
        $len = strlen($code);
        $i = 0;
        $line = 1;
        $inPhp = false;

        $push = function (string $type, ?string $value = null) use (&$tokens, &$line) {
            $tokens[] = ['type' => $type, 'value' => $value, 'line' => $line];
        };

        while ($i < $len) {
            // Outside PHP: copy HTML until next open tag.
            if (!$inPhp) {
                $next = strpos($code, '<?', $i);
                if ($next === false) { $i = $len; break; }
                if ($next > $i) $line += substr_count(substr($code, $i, $next - $i), "\n");
                $i = $next;
                if (strncmp(substr($code, $i), '<?=', 3) === 0) {
                    $push('T_OPEN_TAG', '<?='); $i += 3; $inPhp = true; continue;
                }
                // Consume "<?php" plus whitespace, or short "<?"
                $rest = substr($code, $i, 6);
                if (strncasecmp($rest, '<?php', 5) === 0) {
                    $j = $i + 5;
                    if ($j < $len && ctype_space($code[$j])) { if ($code[$j] === "\n") $line++; $j++; }
                    $push('T_OPEN_TAG', substr($code, $i, $j - $i));
                    $i = $j;
                } else {
                    $push('T_OPEN_TAG', '<?'); $i += 2;
                }
                $inPhp = true;
                continue;
            }

            $c = $code[$i];

            // Close tag.
            if ($c === '?' && isset($code[$i+1]) && $code[$i+1] === '>') {
                $push('T_CLOSE_TAG', '?>'); $i += 2; $inPhp = false; continue;
            }
            // Whitespace.
            if (ctype_space($c)) {
                if ($c === "\n") $line++;
                $i++; continue;
            }
            // Comments.
            if ($c === '/' && isset($code[$i+1]) && ($code[$i+1] === '/' || $code[$i+1] === '#')) {
                $nl = strpos($code, "\n", $i);
                $end = $nl === false ? $len : $nl;
                $i = $end; continue;
            }
            if ($c === '#') {
                if (strncmp(substr($code, $i, 2), '#[', 2) === 0) {
                    // Attribute — skip balanced brackets.
                    $depth = 0; $j = $i;
                    while ($j < $len) {
                        if ($code[$j] === '[') $depth++;
                        elseif ($code[$j] === ']') { $depth--; if ($depth === 0) { $j++; break; } }
                        elseif ($code[$j] === "\n") $line++;
                        $j++;
                    }
                    $i = $j; continue;
                }
                $nl = strpos($code, "\n", $i);
                $i = $nl === false ? $len : $nl; continue;
            }
            if ($c === '/' && isset($code[$i+1]) && $code[$i+1] === '*') {
                $j = $i + 2;
                while ($j < $len && !( $code[$j] === '*' && isset($code[$j+1]) && $code[$j+1] === '/')) {
                    if ($code[$j] === "\n") $line++;
                    $j++;
                }
                $i = min($len, $j + 2); continue;
            }
            // Variables.
            if ($c === '$') {
                if (preg_match('/\$([A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)/A', $code, $m, 0, $i)) {
                    $push('T_VARIABLE', $m[1]); $i += strlen($m[0]); continue;
                }
                $i++; continue;
            }
            // Labels / keywords.
            if (ctype_alpha($c) || $c === '_' || ord($c) >= 0x80) {
                if (preg_match('/[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*/A', $code, $m, 0, $i)) {
                    $word = $m[0];
                    $lower = strtolower($word);
                    if (in_array($lower, self::KEYWORDS, true)) {
                        $push('T_' . strtoupper($lower), $word);
                    } else {
                        $push('T_STRING', $word);
                    }
                    $i += strlen($word); continue;
                }
            }
            // Numbers.
            if (ctype_digit($c) || ($c === '.' && isset($code[$i+1]) && ctype_digit($code[$i+1]))) {
                if (preg_match('/0[xX][0-9a-fA-F]+(?:_[0-9a-fA-F]+)*|0[bB][01]+(?:_[01]+)*|0[oO]?[0-7]+(?:_[0-7]+)*|\d+(?:_\d+)*(?:\.\d+(?:_\d+)*)?(?:[eE][+-]?\d+)?|\.\d+(?:_\d+)*/A', $code, $m, 0, $i)) {
                    $raw = $m[0];
                    $type = (strpbrk($raw, '.eE') !== false && stripos($raw, '0x') !== 0) ? 'T_DNUMBER' : 'T_LNUMBER';
                    $push($type, $raw); $i += strlen($raw); continue;
                }
            }
            // Single/double quoted strings.
            if ($c === "'" || $c === '"') {
                $quote = $c;
                $j = $i + 1;
                while ($j < $len) {
                    if ($code[$j] === '\\' && isset($code[$j+1])) { $j += 2; continue; }
                    if ($code[$j] === $quote) { $j++; break; }
                    if ($code[$j] === "\n") $line++;
                    $j++;
                }
                $raw = substr($code, $i, $j - $i);
                if ($quote === "'") {
                    $push('T_CONSTANT_ENCAPSED_STRING', $raw);
                } elseif (!preg_match('/\$|(?<!\\\\)\{/', $raw)) {
                    // Double-quoted string without interpolation behaves like a constant string.
                    $push('T_CONSTANT_ENCAPSED_STRING', $raw);
                } else {
                    $push('T_TJ_DQ_STRING', $raw);
                }
                $i = $j; continue;
            }
            // Heredoc / nowdoc.
            if (strncmp(substr($code, $i), '<<<', 3) === 0) {
                $j = $i + 3;
                while ($j < $len && ctype_space($code[$j]) && $code[$j] !== "\n") $j++;
                $quoted = false; $label = '';
                if ($j < $len && ($code[$j] === "'" || $code[$j] === '"')) {
                    $q = $code[$j]; $quoted = ($q === "'"); $j++;
                    while ($j < $len && $code[$j] !== $q) { $label .= $code[$j]; $j++; }
                    $j++;
                } else {
                    while ($j < $len && (ctype_alnum($code[$j]) || $code[$j] === '_')) { $label .= $code[$j]; $j++; }
                }
                while ($j < $len && $code[$j] !== "\n") $j++;
                if ($j < $len) { $j++; $line++; }
                $start = $j;
                $close = "\n" . $label;
                $pos = strpos($code, $close, $j);
                if ($pos === false) { $i = $len; continue; }
                $body = substr($code, $start, $pos - $start);
                $line += substr_count($body, "\n") + 1;
                $j = $pos + strlen($close);
                while ($j < $len && ($code[$j] === ';' || $code[$j] === ',' || ctype_space($code[$j]))) {
                    if ($code[$j] === "\n") $line++;
                    if ($code[$j] === ';' || $code[$j] === ',') break;
                    $j++;
                }
                $push($quoted ? 'T_CONSTANT_ENCAPSED_STRING' : 'T_TJ_DQ_STRING', $body);
                $i = $j; continue;
            }
            // Casts: (int) etc.
            if ($c === '(' && preg_match('/\(\s*\??\s*([A-Za-z]+)\s*\)/A', $code, $m, 0, $i)) {
                $cast = strtolower($m[1]);
                if (isset(self::CASTS[$cast])) {
                    $push(self::CASTS[$cast], $m[0]); $i += strlen($m[0]); continue;
                }
            }
            // Multi/single char operators — longest match first.
            $matched = false;
            foreach ([4,3,2,1] as $llen) {
                if ($i + $llen > $len) continue;
                $piece = substr($code, $i, $llen);
                if (isset(self::MULTI[$piece])) {
                    $push(self::MULTI[$piece], $piece); $i += $llen; $matched = true; break;
                }
            }
            if ($matched) continue;

            // Unknown char — emit and move on.
            $push('T_UNKNOWN', $c);
            $i++;
        }

        $push(self::EOF);
        return $tokens;
    }
}
