<?php
/**
 * VersionRules — the PHP-version-aware exploitability engine.
 *
 * Encodes the semantic differences that matter for type-juggling attacks:
 *
 *  PHP 7.x:
 *   - "abc" == 0          -> true  (non-numeric string juggled to 0)
 *   - "123abc" == 123     -> true  (leading-numeric string converted with warning)
 *   - md5($_GET['x'])     with array arg -> warning, md5() returns NULL -> NULL == NULL true
 *   - strcmp(array(),"x") -> warning, returns NULL -> NULL == 0 true
 *
 *  PHP 8.x:
 *   - "abc" == 0          -> FALSE (string vs number: numeric-string conversion only)
 *   - "123abc" == 123     -> FALSE
 *   - md5(array)          -> TypeError
 *   - strcmp(array, ...)  -> TypeError
 *   - 0 == "0e123"        -> STILL true (0e123 IS a numeric string, equals zero)
 *   - magic hash == magic hash -> true in every version (both numeric strings, both 0)
 *   - true == anything non-empty -> true in every version
 */
final class VersionRules {
    public const FAMILY_7 = '7.x';
    public const FAMILY_8 = '8.x';
    public const FAMILY_ALL = 'all';

    public static function families(): array { return [self::FAMILY_7, self::FAMILY_8]; }

    /**
     * Main entry: turn a raw finding into an exploitability assessment.
     * @return array{exploitable:array<string,bool>, severity:string, technique:string,
     *               explanation:string, payloads:array, preconditions:string[]}
     */
    public static function assess(array $finding): array {
        return match ($finding['type']) {
            'loose_equality' => self::assessLooseEquality($finding),
            'strcmp_compare' => self::assessStrcmp($finding),
            'in_array_loose' => self::assessInArray($finding),
            'loose_switch'   => self::assessSwitch($finding),
            default          => self::unknown($finding),
        };
    }

    // ---------------------------------------------------------------
    // loose_equality
    // ---------------------------------------------------------------
    private static function assessLooseEquality(array $f): array {
        $taintedSide = self::taintedSide($f);
        if ($taintedSide === null) {
            return self::result(['7.x' => false, '8.x' => false], 'info', 'n/a',
                'No user-controlled operand reaches this comparison.', [], []);
        }
        $otherSide = $taintedSide === 'left' ? $f['right'] : $f['left'];
        $taint = $taintedSide === 'left' ? $f['left'] : $f['right'];
        $lit = $otherSide['literal'];
        $hashAlgo = self::hashAlgoOf($taint);

        // Both sides tainted (e.g. two request params, or md5(input) compared with md5(input)).
        if ($otherSide['tainted'] && $lit === null) {
            $both = self::bothSidesControlled($f);
            if ($both !== null) return $both;
        }

        $literalKind = $lit['kind'] ?? 'mixed';

        // ---- integer literal side ----
        if ($literalKind === 'int') {
            $n = (int)$lit['value'];
            if ($n === 0) {
                // Magic-hash flow: hash(input) == "0e..." or hash(input) == 0
                if ($hashAlgo !== null) {
                    $preimages = MagicHash::preimagesForTransform($hashAlgo);
                    if ($preimages) {
                        return self::result(['7.x' => true, '8.x' => true], 'high',
                            'magic-hash (zero exponent)',
                            "{$hashAlgo}(input) is compared with == against 0; a known preimage hashes to 0e\\d+ "
                            . 'which equals 0 under loose comparison in every PHP version.',
                            array_map(fn($p) => ['kind' => 'magic_hash', 'algo' => $hashAlgo, 'value' => $p], $preimages),
                            ["Input flows through {$hashAlgo}() before comparison"]);
                    }
                }
                // Plain "input == 0": classic zero juggling
                return self::result(['7.x' => true, '8.x' => false], 'high',
                    'zero juggling',
                    'Any non-numeric string (e.g. "abc") juggles to 0 in PHP 7.x so "abc" == 0 is true. '
                    . 'PHP 8.x compares strings to numbers numerically only when the string is numeric; '
                    . 'the same payload returns false there (0 == "0e..." style numeric strings still work).',
                    [
                        ['kind' => 'non_numeric_string', 'value' => 'abc'],
                        ['kind' => 'numeric_zero_string', 'value' => '0e1', 'works' => ['7.x' => true, '8.x' => true]],
                    ],
                    []);
            }
            // Non-zero int: exploit needs leading-numeric prefix in PHP7, numeric string in both.
            return self::result(['7.x' => true, '8.x' => true], 'medium',
                'numeric-string match',
                "\"{$n}\" == {$n} is true in every version because the numeric string converts exactly. "
                . 'PHP 7.x additionally accepts leading-numeric junk like "' . $n . 'abc".',
                [
                    ['kind' => 'numeric_string', 'value' => (string)$n],
                    ['kind' => 'leading_numeric', 'value' => $n . 'abc', 'works' => ['7.x' => true, '8.x' => false]],
                ],
                []);
        }

        // ---- string literal side ----
        if ($literalKind === 'string') {
            $s = (string)$lit['value'];
            if (MagicHash::isMagicHashLiteral($lit)) {
                if ($hashAlgo !== null) {
                    $preimages = MagicHash::preimagesForTransform($hashAlgo);
                    if ($preimages) {
                        return self::result(['7.x' => true, '8.x' => true], 'high',
                            'magic hash collusion',
                            "Stored hash '{$s}' has form 0e\\d+; another 0e\\d+ digest compares equal with == "
                            . 'in every PHP version because both are numeric strings evaluating to 0.',
                            array_map(fn($p) => ['kind' => 'magic_hash', 'algo' => $hashAlgo, 'value' => $p], $preimages),
                            ["Tainted operand is hashed with {$hashAlgo}()"]);
                    }
                }
                // No hash transform: attacker can simply send the magic string itself.
                return self::result(['7.x' => true, '8.x' => true], 'high',
                    'magic-hash string equality',
                    "'{$s}' == '{$s}' trivially holds; the 0e\\d+ form also equals 0 and any other 0e\\d+ string.",
                    [['kind' => 'literal_reuse', 'value' => $s]], []);
            }
            if (is_numeric($s)) {
                return self::result(['7.x' => true, '8.x' => true], 'medium',
                    'numeric-string equality',
                    "The comparison target '{$s}' is numeric; sending it (or a numerically equal form) satisfies ==.",
                    [['kind' => 'numeric_string', 'value' => $s]], []);
            }
            // Non-numeric string: equality holds only with the exact string — no juggling win,
            // unless PHP7 zero-juggling applies on the OTHER side (handled above with int 0).
            return self::result(['7.x' => false, '8.x' => false], 'low',
                'exact string required',
                "Target '{$s}' is a non-numeric string; == and === behave identically here for string inputs. "
                . 'Loose comparison remains a code smell but offers no type-juggling bypass.',
                [['kind' => 'exact_string', 'value' => $s]],
                ['No numeric conversion possible on either side']);
        }

        // ---- bool literal ----
        if ($literalKind === 'bool') {
            if ($lit['value'] === true) {
                return self::result(['7.x' => true, '8.x' => true], 'high',
                    'boolean truthiness',
                    'true == <any non-empty/non-zero value>; a normal non-empty parameter already satisfies the check. '
                    . 'The comparison cannot distinguish a valid token from arbitrary truthy input.',
                    [['kind' => 'truthy', 'value' => '1']], []);
            }
            return self::result(['7.x' => true, '8.x' => true], 'medium',
                'boolean falsiness',
                    'false == "" and false == "0" in every version; empty/falsy input satisfies the guard.',
                [['kind' => 'falsy', 'value' => ''], ['kind' => 'falsy', 'value' => '0']], []);
        }

        // ---- null literal ----
        if ($literalKind === 'null') {
            return self::result(['7.x' => true, '8.x' => true], 'high',
                'null comparison',
                'null == "" and null == false in every version; an empty parameter bypasses the guard. '
                . 'In PHP 7.x null == 0 also holds.',
                [['kind' => 'empty_string', 'value' => '']], []);
        }

        // ---- float ----
        if ($literalKind === 'float') {
            return self::result(['7.x' => true, '8.x' => true], 'medium',
                'float juggling',
                'Numeric strings convert to float; a numerically equal string satisfies == in every version.',
                [['kind' => 'numeric_string', 'value' => rtrim(rtrim(number_format((float)$lit['value'], 12, '.', ''), '0'), '.')]], []);
        }

        // ---- fallback: hashed tainted value vs a non-literal (e.g. md5(constant), function-returned hash) ----
        if ($hashAlgo !== null && $lit === null && !$otherSide['tainted']) {
            $otherHashed = self::hashAlgoOf($otherSide) !== null;
            if ($otherHashed) {
                // hash(input) == hash(secret): no static knowledge that either digest is 0e.
                // The reliable vector is PHP 7 array NULL degradation on the tainted side.
                return self::result(
                    ['7.x' => true, '8.x' => false],
                    'high',
                    'hash-vs-hash array NULL collision',
                    "The tainted value is hashed ({$hashAlgo}) and compared with another hash output. "
                    . 'On PHP 7.x an array argument makes the hash function return NULL, and NULL == NULL '
                    . 'passes; PHP 8.x raises a TypeError. A magic-hash collision is only possible if the '
                    . 'reference digest is itself 0e\d+ (review the stored value).',
                    [['kind' => 'array', 'value' => [],
                      'works' => ['7.x' => true, '8.x' => false],
                      'note' => 'PHP 7: hash(array)=NULL; PHP 8: TypeError']],
                    ['Reference hash digest should be inspected for 0e\\d+ form']
                );
            }
            $preimages = MagicHash::preimagesForTransform($hashAlgo);
            if ($preimages) {
                return self::result(['7.x' => true, '8.x' => true], 'high',
                    'magic-hash (zero exponent)',
                    "The tainted operand is hashed with {$hashAlgo}() then compared with ==. A known preimage "
                    . 'produces a 0e\d+ digest; if the other side is also a 0e\d+ hash (or 0), the guard passes '
                    . 'in every PHP version. Confirm the stored value is a 0e\d+ hash.',
                    array_map(fn($p) => ['kind' => 'magic_hash', 'algo' => $hashAlgo, 'value' => $p], $preimages),
                    ["Other side is a hash digest (verify it has 0e\\d+ form)"]);
            }
        }

        return self::unknown($f);
    }
    private static function assessStrcmp(array $f): array {
        $func = $f['func'] ?? 'strcmp';
        return self::result(
            ['7.x' => true, '8.x' => false],
            'high',
            'array argument TypeError/NULL bypass',
            "{$func}() expects strings. In PHP 7.x passing an array raises a warning and returns NULL; "
            . "the surrounding `{$func}(...) == 0` guard then sees NULL == 0 = true. PHP 8.x throws a TypeError instead.",
            [['kind' => 'array', 'value' => [], 'php8' => 'TypeError — fatal, no bypass']],
            ['The guard must compare the return value against 0 (standard idiom)']
        );
    }

    // ---------------------------------------------------------------
    // in_array / array_search
    // ---------------------------------------------------------------
    private static function assessInArray(array $f): array {
        $func = $f['code'] ?? 'in_array';
        $taintedSide = self::taintedSide($f);
        $otherSide = $taintedSide === 'left' ? $f['right'] : $f['left'];
        $payloads = [
            ['kind' => 'non_numeric_string', 'value' => 'abc', 'works' => ['7.x' => true, '8.x' => false]],
            ['kind' => 'numeric_zero_string', 'value' => '0e1', 'works' => ['7.x' => true, '8.x' => true]],
        ];
        return self::result(
            ['7.x' => true, '8.x' => true],
            'high',
            'loose needle/haystack matching',
            "{$func}() without strict=true compares the needle to every haystack element with ==. "
            . 'If the haystack contains 0, any non-numeric needle matches it in PHP 7.x; 0e-style numeric strings '
            . 'match zero elements in every version. Whether exploitation succeeds depends on haystack contents — '
            . 'review the literal array / stored values.',
            $payloads,
            ['Haystack contains a 0 or 0e... element (inspect runtime values)',
             'Needle is user-controlled: ' . implode(', ', self::sourceKeys($taintedSide === 'left' ? $f['left'] : $f['right']))]
        );
    }

    // ---------------------------------------------------------------
    // switch
    // ---------------------------------------------------------------
    private static function assessSwitch(array $f): array {
        return self::result(
            ['7.x' => true, '8.x' => true],
            'medium',
            'loose switch case matching',
            'switch() matches cases with ==. An int-0 case matches "0e..." numeric strings in every version and '
            . 'any non-numeric string in PHP 7.x; bool/string cases follow the same juggling matrix as loose equality.',
            [
                ['kind' => 'numeric_zero_string', 'value' => '0e1'],
                ['kind' => 'non_numeric_string', 'value' => 'abc', 'works' => ['7.x' => true, '8.x' => false]],
            ],
            ['At least one case is int 0, bool, null or a 0e... string']
        );
    }

    // ---------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------
    private static function unknown(array $f): array {
        return self::result(['7.x' => false, '8.x' => false], 'info', 'unknown',
            $f['message'] ?? 'Manual review required.', [], []);
    }

    private static function result(array $exploitable, string $severity, string $technique,
                                   string $explanation, array $payloads, array $preconditions): array {
        return [
            'exploitable' => $exploitable,
            'severity' => $severity,
            'technique' => $technique,
            'explanation' => $explanation,
            'payloads' => $payloads,
            'preconditions' => $preconditions,
        ];
    }

    private static function taintedSide(array $f): ?string {
        $lt = $f['left']['tainted'] ?? false;
        $rt = $f['right']['tainted'] ?? false;
        if ($lt && !$rt) return 'left';
        if ($rt && !$lt) return 'right';
        if ($lt && $rt) return 'left';
        return null;
    }

    private static function sourceKeys(array $term): array {
        return $term['sources'] ?? [];
    }

    /**
     * Walk the transform chain to find a hashing operation applied to the tainted value.
     * Returns the algorithm ('md5','sha1','sha256') or null.
     */
    private static function hashAlgoOf(array $term): ?string {
        foreach (array_reverse($term['transforms'] ?? []) as $tr) {
            $op = $tr['op'] ?? '';
            if (in_array($op, ['md5', 'sha1', 'sha256'], true)) return $op;
            if (str_starts_with($op, 'hash:')) return substr($op, 5);
            if ($op === 'hash_hmac') return null; // keyed hash — preimage attack not applicable
        }
        return null;
    }

    /**
     * Both operands are tainted (or neither carries a concrete literal). Two sub-cases:
     *  - hash(input) == hash(fixed-secret): a magic preimage works ONLY if the secret's
     *    digest happens to be 0e\d+ (not statically knowable); the reliable vector is the
     *    PHP 7 array -> NULL == NULL degradation.
     *  - two request-controlled values: identical chosen inputs always match.
     */
    private static function bothSidesControlled(array $f): ?array {
        $l = $f['left']; $r = $f['right'];
        if (!($l['tainted'] && $r['tainted'] && $l['literal'] === null && $r['literal'] === null)) {
            return null;
        }
        $leftHashed = self::hashAlgoOf($l) !== null;
        $rightHashed = self::hashAlgoOf($r) !== null;

        if ($leftHashed && $rightHashed) {
            // Both sides pass through a hash function. The version-stable vector is the
            // array-argument NULL degradation on PHP 7; magic hashes are conditional.
            return self::result(
                ['7.x' => true, '8.x' => false],
                'high',
                'hash-vs-hash array NULL collision',
                'Both operands are hashed before ==. On PHP 7.x an array argument makes the hash '
                . 'function return NULL (with a warning), so NULL == NULL passes the guard. PHP 8.x '
                . 'turns the array argument into a TypeError. A magic-hash collision is additionally '
                . 'possible only if the reference digest is itself 0e\d+.',
                [
                    ['kind' => 'array', 'value' => [],
                     'works' => ['7.x' => true, '8.x' => false],
                     'note' => 'PHP 7: hash(array)=NULL on both sides; PHP 8: TypeError'],
                ],
                ['Both comparison operands are hash() outputs', 'Reference digest must be reviewed for 0e\\d+ form']
            );
        }

        $arrayOn7 = ['7.x' => true, '8.x' => false];
        return self::result(
            ['7.x' => true, '8.x' => true],
            'high',
            'both operands request-controlled',
            'Both sides of the comparison derive from request input. An attacker supplies identical '
            . 'inputs so the values match directly; on PHP 7.x array arguments additionally degrade '
            . 'string functions to NULL, so NULL == NULL passes.',
            [
                ['kind' => 'equal_pairs', 'note' => 'send the same value through both parameter paths'],
                ['kind' => 'array', 'value' => [], 'works' => $arrayOn7,
                 'note' => 'PHP 7: NULL == NULL; PHP 8: TypeError'],
            ],
            ['Attacker controls both parameter paths']
        );
    }
}
