<?php
/**
 * FixAdvisor — concrete remediation snippets per finding type, with rationale.
 */
final class FixAdvisor {
    public static function advise(array $finding): array {
        return match ($finding['type']) {
            'loose_equality' => self::fixLooseEquality($finding),
            'strcmp_compare' => self::fixStrcmp($finding),
            'in_array_loose' => self::fixInArray($finding),
            'loose_switch'   => self::fixSwitch($finding),
            default          => [
                'summary' => 'Replace loose comparisons with strict type-safe checks.',
                'snippet' => null,
                'references' => ['https://www.php.net/manual/en/language.operators.comparison.php'],
            ],
        };
    }

    private static function fixLooseEquality(array $f): array {
        $op = $f['code'] ?? '==';
        $hashAlgo = self::hashAlgo($f);
        $isHash = $hashAlgo !== null || self::anySideMagicLiteral($f);

        if ($isHash) {
            return [
                'summary' => 'Hash/token comparison must use hash_equals(), which is timing-safe and type-strict.',
                'snippet' => self::hashEqualsSnippet($f, $op),
                'references' => [
                    'https://www.php.net/manual/en/function.hash-equals.php',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
                ],
                'notes' => [
                    'hash_equals() requires both arguments to be strings — an array argument raises TypeError instead of silently passing.',
                    'Keep the stored hash as the FIRST argument semantics do not affect equality, but never trim/cast user input beforehand.',
                ],
            ];
        }

        $strictOp = ($op === '!=' || $op === '<>') ? '!==' : '===';
        return [
            'summary' => "Replace loose '{$op}' with strict '{$strictOp}' and, where a string is expected, guard the type explicitly.",
            'snippet' => [
                'before' => "if (\$a {$op} \$b) { /* security branch */ }",
                'after'  => "if (!is_string(\$a) || !is_string(\$b)) {\n    throw new InvalidArgumentException('string expected');\n}\nif (\$a {$strictOp} \$b) { /* security branch */ }",
            ],
            'references' => ['https://www.php.net/manual/en/language.operators.comparison.php'],
            'notes' => [
                '=== rejects type-juggling entirely: "0e1" === 0 is false, "abc" === 0 is false.',
                'For numeric input, validate with is_numeric() then cast deliberately: (int)$_GET["id"] === $expected.',
                'Reject array parameters early: if (is_array($_GET["x"])) throw new InvalidArgumentException();',
            ],
        ];
    }

    private static function fixStrcmp(array $f): array {
        $func = $f['func'] ?? 'strcmp';
        return [
            'summary' => "Do not use {$func}() as an authentication guard; use hash_equals() for secrets or strict === for plain strings.",
            'snippet' => [
                'before' => "if ({$func}(\$_POST['token'], \$secret) === 0) { /* authorized */ }",
                'after'  => "if (!is_string(\$_POST['token']) || !is_string(\$secret)) {\n    throw new InvalidArgumentException('string expected');\n}\nif (hash_equals(\$secret, \$_POST['token'])) { /* authorized */ }",
            ],
            'references' => ['https://www.php.net/manual/en/function.hash-equals.php'],
            'notes' => [
                "In PHP 7.x {$func}(array(), ...) returns NULL with a warning, and NULL == 0 passes the guard.",
                'PHP 8.x turns that into a TypeError, but the idiom is still fragile — replace it regardless of runtime version.',
            ],
        ];
    }

    private static function fixInArray(array $f): array {
        $func = $f['code'] ?? 'in_array';
        return [
            'summary' => "Enable strict mode: pass `true` as the third argument of {$func}() so comparison uses ===.",
            'snippet' => [
                'before' => "{$func}(\$_POST['role'], \$allowedRoles)",
                'after'  => "{$func}(\$_POST['role'], \$allowedRoles, true)",
            ],
            'references' => ['https://www.php.net/manual/en/function.in-array.php'],
            'notes' => [
                'Without strict mode, a needle "abc" matches haystack element 0 on PHP 7.x; "0e1" matches 0 on every version.',
                'For array_search() the same third-argument strict flag applies; inspect the returned key afterwards.',
            ],
        ];
    }

    private static function fixSwitch(array $f): array {
        return [
            'summary' => 'Replace loose switch() with an explicit strict match statement or a strict comparison map.',
            'snippet' => [
                'before' => "switch (\$_GET['role']) {\n    case 0:        \$granted = true; break;\n    case 'admin':  \$granted = true; break;\n}",
                'after'  => "\$role = \$_GET['role'];\nif (!is_string(\$role)) {\n    throw new InvalidArgumentException('string expected');\n}\n\$allowed = ['admin', 'operator'];\$granted = in_array(\$role, \$allowed, true);",
            ],
            'references' => ['https://www.php.net/manual/en/control-structures.match.php'],
            'notes' => [
                'PHP 8 match() still uses === for arm matching, so match(true){} with identity checks is also safe.',
                'Never use int 0 as a case label for user-supplied strings.',
            ],
        ];
    }

    private static function hashEqualsSnippet(array $f, string $op): array {
        $strictOp = ($op === '!=' || $op === '<>') ? '!' : '';
        return [
            'before' => "if (md5(\$_POST['password']) {$op} \$storedHash) { /* authenticated */ }",
            'after'  => "\$input = \$_POST['password'] ?? '';\nif (!is_string(\$input) || !is_string(\$storedHash)) {\n    throw new InvalidArgumentException('string expected');\n}\nif ({$strictOp}hash_equals(\$storedHash, md5(\$input))) { /* authenticated */ }",
        ];
    }

    private static function hashAlgo(array $f): ?string {
        foreach (['left', 'right'] as $side) {
            foreach (array_reverse($f[$side]['transforms'] ?? []) as $tr) {
                if (in_array($tr['op'] ?? '', ['md5', 'sha1', 'sha256'], true)) return $tr['op'];
            }
        }
        return null;
    }

    private static function anySideMagicLiteral(array $f): bool {
        foreach (['left', 'right'] as $side) {
            $lit = $f[$side]['literal'] ?? null;
            if (MagicHash::isMagicHashLiteral($lit)) return true;
        }
        return false;
    }
}
