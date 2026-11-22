<?php
/**
 * Report rendering: text (terminal), JSON (machine), markdown (ticket).
 */
final class Report {
    public static function json(array $result): string {
        return json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    public static function markdown(array $result): string {
        $md = [];
        $md[] = '# TypeWatch 类型比较安全扫描报告';
        $md[] = '';
        $md[] = sprintf('- 扫描文件: **%d** 个；解析错误: **%d**；发现: **%d** 条',
            count($result['scanned_files']), $result['parse_errors'], $result['finding_count']);
        $md[] = '- PHP 版本判定矩阵: `7.x` 与 `8.x` 分别标注可利用性';
        $md[] = '';
        foreach ($result['findings'] as $i => $f) {
            $a = $f['assessment'];
            $md[] = sprintf('## %d. [%s] %s — %s:%d',
                $i + 1, strtoupper($a['severity']), self::typeLabel($f['type']),
                basename($f['file']), $f['line']);
            $md[] = '';
            $md[] = '**问题:** ' . $f['message'];
            $md[] = '';
            $md[] = '**利用技术:** ' . $a['technique'];
            $md[] = '';
            $md[] = '**版本可利用性:**';
            foreach ($a['exploitable'] as $fam => $ok) {
                $md[] = sprintf('- PHP %s: %s', $fam, $ok ? '✅ 可利用' : '❌ 不可利用');
            }
            $md[] = '';
            $md[] = '**原理:** ' . $a['explanation'];
            $md[] = '';
            if ($f['dataflow']) {
                $md[] = '**数据流:**';
                foreach ($f['dataflow'] as $d) {
                    $chain = array_merge([$d['from']], $d['vars'] ?? []);
                    $tr = array_map(fn($t) => $t['desc'] ?? $t['op'], $d['transforms'] ?? []);
                    $md[] = sprintf('- `%s`%s',
                        implode(' → ', array_unique($chain)),
                        $tr ? '  转换: `' . implode(' → ', $tr) . '`' : '');
                }
                $md[] = '';
            }
            if ($f['pocs']) {
                $md[] = '**验证请求 (PoC):**';
                foreach ($f['pocs'] as $poc) {
                    $md[] = sprintf('- `%s %s?%s` — %s',
                        $poc['method'], $poc['entry'], $poc['query'], $poc['note']);
                }
                $md[] = '';
            }
            if ($a['preconditions']) {
                $md[] = '**前提条件:**';
                foreach ($a['preconditions'] as $pc) $md[] = "- $pc";
                $md[] = '';
            }
            $md[] = '**修复建议:** ' . $f['fix']['summary'];
            if (!empty($f['fix']['snippet'])) {
                $sn = $f['fix']['snippet'];
                if (isset($sn['before'], $sn['after'])) {
                    $md[] = '';
                    $md[] = '```php';
                    $md[] = '// 前: ' . $sn['before'];
                    $md[] = '// 后:';
                    $md[] = $sn['after'];
                    $md[] = '```';
                }
            }
            $md[] = '';
            $md[] = '---';
            $md[] = '';
        }
        return implode("\n", $md);
    }

    public static function text(array $result): string {
        $out = [];
        $out[] = Color::bold("TypeWatch — PHP 类型比较安全扫描");
        $out[] = sprintf("文件 %d 个 | 解析错误 %d | 发现 %d 条",
            count($result['scanned_files']), $result['parse_errors'], $result['finding_count']);
        $out[] = str_repeat('-', 78);

        foreach ($result['findings'] as $i => $f) {
            $a = $f['assessment'];
            $sevColor = ['high' => 'red', 'medium' => 'yellow', 'low' => 'cyan', 'info' => 'gray'][$a['severity']] ?? 'white';
            $out[] = Color::bold(sprintf("[%d] %s  %s  %s:%d",
                $i + 1,
                Color::paint(strtoupper($a['severity']), $sevColor),
                self::typeLabel($f['type']),
                $f['file'], $f['line']));
            $out[] = '  问题   : ' . $f['message'];
            $out[] = '  技术   : ' . $a['technique'];
            $families = [];
            foreach ($a['exploitable'] as $fam => $ok) {
                $families[] = "PHP {$fam}=" . ($ok ? Color::green('可利用') : Color::gray('不可利用'));
            }
            $out[] = '  版本   : ' . implode('  ', $families);
            $out[] = '  原理   : ' . wordwrap($a['explanation'], 72, "\n           ");
            if ($f['dataflow']) {
                foreach ($f['dataflow'] as $d) {
                    $chain = array_merge([$d['from']], $d['vars'] ?? []);
                    $tr = array_map(fn($t) => $t['desc'] ?? $t['op'], $d['transforms'] ?? []);
                    $out[] = Color::cyan('  数据流 : ') . implode(' → ', array_unique($chain)) .
                        ($tr ? '  [' . implode(' → ', $tr) . ']' : '');
                }
            }
            foreach ($f['pocs'] ?? [] as $poc) {
                $out[] = Color::yellow('  PoC    : ') . "{$poc['method']} {$poc['entry']}?{$poc['query']}";
                $out[] = "           {$poc['note']}";
            }
            foreach ($a['preconditions'] ?? [] as $pc) {
                $out[] = Color::gray('  前提   : ') . $pc;
            }
            $out[] = Color::magenta('  修复   : ') . $f['fix']['summary'];
            if (!empty($f['fix']['snippet']['after'])) {
                $after = $f['fix']['snippet']['after'];
                foreach (explode("\n", $after) as $line) $out[] = '           ' . Color::green($line);
            }
            $out[] = '';
        }
        return implode("\n", $out);
    }

    public static function verificationText(array $results): string {
        $out = [Color::bold("动态验证结果 (运行时 PHP " . PHP_VERSION . ")"), str_repeat('-', 78)];
        foreach ($results as $r) {
            if (isset($r['error'])) { $out[] = Color::red("  错误: {$r['error']}"); continue; }
            $color = $r['bypass_confirmed'] ? 'red' : 'green';
            $out[] = Color::paint($r['verdict'], $color) . "  [{$r['technique']} / {$r['kind']}]";
            $out[] = "  请求   : {$r['method']} {$r['url']}?{$r['request_query']}";
            $out[] = "  基线   : ?{$r['baseline_query']}";
            $out[] = "  状态码 : PoC={$r['poc_status']} 基线={$r['baseline_status']}";
            if ($r['poc_excerpt'] !== '') $out[] = "  响应   : " . $r['poc_excerpt'];
            $out[] = "  curl   : " . $r['curl'];
            $out[] = '';
        }
        return implode("\n", $out);
    }

    private static function typeLabel(string $type): string {
        return [
            'loose_equality' => '松散比较 (==/!=)',
            'strcmp_compare' => 'strcmp 系列比较',
            'in_array_loose' => 'in_array/array_search 非严格',
            'loose_switch'   => '松散 switch',
        ][$type] ?? $type;
    }
}

final class Color {
    private static bool $enabled = true;
    public static function disable(): void { self::$enabled = false; }
    public static function paint(string $s, string $color): string {
        if (!self::$enabled) return $s;
        $codes = ['red'=>31,'green'=>32,'yellow'=>33,'magenta'=>35,'cyan'=>36,'gray'=>90,'white'=>97];
        return "\033[" . ($codes[$color] ?? 97) . "m{$s}\033[0m";
    }
    public static function bold(string $s): string { return self::$enabled ? "\033[1m{$s}\033[0m" : $s; }
    public static function red(string $s): string { return self::paint($s, 'red'); }
    public static function green(string $s): string { return self::paint($s, 'green'); }
    public static function yellow(string $s): string { return self::paint($s, 'yellow'); }
    public static function cyan(string $s): string { return self::paint($s, 'cyan'); }
    public static function magenta(string $s): string { return self::paint($s, 'magenta'); }
    public static function gray(string $s): string { return self::paint($s, 'gray'); }
}
