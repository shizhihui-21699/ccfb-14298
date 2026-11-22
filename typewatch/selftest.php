<?php
/**
 * TypeWatch self-test — no external framework, plain assertions.
 * Covers: parser correctness, taint propagation (incl. multi-hop),
 * version-rule matrix, and end-to-end findings on synthetic snippets.
 */

require __DIR__ . '/src/autoload.php';

$pass = 0; $fail = 0;
function check(string $name, bool $cond, string $detail = ''): void {
    global $pass, $fail;
    if ($cond) { $pass++; echo Color::green("  PASS") . " {$name}\n"; }
    else { $fail++; echo Color::red("  FAIL") . " {$name}" . ($detail ? " — {$detail}" : '') . "\n"; }
}

function analyze(string $code): array {
    $ast = Parser::parseCode("<?php\n" . $code);
    $an = new TaintAnalyzer();
    $an->analyzeFile('snippet.php', $ast);
    $an->analyzeProgramStmts('snippet.php', $ast['stmts']);
    foreach ($an->getFunctions() as $sum) $an->analyzeFunctionBody($sum);
    return $an->getFindings();
}

echo Color::bold("== Parser ==\n");
$ast = Parser::parseCode('<?php $x = 1 + 2 * 3; if ($a == $b) { foo($x, ["k" => $v]); }');
check('program parsed', $ast['kind'] === 'program' && count($ast['stmts']) === 2);
check('no parse errors', !str_contains(json_encode($ast), '"parseerror"'));

$ast2 = Parser::parseCode('<?php function f(int $x, string $y = "a"): bool { return $x === 1; }');
check('function with typed signature parsed', isset($ast2['stmts'][0]['params'][1]['default']['value']) && $ast2['stmts'][0]['params'][1]['default']['value'] === 'a');

$ast3 = Parser::parseCode('<?php $z = in_array($needle, $haystack, true);');
check('call node parsed', $ast3['stmts'][0]['expr']['kind'] === 'assign' && $ast3['stmts'][0]['expr']['expr']['kind'] === 'call');

echo Color::bold("\n== Taint sources & propagation ==\n");
$f = analyze('$x = $_GET["p"]; if ($x == "ok") {}');
check('$_GET source reaches == sink', count($f) === 1 && $f[0]['type'] === 'loose_equality');
check('source label recorded', str_contains(json_encode($f[0]['dataflow']), '$_GET[p]') || str_contains(json_encode($f[0]['dataflow']), '$_GET'));

$f = analyze('$x = $_POST["p"]; $y = trim($x); $z = md5($y); if ($z == "0e123") {}');
check('multi-hop taint (trim+md5)', count($f) === 1);
check('transform chain includes md5', !empty($f) && str_contains(json_encode($f[0]), 'md5'));

$f = analyze('function clean($v){ return strtolower(trim($v)); } $u = clean($_GET["u"]); if ($u == 0) {}');
check('interprocedural taint through user function', count($f) === 1, json_encode(array_map(fn($x)=>$x['type'], $f)));

$f = analyze('$a = 1; $b = 2; if ($a == $b) {}');
check('clean comparison not flagged', count($f) === 0);

$f = analyze('if (in_array($_GET["r"], $roles)) {}');
check('in_array loose mode flagged', count($f) === 1 && $f[0]['type'] === 'in_array_loose');

$f = analyze('if (in_array($_GET["r"], $roles, true)) {}');
check('in_array strict mode not flagged', count($f) === 0);

$f = analyze('if (strcmp($_POST["t"], $secret) == 0) {}');
check('strcmp family flagged', count($f) >= 1 && $f[0]['type'] === 'strcmp_compare');

$f = analyze('switch ($_GET["l"]) { case 0: break; }');
check('loose switch flagged', count($f) === 1 && $f[0]['type'] === 'loose_switch');

$f = analyze('if ($_GET["a"] === $_GET["b"]) {}');
check('strict === not flagged', count($f) === 0);

$f = analyze('$x = (int)$_GET["n"]; if ($x == 0) {}');
check('int-cast taint still tracked', count($f) === 1);

echo Color::bold("\n== Version rule matrix ==\n");
$f = analyze('if ($_GET["p"] == 0) {}');
$a = VersionRules::assess($f[0]);
check('"abc"==0 exploitable on 7.x', $a['exploitable']['7.x'] === true);
check('"abc"==0 NOT exploitable on 8.x', $a['exploitable']['8.x'] === false);
check('zero-juggle payload present', collect_values($a['payloads'], 'non_numeric_string') === true);

$f = analyze('if (md5($_GET["p"]) == "0e462097431906509019562988736854") {}');
$a = VersionRules::assess($f[0]);
check('magic hash exploitable on BOTH versions', $a['exploitable']['7.x'] === true && $a['exploitable']['8.x'] === true);
check('md5 preimage suggested', str_contains(json_encode($a['payloads']), '240610708'));

$f = analyze('if (strcmp($_GET["p"], "x") == 0) {}');
$a = VersionRules::assess($f[0]);
check('strcmp array bypass 7.x only', $a['exploitable']['7.x'] === true && $a['exploitable']['8.x'] === false);

$f = analyze('if ($_GET["p"] == true) {}');
$a = VersionRules::assess($f[0]);
check('bool true comparison exploitable both', $a['exploitable']['7.x'] === true && $a['exploitable']['8.x'] === true);

$f = analyze('if ($_GET["p"] == 123) {}');
$a = VersionRules::assess($f[0]);
check('numeric string "123" works both versions', $a['exploitable']['7.x'] === true && $a['exploitable']['8.x'] === true);

$f = analyze('if ($_GET["p"] == "plain-text") {}');
$a = VersionRules::assess($f[0]);
check('non-numeric string target: no juggling bypass', $a['exploitable']['7.x'] === false && $a['exploitable']['8.x'] === false);

$f = analyze('if (md5($_GET["p"]) == md5("fixed-secret")) {}');
$a = VersionRules::assess($f[0]);
check('hash-vs-hash recommends array NULL vector on 7.x only',
    $a['exploitable']['7.x'] === true && $a['exploitable']['8.x'] === false &&
    collect_values($a['payloads'], 'array'));

$f = analyze('if (md5($_GET["a"]) == md5($_GET["b"])) {}');
$a = VersionRules::assess($f[0]);
check('two tainted hashes: equal-pairs/array vector offered',
    $a['exploitable']['7.x'] === true && count($a['payloads']) >= 1);

echo Color::bold("\n== PoC construction ==\n");
$f = analyze('if ($_POST["password"] == 0) {}');
$a = VersionRules::assess($f[0]);
$pocs = ExploitBuilder::build($f[0], $a, '/index.php');
check('PoC generated', count($pocs) >= 1);
check('PoC uses POST for $_POST source', $pocs[0]['method'] === 'POST');
check('PoC query contains password=', str_contains($pocs[0]['query'], 'password='));
check('baseline request differs', $pocs[0]['baseline_query'] !== $pocs[0]['query']);

$f = analyze('if (strcmp($_POST["token"], "x") == 0) {}');
$a = VersionRules::assess($f[0]);
$pocs = ExploitBuilder::build($f[0], $a, '/index.php');
check('array payload rendered as token[]=', str_contains($pocs[0]['query'], 'token%5B%5D') || str_contains($pocs[0]['query'], 'token[]'));

echo Color::bold("\n== Magic hash table runtime validation ==\n");
foreach (MagicHash::PREIMAGES as $algo => $preimages) {
    foreach ($preimages as $p) {
        $h = $algo === 'md5' ? md5($p) : ($algo === 'sha1' ? sha1($p) : hash($algo, $p));
        check("{$algo} preimage '{$p}' really hashes to 0e\\d+", (bool)preg_match('/^0+e\d+$/', $h), "got {$h}");
    }
}

echo Color::bold("\n== Fix advice ==\n");
$f = analyze('if (md5($_GET["p"]) == "0e1") {}');
$fix = FixAdvisor::advise($f[0]);
check('hash finding recommends hash_equals', str_contains(json_encode($fix), 'hash_equals'));
$f = analyze('if (in_array($_GET["r"], $x)) {}');
$fix = FixAdvisor::advise($f[0]);
check('in_array finding recommends strict=true', str_contains(json_encode($fix), 'true'));

echo Color::bold("\n== Demo app end-to-end ==\n");
$scanner = new Scanner();
$res = $scanner->scan([__DIR__ . '/../demo-app'], '/index.php');
$types = array_map(fn($x) => $x['type'], $res['findings']);
check('demo scan finds loose equalities', in_array('loose_equality', $types, true));
check('demo scan finds strcmp issue', in_array('strcmp_compare', $types, true));
check('demo scan finds in_array issue', in_array('in_array_loose', $types, true));
check('demo scan finds loose switch', in_array('loose_switch', $types, true));
$safeFindings = array_filter($res['findings'], fn($x) => str_contains($x['message'], '') && in_array($x['line'], [0], true));
check('parse error count is zero', $res['parse_errors'] === 0, 'parse errors: ' . $res['parse_errors']);

echo "\n" . Color::bold(sprintf("Self-test: %d passed, %d failed\n", $pass, $fail));
exit($fail === 0 ? 0 : 1);

function collect_values(array $payloads, string $kind): bool {
    foreach ($payloads as $p) if (($p['kind'] ?? '') === $kind) return true;
    return false;
}
