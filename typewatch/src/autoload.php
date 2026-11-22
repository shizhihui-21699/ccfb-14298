<?php
spl_autoload_register(function (string $class): void {
    $aliases = [
        'Color' => 'Report.php',
        'FuncSummary' => 'TaintTerm.php',
        'TaintTerm' => 'TaintTerm.php',
    ];
    $file = __DIR__ . '/' . ($aliases[$class] ?? $class . '.php');
    if (is_file($file)) require $file;
});
