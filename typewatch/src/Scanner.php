<?php
/**
 * Scanner — orchestrates parse → taint → version assessment → PoC build → fix.
 */
final class Scanner {
    private array $analyzers = [];
    private TaintAnalyzer $global;
    private int $parseErrors = 0;

    public function __construct() {
        $this->global = new TaintAnalyzer();
    }

    /**
     * @param string[] $paths files or directories
     */
    public function scan(array $paths, string $entryPoint = '/index.php'): array {
        $files = $this->expandPaths($paths);
        $asts = [];
        $routeMap = [];
        foreach ($files as $file) {
            $code = file_get_contents($file);
            if ($code === false) continue;
            try {
                $ast = Parser::parseCode($code);
            } catch (\Throwable $e) {
                $this->parseErrors++;
                $ast = ['kind' => 'program', 'stmts' => [], 'line' => 1];
            }
            $asts[$file] = $ast;
            $routeMap[$file] = RouteDiscovery::forProgram($ast);
            $this->countParseErrors($ast);
            $this->global->analyzeFile($file, $ast);
        }

        // Analyze global scope of every file and bodies of collected functions.
        foreach ($asts as $file => $ast) {
            $this->global->analyzeProgramStmts($file, $ast['stmts']);
        }
        foreach ($this->global->getFunctions() as $summary) {
            $this->global->analyzeFunctionBody($summary);
        }
        foreach ($this->global->getMethods() as $summary) {
            $this->global->analyzeFunctionBody($summary);
        }

        $raw = $this->global->getFindings();
        $findings = [];
        foreach ($raw as $f) {
            $assessment = VersionRules::assess($f);
            $routeParams = $routeMap[$f['file']][$f['line']] ?? [];
            $pocs = ExploitBuilder::build($f, $assessment, $entryPoint, $routeParams);
            $fix = FixAdvisor::advise($f);
            $f['assessment'] = $assessment;
            $f['route_params'] = $routeParams;
            $f['pocs'] = $pocs;
            $f['fix'] = $fix;
            $findings[] = $f;
        }

        usort($findings, fn($a, $b) => [
            ['high' => 0, 'medium' => 1, 'low' => 2, 'info' => 3][$a['assessment']['severity']] ?? 4,
            $a['file'], $a['line'],
        ] <=> [
            ['high' => 0, 'medium' => 1, 'low' => 2, 'info' => 3][$b['assessment']['severity']] ?? 4,
            $b['file'], $b['line'],
        ]);

        return [
            'tool' => 'TypeWatch',
            'scanned_files' => array_values($files),
            'parse_errors' => $this->parseErrors,
            'finding_count' => count($findings),
            'findings' => $findings,
        ];
    }

    private function countParseErrors(array $ast): void {
        array_walk_recursive($ast, function ($v) {
            if (is_array($v) && ($v['kind'] ?? '') === 'parseerror') $this->parseErrors++;
        });
    }

    private function expandPaths(array $paths): array {
        $files = [];
        foreach ($paths as $p) {
            if (is_file($p)) { $files[realpath($p)] = realpath($p); continue; }
            if (is_dir($p)) {
                $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($p, FilesystemIterator::SKIP_DOTS));
                foreach ($it as $f) {
                    if ($f->getExtension() === 'php') $files[realpath($f->getPathname())] = realpath($f->getPathname());
                }
            }
        }
        ksort($files);
        return array_values($files);
    }
}
