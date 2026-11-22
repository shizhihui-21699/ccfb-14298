<?php
/**
 * RouteDiscovery — maps sink line numbers to the request parameters that select
 * their code path. Handles the common PHP router idiom at any nesting depth:
 *
 *   $action = $_GET['action'] ?? 'help';
 *   switch ($action) {
 *       case 'login_magic': ...   // line range
 *   }
 *
 * Also supports if/elseif chains comparing a route variable to string literals.
 */
final class RouteDiscovery {
    /** @var array<int, array<string,string>> line => [param => value] */
    private array $map = [];
    /** @var array<string, string> variable key ($action) => request param name (action) */
    private array $routeVars = [];

    public static function forProgram(array $ast): array {
        $self = new self();
        $self->walk($ast);
        return $self->map;
    }

    private function walk(mixed $node): void {
        if (!is_array($node)) return;
        $kind = $node['kind'] ?? '';

        if ($kind === 'assign' && ($node['target']['kind'] ?? '') === 'variable') {
            $param = $this->superglobalKey($node['expr']);
            if ($param !== null) {
                $this->routeVars['$' . $node['target']['name']] = $param;
            }
        }
        if ($kind === 'switch' && ($node['expr']['kind'] ?? '') === 'variable') {
            $varKey = '$' . $node['expr']['name'];
            if (isset($this->routeVars[$varKey])) {
                $param = $this->routeVars[$varKey];
                foreach ($node['cases'] ?? [] as $case) {
                    if ($case['cond'] === null || ($case['cond']['kind'] ?? '') !== 'string') continue;
                    $value = $case['cond']['value'];
                    $start = $case['cond']['line'] ?? $node['line'];
                    $end = $this->lastLine($case['stmts'] ?? []);
                    for ($ln = $start; $ln <= $end; $ln++) $this->map[$ln][$param] = $value;
                }
            }
        }
        if ($kind === 'if') $this->collectFromIf($node);

        foreach ($node as $k => $v) {
            if ($k === 'line') continue;
            $this->walk($v);
        }
    }

    private function collectFromIf(array $if): void {
        foreach ([$if, ...($if['elseifs'] ?? [])] as $branch) {
            if (!isset($branch['cond'])) continue;
            $hit = $this->routeLiteral($branch['cond']);
            if ($hit === null) continue;
            [$param, $value] = $hit;
            $body = $branch['body'] ?? [];
            $start = $body['line'] ?? ($branch['cond']['line'] ?? 0);
            $end = $this->lastLine($body['stmts'] ?? []);
            for ($ln = $start; $ln <= $end; $ln++) $this->map[$ln][$param] = $value;
        }
    }

    /** @return array{0:string,1:string}|null [param, value] */
    private function routeLiteral(array $cond): ?array {
        if (($cond['kind'] ?? '') !== 'binary' || !in_array($cond['op'] ?? '', ['==','==='], true)) return null;
        foreach (['left', 'right'] as $side) {
            $other = $side === 'left' ? 'right' : 'left';
            if (($cond[$side]['kind'] ?? '') === 'variable' &&
                isset($this->routeVars['$' . $cond[$side]['name']]) &&
                ($cond[$other]['kind'] ?? '') === 'string') {
                return [$this->routeVars['$' . $cond[$side]['name']], $cond[$other]['value']];
            }
        }
        return null;
    }

    private function superglobalKey(array $node): ?string {
        $target = $node;
        if (($node['kind'] ?? '') === 'coalesce') $target = $node['left'];
        if (($target['kind'] ?? '') === 'arrayfetch' &&
            ($target['var']['kind'] ?? '') === 'variable' &&
            in_array($target['var']['name'], TaintAnalyzer::SUPERGLOBALS, true) &&
            ($target['dim']['kind'] ?? '') === 'string') {
            return $target['dim']['value'];
        }
        return null;
    }

    private function lastLine(array $stmts): int {
        $max = 0;
        array_walk_recursive($stmts, function ($v, $k) use (&$max) {
            if ($k === 'line' && is_int($v)) $max = max($max, $v);
        });
        return $max;
    }
}
