<?php
/**
 * DynamicVerifier — fires the constructed PoCs against a real PHP runtime
 * (the built-in development server) and diffs the response against a baseline.
 *
 * A PoC "succeeds" when the application emits a success marker that the benign
 * baseline request does not — i.e. the guard was actually bypassed.
 */
final class DynamicVerifier {
    /** Markers that unambiguously indicate the security branch was reached. */
    private const SUCCESS_MARKERS = [
        'AUTH_OK', 'LOGIN_OK', 'BYPASS_OK', 'ACCESS_GRANTED',
        '"authenticated":true', '"granted":true',
    ];
    private const FAIL_MARKERS = [
        '"ok":false', '"success":false', 'denied', 'forbidden', 'unauthorized',
        'Fatal error', 'TypeError', 'AUTH_FAIL', 'LOGIN_FAIL',
    ];

    public function __construct(
        private string $docRoot,
        private string $phpBin = 'php',
        private string $host = '127.0.0.1',
        private int $port = 8791,
    ) {}

    public function verifyAll(array $pocs, array $options = []): array {
        $server = $this->startServer();
        if ($server === null) {
            return [['error' => 'failed to start PHP built-in server']];
        }
        $results = [];
        try {
            foreach ($pocs as $poc) {
                $results[] = $this->verifyOne($poc, $options);
            }
        } finally {
            $this->stopServer($server);
        }
        return $results;
    }

    /** @return resource|null */
    private function startServer() {
        $cmd = sprintf(
            '%s -S %s:%d -t %s 2>&1',
            escapeshellcmd($this->phpBin),
            $this->host,
            $this->port,
            escapeshellarg($this->docRoot)
        );
        $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $proc = proc_open($cmd, $spec, $pipes);
        if (!is_resource($proc)) return null;
        // Wait for the socket to accept connections.
        $deadline = microtime(true) + 5.0;
        while (microtime(true) < $deadline) {
            $fp = @fsockopen($this->host, $this->port, $errno, $errstr, 0.3);
            if ($fp) { fclose($fp); return ['proc' => $proc, 'pipes' => $pipes]; }
            usleep(150_000);
        }
        $this->stopServer(['proc' => $proc, 'pipes' => $pipes]);
        return null;
    }

    private function stopServer(array $server): void {
        if (is_resource($server['proc'] ?? null)) {
            proc_terminate($server['proc'], 15);
            proc_close($server['proc']);
        }
    }

    private function verifyOne(array $poc, array $options): array {
        $base = "http://{$this->host}:{$this->port}";
        $entry = ltrim($poc['entry'] ?? '/index.php', '/');
        $routeQuery = $poc['route_query'] ?? '';
        $url = $base . '/' . $entry;
        $baselineUrl = $url;
        if ($routeQuery !== '') {
            $url .= '?' . $routeQuery;
            $baselineUrl = $url;
        }

        $pocResp = $this->send($poc['method'], $url, $poc['method'] === 'GET'
            ? ($poc['full_query'] ?? $poc['query']) : ($poc['query'] ?? ''));
        $baseResp = $this->send($poc['method'], $baselineUrl, $poc['method'] === 'GET'
            ? ($poc['baseline_full_query'] ?? ($poc['baseline_query'] ?? ''))
            : ($poc['baseline_query'] ?? ''));

        $pocHit = $this->securityBranchReached($pocResp['body']);
        $baseHit = $this->securityBranchReached($baseResp['body']);
        $bypassed = $pocHit && !$baseHit;

        $runtimeFamily = $this->runtimeFamily();
        $expected = $poc['works_on'][$runtimeFamily] ?? null;

        return [
            'technique' => $poc['technique'],
            'kind' => $poc['kind'],
            'method' => $poc['method'],
            'url' => $url,
            'route_query' => $routeQuery,
            'request_query' => $poc['query'],
            'baseline_query' => $poc['baseline_query'] ?? '',
            'poc_status' => $pocResp['status'],
            'baseline_status' => $baseResp['status'],
            'poc_excerpt' => $this->excerpt($pocResp['body']),
            'baseline_excerpt' => $this->excerpt($baseResp['body']),
            'runtime_php_family' => $runtimeFamily,
            'runtime_php_version' => PHP_VERSION,
            'expected_exploitable_on_runtime' => $expected,
            'bypass_confirmed' => $bypassed,
            'poc_type_error' => $this->hasTypeError($pocResp['body']),
            'verdict' => $this->verdict($bypassed, $expected, $pocResp),
            'curl' => ExploitBuilder::curlCommand($poc, $base),
        ];
    }

    private function send(string $method, string $url, string $query): array {
        if ($method !== 'POST' && $query !== '') {
            $url .= (str_contains($url, '?') ? '&' : '?') . $query;
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => false,
            CURLOPT_TIMEOUT => 8,
            CURLOPT_CONNECTTIMEOUT => 4,
            CURLOPT_HTTPHEADER => ['Connection: close'],
        ]);
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $query);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Connection: close',
                'Content-Type: application/x-www-form-urlencoded',
            ]);
        }
        $body = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        unset($ch); // curl_close() is a no-op (and deprecated) on PHP 8.5+
        return ['status' => $status, 'body' => $body === false ? '' : (string)$body];
    }

    private function hasSuccessMarker(string $body): bool {
        foreach (self::SUCCESS_MARKERS as $m) {
            if (stripos($body, $m) !== false) return true;
        }
        return false;
    }

    /**
     * Decide whether the response proves the protected branch executed.
     * Prefers structured JSON (ok/marker/granted/authenticated); falls back to text markers.
     */
    private function securityBranchReached(string $body): bool {
        $json = json_decode($body, true);
        if (is_array($json)) {
            if (array_key_exists('ok', $json) && $json['ok'] === true
                && !array_key_exists('actions', $json)) {
                // Real endpoint success (the help/default payload carries "actions", not a verdict).
                return true;
            }
            foreach (['granted', 'authenticated', 'success'] as $k) {
                if (($json[$k] ?? null) === true) return true;
            }
            if (in_array($json['marker'] ?? null, ['AUTH_OK', 'LOGIN_OK', 'BYPASS_OK', 'ACCESS_GRANTED'], true)) {
                return true;
            }
        }
        return $this->hasSuccessMarker($body);
    }

    private function hasTypeError(string $body): bool {
        return stripos($body, 'TypeError') !== false || stripos($body, 'must be of type') !== false;
    }

    private function verdict(bool $bypassed, ?bool $expected, array $resp): string {
        if ($bypassed) return 'BYPASS_CONFIRMED';
        if ($this->hasTypeError($resp['body'])) return 'TYPE_ERROR (PHP 8 rejects array/degraded argument — expected on 8.x)';
        if ($expected === false) return 'NOT_EXPLOITABLE_ON_RUNTIME (matches version rule prediction)';
        if ($resp['status'] >= 500) return 'RUNTIME_ERROR';
        return 'NO_BYPASS (guard held or marker not found — manual check advised)';
    }

    private function runtimeFamily(): string {
        return PHP_MAJOR_VERSION >= 8 ? VersionRules::FAMILY_8 : VersionRules::FAMILY_7;
    }

    private function excerpt(string $body): string {
        $body = trim(preg_replace('/\s+/', ' ', $body) ?? '');
        return strlen($body) > 240 ? substr($body, 0, 240) . '…' : $body;
    }
}
