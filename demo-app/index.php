<?php
/**
 * TypeWatch demo application — intentionally vulnerable endpoints.
 * Every endpoint returns JSON with an "ok"/"authenticated" marker so the
 * dynamic verifier can distinguish a successful bypass from a denial.
 *
 * Run: php -S 127.0.0.1:8791 -t demo-app
 */
declare(strict_types=1);

require __DIR__ . '/lib/auth.php';

header('Content-Type: application/json');

$action = $_GET['action'] ?? 'help';

function json_out(array $payload): never {
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

try {
    switch ($action) {
        // ---------------------------------------------------------------
        // 1. Magic-hash login: md5(input) == stored 0e... hash
        //    Exploitable on EVERY PHP version with a known md5 preimage.
        // ---------------------------------------------------------------
        case 'login_magic':
            $password = $_POST['password'] ?? '';
            $storedHash = '0e462097431906509019562988736854'; // md5("240610708")
            if (md5($password) == $storedHash) {
                json_out(['ok' => true, 'endpoint' => 'login_magic', 'marker' => 'AUTH_OK']);
            }
            json_out(['ok' => false, 'endpoint' => 'login_magic', 'marker' => 'AUTH_FAIL']);

        // ---------------------------------------------------------------
        // 2. Zero juggling: loose compare against integer 0.
        //    PHP 7: any non-numeric string passes. PHP 8: only 0e... style.
        // ---------------------------------------------------------------
        case 'login_zero':
            $code = $_POST['code'] ?? '';
            if ($code == 0) {
                json_out(['ok' => true, 'endpoint' => 'login_zero', 'marker' => 'AUTH_OK']);
            }
            json_out(['ok' => false, 'endpoint' => 'login_zero', 'marker' => 'AUTH_FAIL']);

        // ---------------------------------------------------------------
        // 3. strcmp(array) bypass — classic PHP 7 NULL == 0 trick.
        //    PHP 8 throws TypeError.
        // ---------------------------------------------------------------
        case 'token_strcmp':
            $token = $_POST['token'] ?? '';
            $secret = 's3cr3t-server-token';
            if (strcmp($token, $secret) == 0) {
                json_out(['ok' => true, 'endpoint' => 'token_strcmp', 'marker' => 'AUTH_OK']);
            }
            json_out(['ok' => false, 'endpoint' => 'token_strcmp', 'marker' => 'AUTH_FAIL']);

        // ---------------------------------------------------------------
        // 4. in_array() without strict flag — needle "abc" matches int 0
        //    on PHP 7; "0e1" matches on every version.
        // ---------------------------------------------------------------
        case 'role_check':
            $role = $_GET['role'] ?? '';
            $allowedRoles = ['admin', 'operator', 0 => 0];
            if (in_array($role, $allowedRoles)) {
                json_out(['ok' => true, 'endpoint' => 'role_check', 'marker' => 'ACCESS_GRANTED']);
            }
            json_out(['ok' => false, 'endpoint' => 'role_check', 'marker' => 'ACCESS_DENIED']);

        // ---------------------------------------------------------------
        // 5. Loose switch() — case 0 catches arbitrary strings on PHP 7
        //    and 0e... numeric strings on PHP 8.
        // ---------------------------------------------------------------
        case 'switch_login':
            $level = $_GET['level'] ?? '';
            switch ($level) {
                case 0:
                    json_out(['ok' => true, 'endpoint' => 'switch_login', 'granted' => true, 'marker' => 'ACCESS_GRANTED']);
                case 'admin':
                    json_out(['ok' => true, 'endpoint' => 'switch_login', 'granted' => true, 'marker' => 'ACCESS_GRANTED']);
                default:
                    json_out(['ok' => false, 'endpoint' => 'switch_login', 'marker' => 'ACCESS_DENIED']);
            }

        // ---------------------------------------------------------------
        // 6. Hashing function fed an array — NULL == NULL (PHP 7 only).
        // ---------------------------------------------------------------
        case 'digest_array':
            $sig = $_POST['sig'] ?? '';
            if (md5($sig) == md5('expected-signature-value')) {
                json_out(['ok' => true, 'endpoint' => 'digest_array', 'marker' => 'AUTH_OK']);
            }
            json_out(['ok' => false, 'endpoint' => 'digest_array', 'marker' => 'AUTH_FAIL']);

        // ---------------------------------------------------------------
        // 7. Layered flow: request -> normalizeInput -> wrapForCompare
        //    -> custom hash wrapper -> loose equality. Multi-hop taint.
        // ---------------------------------------------------------------
        case 'layered_token':
            $raw = $_POST['raw_token'] ?? '';
            $userToken = wrapForCompare($raw);
            $digest = computeDigest('md5', $userToken);
            $known = loadKnownToken();
            if ($digest == $known) {
                json_out(['ok' => true, 'endpoint' => 'layered_token', 'marker' => 'AUTH_OK']);
            }
            json_out(['ok' => false, 'endpoint' => 'layered_token', 'marker' => 'AUTH_FAIL']);

        // ---------------------------------------------------------------
        // 8. Safe reference implementation — strict comparison and
        //    hash_equals; must produce no high-severity finding.
        // ---------------------------------------------------------------
        case 'safe_login':
            $password = $_POST['password'] ?? '';
            if (!is_string($password)) {
                json_out(['ok' => false, 'endpoint' => 'safe_login', 'marker' => 'AUTH_FAIL']);
            }
            $storedHash = '0e462097431906509019562988736854';
            if (hash_equals($storedHash, md5($password)) === true) {
                json_out(['ok' => true, 'endpoint' => 'safe_login', 'marker' => 'AUTH_OK']);
            }
            json_out(['ok' => false, 'endpoint' => 'safe_login', 'marker' => 'AUTH_FAIL']);

        default:
            json_out([
                'ok' => true,
                'app' => 'TypeWatch demo',
                'actions' => [
                    'login_magic (POST password)',
                    'login_zero (POST code)',
                    'token_strcmp (POST token)',
                    'role_check (GET role)',
                    'switch_login (GET level)',
                    'digest_array (POST sig)',
                    'layered_token (POST raw_token)',
                    'safe_login (POST password)',
                ],
            ]);
    }
} catch (\TypeError $e) {
    // PHP 8 behavior for array arguments to string functions.
    json_out(['ok' => false, 'error' => 'TypeError: ' . $e->getMessage(), 'marker' => 'TYPE_ERROR']);
}
