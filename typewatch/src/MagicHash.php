<?php
/**
 * Magic-hash reference table: input strings whose cryptographic digest is of the
 * form 0e\d+ (all digits, scientific-notation zero), so two such hashes compare
 * equal under == in EVERY PHP version.
 */
final class MagicHash {
    /** @var array<string, string[]> algo => known preimages (verified against PHP runtime) */
    public const PREIMAGES = [
        'md5' => [
            '240610708',   // 0e462097431906509019562988736854
            'QNKCDZO',     // 0e830400451993494058024219903391
            's878926199a', // 0e545993274517709034328855841020
            's155964671a', // 0e342768416822451524974117254469
            's214587387a', // 0e848240448830537924465865611904
            's1091221200a',// 0e940624217856561557816327384675
            'aabg7XSs',    // 0e087386482136013740957780965295
            'aabC9RqS',    // 0e041022518165728065344349536299
            '0e215962017', // 0e291242476940776845150308577824
        ],
        'sha1' => [
            'aaroZmOk', // 0e66507019969427134894567494305185566735
            'aaK1STfY', // 0e76658526655756247671816452429635272248
            'aaO8zKZF', // 0e89257456677279068558073954252716165668
            'aa3OFF9m', // 0e36977786278517984959260394024281014729
        ],
        // No reliable, publicly documented sha256 0e\d+ preimages are known; the table
        // intentionally omits the algorithm rather than ship unverifiable entries.
        'sha256' => [],
    ];

    public static function preimagesForTransform(string $hashFunc): array {
        $algo = strtolower($hashFunc);
        if (isset(self::PREIMAGES[$algo])) return self::PREIMAGES[$algo];
        if (str_starts_with($algo, 'hash:')) {
            $algo = substr($algo, 5);
            return self::PREIMAGES[$algo] ?? [];
        }
        return [];
    }

    /**
     * Detect whether a literal node is itself a "0e..." magic hash string.
     */
    public static function isMagicHashLiteral(?array $literal): bool {
        if (!$literal || ($literal['kind'] ?? '') !== 'string') return false;
        return (bool)preg_match('/^0+e\d+$/', $literal['value']);
    }

    public static function looksNumericString(?array $literal): bool {
        if (!$literal || ($literal['kind'] ?? '') !== 'string') return false;
        return is_numeric($literal['value']) && preg_match('/[0-9]/', $literal['value']) === 1;
    }
}
