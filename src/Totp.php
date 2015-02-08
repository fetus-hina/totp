<?php
/**
 * @author AIZAWA Hina <hina@bouhime.com>
 * @copyright 2015 by AIZAWA Hina <hina@bouhime.com>
 * @license https://github.com/fetus-hina/totp/blob/master/LICENSE MIT
 * @since 1.0.0
 */

namespace jp3cki\totp;
use Base32\Base32;

/**
 * TOTP: Time-Based One-Time Password Algorithm
 */
class Totp {
    /** Default key size: 80 bits */
    const DEFAULT_KEY_SIZE_BITS = 80;

    /** Default hash algorithm: SHA1 */
    const DEFAULT_HASH_ALGORITHM = 'sha1';

    /** Default digits: 6 digits */
    const DEFAULT_DIGITS = 6;

    /** Default interval: 30 sec */
    const DEFAULT_INTERVAL_SEC = 30;


    /** 
     * Generate user key
     *
     * @param   int     $size_bits      Generate size(bits, must multiples of 8)
     * @return  string                  Base32 encoded generated key
     * @throws  \Exception              Throw exception if $size_bits is not multiples of 8 or system does not support strong random generating
     */
    public static function generateKey($size_bits = self::DEFAULT_KEY_SIZE_BITS) {
        if($size_bits < 8 || $size_bits % 8 !== 0) {
            throw new \Exception('$size_bits is not multiples of 8');
        }
        $is_strong = false;
        $binary = openssl_random_pseudo_bytes($size_bits / 8, $is_strong);
        if($binary === false || $is_strong === false) {
            throw new \Exception('System does not support strong random generating');
        }
        return Base32::encode($binary);
    }
}
