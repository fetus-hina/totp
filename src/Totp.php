<?php
/**
 * @author AIZAWA Hina <hina@bouhime.com>
 * @copyright 2015 by AIZAWA Hina <hina@bouhime.com>
 * @license https://github.com/fetus-hina/totp/blob/master/LICENSE MIT
 * @since 1.0.0
 */

namespace jp3cki\totp;

use InvalidArgumentException;
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

    /** Default time step: 30 sec */
    const DEFAULT_TIME_STEP_SEC = 30;

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

    /**
     * Calculate TOTP
     *
     * @param   string          $key        Base32 encoded key
     * @param   int|\DateTime   $time       A value that reflects a time
     * @param   int             $digits     Number of digits to return
     * @param   string          $hash       Hash algorithm such as "sha1", "sha256" or "sha512"
     * @param   int             $time_step  Time-step
     * @return  string                      TOTP value like "012345"
     * @throws  \InvalidArgumentException   Throw exception if not-acceptable parameter given.
     */
    public static function calc(
        $key,
        $time,
        $digits = self::DEFAULT_DIGITS,
        $hash = self::DEFAULT_HASH_ALGORITHM,
        $time_step = self::DEFAULT_TIME_STEP_SEC
    ) {
        if(!self::isValidBase32($key)) {
            throw new InvalidArgumentException("Invalid shared secret key given");
        }
        if(!self::isValidDigitCount($digits)) {
            throw new InvalidArgumentException("Digit-of-return value is out of range");
        }
        if(!self::isValidHash($hash)) {
            throw new InvalidArgumentException("Unsupported hash algorithm");
        }
        return self::calcMain(
            Base32::decode(strtoupper($key)),
            self::makeTimeStepCount($time, $time_step),
            (int)$digits,
            strtolower($hash)
        );
    }

    /**
     * Calculate TOTP (Implementation)
     *
     * @param   string  $key_binary shared secret key (binary)
     * @param   int     $step_count A value that reflects a time
     * @param   int     $digits     Number of digits to return
     * @param   string  $hash       Hash algorithm such as "sha1", "sha256" or "sha512"
     * @return  string              TOTP value like "012345"
     */
    private static function calcMain($key_binary, $step_count, $digits, $hash) {
        $t = self::pack64($step_count);
        $hmac = hash_hmac($hash, $t, $key_binary, true);
        $offset = ord($hmac[strlen($hmac) - 1]) & 0x0f;
        $int_value = ((ord($hmac[$offset]) & 0x7f) << 24) +
                     ((ord($hmac[$offset + 1])) << 16) +
                     ((ord($hmac[$offset + 2])) << 8) +
                     ((ord($hmac[$offset + 3])) << 0);
        $otp = (string)($int_value % pow(10, $digits));
        return substr(str_repeat('0', $digits) . $otp, -$digits);
    }

    /**
     * Pack 64bit integer to bigendian binary
     *
     * @param int $value int64 value
     */
    private static function pack64($value) {
        if(version_compare(PHP_VERSION, '5.6.3', '>=')) {
            return pack('J', $value);
        } else {
            $high_map = 0xffffffff << 32;
            $low_map  = 0xffffffff;
            $higher = ($value & $high_map) >> 32; 
            $lower = $value & $low_map; 
            return pack('NN', $higher, $lower); 
        }
    }

    /**
     * Get is valid base32 value
     *
     * @param   string  $base32     Base32 value
     * @return  bool
     */
    private static function isValidBase32($base32) {
        return !!preg_match('/^[A-Z2-7]+=*$/', $base32);
    }

    /**
     * Get is valid digit count
     *
     * @param   int     $digits     Return digit count
     * @return  bool
     */
    private static function isValidDigitCount($digits) {
        if(is_int($digits) || is_numeric($digits)) {
            $digits = (int)$digits;
            if(1 <= $digits && $digits <= 8) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get is valid hash function
     *
     * @param   string  $hash   Hash algorithm such as "sha1", "sha256" or "sha512"
     * @return  bool
     */
    private static function isValidHash($hash) {
        $hash = strtolower($hash);
        return !!in_array($hash, hash_algos(), true);
    }

    /**
     * Make time-step count value
     *
     * @param   int|\DateTime   $time       A value that reflects a time
     * @param   int             $time_step  Time-step
     * @return  int
     * @throws  \InvalidArgumentException   Throw exception if not-acceptable parameter given.
     */
    private static function makeTimeStepCount($time, $time_step) {
        if(!is_int($time)) {
            if($time instanceof \DateTime) {
                $time = $time->getTimestamp();
            } elseif(!is_numeric($time)) {
                throw new InvalidArgumentException("Invalid timestamp given");
            }
        }
        if(is_int($time_step) || is_numeric($time_step)) {
            if($time_step < 1) {
                throw new InvalidArgumentException("Time-step value is out of range");
            }
        }
        return (int)floor((int)$time / (int)$time_step);
    }
}
