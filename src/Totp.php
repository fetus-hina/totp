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
     * @param   int     $sizeBits       Generate size(bits, must multiples of 8)
     * @return  string                  Base32 encoded generated key
     * @throws  \Exception              Throw exception if $sizeBits is not multiples of 8 or system does not support strong random generating
     *
     * @SuppressWarnings(PHPMD.StaticAccess)
     */
    public static function generateKey($sizeBits = self::DEFAULT_KEY_SIZE_BITS) {
        if($sizeBits < 8 || $sizeBits % 8 !== 0) {
            throw new \Exception('$sizeBits is not multiples of 8');
        }
        $isStrong = false;
        $binary = openssl_random_pseudo_bytes($sizeBits / 8, $isStrong);
        if($binary === false || $isStrong === false) {
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
     * @param   int             $timeStep  Time-step
     * @return  string                      TOTP value like "012345"
     * @throws  \InvalidArgumentException   Throw exception if not-acceptable parameter given.
     *
     * @SuppressWarnings(PHPMD.StaticAccess)
     */
    public static function calc(
        $key,
        $time,
        $digits = self::DEFAULT_DIGITS,
        $hash = self::DEFAULT_HASH_ALGORITHM,
        $timeStep = self::DEFAULT_TIME_STEP_SEC
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
            self::makeTimeStepCount($time, $timeStep),
            (int)$digits,
            strtolower($hash)
        );
    }

    /**
     * Calculate TOTP (Implementation)
     *
     * @param   string  $keyBinary shared secret key (binary)
     * @param   int     $stepCount A value that reflects a time
     * @param   int     $digits     Number of digits to return
     * @param   string  $hash       Hash algorithm such as "sha1", "sha256" or "sha512"
     * @return  string              TOTP value like "012345"
     */
    private static function calcMain($keyBinary, $stepCount, $digits, $hash) {
        $timeStep = self::pack64($stepCount);
        $hmac = hash_hmac($hash, $timeStep, $keyBinary, true);
        $offset = ord($hmac[strlen($hmac) - 1]) & 0x0f;
        $intValue = ((ord($hmac[$offset]) & 0x7f) << 24) +
                    ((ord($hmac[$offset + 1])) << 16) +
                    ((ord($hmac[$offset + 2])) << 8) +
                    ((ord($hmac[$offset + 3])) << 0);
        $otp = (string)($intValue % pow(10, $digits));
        return substr(str_repeat('0', $digits) . $otp, -$digits);
    }

    /**
     * Create URI to automatically set the authenticator application "Google Authenticator"
     *
     * Please note:
     *      Following parameters will ignored in the Google Authenticator which is de facto standard application:
     *          - digits:   6 digits only
     *          - hash:     sha1 only
     *          - timeStep: 30 seconds only
     *
     * @param   string  $key            Base32 encoded key
     * @param   string  $accountName    User account name, e.g. email address
     * @param   string  $issuer         Issuer name, e.g. your service name
     * @return  string                  URI
     * @throws  \InvalidArgumentException   Throw exception if not-acceptable parameter given.
     */
    public static function createKeyUriForGoogleAuthenticator(
        $key,
        $accountName,
        $issuer
    ) {
        if(!self::isValidBase32($key)) {
            throw new InvalidArgumentException("Invalid shared secret key given");
        }

        return self::createKeyUriImpl(
            $key,
            trim($accountName),
            trim($issuer)
        );
    }

    /**
     * Create URI to automatically set the authenticator application (Implemetation)
     *
     * Please note:
     *      Following parameters will ignored in the Google Authenticator which is de facto standard application:
     *          - digits:   6 digits only
     *          - hash:     sha1 only
     *          - timeStep: 30 seconds only
     *
     * @param   string  $key            Base32 encoded key
     * @param   string  $accountName    User account name, e.g. email address
     * @param   string  $issuer         Issuer name, e.g. your service name
     * @return  string                  URI
     */
    public static function createKeyUriImpl(
        $key,
        $accountName,
        $issuer
    ) {
        $params = [ 'secret' => $key ];
        if(strlen((string)$issuer) > 0) {
            $params['issuer'] = $issuer;
        }

        return sprintf(
            'otpauth://totp/%s?%s',
            rawurlencode(
                strlen((string)$issuer) < 1
                    ? $accountName
                    : sprintf('%s:%s', $issuer, $accountName)
            ),
            http_build_query($params, PHP_QUERY_RFC3986)
        );
    }

    /**
     * Pack 64bit integer to bigendian binary
     *
     * @param int $value int64 value
     */
    private static function pack64($value) {
        if(version_compare(PHP_VERSION, '5.6.3', '>=')) {
            return pack('J', $value);
        }
        $highMap = 0xffffffff << 32;
        $lowMap  = 0xffffffff;
        $higher = ($value & $highMap) >> 32; 
        $lower = $value & $lowMap; 
        return pack('NN', $higher, $lower); 
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
     * @param   int             $timeStep  Time-step
     * @return  int
     * @throws  \InvalidArgumentException   Throw exception if not-acceptable parameter given.
     */
    private static function makeTimeStepCount($time, $timeStep) {
        if(!is_int($time)) {
            if($time instanceof \DateTime) {
                $time = $time->getTimestamp();
            } elseif(!is_numeric($time)) {
                throw new InvalidArgumentException("Invalid timestamp given");
            }
        }
        if($timeStep < 1) {
            throw new InvalidArgumentException("Time-step value is out of range");
        }
        return (int)floor((int)$time / (int)$timeStep);
    }
}
