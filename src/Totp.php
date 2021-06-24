<?php

/**
 * @author AIZAWA Hina <hina@fetus.jp>
 * @copyright 2015 by AIZAWA Hina <hina@fetus.jp>
 * @license https://github.com/fetus-hina/totp/blob/master/LICENSE MIT
 * @since 1.0.0
 */

declare(strict_types=1);

namespace jp3cki\totp;

use Base32\Base32;
use DateTimeInterface;
use Exception;
use InvalidArgumentException;

/**
 * TOTP: Time-Based One-Time Password Algorithm
 */
class Totp
{
    /** Default key size: 80 bits */
    public const DEFAULT_KEY_SIZE_BITS = 80;

    /** Default hash algorithm: SHA1 */
    public const DEFAULT_HASH_ALGORITHM = 'sha1';

    /** Default digits: 6 digits */
    public const DEFAULT_DIGITS = 6;

    /** Default time step: 30 sec */
    public const DEFAULT_TIME_STEP_SEC = 30;

    /**
     * Generate user key
     *
     * @param  int    $sizeBits Generate size(bits, must multiples of 8)
     * @return string           Base32 encoded generated key
     * @throws Exception if $sizeBits is not multiples of 8 or system does not support strong random generating
     */
    public static function generateKey(int $sizeBits = self::DEFAULT_KEY_SIZE_BITS): string
    {
        if ($sizeBits < 8 || $sizeBits % 8 !== 0) {
            throw new Exception('$sizeBits is not multiples of 8');
        }

        return Base32::encode(Random::generate($sizeBits / 8));
    }

    /**
     * Calculate TOTP
     *
     * @param  string        $key      Base32 encoded key
     * @param  int|DateTimeInterface $time A value that reflects a time
     * @param  int           $digits   Number of digits to return
     * @param  string        $hash     Hash algorithm such as "sha1", "sha256" or "sha512"
     * @param  int           $timeStep Time-step
     * @return string                  TOTP value like "012345"
     * @throws InvalidArgumentException Throw exception if not-acceptable parameter given.
     */
    public static function calc(
        string $key,
        $time,
        int $digits = self::DEFAULT_DIGITS,
        string $hash = self::DEFAULT_HASH_ALGORITHM,
        int $timeStep = self::DEFAULT_TIME_STEP_SEC
    ): string {
        if (!static::isValidBase32($key)) {
            throw new InvalidArgumentException("Invalid shared secret key given");
        }

        if (!static::isValidDigitCount($digits)) {
            throw new InvalidArgumentException("Digit-of-return value is out of range");
        }

        if (!static::isValidHash($hash)) {
            throw new InvalidArgumentException("Unsupported hash algorithm");
        }

        return static::calcMain(
            Base32::decode(strtoupper($key)),
            static::makeTimeStepCount($time, $timeStep),
            (int)$digits,
            strtolower($hash)
        );
    }

    /**
     * Calculate TOTP (Implementation)
     *
     * @param  string $keyBinary shared secret key (binary)
     * @param  int    $stepCount A value that reflects a time
     * @param  int    $digits    Number of digits to return
     * @param  string $hash      Hash algorithm such as "sha1", "sha256" or "sha512"
     * @return string TOTP value like "012345"
     */
    private static function calcMain(string $keyBinary, int $stepCount, int $digits, string $hash): string
    {
        $timeStep = static::pack64($stepCount);
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
     * Verify TOTP
     *
     * @param  string        $value            TOTP value like "012345" which is specified by the user
     * @param  string        $key              Base32 encoded key
     * @param  int|DateTimeInterface $time     A value that reflects a time
     * @param  int           $acceptStepPast   Acceptable time-step (past)
     * @param  int           $acceptStepFuture Acceptable time-step (future)
     * @param  int           $digits           Number of digits to return
     * @param  string        $hash             Hash algorithm such as "sha1", "sha256" or "sha512"
     * @param  int           $timeStep         Time-step
     * @return bool true if verify successful. false if verify failed.
     *
     * @throws InvalidArgumentException Throw exception if not-acceptable parameter given.
     */
    public static function verify(
        string $value,
        string $key,
        $time,
        int $acceptStepPast = 2,
        int $acceptStepFuture = 1,
        int $digits = self::DEFAULT_DIGITS,
        string $hash = self::DEFAULT_HASH_ALGORITHM,
        int $timeStep = self::DEFAULT_TIME_STEP_SEC
    ): bool {
        if (!static::isValidBase32($key)) {
            throw new InvalidArgumentException("Invalid shared secret key given");
        }

        if (!static::isValidDigitCount($digits)) {
            throw new InvalidArgumentException("Digit-of-return value is out of range");
        }

        if (!static::isValidHash($hash)) {
            throw new InvalidArgumentException("Unsupported hash algorithm");
        }

        $keyBinary = Base32::decode(strtoupper($key));
        $currentStep = static::makeTimeStepCount($time, $timeStep);
        $digits = (int)$digits;
        $hash = strtolower($hash);

        $stepBegin = $currentStep - (int)$acceptStepPast;
        $stepEnd   = $currentStep + (int)$acceptStepFuture + 1;
        for ($testTimeStep = $stepBegin; $testTimeStep < $stepEnd; ++$testTimeStep) {
            $testValue = static::calcMain($keyBinary, $testTimeStep, $digits, $hash);
            if ($testValue === $value) {
                return true;
            }
        }
        return false;
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
     * @param  string $key         Base32 encoded key
     * @param  string $accountName User account name, e.g. email address
     * @param  string $issuer      Issuer name, e.g. your service name
     * @return string URI
     * @throws InvalidArgumentException Throw exception if not-acceptable parameter given.
     */
    public static function createKeyUriForGoogleAuthenticator(
        string $key,
        string $accountName,
        string $issuer
    ): string {
        if (!static::isValidBase32($key)) {
            throw new InvalidArgumentException("Invalid shared secret key given");
        }

        return static::createKeyUriImpl(
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
     * @param  string $key         Base32 encoded key
     * @param  string $accountName User account name, e.g. email address
     * @param  string $issuer      Issuer name, e.g. your service name
     * @return string URI
     */
    private static function createKeyUriImpl(
        string $key,
        string $accountName,
        string $issuer
    ): string {
        $params = ['secret' => $key];
        if (strlen((string)$issuer) > 0) {
            $params['issuer'] = $issuer;
        }

        return sprintf(
            'otpauth://totp/%s?%s',
            rawurlencode(
                strlen((string)$issuer) < 1
                ? $accountName
                : sprintf('%s:%s', $issuer, $accountName)
            ),
            http_build_query($params, '', '&', PHP_QUERY_RFC3986)
        );
    }

    /**
     * Pack 64bit integer to bigendian binary
     *
     * @param int $value int64 value
     */
    private static function pack64(int $value): string
    {
        return pack('J', $value);
    }

    /**
     * Get is valid base32 value
     *
     * @param  string $base32 Base32 value
     * @return bool
     */
    private static function isValidBase32(string $base32): bool
    {
        return (bool)preg_match('/^[A-Z2-7]+=*$/', $base32);
    }

    /**
     * Get is valid digit count
     *
     * @param  int  $digits Return digit count
     * @return bool
     */
    private static function isValidDigitCount(int $digits): bool
    {
        return 1 <= $digits && $digits <= 8;
    }

    /**
     * Get is valid hash function
     *
     * @param  string $hash Hash algorithm such as "sha1", "sha256" or "sha512"
     * @return bool
     */
    private static function isValidHash(string $hash): bool
    {
        $hash = strtolower($hash);
        return (bool)in_array($hash, hash_algos(), true);
    }

    /**
     * Make time-step count value
     *
     * @param  int|DateTimeInterface $time A value that reflects a time
     * @param  int           $timeStep Time-step
     * @return int
     * @throws InvalidArgumentException Throw exception if not-acceptable parameter given.
     */
    private static function makeTimeStepCount($time, int $timeStep): int
    {
        if (!is_int($time)) {
            if ($time instanceof DateTimeInterface) {
                $time = $time->getTimestamp();
            } else {
                throw new InvalidArgumentException("Invalid timestamp given");
            }
        }

        if ((int)$timeStep < 1) {
            throw new InvalidArgumentException("Time-step value is out of range");
        }

        return (int)floor((int)$time / $timeStep);
    }
}
