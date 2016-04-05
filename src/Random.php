<?php
/**
 * @author AIZAWA Hina <hina@bouhime.com>
 * @copyright 2015-2016 by AIZAWA Hina <hina@bouhime.com>
 * @license https://github.com/fetus-hina/totp/blob/master/LICENSE MIT
 * @since 1.1.0
 */

namespace jp3cki\totp;

/**
 * Random bytes generator
 */
class Random
{
    /**
     * Generate random bytes
     *
     * @param   int $bytes  The length of the random string that should be returned in bytes.
     * @return  string      Returns a string containing the requested number of cryptographically secure random bytes.
     * @throws \Exception   If your system has no secure random generators.
     */
    public static function generate($bytes)
    {
        $bytes = (int)$bytes;

        $methods = [
            [__CLASS__, 'generateByPhp7Random'],
            [__CLASS__, 'generateByUnixRandom'],
            [__CLASS__, 'generateByOpenSslRandom'],
        ];

        foreach ($methods as $method) {
            $ret = call_user_func($method, $bytes);
            if (is_string($ret) && strlen($ret) === $bytes) {
                return $ret;
            }
        }

        throw new \Exception('Your PHP environment has not any random-source.');
    }

    /**
     * Generate random bytes (use random_bytes)
     *
     * @param   int $bytes      The length of the random string that should be returned in bytes.
     * @return  string|false    Returns a string containing the requested number of cryptographically secure random
     *                          bytes.
     */
    public static function generateByPhp7Random($bytes)
    {
        return function_exists('random_bytes')
            ? random_bytes($bytes)
            : false;
    }

    /**
     * Generate random bytes (use /dev/urandom)
     *
     * @param   int $bytes      The length of the random string that should be returned in bytes.
     * @return  string|false    Returns a string containing the requested number of cryptographically secure random
     *                          bytes.
     */
    public static function generateByUnixRandom($bytes)
    {
        return file_exists('/dev/urandom') && is_readable('/dev/urandom')
            ? file_get_contents('/dev/urandom', false, null, 0, $bytes)
            : false;
    }

    /**
     * Generate random bytes (use openssl_random_pseudo_bytes)
     *
     * @param   int $bytes      The length of the random string that should be returned in bytes.
     * @return  string|false    Returns a string containing the requested number of cryptographically secure random
     *                          bytes.
     */
    public static function generateByOpenSslRandom($bytes)
    {
        if (!function_exists('openssl_random_pseudo_bytes')) {
            return false;
        }
        $strong = false;
        $ret = openssl_random_pseudo_bytes($bytes, $strong);
        return $strong ? $ret : false;
    }
}
