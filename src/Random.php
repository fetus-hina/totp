<?php

/**
 * @author AIZAWA Hina <hina@fetus.jp>
 * @copyright 2015-2016 by AIZAWA Hina <hina@fetus.jp>
 * @license https://github.com/fetus-hina/totp/blob/master/LICENSE MIT
 * @since 1.1.0
 */

declare(strict_types=1);

namespace jp3cki\totp;

use Throwable;

use function random_bytes;

/**
 * Random bytes generator
 */
final class Random
{
    /**
     * Generate random bytes
     *
     * @param int<1, max> $bytes The length of the random string that should be returned in bytes.
     * @return string Returns a string containing the requested number of cryptographically secure random bytes.
     * @throws Throwable If your system has no secure random generators.
     */
    public static function generate(int $bytes): string
    {
        return random_bytes($bytes);
    }
}
