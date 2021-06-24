<?php

declare(strict_types=1);

namespace jp3cki\totp\test;

use Base32\Base32;
use DateTime;
use DateTimeZone;
use PHPUnit\Framework\TestCase;
use jp3cki\totp\Random;

final class RandomTest extends TestCase
{
    public function testGenerate(): void
    {
        $this->assertEquals(4, strlen(Random::generate(4)));
        $this->assertEquals(8, strlen(Random::generate(8)));
        $this->assertEquals(16, strlen(Random::generate(16)));
    }

    public function testGeneratePhp7Random(): void
    {
        if (!function_exists('random_bytes')) {
            $this->assertFalse(Random::generateByPhp7Random(4));
        } else {
            $this->assertEquals(4, strlen(Random::generateByPhp7Random(4)));
        }
    }

    public function testGenerateByUnixRandom(): void
    {
        if (!file_exists('/dev/urandom')) {
            $this->assertFalse(Random::generateByUnixRandom(4));
        } else {
            $this->assertEquals(4, strlen(Random::generateByUnixRandom(4)));
        }
    }

    public function testGenerateByOpenSslRandom(): void
    {
        if (!function_exists('openssl_random_pseudo_bytes')) {
            $this->assertFalse(Random::generateByOpenSslRandom(4));
        } else {
            $this->assertEquals(4, strlen(Random::generateByOpenSslRandom(4)));
        }
    }
}
