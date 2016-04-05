<?php
namespace jp3cki\totp\test;

use Base32\Base32;
use DateTime;
use DateTimeZone;
use jp3cki\totp\Random;

class RandomTest extends \PHPUnit_Framework_TestCase
{
    public function testGenerate()
    {
        $this->assertEquals(4, strlen(Random::generate(4)));
        $this->assertEquals(8, strlen(Random::generate(8)));
        $this->assertEquals(16, strlen(Random::generate(16)));
    }

    public function testGeneratePhp7Random()
    {
        if (!function_exists('random_bytes')) {
            $this->assertFalse(Random::generateByPhp7Random(4));
        } else {
            $this->assertEquals(4, strlen(Random::generateByPhp7Random(4)));
        }
    }

    public function testGenerateByUnixRandom()
    {
        if (!file_exists('/dev/urandom')) {
            $this->assertFalse(Random::generateByUnixRandom(4));
        } else {
            $this->assertEquals(4, strlen(Random::generateByUnixRandom(4)));
        }
    }

    public function testGenerateByOpenSslRandom()
    {
        if (!function_exists('openssl_random_pseudo_bytes')) {
            $this->assertFalse(Random::generateByOpenSslRandom(4));
        } else {
            $this->assertEquals(4, strlen(Random::generateByOpenSslRandom(4)));
        }
    }
}
