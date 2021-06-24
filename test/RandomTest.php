<?php

declare(strict_types=1);

namespace jp3cki\totp\test;

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
}
