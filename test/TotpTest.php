<?php
use jp3cki\totp\Totp;

class TotpTest extends \PHPUnit_Framework_TestCase {
    public function testGenerateChars() {
        $this->assertRegExp('/^[A-Z2-7]+$/', Totp::generateKey(80));
    }

    public function testGenerateLength() {
        // base32: 40bits -> 8chars
        $this->assertEquals( 8, strlen(Totp::generateKey( 40)));
        $this->assertEquals(16, strlen(Totp::generateKey( 80)));
        $this->assertEquals(24, strlen(Totp::generateKey(120)));
        $this->assertEquals(32, strlen(Totp::generateKey(160)));
    }
}
