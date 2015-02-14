<?php
use jp3cki\totp\Totp;
use Base32\Base32;

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

    public function testSuiteRfcSha1Provider() {
        $key_b32 = Base32::encode('12345678901234567890');
        return [
            [$key_b32,          59, '94287082'],
            [$key_b32,  1111111109, '07081804'],
            [$key_b32,  1111111111, '14050471'],
            [$key_b32,  1234567890, '89005924'],
            [$key_b32,  2000000000, '69279037'],
            [$key_b32, 20000000000, '65353130'],
        ];
    }


    public function testSuiteRfcSha256Provider() {
        $key_b32 = Base32::encode('12345678901234567890123456789012');
        return [
            [$key_b32,          59, '46119246'],
            [$key_b32,  1111111109, '68084774'],
            [$key_b32,  1111111111, '67062674'],
            [$key_b32,  1234567890, '91819424'],
            [$key_b32,  2000000000, '90698825'],
            [$key_b32, 20000000000, '77737706'],
        ];
    }

    public function testSuiteRfcSha512Provider() {
        $key_b32 = Base32::encode('1234567890123456789012345678901234567890123456789012345678901234');
        return [
            [$key_b32,          59, '90693936'],
            [$key_b32,  1111111109, '25091201'],
            [$key_b32,  1111111111, '99943326'],
            [$key_b32,  1234567890, '93441116'],
            [$key_b32,  2000000000, '38618901'],
            [$key_b32, 20000000000, '47863826'],
        ];
    }

    /**
     * @dataProvider testSuiteRfcSha1Provider
     */
    public function testGenerateSha1($key_b32, $time, $expect) {
        $this->assertEquals(
            $expect,
            Totp::calc(
                $key_b32,
                $time,
                strlen($expect),
                'sha1',
                30
            )
        );
    }

    /**
     * @dataProvider testSuiteRfcSha256Provider
     */
    public function testGenerateSha256($key_b32, $time, $expect) {
        $this->assertEquals(
            $expect,
            Totp::calc(
                $key_b32,
                $time,
                strlen($expect),
                'sha256',
                30
            )
        );
    }

    /**
     * @dataProvider testSuiteRfcSha512Provider
     */
    public function testGenerateSha512($key_b32, $time, $expect) {
        $this->assertEquals(
            $expect,
            Totp::calc(
                $key_b32,
                $time,
                strlen($expect),
                'sha512',
                30
            )
        );
    }

    public function testCreateKeyUrlGA() {
        $expectRegex = '!otpauth://totp/Example(?::|%3[Aa])alice(?:@|%40)google.com\?secret=JBSWY3DPEHPK3PXP&issuer=Example!';
        $this->assertRegExp(
            $expectRegex,
            Totp::createKeyUriForGoogleAuthenticator(
                'JBSWY3DPEHPK3PXP',
                'alice@google.com',
                'Example'
            )
        );
    }
}
