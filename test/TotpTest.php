<?php

declare(strict_types=1);

namespace jp3cki\totp\test;

use Base32\Base32;
use DateTime;
use DateTimeInterface;
use DateTimeZone;
use Exception;
use PHPUnit\Framework\TestCase;
use jp3cki\totp\Totp;

class TotpTest extends TestCase
{
    public function testGenerateChars(): void
    {
        $this->assertRegExp('/^[A-Z2-7]+$/', Totp::generateKey(80));
    }

    public function testGenerateLength(): void
    {
        // base32: 40bits -> 8chars
        $this->assertEquals(8, strlen(Totp::generateKey(40)));
        $this->assertEquals(16, strlen(Totp::generateKey(80)));
        $this->assertEquals(24, strlen(Totp::generateKey(120)));
        $this->assertEquals(32, strlen(Totp::generateKey(160)));
    }

    public function testGenerateLengthNegative(): void
    {
        $this->expectException(Exception::class);
        Totp::generateKey(-40); // @phpstan-ignore-line
    }

    public function testGenerateLengthNot8bits(): void
    {
        $this->expectException(Exception::class);
        Totp::generateKey(15);
    }

    public function rfcSha1Provider(): array
    {
        $key_b32 = Base32::encode('12345678901234567890');
        return [
            [$key_b32,          59, '94287082'],
            [$key_b32,  1111111109, '07081804'],
            [$key_b32,  1111111111, '14050471'],
            [$key_b32,  1234567890, '89005924'],
            [$key_b32,  2000000000, '69279037'],
            [$key_b32, 20000000000, '65353130'],
            [$key_b32, new DateTime('1970-01-01T00:00:59', new DateTimeZone('UTC')), '94287082'],
            [$key_b32, new DateTime('2005-03-18T01:58:29', new DateTimeZone('UTC')), '07081804'],
            [$key_b32, new DateTime('2005-03-18T01:58:31', new DateTimeZone('UTC')), '14050471'],
            [$key_b32, new DateTime('2009-02-13T23:31:30', new DateTimeZone('UTC')), '89005924'],
            [$key_b32, new DateTime('2033-05-18T03:33:20', new DateTimeZone('UTC')), '69279037'],
            [$key_b32, new DateTime('2603-10-11T11:33:20', new DateTimeZone('UTC')), '65353130'],
        ];
    }

    public function rfcSha256Provider(): array
    {
        $key_b32 = Base32::encode('12345678901234567890123456789012');
        return [
            [$key_b32,          59, '46119246'],
            [$key_b32,  1111111109, '68084774'],
            [$key_b32,  1111111111, '67062674'],
            [$key_b32,  1234567890, '91819424'],
            [$key_b32,  2000000000, '90698825'],
            [$key_b32, 20000000000, '77737706'],
            [$key_b32, new DateTime('1970-01-01T00:00:59', new DateTimeZone('UTC')), '46119246'],
            [$key_b32, new DateTime('2005-03-18T01:58:29', new DateTimeZone('UTC')), '68084774'],
            [$key_b32, new DateTime('2005-03-18T01:58:31', new DateTimeZone('UTC')), '67062674'],
            [$key_b32, new DateTime('2009-02-13T23:31:30', new DateTimeZone('UTC')), '91819424'],
            [$key_b32, new DateTime('2033-05-18T03:33:20', new DateTimeZone('UTC')), '90698825'],
            [$key_b32, new DateTime('2603-10-11T11:33:20', new DateTimeZone('UTC')), '77737706'],
        ];
    }

    public function rfcSha512Provider(): array
    {
        $key_b32 = Base32::encode('1234567890123456789012345678901234567890123456789012345678901234');
        return [
            [$key_b32,          59, '90693936'],
            [$key_b32,  1111111109, '25091201'],
            [$key_b32,  1111111111, '99943326'],
            [$key_b32,  1234567890, '93441116'],
            [$key_b32,  2000000000, '38618901'],
            [$key_b32, 20000000000, '47863826'],
            [$key_b32, new DateTime('1970-01-01T00:00:59', new DateTimeZone('UTC')), '90693936'],
            [$key_b32, new DateTime('2005-03-18T01:58:29', new DateTimeZone('UTC')), '25091201'],
            [$key_b32, new DateTime('2005-03-18T01:58:31', new DateTimeZone('UTC')), '99943326'],
            [$key_b32, new DateTime('2009-02-13T23:31:30', new DateTimeZone('UTC')), '93441116'],
            [$key_b32, new DateTime('2033-05-18T03:33:20', new DateTimeZone('UTC')), '38618901'],
            [$key_b32, new DateTime('2603-10-11T11:33:20', new DateTimeZone('UTC')), '47863826'],
        ];
    }

    /**
     * @param int|DateTimeInterface $time
     * @dataProvider rfcSha1Provider
     */
    public function testGenerateSha1(
        string $key_b32,
        $time,
        string $expect
    ): void {
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
     * @param int|DateTimeInterface $time
     * @dataProvider rfcSha256Provider
     */
    public function testGenerateSha256(
        string $key_b32,
        $time,
        string $expect
    ): void {
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
     * @param int|DateTimeInterface $time
     * @dataProvider rfcSha512Provider
     */
    public function testGenerateSha512(
        string $key_b32,
        $time,
        string $expect
    ): void {
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

    public function verifyProvider(): array
    {
        $key_b32 = Base32::encode('12345678901234567890');
        $time = 1111111111;
        return [
            // 厳密に正しい
            [ Totp::calc($key_b32, $time, 6, 'sha1', 30), $key_b32, $time, true ],

            // 1 ステップだけずれている
            [ Totp::calc($key_b32, $time, 6, 'sha1', 30), $key_b32, $time - 30, true ],
            [ Totp::calc($key_b32, $time, 6, 'sha1', 30), $key_b32, $time + 30, true ],

            // 大幅にずれている
            [ Totp::calc($key_b32, $time, 6, 'sha1', 30), $key_b32, $time - 3600, false ],
            [ Totp::calc($key_b32, $time, 6, 'sha1', 30), $key_b32, $time + 3600, false ],
        ];
    }

    public function testCalcInvalidBase32(): void
    {
        $this->expectException(Exception::class);
        Totp::calc('JBSWY0DP', time());
    }

    public function testCalcInvalidTimestamp(): void
    {
        $this->expectException(Exception::class);
        Totp::calc('JBSWY3DP', 'A'); // @phpstan-ignore-line
    }

    public function testCalcInvalidDigitsL(): void
    {
        $this->expectException(Exception::class);
        Totp::calc('JBSWY3DP', time(), 0);
    }

    public function testCalcInvalidDigitsH(): void
    {
        $this->expectException(Exception::class);
        Totp::calc('JBSWY3DP', time(), 9);
    }

    public function testCalcInvalidHash(): void
    {
        $this->expectException(Exception::class);
        Totp::calc('JBSWY3DP', time(), 6, 'my-amazing-hash');
    }

    public function testCalcInvalidTimestep(): void
    {
        $this->expectException(Exception::class);
        Totp::calc('JBSWY3DP', time(), 6, 'sha1', 0);
    }

    /**
     * @dataProvider verifyProvider
     */
    public function testVerify(
        string $value,
        string $keyB32,
        int $time,
        bool $expect
    ): void {
        $this->assertEquals(
            $expect,
            Totp::verify(
                $value,
                $keyB32,
                $time
            )
        );
    }

    public function testVerifyInvalidBase32(): void
    {
        $this->expectException(Exception::class);
        Totp::verify('1', 'JBSWY0DP', time());
    }

    public function testVerifyInvalidTimestamp(): void
    {
        $this->expectException(Exception::class);
        Totp::verify('1', 'JBSWY3DP', 'A'); // @phpstan-ignore-line
    }

    public function testVerifyInvalidDigitsL(): void
    {
        $this->expectException(Exception::class);
        Totp::verify('1', 'JBSWY3DP', time(), 2, 1, 0);
    }

    public function testVerifyInvalidDigitsH(): void
    {
        $this->expectException(Exception::class);
        Totp::verify('1', 'JBSWY3DP', time(), 2, 1, 9);
    }

    public function testVerifyInvalidHash(): void
    {
        $this->expectException(Exception::class);
        Totp::verify('1', 'JBSWY3DP', time(), 2, 1, 6, 'my-amazing-hash');
    }

    public function testVerifyInvalidTimestep(): void
    {
        $this->expectException(Exception::class);
        Totp::verify('1', 'JBSWY3DP', time(), 2, 1, 6, 'sha1', 0);
    }

    public function testCreateKeyUrlGA(): void
    {
        $expectRegex = '!^otpauth://totp/Example%20Issuer(?::|%3[Aa])alice(?:@|%40)google.com' .
                       '\?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Issuer$!';
        $this->assertRegExp(
            $expectRegex,
            Totp::createKeyUriForGoogleAuthenticator(
                'JBSWY3DPEHPK3PXP',
                'alice@google.com',
                'Example Issuer'
            )
        );
    }

    public function testCreateKeyUrlGAInvalidBase32(): void
    {
        $this->expectException(Exception::class);
        Totp::createKeyUriForGoogleAuthenticator(
            'JBSWY0DP',
            'alice@google.com',
            'Example Issuer'
        );
    }
}
