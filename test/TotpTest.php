<?php

declare(strict_types=1);

namespace jp3cki\totp\test;

use DateTime;
use DateTimeInterface;
use DateTimeZone;
use PHPUnit\Framework\TestCase;
use ParagonIE\ConstantTime\Base32;
use Throwable;
use jp3cki\totp\Totp;

use function strlen;
use function time;

class TotpTest extends TestCase
{
    public function testGenerateChars(): void
    {
        $this->assertMatchesRegularExpression('/^[A-Z2-7]+$/', Totp::generateKey(80));
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
        $this->expectException(Throwable::class);
        Totp::generateKey(-40); // @phpstan-ignore-line
    }

    public function testGenerateLengthNot8bits(): void
    {
        $this->expectException(Throwable::class);
        Totp::generateKey(15);
    }

    /**
     * @return array{string, int|DateTime, string}[]
     */
    public static function rfcSha1Provider(): array
    {
        $keyB32 = Base32::encodeUpperUnpadded('12345678901234567890');
        return [
            [$keyB32, 59, '94287082'],
            [$keyB32, 1111111109, '07081804'],
            [$keyB32, 1111111111, '14050471'],
            [$keyB32, 1234567890, '89005924'],
            [$keyB32, 2000000000, '69279037'],
            [$keyB32, 20000000000, '65353130'],
            [$keyB32, new DateTime('1970-01-01T00:00:59', new DateTimeZone('UTC')), '94287082'],
            [$keyB32, new DateTime('2005-03-18T01:58:29', new DateTimeZone('UTC')), '07081804'],
            [$keyB32, new DateTime('2005-03-18T01:58:31', new DateTimeZone('UTC')), '14050471'],
            [$keyB32, new DateTime('2009-02-13T23:31:30', new DateTimeZone('UTC')), '89005924'],
            [$keyB32, new DateTime('2033-05-18T03:33:20', new DateTimeZone('UTC')), '69279037'],
            [$keyB32, new DateTime('2603-10-11T11:33:20', new DateTimeZone('UTC')), '65353130'],
        ];
    }

    /**
     * @return array{string, int|DateTime, string}[]
     */
    public static function rfcSha256Provider(): array
    {
        $keyB32 = Base32::encodeUpperUnpadded('12345678901234567890123456789012');
        return [
            [$keyB32, 59, '46119246'],
            [$keyB32, 1111111109, '68084774'],
            [$keyB32, 1111111111, '67062674'],
            [$keyB32, 1234567890, '91819424'],
            [$keyB32, 2000000000, '90698825'],
            [$keyB32, 20000000000, '77737706'],
            [$keyB32, new DateTime('1970-01-01T00:00:59', new DateTimeZone('UTC')), '46119246'],
            [$keyB32, new DateTime('2005-03-18T01:58:29', new DateTimeZone('UTC')), '68084774'],
            [$keyB32, new DateTime('2005-03-18T01:58:31', new DateTimeZone('UTC')), '67062674'],
            [$keyB32, new DateTime('2009-02-13T23:31:30', new DateTimeZone('UTC')), '91819424'],
            [$keyB32, new DateTime('2033-05-18T03:33:20', new DateTimeZone('UTC')), '90698825'],
            [$keyB32, new DateTime('2603-10-11T11:33:20', new DateTimeZone('UTC')), '77737706'],
        ];
    }

    /**
     * @return array{string, int|DateTime, string}[]
     */
    public static function rfcSha512Provider(): array
    {
        $keyB32 = Base32::encodeUpperUnpadded('1234567890123456789012345678901234567890123456789012345678901234');
        return [
            [$keyB32, 59, '90693936'],
            [$keyB32, 1111111109, '25091201'],
            [$keyB32, 1111111111, '99943326'],
            [$keyB32, 1234567890, '93441116'],
            [$keyB32, 2000000000, '38618901'],
            [$keyB32, 20000000000, '47863826'],
            [$keyB32, new DateTime('1970-01-01T00:00:59', new DateTimeZone('UTC')), '90693936'],
            [$keyB32, new DateTime('2005-03-18T01:58:29', new DateTimeZone('UTC')), '25091201'],
            [$keyB32, new DateTime('2005-03-18T01:58:31', new DateTimeZone('UTC')), '99943326'],
            [$keyB32, new DateTime('2009-02-13T23:31:30', new DateTimeZone('UTC')), '93441116'],
            [$keyB32, new DateTime('2033-05-18T03:33:20', new DateTimeZone('UTC')), '38618901'],
            [$keyB32, new DateTime('2603-10-11T11:33:20', new DateTimeZone('UTC')), '47863826'],
        ];
    }

    /**
     * @dataProvider rfcSha1Provider
     */
    public function testGenerateSha1(
        string $keyB32,
        int|DateTimeInterface $time,
        string $expect,
    ): void {
        $this->assertEquals(
            $expect,
            Totp::calc(
                $keyB32,
                $time,
                strlen($expect),
                'sha1',
                30,
            ),
        );
    }

    /**
     * @dataProvider rfcSha256Provider
     */
    public function testGenerateSha256(
        string $keyB32,
        int|DateTimeInterface $time,
        string $expect,
    ): void {
        $this->assertEquals(
            $expect,
            Totp::calc(
                $keyB32,
                $time,
                strlen($expect),
                'sha256',
                30,
            ),
        );
    }

    /**
     * @dataProvider rfcSha512Provider
     */
    public function testGenerateSha512(
        string $keyB32,
        int|DateTimeInterface $time,
        string $expect,
    ): void {
        $this->assertEquals(
            $expect,
            Totp::calc(
                $keyB32,
                $time,
                strlen($expect),
                'sha512',
                30,
            ),
        );
    }

    /**
     * @return array{string, string, int, bool}[]
     */
    public static function verifyProvider(): array
    {
        $keyB32 = Base32::encodeUpperUnpadded('12345678901234567890');
        $time = 1111111111;
        return [
            // 厳密に正しい
            [ Totp::calc($keyB32, $time, 6, 'sha1', 30), $keyB32, $time, true ],

            // 1 ステップだけずれている
            [ Totp::calc($keyB32, $time, 6, 'sha1', 30), $keyB32, $time - 30, true ],
            [ Totp::calc($keyB32, $time, 6, 'sha1', 30), $keyB32, $time + 30, true ],

            // 大幅にずれている
            [ Totp::calc($keyB32, $time, 6, 'sha1', 30), $keyB32, $time - 3600, false ],
            [ Totp::calc($keyB32, $time, 6, 'sha1', 30), $keyB32, $time + 3600, false ],
        ];
    }

    public function testCalcInvalidBase32(): void
    {
        $this->expectException(Throwable::class);
        Totp::calc('JBSWY0DP', time());
    }

    public function testCalcInvalidTimestamp(): void
    {
        $this->expectException(Throwable::class);
        Totp::calc('JBSWY3DP', 'A'); // @phpstan-ignore-line
    }

    public function testCalcInvalidDigitsL(): void
    {
        $this->expectException(Throwable::class);
        Totp::calc('JBSWY3DP', time(), 0);
    }

    public function testCalcInvalidDigitsH(): void
    {
        $this->expectException(Throwable::class);
        Totp::calc('JBSWY3DP', time(), 9);
    }

    public function testCalcInvalidHash(): void
    {
        $this->expectException(Throwable::class);
        Totp::calc('JBSWY3DP', time(), 6, 'my-amazing-hash');
    }

    public function testCalcInvalidTimestep(): void
    {
        $this->expectException(Throwable::class);
        Totp::calc('JBSWY3DP', time(), 6, 'sha1', 0);
    }

    /**
     * @dataProvider verifyProvider
     */
    public function testVerify(
        string $value,
        string $keyB32,
        int $time,
        bool $expect,
    ): void {
        $this->assertEquals(
            $expect,
            Totp::verify(
                $value,
                $keyB32,
                $time,
            ),
        );
    }

    public function testVerifyInvalidBase32(): void
    {
        $this->expectException(Throwable::class);
        Totp::verify('1', 'JBSWY0DP', time());
    }

    public function testVerifyInvalidTimestamp(): void
    {
        $this->expectException(Throwable::class);
        Totp::verify('1', 'JBSWY3DP', 'A'); // @phpstan-ignore-line
    }

    public function testVerifyInvalidDigitsL(): void
    {
        $this->expectException(Throwable::class);
        Totp::verify('1', 'JBSWY3DP', time(), 2, 1, 0);
    }

    public function testVerifyInvalidDigitsH(): void
    {
        $this->expectException(Throwable::class);
        Totp::verify('1', 'JBSWY3DP', time(), 2, 1, 9);
    }

    public function testVerifyInvalidHash(): void
    {
        $this->expectException(Throwable::class);
        Totp::verify('1', 'JBSWY3DP', time(), 2, 1, 6, 'my-amazing-hash');
    }

    public function testVerifyInvalidTimestep(): void
    {
        $this->expectException(Throwable::class);
        Totp::verify('1', 'JBSWY3DP', time(), 2, 1, 6, 'sha1', 0);
    }

    public function testCreateKeyUrlGA(): void
    {
        $expectRegex = '!^otpauth://totp/Example%20Issuer(?::|%3[Aa])alice(?:@|%40)google.com' .
                       '\?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Issuer$!';
        $this->assertMatchesRegularExpression(
            $expectRegex,
            Totp::createKeyUriForGoogleAuthenticator(
                'JBSWY3DPEHPK3PXP',
                'alice@google.com',
                'Example Issuer',
            ),
        );
    }

    public function testCreateKeyUrlGAInvalidBase32(): void
    {
        $this->expectException(Throwable::class);
        Totp::createKeyUriForGoogleAuthenticator(
            'JBSWY0DP',
            'alice@google.com',
            'Example Issuer',
        );
    }
}
