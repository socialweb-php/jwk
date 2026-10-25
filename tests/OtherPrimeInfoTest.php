<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use LogicException;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\OtherPrimeInfo;

use function print_r;
use function serialize;
use function sprintf;
use function strlen;
use function unserialize;

class OtherPrimeInfoTest extends TestCase
{
    public function testHoldsTheThreeMembersAndWritesThemAsBase64Url(): void
    {
        $info = new OtherPrimeInfo("\x01\x02", "\x03", "\x04\x05\x06");

        $this->assertSame("\x01\x02", $info->primeFactor);
        $this->assertSame("\x03", $info->factorCrtExponent);
        $this->assertSame("\x04\x05\x06", $info->factorCrtCoefficient);
        $this->assertSame(['r' => 'AQI', 'd' => 'Aw', 't' => 'BAUG'], $info->jsonSerialize());
    }

    public function testRefusesAnEmptyPrimeFactor(): void
    {
        try {
            new OtherPrimeInfo('', "\x03", "\x04");
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::InvalidValue, $exception->reason);
            $this->assertSame('r', $exception->member);
        }
    }

    public function testRefusesANonMinimalExponent(): void
    {
        try {
            new OtherPrimeInfo("\x01", "\x00\x03", "\x04");
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::NonMinimalInteger, $exception->reason);
            $this->assertSame('d', $exception->member);
        }
    }

    public function testRefusesAZeroCoefficient(): void
    {
        try {
            new OtherPrimeInfo("\x01", "\x03", "\x00");
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::InvalidValue, $exception->reason);
            $this->assertSame('t', $exception->member);
        }
    }

    public function testRefusesAPrimeFactorOfOne(): void
    {
        try {
            new OtherPrimeInfo("\x01", "\x03", "\x04");
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::InvalidValue, $exception->reason);
            $this->assertSame('r', $exception->member);
            $this->assertSame('The "r" member must be a prime, and 1 is not a prime', $exception->getMessage());
        }
    }

    public function testRedactsEveryMemberWhenDumped(): void
    {
        $dump = print_r(new OtherPrimeInfo("\x01\x02", "\x03", "\x04\x05\x06"), true);

        $this->assertStringContainsString('[r] => [redacted]', $dump);
        $this->assertStringContainsString('[d] => [redacted]', $dump);
        $this->assertStringContainsString('[t] => [redacted]', $dump);
        $this->assertStringNotContainsString("\x01\x02", $dump);
        $this->assertStringNotContainsString('AQI', $dump);
    }

    public function testCannotBeSerializedWithPhpSerialize(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains(
            'An "oth" entry cannot be serialized with serialize(); use the toJson() of its key',
        );

        serialize(new OtherPrimeInfo("\x01\x02", "\x03", "\x04"));
    }

    public function testRefusesAnEntryCraftedForPhpUnserialize(): void
    {
        $crafted = sprintf(
            'O:%d:"%s":1:{s:11:"primeFactor";s:0:"";}',
            strlen(OtherPrimeInfo::class),
            OtherPrimeInfo::class,
        );

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains(
            'An "oth" entry cannot be unserialized with unserialize(); use Jwk::fromJson()',
        );

        unserialize($crafted);
    }
}
