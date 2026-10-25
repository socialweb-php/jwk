<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\OtherPrimeInfo;

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
}
