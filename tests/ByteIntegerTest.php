<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\ByteInteger;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;

use function array_fill;
use function array_reverse;
use function count;
use function implode;
use function intdiv;
use function ltrim;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function ord;
use function random_bytes;
use function strlen;

use const OPENSSL_KEYTYPE_RSA;

class ByteIntegerTest extends TestCase
{
    public function testAMinimalIntegerHasNoLeadingZeroByteExceptZeroItself(): void
    {
        $this->assertTrue(ByteInteger::isMinimal("\x01\x00\x01"));
        $this->assertTrue(ByteInteger::isMinimal("\x00"));
        $this->assertTrue(ByteInteger::isMinimal("\xff"));
        $this->assertFalse(ByteInteger::isMinimal("\x00\x01"));
        $this->assertFalse(ByteInteger::isMinimal("\x00\x00"));
        $this->assertFalse(ByteInteger::isMinimal(''));
    }

    public function testZeroIsAnyRunOfZeroBytes(): void
    {
        $this->assertTrue(ByteInteger::isZero("\x00"));
        $this->assertTrue(ByteInteger::isZero("\x00\x00\x00"));
        $this->assertTrue(ByteInteger::isZero(''));
        $this->assertFalse(ByteInteger::isZero("\x00\x01"));
        $this->assertFalse(ByteInteger::isZero("\x01"));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function productProvider(): iterable
    {
        yield 'one times one' => ["\x01", "\x01", "\x01"];
        yield 'zero times anything' => ["\x00", "\xff\xff", "\x00"];
        yield '255 times 255 is 65025' => ["\xff", "\xff", "\xfe\x01"];
        yield '256 times 256 is 65536' => ["\x01\x00", "\x01\x00", "\x01\x00\x00"];
        yield '65537 times 3' => ["\x01\x00\x01", "\x03", "\x03\x00\x03"];
        yield 'a product shorter than the sum of the lengths' => ["\x02", "\x03", "\x06"];
        yield 'the factors in either order' => ["\x12\x34\x56", "\xab\xcd", "\x0c\x37\x89\x5a\xde"];
    }

    #[DataProvider('productProvider')]
    public function testMultipliesUnsignedIntegers(string $a, string $b, string $expected): void
    {
        $this->assertSame($expected, ByteInteger::multiply($a, $b));
        $this->assertSame($expected, ByteInteger::multiply($b, $a));
    }

    public function testTheProductOfThePrimesOfAnRsaKeyIsItsModulus(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        $this->assertNotFalse($key);

        /** @var array{rsa: array{n: string, p: string, q: string}} $details */
        $details = openssl_pkey_get_details($key);

        $this->assertSame($details['rsa']['n'], ByteInteger::multiply($details['rsa']['p'], $details['rsa']['q']));
        $this->assertSame($details['rsa']['n'], ByteInteger::product([$details['rsa']['p'], $details['rsa']['q']]));
    }

    public function testTheProductOfAListMultipliesEveryFactor(): void
    {
        $this->assertSame("\x1e", ByteInteger::product(["\x02", "\x03", "\x05"]));
        $this->assertSame("\x07", ByteInteger::product(["\x07"]));
    }

    public function testTheProductOfTwoRandomIntegersAgreesWithTheirDecimalProduct(): void
    {
        $a = random_bytes(32);
        $b = random_bytes(48);

        $this->assertSame(
            self::multiplyDecimal(self::decimal($a), self::decimal($b)),
            self::decimal(ByteInteger::multiply($a, $b)),
        );
    }

    public function testMinimalDropsLeadingZeroBytesAndKeepsOneForZero(): void
    {
        $this->assertSame("\x01\x02", ByteInteger::minimal("\x00\x00\x01\x02"));
        $this->assertSame("\x00", ByteInteger::minimal("\x00\x00"));
        $this->assertSame("\x00", ByteInteger::minimal(''));
        $this->assertSame("\xff", ByteInteger::minimal("\xff"));
    }

    public function testAnRsaMemberPassesWhenMinimalAndNotZero(): void
    {
        ByteInteger::checkRsaMember('e', "\x01\x00\x01");
        ByteInteger::checkRsaMember('n', "\xff");

        $this->addToAssertionCount(1);
    }

    public function testAnEmptyRsaMemberIsAnInvalidValue(): void
    {
        try {
            ByteInteger::checkRsaMember('n', '');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::InvalidValue, $exception->reason);
            $this->assertSame('n', $exception->member);
            $this->assertSame('The "n" member must not be empty', $exception->getMessage());
        }
    }

    public function testAnRsaMemberWithALeadingZeroByteIsNotMinimal(): void
    {
        try {
            ByteInteger::checkRsaMember('e', "\x00\x01\x00\x01");
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::NonMinimalInteger, $exception->reason);
            $this->assertSame('e', $exception->member);
            $this->assertSame(
                'The "e" member has a leading zero byte, so it is not a minimal Base64urlUInt',
                $exception->getMessage(),
            );
        }
    }

    public function testAZeroRsaMemberIsAnInvalidValue(): void
    {
        try {
            ByteInteger::checkRsaMember('d', "\x00");
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::InvalidValue, $exception->reason);
            $this->assertSame('d', $exception->member);
            $this->assertSame('The "d" member must not be zero', $exception->getMessage());
        }
    }

    /**
     * Converts bytes to a decimal string by schoolbook arithmetic on digit
     * arrays, independently of the class under test
     */
    private static function decimal(string $bytes): string
    {
        $digits = [0];

        for ($i = 0, $length = strlen($bytes); $i < $length; $i++) {
            $carry = ord($bytes[$i]);

            for ($j = 0, $count = count($digits); $j < $count; $j++) {
                $value = $digits[$j] * 256 + $carry;
                $digits[$j] = $value % 10;
                $carry = intdiv($value, 10);
            }

            while ($carry > 0) {
                $digits[] = $carry % 10;
                $carry = intdiv($carry, 10);
            }
        }

        return implode('', array_reverse($digits));
    }

    private static function multiplyDecimal(string $a, string $b): string
    {
        $result = array_fill(0, strlen($a) + strlen($b), 0);

        for ($i = strlen($a) - 1; $i >= 0; $i--) {
            for ($j = strlen($b) - 1; $j >= 0; $j--) {
                $result[$i + $j + 1] += (int) $a[$i] * (int) $b[$j];
            }
        }

        for ($k = count($result) - 1; $k > 0; $k--) {
            $result[$k - 1] += intdiv($result[$k], 10);
            $result[$k] %= 10;
        }

        return ltrim(implode('', $result), '0') === '' ? '0' : ltrim(implode('', $result), '0');
    }
}
