<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\Base64Url;
use SocialWeb\Jwk\RsaPublicKeyInfo;

use function base64_decode;
use function explode;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function openssl_pkey_new;
use function preg_replace;
use function str_ends_with;
use function str_repeat;
use function str_starts_with;
use function strlen;
use function substr;
use function substr_count;
use function trim;

use const OPENSSL_KEYTYPE_RSA;

class RsaPublicKeyInfoTest extends TestCase
{
    /**
     * @return iterable<string, array{int}>
     */
    public static function keySizeProvider(): iterable
    {
        yield '1024 bits' => [1024];
        yield '2048 bits' => [2048];
        yield '3072 bits' => [3072];
        yield '4096 bits' => [4096];
    }

    #[DataProvider('keySizeProvider')]
    public function testEncodesTheSameDerAsOpenSsl(int $bits): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $bits]);
        $this->assertNotFalse($key);

        /** @var array{key: string, rsa: array{n: string, e: string}} $details */
        $details = openssl_pkey_get_details($key);

        $this->assertSame(
            self::derOfPem($details['key']),
            RsaPublicKeyInfo::der($details['rsa']['n'], $details['rsa']['e']),
        );
        $this->assertSame($details['key'], RsaPublicKeyInfo::pem($details['rsa']['n'], $details['rsa']['e']));
    }

    public function testEncodesTheRfc7517AppendixA1KeyAsAPemOpenSslReadsBack(): void
    {
        /** @var array{n: string, e: string} $jwk */
        $jwk = self::fixtureSetMember('rfc7517/appendix-a1.json', 1);
        $modulus = Base64Url::decode($jwk['n']);
        $exponent = Base64Url::decode($jwk['e']);

        $pem = RsaPublicKeyInfo::pem($modulus, $exponent);
        $key = openssl_pkey_get_public($pem);
        $this->assertNotFalse($key);

        /** @var array{bits: int, type: int, rsa: array{n: string, e: string}} $details */
        $details = openssl_pkey_get_details($key);

        $this->assertSame(OPENSSL_KEYTYPE_RSA, $details['type']);
        $this->assertSame(2048, $details['bits']);
        $this->assertSame($modulus, $details['rsa']['n']);
        $this->assertSame($exponent, $details['rsa']['e']);
    }

    public function testWritesThePemInTheStrictFormOfRfc7468(): void
    {
        $pem = RsaPublicKeyInfo::pem("\x80\x00\x00\x00\x00\x00\x00\x01", "\x01\x00\x01");

        $this->assertTrue(str_starts_with($pem, "-----BEGIN PUBLIC KEY-----\n"));
        $this->assertTrue(str_ends_with($pem, "\n-----END PUBLIC KEY-----\n"));
        $this->assertSame(0, substr_count($pem, "\r"));

        foreach (explode("\n", trim($pem)) as $line) {
            $this->assertLessThanOrEqual(64, strlen($line));
        }
    }

    public function testAddsAZeroByteBeforeAnIntegerWhoseHighBitIsSet(): void
    {
        // 30 15: SEQUENCE of 21 bytes; 30 0d ...: the algorithm identifier;
        // 03 04 00 30 01 ...? The BIT STRING holds SEQUENCE { INTEGER 00 80, INTEGER 03 }.
        $der = RsaPublicKeyInfo::der("\x80", "\x03");

        $this->assertSame(
            "\x30\x1b" . "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00"
            . "\x03\x0a\x00" . "\x30\x07" . "\x02\x02\x00\x80" . "\x02\x01\x03",
            $der,
        );
    }

    public function testWritesALongFormLengthOnceTheContentsReach128Bytes(): void
    {
        $modulus = "\x7f" . str_repeat("\x01", 126);
        $der = RsaPublicKeyInfo::der($modulus, "\x03");

        // The RSAPublicKey SEQUENCE holds a 129-byte INTEGER (2 + 127) and a
        // 3-byte INTEGER, so its length, 132, takes the long form 81 84.
        $this->assertStringContainsString("\x30\x81\x84\x02\x7f\x7f", $der);
        // The outer SEQUENCE then holds 15 + 3 + 1 + 135 = 154 bytes.
        $this->assertSame("\x30\x81\x9a", substr($der, 0, 3));
    }

    public function testSwitchesToTheLongFormAtExactly128Bytes(): void
    {
        // INTEGER of 122 bytes (2 + 122 = 124) plus INTEGER 03 (3) is 127: short form.
        $der = RsaPublicKeyInfo::der("\x7f" . str_repeat("\x01", 121), "\x03");
        $this->assertStringContainsString("\x30\x7f\x02\x7a\x7f", $der);

        // One byte more is 128: long form 81 80.
        $der = RsaPublicKeyInfo::der("\x7f" . str_repeat("\x01", 122), "\x03");
        $this->assertStringContainsString("\x30\x81\x80\x02\x7b\x7f", $der);
    }

    public function testEncodesZeroAsASingleZeroByteInteger(): void
    {
        $der = RsaPublicKeyInfo::der("\x00\x00", "\x00");

        $this->assertStringContainsString("\x02\x01\x00\x02\x01\x00", $der);
    }

    private static function derOfPem(string $pem): string
    {
        $base64 = (string) preg_replace('/-----[^-]+-----|\s/', '', $pem);

        return (string) base64_decode($base64, true);
    }
}
