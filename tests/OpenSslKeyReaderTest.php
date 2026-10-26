<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use SocialWeb\Jwk\Base64Url;
use SocialWeb\Jwk\Curve;
use SocialWeb\Jwk\EcKey;
use SocialWeb\Jwk\Exception\ConversionFailed;
use SocialWeb\Jwk\Exception\ConversionFailedReason;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\Jwk;
use SocialWeb\Jwk\OkpKey;
use SocialWeb\Jwk\OpenSsl;
use SocialWeb\Jwk\OpenSslKeyReader;
use SocialWeb\Jwk\RsaKey;

use function array_diff_key;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function strlen;

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_ED25519;
use const OPENSSL_KEYTYPE_ED448;
use const OPENSSL_KEYTYPE_X25519;
use const OPENSSL_KEYTYPE_X448;

class OpenSslKeyReaderTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string, class-string<Jwk>, bool}>
     */
    public static function fixtureProvider(): iterable
    {
        $rsa = 'rfc9421/test-key-rsa';
        $ec = 'rfc9421/test-key-ecc-p256';
        $okp = 'rfc9421/test-key-ed25519';

        yield 'RSA private' => [$rsa . '.private.pem', $rsa . '.json', RsaKey::class, true];
        yield 'RSA public' => [$rsa . '.public.pem', $rsa . '.json', RsaKey::class, false];
        yield 'EC private' => [$ec . '.private.pem', $ec . '.json', EcKey::class, true];
        yield 'EC public' => [$ec . '.public.pem', $ec . '.json', EcKey::class, false];
        yield 'OKP private' => [$okp . '.private.pem', $okp . '.json', OkpKey::class, true];
        yield 'OKP public' => [$okp . '.public.pem', $okp . '.json', OkpKey::class, false];
    }

    /**
     * @param class-string<Jwk> $class
     */
    #[DataProvider('fixtureProvider')]
    public function testReadsTheMembersOpenSslReports(string $pem, string $jwk, string $class, bool $private): void
    {
        $key = OpenSslKeyReader::read(OpenSsl::readPem(self::fixturePem($pem), null));

        $expected = array_diff_key(self::fixture($jwk), ['kid' => true]);

        if (!$private) {
            $expected = array_diff_key($expected, ['d' => 1, 'p' => 1, 'q' => 1, 'dp' => 1, 'dq' => 1, 'qi' => 1]);
        }

        $this->assertInstanceOf($class, $key);
        $this->assertSame($private, $key->isPrivate());
        $this->assertNull($key->keyId);
        $this->assertEquals($expected, $key->jsonSerialize());
        $this->assertFalse(openssl_error_string());
    }

    public function testPadsAnEcCoordinateOpenSslReportsShort(): void
    {
        // About one key in 128 has a coordinate whose high byte is zero, which
        // OpenSSL reports as 31 bytes; keys are generated until one appears.
        do {
            $generated = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

            if ($generated === false) {
                throw new RuntimeException('OpenSSL could not generate a key');
            }

            /** @var array{ec: array{x: string, y: string, d: string}} $details */
            $details = openssl_pkey_get_details($generated);
        } while (strlen($details['ec']['x']) === 32 && strlen($details['ec']['y']) === 32);

        $key = OpenSslKeyReader::read($generated);

        $this->assertInstanceOf(EcKey::class, $key);
        $this->assertSame(32, strlen($key->x));
        $this->assertSame(32, strlen($key->y));
        $this->assertSame(OpenSsl::padLeft($details['ec']['x'], 32), $key->x);
        $this->assertSame(OpenSsl::padLeft($details['ec']['y'], 32), $key->y);
        $this->assertSame(OpenSsl::padLeft($details['ec']['d'], 32), $key->privateKey);
    }

    /**
     * @return iterable<string, array{Curve, string}>
     */
    public static function ecCurveProvider(): iterable
    {
        yield 'P-256' => [Curve::P256, 'prime256v1'];
        yield 'P-384' => [Curve::P384, 'secp384r1'];
        yield 'P-521' => [Curve::P521, 'secp521r1'];
        yield 'secp256k1' => [Curve::Secp256k1, 'secp256k1'];
    }

    #[DataProvider('ecCurveProvider')]
    public function testReadsAGeneratedKeyOnEachEcCurve(Curve $curve, string $curveName): void
    {
        $generated = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curveName]);
        $this->assertNotFalse($generated);

        $key = OpenSslKeyReader::read($generated);

        $this->assertInstanceOf(EcKey::class, $key);
        $this->assertSame($curve, $key->curve);
        $this->assertTrue($key->isPrivate());
        $this->assertSame($curve->publicKeyLength(), strlen($key->x));
        $this->assertSame(OpenSsl::publicPem($generated), $key->toPem());
    }

    /**
     * @return iterable<string, array{Curve, int}>
     */
    public static function okpCurveProvider(): iterable
    {
        yield 'Ed25519' => [Curve::Ed25519, OPENSSL_KEYTYPE_ED25519];
        yield 'Ed448' => [Curve::Ed448, OPENSSL_KEYTYPE_ED448];
        yield 'X25519' => [Curve::X25519, OPENSSL_KEYTYPE_X25519];
        yield 'X448' => [Curve::X448, OPENSSL_KEYTYPE_X448];
    }

    #[DataProvider('okpCurveProvider')]
    public function testReadsAGeneratedKeyOnEachOkpCurve(Curve $curve, int $keyType): void
    {
        $generated = openssl_pkey_new(['private_key_type' => $keyType]);
        $this->assertNotFalse($generated);

        $key = OpenSslKeyReader::read($generated);

        $this->assertInstanceOf(OkpKey::class, $key);
        $this->assertSame($curve, $key->curve);
        $this->assertTrue($key->isPrivate());
        $this->assertSame($curve->publicKeyLength(), strlen($key->publicKey));
        $this->assertSame(OpenSsl::publicPem($generated), $key->toPem());
    }

    public function testReadsAnRsaKeyBuiltFromDAloneAsAPrivateKeyWithoutPrimes(): void
    {
        $fixture = self::fixture('rfc9421/test-key-rsa.json');
        $members = [];

        foreach (['n', 'e', 'd'] as $name) {
            $members[$name] = Base64Url::decode(self::fixtureString($fixture, $name));
        }

        $generated = openssl_pkey_new(['rsa' => $members]);
        $this->assertNotFalse($generated);

        $key = OpenSslKeyReader::read($generated);

        $this->assertInstanceOf(RsaKey::class, $key);
        $this->assertTrue($key->isPrivate());
        $this->assertSame($members['d'], $key->privateExponent);
        $this->assertNull($key->firstPrimeFactor);
    }

    public function testPassesNoCrtMemberWhenOpenSslReportsOnlySomeOfThem(): void
    {
        $fixture = self::fixture('rfc9421/test-key-rsa.json');
        $members = [];

        foreach (['n', 'e', 'd', 'p', 'q'] as $name) {
            $members[$name] = Base64Url::decode(self::fixtureString($fixture, $name));
        }

        $generated = openssl_pkey_new(['rsa' => $members]);
        $this->assertNotFalse($generated);

        /** @var array{rsa: array<string, string>} $details */
        $details = openssl_pkey_get_details($generated);
        $this->assertArrayHasKey('p', $details['rsa']);
        $this->assertArrayNotHasKey('dmp1', $details['rsa']);

        $key = OpenSslKeyReader::read($generated);

        $this->assertInstanceOf(RsaKey::class, $key);
        $this->assertSame($members['d'], $key->privateExponent);
        $this->assertNull($key->firstPrimeFactor);
        $this->assertNull($key->secondPrimeFactor);
    }

    public function testAppliesTheRulesOfAParsedKeyToTheMembersOpenSslReports(): void
    {
        $fixture = self::fixture('rfc9421/test-key-rsa.json');
        $generated = openssl_pkey_new(['rsa' => [
            'n' => Base64Url::decode(self::fixtureString($fixture, 'n')),
            'e' => "\x01",
            'd' => Base64Url::decode(self::fixtureString($fixture, 'd')),
        ],
        ]);
        $this->assertNotFalse($generated);

        try {
            OpenSslKeyReader::read($generated);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::InvalidValue, $exception->reason);
            $this->assertSame('e', $exception->member);
        }
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function unsupportedKeyProvider(): iterable
    {
        yield 'DSA' => ['generated/dsa-public.pem', 'The key is a DSA key, which the package does not implement'];
        yield 'DH' => ['generated/dh-public.pem', 'The key is a DH key, which the package does not implement'];
        yield 'RSA with the id-RSASSA-PSS identifier' => [
            'rfc9421/test-key-rsa-pss.private.pem',
            'The key is of a type OpenSSL does not describe (type -1), such as an RSA key with the id-RSASSA-PSS'
            . ' algorithm identifier, which the package does not read',
        ];
    }

    #[DataProvider('unsupportedKeyProvider')]
    public function testRefusesAKeyTypeThePackageDoesNotImplement(string $file, string $message): void
    {
        $key = OpenSsl::readPem(self::fixturePem($file), null);

        try {
            OpenSslKeyReader::read($key);
            $this->fail('Expected ConversionFailed');
        } catch (ConversionFailed $exception) {
            $this->assertSame(ConversionFailedReason::UnsupportedKey, $exception->reason);
            $this->assertSame($message, $exception->getMessage());
        }

        $this->assertFalse(openssl_error_string());
    }

    public function testRefusesAnEcCurveThePackageDoesNotImplement(): void
    {
        $generated = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp224r1']);
        $this->assertNotFalse($generated);

        try {
            OpenSslKeyReader::read($generated);
            $this->fail('Expected ConversionFailed');
        } catch (ConversionFailed $exception) {
            $this->assertSame(ConversionFailedReason::UnsupportedKey, $exception->reason);
            $this->assertSame(
                'The key is on the EC curve secp224r1, which the package does not implement',
                $exception->getMessage(),
            );
        }
    }
}
