<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\Curve;
use SocialWeb\Jwk\KeyType;

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_ED25519;
use const OPENSSL_KEYTYPE_ED448;
use const OPENSSL_KEYTYPE_X25519;
use const OPENSSL_KEYTYPE_X448;

class CurveTest extends TestCase
{
    /**
     * @return iterable<string, array{Curve, string, KeyType, int, int, ?string, int, ?string}>
     */
    public static function curveProvider(): iterable
    {
        yield 'P-256' => [Curve::P256, 'P-256', KeyType::Ec, 32, 32, 'prime256v1', OPENSSL_KEYTYPE_EC, null];
        yield 'P-384' => [Curve::P384, 'P-384', KeyType::Ec, 48, 48, 'secp384r1', OPENSSL_KEYTYPE_EC, null];
        yield 'P-521' => [Curve::P521, 'P-521', KeyType::Ec, 66, 66, 'secp521r1', OPENSSL_KEYTYPE_EC, null];
        yield 'secp256k1' => [
            Curve::Secp256k1, 'secp256k1', KeyType::Ec, 32, 32, 'secp256k1', OPENSSL_KEYTYPE_EC, null,
        ];
        yield 'Ed25519' => [Curve::Ed25519, 'Ed25519', KeyType::Okp, 32, 32, null, OPENSSL_KEYTYPE_ED25519, 'ed25519'];
        yield 'Ed448' => [Curve::Ed448, 'Ed448', KeyType::Okp, 57, 57, null, OPENSSL_KEYTYPE_ED448, 'ed448'];
        yield 'X25519' => [Curve::X25519, 'X25519', KeyType::Okp, 32, 32, null, OPENSSL_KEYTYPE_X25519, 'x25519'];
        yield 'X448' => [Curve::X448, 'X448', KeyType::Okp, 56, 56, null, OPENSSL_KEYTYPE_X448, 'x448'];
    }

    #[DataProvider('curveProvider')]
    public function testDescribesEachCurve(
        Curve $curve,
        string $crv,
        KeyType $keyType,
        int $publicKeyLength,
        int $privateKeyLength,
        ?string $opensslCurveName,
        int $opensslKeyType,
        ?string $opensslDetailsKey,
    ): void {
        $this->assertSame($crv, $curve->value);
        $this->assertSame($keyType, $curve->keyType());
        $this->assertSame($publicKeyLength, $curve->publicKeyLength());
        $this->assertSame($privateKeyLength, $curve->privateKeyLength());
        $this->assertSame($opensslCurveName, $curve->opensslCurveName());
        $this->assertSame($opensslKeyType, $curve->opensslKeyType());
        $this->assertSame($opensslDetailsKey, $curve->opensslDetailsKey());
    }

    public function testMatchesTheCrvValueCaseSensitively(): void
    {
        $this->assertNull(Curve::tryFrom('p-256'));
        $this->assertNull(Curve::tryFrom('ed25519'));
        $this->assertNull(Curve::tryFrom('prime256v1'));
    }
}
