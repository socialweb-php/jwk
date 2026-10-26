<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\Curve;
use SocialWeb\Jwk\KeyType;

use function bin2hex;
use function strlen;

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_ED25519;
use const OPENSSL_KEYTYPE_ED448;
use const OPENSSL_KEYTYPE_RSA;
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

    /**
     * The orders as `openssl ecparam -param_enc explicit -text` prints them
     *
     * @return iterable<string, array{Curve, ?string}>
     */
    public static function orderProvider(): iterable
    {
        yield 'P-256' => [Curve::P256, 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'];
        yield 'P-384' => [
            Curve::P384,
            'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
        ];
        yield 'P-521' => [
            Curve::P521,
            '01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            . 'fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409',
        ];
        yield 'secp256k1' => [Curve::Secp256k1, 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'];
        yield 'Ed25519' => [Curve::Ed25519, null];
        yield 'Ed448' => [Curve::Ed448, null];
        yield 'X25519' => [Curve::X25519, null];
        yield 'X448' => [Curve::X448, null];
    }

    #[DataProvider('orderProvider')]
    public function testGivesTheOrderOfAnEcCurve(Curve $curve, ?string $order): void
    {
        $actual = $curve->order();

        $this->assertSame($order, $actual === null ? null : bin2hex($actual));

        if ($actual !== null) {
            $this->assertSame($curve->publicKeyLength(), strlen($actual));
        }
    }

    public function testMatchesTheCrvValueCaseSensitively(): void
    {
        $this->assertNull(Curve::tryFrom('p-256'));
        $this->assertNull(Curve::tryFrom('ed25519'));
        $this->assertNull(Curve::tryFrom('prime256v1'));
    }

    public function testFindsAnEcCurveByItsOpenSslName(): void
    {
        $this->assertSame(Curve::P256, Curve::fromOpensslCurveName('prime256v1'));
        $this->assertSame(Curve::P384, Curve::fromOpensslCurveName('secp384r1'));
        $this->assertSame(Curve::P521, Curve::fromOpensslCurveName('secp521r1'));
        $this->assertSame(Curve::Secp256k1, Curve::fromOpensslCurveName('secp256k1'));
        $this->assertNull(Curve::fromOpensslCurveName('secp224r1'));
        $this->assertNull(Curve::fromOpensslCurveName('P-256'));
        $this->assertNull(Curve::fromOpensslCurveName(''));
    }

    public function testFindsAnOkpCurveByItsOpenSslKeyType(): void
    {
        $this->assertSame(Curve::Ed25519, Curve::fromOpensslKeyType(OPENSSL_KEYTYPE_ED25519));
        $this->assertSame(Curve::Ed448, Curve::fromOpensslKeyType(OPENSSL_KEYTYPE_ED448));
        $this->assertSame(Curve::X25519, Curve::fromOpensslKeyType(OPENSSL_KEYTYPE_X25519));
        $this->assertSame(Curve::X448, Curve::fromOpensslKeyType(OPENSSL_KEYTYPE_X448));
        $this->assertNull(Curve::fromOpensslKeyType(OPENSSL_KEYTYPE_EC));
        $this->assertNull(Curve::fromOpensslKeyType(OPENSSL_KEYTYPE_RSA));
        $this->assertNull(Curve::fromOpensslKeyType(-1));
    }
}
