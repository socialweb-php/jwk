<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\AlgorithmFit;
use SocialWeb\Jwk\Curve;
use SocialWeb\Jwk\KeyType;

use function in_array;

class AlgorithmFitTest extends TestCase
{
    private const array ECDH_ES = ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'];

    /**
     * @return iterable<string, array{KeyType, ?Curve, list<string>}>
     */
    public static function fitProvider(): iterable
    {
        yield 'RSA' => [
            KeyType::Rsa,
            null,
            ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256'],
        ];
        yield 'EC on P-256' => [KeyType::Ec, Curve::P256, ['ES256', ...self::ECDH_ES]];
        yield 'EC on P-384' => [KeyType::Ec, Curve::P384, ['ES384', ...self::ECDH_ES]];
        yield 'EC on P-521' => [KeyType::Ec, Curve::P521, ['ES512', ...self::ECDH_ES]];
        yield 'EC on secp256k1' => [KeyType::Ec, Curve::Secp256k1, ['ES256K']];
        yield 'OKP on Ed25519' => [KeyType::Okp, Curve::Ed25519, ['EdDSA', 'Ed25519']];
        yield 'OKP on Ed448' => [KeyType::Okp, Curve::Ed448, ['EdDSA', 'Ed448']];
        yield 'OKP on X25519' => [KeyType::Okp, Curve::X25519, self::ECDH_ES];
        yield 'OKP on X448' => [KeyType::Okp, Curve::X448, self::ECDH_ES];
        yield 'oct' => [
            KeyType::Oct,
            null,
            [
                'HS256', 'HS384', 'HS512',
                'A128KW', 'A192KW', 'A256KW',
                'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
                'dir',
                'A128GCM', 'A192GCM', 'A256GCM',
                'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512',
            ],
        ];
    }

    /**
     * @param list<string> $fitting
     */
    #[DataProvider('fitProvider')]
    public function testExactlyTheTabledAlgorithmsFitEachKey(KeyType $keyType, ?Curve $curve, array $fitting): void
    {
        foreach ($fitting as $algorithm) {
            $this->assertTrue(AlgorithmFit::fits($algorithm, $keyType, $curve), $algorithm . ' should fit');
            $this->assertTrue(AlgorithmFit::isRegistered($algorithm));
        }

        foreach (self::everyRegisteredAlgorithm() as $algorithm) {
            if (!in_array($algorithm, $fitting, true)) {
                $this->assertFalse(AlgorithmFit::fits($algorithm, $keyType, $curve), $algorithm . ' should not fit');
            }
        }
    }

    public function testAnUnregisteredAlgorithmFitsEveryKey(): void
    {
        $this->assertFalse(AlgorithmFit::isRegistered('ES256-custom'));
        $this->assertTrue(AlgorithmFit::fits('ES256-custom', KeyType::Rsa, null));
        $this->assertTrue(AlgorithmFit::fits('ES256-custom', KeyType::Ec, Curve::P256));
        $this->assertTrue(AlgorithmFit::fits('ES256-custom', KeyType::Okp, Curve::Ed25519));
        $this->assertTrue(AlgorithmFit::fits('ES256-custom', KeyType::Oct, null));
        $this->assertTrue(AlgorithmFit::fits('', KeyType::Oct, null));
    }

    public function testNoneAndPbes2FitNoKey(): void
    {
        foreach (['none', 'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW'] as $algorithm) {
            $this->assertTrue(AlgorithmFit::isRegistered($algorithm));
            $this->assertFalse(AlgorithmFit::fits($algorithm, KeyType::Rsa, null));
            $this->assertFalse(AlgorithmFit::fits($algorithm, KeyType::Oct, null));
            $this->assertFalse(AlgorithmFit::fits($algorithm, KeyType::Ec, Curve::P256));
            $this->assertFalse(AlgorithmFit::fits($algorithm, KeyType::Okp, Curve::Ed25519));
        }
    }

    public function testAnEcOrOkpKeyWithoutACurveFitsNoRegisteredAlgorithm(): void
    {
        $this->assertFalse(AlgorithmFit::fits('ES256', KeyType::Ec, null));
        $this->assertFalse(AlgorithmFit::fits('EdDSA', KeyType::Okp, null));
    }

    public function testACurveOfAnotherKeyTypeFitsNoAlgorithm(): void
    {
        $this->assertFalse(AlgorithmFit::fits('EdDSA', KeyType::Ec, Curve::Ed25519));
        $this->assertFalse(AlgorithmFit::fits('ES256', KeyType::Okp, Curve::P256));
        $this->assertFalse(AlgorithmFit::fits('ES256', KeyType::Rsa, Curve::P256));
        $this->assertFalse(AlgorithmFit::fits('unregistered', KeyType::Ec, Curve::X25519));
        $this->assertTrue(AlgorithmFit::fits('EdDSA', KeyType::Okp, Curve::Ed25519));
    }

    public function testTheNamesAreCaseSensitive(): void
    {
        $this->assertFalse(AlgorithmFit::isRegistered('rs256'));
        $this->assertFalse(AlgorithmFit::isRegistered('eddsa'));
    }

    /**
     * @return list<string>
     */
    private static function everyRegisteredAlgorithm(): array
    {
        $algorithms = ['none', 'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW'];

        foreach (self::fitProvider() as [, , $fitting]) {
            foreach ($fitting as $algorithm) {
                if (!in_array($algorithm, $algorithms, true)) {
                    $algorithms[] = $algorithm;
                }
            }
        }

        return $algorithms;
    }
}
