<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\Base64Url;
use SocialWeb\Jwk\Curve;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\Jwk;
use SocialWeb\Jwk\KeyType;
use SocialWeb\Jwk\OkpKey;

use function array_keys;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_verify;
use function print_r;
use function str_repeat;
use function strlen;
use function substr;

class OkpKeyTest extends TestCase
{
    private const string RFC8037_THUMBPRINT = 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k';

    /**
     * RFC 8032 section 7.1, TEST 1, which is also RFC 8037 appendix A.1
     */
    private const string ED25519_TEST1_SECRET = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';

    private const string ED25519_TEST1_PUBLIC = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';

    /**
     * RFC 8032 section 7.1, TEST 2
     */
    private const string ED25519_TEST2_SECRET = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';

    private const string ED25519_TEST2_PUBLIC = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';

    /**
     * RFC 8032 section 7.4, the "Blank" vector
     */
    private const string ED448_SECRET = '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3'
        . '528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b';

    private const string ED448_PUBLIC = '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778'
        . 'edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180';

    /**
     * RFC 7748 section 6.1
     */
    private const string X25519_ALICE_SECRET = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';

    private const string X25519_ALICE_PUBLIC = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';

    private const string X25519_BOB_SECRET = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb';

    private const string X25519_BOB_PUBLIC = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f';

    /**
     * RFC 7748 section 6.2
     */
    private const string X448_ALICE_SECRET = '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d'
        . 'd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b';

    private const string X448_ALICE_PUBLIC = '9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c'
        . '22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0';

    private const string X448_BOB_SECRET = '1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d'
        . '6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d';

    private const string X448_BOB_PUBLIC = '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430'
        . '27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609';

    public function testParsesTheRfc8037AppendixA1PrivateKey(): void
    {
        $fixture = self::fixture('rfc8037/appendix-a1.json');
        $key = Jwk::fromJson(self::fixtureJson('rfc8037/appendix-a1.json'));

        $this->assertInstanceOf(OkpKey::class, $key);
        $this->assertSame(KeyType::Okp, $key->keyType());
        $this->assertSame(Curve::Ed25519, $key->curve);
        $this->assertTrue($key->isPrivate());
        $this->assertSame(self::hex(self::ED25519_TEST1_SECRET), $key->privateKey);
        $this->assertSame(self::hex(self::ED25519_TEST1_PUBLIC), $key->publicKey);
        $this->assertSame([], $key->additionalMembers());
        $this->assertEquals($fixture, $key->jsonSerialize());
    }

    public function testTheAppendixA2PublicKeyIsTheAppendixA1KeyWithoutD(): void
    {
        $private = Jwk::fromJson(self::fixture('rfc8037/appendix-a1.json'));
        $public = Jwk::fromJson(self::fixture('rfc8037/appendix-a2.json'));

        $this->assertInstanceOf(OkpKey::class, $public);
        $this->assertFalse($public->isPrivate());
        $this->assertNull($public->privateKey);
        $this->assertEquals($public->jsonSerialize(), $private->toPublic()->jsonSerialize());
        $this->assertSame(['kty', 'crv', 'x'], array_keys($private->toPublic()->jsonSerialize()));
    }

    public function testComputesTheAppendixA3Thumbprint(): void
    {
        $private = Jwk::fromJson(self::fixture('rfc8037/appendix-a1.json'));
        $public = Jwk::fromJson(self::fixture('rfc8037/appendix-a2.json'));

        $this->assertSame(self::RFC8037_THUMBPRINT, $public->thumbprint());
        $this->assertSame(self::RFC8037_THUMBPRINT, $private->thumbprint());
    }

    /**
     * @return iterable<string, array{string, Curve, string}>
     */
    public static function montgomeryFixtureProvider(): iterable
    {
        yield 'RFC 8037 appendix A.6, Bob' => ['rfc8037/appendix-a6-bob.json', Curve::X25519, self::X25519_BOB_PUBLIC];
        yield 'RFC 8037 appendix A.6, ephemeral' => [
            'rfc8037/appendix-a6-ephemeral.json',
            Curve::X25519,
            self::X25519_ALICE_PUBLIC,
        ];
        yield 'RFC 8037 appendix A.7, Dave' => ['rfc8037/appendix-a7-dave.json', Curve::X448, self::X448_BOB_PUBLIC];
        yield 'RFC 8037 appendix A.7, ephemeral' => [
            'rfc8037/appendix-a7-ephemeral.json',
            Curve::X448,
            self::X448_ALICE_PUBLIC,
        ];
    }

    #[DataProvider('montgomeryFixtureProvider')]
    public function testParsesTheRfc8037KeyAgreementKeysWhichAreTheRfc7748Vectors(
        string $file,
        Curve $curve,
        string $publicHex,
    ): void {
        $fixture = self::fixture($file);
        $key = Jwk::fromJson($fixture);

        $this->assertInstanceOf(OkpKey::class, $key);
        $this->assertSame($curve, $key->curve);
        $this->assertSame(self::hex($publicHex), $key->publicKey);
        $this->assertFalse($key->isPrivate());
        $this->assertEquals($fixture, $key->jsonSerialize());

        /** @var array{type: int} $details */
        $details = openssl_pkey_get_details($key->toOpenSslKey());
        $this->assertSame($curve->opensslKeyType(), $details['type']);
    }

    /**
     * @return iterable<string, array{Curve, string, string}>
     */
    public static function keyPairProvider(): iterable
    {
        yield 'Ed25519, RFC 8032 TEST 1' => [Curve::Ed25519, self::ED25519_TEST1_SECRET, self::ED25519_TEST1_PUBLIC];
        yield 'Ed25519, RFC 8032 TEST 2' => [Curve::Ed25519, self::ED25519_TEST2_SECRET, self::ED25519_TEST2_PUBLIC];
        yield 'Ed448, RFC 8032 Blank' => [Curve::Ed448, self::ED448_SECRET, self::ED448_PUBLIC];
        yield 'X25519, Alice' => [Curve::X25519, self::X25519_ALICE_SECRET, self::X25519_ALICE_PUBLIC];
        yield 'X25519, Bob' => [Curve::X25519, self::X25519_BOB_SECRET, self::X25519_BOB_PUBLIC];
        yield 'X448, Alice' => [Curve::X448, self::X448_ALICE_SECRET, self::X448_ALICE_PUBLIC];
        yield 'X448, Bob' => [Curve::X448, self::X448_BOB_SECRET, self::X448_BOB_PUBLIC];
    }

    #[DataProvider('keyPairProvider')]
    public function testAcceptsEachSpecificationKeyPair(Curve $curve, string $secretHex, string $publicHex): void
    {
        $key = new OkpKey($curve, self::hex($publicHex), self::hex($secretHex));

        $this->assertTrue($key->isPrivate());
        $this->assertSame($curve->publicKeyLength(), strlen($key->publicKey));
        $this->assertSame($key->toPublic()->thumbprint(), $key->thumbprint());
        $this->assertSame($key->jsonSerialize(), Jwk::fromJson($key->toJson())->jsonSerialize());

        /** @var array<string, mixed> $details */
        $details = openssl_pkey_get_details($key->toOpenSslKey());
        $this->assertSame($curve->opensslKeyType(), $details['type']);
        /** @var array{pub_key: string, priv_key: string} $members */
        $members = $details[(string) $curve->opensslDetailsKey()];
        $this->assertSame(self::hex($publicHex), $members['pub_key']);
        $this->assertSame(self::hex($secretHex), $members['priv_key']);
    }

    public function testTheEdwardsPrivateKeySignsWhatThePublicKeyVerifies(): void
    {
        $private = Jwk::fromJson(self::fixture('rfc8037/appendix-a1.json'));
        $public = Jwk::fromJson(self::fixture('rfc8037/appendix-a2.json'));

        $signature = self::sign($private->toOpenSslKey(), 0);
        $this->assertSame(1, openssl_verify('message', $signature, $public->toOpenSslKey(), 0));
        $this->assertSame(1, openssl_verify('message', $signature, $private->toPublic()->toOpenSslKey(), 0));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, InvalidJwkReason, string}>
     */
    public static function refusedProvider(): iterable
    {
        $a1 = self::fixture('rfc8037/appendix-a1.json');
        $x = Base64Url::decode(self::fixtureString($a1, 'x'));

        yield 'a missing crv' => [['kty' => 'OKP', 'x' => $a1['x']], InvalidJwkReason::MissingMember, 'crv'];
        yield 'a missing x' => [['kty' => 'OKP', 'crv' => 'Ed25519'], InvalidJwkReason::MissingMember, 'x'];
        yield 'a curve that is not implemented' => [
            [...$a1, 'crv' => 'Ed999'],
            InvalidJwkReason::UnsupportedCurve,
            'crv',
        ];
        yield 'an EC curve' => [[...$a1, 'crv' => 'P-256'], InvalidJwkReason::UnsupportedCurve, 'crv'];
        yield 'an x one byte short' => [
            [...$a1, 'x' => Base64Url::encode(substr($x, 1))],
            InvalidJwkReason::WrongLength,
            'x',
        ];
        yield 'an x one byte long' => [
            [...$a1, 'x' => Base64Url::encode("\0" . $x)],
            InvalidJwkReason::WrongLength,
            'x',
        ];
        yield 'a d of the wrong length' => [[...$a1, 'd' => 'AQID'], InvalidJwkReason::WrongLength, 'd'];
        yield 'another key\'s d' => [
            [...$a1, 'd' => Base64Url::encode(self::hex(self::ED25519_TEST2_SECRET))],
            InvalidJwkReason::KeyPairMismatch,
            'd',
        ];
        yield 'an X25519 public key with another private key' => [
            [
                'kty' => 'OKP',
                'crv' => 'X25519',
                'x' => Base64Url::encode(self::hex(self::X25519_BOB_PUBLIC)),
                'd' => Base64Url::encode(self::hex(self::X25519_ALICE_SECRET)),
            ],
            InvalidJwkReason::KeyPairMismatch,
            'd',
        ];
        yield 'an X448 public key of the X25519 length' => [
            ['kty' => 'OKP', 'crv' => 'X448', 'x' => Base64Url::encode(self::hex(self::X25519_BOB_PUBLIC))],
            InvalidJwkReason::WrongLength,
            'x',
        ];
        yield 'an x that is not base64url' => [
            [...$a1, 'x' => 'not+base64url'],
            InvalidJwkReason::InvalidBase64Url,
            'x',
        ];
        yield 'a crv that is not a string' => [[...$a1, 'crv' => 25519], InvalidJwkReason::WrongType, 'crv'];
        yield 'an x that is a number' => [[...$a1, 'x' => 1], InvalidJwkReason::WrongType, 'x'];
        yield 'a d that is an array' => [[...$a1, 'd' => []], InvalidJwkReason::WrongType, 'd'];
    }

    /**
     * @param array<string, mixed> $jwk
     */
    #[DataProvider('refusedProvider')]
    public function testRefusesAMalformedKey(array $jwk, InvalidJwkReason $reason, string $member): void
    {
        try {
            Jwk::fromJson($jwk);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame($reason, $exception->reason);
            $this->assertSame($member, $exception->member);
        }

        $this->assertFalse(openssl_error_string());
    }

    public function testAParsedX25519PrivateKeyLeavesNoOpenSslError(): void
    {
        $key = new OkpKey(
            Curve::X25519,
            self::hex(self::X25519_ALICE_PUBLIC),
            self::hex(self::X25519_ALICE_SECRET),
        );

        $this->assertTrue($key->isPrivate());
        $this->assertFalse(openssl_error_string());
    }

    public function testTheMessagesNameTheCurveAndTheMembers(): void
    {
        try {
            new OkpKey(Curve::P256, str_repeat("\1", 32));
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame('The curve P-256 is not an OKP curve', $exception->getMessage());
        }

        try {
            new OkpKey(Curve::Ed448, str_repeat("\1", 32));
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(
                'The "x" member must decode to 57 bytes for the curve Ed448, not 32',
                $exception->getMessage(),
            );
        }

        try {
            new OkpKey(Curve::Ed25519, self::hex(self::ED25519_TEST1_PUBLIC), self::hex(self::ED25519_TEST2_SECRET));
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(
                'The "d" member does not derive the public key in the "x" member',
                $exception->getMessage(),
            );
        }
    }

    public function testRedactsThePrivateKeyWhenDumped(): void
    {
        $key = Jwk::fromJson(self::fixture('rfc8037/appendix-a1.json'));
        $dump = $key->__debugInfo();

        $this->assertSame(
            [
                'kty' => 'OKP',
                'crv' => 'Ed25519',
                'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
                'd' => '[redacted]',
            ],
            $dump,
        );
        $this->assertStringNotContainsString('nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A', print_r($key, true));
        $this->assertEquals($key->toPublic()->jsonSerialize(), $key->toPublic()->__debugInfo());
    }
}
