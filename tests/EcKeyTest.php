<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\Base64Url;
use SocialWeb\Jwk\Curve;
use SocialWeb\Jwk\EcKey;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\Jwk;
use SocialWeb\Jwk\KeyType;

use function array_keys;
use function hash;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function openssl_verify;
use function print_r;
use function str_pad;
use function str_repeat;
use function strlen;
use function substr;

use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_EC;
use const STR_PAD_LEFT;

class EcKeyTest extends TestCase
{
    public function testParsesTheRfc7517Section3Example(): void
    {
        $fixture = self::fixture('rfc7517/section-3.json');
        $key = Jwk::fromJson(self::fixtureJson('rfc7517/section-3.json'));

        $this->assertInstanceOf(EcKey::class, $key);
        $this->assertSame(KeyType::Ec, $key->keyType());
        $this->assertSame(Curve::P256, $key->curve);
        $this->assertSame(32, strlen($key->x));
        $this->assertSame(32, strlen($key->y));
        $this->assertNull($key->privateKey);
        $this->assertFalse($key->isPrivate());
        $this->assertSame('Public key used in JWS spec Appendix A.3 example', $key->keyId);
        $this->assertSame([], $key->additionalMembers());
        $this->assertEquals($fixture, $key->jsonSerialize());
    }

    public function testParsesTheRfc7517AppendixA2PrivateKeyWhosePublicFormIsAppendixA1(): void
    {
        $private = Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a2.json', 0));
        $public = Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a1.json', 0));

        $this->assertInstanceOf(EcKey::class, $private);
        $this->assertTrue($private->isPrivate());
        $this->assertSame('enc', $private->use);
        $this->assertSame('1', $private->keyId);
        $this->assertEquals(self::fixtureSetMember('rfc7517/appendix-a2.json', 0), $private->jsonSerialize());
        $this->assertEquals($public->jsonSerialize(), $private->toPublic()->jsonSerialize());
        $this->assertSame($public->thumbprint(), $private->thumbprint());
        $this->assertFalse($private->toPublic()->isPrivate());
    }

    /**
     * @return iterable<string, array{string, Curve, bool}>
     */
    public static function fixtureProvider(): iterable
    {
        yield 'RFC 7520 section 3.1, P-521 public' => ['rfc7520/section-3.1.json', Curve::P521, false];
        yield 'RFC 7520 section 3.2, P-521 private' => ['rfc7520/section-3.2.json', Curve::P521, true];
        yield 'RFC 7520 figure 108, P-384 private' => ['rfc7520/section-5.4-figure-108.json', Curve::P384, true];
        yield 'RFC 7520 figure 111, P-384 ephemeral' => ['rfc7520/section-5.4-figure-111.json', Curve::P384, true];
        yield 'RFC 7520 figure 120, P-256 private' => ['rfc7520/section-5.5-figure-120.json', Curve::P256, true];
        yield 'RFC 7520 figure 122, P-256 ephemeral' => ['rfc7520/section-5.5-figure-122.json', Curve::P256, true];
    }

    #[DataProvider('fixtureProvider')]
    public function testParsesAndWritesBackEachFixture(string $file, Curve $curve, bool $private): void
    {
        $fixture = self::fixture($file);
        $key = Jwk::fromJson($fixture);

        $this->assertInstanceOf(EcKey::class, $key);
        $this->assertSame($curve, $key->curve);
        $this->assertSame($private, $key->isPrivate());
        $this->assertSame($curve->publicKeyLength(), strlen($key->x));
        $this->assertSame($curve->publicKeyLength(), strlen($key->y));
        $this->assertSame([], $key->additionalMembers());
        $this->assertEquals($fixture, $key->jsonSerialize());
        $this->assertSame($key->thumbprint(), $key->toPublic()->thumbprint());

        /** @var array{type: int, ec: array{curve_name: string, x: string, y: string, d?: string}} $details */
        $details = openssl_pkey_get_details($key->toOpenSslKey());
        $this->assertSame(OPENSSL_KEYTYPE_EC, $details['type']);
        $this->assertSame($curve->opensslCurveName(), $details['ec']['curve_name']);
        $this->assertSame($key->x, str_pad($details['ec']['x'], $curve->publicKeyLength(), "\0", STR_PAD_LEFT));
        $this->assertSame($private, isset($details['ec']['d']));
    }

    public function testKeepsTheLeadingZeroByteOfAP521Coordinate(): void
    {
        $key = Jwk::fromJson(self::fixture('rfc7520/section-3.1.json'));

        $this->assertInstanceOf(EcKey::class, $key);
        $this->assertSame("\x00", $key->x[0]);
        $this->assertSame(66, strlen($key->x));
    }

    public function testThePublicAndPrivateFormsOfTheRfc7520P521KeyAgree(): void
    {
        $public = Jwk::fromJson(self::fixture('rfc7520/section-3.1.json'));
        $private = Jwk::fromJson(self::fixture('rfc7520/section-3.2.json'));

        $this->assertEquals($public->jsonSerialize(), $private->toPublic()->jsonSerialize());
    }

    public function testComputesTheThumbprintOverCrvKtyXAndY(): void
    {
        $key = Jwk::fromJson(self::fixture('rfc7517/section-3.json'));
        $this->assertInstanceOf(EcKey::class, $key);

        $input = '{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",'
            . '"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}';

        $this->assertSame(Base64Url::encode(hash('sha256', $input, true)), $key->thumbprint());
    }

    public function testThePrivateOpenSslKeySignsWhatThePublicOneVerifies(): void
    {
        $private = Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a2.json', 0));
        $public = Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a1.json', 0));

        $signature = self::sign($private->toOpenSslKey(), OPENSSL_ALGO_SHA256);
        $this->assertSame(1, openssl_verify('message', $signature, $public->toOpenSslKey(), OPENSSL_ALGO_SHA256));
        $this->assertSame(
            1,
            openssl_verify('message', $signature, $private->toPublic()->toOpenSslKey(), OPENSSL_ALGO_SHA256),
        );
    }

    public function testBuildsAKeyOnSecp256k1FromAGeneratedKey(): void
    {
        $generated = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp256k1']);
        $this->assertNotFalse($generated);

        /** @var array{ec: array{x: string, y: string, d: string}} $details */
        $details = openssl_pkey_get_details($generated);

        $key = new EcKey(
            Curve::Secp256k1,
            str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT),
            str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT),
            str_pad($details['ec']['d'], 32, "\0", STR_PAD_LEFT),
            algorithm: 'ES256K',
        );

        $this->assertSame('secp256k1', $key->jsonSerialize()['crv']);
        $this->assertSame($key->jsonSerialize(), Jwk::fromJson($key->toJson())->jsonSerialize());
        $signature = self::sign($key->toOpenSslKey(), OPENSSL_ALGO_SHA256);
        $this->assertSame(
            1,
            openssl_verify('message', $signature, $key->toPublic()->toOpenSslKey(), OPENSSL_ALGO_SHA256),
        );
    }

    /**
     * @return iterable<string, array{array<string, mixed>, InvalidJwkReason, string}>
     */
    public static function refusedProvider(): iterable
    {
        $a2 = self::fixtureSetMember('rfc7517/appendix-a2.json', 0);
        $other = self::fixture('rfc7520/section-5.5-figure-120.json');
        $x = Base64Url::decode(self::fixtureString($a2, 'x'));
        $y = Base64Url::decode(self::fixtureString($a2, 'y'));
        $d = Base64Url::decode(self::fixtureString($a2, 'd'));

        yield 'a missing crv' => [self::without($a2, ['crv']), InvalidJwkReason::MissingMember, 'crv'];
        yield 'a missing x' => [self::without($a2, ['x']), InvalidJwkReason::MissingMember, 'x'];
        yield 'a missing y' => [self::without($a2, ['y']), InvalidJwkReason::MissingMember, 'y'];
        yield 'a curve that is not implemented' => [
            [...$a2, 'crv' => 'P-999'],
            InvalidJwkReason::UnsupportedCurve,
            'crv',
        ];
        yield 'a lowercase curve name' => [[...$a2, 'crv' => 'p-256'], InvalidJwkReason::UnsupportedCurve, 'crv'];
        yield 'an OKP curve' => [[...$a2, 'crv' => 'Ed25519'], InvalidJwkReason::UnsupportedCurve, 'crv'];
        yield 'an x one byte short' => [
            [...$a2, 'x' => Base64Url::encode(substr($x, 1))],
            InvalidJwkReason::WrongLength,
            'x',
        ];
        yield 'an x one byte long' => [
            [...$a2, 'x' => Base64Url::encode("\0" . $x)],
            InvalidJwkReason::WrongLength,
            'x',
        ];
        yield 'a y one byte short' => [
            [...$a2, 'y' => Base64Url::encode(substr($y, 1))],
            InvalidJwkReason::WrongLength,
            'y',
        ];
        yield 'a d one byte short' => [
            [...$a2, 'd' => Base64Url::encode(substr($d, 1))],
            InvalidJwkReason::WrongLength,
            'd',
        ];
        yield 'a y that is not on the curve' => [
            [...$a2, 'y' => Base64Url::encode(substr($y, 0, 31) . ($y[31] === "\0" ? "\1" : "\0"))],
            InvalidJwkReason::PointNotOnCurve,
            'x',
        ];
        yield 'another key\'s d' => [[...$a2, 'd' => $other['d']], InvalidJwkReason::KeyPairMismatch, 'd'];
        yield 'the point with the same x and the negated y' => [
            [...$a2, 'y' => 'H7SaFdupJnh0rUyGQgQq4ReWEOHwOaSZppakkzH36Nw'],
            InvalidJwkReason::KeyPairMismatch,
            'd',
        ];
        yield 'a d of 32 zero bytes' => [
            [...$a2, 'd' => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
            InvalidJwkReason::InvalidValue,
            'd',
        ];
        yield 'a d equal to the curve order' => [
            [...$a2, 'd' => '_____wAAAAD__________7zm-q2nF56E87nKwvxjJVE'],
            InvalidJwkReason::InvalidValue,
            'd',
        ];
        yield 'a d of the curve order plus 1, with the point 1 derives' => [
            [
                ...$a2,
                'x' => 'axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY',
                'y' => 'T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU',
                'd' => '_____wAAAAD__________7zm-q2nF56E87nKwvxjJVI',
            ],
            InvalidJwkReason::InvalidValue,
            'd',
        ];
        yield 'an x that is not base64url' => [
            [...$a2, 'x' => 'not+base64url'],
            InvalidJwkReason::InvalidBase64Url,
            'x',
        ];
        yield 'a y that is not a string' => [[...$a2, 'y' => 1], InvalidJwkReason::WrongType, 'y'];
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

    public function testTheMessagesNameTheCurveAndTheLengths(): void
    {
        $a2 = self::fixtureSetMember('rfc7517/appendix-a2.json', 0);

        try {
            Jwk::fromJson([...$a2, 'x' => 'AQ']);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(
                'The "x" member must decode to 32 bytes for the curve P-256, not 1',
                $exception->getMessage(),
            );
        }

        try {
            new EcKey(Curve::Ed25519, str_repeat("\1", 32), str_repeat("\1", 32));
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame('The curve Ed25519 is not an EC curve', $exception->getMessage());
        }

        try {
            $y = Base64Url::decode(self::fixtureString($a2, 'y'));
            Jwk::fromJson([...$a2, 'y' => Base64Url::encode(substr($y, 0, 31) . ($y[31] === "\0" ? "\1" : "\0"))]);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertStringStartsWith(
                'The "x" and "y" members are not a point on the curve P-256: error:',
                $exception->getMessage(),
            );
        }

        try {
            Jwk::fromJson([...$a2, 'd' => self::fixture('rfc7520/section-5.5-figure-120.json')['d']]);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(
                'The "d" member does not derive the point in the "x" and "y" members',
                $exception->getMessage(),
            );
        }

        $this->assertFalse(openssl_error_string());
    }

    public function testAcceptsThePrivateKeysAtTheEndsOfTheRange(): void
    {
        $x = 'axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY';
        $one = ['kty' => 'EC', 'crv' => 'P-256', 'x' => $x, 'y' => 'T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU'];
        $orderMinusOne = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => $x,
            'y' => 'sBy9HAHlgGVxGBS1g_Bh6dQxzKmUzqExNEm_l8hArgo',
        ];

        $this->assertTrue(Jwk::fromJson([...$one, 'd' => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE'])->isPrivate());
        $this->assertTrue(
            Jwk::fromJson([...$orderMinusOne, 'd' => '_____wAAAAD__________7zm-q2nF56E87nKwvxjJVA'])->isPrivate(),
        );
    }

    public function testThePrivateKeyRangeMessageNamesTheCurve(): void
    {
        try {
            new EcKey(Curve::P384, str_repeat("\1", 48), str_repeat("\1", 48), str_repeat("\0", 48));
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::InvalidValue, $exception->reason);
            $this->assertSame('d', $exception->member);
            $this->assertSame(
                'The "d" member must be an integer from 1 to the order of the curve P-384 minus 1',
                $exception->getMessage(),
            );
        }

        $this->assertFalse(openssl_error_string());
    }

    public function testRedactsThePrivateKeyWhenDumped(): void
    {
        $key = Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a2.json', 0));
        $dump = $key->__debugInfo();

        $this->assertSame(['kty', 'crv', 'x', 'y', 'd', 'use', 'kid'], array_keys($dump));
        $this->assertSame('[redacted]', $dump['d']);
        $this->assertSame('P-256', $dump['crv']);
        $this->assertStringNotContainsString('870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE', print_r($key, true));
        $this->assertEquals($key->toPublic()->jsonSerialize(), $key->toPublic()->__debugInfo());
    }

    /**
     * @param array<string, mixed> $array
     * @param list<string> $names
     *
     * @return array<string, mixed>
     */
    private static function without(array $array, array $names): array
    {
        foreach ($names as $name) {
            unset($array[$name]);
        }

        return $array;
    }
}
