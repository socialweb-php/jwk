<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use ReflectionClass;
use SocialWeb\Jwk\Base64Url;
use SocialWeb\Jwk\Exception\ConversionFailed;
use SocialWeb\Jwk\Exception\ConversionFailedReason;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\Jwk;
use SocialWeb\Jwk\KeyType;
use SocialWeb\Jwk\OtherPrimeInfo;
use SocialWeb\Jwk\RsaKey;

use function array_keys;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function openssl_verify;
use function print_r;
use function str_repeat;
use function strlen;
use function substr;

use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_RSA;

class RsaKeyTest extends TestCase
{
    private const string RFC7638_THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

    public function testParsesTheRfc7638PublicKeyAndComputesItsThumbprint(): void
    {
        $fixture = self::fixture('rfc7638/section-3.1.json');
        $key = Jwk::fromJson($fixture);

        $this->assertInstanceOf(RsaKey::class, $key);
        $this->assertSame(KeyType::Rsa, $key->keyType());
        $this->assertFalse($key->isPrivate());
        $this->assertSame(256, strlen($key->modulus));
        $this->assertSame("\x01\x00\x01", $key->publicExponent);
        $this->assertNull($key->privateExponent);
        $this->assertSame('RS256', $key->algorithm);
        $this->assertSame('2011-04-29', $key->keyId);
        $this->assertSame(self::RFC7638_THUMBPRINT, $key->thumbprint());
        $this->assertEquals($fixture, $key->jsonSerialize());
    }

    public function testParsesTheRfc7517AppendixA1PublicKey(): void
    {
        $fixture = self::fixtureSetMember('rfc7517/appendix-a1.json', 1);
        $key = Jwk::fromJson($fixture);

        $this->assertInstanceOf(RsaKey::class, $key);
        $this->assertSame(self::RFC7638_THUMBPRINT, $key->thumbprint());
        $this->assertEquals($fixture, $key->jsonSerialize());
        $this->assertEquals($fixture, $key->toPublic()->jsonSerialize());
    }

    public function testParsesTheRfc7517AppendixA2PrivateKey(): void
    {
        $fixture = self::fixtureSetMember('rfc7517/appendix-a2.json', 1);
        $key = Jwk::fromJson($fixture);

        $this->assertInstanceOf(RsaKey::class, $key);
        $this->assertTrue($key->isPrivate());
        $this->assertNotNull($key->privateExponent);
        $this->assertNotNull($key->firstPrimeFactor);
        $this->assertNotNull($key->secondPrimeFactor);
        $this->assertNotNull($key->firstFactorCrtExponent);
        $this->assertNotNull($key->secondFactorCrtExponent);
        $this->assertNotNull($key->firstCrtCoefficient);
        $this->assertSame([], $key->otherPrimesInfo);
        $this->assertSame([], $key->additionalMembers);
        $this->assertEquals($fixture, $key->jsonSerialize());
    }

    public function testLeavesNoOpenSslErrorBehind(): void
    {
        @openssl_pkey_get_public('not a key');
        Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a1.json', 1));
        $this->assertFalse(openssl_error_string());

        @openssl_pkey_get_public('not a key');
        Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a2.json', 1));
        $this->assertFalse(openssl_error_string());

        try {
            Jwk::fromJson([...self::fixtureSetMember('rfc7517/appendix-a2.json', 1), 'd' => 'AQ']);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk) {
            $this->assertFalse(openssl_error_string());
        }
    }

    public function testAPrivateKeyHasTheThumbprintOfItsPublicForm(): void
    {
        $key = Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a2.json', 1));

        $this->assertSame(self::RFC7638_THUMBPRINT, $key->thumbprint());
        $this->assertSame(self::RFC7638_THUMBPRINT, $key->toPublic()->thumbprint());
    }

    public function testToPublicDropsEveryPrivateMemberAndKeepsTheCommonOnes(): void
    {
        $key = Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a2.json', 1));
        $public = $key->toPublic();

        $this->assertInstanceOf(RsaKey::class, $public);
        $this->assertFalse($public->isPrivate());
        $this->assertNull($public->privateExponent);
        $this->assertNull($public->firstPrimeFactor);
        $this->assertNull($public->firstCrtCoefficient);
        $this->assertSame('2011-04-29', $public->keyId);
        $this->assertSame('RS256', $public->algorithm);
        $this->assertEquals(self::fixtureSetMember('rfc7517/appendix-a1.json', 1), $public->jsonSerialize());
        $this->assertTrue($key->isPrivate());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function privateKeyFixtureProvider(): iterable
    {
        yield 'RFC 7517 appendix C.1' => ['rfc7517/appendix-c1.json'];
        yield 'RFC 7520 section 3.4' => ['rfc7520/section-3.4.json'];
    }

    #[DataProvider('privateKeyFixtureProvider')]
    public function testParsesAndWritesBackAPrivateKeyFixture(string $file): void
    {
        $fixture = self::fixture($file);
        $key = Jwk::fromJson(self::fixtureJson($file));

        $this->assertInstanceOf(RsaKey::class, $key);
        $this->assertTrue($key->isPrivate());
        $this->assertEquals($fixture, $key->jsonSerialize());
    }

    public function testParsesTheRfc7520Section33PublicKeyAsThePublicFormOfSection34(): void
    {
        $public = Jwk::fromJson(self::fixture('rfc7520/section-3.3.json'));
        $private = Jwk::fromJson(self::fixture('rfc7520/section-3.4.json'));

        $this->assertEquals($public->jsonSerialize(), $private->toPublic()->jsonSerialize());
        $this->assertSame($public->thumbprint(), $private->thumbprint());
    }

    public function testTheOpenSslKeyOfAPublicKeyHoldsTheModulusAndExponent(): void
    {
        $key = Jwk::fromJson(self::fixture('rfc7638/section-3.1.json'));
        $this->assertInstanceOf(RsaKey::class, $key);

        /** @var array{type: int, bits: int, rsa: array<string, string>} $details */
        $details = openssl_pkey_get_details($key->toOpenSslKey());

        $this->assertSame(OPENSSL_KEYTYPE_RSA, $details['type']);
        $this->assertSame(2048, $details['bits']);
        $this->assertSame($key->modulus, $details['rsa']['n']);
        $this->assertSame($key->publicExponent, $details['rsa']['e']);
        $this->assertSame(['n', 'e'], array_keys($details['rsa']));
    }

    public function testTheOpenSslKeyOfAPrivateKeySignsWhatThePublicKeyVerifies(): void
    {
        $private = Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a2.json', 1));
        $public = Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a1.json', 1));
        $this->assertInstanceOf(RsaKey::class, $private);

        /** @var array{rsa: array<string, string>} $details */
        $details = openssl_pkey_get_details($private->toOpenSslKey());
        $this->assertSame($private->privateExponent, $details['rsa']['d']);
        $this->assertSame($private->firstPrimeFactor, $details['rsa']['p']);
        $this->assertSame($private->firstFactorCrtExponent, $details['rsa']['dmp1']);
        $this->assertSame($private->firstCrtCoefficient, $details['rsa']['iqmp']);

        $signature = self::sign($private->toOpenSslKey(), OPENSSL_ALGO_SHA256);
        $this->assertSame(1, openssl_verify('message', $signature, $public->toOpenSslKey(), OPENSSL_ALGO_SHA256));
        $this->assertSame(
            1,
            openssl_verify('message', $signature, $private->toPublic()->toOpenSslKey(), OPENSSL_ALGO_SHA256),
        );
    }

    public function testAPrivateKeyWithDAloneParsesAndSigns(): void
    {
        $fixture = self::fixtureSetMember('rfc7517/appendix-a2.json', 1);
        $key = new RsaKey(
            Base64Url::decode(self::fixtureString($fixture, 'n')),
            Base64Url::decode(self::fixtureString($fixture, 'e')),
            Base64Url::decode(self::fixtureString($fixture, 'd')),
        );

        $this->assertTrue($key->isPrivate());
        $this->assertNull($key->firstPrimeFactor);
        $this->assertSame(['kty', 'n', 'e', 'd'], array_keys($key->jsonSerialize()));

        /** @var array{rsa: array<string, string>} $details */
        $details = openssl_pkey_get_details($key->toOpenSslKey());
        $this->assertSame(['n', 'e', 'd'], array_keys($details['rsa']));

        $signature = self::sign($key->toOpenSslKey(), OPENSSL_ALGO_SHA256);
        $this->assertSame(
            1,
            openssl_verify('message', $signature, $key->toPublic()->toOpenSslKey(), OPENSSL_ALGO_SHA256),
        );
    }

    public function testParsesAKeyWithThreePrimes(): void
    {
        $fixture = self::fixture('generated/rsa-three-primes.json');
        $key = Jwk::fromJson($fixture);

        $this->assertInstanceOf(RsaKey::class, $key);
        $this->assertCount(1, $key->otherPrimesInfo);
        $this->assertSame(
            Base64Url::decode(self::fixtureString(self::othEntry($fixture), 'r')),
            $key->otherPrimesInfo[0]->primeFactor,
        );
        $this->assertEquals($fixture, $key->jsonSerialize());
        $this->assertSame($key->toPublic()->thumbprint(), $key->thumbprint());
        $this->assertSame([], $key->toPublic()->otherPrimesInfo);
    }

    public function testAKeyWithThreePrimesHasNoOpenSslForm(): void
    {
        $key = Jwk::fromJson(self::fixture('generated/rsa-three-primes.json'));

        try {
            $key->toOpenSslKey();
            $this->fail('Expected ConversionFailed');
        } catch (ConversionFailed $exception) {
            $this->assertSame(ConversionFailedReason::MultiPrimeKey, $exception->reason);
        }

        /** @var array{rsa: array<string, string>} $details */
        $details = openssl_pkey_get_details($key->toPublic()->toOpenSslKey());
        $this->assertSame(['n', 'e'], array_keys($details['rsa']));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, InvalidJwkReason, string}>
     */
    public static function refusedProvider(): iterable
    {
        $a2 = self::fixtureSetMember('rfc7517/appendix-a2.json', 1);
        $other = self::fixture('rfc7520/section-3.4.json');
        $threePrimes = self::fixture('generated/rsa-three-primes.json');

        yield 'a missing modulus' => [['kty' => 'RSA', 'e' => 'AQAB'], InvalidJwkReason::MissingMember, 'n'];
        yield 'a missing exponent' => [['kty' => 'RSA', 'n' => $a2['n']], InvalidJwkReason::MissingMember, 'e'];
        yield 'an exponent with a leading zero byte' => [
            [...$a2, 'e' => 'AAEAAQ'],
            InvalidJwkReason::NonMinimalInteger,
            'e',
        ];
        yield 'a public exponent of one, which Project Wycheproof also rejects' => [
            ['kty' => 'RSA', 'n' => $a2['n'], 'e' => 'AQ'],
            InvalidJwkReason::InvalidValue,
            'e',
        ];
        yield 'an even public exponent' => [
            ['kty' => 'RSA', 'n' => $a2['n'], 'e' => 'Ag'],
            InvalidJwkReason::InvalidValue,
            'e',
        ];
        yield 'an even public exponent whose high byte is odd' => [
            ['kty' => 'RSA', 'n' => $a2['n'], 'e' => 'AQA'],
            InvalidJwkReason::InvalidValue,
            'e',
        ];
        yield 'an empty modulus' => [['kty' => 'RSA', 'n' => '', 'e' => 'AQAB'], InvalidJwkReason::InvalidValue, 'n'];
        $paddedModulus = Base64Url::encode("\0" . Base64Url::decode(self::fixtureString($a2, 'n')));
        yield 'a modulus with a leading zero byte' => [
            ['kty' => 'RSA', 'n' => $paddedModulus, 'e' => 'AQAB'],
            InvalidJwkReason::NonMinimalInteger,
            'n',
        ];
        $evenModulus = Base64Url::encode(substr(Base64Url::decode(self::fixtureString($a2, 'n')), 0, -1) . "\x02");
        yield 'an even modulus' => [
            ['kty' => 'RSA', 'n' => $evenModulus, 'e' => 'AQAB'],
            InvalidJwkReason::InvalidValue,
            'n',
        ];
        yield 'a modulus of zero' => [
            ['kty' => 'RSA', 'n' => 'AA', 'e' => 'AQAB'],
            InvalidJwkReason::InvalidValue,
            'n',
        ];
        yield 'an empty exponent' => [
            ['kty' => 'RSA', 'n' => $a2['n'], 'e' => ''],
            InvalidJwkReason::InvalidValue,
            'e',
        ];
        yield 'a modulus that is not base64url' => [
            ['kty' => 'RSA', 'n' => 'not+base64url', 'e' => 'AQAB'],
            InvalidJwkReason::InvalidBase64Url,
            'n',
        ];
        yield 'a modulus that is not a string' => [
            ['kty' => 'RSA', 'n' => 12345, 'e' => 'AQAB'],
            InvalidJwkReason::WrongType,
            'n',
        ];
        yield 'another key\'s private exponent' => [
            [...$a2, 'd' => $other['d']],
            InvalidJwkReason::KeyPairMismatch,
            'd',
        ];
        yield 'a private exponent of one' => [[...$a2, 'd' => 'AQ'], InvalidJwkReason::KeyPairMismatch, 'd'];
        yield 'another key\'s primes' => [
            [...$a2, 'p' => $other['p'], 'q' => $other['q']],
            InvalidJwkReason::KeyPairMismatch,
            'p',
        ];
        yield 'a third prime that does not divide the modulus' => [
            [...$threePrimes, 'oth' => [['r' => $other['p'], 'd' => 'AQ', 't' => 'AQ']]],
            InvalidJwkReason::KeyPairMismatch,
            'p',
        ];
        yield 'p without q' => [
            ['kty' => 'RSA', 'n' => $a2['n'], 'e' => 'AQAB', 'd' => $a2['d'], 'p' => $a2['p']],
            InvalidJwkReason::InconsistentPrivateMembers,
            'q',
        ];
        yield 'every CRT member but qi' => [
            self::without($a2, ['qi']),
            InvalidJwkReason::InconsistentPrivateMembers,
            'qi',
        ];
        yield 'the CRT members without q and dq' => [
            self::without($a2, ['q', 'dq']),
            InvalidJwkReason::InconsistentPrivateMembers,
            'q',
        ];
        yield 'the CRT members without p' => [
            self::without($a2, ['p']),
            InvalidJwkReason::InconsistentPrivateMembers,
            'p',
        ];
        yield 'the CRT members without dp' => [
            self::without($a2, ['dp']),
            InvalidJwkReason::InconsistentPrivateMembers,
            'dp',
        ];
        yield 'the CRT members without d' => [
            [...self::without($a2, ['d'])],
            InvalidJwkReason::InconsistentPrivateMembers,
            'd',
        ];
        yield 'oth without the primes' => [
            ['kty' => 'RSA', 'n' => $a2['n'], 'e' => 'AQAB', 'd' => $a2['d'], 'oth' => $threePrimes['oth']],
            InvalidJwkReason::InconsistentPrivateMembers,
            'oth',
        ];
        yield 'oth that is not an array' => [[...$a2, 'oth' => 'AQ'], InvalidJwkReason::WrongType, 'oth'];
        yield 'an oth entry without r' => [
            [...$a2, 'oth' => [['d' => 'AQ', 't' => 'AQ']]],
            InvalidJwkReason::MissingMember,
            'r',
        ];
        yield 'a zero private exponent' => [[...$a2, 'd' => 'AA'], InvalidJwkReason::InvalidValue, 'd'];
        yield 'a public exponent equal to the modulus' => [
            ['kty' => 'RSA', 'n' => $a2['n'], 'e' => $a2['n']],
            InvalidJwkReason::InvalidValue,
            'e',
        ];
        $longExponent = Base64Url::encode("\x01" . Base64Url::decode(self::fixtureString($a2, 'n')));
        yield 'a public exponent longer than the modulus' => [
            ['kty' => 'RSA', 'n' => $a2['n'], 'e' => $longExponent],
            InvalidJwkReason::InvalidValue,
            'e',
        ];
        yield 'a first prime of one' => [[...$a2, 'p' => 'AQ'], InvalidJwkReason::InvalidValue, 'p'];
        yield 'a second prime of one' => [[...$a2, 'q' => 'AQ'], InvalidJwkReason::InvalidValue, 'q'];
        yield 'an oth prime of one' => [
            [...$threePrimes, 'oth' => [['r' => 'AQ', 'd' => 'AQ', 't' => 'AQ']]],
            InvalidJwkReason::InvalidValue,
            'r',
        ];
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function wrongOtherPrimesProvider(): iterable
    {
        yield 'an entry that is not an OtherPrimeInfo' => [['AQ']];
        yield 'entries that are not a list' => [[1 => new OtherPrimeInfo("\x03", "\x01", "\x01")]];
    }

    /**
     * The argument goes through reflection, since its type is the one the
     * parameter refuses
     *
     * @param array<array-key, mixed> $otherPrimesInfo
     */
    #[DataProvider('wrongOtherPrimesProvider')]
    public function testTheConstructorChecksTheOtherPrimesAsParsingDoes(array $otherPrimesInfo): void
    {
        $a2 = self::fixtureSetMember('rfc7517/appendix-a2.json', 1);

        try {
            new ReflectionClass(RsaKey::class)->newInstanceArgs([
                'modulus' => Base64Url::decode(self::fixtureString($a2, 'n')),
                'publicExponent' => "\x01\x00\x01",
                'otherPrimesInfo' => $otherPrimesInfo,
            ]);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::WrongType, $exception->reason);
            $this->assertSame('oth', $exception->member);
            $this->assertSame('The "oth" member must be a list of OtherPrimeInfo objects', $exception->getMessage());
        }
    }

    public function testAcceptsAPublicExponentBelowTheModulus(): void
    {
        $a2 = self::fixtureSetMember('rfc7517/appendix-a2.json', 1);
        $modulus = Base64Url::decode(self::fixtureString($a2, 'n'));
        // The modulus ends in the byte 0x83, so ending it in 0x81 instead
        // gives an odd exponent of the same length, just below it.
        $belowModulus = substr($modulus, 0, -1) . "\x81";

        $sameLength = Jwk::fromJson(['kty' => 'RSA', 'n' => $a2['n'], 'e' => Base64Url::encode($belowModulus)]);
        $this->assertInstanceOf(RsaKey::class, $sameLength);
        $this->assertSame($belowModulus, $sameLength->publicExponent);

        $shorterWithAHigherFirstByte = Jwk::fromJson(['kty' => 'RSA', 'n' => $a2['n'], 'e' => '____']);
        $this->assertInstanceOf(RsaKey::class, $shorterWithAHigherFirstByte);
        $this->assertSame("\xff\xff\xff", $shorterWithAHigherFirstByte->publicExponent);
    }

    public function testTheRangeMessagesNameTheRule(): void
    {
        $a2 = self::fixtureSetMember('rfc7517/appendix-a2.json', 1);

        try {
            Jwk::fromJson(['kty' => 'RSA', 'n' => $a2['n'], 'e' => $a2['n']]);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame('The "e" member must be less than the "n" member', $exception->getMessage());
        }

        try {
            Jwk::fromJson([...$a2, 'q' => 'AQ']);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame('The "q" member must be a prime, and 1 is not a prime', $exception->getMessage());
        }
    }

    /**
     * @return iterable<string, array{int, int, string}>
     */
    public static function primeLengthProvider(): iterable
    {
        $tooLong = 'The prime factors are too long to multiply to the "n" member';
        $tooShort = 'The prime factors are too short to multiply to the "n" member';
        $mismatch = 'The prime factors do not multiply to the "n" member';

        yield 'primes far too long for the modulus' => [512, 512, $tooLong];
        yield 'primes far too short for the modulus' => [1, 1, $tooShort];
        yield 'primes one byte too short in all' => [128, 127, $tooShort];
        yield 'primes one byte too long in all' => [129, 129, $tooLong];
        yield 'primes whose product could have the length of the modulus' => [129, 128, $mismatch];
    }

    /**
     * The modulus of the RFC 7517 appendix A.2 key is 256 bytes long, and
     * the product of two minimal factors of 129 and 128 bytes is 256 or 257
     * bytes long
     */
    #[DataProvider('primeLengthProvider')]
    public function testRefusesPrimesWhoseLengthsCannotGiveTheModulus(
        int $firstLength,
        int $secondLength,
        string $message,
    ): void {
        $a2 = self::fixtureSetMember('rfc7517/appendix-a2.json', 1);

        try {
            Jwk::fromJson([
                ...$a2,
                'p' => Base64Url::encode(str_repeat("\x03", $firstLength)),
                'q' => Base64Url::encode(str_repeat("\x03", $secondLength)),
            ]);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::KeyPairMismatch, $exception->reason);
            $this->assertSame('p', $exception->member);
            $this->assertSame($message, $exception->getMessage());
        }
    }

    public function testRefusesAThirdPrimeThatMakesTheProductTooLong(): void
    {
        $threePrimes = self::fixture('generated/rsa-three-primes.json');

        try {
            $longPrime = Base64Url::encode(str_repeat("\x03", 87));
            Jwk::fromJson([...$threePrimes, 'oth' => [['r' => $longPrime, 'd' => 'AQ', 't' => 'AQ']]]);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::KeyPairMismatch, $exception->reason);
            $this->assertSame('p', $exception->member);
            $this->assertSame('The prime factors are too long to multiply to the "n" member', $exception->getMessage());
        }
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
    }

    public function testThePublicMemberMessagesNameTheRule(): void
    {
        $a2 = self::fixtureSetMember('rfc7517/appendix-a2.json', 1);

        try {
            Jwk::fromJson(['kty' => 'RSA', 'n' => $a2['n'], 'e' => 'AQ']);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame('The "e" member must be an odd integer of at least 3', $exception->getMessage());
        }

        try {
            Jwk::fromJson(['kty' => 'RSA', 'n' => 'BA', 'e' => 'AQAB']);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame('The "n" member must be odd', $exception->getMessage());
        }

        try {
            Jwk::fromJson(['kty' => 'RSA', 'n' => '', 'e' => 'AQAB']);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame('The "n" member must not be empty', $exception->getMessage());
        }

        $smallest = Jwk::fromJson(['kty' => 'RSA', 'n' => 'BQ', 'e' => 'Aw']);
        $this->assertInstanceOf(RsaKey::class, $smallest);
        $this->assertSame("\x03", $smallest->publicExponent);
    }

    public function testTheMismatchMessagesNameTheMembers(): void
    {
        $a2 = self::fixtureSetMember('rfc7517/appendix-a2.json', 1);
        $other = self::fixture('rfc7520/section-3.4.json');

        try {
            Jwk::fromJson([...$a2, 'd' => $other['d']]);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame('The "d" member does not belong to the "n" and "e" members', $exception->getMessage());
        }

        $this->assertFalse(openssl_error_string());

        try {
            Jwk::fromJson([...$a2, 'p' => $other['p'], 'q' => $other['q']]);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame('The prime factors do not multiply to the "n" member', $exception->getMessage());
        }

        $this->assertFalse(openssl_error_string());
    }

    public function testThePartialCrtMessageListsEveryCrtMember(): void
    {
        $a2 = self::fixtureSetMember('rfc7517/appendix-a2.json', 1);

        try {
            Jwk::fromJson(self::without($a2, ['qi']));
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame('qi', $exception->member);
            $this->assertSame(
                'The "p", "q", "dp", "dq", and "qi" members must be all present or all absent',
                $exception->getMessage(),
            );
        }
    }

    public function testRedactsThePrivateMembersWhenDumped(): void
    {
        $key = Jwk::fromJson(self::fixture('generated/rsa-three-primes.json'));
        $dump = $key->__debugInfo();

        $this->assertSame(['kty', 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'oth'], array_keys($dump));
        $this->assertSame('[redacted]', $dump['d']);
        $this->assertSame('[redacted]', $dump['qi']);
        $this->assertSame('[redacted]', $dump['oth']);
        $this->assertSame('AQAB', $dump['e']);

        $printed = print_r($key, true);
        $this->assertStringNotContainsString(
            self::fixtureString(self::fixture('generated/rsa-three-primes.json'), 'd'),
            $printed,
        );
    }

    public function testAPublicKeyDumpsEveryMember(): void
    {
        $key = Jwk::fromJson(self::fixture('rfc7638/section-3.1.json'));

        $this->assertEquals($key->jsonSerialize(), $key->__debugInfo());
    }

    /**
     * @param array<string, mixed> $fixture
     *
     * @return array<string, mixed>
     */
    private static function othEntry(array $fixture): array
    {
        /** @var list<array<string, mixed>> $oth */
        $oth = $fixture['oth'];

        return $oth[0];
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
