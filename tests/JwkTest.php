<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use ReflectionClass;
use ReflectionMethod;
use SensitiveParameterValue;
use SocialWeb\Jwk\Base64Url;
use SocialWeb\Jwk\EcKey;
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\HashAlgorithm;
use SocialWeb\Jwk\Jwk;
use SocialWeb\Jwk\KeyOperation;
use SocialWeb\Jwk\KeyUse;
use SocialWeb\Jwk\OctKey;
use SocialWeb\Jwk\OkpKey;
use SocialWeb\Jwk\RsaKey;
use Throwable;
use stdClass;

use function array_keys;
use function hash;
use function ini_set;
use function is_array;
use function is_object;
use function is_string;
use function json_decode;
use function json_encode;
use function serialize;
use function sprintf;
use function str_contains;
use function str_repeat;
use function strlen;
use function unserialize;

use const JSON_PRESERVE_ZERO_FRACTION;
use const JSON_THROW_ON_ERROR;

class JwkTest extends TestCase
{
    public function testFromJsonReturnsTheClassForTheKeyType(): void
    {
        $this->assertInstanceOf(RsaKey::class, Jwk::fromJson(self::fixture('rfc7638/section-3.1.json')));
        $this->assertInstanceOf(EcKey::class, Jwk::fromJson(self::fixture('rfc7517/section-3.json')));
        $this->assertInstanceOf(OkpKey::class, Jwk::fromJson(self::fixture('rfc8037/appendix-a2.json')));
        $this->assertInstanceOf(OctKey::class, Jwk::fromJson(self::fixture('rfc7520/section-3.5.json')));
    }

    public function testFromJsonOnASubclassStillReturnsTheClassForTheKeyType(): void
    {
        $this->assertInstanceOf(EcKey::class, RsaKey::fromJson(self::fixture('rfc7517/section-3.json')));
    }

    public function testFromJsonTakesJsonTextOrADecodedArray(): void
    {
        $text = self::fixtureJson('rfc8037/appendix-a2.json');
        /** @var array<string, mixed> $array */
        $array = json_decode($text, true, 512, JSON_THROW_ON_ERROR);

        $this->assertEquals(Jwk::fromJson($text)->jsonSerialize(), Jwk::fromJson($array)->jsonSerialize());
    }

    /**
     * @return iterable<string, array{string | array<array-key, mixed>, InvalidJwkReason, ?string}>
     */
    public static function refusedObjectProvider(): iterable
    {
        yield 'malformed JSON' => ['{"kty":', InvalidJwkReason::MalformedJson, null];
        yield 'a JSON array' => ['[{"kty":"oct","k":"AQAB"}]', InvalidJwkReason::NotAnObject, null];
        yield 'a JSON string' => ['"oct"', InvalidJwkReason::NotAnObject, null];
        yield 'a missing kty' => ['{"k":"AQAB"}', InvalidJwkReason::MissingMember, 'kty'];
        yield 'a kty that is not a string' => ['{"kty":1}', InvalidJwkReason::WrongType, 'kty'];
        yield 'a kty that is not implemented' => ['{"kty":"AKP"}', InvalidJwkReason::UnsupportedKeyType, 'kty'];
        yield 'a lowercase kty' => [['kty' => 'rsa'], InvalidJwkReason::UnsupportedKeyType, 'kty'];
    }

    /**
     * @param string | array<array-key, mixed> $json
     */
    #[DataProvider('refusedObjectProvider')]
    public function testRefusesWhatIsNotAJwkObject(
        string | array $json,
        InvalidJwkReason $reason,
        ?string $member,
    ): void {
        try {
            Jwk::fromJson($json);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame($reason, $exception->reason);
            $this->assertSame($member, $exception->member);
        }
    }

    public function testTheUnsupportedKeyTypeMessageNamesTheTypeAndTheFour(): void
    {
        try {
            Jwk::fromJson('{"kty":"AKP"}');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(
                'The key type "AKP" is not implemented; the package implements RSA, EC, OKP, and oct',
                $exception->getMessage(),
            );
        }
    }

    /**
     * @return iterable<string, array{array<string, mixed>, InvalidJwkReason, string}>
     */
    public static function publicOnlyProvider(): iterable
    {
        yield 'an oct key' => [self::fixture('rfc7520/section-3.5.json'), InvalidJwkReason::SymmetricKey, 'kty'];
        yield 'an RSA key with d' => [
            self::fixtureSetMember('rfc7517/appendix-a2.json', 1),
            InvalidJwkReason::PrivateMembersPresent,
            'd',
        ];
        yield 'an RSA key with only a prime' => [
            [...self::fixtureSetMember('rfc7517/appendix-a1.json', 1), 'p' => 'AQ'],
            InvalidJwkReason::PrivateMembersPresent,
            'p',
        ];
        yield 'an RSA key with only oth' => [
            [...self::fixtureSetMember('rfc7517/appendix-a1.json', 1), 'oth' => []],
            InvalidJwkReason::PrivateMembersPresent,
            'oth',
        ];
        yield 'an EC key with d' => [
            self::fixtureSetMember('rfc7517/appendix-a2.json', 0),
            InvalidJwkReason::PrivateMembersPresent,
            'd',
        ];
        yield 'an OKP key with d' => [
            self::fixture('rfc8037/appendix-a1.json'),
            InvalidJwkReason::PrivateMembersPresent,
            'd',
        ];
    }

    /**
     * @param array<string, mixed> $jwk
     */
    #[DataProvider('publicOnlyProvider')]
    public function testPublicOnlyRefusesPrivateAndSymmetricKeys(
        array $jwk,
        InvalidJwkReason $reason,
        string $member,
    ): void {
        try {
            Jwk::fromJson($jwk, publicOnly: true);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame($reason, $exception->reason);
            $this->assertSame($member, $exception->member);
        }
    }

    public function testPublicOnlyAcceptsAPublicKeyOfEachAsymmetricType(): void
    {
        $this->assertFalse(Jwk::fromJson(self::fixture('rfc7638/section-3.1.json'), true)->isPrivate());
        $this->assertFalse(Jwk::fromJson(self::fixture('rfc7517/section-3.json'), true)->isPrivate());
        $this->assertFalse(Jwk::fromJson(self::fixture('rfc8037/appendix-a2.json'), true)->isPrivate());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, InvalidJwkReason, string, string}>
     */
    public static function commonMemberProvider(): iterable
    {
        $okp = self::fixture('rfc8037/appendix-a2.json');

        yield 'an empty kid' => [
            [...$okp, 'kid' => ''],
            InvalidJwkReason::InvalidValue,
            'kid',
            'The "kid" member must not be empty',
        ];
        yield 'a repeated key operation' => [
            [...$okp, 'key_ops' => ['verify', 'verify']],
            InvalidJwkReason::DuplicateKeyOperation,
            'key_ops',
            'The "key_ops" member must not list an operation twice',
        ];
        yield 'a signature use with an encryption operation' => [
            [...$okp, 'use' => 'sig', 'key_ops' => ['verify', 'encrypt']],
            InvalidJwkReason::InconsistentUseAndKeyOperations,
            'key_ops',
            'The "use" value "sig" is not consistent with the "key_ops" value "encrypt"',
        ];
        yield 'an encryption use with a signing operation' => [
            [...$okp, 'use' => 'enc', 'key_ops' => ['sign']],
            InvalidJwkReason::InconsistentUseAndKeyOperations,
            'key_ops',
            'The "use" value "enc" is not consistent with the "key_ops" value "sign"',
        ];
        yield 'an algorithm for another key type' => [
            [...$okp, 'alg' => 'RS256'],
            InvalidJwkReason::AlgorithmDoesNotFitKey,
            'alg',
            'The algorithm "RS256" does not fit an OKP key on the curve Ed25519',
        ];
        yield 'an algorithm for another curve' => [
            [...$okp, 'alg' => 'Ed448'],
            InvalidJwkReason::AlgorithmDoesNotFitKey,
            'alg',
            'The algorithm "Ed448" does not fit an OKP key on the curve Ed25519',
        ];
        yield 'a key agreement algorithm on a signing curve' => [
            [...$okp, 'alg' => 'ECDH-ES'],
            InvalidJwkReason::AlgorithmDoesNotFitKey,
            'alg',
            'The algorithm "ECDH-ES" does not fit an OKP key on the curve Ed25519',
        ];
        yield 'none' => [
            [...self::fixture('rfc7520/section-3.5.json'), 'alg' => 'none'],
            InvalidJwkReason::AlgorithmDoesNotFitKey,
            'alg',
            'The algorithm "none" does not fit an oct key',
        ];
        yield 'a kid that is not a string' => [
            [...$okp, 'kid' => 1],
            InvalidJwkReason::WrongType,
            'kid',
            'The "kid" member must be a string',
        ];
        yield 'key_ops that is not an array' => [
            [...$okp, 'key_ops' => 'verify'],
            InvalidJwkReason::WrongType,
            'key_ops',
            'The "key_ops" member must be an array',
        ];
        yield 'x5c that is not an array' => [
            [...$okp, 'x5c' => 'MIID'],
            InvalidJwkReason::WrongType,
            'x5c',
            'The "x5c" member must be an array',
        ];
    }

    /**
     * @param array<string, mixed> $jwk
     */
    #[DataProvider('commonMemberProvider')]
    public function testAppliesTheRulesOfTheCommonMembers(
        array $jwk,
        InvalidJwkReason $reason,
        string $member,
        string $message,
    ): void {
        try {
            Jwk::fromJson($jwk);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame($reason, $exception->reason);
            $this->assertSame($member, $exception->member);
            $this->assertSame($message, $exception->getMessage());
        }
    }

    public function testAcceptsWhatTheRulesLeaveAlone(): void
    {
        $okp = self::fixture('rfc8037/appendix-a2.json');

        $key = Jwk::fromJson([
            ...$okp,
            'use' => 'custom-use',
            'key_ops' => ['verify', 'custom-op'],
            'alg' => 'Custom-Alg',
            'kid' => 'a kid with spaces',
            'x5u' => 'https://example.com/certs',
            'x5c' => ['MIID'],
            'x5t' => 'AQAB',
            'x5t#S256' => 'AQAB',
            'ext' => true,
            'nested' => ['a' => [1, 2, 3]],
        ]);

        $this->assertSame('custom-use', $key->use);
        $this->assertSame(['verify', 'custom-op'], $key->keyOperations);
        $this->assertSame('Custom-Alg', $key->algorithm);
        $this->assertSame('https://example.com/certs', $key->certificateUrl);
        $this->assertSame(['MIID'], $key->certificateChain);
        $this->assertSame('AQAB', $key->certificateSha1Thumbprint);
        $this->assertSame('AQAB', $key->certificateSha256Thumbprint);
        $this->assertEquals(['ext' => true, 'nested' => (object) ['a' => [1, 2, 3]]], $key->additionalMembers);
        $this->assertInstanceOf(stdClass::class, $key->additionalMembers['nested']);
    }

    public function testWritesJsonObjectsInAdditionalMembersBackAsObjects(): void
    {
        $json = '{"kty":"oct","k":"AQAB","empty":{},"numbered":{"0":"a","1":"b"},"nested":{"a":{},"b":[]}}';

        $this->assertSame($json, Jwk::fromJson($json)->toJson());
    }

    public function testKeepsAnAdditionalMemberAsAJsonValue(): void
    {
        $key = new OctKey("\x01");
        $object = new stdClass();
        $object->a = [1.0, ['b' => []]];
        $changed = $key->withAdditionalMember('object', $object)
            ->withAdditionalMember('list', ['a', 'b'])
            ->withAdditionalMember('empty', [])
            ->withAdditionalMember('keyed', ['0' => 'a', '2' => 'b'])
            ->withAdditionalMember('scalar', 1.0);
        $object->a = 'changed';

        $this->assertSame(
            '{"kty":"oct","k":"AQ","object":{"a":[1.0,{"b":[]}]},"list":["a","b"],"empty":[],'
            . '"keyed":{"0":"a","2":"b"},"scalar":1.0}',
            json_encode($changed, JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR),
        );
        $this->assertNotSame($object, $changed->additionalMembers['object']);
        $this->assertSame(
            '{"kty":"oct","k":"AQ","nested":{"a":{}}}',
            new OctKey("\x01", additionalMembers: ['nested' => ['a' => new stdClass()]])->toJson(),
        );
    }

    public function testTheDeprecatedEdDsaNameIsStillAccepted(): void
    {
        $key = Jwk::fromJson([...self::fixture('rfc8037/appendix-a2.json'), 'alg' => 'EdDSA']);

        $this->assertSame('EdDSA', $key->algorithm);
        $this->assertSame('Ed25519', $key->withAlgorithm('Ed25519')->algorithm);
    }

    public function testASignatureUseAgreesWithSigningOperationsAndUnregisteredOnes(): void
    {
        $key = Jwk::fromJson([
            ...self::fixture('rfc8037/appendix-a2.json'),
            'use' => 'sig',
            'key_ops' => ['sign', 'verify', 'custom-op'],
        ]);

        $this->assertSame(['sign', 'verify', 'custom-op'], $key->keyOperations);
    }

    public function testWritesTheMembersInTheOrderOfTheDesign(): void
    {
        $key = Jwk::fromJson([
            'ext' => true,
            'x5t#S256' => 'BBBB',
            'kid' => 'k1',
            'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
            'alg' => 'Ed25519',
            'crv' => 'Ed25519',
            'x5c' => ['MIID'],
            'key_ops' => ['verify'],
            'kty' => 'OKP',
            'x5u' => 'https://example.com/certs',
            'use' => 'sig',
            'x5t' => 'AAAA',
            'another' => 1,
        ]);

        $this->assertSame(
            '{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",'
            . '"use":"sig","key_ops":["verify"],"alg":"Ed25519","kid":"k1","x5u":"https://example.com/certs",'
            . '"x5c":["MIID"],"x5t":"AAAA","x5t#S256":"BBBB","ext":true,"another":1}',
            $key->toJson(),
        );
    }

    public function testOmitsAbsentCommonMembersAndEmptyLists(): void
    {
        $key = new OctKey("\x01", keyOperations: [], certificateChain: []);

        $this->assertSame('{"kty":"oct","k":"AQ"}', $key->toJson());
    }

    public function testComputesTheThumbprintUriOfRfc9278(): void
    {
        $key = Jwk::fromJson(self::fixture('rfc7638/section-3.1.json'));

        $this->assertSame(
            'urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
            $key->thumbprintUri(),
        );
    }

    public function testComputesTheThumbprintWithEachHashFunction(): void
    {
        $key = Jwk::fromJson(self::fixture('rfc8037/appendix-a2.json'));
        $input = '{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}';

        foreach (HashAlgorithm::cases() as $hash) {
            $expected = Base64Url::encode(hash($hash->hashName(), $input, true));

            $this->assertSame($expected, $key->thumbprint($hash));
            $this->assertSame(
                'urn:ietf:params:oauth:jwk-thumbprint:' . $hash->value . ':' . $expected,
                $key->thumbprintUri($hash),
            );
        }
    }

    public function testTheWithMethodsReturnANewKeyAndLeaveTheOldOneAlone(): void
    {
        $key = Jwk::fromJson(self::fixture('rfc8037/appendix-a2.json'));

        $changed = $key
            ->withKeyId('k1')
            ->withAlgorithm('Ed25519')
            ->withUse(KeyUse::Signature)
            ->withKeyOperations([KeyOperation::Verify, 'custom-op'])
            ->withCertificateUrl('https://example.com/certs')
            ->withCertificateChain(['MIID'])
            ->withCertificateSha1Thumbprint('AAAA')
            ->withCertificateSha256Thumbprint('BBBB')
            ->withAdditionalMember('ext', true);

        $this->assertSame('k1', $changed->keyId);
        $this->assertSame('Ed25519', $changed->algorithm);
        $this->assertSame('sig', $changed->use);
        $this->assertSame(['verify', 'custom-op'], $changed->keyOperations);
        $this->assertSame('https://example.com/certs', $changed->certificateUrl);
        $this->assertSame(['MIID'], $changed->certificateChain);
        $this->assertSame('AAAA', $changed->certificateSha1Thumbprint);
        $this->assertSame('BBBB', $changed->certificateSha256Thumbprint);
        $this->assertSame(['ext' => true], $changed->additionalMembers);
        $this->assertInstanceOf(OkpKey::class, $changed);
        $this->assertSame($key->thumbprint(), $changed->thumbprint());

        $this->assertNull($key->keyId);
        $this->assertNull($key->algorithm);
        $this->assertSame([], $key->keyOperations);
        $this->assertSame([], $key->additionalMembers);
    }

    public function testTheWithMethodsRemoveAMemberForNullOrAnEmptyList(): void
    {
        $key = Jwk::fromJson(self::fixture('rfc7520/section-3.5.json'))
            ->withKeyId(null)
            ->withAlgorithm(null)
            ->withUse(null)
            ->withKeyOperations([])
            ->withCertificateChain([])
            ->withCertificateUrl(null)
            ->withCertificateSha1Thumbprint(null)
            ->withCertificateSha256Thumbprint(null);

        $this->assertSame(['kty', 'k'], array_keys($key->jsonSerialize()));
    }

    public function testTheWithMethodsAcceptStringsForTheOpenRegistries(): void
    {
        $key = Jwk::fromJson(self::fixture('rfc8037/appendix-a2.json'))
            ->withUse('enc')
            ->withKeyOperations(['deriveKey']);

        $this->assertSame('enc', $key->use);
        $this->assertSame(['deriveKey'], $key->keyOperations);
    }

    public function testTheWithMethodsApplyTheSameChecksAsParsing(): void
    {
        $key = Jwk::fromJson(self::fixture('rfc8037/appendix-a2.json'));

        try {
            $key->withKeyId('');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::InvalidValue, $exception->reason);
        }

        try {
            $key->withAlgorithm('ES256');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::AlgorithmDoesNotFitKey, $exception->reason);
        }

        try {
            $key->withUse(KeyUse::Encryption)->withKeyOperations([KeyOperation::Verify]);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::InconsistentUseAndKeyOperations, $exception->reason);
        }

        try {
            $key->withKeyOperations([KeyOperation::Verify, 'verify']);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::DuplicateKeyOperation, $exception->reason);
        }
    }

    public function testAnAdditionalMemberCannotShadowADefinedOne(): void
    {
        $key = Jwk::fromJson(self::fixture('rfc8037/appendix-a2.json'));

        foreach (['kty', 'kid', 'x5t#S256', 'crv', 'x', 'd'] as $name) {
            try {
                $key->withAdditionalMember($name, 'value');
                $this->fail('Expected InvalidArgument for ' . $name);
            } catch (InvalidArgument $exception) {
                $this->assertSame(
                    'The "' . $name . '" member is defined for this key type and is not an additional member',
                    $exception->getMessage(),
                );
            }
        }

        $this->assertSame(['n' => 1], $key->withAdditionalMember('n', 1)->additionalMembers);
    }

    public function testAnAdditionalMemberCanBeReplacedAndRemoved(): void
    {
        $key = Jwk::fromJson([...self::fixture('rfc8037/appendix-a2.json'), 'ext' => true, 'other' => 1]);

        $this->assertSame(['ext' => false, 'other' => 1], $key->withAdditionalMember('ext', false)->additionalMembers);
        $this->assertSame(['other' => 1], $key->withoutAdditionalMember('ext')->additionalMembers);
        $this->assertSame(['ext' => true, 'other' => 1], $key->withoutAdditionalMember('missing')->additionalMembers);
    }

    public function testCannotBeSerializedWithPhpSerialize(): void
    {
        $key = Jwk::fromJson(self::fixture('rfc8037/appendix-a1.json'));

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('A JWK cannot be serialized with serialize(); use toJson()');

        serialize($key);
    }

    public function testAnOctKeyCannotBeSerializedEither(): void
    {
        $this->expectException(LogicException::class);

        serialize(new OctKey("\x01"));
    }

    public function testRefusesAKeyCraftedForPhpUnserialize(): void
    {
        $crafted = sprintf('O:%d:"%s":1:{s:8:"keyValue";s:0:"";}', strlen(OctKey::class), OctKey::class);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains(
            'A JWK cannot be unserialized with unserialize(); use Jwk::fromJson()',
        );

        unserialize($crafted);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function wrongListArgumentProvider(): iterable
    {
        yield 'a key operation that is not a string' => [['keyOperations' => [1]], 'key_ops'];
        yield 'key operations that are not a list' => [['keyOperations' => ['a' => 'sign']], 'key_ops'];
        yield 'a certificate that is not a string' => [['certificateChain' => [1]], 'x5c'];
        yield 'certificates that are not a list' => [['certificateChain' => ['a' => 'MIIB']], 'x5c'];
    }

    /**
     * The arguments go through reflection, since their types are the ones
     * the parameters refuse
     *
     * @param array<string, mixed> $arguments
     */
    #[DataProvider('wrongListArgumentProvider')]
    public function testAConstructorChecksItsListArgumentsAsParsingDoes(array $arguments, string $member): void
    {
        try {
            new ReflectionClass(OctKey::class)->newInstanceArgs(['keyValue' => "\x01", ...$arguments]);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::WrongType, $exception->reason);
            $this->assertSame($member, $exception->member);
            $this->assertSame(sprintf('The "%s" member must be a list of strings', $member), $exception->getMessage());
        }
    }

    /**
     * @param array<string, mixed> $arguments
     */
    #[DataProvider('wrongListArgumentProvider')]
    public function testTheWithMethodsCheckTheirListArgumentsAsParsingDoes(array $arguments, string $member): void
    {
        $key = new OctKey("\x01");
        $method = $member === 'key_ops' ? 'withKeyOperations' : 'withCertificateChain';

        try {
            new ReflectionMethod($key, $method)->invoke($key, ...$arguments);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::WrongType, $exception->reason);
            $this->assertSame($member, $exception->member);
        }
    }

    public function testAConstructorAcceptsKeyOperationCasesAndStrings(): void
    {
        $key = new OctKey("\x01", keyOperations: [KeyOperation::Sign, 'verify'], certificateChain: ['MIIB']);

        $this->assertSame(['sign', 'verify'], $key->keyOperations);
        $this->assertSame(['MIIB'], $key->certificateChain);
    }

    public function testKeepsPrivateKeyMaterialOutOfExceptionTraces(): void
    {
        $ec = self::fixtureSetMember('rfc7517/appendix-a2.json', 0);
        $rsa = self::fixtureSetMember('rfc7517/appendix-a2.json', 1);
        $other = self::fixture('rfc7520/section-3.4.json');
        $ecSecret = str_repeat("\x11", 32);

        $cases = [
            'an EC private key that derives another point' => [
                json_encode([...$ec, 'd' => Base64Url::encode($ecSecret)], JSON_THROW_ON_ERROR),
                [$ecSecret, Base64Url::encode($ecSecret)],
                InvalidJwkReason::KeyPairMismatch,
            ],
            'an RSA private exponent of another key' => [
                json_encode([...$rsa, 'd' => $other['d']], JSON_THROW_ON_ERROR),
                [Base64Url::decode(self::fixtureString($other, 'd')), self::fixtureString($other, 'd')],
                InvalidJwkReason::KeyPairMismatch,
            ],
            'RSA primes of another key' => [
                json_encode([...$rsa, 'p' => $other['p'], 'q' => $other['q']], JSON_THROW_ON_ERROR),
                [
                    Base64Url::decode(self::fixtureString($other, 'p')),
                    self::fixtureString($other, 'p'),
                    Base64Url::decode(self::fixtureString($rsa, 'd')),
                    self::fixtureString($rsa, 'd'),
                ],
                InvalidJwkReason::KeyPairMismatch,
            ],
            'a malformed private key text' => [
                json_encode($ec, JSON_THROW_ON_ERROR) . ',',
                [self::fixtureString($ec, 'd'), Base64Url::decode(self::fixtureString($ec, 'd'))],
                InvalidJwkReason::MalformedJson,
            ],
        ];

        $previous = ini_set('zend.exception_ignore_args', '0');

        try {
            foreach ($cases as $label => [$json, $secrets, $reason]) {
                try {
                    Jwk::fromJson($json);
                    $this->fail('Expected InvalidJwk for ' . $label);
                } catch (InvalidJwk $exception) {
                    $this->assertSame($reason, $exception->reason, $label);
                    $this->assertInstanceOf(
                        SensitiveParameterValue::class,
                        self::fromJsonArgument($exception),
                        $label,
                    );

                    $leaks = [];

                    foreach (self::traceStrings($exception) as $string) {
                        foreach ([$json, ...$secrets] as $secret) {
                            if (str_contains($string, $secret)) {
                                $leaks[] = Base64Url::encode($secret);
                            }
                        }
                    }

                    $this->assertSame([], $leaks, $label);
                }
            }
        } finally {
            ini_set('zend.exception_ignore_args', $previous === false ? '1' : $previous);
        }
    }

    /**
     * Returns the first argument of the `Jwk::fromJson()` frame of the trace
     */
    private static function fromJsonArgument(Throwable $exception): mixed
    {
        foreach ($exception->getTrace() as $frame) {
            if (($frame['class'] ?? null) === Jwk::class && $frame['function'] === 'fromJson') {
                return $frame['args'][0] ?? null;
            }
        }

        return null;
    }

    /**
     * Returns every string in the arguments of every frame of the trace of
     * the exception and of the exceptions before it, looking inside arrays
     * and the properties of objects
     *
     * @return list<string>
     */
    private static function traceStrings(Throwable $exception): array
    {
        $strings = [];

        for ($current = $exception; $current !== null; $current = $current->getPrevious()) {
            foreach ($current->getTrace() as $frame) {
                foreach ($frame['args'] ?? [] as $argument) {
                    self::collectStrings($argument, $strings, 0);
                }
            }
        }

        return $strings;
    }

    /**
     * @param list<string> $strings
     */
    private static function collectStrings(mixed $value, array &$strings, int $depth): void
    {
        if ($depth > 8 || $value instanceof SensitiveParameterValue) {
            return;
        }

        if (is_string($value)) {
            $strings[] = $value;

            return;
        }

        if (is_object($value)) {
            $value = (array) $value;
        }

        if (is_array($value)) {
            /** @var mixed $entry */
            foreach ($value as $entry) {
                self::collectStrings($entry, $strings, $depth + 1);
            }
        }
    }
}
