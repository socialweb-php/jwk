<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\Base64Url;
use SocialWeb\Jwk\Exception\ConversionFailed;
use SocialWeb\Jwk\Exception\ConversionFailedReason;
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\Jwk;
use SocialWeb\Jwk\KeyType;
use SocialWeb\Jwk\KeyUse;
use SocialWeb\Jwk\OctKey;

use function hash;
use function json_encode;
use function print_r;
use function sprintf;
use function strlen;
use function substr;

use const JSON_THROW_ON_ERROR;

class OctKeyTest extends TestCase
{
    public function testParsesTheRfc7520Section35HmacKey(): void
    {
        $fixture = self::fixture('rfc7520/section-3.5.json');
        $key = Jwk::fromJson($fixture);

        $this->assertInstanceOf(OctKey::class, $key);
        $this->assertSame(KeyType::Oct, $key->keyType());
        $this->assertSame(32, strlen($key->keyValue));
        $this->assertSame('018c0ae5-4d9b-471b-bfd6-eef314bc7037', $key->keyId);
        $this->assertSame('sig', $key->use);
        $this->assertSame('HS256', $key->algorithm);
        $this->assertTrue($key->isPrivate());
        $this->assertSame([], $key->additionalMembers);
        $this->assertEquals($fixture, $key->jsonSerialize());
    }

    public function testParsesTheRfc7520Section36EncryptionKey(): void
    {
        $fixture = self::fixture('rfc7520/section-3.6.json');
        $key = Jwk::fromJson(self::fixtureJson('rfc7520/section-3.6.json'));

        $this->assertInstanceOf(OctKey::class, $key);
        $this->assertSame("\x00\x03", substr($key->keyValue, 0, 2));
        $this->assertSame('A256GCM', $key->algorithm);
        $this->assertEquals($fixture, $key->jsonSerialize());
    }

    public function testParsesTheRfc7517AppendixA3Keys(): void
    {
        $wrapping = Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a3.json', 0));
        $hmac = Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a3.json', 1));

        $this->assertInstanceOf(OctKey::class, $wrapping);
        $this->assertInstanceOf(OctKey::class, $hmac);
        $this->assertSame('A128KW', $wrapping->algorithm);
        $this->assertSame(16, strlen($wrapping->keyValue));
        $this->assertSame('HMAC key used in JWS spec Appendix A.1 example', $hmac->keyId);
        $this->assertSame(64, strlen($hmac->keyValue));
        $this->assertEquals(self::fixtureSetMember('rfc7517/appendix-a3.json', 1), $hmac->jsonSerialize());
    }

    public function testComputesTheThumbprintOverKAndKty(): void
    {
        $key = new OctKey("\x01\x02\x03");
        $expected = Base64Url::encode(hash('sha256', '{"k":"AQID","kty":"oct"}', true));

        $this->assertSame($expected, $key->thumbprint());
    }

    public function testHasNoPublicForm(): void
    {
        $key = new OctKey("\x01\x02\x03");

        try {
            $key->toPublic();
            $this->fail('Expected ConversionFailed');
        } catch (ConversionFailed $exception) {
            $this->assertSame(ConversionFailedReason::SymmetricKey, $exception->reason);
            $this->assertSame('A symmetric key has no public form', $exception->getMessage());
        }
    }

    public function testHasNoOpenSslForm(): void
    {
        $key = new OctKey("\x01\x02\x03");

        try {
            $key->toOpenSslKey();
            $this->fail('Expected ConversionFailed');
        } catch (ConversionFailed $exception) {
            $this->assertSame(ConversionFailedReason::SymmetricKey, $exception->reason);
            $this->assertSame('A symmetric key has no OpenSSL form', $exception->getMessage());
        }
    }

    public function testRefusesAnEmptyKey(): void
    {
        try {
            new OctKey('');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::InvalidValue, $exception->reason);
            $this->assertSame('k', $exception->member);
            $this->assertSame('The "k" member must not be empty', $exception->getMessage());
        }
    }

    public function testRefusesAnEmptyJsonArrayAsAnObject(): void
    {
        try {
            Jwk::fromJson('[]');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::NotAnObject, $exception->reason);
        }
    }

    public function testRefusesAMissingKThroughFromJson(): void
    {
        try {
            Jwk::fromJson('{"kty":"oct"}');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::MissingMember, $exception->reason);
            $this->assertSame('k', $exception->member);
        }
    }

    public function testCanBeBuiltWithTheCommonMembers(): void
    {
        $key = new OctKey(
            keyValue: "\x01\x02\x03",
            keyId: 'hmac-1',
            algorithm: 'HS256',
            use: KeyUse::Signature,
            keyOperations: ['sign', 'verify'],
            additionalMembers: ['ext' => true],
        );

        $this->assertSame(
            '{"kty":"oct","k":"AQID","use":"sig","key_ops":["sign","verify"],"alg":"HS256","kid":"hmac-1","ext":true}',
            $key->toJson(),
        );
        $this->assertSame(json_encode($key, JSON_THROW_ON_ERROR), $key->toJson());
    }

    public function testRedactsTheKeyValueWhenDumped(): void
    {
        $key = new OctKey("\x01\x02\x03", keyId: 'hmac-1');

        $this->assertSame(['kty' => 'oct', 'k' => '[redacted]', 'kid' => 'hmac-1'], $key->__debugInfo());
        $this->assertStringNotContainsString('AQID', print_r($key, true));
    }

    public function testKeepsNumericAdditionalMemberNamesThroughARoundTrip(): void
    {
        $json = '{"kty":"oct","k":"AQID","1":"one","kid":"a","7":"seven"}';
        $key = Jwk::fromJson($json);

        $this->assertSame('{"kty":"oct","k":"AQID","kid":"a","1":"one","7":"seven"}', $key->toJson());
        $this->assertSame($key->toJson(), Jwk::fromJson($key->toJson())->toJson());
    }

    public function testAddsAndRemovesNumericAdditionalMemberNames(): void
    {
        $key = (new OctKey("\x01"))->withAdditionalMember('5', 'five')->withAdditionalMember('7', 'seven');

        $this->assertSame('{"kty":"oct","k":"AQ","5":"five","7":"seven"}', $key->toJson());
        $this->assertSame('{"kty":"oct","k":"AQ","7":"seven"}', $key->withoutAdditionalMember('5')->toJson());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function definedMemberNameProvider(): iterable
    {
        yield 'kty' => ['kty'];
        yield 'kid' => ['kid'];
        yield 'k' => ['k'];
    }

    #[DataProvider('definedMemberNameProvider')]
    public function testRefusesAnAdditionalMemberNamedForADefinedMember(string $name): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains(
            sprintf('The "%s" member is defined for this key type and is not an additional member', $name),
        );

        new OctKey("\x01", additionalMembers: [$name => 'x']);
    }

    public function testWithAdditionalMemberRefusesADefinedMemberName(): void
    {
        $this->expectException(InvalidArgument::class);

        (new OctKey("\x01"))->withAdditionalMember('k', 'x');
    }
}
