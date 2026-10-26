<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use ReflectionClass;
use SocialWeb\Jwk\EcKey;
use SocialWeb\Jwk\Exception\AmbiguousKeyId;
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\Exception\InvalidJwkSet;
use SocialWeb\Jwk\HashAlgorithm;
use SocialWeb\Jwk\Jwk;
use SocialWeb\Jwk\JwkSet;
use SocialWeb\Jwk\KeyType;
use SocialWeb\Jwk\OctKey;
use SocialWeb\Jwk\OkpKey;
use SocialWeb\Jwk\RsaKey;
use SocialWeb\Jwk\SkippedKey;
use stdClass;

use function array_keys;
use function array_map;
use function iterator_to_array;
use function json_decode;
use function serialize;
use function unserialize;

use const INF;
use const JSON_THROW_ON_ERROR;

class JwkSetTest extends TestCase
{
    /**
     * @return iterable<string, array{string, list<class-string<Jwk>>, list<?string>}>
     */
    public static function rfc7517AppendixAProvider(): iterable
    {
        yield 'A.1, public keys' => ['rfc7517/appendix-a1.json', [EcKey::class, RsaKey::class], ['1', '2011-04-29']];
        yield 'A.2, private keys' => ['rfc7517/appendix-a2.json', [EcKey::class, RsaKey::class], ['1', '2011-04-29']];
        yield 'A.3, symmetric keys' => [
            'rfc7517/appendix-a3.json',
            [OctKey::class, OctKey::class],
            [null, 'HMAC key used in JWS spec Appendix A.1 example'],
        ];
    }

    /**
     * @param list<class-string<Jwk>> $classes
     * @param list<?string> $keyIds
     */
    #[DataProvider('rfc7517AppendixAProvider')]
    public function testParsesTheRfc7517AppendixASets(string $file, array $classes, array $keyIds): void
    {
        $fixture = self::fixture($file);
        $set = JwkSet::fromJson(self::fixtureJson($file));

        $this->assertCount(2, $set);
        $this->assertSame([], $set->skipped());
        $this->assertSame($classes, array_map(static fn (Jwk $key): string => $key::class, $set->keys()));
        $this->assertSame($keyIds, array_map(static fn (Jwk $key): ?string => $key->keyId, $set->keys()));
        $this->assertSame($set->keys(), iterator_to_array($set));
        $this->assertSame([], $set->additionalMembers());
        $this->assertEquals($fixture, $set->jsonSerialize());
        $this->assertEquals($fixture, json_decode($set->toJson(), true, 512, JSON_THROW_ON_ERROR));
    }

    public function testFromJsonTakesJsonTextADecodedArrayOrATreeOfStdClassObjects(): void
    {
        $text = self::fixtureJson('rfc7517/appendix-a1.json');
        $fromText = JwkSet::fromJson($text);
        $fromArray = JwkSet::fromJson(self::fixture('rfc7517/appendix-a1.json'));
        $objects = json_decode($text, false, 512, JSON_THROW_ON_ERROR);
        $this->assertInstanceOf(stdClass::class, $objects);
        $fromObjects = JwkSet::fromJson($objects);

        $this->assertSame($fromText->toJson(), $fromArray->toJson());
        $this->assertSame($fromText->toJson(), $fromObjects->toJson());
    }

    public function testWritesAnEmptySetAsAnEmptyKeysArray(): void
    {
        $set = new JwkSet([]);

        $this->assertCount(0, $set);
        $this->assertSame('{"keys":[]}', $set->toJson());
        $this->assertSame('{"keys":[]}', JwkSet::fromJson('{"keys":[]}')->toJson());
        $this->assertSame('{"keys":[]}', JwkSet::fromJson(['keys' => []])->toJson());
    }

    public function testKeepsTheOtherMembersOfTheSetObjectAndWritesThemAfterKeys(): void
    {
        $set = JwkSet::fromJson('{"issuer":"https://example.com","keys":[],"meta":{"n":1.0,"list":[]},"empty":{}}');

        $members = $set->additionalMembers();
        $this->assertSame(['issuer', 'meta', 'empty'], array_keys($members));
        $this->assertInstanceOf(stdClass::class, $members['meta']);
        $this->assertInstanceOf(stdClass::class, $members['empty']);
        $this->assertSame(
            '{"keys":[],"issuer":"https://example.com","meta":{"n":1.0,"list":[]},"empty":{}}',
            $set->toJson(),
        );
    }

    public function testHandsOutCopiesOfTheAdditionalMembers(): void
    {
        $meta = new stdClass();
        $meta->n = 1;
        $set = new JwkSet([], ['meta' => $meta]);

        $copy = $set->additionalMembers()['meta'];
        $this->assertInstanceOf(stdClass::class, $copy);
        $this->assertNotSame($meta, $copy);
        $copy->n = 2;
        $meta->n = 3;

        $this->assertSame('{"keys":[],"meta":{"n":1}}', $set->toJson());
    }

    public function testKeepsANumericMemberNameAsReceived(): void
    {
        $set = JwkSet::fromJson('{"keys":[],"1":"one"}');

        $this->assertSame(['1' => 'one'], $set->additionalMembers());
        $this->assertSame('{"keys":[],"1":"one"}', $set->toJson());
        $this->assertSame('{"keys":[],"1":"one"}', JwkSet::fromJson(['keys' => [], '1' => 'one'])->toJson());
    }

    public function testKeepsTheLexicallyLastOfTwoMembersWithOneName(): void
    {
        $key = self::fixtureJson('rfc8037/appendix-a2.json');
        $set = JwkSet::fromJson('{"keys":[],"keys":[' . $key . ']}');

        $this->assertCount(1, $set);
    }

    /**
     * @return iterable<string, array{string | array<array-key, mixed> | stdClass, string}>
     */
    public static function invalidSetProvider(): iterable
    {
        yield 'malformed text' => ['{"keys":', 'The JSON text does not parse: Syntax error'];
        yield 'a JSON array' => ['[]', 'The JSON value is not an object'];
        yield 'a JSON string' => ['"keys"', 'The JSON value is not an object'];
        yield 'a PHP list' => [[['kty' => 'oct', 'k' => 'AQ']], 'The JSON value is not an object'];
        yield 'an empty PHP array' => [[], 'The JSON value is not an object'];
        yield 'a stdClass subclass' => [
            new class extends stdClass {
                /** @var array<never, never> */
                public array $keys = [];
            },
            'The JSON value is not an object',
        ];
        yield 'no keys member' => ['{"kty":"oct"}', 'The "keys" member is required'];
        yield 'keys as an object' => ['{"keys":{}}', 'The "keys" member must be an array'];
        yield 'keys as a string' => ['{"keys":"none"}', 'The "keys" member must be an array'];
        yield 'keys as null' => ['{"keys":null}', 'The "keys" member must be an array'];
        yield 'keys as a keyed PHP array' => [
            ['keys' => ['a' => ['kty' => 'oct', 'k' => 'AQ']]],
            'The "keys" member must be an array',
        ];
        yield 'another member that is not UTF-8' => [
            ['keys' => [], 'issuer' => "\xff"],
            'The "issuer" member holds a string that is not valid UTF-8',
        ];
        yield 'a member name that starts with NUL' => [
            ['keys' => [], "\0x" => 1],
            'A member name starts with a NUL byte',
        ];
    }

    /**
     * @param string | array<array-key, mixed> | stdClass $json
     */
    #[DataProvider('invalidSetProvider')]
    public function testRefusesASetObjectThatIsNotWellFormed(string | array | stdClass $json, string $message): void
    {
        $this->expectException(InvalidJwkSet::class);
        $this->expectExceptionMessageIsOrContains($message);

        JwkSet::fromJson($json);
    }

    public function testTheRefusalOfAnotherMemberKeepsTheKeysRefusalAsItsCause(): void
    {
        try {
            JwkSet::fromJson(['keys' => [], 'issuer' => "\xff"]);
            $this->fail('Expected InvalidJwkSet');
        } catch (InvalidJwkSet $exception) {
            $previous = $exception->getPrevious();
            $this->assertInstanceOf(InvalidJwk::class, $previous);
            $this->assertSame(InvalidJwkReason::InvalidValue, $previous->reason);
            $this->assertSame('issuer', $previous->member);
        }
    }

    public function testSkipsTheMembersItCannotUseAndKeepsTheRest(): void
    {
        $ec = self::fixture('rfc7517/section-3.json');
        $oct = self::fixture('rfc7520/section-3.5.json');
        $okp = self::fixture('rfc8037/appendix-a2.json');

        $set = JwkSet::fromJson(['keys' => [
            $ec,
            1,
            ['kty' => 'AKP', 'pub' => 'AQAB'],
            $oct,
            ['kty' => 'EC', 'crv' => 'P-256', 'x' => $ec['x']],
            [...$ec, 'x' => 'not base64url!'],
            [...$okp, 'alg' => 'ES256'],
            'a string',
            [],
            new stdClass(),
            $okp,
        ],
        ]);

        $this->assertCount(3, $set);
        $this->assertSame(
            [EcKey::class, OctKey::class, OkpKey::class],
            array_map(static fn (Jwk $key): string => $key::class, $set->keys()),
        );

        $skipped = $set->skipped();
        $this->assertSame(
            [1, 2, 4, 5, 6, 7, 8, 9],
            array_map(static fn (SkippedKey $skipped): int => $skipped->index, $skipped),
        );
        $this->assertSame(
            [
                InvalidJwkReason::NotAnObject,
                InvalidJwkReason::UnsupportedKeyType,
                InvalidJwkReason::MissingMember,
                InvalidJwkReason::InvalidBase64Url,
                InvalidJwkReason::AlgorithmDoesNotFitKey,
                InvalidJwkReason::NotAnObject,
                InvalidJwkReason::NotAnObject,
                InvalidJwkReason::MissingMember,
            ],
            array_map(static fn (SkippedKey $skipped): InvalidJwkReason => $skipped->cause->reason, $skipped),
        );
        $this->assertSame(
            'The "keys" member holds a value that is not an object at index 1',
            $skipped[0]->cause->getMessage(),
        );
        $this->assertSame('y', $skipped[2]->cause->member);
        $this->assertSame('kty', $skipped[7]->cause->member);
    }

    public function testSkipsAPrivateKeyAndASymmetricKeyWhenOnlyPublicKeysAreAccepted(): void
    {
        $set = JwkSet::fromJson(self::fixtureJson('rfc7517/appendix-a2.json'), publicOnly: true);
        $this->assertCount(0, $set);
        $this->assertSame(
            [InvalidJwkReason::PrivateMembersPresent, InvalidJwkReason::PrivateMembersPresent],
            array_map(static fn (SkippedKey $skipped): InvalidJwkReason => $skipped->cause->reason, $set->skipped()),
        );

        $set = JwkSet::fromJson(self::fixtureJson('rfc7517/appendix-a3.json'), publicOnly: true);
        $this->assertCount(0, $set);
        $this->assertSame(
            [InvalidJwkReason::SymmetricKey, InvalidJwkReason::SymmetricKey],
            array_map(static fn (SkippedKey $skipped): InvalidJwkReason => $skipped->cause->reason, $set->skipped()),
        );

        $this->assertCount(2, JwkSet::fromJson(self::fixtureJson('rfc7517/appendix-a1.json'), publicOnly: true));
    }

    public function testASetMixingSymmetricAndAsymmetricKeysParsesWhole(): void
    {
        $set = JwkSet::fromJson(['keys' => [
            self::fixture('rfc7520/section-3.5.json'),
            self::fixture('rfc7517/section-3.json'),
            self::fixture('rfc7520/section-3.6.json'),
        ],
        ]);

        $this->assertCount(3, $set);
        $this->assertSame([], $set->skipped());
        $this->assertInstanceOf(OctKey::class, $set->keys()[0]);
        $this->assertInstanceOf(EcKey::class, $set->keys()[1]);
    }

    public function testFindsAKeyByItsIdentifier(): void
    {
        $set = JwkSet::fromJson(self::fixtureJson('rfc7517/appendix-a1.json'));

        $this->assertInstanceOf(RsaKey::class, $set->findByKeyId('2011-04-29'));
        $this->assertInstanceOf(EcKey::class, $set->findByKeyId('1'));
        $this->assertInstanceOf(EcKey::class, $set->findByKeyId('1', KeyType::Ec));
        $this->assertNull($set->findByKeyId('1', KeyType::Rsa));
        $this->assertNull($set->findByKeyId('2'));
        $this->assertNull($set->findByKeyId(''));
        $this->assertSame([$set->keys()[0]], $set->findAllByKeyId('1'));
        $this->assertSame([], $set->findAllByKeyId('2'));
    }

    public function testASharedIdentifierIsAmbiguousUntilTheKeyTypeIsGiven(): void
    {
        $ec = Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a1.json', 0));
        $rsa = Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a1.json', 1))->withKeyId('1');
        $set = new JwkSet([$ec, $rsa]);

        $this->assertSame($ec, $set->findByKeyId('1', KeyType::Ec));
        $this->assertSame($rsa, $set->findByKeyId('1', KeyType::Rsa));
        $this->assertSame([$ec, $rsa], $set->findAllByKeyId('1'));

        try {
            $set->findByKeyId('1');
            $this->fail('Expected AmbiguousKeyId');
        } catch (AmbiguousKeyId $exception) {
            $this->assertSame(
                '2 keys have the key identifier "1"; pass the key type to choose among them',
                $exception->getMessage(),
            );
        }
    }

    public function testTwoKeysOfOneTypeWithOneIdentifierStayAmbiguous(): void
    {
        $ec = Jwk::fromJson(self::fixture('rfc7517/section-3.json'))->withKeyId('1');
        $set = new JwkSet([$ec, Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a1.json', 0)), $ec]);

        try {
            $set->findByKeyId('1', KeyType::Ec);
            $this->fail('Expected AmbiguousKeyId');
        } catch (AmbiguousKeyId $exception) {
            $this->assertSame('3 keys of type EC have the key identifier "1"', $exception->getMessage());
        }
    }

    public function testFindsAKeyByItsThumbprint(): void
    {
        $set = JwkSet::fromJson(self::fixtureJson('rfc7517/appendix-a2.json'));
        $public = Jwk::fromJson(self::fixtureSetMember('rfc7517/appendix-a1.json', 1));

        $found = $set->findByThumbprint($public->thumbprint());
        $this->assertInstanceOf(RsaKey::class, $found);
        $this->assertTrue($found->isPrivate());
        $this->assertSame(
            $found,
            $set->findByThumbprint($public->thumbprint(HashAlgorithm::Sha384), HashAlgorithm::Sha384),
        );
        $this->assertNull($set->findByThumbprint($public->thumbprint(HashAlgorithm::Sha384)));
        $this->assertNull($set->findByThumbprint('kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k'));
        $this->assertNull($set->findByThumbprint(''));
    }

    public function testWithKeyAppendsAndWithoutKeyRemovesTheInstance(): void
    {
        $set = JwkSet::fromJson(self::fixtureJson('rfc7517/appendix-a1.json'));
        $oct = Jwk::fromJson(self::fixture('rfc7520/section-3.5.json'));

        $added = $set->withKey($oct);
        $this->assertCount(3, $added);
        $this->assertSame($oct, $added->keys()[2]);
        $this->assertCount(2, $set);

        $removed = $added->withoutKey($set->keys()[0]);
        $this->assertSame([$set->keys()[1], $oct], $removed->keys());
        $this->assertCount(3, $added);

        $equalButDifferent = Jwk::fromJson(self::fixture('rfc7520/section-3.5.json'));
        $this->assertSame($removed->keys(), $removed->withoutKey($equalButDifferent)->keys());
    }

    public function testTheChangedSetsKeepTheSkippedMembersAndTheOtherMembers(): void
    {
        $set = JwkSet::fromJson('{"keys":[{"kty":"none"}],"issuer":"https://example.com"}');
        $oct = Jwk::fromJson(self::fixture('rfc7520/section-3.5.json'));

        $changed = $set->withKey($oct)->withoutKey($oct);

        $this->assertCount(1, $changed->skipped());
        $this->assertSame(['issuer' => 'https://example.com'], $changed->additionalMembers());
        $this->assertSame('{"keys":[],"issuer":"https://example.com"}', $changed->toJson());
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function notAListOfKeysProvider(): iterable
    {
        yield 'a keyed array' => [['a' => Jwk::fromJson(['kty' => 'oct', 'k' => 'AQ'])]];
        yield 'a string' => [['not a key']];
        yield 'a decoded JWK' => [[['kty' => 'oct', 'k' => 'AQ']]];
        yield 'null' => [[null]];
    }

    /**
     * @param array<array-key, mixed> $keys
     */
    #[DataProvider('notAListOfKeysProvider')]
    public function testTheConstructorRefusesAnythingButAListOfKeys(array $keys): void
    {
        $this->expectException(InvalidJwkSet::class);
        $this->expectExceptionMessageIsOrContains('The keys must be a list of Jwk objects');

        new ReflectionClass(JwkSet::class)->newInstance($keys);
    }

    public function testTheConstructorRefusesAnAdditionalMemberNamedKeys(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains(
            'The "keys" member holds the keys and is not an additional member',
        );

        new JwkSet([], ['keys' => []]);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, InvalidJwkReason}>
     */
    public static function refusedAdditionalMemberProvider(): iterable
    {
        yield 'a string that is not UTF-8' => [['issuer' => "\xff"], InvalidJwkReason::InvalidValue];
        yield 'a number that is not finite' => [['n' => INF], InvalidJwkReason::InvalidValue];
        yield 'a value that is not a JSON value' => [['when' => new DateTimeImmutable()], InvalidJwkReason::WrongType];
        yield 'a name that is not UTF-8' => [["\xff" => 1], InvalidJwkReason::MalformedJson];
    }

    /**
     * @param array<string, mixed> $members
     */
    #[DataProvider('refusedAdditionalMemberProvider')]
    public function testTheConstructorChecksTheAdditionalMembersAsAKeyDoes(
        array $members,
        InvalidJwkReason $reason,
    ): void {
        try {
            new JwkSet([], $members);
            $this->fail('Expected InvalidJwkSet');
        } catch (InvalidJwkSet $exception) {
            $previous = $exception->getPrevious();
            $this->assertInstanceOf(InvalidJwk::class, $previous);
            $this->assertSame($reason, $previous->reason);
            $this->assertSame($previous->getMessage(), $exception->getMessage());
            $this->assertSame(0, $exception->getCode());
        }
    }

    public function testCannotBeSerializedOrUnserialized(): void
    {
        $set = JwkSet::fromJson(self::fixtureJson('rfc7517/appendix-a3.json'));

        try {
            serialize($set);
            $this->fail('Expected LogicException');
        } catch (LogicException $exception) {
            $this->assertSame(
                'A JWK Set cannot be serialized with serialize(); use toJson()',
                $exception->getMessage(),
            );
        }

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains(
            'A JWK Set cannot be unserialized with unserialize(); use JwkSet::fromJson()',
        );

        unserialize('O:20:"SocialWeb\Jwk\JwkSet":1:{s:4:"keys";a:0:{}}');
    }
}
