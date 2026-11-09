<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use DateTimeImmutable;
use JsonSerializable;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use ReflectionClass;
use SocialWeb\Jwk\EcKey;
use SocialWeb\Jwk\Exception\AmbiguousKeyId;
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\Exception\InvalidJwkSet;
use SocialWeb\Jwk\Exception\InvalidJwkSetReason;
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
use function sprintf;
use function str_repeat;
use function unserialize;

use const INF;
use const JSON_THROW_ON_ERROR;

final class JwkSetTest extends TestCase
{
    /**
     * @return iterable<string, array{string, list<class-string<Jwk>>, list<?string>}>
     */
    public static function rfc7517AppendixASets(): iterable
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
    #[DataProvider('rfc7517AppendixASets')]
    public function testParsesTheRfc7517AppendixASets(string $file, array $classes, array $keyIds): void
    {
        $fixture = self::fixture($file);
        $set = JwkSet::fromJson(self::fixtureJson($file));

        $keys = iterator_to_array($set);

        $this->assertCount(2, $set);
        $this->assertSame([], $set->skipped);
        $this->assertSame($classes, array_map(static fn (Jwk $key): string => $key::class, $keys));
        $this->assertSame($keyIds, array_map(static fn (Jwk $key): ?string => $key->keyId, $keys));
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

    public function testFromJsonTakesAJsonSerializableAsWhatItSerializesTo(): void
    {
        $set = JwkSet::fromJson(self::fixtureJson('rfc7517/appendix-a1.json'));
        $serializable = new class ($set->jsonSerialize()) implements JsonSerializable {
            /**
             * @param array<string, mixed> $value
             */
            public function __construct(private readonly array $value)
            {
            }

            public function jsonSerialize(): mixed
            {
                return $this->value;
            }
        };

        $this->assertSame($set->toJson(), JwkSet::fromJson($set)->toJson());
        $this->assertSame($set->toJson(), JwkSet::fromJson($serializable)->toJson());
    }

    public function testRefusesAValueOfATypeJsonCannotHoldBeforeReadingAnyEntry(): void
    {
        $ec = self::fixture('rfc7517/section-3.json');
        $attempts = [
            'a stdClass subclass' => [
                new class extends stdClass {
                    /** @var array<never, never> */
                    public array $keys = [];
                },
                'stdClass@anonymous',
            ],
            'a closure in a keys entry after a malformed one' => [
                ['keys' => [[...$ec, 'x' => "\xff"], [...$ec, 'ext' => static fn (): int => 1]]],
                'Closure',
            ],
            'a date in another member' => [['keys' => [], 'when' => new DateTimeImmutable()], 'DateTimeImmutable'],
        ];

        foreach ($attempts as $label => [$json, $type]) {
            try {
                JwkSet::fromJson($json);
                $this->fail('Expected InvalidArgument for ' . $label);
            } catch (InvalidArgument $exception) {
                $this->assertSame(
                    sprintf('A value of type %s cannot be read as JSON', $type),
                    $exception->getMessage(),
                    $label,
                );
            }
        }
    }

    public function testASetTextNestedDeeperThanAKeyMayBeIsMalformed(): void
    {
        $deep = str_repeat('[', 511) . str_repeat(']', 511);

        try {
            JwkSet::fromJson('{"keys":[{"kty":"oct","k":"AQ","deep":' . $deep . '}]}');
            $this->fail('Expected InvalidJwkSet');
        } catch (InvalidJwkSet $exception) {
            $this->assertSame(InvalidJwkSetReason::MalformedJson, $exception->reason);
            $this->assertSame(
                'The JSON text does not parse: Maximum stack depth exceeded',
                $exception->getMessage(),
            );
        }
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

    public function testWritesACharacterOutsideAsciiAsItself(): void
    {
        $set = JwkSet::fromJson('{"keys":[],"issuer":"https://example.com/clé"}');

        $this->assertSame('{"keys":[],"issuer":"https://example.com/clé"}', $set->toJson());
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
     * @return iterable<string, array{string | array<array-key, mixed>, InvalidJwkSetReason, string}>
     */
    public static function invalidSets(): iterable
    {
        yield 'malformed text' => [
            '{"keys":',
            InvalidJwkSetReason::MalformedJson,
            'The JSON text does not parse: Syntax error',
        ];
        yield 'a JSON array' => ['[]', InvalidJwkSetReason::NotAnObject, 'The JSON value is not an object'];
        yield 'a JSON string' => ['"keys"', InvalidJwkSetReason::NotAnObject, 'The JSON value is not an object'];
        yield 'JSON null' => ['null', InvalidJwkSetReason::NotAnObject, 'The JSON value is not an object'];
        yield 'a PHP list' => [
            [['kty' => 'oct', 'k' => 'AQ']],
            InvalidJwkSetReason::NotAnObject,
            'The JSON value is not an object',
        ];
        yield 'an empty PHP array' => [[], InvalidJwkSetReason::NotAnObject, 'The JSON value is not an object'];
        yield 'no keys member' => [
            '{"kty":"oct"}',
            InvalidJwkSetReason::MissingKeysMember,
            'The "keys" member is required',
        ];
        yield 'keys as an object' => [
            '{"keys":{}}',
            InvalidJwkSetReason::KeysNotAnArray,
            'The "keys" member must be an array',
        ];
        yield 'keys as a string' => [
            '{"keys":"none"}',
            InvalidJwkSetReason::KeysNotAnArray,
            'The "keys" member must be an array',
        ];
        yield 'keys as null' => [
            '{"keys":null}',
            InvalidJwkSetReason::KeysNotAnArray,
            'The "keys" member must be an array',
        ];
        yield 'keys as a keyed PHP array' => [
            ['keys' => ['a' => ['kty' => 'oct', 'k' => 'AQ']]],
            InvalidJwkSetReason::KeysNotAnArray,
            'The "keys" member must be an array',
        ];
        yield 'another member that is not UTF-8' => [
            ['keys' => [], 'issuer' => "\xff"],
            InvalidJwkSetReason::MalformedJson,
            'The "issuer" member holds a string that is not valid UTF-8',
        ];
        yield 'another member that is not finite' => [
            ['keys' => [], 'n' => INF],
            InvalidJwkSetReason::MalformedJson,
            'The "n" member holds a number that is not finite',
        ];
        yield 'a member name that starts with NUL' => [
            ['keys' => [], "\0x" => 1],
            InvalidJwkSetReason::MalformedJson,
            'A member name starts with a NUL byte',
        ];
    }

    /**
     * @param string | array<array-key, mixed> $json
     */
    #[DataProvider('invalidSets')]
    public function testRefusesASetObjectThatIsNotWellFormed(
        string | array $json,
        InvalidJwkSetReason $reason,
        string $message,
    ): void {
        try {
            JwkSet::fromJson($json);
            $this->fail('Expected InvalidJwkSet');
        } catch (InvalidJwkSet $exception) {
            $this->assertSame($reason, $exception->reason);
            $this->assertSame($message, $exception->getMessage());
        }
    }

    public function testTheRefusalOfAnotherMemberKeepsTheKeysRefusalAsItsCause(): void
    {
        try {
            JwkSet::fromJson(['keys' => [], 'issuer' => "\xff"]);
            $this->fail('Expected InvalidJwkSet');
        } catch (InvalidJwkSet $exception) {
            $this->assertSame(InvalidJwkSetReason::MalformedJson, $exception->reason);
            $previous = $exception->getPrevious();
            $this->assertInstanceOf(InvalidJwk::class, $previous);
            $this->assertSame(InvalidJwkReason::MalformedJson, $previous->reason);
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
            array_map(static fn (Jwk $key): string => $key::class, iterator_to_array($set)),
        );

        $skipped = $set->skipped;
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

    public function testSkipsAKeyWithAnEmptyKeyOperationsArrayAndKeepsTheRest(): void
    {
        $okp = self::fixture('rfc8037/appendix-a2.json');

        $set = JwkSet::fromJson(['keys' => [[...$okp, 'key_ops' => []], $okp]]);

        $this->assertCount(1, $set);
        $this->assertCount(1, $set->skipped);
        $this->assertSame(0, $set->skipped[0]->index);
        $this->assertSame(InvalidJwkReason::EmptyKeyOperations, $set->skipped[0]->cause->reason);
        $this->assertSame('key_ops', $set->skipped[0]->cause->member);
    }

    public function testSkipsAMemberOfTheWrongJsonTypeAndKeepsTheRest(): void
    {
        $ec = self::fixture('rfc7517/section-3.json');
        $okp = self::fixture('rfc8037/appendix-a2.json');

        $set = JwkSet::fromJson(['keys' => [$ec, [...$ec, 'kid' => 5], $okp]]);

        $this->assertSame(
            [EcKey::class, OkpKey::class],
            array_map(static fn (Jwk $key): string => $key::class, iterator_to_array($set)),
        );

        $skipped = $set->skipped;
        $this->assertCount(1, $skipped);
        $this->assertSame(1, $skipped[0]->index);
        $this->assertSame(InvalidJwkReason::WrongType, $skipped[0]->cause->reason);
        $this->assertSame('kid', $skipped[0]->cause->member);
    }

    public function testSkipsAPrivateKeyAndASymmetricKeyWhenOnlyPublicKeysAreAccepted(): void
    {
        $set = JwkSet::fromJson(self::fixtureJson('rfc7517/appendix-a2.json'), publicOnly: true);
        $this->assertCount(0, $set);
        $this->assertSame(
            [InvalidJwkReason::PrivateMembersPresent, InvalidJwkReason::PrivateMembersPresent],
            array_map(static fn (SkippedKey $skipped): InvalidJwkReason => $skipped->cause->reason, $set->skipped),
        );

        $set = JwkSet::fromJson(self::fixtureJson('rfc7517/appendix-a3.json'), publicOnly: true);
        $this->assertCount(0, $set);
        $this->assertSame(
            [InvalidJwkReason::SymmetricKey, InvalidJwkReason::SymmetricKey],
            array_map(static fn (SkippedKey $skipped): InvalidJwkReason => $skipped->cause->reason, $set->skipped),
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

        $keys = iterator_to_array($set);

        $this->assertCount(3, $set);
        $this->assertSame([], $set->skipped);
        $this->assertInstanceOf(OctKey::class, $keys[0]);
        $this->assertInstanceOf(EcKey::class, $keys[1]);
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
        $this->assertSame([iterator_to_array($set)[0]], $set->findAllByKeyId('1'));
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
                'Key identifier "1" names 2 keys; pass the key type to choose among them',
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
            $this->assertSame('Key identifier "1" names 3 keys of type EC', $exception->getMessage());
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

        $keys = iterator_to_array($set);

        $added = $set->withKey($oct);
        $this->assertCount(3, $added);
        $this->assertSame($oct, iterator_to_array($added)[2]);
        $this->assertCount(2, $set);

        $removed = $added->withoutKey($keys[0]);
        $this->assertSame([$keys[1], $oct], iterator_to_array($removed));
        $this->assertCount(3, $added);

        $equalButDifferent = Jwk::fromJson(self::fixture('rfc7520/section-3.5.json'));
        $this->assertSame(iterator_to_array($removed), iterator_to_array($removed->withoutKey($equalButDifferent)));
    }

    public function testTheChangedSetsKeepTheSkippedMembersAndTheOtherMembers(): void
    {
        $set = JwkSet::fromJson('{"keys":[{"kty":"none"}],"issuer":"https://example.com"}');
        $oct = Jwk::fromJson(self::fixture('rfc7520/section-3.5.json'));

        $changed = $set->withKey($oct)->withoutKey($oct);

        $this->assertCount(1, $changed->skipped);
        $this->assertSame(['issuer' => 'https://example.com'], $changed->additionalMembers());
        $this->assertSame('{"keys":[],"issuer":"https://example.com"}', $changed->toJson());
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function invalidKeyLists(): iterable
    {
        yield 'a keyed array' => [['a' => Jwk::fromJson(['kty' => 'oct', 'k' => 'AQ'])]];
        yield 'a string' => [['not a key']];
        yield 'a decoded JWK' => [[['kty' => 'oct', 'k' => 'AQ']]];
        yield 'null' => [[null]];
    }

    /**
     * @param array<array-key, mixed> $keys
     */
    #[DataProvider('invalidKeyLists')]
    public function testTheConstructorRefusesAnythingButAListOfKeys(array $keys): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('keys must be a list of Jwk objects');

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
    public static function refusedAdditionalMembers(): iterable
    {
        yield 'a string that is not UTF-8' => [['issuer' => "\xff"], InvalidJwkReason::MalformedJson];
        yield 'a number that is not finite' => [['n' => INF], InvalidJwkReason::MalformedJson];
        yield 'a name that is not UTF-8' => [["\xff" => 1], InvalidJwkReason::MalformedJson];
    }

    /**
     * @param array<string, mixed> $members
     */
    #[DataProvider('refusedAdditionalMembers')]
    public function testTheConstructorChecksTheAdditionalMembersAsAKeyDoes(
        array $members,
        InvalidJwkReason $reason,
    ): void {
        try {
            new JwkSet([], $members);
            $this->fail('Expected InvalidJwkSet');
        } catch (InvalidJwkSet $exception) {
            $this->assertSame(InvalidJwkSetReason::MalformedJson, $exception->reason);
            $previous = $exception->getPrevious();
            $this->assertInstanceOf(InvalidJwk::class, $previous);
            $this->assertSame($reason, $previous->reason);
            $this->assertSame($previous->getMessage(), $exception->getMessage());
            $this->assertSame(0, $exception->getCode());
        }
    }

    public function testTheConstructorRefusesAnAdditionalMemberOfATypeJsonCannotHold(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('A value of type DateTimeImmutable cannot be read as JSON');

        new JwkSet([], ['when' => new DateTimeImmutable()]);
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
