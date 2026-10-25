<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\MemberReader;

use function sprintf;
use function str_contains;
use function str_repeat;

class MemberReaderTest extends TestCase
{
    public function testReadsAnObjectFromJsonText(): void
    {
        $reader = MemberReader::fromJson('{"kty":"EC","crv":"P-256","x":"AQAB"}');

        $this->assertTrue($reader->has('kty'));
        $this->assertFalse($reader->has('y'));
        $this->assertSame('EC', $reader->string('kty'));
        $this->assertSame("\x01\x00\x01", $reader->bytes('x'));
    }

    public function testReadsAnObjectFromADecodedArray(): void
    {
        $reader = MemberReader::fromJson(['kty' => 'oct', 'k' => 'AQAB']);

        $this->assertSame('oct', $reader->requiredString('kty'));
        $this->assertSame("\x01\x00\x01", $reader->requiredBytes('k'));
    }

    public function testAnEmptyObjectHasNoMembers(): void
    {
        $this->assertFalse(MemberReader::fromJson('{}')->has('kty'));
        $this->assertFalse(MemberReader::fromJson([])->has('kty'));
    }

    public function testKeepsTheLexicallyLastOfTwoMembersWithOneName(): void
    {
        $reader = MemberReader::fromJson('{"kty":"EC","kty":"RSA"}');

        $this->assertSame('RSA', $reader->string('kty'));
    }

    public function testANumericMemberNameIsReadAsAString(): void
    {
        $reader = MemberReader::fromJson('{"1":"one","kty":"oct"}');

        $this->assertTrue($reader->has('1'));
        $this->assertSame('one', $reader->string('1'));
        $this->assertSame(['1' => 'one'], $reader->except(['kty']));
    }

    public function testRefusesJsonTextThatDoesNotParse(): void
    {
        try {
            MemberReader::fromJson('{"kty":');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::MalformedJson, $exception->reason);
            $this->assertNull($exception->member);
            $this->assertSame('The JSON text does not parse: Syntax error', $exception->getMessage());
            $this->assertNull($exception->getPrevious());
        }
    }

    public function testReadsAMemberNestedToTheDepthPhpAllowsAndRefusesOneDeeper(): void
    {
        $nested = static fn (int $depth): string => '{"kty":"oct","deep":'
            . str_repeat('[', $depth) . str_repeat(']', $depth) . '}';

        $this->assertTrue(MemberReader::fromJson($nested(510))->has('deep'));

        try {
            MemberReader::fromJson($nested(511));
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::MalformedJson, $exception->reason);
            $this->assertSame(
                'The JSON text does not parse: Maximum stack depth exceeded',
                $exception->getMessage(),
            );
        }
    }

    public function testRefusesJsonTextWithContentAfterTheObject(): void
    {
        $this->expectException(InvalidJwk::class);

        MemberReader::fromJson('{"kty":"oct"} trailing');
    }

    /**
     * @return iterable<string, array{string | array<array-key, mixed>}>
     */
    public static function notAnObjectProvider(): iterable
    {
        yield 'a JSON array' => ['["kty"]'];
        yield 'a JSON string' => ['"kty"'];
        yield 'a JSON number' => ['42'];
        yield 'JSON null' => ['null'];
        yield 'a PHP list' => [['kty', 'oct']];
    }

    /**
     * @param string | array<array-key, mixed> $json
     */
    #[DataProvider('notAnObjectProvider')]
    public function testRefusesAValueThatIsNotAnObject(string | array $json): void
    {
        try {
            MemberReader::fromJson($json);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::NotAnObject, $exception->reason);
            $this->assertSame('The JSON value is not an object', $exception->getMessage());
        }
    }

    public function testAnAbsentStringIsNull(): void
    {
        $this->assertNull(MemberReader::fromJson('{}')->string('kid'));
        $this->assertNull(MemberReader::fromJson('{}')->bytes('x'));
    }

    public function testAStringMemberMustBeAString(): void
    {
        try {
            MemberReader::fromJson('{"kid":1}')->string('kid');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::WrongType, $exception->reason);
            $this->assertSame('kid', $exception->member);
            $this->assertSame('The "kid" member must be a string', $exception->getMessage());
        }
    }

    public function testARequiredStringMustBePresent(): void
    {
        try {
            MemberReader::fromJson('{}')->requiredString('kty');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::MissingMember, $exception->reason);
            $this->assertSame('kty', $exception->member);
            $this->assertSame('The "kty" member is required', $exception->getMessage());
        }
    }

    public function testABytesMemberMustBeBase64Url(): void
    {
        try {
            MemberReader::fromJson('{"x":"AQAB=="}')->bytes('x');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::InvalidBase64Url, $exception->reason);
            $this->assertSame('x', $exception->member);
            $this->assertSame(
                'The "x" member is not base64url without padding: '
                . 'The text has a character outside the base64url alphabet',
                $exception->getMessage(),
            );
            $this->assertInstanceOf(InvalidArgument::class, $exception->getPrevious());
        }
    }

    public function testABytesMemberMustBeAString(): void
    {
        try {
            MemberReader::fromJson('{"x":[1]}')->bytes('x');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::WrongType, $exception->reason);
        }
    }

    public function testRequiredBytesMustBePresent(): void
    {
        try {
            MemberReader::fromJson('{}')->requiredBytes('n');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::MissingMember, $exception->reason);
            $this->assertSame('n', $exception->member);
        }
    }

    public function testAnAbsentStringListIsEmpty(): void
    {
        $this->assertSame([], MemberReader::fromJson('{}')->stringList('key_ops'));
    }

    public function testReadsAStringList(): void
    {
        $reader = MemberReader::fromJson('{"key_ops":["sign","verify"]}');

        $this->assertSame(['sign', 'verify'], $reader->stringList('key_ops'));
        $this->assertSame([], MemberReader::fromJson('{"key_ops":[]}')->stringList('key_ops'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function badStringListProvider(): iterable
    {
        yield 'a string' => ['{"key_ops":"sign"}', 'The "key_ops" member must be an array'];
        yield 'an object' => ['{"key_ops":{"a":"sign"}}', 'The "key_ops" member must be an array'];
        yield 'a number entry' => ['{"key_ops":["sign",1]}', 'Every entry of the "key_ops" member must be a string'];
        yield 'a null entry' => ['{"key_ops":[null]}', 'Every entry of the "key_ops" member must be a string'];
    }

    #[DataProvider('badStringListProvider')]
    public function testAStringListMustBeAnArrayOfStrings(string $json, string $message): void
    {
        try {
            MemberReader::fromJson($json)->stringList('key_ops');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::WrongType, $exception->reason);
            $this->assertSame('key_ops', $exception->member);
            $this->assertSame($message, $exception->getMessage());
        }
    }

    public function testAnAbsentObjectListIsEmpty(): void
    {
        $this->assertSame([], MemberReader::fromJson('{}')->objectList('oth'));
    }

    public function testReadsAnObjectList(): void
    {
        $readers = MemberReader::fromJson('{"oth":[{"r":"AQ"},{"r":"Ag"}]}')->objectList('oth');

        $this->assertCount(2, $readers);
        $this->assertSame("\x01", $readers[0]->bytes('r'));
        $this->assertSame("\x02", $readers[1]->bytes('r'));
        $this->assertSame([], MemberReader::fromJson('{"oth":[{}]}')->objectList('oth')[0]->except([]));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function badObjectListProvider(): iterable
    {
        yield 'a string' => ['{"oth":"r"}', 'The "oth" member must be an array'];
        yield 'an object' => ['{"oth":{"r":"AQ"}}', 'The "oth" member must be an array'];
        yield 'a string entry' => ['{"oth":["AQ"]}', 'Every entry of the "oth" member must be an object'];
        yield 'an array entry' => ['{"oth":[["AQ"]]}', 'Every entry of the "oth" member must be an object'];
    }

    #[DataProvider('badObjectListProvider')]
    public function testAnObjectListMustBeAnArrayOfObjects(string $json, string $message): void
    {
        try {
            MemberReader::fromJson($json)->objectList('oth');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::WrongType, $exception->reason);
            $this->assertSame('oth', $exception->member);
            $this->assertSame($message, $exception->getMessage());
        }
    }

    public function testExceptReturnsTheOtherMembersInOrder(): void
    {
        $reader = MemberReader::fromJson('{"kty":"oct","ext":true,"k":"AQAB","nested":{"a":[1,2]}}');

        $this->assertSame(['ext' => true, 'nested' => ['a' => [1, 2]]], $reader->except(['kty', 'k']));
        $this->assertSame([], $reader->except(['kty', 'ext', 'k', 'nested']));
    }

    public function testExceptLeavesOutANumericMemberName(): void
    {
        $reader = MemberReader::fromJson('{"1":"one","2":"two","kty":"oct"}');

        $this->assertSame(['2' => 'two', 'kty' => 'oct'], $reader->except(['1']));
        $this->assertSame([], $reader->except(['1', '2', 'kty']));
    }

    public function testAnEmptyJsonArrayIsNotAnObject(): void
    {
        try {
            MemberReader::fromJson('[]');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::NotAnObject, $exception->reason);
        }
    }

    public function testAJsonObjectIsNotAStringList(): void
    {
        foreach (['{"key_ops":{}}', '{"x5c":{}}'] as $json) {
            $member = str_contains($json, 'key_ops') ? 'key_ops' : 'x5c';

            try {
                MemberReader::fromJson($json)->stringList($member);
                $this->fail('Expected InvalidJwk');
            } catch (InvalidJwk $exception) {
                $this->assertSame(InvalidJwkReason::WrongType, $exception->reason);
                $this->assertSame($member, $exception->member);
                $this->assertSame(sprintf('The "%s" member must be an array', $member), $exception->getMessage());
            }
        }
    }

    public function testAJsonObjectIsNotAnObjectList(): void
    {
        try {
            MemberReader::fromJson('{"oth":{}}')->objectList('oth');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::WrongType, $exception->reason);
            $this->assertSame('The "oth" member must be an array', $exception->getMessage());
        }
    }

    public function testAJsonArrayIsNotAnEntryOfAnObjectList(): void
    {
        try {
            MemberReader::fromJson('{"oth":[[]]}')->objectList('oth');
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::WrongType, $exception->reason);
            $this->assertSame('oth', $exception->member);
            $this->assertSame('Every entry of the "oth" member must be an object', $exception->getMessage());
        }
    }

    public function testReadsEmptyJsonObjectsAndArraysAsTheyAre(): void
    {
        $reader = MemberReader::fromJson('{"key_ops":[],"oth":[{}],"nested":{"a":{},"b":[]}}');

        $this->assertSame([], $reader->stringList('key_ops'));
        $this->assertCount(1, $reader->objectList('oth'));
        $this->assertSame(['nested' => ['a' => [], 'b' => []]], $reader->except(['key_ops', 'oth']));
    }
}
