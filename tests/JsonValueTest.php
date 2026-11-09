<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use DateTimeImmutable;
use JsonSerializable;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\JsonValue;
use SocialWeb\Jwk\KeyUse;
use stdClass;

use function fclose;
use function fopen;
use function get_debug_type;
use function get_object_vars;
use function ini_set;
use function json_encode;
use function sprintf;

use const INF;
use const JSON_PRESERVE_ZERO_FRACTION;
use const JSON_THROW_ON_ERROR;
use const NAN;

final class JsonValueTest extends TestCase
{
    public function testReadsScalarsAsTheyAre(): void
    {
        $this->assertNull(JsonValue::read('m', null));
        $this->assertTrue(JsonValue::read('m', true));
        $this->assertFalse(JsonValue::read('m', false));
        $this->assertSame(-1, JsonValue::read('m', -1));
        $this->assertSame(1.0, JsonValue::read('m', 1.0));
        $this->assertSame('é', JsonValue::read('m', 'é'));
    }

    public function testReadsAPhpListAsAJsonArrayAndAnyOtherPhpArrayAsAJsonObject(): void
    {
        $object = new stdClass();
        $object->{'0'} = 'a';
        $value = JsonValue::read('m', [[], ['a' => 1.0], [1 => 'b'], $object, new stdClass(), ['x', 2.5]]);

        $this->assertSame(
            '[[],{"a":1.0},{"1":"b"},{"0":"a"},{},["x",2.5]]',
            json_encode($value, JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR),
        );
    }

    public function testReadsKeyedArraysNestedToTheDepthPhpAllows(): void
    {
        $value = ['a' => 1];

        for ($level = 1; $level < 510; $level++) {
            $value = ['a' => $value];
        }

        $copy = JsonValue::read('m', $value);
        $this->assertInstanceOf(stdClass::class, $copy);

        try {
            JsonValue::read('m', ['a' => $value]);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::MalformedJson, $exception->reason);
            $this->assertSame('m', $exception->member);
        }
    }

    public function testReadsAMemberNestedToTheDepthPhpAllows(): void
    {
        $value = [];

        for ($level = 1; $level < 510; $level++) {
            $value = [$value];
        }

        $this->assertSame($value, JsonValue::read('m', $value));

        try {
            JsonValue::read('m', [$value]);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::MalformedJson, $exception->reason);
            $this->assertSame('m', $exception->member);
            $this->assertSame(
                'The "m" member is nested deeper than the 512 levels JSON text allows',
                $exception->getMessage(),
            );
        }
    }

    /**
     * @return iterable<string, array{mixed, InvalidJwkReason, string}>
     */
    public static function refusedValues(): iterable
    {
        yield 'a string that is not UTF-8' => [
            "\xff",
            InvalidJwkReason::MalformedJson,
            'The "m" member holds a string that is not valid UTF-8',
        ];
        yield 'a nested string that is not UTF-8' => [
            ['a' => ['ok', "\xc3"]],
            InvalidJwkReason::MalformedJson,
            'The "m" member holds a string that is not valid UTF-8',
        ];
        yield 'infinity' => [INF, InvalidJwkReason::MalformedJson, 'The "m" member holds a number that is not finite'];
        yield 'negative infinity' => [
            [-INF],
            InvalidJwkReason::MalformedJson,
            'The "m" member holds a number that is not finite',
        ];
        yield 'not a number' => [
            (object) ['a' => NAN],
            InvalidJwkReason::MalformedJson,
            'The "m" member holds a number that is not finite',
        ];
        yield 'a nested name that is not UTF-8' => [
            [['ok' => 1, "\xff" => 1]],
            InvalidJwkReason::MalformedJson,
            'A member name in the "m" member is not valid UTF-8',
        ];
        yield 'a nested stdClass name that is not UTF-8' => [
            (object) ["\xff" => 1],
            InvalidJwkReason::MalformedJson,
            'A member name in the "m" member is not valid UTF-8',
        ];
        yield 'a nested name that starts with NUL' => [
            ["\0a" => 1],
            InvalidJwkReason::MalformedJson,
            'A member name in the "m" member starts with a NUL byte',
        ];
        yield 'a nested stdClass name that starts with NUL' => [
            ['a' => (object) ["\0a" => 1]],
            InvalidJwkReason::MalformedJson,
            'A member name in the "m" member starts with a NUL byte',
        ];
    }

    #[DataProvider('refusedValues')]
    public function testRefusesWhatJsonTextCannotHold(mixed $value, InvalidJwkReason $reason, string $message): void
    {
        try {
            JsonValue::read('m', $value);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame($reason, $exception->reason);
            $this->assertSame('m', $exception->member);
            $this->assertSame($message, $exception->getMessage());
        }
    }

    /**
     * @return iterable<string, array{mixed, string}>
     */
    public static function valuesOfATypeJsonCannotHold(): iterable
    {
        yield 'an object other than stdClass' => [new DateTimeImmutable(), 'DateTimeImmutable'];
        yield 'a closure in a list' => [[static fn (): int => 1], 'Closure'];
        yield 'an enum case in an object' => [(object) ['a' => KeyUse::Signature], KeyUse::class];
    }

    #[DataProvider('valuesOfATypeJsonCannotHold')]
    public function testRefusesAValueOfATypeJsonCannotHoldAsACallersMistake(mixed $value, string $type): void
    {
        try {
            JsonValue::read('m', $value);
            $this->fail('Expected InvalidArgument');
        } catch (InvalidArgument $exception) {
            $this->assertSame(
                sprintf('The "m" member holds a value of type %s, which cannot be read as JSON', $type),
                $exception->getMessage(),
            );
        }
    }

    public function testRefusesAResource(): void
    {
        $resource = fopen('php://memory', 'r');

        try {
            JsonValue::read('m', ['a' => $resource]);
            $this->fail('Expected InvalidArgument');
        } catch (InvalidArgument $exception) {
            $this->assertSame(
                'The "m" member holds a value of type resource (stream), which cannot be read as JSON',
                $exception->getMessage(),
            );
        } finally {
            if ($resource !== false) {
                fclose($resource);
            }
        }
    }

    public function testCheckTypesRefusesAValueJsonCannotHoldAtAnyDepth(): void
    {
        $resource = fopen('php://memory', 'r');
        $values = [
            'at the top' => [new DateTimeImmutable(), 'DateTimeImmutable'],
            'in a list' => [[1, [2, [static fn (): int => 3]]], 'Closure'],
            'in an object' => [(object) ['a' => (object) ['b' => KeyUse::Signature]], KeyUse::class],
            'a stdClass subclass' => [
                ['a' => new class extends stdClass {
                },
                ],
                'stdClass@anonymous',
            ],
            'a resource' => [['a' => $resource], 'resource (stream)'],
        ];

        try {
            foreach ($values as $label => [$value, $type]) {
                try {
                    JsonValue::checkTypes($value);
                    $this->fail('Expected InvalidArgument for ' . $label);
                } catch (InvalidArgument $exception) {
                    $this->assertSame(
                        sprintf('A value of type %s cannot be read as JSON', $type),
                        $exception->getMessage(),
                        $label,
                    );
                }
            }
        } finally {
            if ($resource !== false) {
                fclose($resource);
            }
        }
    }

    public function testCheckTypesWalksEveryJsonTypeAndStopsAtTheDepthReadRefuses(): void
    {
        $value = ['a' => null, 'b' => [true, false, 1, 1.5, 'é'], 'c' => (object) ['d' => [new stdClass()]]];

        for ($level = 1; $level < 600; $level++) {
            $value = ['deep' => $value];
        }

        JsonValue::checkTypes($value);
        $cyclic = new stdClass();
        $cyclic->self = $cyclic;
        JsonValue::checkTypes($cyclic);

        $this->expectException(InvalidJwk::class);

        JsonValue::read('m', $value);
    }

    public function testCheckTypesEndsOnAnObjectThatHoldsItselfTwice(): void
    {
        $twice = new stdClass();
        $twice->a = $twice;
        $twice->b = $twice;
        JsonValue::checkTypes($twice);

        $this->expectException(InvalidJwk::class);

        JsonValue::read('m', $twice);
    }

    public function testCheckTypesWalksExactlyAsDeepAsReadReads(): void
    {
        $closure = static fn (): int => 1;
        $atTheDeepestLevelRead = [$closure];
        $oneLevelDeeper = [$closure];

        for ($level = 2; $level <= JsonValue::MAX_DEPTH; $level++) {
            $atTheDeepestLevelRead = [$atTheDeepestLevelRead];
            $oneLevelDeeper = [$oneLevelDeeper];
        }

        $oneLevelDeeper = [$oneLevelDeeper];
        JsonValue::checkTypes($oneLevelDeeper);

        try {
            JsonValue::read('m', $oneLevelDeeper);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::MalformedJson, $exception->reason);
        }

        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('A value of type Closure cannot be read as JSON');

        JsonValue::checkTypes($atTheDeepestLevelRead);
    }

    public function testReadMembersFindsATypeJsonCannotHoldBeforeReadingAnyMember(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('A value of type Closure cannot be read as JSON');

        JsonValue::readMembers(['a' => "\xff", 'b' => static fn (): int => 1]);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function refusedNames(): iterable
    {
        yield 'not UTF-8' => ["a\xff", 'A member name is not valid UTF-8'];
        yield 'a NUL byte first' => ["\0a", 'A member name starts with a NUL byte'];
    }

    #[DataProvider('refusedNames')]
    public function testRefusesAMemberNameJsonTextCannotHold(string $name, string $message): void
    {
        try {
            JsonValue::checkName($name, null);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::MalformedJson, $exception->reason);
            $this->assertNull($exception->member);
            $this->assertSame($message, $exception->getMessage());
        }

        foreach ([[$name => 1], (object) [$name => 1]] as $object) {
            try {
                JsonValue::readMembers($object);
                $this->fail('Expected InvalidJwk');
            } catch (InvalidJwk $exception) {
                $this->assertSame(InvalidJwkReason::MalformedJson, $exception->reason);
                $this->assertSame($message, $exception->getMessage());
            }
        }
    }

    public function testAcceptsANameWithANulByteAfterTheFirst(): void
    {
        $members = JsonValue::readMembers(["a\0" => 1, 'b' => ["b\0" => 2]]);

        $this->assertSame(1, $members["a\0"]);
        $this->assertInstanceOf(stdClass::class, $members['b']);
        $this->assertSame(["b\0" => 2], get_object_vars($members['b']));
    }

    /**
     * @return iterable<string, array{object}>
     */
    public static function objectsThatAreNotStdClass(): iterable
    {
        yield 'a subclass whose JSON form is NAN' => [
            new class extends stdClass implements JsonSerializable {
                public function jsonSerialize(): mixed
                {
                    return NAN;
                }
            },
        ];
        yield 'a subclass whose JSON form is a date' => [
            new class extends stdClass implements JsonSerializable {
                public function jsonSerialize(): mixed
                {
                    return new DateTimeImmutable('2020-01-01');
                }
            },
        ];
        yield 'a subclass with a private property' => [
            new class extends stdClass {
                public int $shown = 1;

                private string $hidden = 'hidden';

                public function hidden(): string
                {
                    return $this->hidden;
                }
            },
        ];
        yield 'an enum case' => [KeyUse::Signature];
    }

    #[DataProvider('objectsThatAreNotStdClass')]
    public function testRefusesAnObjectWhoseClassIsNotStdClass(object $object): void
    {
        foreach ([$object, [$object], (object) ['a' => $object]] as $value) {
            try {
                JsonValue::read('m', $value);
                $this->fail('Expected InvalidArgument');
            } catch (InvalidArgument $exception) {
                $this->assertSame(
                    sprintf(
                        'The "m" member holds a value of type %s, which cannot be read as JSON',
                        get_debug_type($object),
                    ),
                    $exception->getMessage(),
                );
            }
        }
    }

    public function testCopiesNumbersExactlyWhateverTheSerializePrecision(): void
    {
        $previous = ini_set('serialize_precision', '5');

        try {
            $value = JsonValue::read('m', [0.1234567890123, -0.0, ['a' => 1.0e300]]);
        } finally {
            ini_set('serialize_precision', $previous === false ? '-1' : $previous);
        }

        $this->assertIsArray($value);
        $this->assertSame(0.1234567890123, $value[0]);
        $this->assertSame(-0.0, $value[1]);
        $this->assertSame('-0', (string) $value[1]);
        $this->assertEquals([0.1234567890123, -0.0, (object) ['a' => 1.0e300]], $value);
    }

    public function testACopyIsIndependentOfTheValueAndOfItself(): void
    {
        $object = new stdClass();
        $object->list = [1, [2]];
        $copy = JsonValue::read('m', ['o' => $object]);
        $object->list[1][0] = 3;

        $this->assertInstanceOf(stdClass::class, $copy);
        $this->assertSame('{"o":{"list":[1,[2]]}}', json_encode($copy, JSON_THROW_ON_ERROR));
        $this->assertNotSame($object, $copy->o);
    }

    public function testRefusesAnObjectThatHoldsItself(): void
    {
        $object = new stdClass();
        $object->self = $object;

        try {
            JsonValue::read('m', $object);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::MalformedJson, $exception->reason);
        }
    }

    /**
     * @return iterable<string, array{array<array-key, mixed> | stdClass}>
     */
    public static function valuesThatAreNotObjects(): iterable
    {
        yield 'a PHP list' => [[1, 2]];
        yield 'an empty PHP array' => [[]];
    }

    /**
     * @param array<array-key, mixed> | stdClass $object
     */
    #[DataProvider('valuesThatAreNotObjects')]
    public function testReadMembersRefusesWhatIsNotAJsonObject(array | stdClass $object): void
    {
        try {
            JsonValue::readMembers($object);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::NotAnObject, $exception->reason);
            $this->assertNull($exception->member);
            $this->assertSame('The JSON value is not an object', $exception->getMessage());
        }
    }

    public function testReadMembersRefusesAStdClassSubclassAsACallersMistake(): void
    {
        $this->expectException(InvalidArgument::class);
        $this->expectExceptionMessageIsOrContains('A value of type stdClass@anonymous cannot be read as JSON');

        JsonValue::readMembers(new class extends stdClass {
            public string $kty = 'oct';
        });
    }

    public function testReadMembersReadsAnArrayThatIsNotAListAndAStdClass(): void
    {
        $this->assertSame(['1' => 'a', '0' => 'b'], JsonValue::readMembers([1 => 'a', 0 => 'b']));
        $this->assertSame(['0' => 'a', '1' => 'b'], JsonValue::readMembers((object) ['a', 'b']));
        $this->assertSame([], JsonValue::readMembers(new stdClass()));
    }
}
