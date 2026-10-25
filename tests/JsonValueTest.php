<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\JsonValue;
use stdClass;

use function fclose;
use function fopen;
use function get_object_vars;
use function json_encode;

use const INF;
use const JSON_PRESERVE_ZERO_FRACTION;
use const JSON_THROW_ON_ERROR;
use const NAN;

class JsonValueTest extends TestCase
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
            $this->assertNull($exception->member);
        }
    }

    /**
     * @return iterable<string, array{mixed, InvalidJwkReason, string}>
     */
    public static function refusedValueProvider(): iterable
    {
        yield 'a string that is not UTF-8' => [
            "\xff",
            InvalidJwkReason::InvalidValue,
            'The "m" member holds a string that is not valid UTF-8',
        ];
        yield 'a nested string that is not UTF-8' => [
            ['a' => ['ok', "\xc3"]],
            InvalidJwkReason::InvalidValue,
            'The "m" member holds a string that is not valid UTF-8',
        ];
        yield 'infinity' => [INF, InvalidJwkReason::InvalidValue, 'The "m" member holds a number that is not finite'];
        yield 'negative infinity' => [
            [-INF],
            InvalidJwkReason::InvalidValue,
            'The "m" member holds a number that is not finite',
        ];
        yield 'not a number' => [
            (object) ['a' => NAN],
            InvalidJwkReason::InvalidValue,
            'The "m" member holds a number that is not finite',
        ];
        yield 'an object other than stdClass' => [
            new DateTimeImmutable(),
            InvalidJwkReason::WrongType,
            'The "m" member holds a value that is not a JSON value: DateTimeImmutable',
        ];
        yield 'a closure in a list' => [
            [static fn (): int => 1],
            InvalidJwkReason::WrongType,
            'The "m" member holds a value that is not a JSON value: Closure',
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

    #[DataProvider('refusedValueProvider')]
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

    public function testRefusesAResource(): void
    {
        $resource = fopen('php://memory', 'r');

        try {
            JsonValue::read('m', ['a' => $resource]);
            $this->fail('Expected InvalidJwk');
        } catch (InvalidJwk $exception) {
            $this->assertSame(InvalidJwkReason::WrongType, $exception->reason);
            $this->assertSame(
                'The "m" member holds a value that is not a JSON value: resource (stream)',
                $exception->getMessage(),
            );
        } finally {
            if ($resource !== false) {
                fclose($resource);
            }
        }
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function refusedNameProvider(): iterable
    {
        yield 'not UTF-8' => ["a\xff", 'A member name is not valid UTF-8'];
        yield 'a NUL byte first' => ["\0a", 'A member name starts with a NUL byte'];
    }

    #[DataProvider('refusedNameProvider')]
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
}
