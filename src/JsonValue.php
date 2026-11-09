<?php

/**
 * This file is part of socialweb/jwk
 *
 * Copyright © socialweb/jwk Contributors
 *
 * socialweb/jwk is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * socialweb/jwk is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with socialweb/jwk. If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

declare(strict_types=1);

namespace SocialWeb\Jwk;

use SensitiveParameter;
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use stdClass;

use function array_is_list;
use function array_pop;
use function get_debug_type;
use function get_object_vars;
use function is_array;
use function is_finite;
use function is_float;
use function is_int;
use function is_scalar;
use function is_string;
use function preg_match;
use function sprintf;
use function str_starts_with;

/**
 * Reads a JSON value into the form the package keeps it in
 *
 * The form is what `json_decode()` gives by default: a JSON object as a
 * `stdClass`, a JSON array as a PHP list, and a scalar as a PHP scalar. A
 * PHP array that is a list, including an empty array, is read as a JSON
 * array, and any other PHP array as a JSON object. An object is a JSON
 * object only when its class is `stdClass` itself, not a subclass. Reading
 * always builds a new value, so a key never shares an object with its
 * caller.
 *
 * Reading refuses what JSON cannot hold, so that every key the package
 * accepts can be written as JSON text. A value of a PHP type that is not a
 * JSON type, such as an object of a class other than `stdClass`, a
 * closure, or a resource, is the caller's mistake and is refused as
 * `InvalidArgument` before any member is read. A value of a JSON type
 * whose content JSON text cannot express is a malformed document and is
 * refused as `InvalidJwk` with `MalformedJson`: a string or a member name
 * that is not valid UTF-8, a member name that starts with a NUL byte, which
 * PHP does not keep as a property name, a number that is not finite, and
 * nesting deeper than `json_decode()` reads.
 *
 * @internal
 */
final class JsonValue
{
    /**
     * The deepest nesting of objects and arrays that `json_decode()` reads
     * at its default depth of 512, which counts the values inside the
     * innermost container as one more level
     */
    public const int MAX_DEPTH = 511;

    /**
     * Returns the members of a JSON object, each value read as `read()`
     * reads it
     *
     * @param array<array-key, mixed> | stdClass $object
     *
     * @return array<string, mixed>
     *
     * @throws InvalidArgument as `checkTypes()` does, before any member is
     *     read
     * @throws InvalidJwk with `NotAnObject` for a PHP list, which is a JSON
     *     array; otherwise as `checkName()` and `read()` do
     */
    public static function readMembers(#[SensitiveParameter] array | stdClass $object): array
    {
        self::checkTypes($object);

        if (is_array($object) && array_is_list($object)) {
            throw new InvalidJwk(InvalidJwkReason::NotAnObject, 'The JSON value is not an object');
        }

        $members = [];

        /** @var mixed $value */
        foreach ($object instanceof stdClass ? get_object_vars($object) : $object as $name => $value) {
            $name = (string) $name;
            self::checkName($name, null);
            $members[$name] = self::read($name, $value);
        }

        return $members;
    }

    /**
     * Returns a copy of the value of a member in the package's form,
     * checking it as it goes
     *
     * The value is walked one container at a time, without a PHP call for
     * each level of nesting. The value is a member of a JWK, which is
     * depth 1, so the value's outermost container is at depth 2.
     *
     * @param string $member The name of the member that holds the value,
     *     which every refusal names
     *
     * @throws InvalidArgument for a value of a PHP type that is not a JSON
     *     type, including an object whose class is not `stdClass`
     * @throws InvalidJwk with `MalformedJson`, naming the member, for a
     *     string that is not valid UTF-8, a number that is not finite, a
     *     member name that `checkName()` refuses, or objects and arrays
     *     nested deeper than `json_decode()` reads JSON text
     */
    public static function read(string $member, #[SensitiveParameter] mixed $value): mixed
    {
        $copy = null;
        $pending = [[$value, 2, &$copy]];

        while (($next = array_pop($pending)) !== null) {
            [$current, $depth] = $next;
            $target = &$next[2];

            if (is_array($current) && array_is_list($current)) {
                self::checkDepth($depth, $member);
                $target = [];

                /** @var mixed $entry */
                foreach ($current as $index => $entry) {
                    $target[$index] = null;
                    $pending[] = [$entry, $depth + 1, &$target[$index]];
                }
            } elseif (is_array($current) || ($current instanceof stdClass && $current::class === stdClass::class)) {
                self::checkDepth($depth, $member);
                $object = new stdClass();
                $target = $object;

                /** @var mixed $entry */
                foreach (is_array($current) ? $current : get_object_vars($current) as $name => $entry) {
                    self::checkName((string) $name, $member);
                    $object->{$name} = null;
                    $pending[] = [$entry, $depth + 1, &$object->{$name}];
                }
            } else {
                self::checkScalar($member, $current);
                $target = $current;
            }

            unset($target);
        }

        return $copy;
    }

    /**
     * Checks that the value of a member is a JSON value that JSON text can
     * hold, as `read()` does
     *
     * @throws InvalidArgument as `read()` does
     * @throws InvalidJwk as `read()` does
     */
    public static function check(string $member, #[SensitiveParameter] mixed $value): void
    {
        self::read($member, $value);
    }

    /**
     * Checks that every value in a tree has a PHP type JSON can hold, before
     * any of it is read, so that a caller's mistake is reported as one and
     * not as a fault of the document
     *
     * The JSON types are `null`, booleans, integers, floats, strings, PHP
     * arrays, and `stdClass` objects whose class is `stdClass` itself.
     * Nesting deeper than `json_decode()` reads is not walked; `read()`
     * refuses it.
     *
     * @throws InvalidArgument naming the type of the first value found
     *     whose PHP type is not a JSON type
     */
    public static function checkTypes(#[SensitiveParameter] mixed $value): void
    {
        $pending = [[$value, 1]];

        while (($next = array_pop($pending)) !== null) {
            [$current, $depth] = $next;

            if (is_array($current) || ($current instanceof stdClass && $current::class === stdClass::class)) {
                if ($depth > self::MAX_DEPTH) {
                    continue;
                }

                /** @var mixed $entry */
                foreach (is_array($current) ? $current : get_object_vars($current) as $entry) {
                    $pending[] = [$entry, $depth + 1];
                }
            } elseif ($current !== null && !is_scalar($current)) {
                throw new InvalidArgument(
                    sprintf('A value of type %s cannot be read as JSON', get_debug_type($current)),
                );
            }
        }
    }

    /**
     * Checks a member name, of the JWK when `$member` is `null` or of an
     * object inside that member
     *
     * @throws InvalidJwk with `MalformedJson` for a name that starts with a
     *     NUL byte or is not valid UTF-8
     */
    public static function checkName(string $name, ?string $member): void
    {
        $where = $member === null ? '' : sprintf(' in the "%s" member', $member);

        if (str_starts_with($name, "\0")) {
            throw new InvalidJwk(
                InvalidJwkReason::MalformedJson,
                sprintf('A member name%s starts with a NUL byte', $where),
                $member,
            );
        }

        if (preg_match('//u', $name) !== 1) {
            throw new InvalidJwk(
                InvalidJwkReason::MalformedJson,
                sprintf('A member name%s is not valid UTF-8', $where),
                $member,
            );
        }
    }

    /**
     * Checks the depth of an object or array in a value that did not come
     * from JSON text; `json_decode()` has already refused text nested this
     * deep, with its own message
     *
     * @param int $depth The depth of an object or array, the JWK itself
     *     being depth 1
     *
     * @throws InvalidJwk with `MalformedJson` naming the member
     */
    private static function checkDepth(int $depth, string $member): void
    {
        if ($depth > self::MAX_DEPTH) {
            throw new InvalidJwk(
                InvalidJwkReason::MalformedJson,
                sprintf('The "%s" member is nested deeper than the 512 levels JSON text allows', $member),
                $member,
            );
        }
    }

    /**
     * @throws InvalidArgument for a value of a PHP type that is not a JSON
     *     type
     * @throws InvalidJwk with `MalformedJson` for a string that is not
     *     valid UTF-8 or a number that is not finite
     */
    private static function checkScalar(string $member, #[SensitiveParameter] mixed $value): void
    {
        if (is_string($value)) {
            if (preg_match('//u', $value) !== 1) {
                throw new InvalidJwk(
                    InvalidJwkReason::MalformedJson,
                    sprintf('The "%s" member holds a string that is not valid UTF-8', $member),
                    $member,
                );
            }

            return;
        }

        if (is_float($value)) {
            if (!is_finite($value)) {
                throw new InvalidJwk(
                    InvalidJwkReason::MalformedJson,
                    sprintf('The "%s" member holds a number that is not finite', $member),
                    $member,
                );
            }

            return;
        }

        if ($value !== null && $value !== true && $value !== false && !is_int($value)) {
            throw new InvalidArgument(sprintf(
                'The "%s" member holds a value of type %s, which cannot be read as JSON',
                $member,
                get_debug_type($value),
            ));
        }
    }
}
