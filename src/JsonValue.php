<?php

/**
 * This file is part of socialweb/jwk
 *
 * socialweb/jwk is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * socialweb/jwk is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with socialweb/jwk. If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

declare(strict_types=1);

namespace SocialWeb\Jwk;

use SensitiveParameter;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use stdClass;

use function array_pop;
use function get_debug_type;
use function get_object_vars;
use function is_array;
use function is_finite;
use function is_float;
use function is_int;
use function is_string;
use function json_decode;
use function json_encode;
use function preg_match;
use function sprintf;
use function str_starts_with;

use const JSON_PRESERVE_ZERO_FRACTION;
use const JSON_THROW_ON_ERROR;

/**
 * Reads a JSON value into the form the package keeps it in
 *
 * The form is what `json_decode()` gives by default: a JSON object as a
 * `stdClass`, a JSON array as a PHP list, and a scalar as a PHP scalar. A
 * PHP array that is a list, including an empty array, is read as a JSON
 * array, and any other PHP array as a JSON object. Reading always builds a
 * new value, so a key never shares an object with its caller.
 *
 * Reading refuses what JSON cannot hold, so that every key the package
 * accepts can be written as JSON text: a string or a member name that is
 * not valid UTF-8, a member name that starts with a NUL byte, which PHP
 * does not keep as a property name, a number that is not finite, a value
 * of a PHP type that is not a JSON type, and nesting deeper than
 * `json_decode()` reads.
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
    private const int MAX_DEPTH = 511;

    /**
     * Returns the members of a JSON object, each value read as `read()`
     * reads it
     *
     * @param array<array-key, mixed> | stdClass $object
     *
     * @return array<string, mixed>
     *
     * @throws InvalidJwk as `checkName()` and `read()` do
     */
    public static function readMembers(#[SensitiveParameter] array | stdClass $object): array
    {
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
     * Returns the value of a member in the package's form
     *
     * The value is copied by encoding and decoding it, which builds the
     * form `json_decode()` gives without a PHP call for each level of
     * nesting. A scalar comes back as it was.
     *
     * @param string $member The name of the member that holds the value
     *
     * @throws InvalidJwk as `check()` does
     */
    public static function read(string $member, #[SensitiveParameter] mixed $value): mixed
    {
        self::check($member, $value);

        return json_decode(json_encode($value, JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR));
    }

    /**
     * Checks that the value of a member is a JSON value that JSON text can
     * hold, one container at a time, without a PHP call for each level of
     * nesting
     *
     * The value is a member of a JWK, so its outermost container is at
     * depth 2.
     *
     * @param string $member The name of the member that holds the value,
     *     which every refusal names
     *
     * @throws InvalidJwk with `InvalidValue` for a string that is not valid
     *     UTF-8 or a number that is not finite; with `WrongType` for a
     *     value of a PHP type that is not a JSON type; or with
     *     `MalformedJson` for a member name that `checkName()` refuses or
     *     for objects and arrays nested deeper than `json_decode()` reads
     *     JSON text
     */
    public static function check(string $member, #[SensitiveParameter] mixed $value): void
    {
        /** @var list<array{mixed, int}> $pending */
        $pending = [[$value, 1]];

        while (($next = array_pop($pending)) !== null) {
            [$current, $depth] = $next;

            if ($current instanceof stdClass) {
                $current = get_object_vars($current);
            }

            if (is_array($current)) {
                if ($depth >= self::MAX_DEPTH) {
                    throw new InvalidJwk(
                        InvalidJwkReason::MalformedJson,
                        'The JSON text does not parse: Maximum stack depth exceeded',
                    );
                }

                /** @var mixed $entry */
                foreach ($current as $name => $entry) {
                    if (is_string($name)) {
                        self::checkName($name, $member);
                    }

                    $pending[] = [$entry, $depth + 1];
                }

                continue;
            }

            self::checkScalar($member, $current);
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
     * @throws InvalidJwk
     */
    private static function checkScalar(string $member, #[SensitiveParameter] mixed $value): void
    {
        if (is_string($value)) {
            if (preg_match('//u', $value) !== 1) {
                throw new InvalidJwk(
                    InvalidJwkReason::InvalidValue,
                    sprintf('The "%s" member holds a string that is not valid UTF-8', $member),
                    $member,
                );
            }

            return;
        }

        if (is_float($value)) {
            if (!is_finite($value)) {
                throw new InvalidJwk(
                    InvalidJwkReason::InvalidValue,
                    sprintf('The "%s" member holds a number that is not finite', $member),
                    $member,
                );
            }

            return;
        }

        if ($value !== null && $value !== true && $value !== false && !is_int($value)) {
            throw new InvalidJwk(
                InvalidJwkReason::WrongType,
                sprintf('The "%s" member holds a value that is not a JSON value: %s', $member, get_debug_type($value)),
                $member,
            );
        }
    }
}
