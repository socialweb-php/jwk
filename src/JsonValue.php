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
use stdClass;

use function get_object_vars;
use function is_array;
use function json_decode;
use function json_encode;

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
 * @internal
 */
final class JsonValue
{
    /**
     * Returns the members of a JSON object, each value read as `read()`
     * reads it
     *
     * @param array<array-key, mixed> | stdClass $object
     *
     * @return array<string, mixed>
     */
    public static function readMembers(#[SensitiveParameter] array | stdClass $object): array
    {
        $members = [];

        /** @var mixed $value */
        foreach ($object instanceof stdClass ? get_object_vars($object) : $object as $name => $value) {
            $name = (string) $name;
            $members[$name] = self::read($name, $value);
        }

        return $members;
    }

    /**
     * Returns the value of a member in the package's form
     *
     * The value is copied by encoding and decoding it, which builds the
     * form `json_decode()` gives without a PHP call for each level of
     * nesting.
     *
     * @param string $member The name of the member that holds the value
     */
    public static function read(string $member, #[SensitiveParameter] mixed $value): mixed
    {
        if (!is_array($value) && !$value instanceof stdClass) {
            return $value;
        }

        return json_decode(json_encode($value, JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR));
    }
}
