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

use JsonException;
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;

use function array_is_list;
use function array_key_exists;
use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use function sprintf;

use const JSON_THROW_ON_ERROR;

/**
 * Reads the members of a decoded JSON object by name and type, refusing
 * each the way RFC 7517 does
 *
 * The reader knows nothing of key types. It turns JSON text or a decoded
 * array into named members, checks that each member asked for has the
 * JSON type the caller expects, and decodes the byte-string members from
 * base64url. The key classes decide which members are required and what
 * their values must be.
 *
 * @internal
 */
final class MemberReader
{
    /**
     * @param array<string, mixed> $members
     */
    private function __construct(private readonly array $members)
    {
    }

    /**
     * Reads a JSON object from JSON text or from an array that JSON text was
     * already decoded into
     *
     * PHP's parser keeps the lexically last of two members with one name,
     * which is one of the two behaviors RFC 7517 section 4 allows.
     *
     * @param string | array<array-key, mixed> $json
     *
     * @throws InvalidJwk with `MalformedJson` when the text does not parse,
     *     or with `NotAnObject` when the value is not a JSON object
     */
    public static function fromJson(string | array $json): self
    {
        if (is_string($json)) {
            try {
                /** @var mixed $json */
                $json = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
            } catch (JsonException $exception) {
                throw new InvalidJwk(
                    InvalidJwkReason::MalformedJson,
                    'The JSON text does not parse: ' . $exception->getMessage(),
                    null,
                    $exception,
                );
            }
        }

        if (!is_array($json) || ($json !== [] && array_is_list($json))) {
            throw new InvalidJwk(InvalidJwkReason::NotAnObject, 'The JSON value is not an object');
        }

        $members = [];

        /** @var mixed $value */
        foreach ($json as $name => $value) {
            $members[(string) $name] = $value;
        }

        return new self($members);
    }

    /**
     * Returns whether the object has the member
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->members);
    }

    /**
     * Returns the member as a string, or `null` when it is absent
     *
     * @throws InvalidJwk with `WrongType` when the member is not a string
     */
    public function string(string $name): ?string
    {
        if (!$this->has($name)) {
            return null;
        }

        $value = $this->members[$name];

        if (!is_string($value)) {
            throw new InvalidJwk(
                InvalidJwkReason::WrongType,
                sprintf('The "%s" member must be a string', $name),
                $name,
            );
        }

        return $value;
    }

    /**
     * Returns the member as a string
     *
     * @throws InvalidJwk with `MissingMember` when the member is absent, or
     *     with `WrongType` when it is not a string
     */
    public function requiredString(string $name): string
    {
        return $this->string($name) ?? throw new InvalidJwk(
            InvalidJwkReason::MissingMember,
            sprintf('The "%s" member is required', $name),
            $name,
        );
    }

    /**
     * Returns the bytes a base64url member encodes, or `null` when the
     * member is absent
     *
     * @throws InvalidJwk with `WrongType` when the member is not a string,
     *     or with `InvalidBase64Url` when it is not base64url without
     *     padding
     */
    public function bytes(string $name): ?string
    {
        $text = $this->string($name);

        if ($text === null) {
            return null;
        }

        try {
            return Base64Url::decode($text);
        } catch (InvalidArgument $exception) {
            throw new InvalidJwk(
                InvalidJwkReason::InvalidBase64Url,
                sprintf('The "%s" member is not base64url without padding: %s', $name, $exception->getMessage()),
                $name,
                $exception,
            );
        }
    }

    /**
     * Returns the bytes a base64url member encodes
     *
     * @throws InvalidJwk with `MissingMember` when the member is absent, and
     *     otherwise as `bytes()` does
     */
    public function requiredBytes(string $name): string
    {
        return $this->bytes($name) ?? throw new InvalidJwk(
            InvalidJwkReason::MissingMember,
            sprintf('The "%s" member is required', $name),
            $name,
        );
    }

    /**
     * Returns the member as a list of strings, or an empty list when it is
     * absent
     *
     * @return list<string>
     *
     * @throws InvalidJwk with `WrongType` when the member is not an array
     *     of strings
     */
    public function stringList(string $name): array
    {
        if (!$this->has($name)) {
            return [];
        }

        $value = $this->members[$name];

        if (!is_array($value) || !array_is_list($value)) {
            throw new InvalidJwk(
                InvalidJwkReason::WrongType,
                sprintf('The "%s" member must be an array', $name),
                $name,
            );
        }

        $strings = [];

        /** @var mixed $entry */
        foreach ($value as $entry) {
            if (!is_string($entry)) {
                throw new InvalidJwk(
                    InvalidJwkReason::WrongType,
                    sprintf('Every entry of the "%s" member must be a string', $name),
                    $name,
                );
            }

            $strings[] = $entry;
        }

        return $strings;
    }

    /**
     * Returns the member as a list of objects, each as a reader, or an
     * empty list when it is absent
     *
     * @return list<self>
     *
     * @throws InvalidJwk with `WrongType` when the member is not an array
     *     of objects
     */
    public function objectList(string $name): array
    {
        if (!$this->has($name)) {
            return [];
        }

        $value = $this->members[$name];

        if (!is_array($value) || !array_is_list($value)) {
            throw new InvalidJwk(
                InvalidJwkReason::WrongType,
                sprintf('The "%s" member must be an array', $name),
                $name,
            );
        }

        $readers = [];

        /** @var mixed $entry */
        foreach ($value as $entry) {
            if (!is_array($entry) || ($entry !== [] && array_is_list($entry))) {
                throw new InvalidJwk(
                    InvalidJwkReason::WrongType,
                    sprintf('Every entry of the "%s" member must be an object', $name),
                    $name,
                );
            }

            $readers[] = self::fromJson($entry);
        }

        return $readers;
    }

    /**
     * Returns every member whose name is not in the list, in the order
     * received
     *
     * @param list<string> $names
     *
     * @return array<string, mixed>
     */
    public function except(array $names): array
    {
        $remaining = [];

        /** @var mixed $value */
        foreach ($this->members as $name => $value) {
            if (!in_array($name, $names, true)) {
                $remaining[$name] = $value;
            }
        }

        return $remaining;
    }
}
