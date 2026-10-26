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

use ArrayIterator;
use Countable;
use IteratorAggregate;
use JsonException;
use JsonSerializable;
use LogicException;
use SensitiveParameter;
use SocialWeb\Jwk\Exception\AmbiguousKeyId;
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Jwk\Exception\InvalidJwkSet;
use Traversable;
use stdClass;

use function array_is_list;
use function array_key_exists;
use function count;
use function get_object_vars;
use function hash_equals;
use function is_array;
use function is_object;
use function is_string;
use function json_decode;
use function json_encode;
use function sprintf;

use const JSON_PRESERVE_ZERO_FRACTION;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * A JWK Set, per RFC 7517 section 5: a JSON object whose `keys` member is
 * an array of JWKs
 *
 * A set is immutable. Parsing keeps every member it can use and sets the
 * rest aside with the reason, so that one unusable member does not make
 * the set unusable; a caller that wants strictness checks `skipped()`.
 * Members of the set object other than `keys` are kept as additional
 * members and written back.
 *
 * @implements IteratorAggregate<int, Jwk>
 */
final readonly class JwkSet implements Countable, IteratorAggregate, JsonSerializable
{
    /**
     * Every member of the set object other than `keys`, in the order
     * received, with each JSON object in a value as a `stdClass` and each
     * JSON array as a PHP list, as `json_decode()` gives them by default
     *
     * @var array<string, mixed>
     */
    private array $additionalMembers;

    /**
     * The members of the received `keys` array that could not be used
     *
     * @var list<SkippedKey>
     */
    private array $skipped;

    /**
     * @param list<Jwk> $keys The keys, in order
     * @param array<string, mixed> $additionalMembers Every member of the
     *     set object other than `keys`, as decoded JSON; a JSON object is a
     *     `stdClass` or a PHP array that is not a list, and a JSON array is
     *     a PHP list
     *
     * @throws InvalidJwkSet when the keys are not a list of `Jwk` objects,
     *     or when an additional member holds a value JSON text cannot hold,
     *     as `Jwk::fromJson()` refuses it; the refusal is the previous
     *     exception
     * @throws InvalidArgument when an additional member is named `keys`
     */
    public function __construct(
        private array $keys,
        array $additionalMembers = [],
    ) {
        if (!array_is_list($keys)) {
            throw new InvalidJwkSet('The keys must be a list of Jwk objects');
        }

        foreach ($keys as $key) {
            if (!$key instanceof Jwk) {
                throw new InvalidJwkSet('The keys must be a list of Jwk objects');
            }
        }

        $members = [];

        /** @var mixed $value */
        foreach ($additionalMembers as $name => $value) {
            $name = (string) $name;
            self::checkAdditionalMemberName($name);
            $members[$name] = self::readAdditionalMember($name, $value);
        }

        $this->additionalMembers = $members;
        $this->skipped = [];
    }

    /**
     * Parses a JWK Set from JSON text or from a value the text was already
     * decoded into
     *
     * A decoded value is an array or a tree of `stdClass` objects, as
     * `json_decode()` gives either. In an array, a PHP array that is a
     * list, including an empty array, is a JSON array, and any other PHP
     * array is a JSON object. PHP's parser keeps the lexically last of two
     * members with one name, which RFC 7517 section 5 allows.
     *
     * Each entry of `keys` is given to `Jwk::fromJson()` with the same
     * `$publicOnly`. One that is not an object, or that `fromJson()`
     * refuses, is set aside in `skipped()` with its position and the
     * refusal, and the rest of the set is usable.
     *
     * @param string | array<array-key, mixed> | stdClass $json
     *
     * @throws InvalidJwkSet when the text does not parse, the value is not
     *     an object, the object has no `keys` member, `keys` is not an
     *     array, or another member holds a value JSON text cannot hold
     */
    public static function fromJson(
        #[SensitiveParameter] string | array | stdClass $json,
        bool $publicOnly = false,
    ): self {
        if (is_string($json)) {
            try {
                /** @var mixed $json */
                $json = json_decode($json, false, flags: JSON_THROW_ON_ERROR);
            } catch (JsonException $exception) {
                throw new InvalidJwkSet('The JSON text does not parse: ' . $exception->getMessage());
            }
        }

        if (is_object($json) ? $json::class !== stdClass::class : (!is_array($json) || array_is_list($json))) {
            throw new InvalidJwkSet('The JSON value is not an object');
        }

        // A PHP array is cast to an object so that both forms are read the
        // same way; PHP gives the properties back with their names as keys.
        /** @var array<string, mixed> $members */
        $members = get_object_vars((object) $json);

        if (!array_key_exists('keys', $members)) {
            throw new InvalidJwkSet('The "keys" member is required');
        }

        /** @var mixed $entries */
        $entries = $members['keys'];
        unset($members['keys']);

        if (!is_array($entries) || !array_is_list($entries)) {
            throw new InvalidJwkSet('The "keys" member must be an array');
        }

        $keys = [];
        $skipped = [];

        /** @var mixed $entry */
        foreach ($entries as $index => $entry) {
            try {
                $keys[] = self::readKey($index, $entry, $publicOnly);
            } catch (InvalidJwk $exception) {
                $skipped[] = new SkippedKey($index, $exception);
            }
        }

        $set = new self($keys, $members);

        return clone($set, ['skipped' => $skipped]);
    }

    /**
     * Returns the keys, in the order received
     *
     * @return list<Jwk>
     */
    public function keys(): array
    {
        return $this->keys;
    }

    /**
     * Returns the members of the received `keys` array that `fromJson()`
     * could not use, each with its position and the refusal; a set built in
     * code has none
     *
     * @return list<SkippedKey>
     */
    public function skipped(): array
    {
        return $this->skipped;
    }

    /**
     * Returns the number of keys
     */
    public function count(): int
    {
        return count($this->keys);
    }

    /**
     * @return Traversable<int, Jwk>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->keys);
    }

    /**
     * Returns the key whose `kid` equals the identifier, or `null` when none
     * does
     *
     * The identifiers are compared as RFC 7515 section 5.3 compares strings,
     * by code points, which is PHP string equality on decoded JSON. RFC 7517
     * section 4.5 lets keys of different types share a `kid`; a caller that
     * passes the key type chooses among them.
     *
     * @throws AmbiguousKeyId when more than one key matches
     */
    public function findByKeyId(string $keyId, ?KeyType $keyType = null): ?Jwk
    {
        $matches = [];

        foreach ($this->keys as $key) {
            if ($key->keyId === $keyId && ($keyType === null || $key->keyType() === $keyType)) {
                $matches[] = $key;
            }
        }

        if (count($matches) > 1) {
            throw new AmbiguousKeyId(sprintf(
                '%d keys%s have the key identifier "%s"%s',
                count($matches),
                $keyType === null ? '' : ' of type ' . $keyType->value,
                $keyId,
                $keyType === null ? '; pass the key type to choose among them' : '',
            ));
        }

        return $matches[0] ?? null;
    }

    /**
     * Returns every key whose `kid` equals the identifier, in the order
     * received
     *
     * @return list<Jwk>
     */
    public function findAllByKeyId(string $keyId): array
    {
        $matches = [];

        foreach ($this->keys as $key) {
            if ($key->keyId === $keyId) {
                $matches[] = $key;
            }
        }

        return $matches;
    }

    /**
     * Returns the first key whose RFC 7638 thumbprint under the hash equals
     * the thumbprint, compared in constant time, or `null` when none does
     */
    public function findByThumbprint(string $thumbprint, HashAlgorithm $hash = HashAlgorithm::Sha256): ?Jwk
    {
        foreach ($this->keys as $key) {
            if (hash_equals($key->thumbprint($hash), $thumbprint)) {
                return $key;
            }
        }

        return null;
    }

    /**
     * Returns the set with the key appended
     */
    public function withKey(Jwk $key): self
    {
        return clone($this, ['keys' => [...$this->keys, $key]]);
    }

    /**
     * Returns the set without the key, which is the instance `keys()` or a
     * lookup returned, or an equal set when it holds no such instance
     */
    public function withoutKey(Jwk $key): self
    {
        $keys = [];

        foreach ($this->keys as $member) {
            if ($member !== $key) {
                $keys[] = $member;
            }
        }

        return clone($this, ['keys' => $keys]);
    }

    /**
     * Returns every member of the set object other than `keys`, in the
     * order received
     *
     * Each JSON object in a value is a `stdClass` and each JSON array a PHP
     * list, as `json_decode()` gives them by default. The members are a
     * copy: changing them, or an object inside them, does not change the
     * set.
     *
     * @return array<string, mixed>
     */
    public function additionalMembers(): array
    {
        $members = [];

        /** @var mixed $value */
        foreach ($this->additionalMembers as $name => $value) {
            $name = (string) $name;
            $members[$name] = JsonValue::read($name, $value);
        }

        return $members;
    }

    /**
     * Returns the set as RFC 7517 writes it: `keys`, then the additional
     * members as received
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $keys = [];

        foreach ($this->keys as $key) {
            $keys[] = $key->jsonSerialize();
        }

        $json = ['keys' => $keys];

        /** @var mixed $value */
        foreach ($this->additionalMembers() as $name => $value) {
            $json[$name] = $value;
        }

        return $json;
    }

    /**
     * Returns the set as JSON text
     *
     * Every set the package accepts can be written: its keys can be, and
     * its additional members are checked as a key's are.
     */
    public function toJson(): string
    {
        return json_encode($this, JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
    }

    /**
     * Refuses PHP serialization, which would write the private members of
     * the keys to a string the caller did not ask for; the JSON form is the
     * serialization
     *
     * @return array{}
     */
    public function __serialize(): array
    {
        throw new LogicException('A JWK Set cannot be serialized with serialize(); use toJson()');
    }

    /**
     * Refuses PHP unserialization, which would build a set without checking
     * its keys; `fromJson()` is the way back from the JSON form
     *
     * @param array<array-key, mixed> $data
     */
    public function __unserialize(array $data): void
    {
        throw new LogicException('A JWK Set cannot be unserialized with unserialize(); use JwkSet::fromJson()');
    }

    /**
     * Reads one entry of the `keys` array
     *
     * @throws InvalidJwk with `NotAnObject` when the entry is not a JSON
     *     object, or as `Jwk::fromJson()` does
     */
    private static function readKey(int $index, #[SensitiveParameter] mixed $entry, bool $publicOnly): Jwk
    {
        if (!is_array($entry) && !$entry instanceof stdClass) {
            throw new InvalidJwk(
                InvalidJwkReason::NotAnObject,
                sprintf('The "keys" member holds a value that is not an object at index %d', $index),
            );
        }

        return Jwk::fromJson($entry, $publicOnly);
    }

    /**
     * @throws InvalidArgument when the name is `keys`
     * @throws InvalidJwkSet for a name that JSON text cannot hold
     */
    private static function checkAdditionalMemberName(string $name): void
    {
        if ($name === 'keys') {
            throw new InvalidArgument('The "keys" member holds the keys and is not an additional member');
        }

        try {
            JsonValue::checkName($name, null);
        } catch (InvalidJwk $exception) {
            throw new InvalidJwkSet($exception->getMessage(), 0, $exception);
        }
    }

    /**
     * @throws InvalidJwkSet when the value is one JSON text cannot hold
     */
    private static function readAdditionalMember(string $name, #[SensitiveParameter] mixed $value): mixed
    {
        try {
            return JsonValue::read($name, $value);
        } catch (InvalidJwk $exception) {
            throw new InvalidJwkSet($exception->getMessage(), 0, $exception);
        }
    }
}
