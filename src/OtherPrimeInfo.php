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

use JsonSerializable;
use LogicException;
use SensitiveParameter;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;

use function sprintf;

/**
 * One entry of the `oth` member of an RSA private key, per RFC 7518
 * section 6.3.2.7: a third or later prime factor with its CRT values
 */
final readonly class OtherPrimeInfo implements JsonSerializable
{
    /**
     * @param string $primeFactor The `r` member, as unsigned big-endian bytes
     * @param string $factorCrtExponent The `d` member
     * @param string $factorCrtCoefficient The `t` member
     *
     * @throws InvalidJwk naming the `oth` member when a member is empty,
     *     zero, or not minimal, or when the prime factor is 1; the message
     *     names the member of the entry
     */
    public function __construct(
        #[SensitiveParameter]
        public string $primeFactor,
        #[SensitiveParameter]
        public string $factorCrtExponent,
        #[SensitiveParameter]
        public string $factorCrtCoefficient,
    ) {
        self::checkMembers($primeFactor, $factorCrtExponent, $factorCrtCoefficient, 'an "oth" entry');
    }

    /**
     * Reads an entry of the `oth` member, naming its position in every
     * message, such as `The "d" member of entry 2 of "oth"`
     *
     * @internal
     *
     * @throws InvalidJwk naming the `oth` member, as the constructor does,
     *     or when a member is absent, is not a string, or is not base64url
     */
    public static function fromMembers(#[SensitiveParameter] MemberReader $members): self
    {
        $primeFactor = $members->requiredBytes('r');
        $factorCrtExponent = $members->requiredBytes('d');
        $factorCrtCoefficient = $members->requiredBytes('t');

        self::checkMembers(
            $primeFactor,
            $factorCrtExponent,
            $factorCrtCoefficient,
            $members->entry() ?? 'an "oth" entry',
        );

        return new self($primeFactor, $factorCrtExponent, $factorCrtCoefficient);
    }

    /**
     * @return array{r: string, d: string, t: string}
     */
    public function jsonSerialize(): array
    {
        return [
            'r' => Base64Url::encode($this->primeFactor),
            'd' => Base64Url::encode($this->factorCrtExponent),
            't' => Base64Url::encode($this->factorCrtCoefficient),
        ];
    }

    /**
     * Returns what `var_dump()` and `print_r()` show: every member
     * redacted, since every member is private
     *
     * @return array{r: string, d: string, t: string}
     */
    public function __debugInfo(): array
    {
        return ['r' => '[redacted]', 'd' => '[redacted]', 't' => '[redacted]'];
    }

    /**
     * Refuses PHP serialization, which would write private members to a
     * string the caller did not ask for; the JSON form of the key is the
     * serialization
     *
     * @return array{}
     */
    public function __serialize(): array
    {
        throw new LogicException('An "oth" entry cannot be serialized with serialize(); use the toJson() of its key');
    }

    /**
     * @param string $entry Which entry, as the messages name it
     *
     * @throws InvalidJwk
     */
    private static function checkMembers(
        #[SensitiveParameter] string $primeFactor,
        #[SensitiveParameter] string $factorCrtExponent,
        #[SensitiveParameter] string $factorCrtCoefficient,
        string $entry,
    ): void {
        ByteInteger::checkRsaMember('oth', $primeFactor, sprintf('"r" member of %s', $entry));
        ByteInteger::checkRsaMember('oth', $factorCrtExponent, sprintf('"d" member of %s', $entry));
        ByteInteger::checkRsaMember('oth', $factorCrtCoefficient, sprintf('"t" member of %s', $entry));

        if ($primeFactor === "\x01") {
            throw new InvalidJwk(
                InvalidJwkReason::InvalidValue,
                sprintf('The "r" member of %s must be a prime, and 1 is not a prime', $entry),
                'oth',
            );
        }
    }

    /**
     * Refuses PHP unserialization, which would build an entry without
     * checking its members
     *
     * @param array<array-key, mixed> $data
     */
    public function __unserialize(array $data): void
    {
        throw new LogicException('An "oth" entry cannot be unserialized with unserialize(); use Jwk::fromJson()');
    }
}
