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
     * @throws InvalidJwk when a member is empty, zero, or not minimal, or
     *     when the prime factor is 1
     */
    public function __construct(
        #[SensitiveParameter]
        public string $primeFactor,
        #[SensitiveParameter]
        public string $factorCrtExponent,
        #[SensitiveParameter]
        public string $factorCrtCoefficient,
    ) {
        ByteInteger::checkRsaMember('r', $primeFactor);
        ByteInteger::checkRsaMember('d', $factorCrtExponent);
        ByteInteger::checkRsaMember('t', $factorCrtCoefficient);

        if ($primeFactor === "\x01") {
            throw new InvalidJwk(
                InvalidJwkReason::InvalidValue,
                'The "r" member must be a prime, and 1 is not a prime',
                'r',
            );
        }
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
