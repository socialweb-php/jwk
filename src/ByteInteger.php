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

use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;

use function array_fill;
use function intdiv;
use function ltrim;
use function ord;
use function pack;
use function sprintf;
use function strlen;

/**
 * Unsigned integers as big-endian byte strings, which is how RFC 7518
 * section 2 has a JWK hold them and how OpenSSL reports them
 *
 * PHP has no integer of this size, and the package takes no dependency
 * for one, so the two operations the package needs are written here: the
 * minimality test of a Base64urlUInt and the multiplication that checks an
 * RSA modulus against its primes.
 *
 * @internal
 */
final class ByteInteger
{
    /**
     * Returns whether the bytes are the minimal representation of their
     * value: no leading zero byte, except that zero itself is the single
     * byte `0x00`
     */
    public static function isMinimal(string $bytes): bool
    {
        return $bytes === "\0" || ($bytes !== '' && $bytes[0] !== "\0");
    }

    /**
     * Returns whether the bytes represent zero
     */
    public static function isZero(string $bytes): bool
    {
        return ltrim($bytes, "\0") === '';
    }

    /**
     * Checks that the bytes are a Base64urlUInt an RSA member may hold:
     * present, minimal, and not zero
     *
     * @throws InvalidJwk with `InvalidValue` for an empty or zero value, or
     *     with `NonMinimalInteger` for a leading zero byte
     */
    public static function checkRsaMember(string $member, string $bytes): void
    {
        if ($bytes === '') {
            throw new InvalidJwk(
                InvalidJwkReason::InvalidValue,
                sprintf('The "%s" member must not be empty', $member),
                $member,
            );
        }

        if (!self::isMinimal($bytes)) {
            throw new InvalidJwk(
                InvalidJwkReason::NonMinimalInteger,
                sprintf('The "%s" member has a leading zero byte, so it is not a minimal Base64urlUInt', $member),
                $member,
            );
        }

        if (self::isZero($bytes)) {
            throw new InvalidJwk(
                InvalidJwkReason::InvalidValue,
                sprintf('The "%s" member must not be zero', $member),
                $member,
            );
        }
    }

    /**
     * Returns the product of two unsigned integers, in minimal form
     */
    public static function multiply(string $a, string $b): string
    {
        $lengthA = strlen($a);
        $lengthB = strlen($b);
        $product = array_fill(0, $lengthA + $lengthB, 0);

        for ($i = $lengthA - 1; $i >= 0; $i--) {
            $carry = 0;

            for ($j = $lengthB - 1; $j >= 0; $j--) {
                $sum = $product[$i + $j + 1] + ord($a[$i]) * ord($b[$j]) + $carry;
                $product[$i + $j + 1] = $sum % 256;
                $carry = intdiv($sum, 256);
            }

            $product[$i] = $carry;
        }

        return self::minimal(pack('C*', ...$product));
    }

    /**
     * Returns the product of a list of unsigned integers, in minimal form
     *
     * @param non-empty-list<string> $factors
     */
    public static function product(array $factors): string
    {
        $product = "\x01";

        foreach ($factors as $factor) {
            $product = self::multiply($product, $factor);
        }

        return $product;
    }

    /**
     * Returns the bytes without their leading zero bytes, keeping one byte
     * for zero
     */
    public static function minimal(string $bytes): string
    {
        $trimmed = ltrim($bytes, "\0");

        return $trimmed === '' ? "\0" : $trimmed;
    }
}
