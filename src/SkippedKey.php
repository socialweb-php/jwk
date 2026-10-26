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

use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;

/**
 * A member of a JWK Set that `JwkSet::fromJson()` set aside, as RFC 7517
 * section 5 says to ignore a key an implementation cannot use
 *
 * The index is the member's position in the `keys` array as received,
 * counted from zero, and the cause is the refusal, whose reason and member
 * say why.
 */
final readonly class SkippedKey
{
    /**
     * @param int $index The position in the `keys` array, counted from zero
     * @param InvalidJwk $cause Why the member was not used
     *
     * @throws InvalidArgument for a negative index
     */
    public function __construct(
        public int $index,
        public InvalidJwk $cause,
    ) {
        if ($index < 0) {
            throw new InvalidArgument('The index is a position in the "keys" array and cannot be negative');
        }
    }
}
