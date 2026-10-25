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

/**
 * The key types the package implements, backed by their `kty` values
 *
 * `RSA`, `EC`, and `oct` are registered by RFC 7518 section 6.1 and `OKP`
 * by RFC 8037 section 2.
 */
enum KeyType: string
{
    case Rsa = 'RSA';
    case Ec = 'EC';
    case Okp = 'OKP';
    case Oct = 'oct';

    /**
     * Returns the names of the members that make a key of this type private
     *
     * For `oct`, the key value itself, since a symmetric key is never
     * public.
     *
     * @return non-empty-list<string>
     */
    public function privateMemberNames(): array
    {
        return match ($this) {
            self::Rsa => ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'],
            self::Ec, self::Okp => ['d'],
            self::Oct => ['k'],
        };
    }
}
