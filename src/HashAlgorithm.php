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
 * The hash functions a thumbprint may use, backed by their names in the
 * IANA Named Information Hash Algorithm Registry, which RFC 9278 section 4
 * requires in a thumbprint URI
 *
 * SHA-256 is the one RFC 9278 section 5 requires an implementation to
 * have, and the default throughout the package.
 */
enum HashAlgorithm: string
{
    case Sha256 = 'sha-256';
    case Sha384 = 'sha-384';
    case Sha512 = 'sha-512';

    /**
     * Returns the name `hash()` knows the function by
     */
    public function hashName(): string
    {
        return match ($this) {
            self::Sha256 => 'sha256',
            self::Sha384 => 'sha384',
            self::Sha512 => 'sha512',
        };
    }

    /**
     * Returns the length of a digest in bytes
     */
    public function digestLength(): int
    {
        return match ($this) {
            self::Sha256 => 32,
            self::Sha384 => 48,
            self::Sha512 => 64,
        };
    }
}
