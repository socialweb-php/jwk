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
 * The registered values of the `key_ops` member, from RFC 7517 section 4.3
 *
 * The member is an open registry, so a key stores its operations as
 * strings; this enum names the eight registered values.
 */
enum KeyOperation: string
{
    case Sign = 'sign';
    case Verify = 'verify';
    case Encrypt = 'encrypt';
    case Decrypt = 'decrypt';
    case WrapKey = 'wrapKey';
    case UnwrapKey = 'unwrapKey';
    case DeriveKey = 'deriveKey';
    case DeriveBits = 'deriveBits';

    /**
     * Returns the registered `use` value this operation is consistent with
     */
    public function keyUse(): KeyUse
    {
        return match ($this) {
            self::Sign, self::Verify => KeyUse::Signature,
            default => KeyUse::Encryption,
        };
    }
}
