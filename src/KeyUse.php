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
 * The registered values of the `use` member, from RFC 7517 section 4.2
 *
 * The member is an open registry, so a key stores it as a string; this
 * enum names the two registered values and the operations each one is
 * consistent with.
 */
enum KeyUse: string
{
    case Signature = 'sig';
    case Encryption = 'enc';

    /**
     * Returns the registered operations that are consistent with this use
     *
     * RFC 7517 section 4.3 requires `use` and `key_ops` to agree without
     * saying how; this is the mapping of the Web Cryptography API the
     * section cites, where key wrapping and key agreement are kinds of
     * encryption, as section 4.2 says.
     *
     * @return non-empty-list<KeyOperation>
     */
    public function operations(): array
    {
        return match ($this) {
            self::Signature => [KeyOperation::Sign, KeyOperation::Verify],
            self::Encryption => [
                KeyOperation::Encrypt,
                KeyOperation::Decrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
                KeyOperation::DeriveKey,
                KeyOperation::DeriveBits,
            ],
        };
    }
}
