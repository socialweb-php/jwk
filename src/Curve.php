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

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_ED25519;
use const OPENSSL_KEYTYPE_ED448;
use const OPENSSL_KEYTYPE_X25519;
use const OPENSSL_KEYTYPE_X448;

/**
 * The curves the package implements, backed by their `crv` values
 *
 * The first four are `EC` curves: P-256, P-384, and P-521 from RFC 7518
 * section 6.2.1.1 and secp256k1 from RFC 8812 section 3.1. The last four
 * are `OKP` curves from RFC 8037 section 3: the Edwards curves sign and
 * the Montgomery curves agree on keys.
 */
enum Curve: string
{
    case P256 = 'P-256';
    case P384 = 'P-384';
    case P521 = 'P-521';
    case Secp256k1 = 'secp256k1';
    case Ed25519 = 'Ed25519';
    case Ed448 = 'Ed448';
    case X25519 = 'X25519';
    case X448 = 'X448';

    /**
     * Returns the key type whose `crv` member names this curve
     */
    public function keyType(): KeyType
    {
        return match ($this) {
            self::P256, self::P384, self::P521, self::Secp256k1 => KeyType::Ec,
            self::Ed25519, self::Ed448, self::X25519, self::X448 => KeyType::Okp,
        };
    }

    /**
     * Returns the byte length of one coordinate of an `EC` public key, or of
     * the public key of an `OKP` key
     *
     * RFC 7518 sections 6.2.1.2 and 6.2.1.3 fix the coordinate length at the
     * full size of the curve's field; RFC 8812 section 3.1 does the same for
     * secp256k1. RFC 8032 sections 5.1.5 and 5.2.5 fix the Edwards public
     * keys at 32 and 57 bytes, and RFC 7748 section 5 fixes the Montgomery
     * public keys at 32 and 56.
     */
    public function publicKeyLength(): int
    {
        return match ($this) {
            self::P256, self::Secp256k1 => 32,
            self::P384 => 48,
            self::P521 => 66,
            self::Ed25519, self::X25519 => 32,
            self::Ed448 => 57,
            self::X448 => 56,
        };
    }

    /**
     * Returns the byte length of the private key, the `d` member
     *
     * RFC 7518 section 6.2.2.1 fixes it at the length of the curve's order,
     * which equals the coordinate length for the four `EC` curves. The
     * Edwards private key is a seed of the public key's length, and the
     * Montgomery private key is a scalar of the public key's length.
     */
    public function privateKeyLength(): int
    {
        return $this->publicKeyLength();
    }

    /**
     * Returns the name OpenSSL gives the curve in the details of an `EC`
     * key, or `null` for an `OKP` curve, which OpenSSL treats as a key type
     */
    public function opensslCurveName(): ?string
    {
        return match ($this) {
            self::P256 => 'prime256v1',
            self::P384 => 'secp384r1',
            self::P521 => 'secp521r1',
            self::Secp256k1 => 'secp256k1',
            default => null,
        };
    }

    /**
     * Returns the `OPENSSL_KEYTYPE_*` constant OpenSSL reports for a key on
     * this curve
     */
    public function opensslKeyType(): int
    {
        return match ($this) {
            self::P256, self::P384, self::P521, self::Secp256k1 => OPENSSL_KEYTYPE_EC,
            self::Ed25519 => OPENSSL_KEYTYPE_ED25519,
            self::Ed448 => OPENSSL_KEYTYPE_ED448,
            self::X25519 => OPENSSL_KEYTYPE_X25519,
            self::X448 => OPENSSL_KEYTYPE_X448,
        };
    }

    /**
     * Returns the key under which `openssl_pkey_get_details()` reports, and
     * `openssl_pkey_new()` takes, the members of an `OKP` key, or `null` for
     * an `EC` curve, whose members sit under `ec`
     */
    public function opensslDetailsKey(): ?string
    {
        return match ($this) {
            self::Ed25519 => 'ed25519',
            self::Ed448 => 'ed448',
            self::X25519 => 'x25519',
            self::X448 => 'x448',
            default => null,
        };
    }
}
