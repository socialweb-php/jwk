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
     * Returns the order of an `EC` curve's base point as big-endian bytes of
     * the curve's coordinate length, or `null` for an `OKP` curve
     *
     * An `EC` private key is an integer from 1 to the order minus 1, per
     * SEC 1 section 3.2.1. The orders are the curves' domain parameters
     * from SEC 2, for the curves RFC 7518 section 6.2.1.1 and RFC 8812
     * section 3.1 name.
     */
    public function order(): ?string
    {
        return match ($this) {
            self::P256 => "\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"
                . "\xbc\xe6\xfa\xad\xa7\x17\x9e\x84\xf3\xb9\xca\xc2\xfc\x63\x25\x51",
            self::P384 => "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                . "\xff\xff\xff\xff\xff\xff\xff\xff\xc7\x63\x4d\x81\xf4\x37\x2d\xdf"
                . "\x58\x1a\x0d\xb2\x48\xb0\xa7\x7a\xec\xec\x19\x6a\xcc\xc5\x29\x73",
            self::P521 => "\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                . "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                . "\xff\xfa\x51\x86\x87\x83\xbf\x2f\x96\x6b\x7f\xcc\x01\x48\xf7\x09"
                . "\xa5\xd0\x3b\xb5\xc9\xb8\x89\x9c\x47\xae\xbb\x6f\xb7\x1e\x91\x38"
                . "\x64\x09",
            self::Secp256k1 => "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe"
                . "\xba\xae\xdc\xe6\xaf\x48\xa0\x3b\xbf\xd2\x5e\x8c\xd0\x36\x41\x41",
            default => null,
        };
    }

    /**
     * Returns the `EC` curve OpenSSL names in the details of a key, or
     * `null` for a name the package does not implement
     */
    public static function fromOpensslCurveName(string $curveName): ?self
    {
        foreach ([self::P256, self::P384, self::P521, self::Secp256k1] as $curve) {
            if ($curve->opensslCurveName() === $curveName) {
                return $curve;
            }
        }

        return null;
    }

    /**
     * Returns the `OKP` curve whose keys OpenSSL reports under the
     * `OPENSSL_KEYTYPE_*` constant, or `null` for any other constant,
     * including `OPENSSL_KEYTYPE_EC`, whose curve is in the key's details
     */
    public static function fromOpensslKeyType(int $keyType): ?self
    {
        foreach ([self::Ed25519, self::Ed448, self::X25519, self::X448] as $curve) {
            if ($curve->opensslKeyType() === $keyType) {
                return $curve;
            }
        }

        return null;
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
