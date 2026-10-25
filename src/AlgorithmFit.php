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

use function array_merge;
use function in_array;

/**
 * Which registered `alg` values fit which keys
 *
 * The table comes from RFC 7518 sections 3.1 and 4.1, RFC 8037 section 3,
 * RFC 8812 section 3.2, and RFC 9864 section 4.1.1. The `enc` names of
 * RFC 7518 section 5.1 fit an `oct` key because a content encryption key
 * may name its algorithm with them. `none` and the PBES2 values fit no
 * key: `none` has no key, and PBES2 derives its key from a password. A
 * value none of those documents registers is left alone, since RFC 7517
 * section 4.4 lets other values be used.
 *
 * @internal
 */
final class AlgorithmFit
{
    private const array ECDH_ES = ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'];

    private const array RSA = [
        'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256',
    ];

    private const array OCT = [
        'HS256', 'HS384', 'HS512',
        'A128KW', 'A192KW', 'A256KW',
        'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
        'dir',
        'A128GCM', 'A192GCM', 'A256GCM',
        'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512',
    ];

    private const array FITS_NO_KEY = ['none', 'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW'];

    /**
     * Returns whether a key of the type, on the curve, can run the
     * algorithm, or whether the algorithm is one the registries do not
     * name and so is not checked
     */
    public static function fits(string $algorithm, KeyType $keyType, ?Curve $curve): bool
    {
        if (!self::isRegistered($algorithm)) {
            return true;
        }

        return in_array($algorithm, self::fitting($keyType, $curve), true);
    }

    /**
     * Returns whether one of the documents the table comes from registers
     * the algorithm
     */
    public static function isRegistered(string $algorithm): bool
    {
        return in_array($algorithm, array_merge(
            self::RSA,
            self::OCT,
            self::ECDH_ES,
            self::FITS_NO_KEY,
            ['ES256', 'ES384', 'ES512', 'ES256K', 'EdDSA', 'Ed25519', 'Ed448'],
        ), true);
    }

    /**
     * @return list<string>
     */
    private static function fitting(KeyType $keyType, ?Curve $curve): array
    {
        return match ($keyType) {
            KeyType::Rsa => self::RSA,
            KeyType::Oct => self::OCT,
            KeyType::Ec, KeyType::Okp => match ($curve) {
                Curve::P256 => ['ES256', ...self::ECDH_ES],
                Curve::P384 => ['ES384', ...self::ECDH_ES],
                Curve::P521 => ['ES512', ...self::ECDH_ES],
                Curve::Secp256k1 => ['ES256K'],
                Curve::Ed25519 => ['EdDSA', 'Ed25519'],
                Curve::Ed448 => ['EdDSA', 'Ed448'],
                Curve::X25519, Curve::X448 => self::ECDH_ES,
                null => [],
            },
        };
    }
}
