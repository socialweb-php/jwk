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

use OpenSSLAsymmetricKey;
use SensitiveParameter;
use SocialWeb\Jwk\Exception\ConversionFailed;
use SocialWeb\Jwk\Exception\ConversionFailedReason;
use SocialWeb\Jwk\Exception\InvalidJwk;

use function is_array;
use function is_string;
use function sprintf;

use const OPENSSL_KEYTYPE_DH;
use const OPENSSL_KEYTYPE_DSA;
use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;

/**
 * Builds a key object from the members OpenSSL reports for a key it holds
 *
 * `openssl_pkey_get_details()` reports the type of a key and its members,
 * each integer as big-endian bytes without leading zeros. That is the
 * Base64urlUInt form of an RSA member, and for an EC member it means a
 * coordinate or scalar whose high byte is zero comes back short, so each
 * is left-padded to the length its curve fixes.
 *
 * @internal
 */
final class OpenSslKeyReader
{
    /**
     * Returns the key object for a key OpenSSL holds, private when the key
     * is private
     *
     * The key object is built through its constructor, which applies every
     * rule of a parsed key, so a key OpenSSL holds that breaks one, such
     * as an RSA key with a public exponent of 1, is refused as a parsed one
     * would be.
     *
     * @throws ConversionFailed with `UnsupportedKey` for a key type the
     *     package does not implement, which OpenSSL reports as DSA, DH, or
     *     a type it does not describe, such as an RSA key with the
     *     id-RSASSA-PSS algorithm identifier; or for an EC curve the package
     *     does not implement
     * @throws InvalidJwk when the key breaks a rule a parsed key must keep
     */
    public static function read(#[SensitiveParameter] OpenSSLAsymmetricKey $key): RsaKey | EcKey | OkpKey
    {
        /**
         * @var array{
         *     type: int,
         *     rsa?: array<string, string>,
         *     ec?: array<string, string>,
         *     ed25519?: array<string, string>,
         *     ed448?: array<string, string>,
         *     x25519?: array<string, string>,
         *     x448?: array<string, string>,
         * } $details
         */
        $details = OpenSsl::details($key);
        $type = $details['type'];

        if ($type === OPENSSL_KEYTYPE_RSA) {
            return self::rsa($details['rsa'] ?? []);
        }

        if ($type === OPENSSL_KEYTYPE_EC) {
            return self::ec($details['ec'] ?? []);
        }

        $curve = Curve::fromOpensslKeyType($type);

        if ($curve !== null) {
            $members = $details[$curve->opensslDetailsKey() ?? ''] ?? null;

            return self::okp($curve, is_array($members) ? $members : []);
        }

        throw new ConversionFailed(
            ConversionFailedReason::UnsupportedKey,
            match ($type) {
                OPENSSL_KEYTYPE_DSA => 'The key is a DSA key, which the package does not implement',
                OPENSSL_KEYTYPE_DH => 'The key is a DH key, which the package does not implement',
                default => sprintf(
                    'The key is of a type OpenSSL does not describe (type %d), such as an RSA key with the'
                    . ' id-RSASSA-PSS algorithm identifier, which the package does not read',
                    $type,
                ),
            },
        );
    }

    /**
     * Builds an RSA key from the `rsa` entry of the details
     *
     * The five CRT members are passed only when OpenSSL reports all of
     * them, since RFC 7518 section 6.3.2 wants them all or none; a key
     * with `d` alone is a valid private key.
     *
     * @param array<string, string> $members
     */
    private static function rsa(#[SensitiveParameter] array $members): RsaKey
    {
        $hasCrt = isset(
            $members['d'],
            $members['p'],
            $members['q'],
            $members['dmp1'],
            $members['dmq1'],
            $members['iqmp'],
        );

        return new RsaKey(
            $members['n'] ?? '',
            $members['e'] ?? '',
            $members['d'] ?? null,
            $hasCrt ? $members['p'] : null,
            $hasCrt ? $members['q'] : null,
            $hasCrt ? $members['dmp1'] : null,
            $hasCrt ? $members['dmq1'] : null,
            $hasCrt ? $members['iqmp'] : null,
        );
    }

    /**
     * Builds an EC key from the `ec` entry of the details, padding each
     * coordinate and the private key to the curve's length
     *
     * @param array<string, string> $members
     *
     * @throws ConversionFailed with `UnsupportedKey` when the curve is not
     *     one the package implements, or when OpenSSL names none
     */
    private static function ec(#[SensitiveParameter] array $members): EcKey
    {
        $curveName = $members['curve_name'] ?? null;
        $curve = is_string($curveName) ? Curve::fromOpensslCurveName($curveName) : null;

        if ($curve === null) {
            throw new ConversionFailed(
                ConversionFailedReason::UnsupportedKey,
                $curveName === null
                    ? 'The key is on an EC curve OpenSSL does not name, which the package does not implement'
                    : sprintf('The key is on the EC curve %s, which the package does not implement', $curveName),
            );
        }

        $length = $curve->publicKeyLength();
        $privateKey = $members['d'] ?? null;

        return new EcKey(
            $curve,
            OpenSsl::padLeft($members['x'] ?? '', $length),
            OpenSsl::padLeft($members['y'] ?? '', $length),
            $privateKey === null ? null : OpenSsl::padLeft($privateKey, $curve->privateKeyLength()),
        );
    }

    /**
     * Builds an OKP key from the entry of the details for its curve
     *
     * @param array<string, string> $members
     */
    private static function okp(Curve $curve, #[SensitiveParameter] array $members): OkpKey
    {
        return new OkpKey($curve, $members['pub_key'] ?? '', $members['priv_key'] ?? null);
    }
}
