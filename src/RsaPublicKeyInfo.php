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

use function base64_encode;
use function chr;
use function chunk_split;
use function ltrim;
use function ord;
use function pack;
use function strlen;

/**
 * The SubjectPublicKeyInfo of an RSA public key, as DER and as PEM
 *
 * OpenSSL's PHP binding builds an RSA key from its members only when the
 * private exponent is among them, so the public key is the one structure
 * the package encodes itself. RFC 5280 section 4.1 gives the outer
 * SEQUENCE of an AlgorithmIdentifier and a BIT STRING, RFC 3279 section
 * 2.3.1 fixes the identifier at rsaEncryption with NULL parameters, and
 * RFC 8017 appendix A.1.1 gives the RSAPublicKey SEQUENCE of two INTEGERs
 * that the BIT STRING holds.
 *
 * @internal
 */
final class RsaPublicKeyInfo
{
    /**
     * The AlgorithmIdentifier `SEQUENCE { rsaEncryption, NULL }`, which is
     * the same fifteen bytes for every RSA key
     */
    private const string ALGORITHM_IDENTIFIER = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

    /**
     * Returns the DER encoding of the SubjectPublicKeyInfo
     *
     * The modulus and the exponent are unsigned big-endian bytes in minimal
     * form, as `RsaKey` holds them.
     */
    public static function der(string $modulus, string $publicExponent): string
    {
        $rsaPublicKey = self::sequence(self::integer($modulus) . self::integer($publicExponent));
        $subjectPublicKey = self::bitString($rsaPublicKey);

        return self::sequence(self::ALGORITHM_IDENTIFIER . $subjectPublicKey);
    }

    /**
     * Returns the SubjectPublicKeyInfo as a `PUBLIC KEY` PEM, per RFC 7468
     * section 13, in the strict form of its section 3: 64-character lines,
     * LF line endings, and a trailing newline
     */
    public static function pem(string $modulus, string $publicExponent): string
    {
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode(self::der($modulus, $publicExponent)), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    /**
     * Encodes an unsigned integer as a DER INTEGER, adding the zero byte
     * that keeps a value with its high bit set positive
     */
    private static function integer(string $unsigned): string
    {
        $value = ltrim($unsigned, "\0");

        if ($value === '' || (ord($value[0]) & 0x80) !== 0) {
            $value = "\0" . $value;
        }

        return "\x02" . self::length(strlen($value)) . $value;
    }

    private static function sequence(string $contents): string
    {
        return "\x30" . self::length(strlen($contents)) . $contents;
    }

    /**
     * Encodes the contents as a BIT STRING with no unused bits
     */
    private static function bitString(string $contents): string
    {
        return "\x03" . self::length(strlen($contents) + 1) . "\0" . $contents;
    }

    /**
     * Encodes a length in the short form below 128 and in the long form
     * above it, with as many bytes as the length needs
     */
    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return pack('C', $length);
        }

        // The bytes are taken one at a time, since pack() has no format for a
        // 64-bit integer on a 32-bit build of PHP.
        $bytes = '';

        do {
            $bytes = chr($length & 0xff) . $bytes;
            $length >>= 8;
        } while ($length > 0);

        return pack('C', 0x80 | strlen($bytes)) . $bytes;
    }
}
