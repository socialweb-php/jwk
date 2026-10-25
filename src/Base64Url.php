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

use SensitiveParameter;
use SocialWeb\Jwk\Exception\InvalidArgument;

use function base64_decode;
use function base64_encode;
use function is_string;
use function rtrim;
use function strlen;
use function strspn;
use function strtr;

/**
 * Base64url without padding, as RFC 7515 section 2 defines it and appendix
 * C shows it: the URL-safe alphabet of RFC 4648 section 5, no `=`, and no
 * line breaks
 *
 * Decoding is strict. A string decodes only when it is the one encoding of
 * its bytes, so that `encode(decode($text)) === $text` for every string
 * this class accepts; a thumbprint computed from re-encoded members then
 * equals one computed from the members as sent.
 *
 * @internal
 */
final class Base64Url
{
    private const string ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    /**
     * Returns the base64url encoding of the bytes, without padding
     */
    public static function encode(#[SensitiveParameter] string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Returns the bytes the text encodes
     *
     * @throws InvalidArgument when the text has a character outside the
     *     alphabet, which includes `=`, `+`, and `/`; when its length is 1
     *     modulo 4, which no byte sequence encodes; or when the final
     *     character has bits set that the bytes do not use, which RFC 4648
     *     section 3.5 calls a non-canonical encoding
     */
    public static function decode(#[SensitiveParameter] string $text): string
    {
        if (strspn($text, self::ALPHABET) !== strlen($text)) {
            throw new InvalidArgument('The text has a character outside the base64url alphabet');
        }

        if (strlen($text) % 4 === 1) {
            throw new InvalidArgument('The text has a length no byte sequence encodes in base64url');
        }

        $bytes = base64_decode(strtr($text, '-_', '+/'), true);

        if (!is_string($bytes) || self::encode($bytes) !== $text) {
            throw new InvalidArgument('The text is not the canonical base64url encoding of its bytes');
        }

        return $bytes;
    }
}
