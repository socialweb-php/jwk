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
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;

use function implode;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function str_pad;

use const STR_PAD_LEFT;

/**
 * The few OpenSSL calls the key classes share
 *
 * OpenSSL keeps a queue of error messages that outlives the call that
 * produced them, so every call that can fail is preceded by a drain and
 * followed by one, and a message built here holds only its own call's
 * errors.
 *
 * @internal
 */
final class OpenSsl
{
    /**
     * Builds a key from its members through `openssl_pkey_new()`
     *
     * @param array<string, array<string, string>> $members
     * @param InvalidJwkReason $reason The reason to report when OpenSSL
     *     refuses the members
     * @param string $member The member to name in that case
     * @param string $message The message in that case, to which OpenSSL's
     *     error text is appended when there is any
     *
     * @throws InvalidJwk when OpenSSL refuses the members
     */
    public static function build(
        array $members,
        InvalidJwkReason $reason,
        string $member,
        string $message,
    ): OpenSSLAsymmetricKey {
        self::drainErrors();
        $key = @openssl_pkey_new($members);

        if ($key === false) {
            $errors = self::drainErrors();

            throw new InvalidJwk($reason, $errors === '' ? $message : $message . ': ' . $errors, $member);
        }

        return $key;
    }

    /**
     * Returns the details of a key, as `openssl_pkey_get_details()` reports
     * them
     *
     * @return array<string, mixed>
     */
    public static function details(OpenSSLAsymmetricKey $key): array
    {
        /** @var array<string, mixed> $details */
        $details = openssl_pkey_get_details($key);

        return $details;
    }

    /**
     * Returns and empties OpenSSL's error queue, the messages joined with
     * a semicolon and a space
     */
    public static function drainErrors(): string
    {
        $errors = [];

        while (($error = openssl_error_string()) !== false) {
            $errors[] = $error;
        }

        return implode('; ', $errors);
    }

    /**
     * Returns the bytes left-padded with zero bytes to the length
     *
     * OpenSSL reports an integer without its leading zero bytes, so a
     * coordinate or a scalar whose high byte is zero comes back short of
     * the length its curve fixes.
     */
    public static function padLeft(string $bytes, int $length): string
    {
        return str_pad($bytes, $length, "\0", STR_PAD_LEFT);
    }
}
