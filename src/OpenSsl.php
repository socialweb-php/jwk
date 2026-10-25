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
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;

use function array_key_first;
use function count;
use function implode;
use function in_array;
use function is_string;
use function ltrim;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function sprintf;
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
    private const array KEY_TYPES = ['rsa', 'ec', 'ed25519', 'ed448', 'x25519', 'x448'];

    /**
     * Builds a key from its members through `openssl_pkey_new()`
     *
     * OpenSSL generates a fresh random key, instead of failing, when the
     * members describe no key, and it accepts some invalid values without
     * error. So the members are checked before the call, and afterward the
     * key must report back every member it was given.
     *
     * @param array<string, array<string, string>> $members One entry, named
     *     for the key type, that holds at least one member besides
     *     `curve_name`
     * @param InvalidJwkReason $reason The reason to report when OpenSSL
     *     refuses the members
     * @param string $member The member to name in that case
     * @param string $message The message in that case, to which OpenSSL's
     *     error text is appended when there is any
     *
     * @throws InvalidArgument when the members are not one entry of a known
     *     key type that holds a member besides `curve_name`
     * @throws InvalidJwk when OpenSSL refuses the members, or builds a key
     *     that does not report them back, which is a generated key
     */
    public static function build(
        #[SensitiveParameter] array $members,
        InvalidJwkReason $reason,
        string $member,
        string $message,
    ): OpenSSLAsymmetricKey {
        if (count($members) !== 1) {
            throw new InvalidArgument('The members must hold exactly one entry, named for the key type');
        }

        $type = array_key_first($members);

        if (!in_array($type, self::KEY_TYPES, true)) {
            throw new InvalidArgument(sprintf('The entry "%s" is not a key type OpenSSL builds from members', $type));
        }

        $given = $members[$type];
        unset($given['curve_name']);

        if ($given === []) {
            throw new InvalidArgument(sprintf('The "%s" entry must hold a member besides "curve_name"', $type));
        }

        self::drainErrors();
        $key = @openssl_pkey_new($members);

        if ($key === false) {
            throw self::refusal($reason, $message, $member);
        }

        /** @var array<string, array<string, mixed>> $details */
        $details = self::details($key);

        foreach ($given as $name => $value) {
            $reported = $details[$type][$name] ?? null;

            if (!is_string($reported) || ltrim($reported, "\0") !== ltrim($value, "\0")) {
                throw self::refusal($reason, $message, $member);
            }
        }

        self::drainErrors();

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

    private static function refusal(InvalidJwkReason $reason, string $message, string $member): InvalidJwk
    {
        $errors = self::drainErrors();

        return new InvalidJwk($reason, $errors === '' ? $message : $message . ': ' . $errors, $member);
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
