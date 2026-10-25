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

use LogicException;
use OpenSSLAsymmetricKey;
use SensitiveParameter;
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;

use function array_key_first;
use function array_keys;
use function count;
use function implode;
use function in_array;
use function is_array;
use function is_string;
use function ltrim;
use function openssl_error_string;
use function openssl_get_curve_names;
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
    /**
     * The members OpenSSL reads from each entry, by the entry's key type
     */
    private const array MEMBER_NAMES = [
        'rsa' => ['n', 'e', 'd', 'p', 'q', 'dmp1', 'dmq1', 'iqmp'],
        'ec' => ['curve_name', 'x', 'y', 'd'],
        'ed25519' => ['pub_key', 'priv_key'],
        'ed448' => ['pub_key', 'priv_key'],
        'x25519' => ['pub_key', 'priv_key'],
        'x448' => ['pub_key', 'priv_key'],
    ];

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
     *     `curve_name`, and only members OpenSSL reads for that key type
     * @param InvalidJwkReason $reason The reason to report when OpenSSL
     *     refuses the members
     * @param string $member The member to name in that case
     * @param string $message The message in that case, to which OpenSSL's
     *     error text is appended when there is any
     *
     * @throws InvalidArgument when the members are not one entry of a known
     *     key type that holds a member besides `curve_name`; when the entry
     *     has a member OpenSSL does not read for that key type; or when an
     *     `ec` entry has no `curve_name` or one OpenSSL does not know
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

        if (!in_array($type, array_keys(self::MEMBER_NAMES), true)) {
            throw new InvalidArgument(sprintf('The entry "%s" is not a key type OpenSSL builds from members', $type));
        }

        foreach (array_keys($members[$type]) as $name) {
            if (!in_array($name, self::MEMBER_NAMES[$type], true)) {
                throw new InvalidArgument(
                    sprintf('The "%s" entry has the member "%s", which OpenSSL does not read for it', $type, $name),
                );
            }
        }

        if ($type === 'ec') {
            self::checkCurveName($members['ec']['curve_name'] ?? null);
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
        $details = openssl_pkey_get_details($key);

        if ($details === false) {
            throw new LogicException('OpenSSL reported no details for a key it holds: ' . self::drainErrors());
        }

        /** @var array<string, mixed> $details */
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
     * @throws InvalidArgument when the curve name is missing or is not one
     *     OpenSSL knows
     */
    private static function checkCurveName(?string $curveName): void
    {
        if ($curveName === null) {
            throw new InvalidArgument('The "ec" entry must hold a "curve_name" member');
        }

        $known = openssl_get_curve_names();

        if (!is_array($known) || !in_array($curveName, $known, true)) {
            throw new InvalidArgument(sprintf('The curve name "%s" is not one OpenSSL knows', $curveName));
        }
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
