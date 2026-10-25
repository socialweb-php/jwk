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

namespace SocialWeb\Jwk\Exception;

/**
 * Why a key could not be converted between its JWK form and a PEM or an
 * OpenSSL key
 */
enum ConversionFailedReason
{
    /**
     * OpenSSL could not read the PEM text, or an encrypted key was given
     * without its passphrase
     */
    case UnreadablePem;

    /**
     * OpenSSL read the key, and it is of a type or on a curve the package
     * does not implement
     */
    case UnsupportedKey;

    /**
     * An `oct` key has no public form, no PEM form, and no OpenSSL form
     */
    case SymmetricKey;

    /**
     * A private form was asked of a public key
     */
    case NotAPrivateKey;

    /**
     * An RSA private key has `d` and not the primes, which PKCS #8 needs
     */
    case MissingCrtMembers;

    /**
     * An RSA key has more than two primes, which OpenSSL's PHP binding does
     * not build
     */
    case MultiPrimeKey;
}
