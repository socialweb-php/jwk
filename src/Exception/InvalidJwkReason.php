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
 * Why an input was refused as a JSON Web Key
 *
 * Each case names a rule of RFC 7517, RFC 7518 section 6, RFC 8037 section
 * 2, or RFC 8812 section 3 that the input broke, or a check the package
 * makes so that a key object that exists is well formed.
 */
enum InvalidJwkReason
{
    /**
     * The JSON text does not parse, or has content after the object
     */
    case MalformedJson;

    /**
     * The JSON value is not an object
     */
    case NotAnObject;

    /**
     * A member the key type requires is absent
     */
    case MissingMember;

    /**
     * A member has the wrong JSON type: a number where a string belongs, a
     * string where an array belongs
     */
    case WrongType;

    /**
     * The `kty` member names a key type the package does not implement
     */
    case UnsupportedKeyType;

    /**
     * The `crv` member names a curve the package does not implement
     */
    case UnsupportedCurve;

    /**
     * A byte-string member is not base64url without padding: a character
     * outside the alphabet, padding, an impossible length, or stray bits in
     * the final character
     */
    case InvalidBase64Url;

    /**
     * An integer member has a leading zero byte, so it is not the minimal
     * Base64urlUInt form that RFC 7518 section 2 requires
     */
    case NonMinimalInteger;

    /**
     * A member has a value the key type gives no meaning: a modulus of
     * zero, an empty key identifier, an empty symmetric key
     */
    case InvalidValue;

    /**
     * The `x` and `y` members of an EC key are not a point on its curve
     */
    case PointNotOnCurve;

    /**
     * A byte-string member does not have the length its curve fixes
     */
    case WrongLength;

    /**
     * The private members of an RSA key are not all present or all absent,
     * or a private member appears without `d`
     */
    case InconsistentPrivateMembers;

    /**
     * The private members do not belong to the key the public members
     * describe
     */
    case KeyPairMismatch;

    /**
     * A private member is present where only a public key is accepted
     */
    case PrivateMembersPresent;

    /**
     * An `oct` key is present where only a public key is accepted
     */
    case SymmetricKey;

    /**
     * The `key_ops` member lists the same operation twice
     */
    case DuplicateKeyOperation;

    /**
     * The `use` member and the `key_ops` member describe different uses
     */
    case InconsistentUseAndKeyOperations;

    /**
     * The `alg` member names a registered algorithm the key type or curve
     * cannot run
     */
    case AlgorithmDoesNotFitKey;

    /**
     * An entry of `x5c` is not a base64-encoded DER certificate
     */
    case InvalidCertificate;

    /**
     * The first certificate of `x5c` holds a different key
     */
    case CertificateKeyMismatch;

    /**
     * The `x5t` or `x5t#S256` member is not the digest of the first
     * certificate of `x5c`
     */
    case CertificateThumbprintMismatch;
}
