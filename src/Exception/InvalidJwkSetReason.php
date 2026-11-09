<?php

/**
 * This file is part of socialweb/jwk
 *
 * Copyright © socialweb/jwk Contributors
 *
 * socialweb/jwk is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * socialweb/jwk is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with socialweb/jwk. If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

declare(strict_types=1);

namespace SocialWeb\Jwk\Exception;

/**
 * Why an input was refused as a JWK Set
 *
 * Each case is a way the set object itself fails RFC 7517 section 5. A
 * member of the `keys` array that is not a usable key is never a reason
 * here; the set records it as skipped.
 */
enum InvalidJwkSetReason
{
    /**
     * The JSON text does not parse or has content after the object, or a
     * member of the set object other than `keys` holds content JSON text
     * cannot express: a string or a member name that is not valid UTF-8, a
     * member name that starts with a NUL byte, a number that is not
     * finite, or nesting deeper than `json_decode()` reads
     */
    case MalformedJson;

    /**
     * The JSON value is not an object
     */
    case NotAnObject;

    /**
     * The object has no `keys` member, which RFC 7517 section 5.1 requires
     */
    case MissingKeysMember;

    /**
     * The `keys` member is not an array
     */
    case KeysNotAnArray;
}
