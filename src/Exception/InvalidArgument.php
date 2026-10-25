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

use InvalidArgumentException;

/**
 * Thrown for a caller's own mistake: an additional member named after a
 * member the key type defines, given to `withAdditionalMember()` or to a
 * key class's constructor; a string that is not base64url, given to
 * `Base64Url::decode()`; members that describe no key OpenSSL builds,
 * given to `OpenSsl::build()`; or a reader that is not an entry of the
 * `oth` member, given to `OtherPrimeInfo::fromMembers()`
 */
final class InvalidArgument extends InvalidArgumentException implements JwkException
{
}
