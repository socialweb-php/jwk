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
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;

/**
 * A symmetric key, the `oct` key type of RFC 7518 section 6.4
 *
 * A symmetric key is never public: `isPrivate()` is always `true`, and it
 * has no public form, no PEM form, and no OpenSSL form.
 */
final readonly class OctKey extends Jwk
{
    /**
     * @param string $keyValue The key bytes, the `k` member
     * @param list<KeyOperation | string> $keyOperations
     * @param list<string> $certificateChain
     * @param array<string, mixed> $additionalMembers Every member the
     *     package does not define; a JSON object is a `stdClass` or a PHP
     *     array that is not a list, and a JSON array is a PHP list
     *
     * @throws InvalidJwk with `InvalidValue` for an empty key, or as the
     *     common members' rules say
     * @throws InvalidArgument when an additional member is named after a member
     *     the key type defines
     */
    public function __construct(
        #[SensitiveParameter]
        public string $keyValue,
        ?string $keyId = null,
        ?string $algorithm = null,
        KeyUse | string | null $use = null,
        array $keyOperations = [],
        ?string $certificateUrl = null,
        array $certificateChain = [],
        ?string $certificateSha1Thumbprint = null,
        ?string $certificateSha256Thumbprint = null,
        array $additionalMembers = [],
    ) {
        if ($keyValue === '') {
            throw new InvalidJwk(InvalidJwkReason::InvalidValue, 'The "k" member must not be empty', 'k');
        }

        parent::__construct(
            $keyId,
            $algorithm,
            self::normalizeUse($use),
            self::normalizeKeyOperations($keyOperations),
            $certificateUrl,
            $certificateChain,
            $certificateSha1Thumbprint,
            $certificateSha256Thumbprint,
            $additionalMembers,
        );
    }

    public function keyType(): KeyType
    {
        return KeyType::Oct;
    }

    public function isPrivate(): bool
    {
        return true;
    }

    public function toPublic(): static
    {
        throw new ConversionFailed(ConversionFailedReason::SymmetricKey, 'A symmetric key has no public form');
    }

    public function toOpenSslKey(): OpenSSLAsymmetricKey
    {
        throw new ConversionFailed(ConversionFailedReason::SymmetricKey, 'A symmetric key has no OpenSSL form');
    }

    /**
     * @internal
     */
    protected static function fromMembers(#[SensitiveParameter] MemberReader $members): self
    {
        return new self($members->requiredBytes('k'), ...self::commonArguments($members, ['k']));
    }

    /**
     * @return array<string, string>
     */
    protected function thumbprintMembers(): array
    {
        return ['k' => Base64Url::encode($this->keyValue), 'kty' => KeyType::Oct->value];
    }

    /**
     * @return array<string, mixed>
     */
    protected function keyMembers(): array
    {
        return ['k' => Base64Url::encode($this->keyValue)];
    }

    /**
     * @return array<string, mixed>
     */
    protected function redactedKeyMembers(): array
    {
        return ['k' => '[redacted]'];
    }

    /**
     * @return non-empty-list<string>
     */
    protected function keyMemberNames(): array
    {
        return ['k'];
    }
}
