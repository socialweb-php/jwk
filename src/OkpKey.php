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

use function sprintf;

/**
 * An octet key pair, the `OKP` key type of RFC 8037 section 2: a public
 * key and a private key that are plain byte strings
 *
 * The Edwards curves sign; the Montgomery curves agree on keys. The byte
 * lengths come from RFC 8032 and RFC 7748, and a private key is checked to
 * derive the public key.
 */
final readonly class OkpKey extends Jwk
{
    private const array MEMBER_NAMES = ['crv', 'x', 'd'];

    private OpenSSLAsymmetricKey $openSslKey;

    private OpenSSLAsymmetricKey $publicOpenSslKey;

    /**
     * @param Curve $curve The `crv` member, one of the `OKP` curves
     * @param string $publicKey The `x` member
     * @param ?string $privateKey The `d` member, which makes the key private
     * @param list<KeyOperation | string> $keyOperations
     * @param list<string> $certificateChain
     * @param array<string, mixed> $additionalMembers Every member the
     *     package does not define; a JSON object is a `stdClass` or a PHP
     *     array that is not a list, and a JSON array is a PHP list
     *
     * @throws InvalidJwk with `UnsupportedCurve` for an `EC` curve; with
     *     `WrongLength` for a key of another length than the curve fixes;
     *     with `KeyPairMismatch` when `d` does not derive `x`; or as the
     *     common members' rules say
     * @throws InvalidArgument when an additional member is named after a member
     *     the key type defines
     */
    public function __construct(
        public Curve $curve,
        public string $publicKey,
        #[SensitiveParameter]
        public ?string $privateKey = null,
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
        $detailsKey = $curve->opensslDetailsKey() ?? throw new InvalidJwk(
            InvalidJwkReason::UnsupportedCurve,
            sprintf('The curve %s is not an OKP curve', $curve->value),
            'crv',
        );

        self::checkLength('x', $publicKey, $curve->publicKeyLength(), $curve);

        if ($privateKey !== null) {
            self::checkLength('d', $privateKey, $curve->privateKeyLength(), $curve);
        }

        $this->publicOpenSslKey = $this->buildPublicOpenSslKey($detailsKey);
        $this->openSslKey = $privateKey === null
            ? $this->publicOpenSslKey
            : $this->buildPrivateOpenSslKey($detailsKey, $privateKey);

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
        return KeyType::Okp;
    }

    public function isPrivate(): bool
    {
        return $this->privateKey !== null;
    }

    public function toPublic(): static
    {
        return clone($this, ['privateKey' => null, 'openSslKey' => $this->publicOpenSslKey]);
    }

    public function toOpenSslKey(): OpenSSLAsymmetricKey
    {
        return $this->openSslKey;
    }

    /**
     * @internal
     */
    protected static function fromMembers(#[SensitiveParameter] MemberReader $members): self
    {
        $crv = $members->requiredString('crv');
        $curve = Curve::tryFrom($crv) ?? throw new InvalidJwk(
            InvalidJwkReason::UnsupportedCurve,
            sprintf('The curve "%s" is not implemented', $crv),
            'crv',
        );

        return new self(
            $curve,
            $members->requiredBytes('x'),
            $members->bytes('d'),
            ...self::commonArguments($members, self::MEMBER_NAMES),
        );
    }

    protected function curve(): Curve
    {
        return $this->curve;
    }

    /**
     * @return array<string, string>
     */
    protected function thumbprintMembers(): array
    {
        return [
            'crv' => $this->curve->value,
            'kty' => KeyType::Okp->value,
            'x' => Base64Url::encode($this->publicKey),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    protected function keyMembers(): array
    {
        $members = ['crv' => $this->curve->value, 'x' => Base64Url::encode($this->publicKey)];

        if ($this->privateKey !== null) {
            $members['d'] = Base64Url::encode($this->privateKey);
        }

        return $members;
    }

    /**
     * @return array<string, mixed>
     */
    protected function redactedKeyMembers(): array
    {
        $members = ['crv' => $this->curve->value, 'x' => Base64Url::encode($this->publicKey)];

        if ($this->privateKey !== null) {
            $members['d'] = '[redacted]';
        }

        return $members;
    }

    /**
     * @return non-empty-list<string>
     */
    protected function keyMemberNames(): array
    {
        return self::MEMBER_NAMES;
    }

    /**
     * Builds the public key from its bytes
     *
     * @throws InvalidJwk with `InvalidValue` when OpenSSL refuses the bytes,
     *     which it does for no key of the right length
     */
    private function buildPublicOpenSslKey(string $detailsKey): OpenSSLAsymmetricKey
    {
        return OpenSsl::build(
            [$detailsKey => ['pub_key' => $this->publicKey]],
            InvalidJwkReason::InvalidValue,
            'x',
            sprintf('OpenSSL could not read the "x" member as a public key on the curve %s', $this->curve->value),
        );
    }

    /**
     * Builds the private key from `d` alone and checks that the public key
     * it derives is the one given
     *
     * @throws InvalidJwk with `KeyPairMismatch`
     */
    private function buildPrivateOpenSslKey(
        string $detailsKey,
        #[SensitiveParameter] string $privateKey,
    ): OpenSSLAsymmetricKey {
        $key = OpenSsl::build(
            [$detailsKey => ['priv_key' => $privateKey]],
            InvalidJwkReason::KeyPairMismatch,
            'd',
            'OpenSSL could not derive a public key from the "d" member',
        );

        /** @var array<string, array{pub_key: string}> $details */
        $details = OpenSsl::details($key);

        if ($details[$detailsKey]['pub_key'] !== $this->publicKey) {
            throw new InvalidJwk(
                InvalidJwkReason::KeyPairMismatch,
                'The "d" member does not derive the public key in the "x" member',
                'd',
            );
        }

        return $key;
    }
}
