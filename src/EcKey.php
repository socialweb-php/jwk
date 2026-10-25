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
 * An elliptic curve key, the `EC` key type of RFC 7518 section 6.2
 *
 * The coordinates and the private key are bytes of the full length the
 * curve fixes, leading zeros included, as sections 6.2.1.2, 6.2.1.3, and
 * 6.2.2.1 require. The point is checked to lie on the curve, and a private
 * key is checked to derive the point.
 */
final readonly class EcKey extends Jwk
{
    private const array MEMBER_NAMES = ['crv', 'x', 'y', 'd'];

    private OpenSSLAsymmetricKey $openSslKey;

    private OpenSSLAsymmetricKey $publicOpenSslKey;

    /**
     * @param Curve $curve The `crv` member, one of the `EC` curves
     * @param string $x The `x` member
     * @param string $y The `y` member
     * @param ?string $privateKey The `d` member, which makes the key private
     * @param list<KeyOperation | string> $keyOperations
     * @param list<string> $certificateChain
     * @param array<string, mixed> $additionalMembers Every member the
     *     package does not define; a JSON object is a `stdClass` or a PHP
     *     array that is not a list, and a JSON array is a PHP list
     *
     * @throws InvalidJwk with `UnsupportedCurve` for an `OKP` curve; with
     *     `WrongLength` for a coordinate or private key of another length
     *     than the curve fixes; with `PointNotOnCurve` when `x` and `y` are
     *     not a point on the curve; with `KeyPairMismatch` when `d` does not
     *     derive the point; or as the common members' rules say
     * @throws InvalidArgument when an additional member is named after a member
     *     the key type defines
     */
    public function __construct(
        public Curve $curve,
        public string $x,
        public string $y,
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
        $curveName = $curve->opensslCurveName() ?? throw new InvalidJwk(
            InvalidJwkReason::UnsupportedCurve,
            sprintf('The curve %s is not an EC curve', $curve->value),
            'crv',
        );

        self::checkLength('x', $x, $curve->publicKeyLength(), $curve);
        self::checkLength('y', $y, $curve->publicKeyLength(), $curve);

        if ($privateKey !== null) {
            self::checkLength('d', $privateKey, $curve->privateKeyLength(), $curve);
        }

        $this->publicOpenSslKey = $this->buildPublicOpenSslKey($curveName);
        $this->openSslKey = $privateKey === null
            ? $this->publicOpenSslKey
            : $this->buildPrivateOpenSslKey($curveName, $privateKey);

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
        return KeyType::Ec;
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
            $members->requiredBytes('y'),
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
            'kty' => KeyType::Ec->value,
            'x' => Base64Url::encode($this->x),
            'y' => Base64Url::encode($this->y),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    protected function keyMembers(): array
    {
        $members = [
            'crv' => $this->curve->value,
            'x' => Base64Url::encode($this->x),
            'y' => Base64Url::encode($this->y),
        ];

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
        $members = [
            'crv' => $this->curve->value,
            'x' => Base64Url::encode($this->x),
            'y' => Base64Url::encode($this->y),
        ];

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
     * Builds the public key, which OpenSSL refuses when the point is not on
     * the curve
     *
     * @throws InvalidJwk with `PointNotOnCurve`
     */
    private function buildPublicOpenSslKey(string $curveName): OpenSSLAsymmetricKey
    {
        return OpenSsl::build(
            ['ec' => ['curve_name' => $curveName, 'x' => $this->x, 'y' => $this->y]],
            InvalidJwkReason::PointNotOnCurve,
            'x',
            sprintf('The "x" and "y" members are not a point on the curve %s', $this->curve->value),
        );
    }

    /**
     * Builds the private key from `d` alone and checks that the point it
     * derives is the one given
     *
     * OpenSSL replaces a given point with the derived one when both are
     * supplied, so the derivation is what is compared, not what OpenSSL
     * kept.
     *
     * @throws InvalidJwk with `KeyPairMismatch`
     */
    private function buildPrivateOpenSslKey(
        string $curveName,
        #[SensitiveParameter] string $privateKey,
    ): OpenSSLAsymmetricKey {
        $key = OpenSsl::build(
            ['ec' => ['curve_name' => $curveName, 'd' => $privateKey]],
            InvalidJwkReason::KeyPairMismatch,
            'd',
            'OpenSSL could not derive a public key from the "d" member',
        );

        /** @var array{ec: array{x: string, y: string}} $details */
        $details = OpenSsl::details($key);
        $length = $this->curve->publicKeyLength();

        if (
            OpenSsl::padLeft($details['ec']['x'], $length) !== $this->x
            || OpenSsl::padLeft($details['ec']['y'], $length) !== $this->y
        ) {
            throw new InvalidJwk(
                InvalidJwkReason::KeyPairMismatch,
                'The "d" member does not derive the point in the "x" and "y" members',
                'd',
            );
        }

        return $key;
    }
}
