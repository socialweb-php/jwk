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
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;

use function array_filter;
use function array_keys;
use function array_map;
use function count;
use function is_string;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;
use function ord;

use const OPENSSL_ALGO_SHA256;

/**
 * An RSA key, the `RSA` key type of RFC 7518 section 6.3
 *
 * The members are unsigned big-endian bytes in the minimal form that
 * Base64urlUInt requires. A public key has the modulus and the public
 * exponent; a private key adds the private exponent and, as RFC 7518
 * section 6.3.2 recommends, the two primes and the three CRT values that
 * speed up its use, with any further primes in `oth`.
 */
final readonly class RsaKey extends Jwk
{
    private const array MEMBER_NAMES = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'oth'];

    /**
     * The fixed message the pair check signs; its content is immaterial
     */
    private const string PAIR_CHECK_MESSAGE = 'socialweb/jwk key pair check';

    private OpenSSLAsymmetricKey $openSslKey;

    private OpenSSLAsymmetricKey $publicOpenSslKey;

    /**
     * @param string $modulus The `n` member
     * @param string $publicExponent The `e` member
     * @param ?string $privateExponent The `d` member, which makes the key
     *     private
     * @param ?string $firstPrimeFactor The `p` member
     * @param ?string $secondPrimeFactor The `q` member
     * @param ?string $firstFactorCrtExponent The `dp` member
     * @param ?string $secondFactorCrtExponent The `dq` member
     * @param ?string $firstCrtCoefficient The `qi` member
     * @param list<OtherPrimeInfo> $otherPrimesInfo The `oth` member
     * @param list<KeyOperation | string> $keyOperations
     * @param list<string> $certificateChain
     * @param array<string, mixed> $additionalMembers
     *
     * @throws InvalidJwk with `NonMinimalInteger` or `InvalidValue` for a
     *     member that is not a Base64urlUInt of a positive value, for an even
     *     modulus, or for a public exponent that is even or below 3; with
     *     `InconsistentPrivateMembers` when the primes and CRT values are
     *     neither all present nor all absent, when one is present without
     *     `d`, or when `oth` is present without the primes; with
     *     `KeyPairMismatch` when the private members do not belong to the
     *     public ones; or as the common members' rules say
     */
    public function __construct(
        public string $modulus,
        public string $publicExponent,
        #[SensitiveParameter]
        public ?string $privateExponent = null,
        #[SensitiveParameter]
        public ?string $firstPrimeFactor = null,
        #[SensitiveParameter]
        public ?string $secondPrimeFactor = null,
        #[SensitiveParameter]
        public ?string $firstFactorCrtExponent = null,
        #[SensitiveParameter]
        public ?string $secondFactorCrtExponent = null,
        #[SensitiveParameter]
        public ?string $firstCrtCoefficient = null,
        #[SensitiveParameter]
        public array $otherPrimesInfo = [],
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
        ByteInteger::checkRsaMember('n', $modulus);
        ByteInteger::checkRsaMember('e', $publicExponent);
        self::checkPublicMembers($modulus, $publicExponent);
        $this->checkPrivateMembers();

        $this->publicOpenSslKey = $this->buildPublicOpenSslKey();
        $this->openSslKey = $privateExponent === null
            ? $this->publicOpenSslKey
            : $this->buildPrivateOpenSslKey($privateExponent);

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
        return KeyType::Rsa;
    }

    public function isPrivate(): bool
    {
        return $this->privateExponent !== null;
    }

    public function toPublic(): static
    {
        return clone($this, [
            'privateExponent' => null,
            'firstPrimeFactor' => null,
            'secondPrimeFactor' => null,
            'firstFactorCrtExponent' => null,
            'secondFactorCrtExponent' => null,
            'firstCrtCoefficient' => null,
            'otherPrimesInfo' => [],
            'openSslKey' => $this->publicOpenSslKey,
        ]);
    }

    public function toOpenSslKey(): OpenSSLAsymmetricKey
    {
        if ($this->otherPrimesInfo !== []) {
            throw new ConversionFailed(
                ConversionFailedReason::MultiPrimeKey,
                'An RSA key with more than two primes cannot be built by OpenSSL',
            );
        }

        return $this->openSslKey;
    }

    /**
     * @internal
     */
    protected static function fromMembers(MemberReader $members): self
    {
        $otherPrimesInfo = [];

        foreach ($members->objectList('oth') as $info) {
            $otherPrimesInfo[] = new OtherPrimeInfo(
                $info->requiredBytes('r'),
                $info->requiredBytes('d'),
                $info->requiredBytes('t'),
            );
        }

        return new self(
            $members->requiredBytes('n'),
            $members->requiredBytes('e'),
            $members->bytes('d'),
            $members->bytes('p'),
            $members->bytes('q'),
            $members->bytes('dp'),
            $members->bytes('dq'),
            $members->bytes('qi'),
            $otherPrimesInfo,
            ...self::commonArguments($members, self::MEMBER_NAMES),
        );
    }

    /**
     * @return array<string, string>
     */
    protected function thumbprintMembers(): array
    {
        return [
            'e' => Base64Url::encode($this->publicExponent),
            'kty' => KeyType::Rsa->value,
            'n' => Base64Url::encode($this->modulus),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    protected function keyMembers(): array
    {
        $members = [
            'n' => Base64Url::encode($this->modulus),
            'e' => Base64Url::encode($this->publicExponent),
        ];

        foreach ($this->privateMembers() as $name => $value) {
            $members[$name] = Base64Url::encode($value);
        }

        if ($this->otherPrimesInfo !== []) {
            $members['oth'] = array_map(
                static fn (OtherPrimeInfo $info): array => $info->jsonSerialize(),
                $this->otherPrimesInfo,
            );
        }

        return $members;
    }

    /**
     * @return array<string, mixed>
     */
    protected function redactedKeyMembers(): array
    {
        $members = [
            'n' => Base64Url::encode($this->modulus),
            'e' => Base64Url::encode($this->publicExponent),
        ];

        foreach (array_keys($this->privateMembers()) as $name) {
            $members[$name] = '[redacted]';
        }

        if ($this->otherPrimesInfo !== []) {
            $members['oth'] = '[redacted]';
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
     * Returns the private members that are present, by member name, in
     * the order RFC 7518 section 6.3.2 lists them
     *
     * @return array<string, string>
     */
    private function privateMembers(): array
    {
        return array_filter([
            'd' => $this->privateExponent,
            'p' => $this->firstPrimeFactor,
            'q' => $this->secondPrimeFactor,
            'dp' => $this->firstFactorCrtExponent,
            'dq' => $this->secondFactorCrtExponent,
            'qi' => $this->firstCrtCoefficient,
        ], static fn (?string $value): bool => $value !== null);
    }

    /**
     * Applies RFC 8017 section 3.1: the modulus is a product of odd primes,
     * so it is odd, and the public exponent is an odd integer of at least 3
     *
     * A key with an exponent of 1 would pass the pair check of
     * `buildPrivateOpenSslKey()`, since signing with it is the identity, so
     * it is refused here first.
     *
     * @throws InvalidJwk with `InvalidValue`
     */
    private static function checkPublicMembers(string $modulus, string $publicExponent): void
    {
        if ((ord($modulus[-1]) & 1) === 0) {
            throw new InvalidJwk(InvalidJwkReason::InvalidValue, 'The "n" member must be odd', 'n');
        }

        if ((ord($publicExponent[-1]) & 1) === 0 || $publicExponent === "\x01") {
            throw new InvalidJwk(
                InvalidJwkReason::InvalidValue,
                'The "e" member must be an odd integer of at least 3',
                'e',
            );
        }
    }

    /**
     * Applies RFC 7518 section 6.3.2: `d` is required of a private key, the
     * five optimization members come all together or not at all, and `oth`
     * needs the primes
     *
     * @throws InvalidJwk
     */
    private function checkPrivateMembers(): void
    {
        $privateMembers = $this->privateMembers();

        foreach ($privateMembers as $name => $value) {
            ByteInteger::checkRsaMember($name, $value);
        }

        $crtCount = count($privateMembers) - ($this->privateExponent === null ? 0 : 1);

        if ($crtCount !== 0 && $crtCount !== 5) {
            throw new InvalidJwk(
                InvalidJwkReason::InconsistentPrivateMembers,
                'The "p", "q", "dp", "dq", and "qi" members must be all present or all absent',
                'p',
            );
        }

        if ($this->privateExponent === null && $crtCount === 5) {
            throw new InvalidJwk(
                InvalidJwkReason::InconsistentPrivateMembers,
                'The "d" member is required when the other private members are present',
                'd',
            );
        }

        if ($this->otherPrimesInfo !== [] && $crtCount === 0) {
            throw new InvalidJwk(
                InvalidJwkReason::InconsistentPrivateMembers,
                'The "oth" member requires the "p" and "q" members',
                'oth',
            );
        }
    }

    /**
     * Builds the public key from the SubjectPublicKeyInfo the package
     * encodes, since OpenSSL's PHP binding builds no RSA key without `d`
     *
     * @throws InvalidJwk with `InvalidValue` when OpenSSL cannot read the
     *     result, which no well-formed modulus and exponent produce
     */
    private function buildPublicOpenSslKey(): OpenSSLAsymmetricKey
    {
        OpenSsl::drainErrors();
        $key = openssl_pkey_get_public(RsaPublicKeyInfo::pem($this->modulus, $this->publicExponent));

        if ($key === false) {
            throw new InvalidJwk(
                InvalidJwkReason::InvalidValue,
                'OpenSSL could not read the public key: ' . OpenSsl::drainErrors(),
                'n',
            );
        }

        return $key;
    }

    /**
     * Builds the private key, checking first that the private members
     * belong to the public ones: a signature made with `n`, `e`, and `d`
     * alone must verify under the public key, and the primes must multiply
     * to the modulus
     *
     * The CRT values are not checked. OpenSSL verifies the result of a CRT
     * signature and falls back to `d` when it is wrong, so a wrong value
     * cannot make the key sign as another key.
     *
     * @throws InvalidJwk with `KeyPairMismatch`
     */
    private function buildPrivateOpenSslKey(string $privateExponent): OpenSSLAsymmetricKey
    {
        $members = ['n' => $this->modulus, 'e' => $this->publicExponent, 'd' => $privateExponent];

        $key = OpenSsl::build(
            ['rsa' => $members],
            InvalidJwkReason::KeyPairMismatch,
            'd',
            'OpenSSL could not build a key from "n", "e", and "d"',
        );

        $signature = '';

        if (
            !@openssl_sign(self::PAIR_CHECK_MESSAGE, $signature, $key, OPENSSL_ALGO_SHA256)
            || !is_string($signature)
            || openssl_verify(self::PAIR_CHECK_MESSAGE, $signature, $this->publicOpenSslKey, OPENSSL_ALGO_SHA256) !== 1
        ) {
            OpenSsl::drainErrors();

            throw new InvalidJwk(
                InvalidJwkReason::KeyPairMismatch,
                'The "d" member does not belong to the "n" and "e" members',
                'd',
            );
        }

        $private = $this->privateMembers();

        if (!isset($private['p'])) {
            return $key;
        }

        $factors = [
            $private['p'],
            $private['q'],
            ...array_map(static fn (OtherPrimeInfo $info): string => $info->primeFactor, $this->otherPrimesInfo),
        ];

        if (ByteInteger::product($factors) !== $this->modulus) {
            throw new InvalidJwk(
                InvalidJwkReason::KeyPairMismatch,
                'The prime factors do not multiply to the "n" member',
                'p',
            );
        }

        $members += [
            'p' => $private['p'],
            'q' => $private['q'],
            'dmp1' => $private['dp'],
            'dmq1' => $private['dq'],
            'iqmp' => $private['qi'],
        ];

        // OpenSSL's PHP binding builds a key from two primes only, so a key
        // with more keeps the one built from "d", which signs without them.
        return $this->otherPrimesInfo === [] ? OpenSsl::build(
            ['rsa' => $members],
            InvalidJwkReason::KeyPairMismatch,
            'p',
            'OpenSSL could not build a key from the private members',
        ) : $key;
    }
}
