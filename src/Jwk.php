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

use JsonSerializable;
use LogicException;
use OpenSSLAsymmetricKey;
use SensitiveParameter;
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;

use function array_keys;
use function array_unique;
use function count;
use function hash;
use function in_array;
use function json_encode;
use function sprintf;
use function strlen;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * A JSON Web Key, per RFC 7517: one cryptographic key as a JSON object
 *
 * This class holds the members common to every key type, which RFC 7517
 * section 4 defines, and the operations every key type shares. The key
 * material is in the subclass for the key type: `RsaKey`, `EcKey`,
 * `OkpKey`, or `OctKey`.
 *
 * A key is immutable. The `with` methods return a new key with one member
 * changed, checked the way parsing checks it.
 */
abstract readonly class Jwk implements JsonSerializable
{
    /**
     * The member names RFC 7517 section 4 defines, in the order the
     * package writes them
     */
    private const array COMMON_MEMBER_NAMES = ['kty', 'use', 'key_ops', 'alg', 'kid', 'x5u', 'x5c', 'x5t', 'x5t#S256'];

    /**
     * @param ?string $keyId The `kid` member
     * @param ?string $algorithm The `alg` member, kept as a string because
     *     the registry is open
     * @param ?string $use The `use` member, kept as a string for the same
     *     reason; `KeyUse` names the registered values
     * @param list<string> $keyOperations The `key_ops` member;
     *     `KeyOperation` names the registered values
     * @param ?string $certificateUrl The `x5u` member
     * @param list<string> $certificateChain The `x5c` member, each entry
     *     the standard base64 text as received
     * @param ?string $certificateSha1Thumbprint The `x5t` member
     * @param ?string $certificateSha256Thumbprint The `x5t#S256` member
     * @param array<string, mixed> $additionalMembers Every member the
     *     package does not define, as decoded JSON
     *
     * @throws InvalidArgument when an additional member is named after a member
     *     the key type defines
     */
    protected function __construct(
        public ?string $keyId,
        public ?string $algorithm,
        public ?string $use,
        public array $keyOperations,
        public ?string $certificateUrl,
        public array $certificateChain,
        public ?string $certificateSha1Thumbprint,
        public ?string $certificateSha256Thumbprint,
        public array $additionalMembers,
    ) {
        $this->checkCommonMembers();
    }

    /**
     * Parses a JWK from JSON text or from an array the text was already
     * decoded into, and returns the key class for its `kty`
     *
     * With `$publicOnly`, a key with a private member is refused with the
     * reason `PrivateMembersPresent`, and an `oct` key with `SymmetricKey`,
     * since a symmetric key is never public.
     *
     * @param string | array<array-key, mixed> $json
     *
     * @throws InvalidJwk when the input is not a well-formed JWK of a type
     *     the package implements; the reason says which rule it broke
     */
    public static function fromJson(
        #[SensitiveParameter] string | array $json,
        bool $publicOnly = false,
    ): RsaKey | EcKey | OkpKey | OctKey {
        $members = MemberReader::fromJson($json);
        $kty = $members->requiredString('kty');
        $keyType = KeyType::tryFrom($kty) ?? throw new InvalidJwk(
            InvalidJwkReason::UnsupportedKeyType,
            sprintf('The key type "%s" is not implemented; the package implements RSA, EC, OKP, and oct', $kty),
            'kty',
        );

        if ($publicOnly) {
            self::refusePrivateMembers($members, $keyType);
        }

        return match ($keyType) {
            KeyType::Rsa => RsaKey::fromMembers($members),
            KeyType::Ec => EcKey::fromMembers($members),
            KeyType::Okp => OkpKey::fromMembers($members),
            KeyType::Oct => OctKey::fromMembers($members),
        };
    }

    /**
     * Returns the key type, the `kty` member
     */
    abstract public function keyType(): KeyType;

    /**
     * Returns whether the key holds private members; an `oct` key always
     * does, since a symmetric key is never public
     */
    abstract public function isPrivate(): bool;

    /**
     * Returns the same key with every private member removed and every
     * common member kept
     *
     * @throws Exception\ConversionFailed with `SymmetricKey` for an `oct`
     *     key, which has no public form
     */
    abstract public function toPublic(): static;

    /**
     * Returns the key as OpenSSL holds it, private when the key is private
     *
     * The key was built while parsing, so this costs nothing more; it is the
     * handle a signer or verifier takes instead of a PEM.
     *
     * @throws Exception\ConversionFailed with `SymmetricKey` for an `oct`
     *     key, or with `MultiPrimeKey` for an RSA key with more than two
     *     primes, which OpenSSL's PHP binding does not build
     */
    abstract public function toOpenSslKey(): OpenSSLAsymmetricKey;

    /**
     * Returns the RFC 7638 thumbprint of the key: the required members of
     * its public form, as compact JSON in lexicographic order, hashed, and
     * written as base64url without padding
     *
     * A private key gives the thumbprint of its public form, per RFC 7638
     * section 3.2.1.
     */
    public function thumbprint(HashAlgorithm $hash = HashAlgorithm::Sha256): string
    {
        $input = json_encode($this->thumbprintMembers(), JSON_THROW_ON_ERROR);

        return Base64Url::encode(hash($hash->hashName(), $input, true));
    }

    /**
     * Returns the RFC 9278 URI of the thumbprint:
     * `urn:ietf:params:oauth:jwk-thumbprint:` followed by the hash's
     * registered name, a colon, and the thumbprint
     */
    public function thumbprintUri(HashAlgorithm $hash = HashAlgorithm::Sha256): string
    {
        return sprintf('urn:ietf:params:oauth:jwk-thumbprint:%s:%s', $hash->value, $this->thumbprint($hash));
    }

    /**
     * Returns the JWK as RFC 7517 writes it: `kty`, the key type's members
     * in their RFC's order, the common members in RFC 7517's order, then
     * the additional members as received
     *
     * A private key writes its private members; `toPublic()` first is how
     * a caller publishes one.
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->serializeMembers($this->keyMembers());
    }

    /**
     * Returns the JWK as JSON text
     */
    public function toJson(): string
    {
        return json_encode($this, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    /**
     * Returns the key with the `kid` member replaced, or removed for `null`
     *
     * @throws InvalidJwk with `InvalidValue` for an empty string, which
     *     RFC 7517 gives no meaning
     */
    public function withKeyId(?string $keyId): static
    {
        return $this->withCommonMembers(['keyId' => $keyId]);
    }

    /**
     * Returns the key with the `alg` member replaced, or removed for `null`
     *
     * @throws InvalidJwk with `AlgorithmDoesNotFitKey` for a registered
     *     algorithm the key cannot run
     */
    public function withAlgorithm(?string $algorithm): static
    {
        return $this->withCommonMembers(['algorithm' => $algorithm]);
    }

    /**
     * Returns the key with the `use` member replaced, or removed for `null`
     *
     * @throws InvalidJwk with `InconsistentUseAndKeyOperations` when the
     *     use disagrees with the key's operations
     */
    public function withUse(KeyUse | string | null $use): static
    {
        return $this->withCommonMembers(['use' => self::normalizeUse($use)]);
    }

    /**
     * Returns the key with the `key_ops` member replaced, or removed for an
     * empty list
     *
     * @param list<KeyOperation | string> $keyOperations
     *
     * @throws InvalidJwk with `DuplicateKeyOperation` for a repeated
     *     operation, or with `InconsistentUseAndKeyOperations` when an
     *     operation disagrees with the key's use
     */
    public function withKeyOperations(array $keyOperations): static
    {
        return $this->withCommonMembers(['keyOperations' => self::normalizeKeyOperations($keyOperations)]);
    }

    /**
     * Returns the key with the `x5u` member replaced, or removed for `null`
     */
    public function withCertificateUrl(?string $certificateUrl): static
    {
        return $this->withCommonMembers(['certificateUrl' => $certificateUrl]);
    }

    /**
     * Returns the key with the `x5c` member replaced, or removed for an
     * empty list
     *
     * @param list<string> $certificateChain
     */
    public function withCertificateChain(array $certificateChain): static
    {
        return $this->withCommonMembers(['certificateChain' => $certificateChain]);
    }

    /**
     * Returns the key with the `x5t` member replaced, or removed for `null`
     */
    public function withCertificateSha1Thumbprint(?string $thumbprint): static
    {
        return $this->withCommonMembers(['certificateSha1Thumbprint' => $thumbprint]);
    }

    /**
     * Returns the key with the `x5t#S256` member replaced, or removed for
     * `null`
     */
    public function withCertificateSha256Thumbprint(?string $thumbprint): static
    {
        return $this->withCommonMembers(['certificateSha256Thumbprint' => $thumbprint]);
    }

    /**
     * Returns the key with an additional member added or replaced
     *
     * @throws InvalidArgument when the name is one the package defines for
     *     this key, which the typed members hold instead
     */
    public function withAdditionalMember(string $name, mixed $value): static
    {
        $this->checkAdditionalMemberName($name);

        $members = $this->additionalMembers;
        $members[$name] = $value;

        return clone($this, ['additionalMembers' => $members]);
    }

    /**
     * Returns the key without the additional member, or the same key when
     * it has no such member
     */
    public function withoutAdditionalMember(string $name): static
    {
        $members = $this->additionalMembers;
        unset($members[$name]);

        return clone($this, ['additionalMembers' => $members]);
    }

    /**
     * Returns what `var_dump()` and `print_r()` show: the public form, with
     * every private member redacted
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return $this->serializeMembers($this->redactedKeyMembers());
    }

    /**
     * Refuses PHP serialization, which would write private members to a
     * string the caller did not ask for; the JSON form is the serialization
     *
     * @return array{}
     */
    public function __serialize(): array
    {
        throw new LogicException('A JWK cannot be serialized with serialize(); use toJson()');
    }

    /**
     * Returns the required members of the public form, in lexicographic
     * order, each as the string the hash input holds
     *
     * @return array<string, string>
     */
    abstract protected function thumbprintMembers(): array;

    /**
     * Returns the key type's members as the JSON form writes them, private
     * members included, in the order the key type's RFC lists them
     *
     * @return array<string, mixed>
     */
    abstract protected function keyMembers(): array;

    /**
     * Returns the key type's members with every private member redacted
     *
     * @return array<string, mixed>
     */
    abstract protected function redactedKeyMembers(): array;

    /**
     * Returns the names of the key type's own members, which the typed
     * properties hold
     *
     * @return non-empty-list<string>
     */
    abstract protected function keyMemberNames(): array;

    /**
     * Returns the curve of an `EC` or `OKP` key, or `null`
     */
    protected function curve(): ?Curve
    {
        return null;
    }

    /**
     * Reads the common members for a key class's constructor, as named
     * arguments
     *
     * @param non-empty-list<string> $keyMemberNames The key type's own
     *     member names, so that the rest are additional members
     *
     * @return array{
     *     keyId: ?string,
     *     algorithm: ?string,
     *     use: ?string,
     *     keyOperations: list<string>,
     *     certificateUrl: ?string,
     *     certificateChain: list<string>,
     *     certificateSha1Thumbprint: ?string,
     *     certificateSha256Thumbprint: ?string,
     *     additionalMembers: array<string, mixed>,
     * }
     */
    protected static function commonArguments(
        #[SensitiveParameter] MemberReader $members,
        array $keyMemberNames,
    ): array {
        return [
            'keyId' => $members->string('kid'),
            'algorithm' => $members->string('alg'),
            'use' => $members->string('use'),
            'keyOperations' => $members->stringList('key_ops'),
            'certificateUrl' => $members->string('x5u'),
            'certificateChain' => $members->stringList('x5c'),
            'certificateSha1Thumbprint' => $members->string('x5t'),
            'certificateSha256Thumbprint' => $members->string('x5t#S256'),
            'additionalMembers' => $members->except([...self::COMMON_MEMBER_NAMES, ...$keyMemberNames]),
        ];
    }

    /**
     * Checks that a byte-string member has the length its curve fixes
     *
     * @throws InvalidJwk with `WrongLength`
     */
    protected static function checkLength(
        string $member,
        #[SensitiveParameter] string $bytes,
        int $length,
        Curve $curve,
    ): void {
        if (strlen($bytes) !== $length) {
            throw new InvalidJwk(
                InvalidJwkReason::WrongLength,
                sprintf(
                    'The "%s" member must decode to %d bytes for the curve %s, not %d',
                    $member,
                    $length,
                    $curve->value,
                    strlen($bytes),
                ),
                $member,
            );
        }
    }

    /**
     * Returns the `use` value as the string the member holds
     */
    protected static function normalizeUse(KeyUse | string | null $use): ?string
    {
        return $use instanceof KeyUse ? $use->value : $use;
    }

    /**
     * Returns the operations as the strings the member holds
     *
     * @param list<KeyOperation | string> $keyOperations
     *
     * @return list<string>
     */
    protected static function normalizeKeyOperations(array $keyOperations): array
    {
        $operations = [];

        foreach ($keyOperations as $operation) {
            $operations[] = $operation instanceof KeyOperation ? $operation->value : $operation;
        }

        return $operations;
    }

    /**
     * Applies the rules of RFC 7517 sections 4.3 to 4.5 to the common
     * members, as parsing and the `with` methods both do
     *
     * @throws InvalidJwk
     * @throws InvalidArgument when an additional member is named after a member
     *     the key type defines
     */
    private function checkCommonMembers(): void
    {
        foreach (array_keys($this->additionalMembers) as $name) {
            $this->checkAdditionalMemberName((string) $name);
        }

        if ($this->keyId === '') {
            throw new InvalidJwk(InvalidJwkReason::InvalidValue, 'The "kid" member must not be empty', 'kid');
        }

        if (count(array_unique($this->keyOperations)) !== count($this->keyOperations)) {
            throw new InvalidJwk(
                InvalidJwkReason::DuplicateKeyOperation,
                'The "key_ops" member must not list an operation twice',
                'key_ops',
            );
        }

        $use = $this->use === null ? null : KeyUse::tryFrom($this->use);

        foreach ($this->keyOperations as $name) {
            $operation = KeyOperation::tryFrom($name);

            if ($use !== null && $operation !== null && $operation->keyUse() !== $use) {
                throw new InvalidJwk(
                    InvalidJwkReason::InconsistentUseAndKeyOperations,
                    sprintf('The "use" value "%s" is not consistent with the "key_ops" value "%s"', $this->use, $name),
                    'key_ops',
                );
            }
        }

        if ($this->algorithm !== null && !AlgorithmFit::fits($this->algorithm, $this->keyType(), $this->curve())) {
            throw new InvalidJwk(
                InvalidJwkReason::AlgorithmDoesNotFitKey,
                sprintf('The algorithm "%s" does not fit %s', $this->algorithm, $this->describeType()),
                'alg',
            );
        }
    }

    /**
     * @throws InvalidArgument when the name is one the package defines for
     *     this key, which the typed members hold instead
     */
    private function checkAdditionalMemberName(string $name): void
    {
        if (in_array($name, $this->definedMemberNames(), true)) {
            throw new InvalidArgument(
                sprintf('The "%s" member is defined for this key type and is not an additional member', $name),
            );
        }
    }

    /**
     * @param array<string, mixed> $changes
     */
    private function withCommonMembers(array $changes): static
    {
        $key = clone($this, $changes);
        $key->checkCommonMembers();

        return $key;
    }

    /**
     * @param array<string, mixed> $keyMembers
     *
     * @return array<string, mixed>
     */
    private function serializeMembers(array $keyMembers): array
    {
        $json = ['kty' => $this->keyType()->value, ...$keyMembers];

        $common = [
            'use' => $this->use,
            'key_ops' => $this->keyOperations === [] ? null : $this->keyOperations,
            'alg' => $this->algorithm,
            'kid' => $this->keyId,
            'x5u' => $this->certificateUrl,
            'x5c' => $this->certificateChain === [] ? null : $this->certificateChain,
            'x5t' => $this->certificateSha1Thumbprint,
            'x5t#S256' => $this->certificateSha256Thumbprint,
        ];

        foreach ($common as $name => $value) {
            if ($value !== null) {
                $json[$name] = $value;
            }
        }

        /** @var mixed $value */
        foreach ($this->additionalMembers as $name => $value) {
            $json[$name] = $value;
        }

        return $json;
    }

    /**
     * @return non-empty-list<string>
     */
    private function definedMemberNames(): array
    {
        return [...self::COMMON_MEMBER_NAMES, ...$this->keyMemberNames()];
    }

    private function describeType(): string
    {
        $curve = $this->curve();

        return $curve === null
            ? sprintf('an %s key', $this->keyType()->value)
            : sprintf('an %s key on the curve %s', $this->keyType()->value, $curve->value);
    }

    /**
     * @throws InvalidJwk with `SymmetricKey` or `PrivateMembersPresent`
     */
    private static function refusePrivateMembers(#[SensitiveParameter] MemberReader $members, KeyType $keyType): void
    {
        if ($keyType === KeyType::Oct) {
            throw new InvalidJwk(
                InvalidJwkReason::SymmetricKey,
                'A symmetric key was given where only a public key is accepted',
                'kty',
            );
        }

        foreach ($keyType->privateMemberNames() as $name) {
            if ($members->has($name)) {
                throw new InvalidJwk(
                    InvalidJwkReason::PrivateMembersPresent,
                    sprintf('The "%s" member is a private member, and only a public key is accepted', $name),
                    $name,
                );
            }
        }
    }
}
