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
use SocialWeb\Jwk\Exception\ConversionFailed;
use SocialWeb\Jwk\Exception\ConversionFailedReason;
use SocialWeb\Jwk\Exception\InvalidArgument;
use SocialWeb\Jwk\Exception\InvalidJwk;
use SocialWeb\Jwk\Exception\InvalidJwkReason;
use stdClass;

use function array_is_list;
use function array_unique;
use function base64_decode;
use function count;
use function hash;
use function hash_equals;
use function in_array;
use function is_string;
use function json_encode;
use function sprintf;
use function strlen;
use function strspn;

use const JSON_PRESERVE_ZERO_FRACTION;
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
 *
 * Every string a key holds is valid UTF-8 and every number is finite, so
 * that every key can be written as JSON text. A constructor or `with`
 * method given a string that is not valid UTF-8 throws `InvalidJwk` with
 * the reason `InvalidValue` naming the member.
 */
abstract readonly class Jwk implements JsonSerializable
{
    /**
     * The member names RFC 7517 section 4 defines, in the order the
     * package writes them
     */
    private const array COMMON_MEMBER_NAMES = ['kty', 'use', 'key_ops', 'alg', 'kid', 'x5u', 'x5c', 'x5t', 'x5t#S256'];

    /**
     * The alphabet of standard base64 with padding, RFC 4648 section 4,
     * which the `x5c` entries use
     */
    private const string BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

    /**
     * Every member the package does not define, in the order received,
     * with each JSON object in a value as a `stdClass` and each JSON array
     * as a PHP list, as `json_decode()` gives them by default
     *
     * The key's own objects never leave it: `additionalMembers()`,
     * `jsonSerialize()`, and `__debugInfo()` return copies.
     *
     * @var array<string, mixed>
     */
    private array $additionalMembers;

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
     *     package does not define, as decoded JSON; a JSON object is a
     *     `stdClass` or a PHP array that is not a list, and a JSON array is
     *     a PHP list
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
        array $additionalMembers,
    ) {
        $members = [];

        /** @var mixed $value */
        foreach ($additionalMembers as $name => $value) {
            $name = (string) $name;
            $this->checkAdditionalMemberName($name);
            $members[$name] = JsonValue::read($name, $value);
        }

        $this->additionalMembers = $members;
        $this->checkCommonMembers();
    }

    /**
     * Parses a JWK from JSON text or from a value the text was already
     * decoded into, and returns the key class for its `kty`
     *
     * A decoded value is an array or a tree of `stdClass` objects, as
     * `json_decode()` gives either. In an array, a PHP array that is a
     * list, including an empty array, is a JSON array, and any other PHP
     * array is a JSON object.
     *
     * With `$publicOnly`, a key with a private member is refused with the
     * reason `PrivateMembersPresent`, and an `oct` key with `SymmetricKey`,
     * since a symmetric key is never public.
     *
     * @param string | array<array-key, mixed> | stdClass $json
     *
     * @throws InvalidJwk when the input is not a well-formed JWK of a type
     *     the package implements; the reason says which rule it broke
     */
    public static function fromJson(
        #[SensitiveParameter] string | array | stdClass $json,
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
     * Reads a key from PEM text, private when the text holds a private key
     *
     * Every form OpenSSL writes is read: a PKCS #8 private key, encrypted
     * or not, a PKCS #1 `RSA PRIVATE KEY`, a SEC 1 `EC PRIVATE KEY`, a
     * SubjectPublicKeyInfo `PUBLIC KEY`, a PKCS #1 `RSA PUBLIC KEY`, and a
     * certificate, whose public key is read. The key has no common member;
     * the `with` methods add them. A passphrase given for a key that is not
     * encrypted is ignored.
     *
     * @throws InvalidArgument when the text starts with `file://`, which
     *     OpenSSL would read as the path of a local file
     * @throws ConversionFailed with `UnreadablePem` when OpenSSL reads no key
     *     from the text, including an encrypted key given without its
     *     passphrase or with a wrong one, even when the text also holds a
     *     certificate or a public key; or with `UnsupportedKey` as
     *     `fromOpenSslKey()` does
     * @throws InvalidJwk as `fromOpenSslKey()` does
     */
    public static function fromPem(
        #[SensitiveParameter] string $pem,
        #[SensitiveParameter] ?string $passphrase = null,
    ): RsaKey | EcKey | OkpKey {
        return self::fromOpenSslKey(OpenSsl::readPem($pem, $passphrase));
    }

    /**
     * Reads a key OpenSSL holds, private when the key is private
     *
     * The members come from `openssl_pkey_get_details()`, and the key
     * object is built from them as a parsed key is, so every rule of a
     * parsed key applies. The key has no common member.
     *
     * @throws ConversionFailed with `UnsupportedKey` for a key type the
     *     package does not implement, such as DSA, DH, or an RSA key with
     *     the id-RSASSA-PSS algorithm identifier, whose members OpenSSL does
     *     not report; or for an EC curve the package does not implement
     * @throws InvalidJwk when the key breaks a rule a parsed key must keep,
     *     such as an RSA public exponent of 1
     */
    public static function fromOpenSslKey(#[SensitiveParameter] OpenSSLAsymmetricKey $key): RsaKey | EcKey | OkpKey
    {
        return OpenSslKeyReader::read($key);
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
     * Returns the public key as a SubjectPublicKeyInfo PEM, whatever the key
     * holds
     *
     * The PEM is OpenSSL's, in the strict form of RFC 7468 section 3.
     *
     * @throws ConversionFailed with `SymmetricKey` for an `oct` key, which
     *     has no PEM form, or with `MultiPrimeKey` for an RSA key with more
     *     than two primes
     */
    public function toPem(): string
    {
        $key = $this->publicOpenSslKey() ?? throw new ConversionFailed(
            ConversionFailedReason::SymmetricKey,
            'A symmetric key has no PEM form',
        );

        return OpenSsl::publicPem($key);
    }

    /**
     * Returns the private key as a PKCS #8 PEM, encrypted with AES-256-CBC
     * when a passphrase is given
     *
     * @throws InvalidArgument for an empty passphrase, which would encrypt
     *     the key with an empty password; `null` asks for no encryption
     * @throws ConversionFailed with `SymmetricKey` for an `oct` key; with
     *     `NotAPrivateKey` for a public key; with `MissingCrtMembers` for
     *     an RSA key whose private members are `d` alone, which PKCS #8
     *     cannot hold; or with `MultiPrimeKey` for an RSA key with more than
     *     two primes
     */
    public function toPrivatePem(#[SensitiveParameter] ?string $passphrase = null): string
    {
        if ($passphrase === '') {
            throw new InvalidArgument('The passphrase must not be empty; pass null for an unencrypted PEM');
        }

        if (!$this->isPrivate()) {
            throw new ConversionFailed(ConversionFailedReason::NotAPrivateKey, 'A public key has no private PEM form');
        }

        return OpenSsl::privatePem($this->toOpenSslKey(), $passphrase);
    }

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
     * a caller publishes one. The additional members are a copy, as
     * `additionalMembers()` returns them.
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->serializeMembers($this->keyMembers());
    }

    /**
     * Returns the JWK as JSON text
     *
     * A number with a zero fraction, such as `1.0`, is written as it was
     * received, not as an integer.
     *
     * Every key the package accepts can be written: its strings are valid
     * UTF-8, its numbers are finite, and its nesting is no deeper than
     * `json_decode()` reads.
     */
    public function toJson(): string
    {
        return json_encode($this, JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
    }

    /**
     * Returns the key with the `kid` member replaced, or removed for `null`
     *
     * @throws InvalidJwk with `InvalidValue` for an empty string, which
     *     RFC 7517 gives no meaning, or for a string that is not valid UTF-8
     */
    public function withKeyId(?string $keyId): static
    {
        return $this->withCommonMembers(['keyId' => $keyId]);
    }

    /**
     * Returns the key with the `alg` member replaced, or removed for `null`
     *
     * @throws InvalidJwk with `AlgorithmDoesNotFitKey` for a registered
     *     algorithm the key cannot run, or with `InvalidValue` for a string
     *     that is not valid UTF-8
     */
    public function withAlgorithm(?string $algorithm): static
    {
        return $this->withCommonMembers(['algorithm' => $algorithm]);
    }

    /**
     * Returns the key with the `use` member replaced, or removed for `null`
     *
     * @throws InvalidJwk with `InconsistentUseAndKeyOperations` when the
     *     use disagrees with the key's operations, or with `InvalidValue`
     *     for a string that is not valid UTF-8
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
     *     operation; with `InconsistentUseAndKeyOperations` when an
     *     operation disagrees with the key's use; or with `InvalidValue`
     *     for an operation that is not valid UTF-8
     */
    public function withKeyOperations(array $keyOperations): static
    {
        return $this->withCommonMembers(['keyOperations' => self::normalizeKeyOperations($keyOperations)]);
    }

    /**
     * Returns the key with the `x5u` member replaced, or removed for `null`
     *
     * @throws InvalidJwk with `InvalidValue` for a string that is not valid
     *     UTF-8
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
     *
     * @throws InvalidJwk with `WrongType` when the chain is not a list of
     *     strings, with `InvalidValue` for a string that is not valid
     *     UTF-8, or with `InvalidCertificate`, `CertificateKeyMismatch`, or
     *     `CertificateThumbprintMismatch` as the certificate members require
     */
    public function withCertificateChain(array $certificateChain): static
    {
        return $this->withCommonMembers(['certificateChain' => $certificateChain]);
    }

    /**
     * Returns the key with the `x5t` member replaced, or removed for `null`
     *
     * @throws InvalidJwk with `InvalidValue` for a string that is not valid
     *     UTF-8, or with `InvalidCertificate`, `CertificateKeyMismatch`, or
     *     `CertificateThumbprintMismatch` as the certificate members require
     */
    public function withCertificateSha1Thumbprint(?string $thumbprint): static
    {
        return $this->withCommonMembers(['certificateSha1Thumbprint' => $thumbprint]);
    }

    /**
     * Returns the key with the `x5t#S256` member replaced, or removed for
     * `null`
     *
     * @throws InvalidJwk with `InvalidValue` for a string that is not valid
     *     UTF-8, or with `InvalidCertificate`, `CertificateKeyMismatch`, or
     *     `CertificateThumbprintMismatch` as the certificate members require
     */
    public function withCertificateSha256Thumbprint(?string $thumbprint): static
    {
        return $this->withCommonMembers(['certificateSha256Thumbprint' => $thumbprint]);
    }

    /**
     * Returns every member the package does not define, in the order
     * received
     *
     * Each JSON object in a value is a `stdClass` and each JSON array a PHP
     * list, as `json_decode()` gives them by default. The members are a
     * copy: changing them, or an object inside them, does not change the
     * key.
     *
     * @return array<string, mixed>
     */
    public function additionalMembers(): array
    {
        $members = [];

        /** @var mixed $value */
        foreach ($this->additionalMembers as $name => $value) {
            $name = (string) $name;
            $members[$name] = JsonValue::read($name, $value);
        }

        return $members;
    }

    /**
     * Returns the key with an additional member added or replaced
     *
     * The value is kept as `json_decode()` gives a JSON value by default: a
     * JSON object as a `stdClass` and a JSON array as a PHP list. A PHP
     * array that is a list, including an empty array, is a JSON array, and
     * any other PHP array is a JSON object, which the key keeps as a
     * `stdClass`.
     *
     * @throws InvalidArgument when the name is one the package defines for
     *     this key, which the typed members hold instead
     * @throws InvalidJwk when the name or the value is one JSON text cannot
     *     hold, as `fromJson()` refuses it: with `MalformedJson` for a member
     *     name that starts with a NUL byte or is not valid UTF-8, or for
     *     nesting deeper than `json_decode()` reads; with `InvalidValue`
     *     naming the member for a string that is not valid UTF-8 or a number
     *     that is not finite; or with `WrongType` naming the member for a
     *     value of a PHP type that is not a JSON type
     */
    public function withAdditionalMember(string $name, mixed $value): static
    {
        $this->checkAdditionalMemberName($name);

        $members = $this->additionalMembers;
        $members[$name] = JsonValue::read($name, $value);

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
     * Refuses PHP unserialization, which would build a key without checking
     * its members; `fromJson()` is the way back from the JSON form
     *
     * @param array<array-key, mixed> $data
     */
    public function __unserialize(array $data): void
    {
        throw new LogicException('A JWK cannot be unserialized with unserialize(); use Jwk::fromJson()');
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
     * Returns the public key as OpenSSL holds it, or `null` for an `oct`
     * key, which has none
     */
    abstract protected function publicOpenSslKey(): ?OpenSSLAsymmetricKey;

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
     * The type of the list is checked here, before the list is rebuilt,
     * so that a key built in code is refused as a parsed one is.
     *
     * @param list<KeyOperation | string> $keyOperations
     *
     * @return list<string>
     *
     * @throws InvalidJwk with `WrongType` when the operations are not a
     *     list of strings and `KeyOperation` cases
     */
    protected static function normalizeKeyOperations(array $keyOperations): array
    {
        if (!array_is_list($keyOperations)) {
            throw self::notAStringList('key_ops');
        }

        $operations = [];

        foreach ($keyOperations as $operation) {
            if ($operation instanceof KeyOperation) {
                $operation = $operation->value;
            }

            if (!is_string($operation)) {
                throw self::notAStringList('key_ops');
            }

            $operations[] = $operation;
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
        if (!array_is_list($this->certificateChain)) {
            throw self::notAStringList('x5c');
        }

        foreach ($this->certificateChain as $certificate) {
            if (!is_string($certificate)) {
                throw self::notAStringList('x5c');
            }
        }

        $strings = [
            'use' => $this->use,
            'key_ops' => $this->keyOperations,
            'alg' => $this->algorithm,
            'kid' => $this->keyId,
            'x5u' => $this->certificateUrl,
            'x5c' => $this->certificateChain,
            'x5t' => $this->certificateSha1Thumbprint,
            'x5t#S256' => $this->certificateSha256Thumbprint,
        ];

        foreach ($strings as $name => $value) {
            JsonValue::check($name, $value);
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

        $this->checkCertificateMembers();
    }

    /**
     * Applies RFC 7517 sections 4.7 to 4.9 to the certificate members: every
     * `x5c` entry decodes, the first holds this key, and `x5t` and
     * `x5t#S256`, when present beside `x5c`, are its digests
     *
     * The key of the certificate is compared with this key by RFC 7638
     * thumbprint, so a certificate that writes an EC point in a different
     * form, such as the compressed form of RFC 5480 section 2.2, still
     * holds the key. A certificate key the package cannot read, such as an
     * RSA key with the id-RSASSA-PSS algorithm identifier, is a different
     * key.
     *
     * Without `x5c`, the thumbprints are kept as received, since the
     * certificate they describe is not at hand.
     *
     * @throws InvalidJwk with `InvalidCertificate`, `CertificateKeyMismatch`,
     *     or `CertificateThumbprintMismatch`
     */
    private function checkCertificateMembers(): void
    {
        if ($this->certificateChain === []) {
            return;
        }

        $certificates = [];

        foreach ($this->certificateChain as $index => $entry) {
            $certificates[] = self::decodeCertificate($index + 1, $entry);
        }

        $der = $certificates[0];
        $certificateKey = OpenSsl::certificatePublicKey(
            $der,
            'The first entry of the "x5c" member is not a DER certificate OpenSSL reads',
            'x5c',
        );
        if ($this->publicOpenSslKey() === null) {
            throw new InvalidJwk(
                InvalidJwkReason::CertificateKeyMismatch,
                'The "x5c" member holds a certificate, and a symmetric key has no public key for one to hold',
                'x5c',
            );
        }

        try {
            $certificateThumbprint = self::fromOpenSslKey($certificateKey)->thumbprint();
        } catch (ConversionFailed | InvalidJwk) {
            $certificateThumbprint = null;
        }

        if ($certificateThumbprint === null || !hash_equals($this->thumbprint(), $certificateThumbprint)) {
            throw new InvalidJwk(
                InvalidJwkReason::CertificateKeyMismatch,
                'The first certificate of the "x5c" member holds a different key',
                'x5c',
            );
        }

        self::checkCertificateThumbprint('x5t', $this->certificateSha1Thumbprint, 'sha1', 'SHA-1', $der);
        self::checkCertificateThumbprint('x5t#S256', $this->certificateSha256Thumbprint, 'sha256', 'SHA-256', $der);
    }

    /**
     * Returns the DER an `x5c` entry encodes
     *
     * RFC 7517 section 4.7 encodes each entry in the base64 of RFC 4648
     * section 4: the standard alphabet, padded to a multiple of four
     * characters, with no line breaks.
     *
     * @param int $position The entry's position, counted from 1, for the
     *     message
     *
     * @throws InvalidJwk with `InvalidCertificate`
     */
    private static function decodeCertificate(int $position, string $entry): string
    {
        $der = strspn($entry, self::BASE64_ALPHABET) === strlen($entry) && strlen($entry) % 4 === 0
            ? base64_decode($entry, true)
            : false;

        if ($der === false || $der === '') {
            throw new InvalidJwk(
                InvalidJwkReason::InvalidCertificate,
                sprintf('Entry %d of the "x5c" member is not a certificate in standard base64 with padding', $position),
                'x5c',
            );
        }

        return $der;
    }

    /**
     * @param string $algorithm The name `hash()` knows the digest by
     * @param string $digestName The digest as the message names it
     * @param string $der The first certificate of `x5c`
     *
     * @throws InvalidJwk with `CertificateThumbprintMismatch`
     */
    private static function checkCertificateThumbprint(
        string $member,
        ?string $thumbprint,
        string $algorithm,
        string $digestName,
        string $der,
    ): void {
        if ($thumbprint !== null && !hash_equals(Base64Url::encode(hash($algorithm, $der, true)), $thumbprint)) {
            throw new InvalidJwk(
                InvalidJwkReason::CertificateThumbprintMismatch,
                sprintf(
                    'The "%s" member is not the %s digest of the first certificate of the "x5c" member',
                    $member,
                    $digestName,
                ),
                $member,
            );
        }
    }

    /**
     * @throws InvalidArgument when the name is one the package defines for
     *     this key, which the typed members hold instead
     * @throws InvalidJwk with `MalformedJson` for a name that JSON text
     *     cannot hold
     */
    private function checkAdditionalMemberName(string $name): void
    {
        JsonValue::checkName($name, null);

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
        foreach ($this->additionalMembers() as $name => $value) {
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

    private static function notAStringList(string $member): InvalidJwk
    {
        return new InvalidJwk(
            InvalidJwkReason::WrongType,
            sprintf('The "%s" member must be a list of strings', $member),
            $member,
        );
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
