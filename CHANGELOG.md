# socialweb/jwk Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `InvalidJwkSetReason`, a pure enum with the cases `MalformedJson`, `NotAnObject`, `MissingKeysMember`, and `KeysNotAnArray`, and `InvalidJwkSet::$reason`, which holds the case for the refusal.
- `InvalidJwkReason::EmptyKeyOperations`, `EmptyCertificateChain`, and `EmptyOtherPrimesInfo`. A `key_ops`, `x5c`, or `oth` member that is an empty array is refused with the matching case, where it was read and written back as absent.
- `Jwk::fromJson()` and `JwkSet::fromJson()` accept an object that implements `JsonSerializable`, read as what its `jsonSerialize()` returns, so a key or a set reads from another key or set.
- `JwkSet::$skipped`, the public list of the members `fromJson()` set aside, in place of `skipped()`.
- `OtherPrimeInfo::toJson()`.

### Changed

- A value of a PHP type JSON cannot hold, such as an object of a class other than `stdClass`, a closure, or a resource, given anywhere in the input of `fromJson()`, a constructor, or `withAdditionalMember()`, raises `InvalidArgument` before any member is read. It was `InvalidJwk` with `WrongType`, in a set a skipped key, and at the top level of a set `InvalidJwkSet`.
- A `keyOperations`, `certificateChain`, or `otherPrimesInfo` constructor argument that is not a list of the right type, the same arguments of `Jwk::withKeyOperations()` and `Jwk::withCertificateChain()`, and a `keys` argument of `new JwkSet()` that is not a list of `Jwk` objects, raise `InvalidArgument`. They were `InvalidJwk` with `WrongType` and `InvalidJwkSet`.
- The `InvalidJwkSet` constructor takes an `InvalidJwkSetReason` first, then the message, then an optional previous throwable. It took a message, a code, and an optional previous throwable, so code that constructs the exception itself must pass a reason.
- A string that is not valid UTF-8 or a number that is not finite is refused as `InvalidJwk` with `MalformedJson`, where it was `InvalidValue`; in a member of a set other than `keys`, as `InvalidJwkSet` with `MalformedJson`.
- `toJson()` on a key, a set, and an `oth` entry writes a character outside ASCII as itself rather than as a `\u` escape.
- `Curve::fromOpensslCurveName()` is `tryFromOpenSslCurveName()`, `fromOpensslKeyType()` is `tryFromOpenSslKeyType()`, `opensslCurveName()` is `openSslCurveName()`, `opensslKeyType()` is `openSslKeyType()`, and `opensslDetailsKey()` is `openSslDetailsKey()`.
- The `AmbiguousKeyId` message starts with the key identifier, `Key identifier "1" names 2 keys; pass the key type to choose among them`, and the `ConversionFailed` message for an EC curve the package does not implement quotes the curve name.

### Removed

- `JwkSet::keys()`. Iterate the set, or call `iterator_to_array()` on it.
- `JwkSet::skipped()`, replaced by the `$skipped` property.

### Fixed

- `JwkSet::toJson()` writes a set whose key has members nested as deep as `fromJson()` accepts, and `JwkSet::fromJson()` reads it back; both threw at the default depth of `json_encode()` and `json_decode()`.
- The OpenSSL error queue is cleared before and read after every OpenSSL call, so a failure reports its own errors and never one left by an earlier call.

## [0.1.0] - 2026-11-01

### Added

- `Jwk` and its four key classes `RsaKey`, `EcKey`, `OkpKey`, and `OctKey`, which parse a JSON Web Key of RFC 7517 from JSON text or a decoded value, check every member as the RFCs require, keep the members the package does not define, and write the key back with its members in the order the RFCs list them. `RsaKey`, `EcKey`, and `OctKey` implement the key types of RFC 7518 section 6, `OkpKey` the `OKP` type of RFC 8037 on `Ed25519`, `Ed448`, `X25519`, and `X448`, and `EcKey` also the `secp256k1` curve of RFC 8812. A private key's private members are checked against its public ones, and `fromJson()` with `publicOnly: true` refuses a private key and a symmetric key.
- On every key, `toPublic()`, the `with` methods for the common members, `jsonSerialize()` and `toJson()`, and `thumbprint()` and `thumbprintUri()`, the JWK Thumbprint of RFC 7638 and the URI of RFC 9278, with SHA-256 by default and `HashAlgorithm` for the other two.
- `Jwk::fromPem()`, `Jwk::fromOpenSslKey()`, `toPem()`, `toPrivatePem()`, and `toOpenSslKey()`, which convert between a key and the PEM forms OpenSSL reads and writes, and an OpenSSL key handle. A private PEM is written as PKCS #8, encrypted with AES-256-CBC when a passphrase is given.
- The `x5c`, `x5t`, and `x5t#S256` members, checked against the first certificate of the chain when `x5c` is present; `x5u` is kept and never fetched.
- `JwkSet`, the JWK Set of RFC 7517 section 5, which parses every member it can use and sets the rest aside as `SkippedKey` values with the reason, with `findByKeyId()`, `findAllByKeyId()`, `findByThumbprint()`, `withKey()`, and `withoutKey()`.
- The enums `KeyType`, `Curve`, `KeyUse`, `KeyOperation`, and `HashAlgorithm`, and `OtherPrimeInfo` for the `oth` member of an RSA key.
- Exceptions under `SocialWeb\Jwk\Exception`, every one implementing the `JwkException` marker interface: `InvalidArgument`, `InvalidJwk` with an `InvalidJwkReason` case and the member it names, `InvalidJwkSet`, `ConversionFailed` with a `ConversionFailedReason` case, and `AmbiguousKeyId`.

[unreleased]: https://github.com/socialweb-php/jwk/compare/0.1.0...HEAD
[0.1.0]: https://github.com/socialweb-php/jwk/commits/0.1.0/
