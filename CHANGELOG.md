# socialweb/jwk Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 - TBD

### Added

- `Jwk` and its four key classes `RsaKey`, `EcKey`, `OkpKey`, and `OctKey`, which parse a JSON Web Key of RFC 7517 from JSON text or a decoded value, check every member as the RFCs require, keep the members the package does not define, and write the key back with its members in the order the RFCs list them. `RsaKey`, `EcKey`, and `OctKey` implement the key types of RFC 7518 section 6, `OkpKey` the `OKP` type of RFC 8037 on `Ed25519`, `Ed448`, `X25519`, and `X448`, and `EcKey` also the `secp256k1` curve of RFC 8812. A private key's private members are checked against its public ones, and `fromJson()` with `publicOnly: true` refuses a private key and a symmetric key.
- On every key, `toPublic()`, the `with` methods for the common members, `jsonSerialize()` and `toJson()`, and `thumbprint()` and `thumbprintUri()`, the JWK Thumbprint of RFC 7638 and the URI of RFC 9278, with SHA-256 by default and `HashAlgorithm` for the other two.
- `Jwk::fromPem()`, `Jwk::fromOpenSslKey()`, `toPem()`, `toPrivatePem()`, and `toOpenSslKey()`, which convert between a key and the PEM forms OpenSSL reads and writes, and an OpenSSL key handle. A private PEM is written as PKCS #8, encrypted with AES-256-CBC when a passphrase is given.
- The `x5c`, `x5t`, and `x5t#S256` members, checked against the first certificate of the chain when `x5c` is present; `x5u` is kept and never fetched.
- `JwkSet`, the JWK Set of RFC 7517 section 5, which parses every member it can use and sets the rest aside as `SkippedKey` values with the reason, with `findByKeyId()`, `findAllByKeyId()`, `findByThumbprint()`, `withKey()`, and `withoutKey()`.
- The enums `KeyType`, `Curve`, `KeyUse`, `KeyOperation`, and `HashAlgorithm`, and `OtherPrimeInfo` for the `oth` member of an RSA key.
- Exceptions under `SocialWeb\Jwk\Exception`, every one implementing the `JwkException` marker interface: `InvalidArgument`, `InvalidJwk` with an `InvalidJwkReason` case and the member it names, `InvalidJwkSet`, `ConversionFailed` with a `ConversionFailedReason` case, and `AmbiguousKeyId`.

### Changed

- Nothing.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- Nothing.
