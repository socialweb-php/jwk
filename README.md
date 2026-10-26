<h1 align="center">socialweb/jwk</h1>

<p align="center">
    <a href="https://github.com/socialweb-php/jwk"><img src="https://img.shields.io/badge/source-socialweb/jwk-blue.svg?style=flat-square" alt="Source Code"></a>
    <a href="https://packagist.org/packages/socialweb/jwk"><img src="https://img.shields.io/packagist/v/socialweb/jwk.svg?style=flat-square&label=release" alt="Download Package"></a>
    <a href="https://php.net"><img src="https://img.shields.io/packagist/php-v/socialweb/jwk.svg?style=flat-square&colorB=%238892BF" alt="PHP Programming Language"></a>
    <a href="https://github.com/socialweb-php/jwk/blob/main/COPYING.LESSER"><img src="https://img.shields.io/packagist/l/socialweb/jwk.svg?style=flat-square&colorB=darkcyan" alt="Read License"></a>
    <a href="https://github.com/socialweb-php/jwk/actions/workflows/continuous-integration.yml"><img src="https://img.shields.io/github/actions/workflow/status/socialweb-php/jwk/continuous-integration.yml?branch=main&style=flat-square&logo=github" alt="Build Status"></a>
    <a href="https://codecov.io/gh/socialweb-php/jwk"><img src="https://img.shields.io/codecov/c/gh/socialweb-php/jwk?label=codecov&logo=codecov&style=flat-square" alt="Codecov Code Coverage"></a>
</p>

## About

socialweb/jwk reads, writes, and converts JSON Web Keys (JWKs) and JWK Sets,
as published in [RFC 7517][rfc7517]. It implements:

- the JWK and JWK Set objects and their common members, `use`, `key_ops`,
  `alg`, `kid`, `x5u`, `x5c`, `x5t`, and `x5t#S256` (RFC 7517);
- the `RSA`, `EC`, and `oct` key types of [RFC 7518][rfc7518] section 6, the
  `OKP` key type of [RFC 8037][rfc8037] on `Ed25519`, `Ed448`, `X25519`, and
  `X448`, and the `secp256k1` curve of [RFC 8812][rfc8812];
- the JWK Thumbprint of [RFC 7638][rfc7638] and the thumbprint URI of
  [RFC 9278][rfc9278]; and
- conversion between a JWK and the PEM forms OpenSSL reads and writes, in both
  directions, and to and from an OpenSSL key handle.

The parser is strict. It refuses what the RFCs refuse, such as a padded
base64url value, a non-minimal integer, or an EC point that is not on its
curve, and it names the member and the reason. A private key is checked
against its public members, so a key object that exists is a key object that
is well formed. Members the package does not define are kept and written back,
as RFC 7517 requires. The package depends on the OpenSSL extension and on no
other package.

Not included, by design: fetching a JWK Set or the certificates behind `x5u`,
generating keys (the `openssl` commands are in "Generating keys" below),
encrypted JWKs and JWK Sets (JWE), signing, verifying, or encrypting with a
key, validating a certificate chain, a policy on key sizes and algorithms,
and choosing a key from a set by `use`, `alg`, or `key_ops`.

This project adheres to a [code of conduct](CODE_OF_CONDUCT.md).
By participating in this project and its community, you are expected to
uphold this code.

## Installation

Install this package as a dependency using [Composer](https://getcomposer.org).

```bash
composer require socialweb/jwk
```

## Usage

### Reading a JWK Set and picking a key for a verifier

`JwkSet::fromJson()` takes the JSON text of a set, or the text already decoded
with `json_decode()`. With `publicOnly: true`, a member with a private member
and a symmetric (`oct`) key are refused, which is what a verifier wants. A
member the parser cannot use is set aside with its reason, not thrown, and the
rest of the set is usable; `skipped()` lists what was set aside. A verifier
that wants nothing set aside checks that the list is empty.

`$keyId` is the key identifier a signature names. A signer may name a key by
its `kid` or by its thumbprint, so the example looks up both. `findByKeyId()`
throws `AmbiguousKeyId` when two keys share a `kid`, which RFC 7517 allows for
keys of different types; pass a `KeyType` as the second argument to choose.

```php
use SocialWeb\Http\MessageSignatures\VerificationKey;
use SocialWeb\Jwk\JwkSet;

$json = <<<'JSON'
    {
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                "kid": "2026-10"
            },
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            },
            {
                "kty": "AKP",
                "kid": "pq-1"
            }
        ]
    }
    JSON;

$set = JwkSet::fromJson($json, publicOnly: true);

foreach ($set->skipped() as $skipped) {
    echo "Skipped key {$skipped->index}: {$skipped->cause->reason->name}\n";
}

$keyId = 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k';
$jwk = $set->findByKeyId($keyId) ?? $set->findByThumbprint($keyId);

if ($jwk === null) {
    echo "No usable public key for {$keyId}\n";
    exit;
}

echo $jwk->toPem();

$verificationKey = VerificationKey::fromPem($jwk->toPem());
```

This prints:

```text
Skipped key 2: UnsupportedKeyType
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
-----END PUBLIC KEY-----
```

`toPem()` returns the public key as a SubjectPublicKeyInfo PEM, whatever the
key object holds, which is the form most libraries take. The last line builds
a key for [socialweb/http-message-signatures][http-message-signatures], one
such library; any other that verifies with a PEM public key takes the same
string, and `toOpenSslKey()` returns the key as OpenSSL holds it for code
that calls the OpenSSL functions directly.

The key's members are readable after parsing: `$jwk->keyId`, `$jwk->algorithm`,
`$jwk->use`, and `$jwk->keyOperations` hold the common members, each key class
holds its own members as decoded bytes, and `additionalMembers()` returns the
members the package does not define.

### Publishing a set from PEM files

`Jwk::fromPem()` reads a private or public key from PEM text; "Generating
keys" below makes the two files. `toPublic()` removes every private member and
keeps every common member, and the `with` methods set the common members, each
returning a new key. `toJson()` writes the set as RFC 7517 writes it, with the
members of each key in the order the RFCs list them.

```php
use SocialWeb\Jwk\Jwk;
use SocialWeb\Jwk\JwkSet;
use SocialWeb\Jwk\KeyUse;

$signing = Jwk::fromPem(file_get_contents('/etc/example/keys/ed25519.pem'));
$legacy = Jwk::fromPem(file_get_contents('/etc/example/keys/rsa.pem'));

$set = new JwkSet([
    $signing->toPublic()
        ->withKeyId($signing->thumbprint())
        ->withAlgorithm('Ed25519')
        ->withUse(KeyUse::Signature),
    $legacy->toPublic()
        ->withKeyId('2026-10')
        ->withAlgorithm('RS256')
        ->withUse(KeyUse::Signature),
]);

echo $set->toJson(), "\n";
```

This prints the set on one line. With whitespace added and the RSA modulus
shortened, it looks like this:

```json
{
    "keys": [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "HdIujjJCS1emHacaH_QNs_RVOSo3_S1-KBTvUpAuusg",
            "use": "sig",
            "alg": "Ed25519",
            "kid": "dbI0N0QpamDhcInuOQDRKbve8kP_fUH-3udA4nVZeBQ"
        },
        {
            "kty": "RSA",
            "n": "kufUKmyuBF6zl82CXxYx7JsgB_HrCCFClTFlMBPLMWf6jXK_8wMBknrZ...",
            "e": "AQAB",
            "use": "sig",
            "alg": "RS256",
            "kid": "2026-10"
        }
    ]
}
```

Serve that text with the media type `application/jwk-set+json`. A private key
writes its private members, so call `toPublic()` before publishing, as the
example does.

`Ed25519` is the algorithm name [RFC 9864][rfc9864] registers for signing with
an Ed25519 key; `EdDSA`, the older name from RFC 8037, is deprecated by that
RFC and still accepted by the parser, since the package reads what is sent.
The package sets no `alg` on its own.

### Computing a thumbprint

`thumbprint()` computes the JWK Thumbprint of RFC 7638, SHA-256 by default,
and `thumbprintUri()` the URI form of RFC 9278. A private key gives the
thumbprint of its public form. The key below is the Ed25519 public key of
RFC 8037 appendix A.2, whose thumbprint appendix A.3 computes.

```php
use SocialWeb\Jwk\Jwk;

$jwk = Jwk::fromJson(<<<'JSON'
    {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
    JSON);

echo $jwk->thumbprint(), "\n";
echo $jwk->thumbprintUri(), "\n";
```

This prints:

```text
kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
urn:ietf:params:oauth:jwk-thumbprint:sha-256:kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
```

The thumbprint is computed from the parsed values, so whitespace and member
order in the input do not change it. `HashAlgorithm::Sha384` and `Sha512` are
accepted as the argument of both methods.

> [!WARNING]
> The thumbprint of an `oct` key is a hash of the key value itself and reveals
> information about the key, as RFC 7638 section 7 warns. Compute one only
> where the key is strong enough that the hash gives nothing away.

### Reading keys

`Jwk::fromPem()` reads every form `openssl` writes: a PKCS #8 private key,
encrypted or not, a PKCS #1 `RSA PRIVATE KEY`, a SEC 1 `EC PRIVATE KEY`, a
SubjectPublicKeyInfo `PUBLIC KEY`, a PKCS #1 `RSA PUBLIC KEY`, and a
certificate, whose public key is read. `Jwk::fromOpenSslKey()` reads a key
your code already holds as an `OpenSSLAsymmetricKey`.

- A key is given as PEM text, never as a path. Read the file yourself, as the
  examples do; a string that begins with `file://` is refused.
- An encrypted PEM needs its passphrase as the second argument:
  `Jwk::fromPem($pem, $passphrase)`. Without it, or with the wrong one, the
  key is refused as `ConversionFailed` with the reason `UnreadablePem`, and
  the process never stops to ask for a passphrase. A text that holds both a
  certificate and a private key that cannot be decrypted is refused the same
  way, not read for its certificate.
- A PKCS #8 private key that includes its public key, the version 2 form of
  RFC 5958, is read with OpenSSL 3.5.0 or later; an older OpenSSL refuses it
  as `UnreadablePem`. `openssl genpkey` writes the version 1 form, without the
  public key, which every OpenSSL reads.
- A DSA or DH key, an EC key on a curve the package does not implement, and
  an RSA key under the id-RSASSA-PSS algorithm identifier are refused as
  `ConversionFailed` with the reason `UnsupportedKey`.

`Jwk::fromJson()` and `JwkSet::fromJson()` take JSON text, or the text already
decoded with `json_decode()`, with or without `associative: true`. When a JSON
object has two members with one name, PHP's parser keeps the lexically last,
and so does the package, in a JWK and in a JWK Set alike; RFC 7517 allows
either that or a refusal. Every refusal is `InvalidJwk` with an
`InvalidJwkReason` case and, when one member is at fault, its name, or
`InvalidJwkSet` for a set object that is not well formed. Every exception the
package throws implements `SocialWeb\Jwk\Exception\JwkException`.

### Writing keys

`toPem()` writes the public key as a SubjectPublicKeyInfo PEM.
`toPrivatePem()` writes the private key as PKCS #8, unencrypted, or encrypted
with AES-256-CBC when a passphrase is given: `$jwk->toPrivatePem($passphrase)`.
An RSA private key whose private members are `d` alone cannot be written as
PKCS #8, which holds the primes, and is refused as `ConversionFailed` with the
reason `MissingCrtMembers`; `toOpenSslKey()` still returns such a key, and it
signs. An `oct` key has no PEM form.

### Private keys and debugging output

`var_dump()` and `print_r()` show a key with its private members redacted, and
`serialize()` refuses a key. `var_export()` and an `(array)` cast bypass that
and show the private members; do not log a key through either. The JSON form
from `toJson()` is the serialization, and `fromJson()` the way back.

## Generating keys

The package never generates a key. Make one with `openssl genpkey`, which
writes an unencrypted PKCS #8 private key:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out p256.pem
openssl genpkey -algorithm Ed25519 -out ed25519.pem
```

Add `-aes-256-cbc` to encrypt the file with a passphrase that `openssl` asks
for; `fromPem()` then needs the passphrase as its second argument. The private
file belongs outside the web root, readable by the user your application runs
as and nobody else, which is how `openssl genpkey` creates it. The package only
ever reads it. The public form to publish comes from `fromPem()` and
`toPublic()`:

```php
use SocialWeb\Jwk\Jwk;

$privateKey = Jwk::fromPem(file_get_contents('/etc/example/keys/ed25519.pem'));

echo $privateKey->toPublic()->toJson(), "\n";
```

This prints a key like this:

```json
{"kty":"OKP","crv":"Ed25519","x":"HdIujjJCS1emHacaH_QNs_RVOSo3_S1-KBTvUpAuusg"}
```

## Contributing

Contributions are welcome! To contribute, please familiarize yourself with
[CONTRIBUTING.md](CONTRIBUTING.md).

## Coordinated disclosure

Keeping user information safe and secure is a top priority, and we welcome the
contribution of external security researchers. If you believe you've found a
security issue in software that is maintained in this repository, please read
[SECURITY.md](SECURITY.md) for instructions on submitting a vulnerability report.

## Copyright and license

socialweb/jwk is copyright © socialweb/jwk Contributors and licensed for use
under the terms of the GNU Lesser General Public License (LGPL-3.0-or-later) as
published by the Free Software Foundation. Please see
[COPYING.LESSER](COPYING.LESSER), [COPYING](COPYING), and [NOTICE](NOTICE) for
more information.

[rfc7517]: https://www.rfc-editor.org/rfc/rfc7517
[rfc7518]: https://www.rfc-editor.org/rfc/rfc7518
[rfc8037]: https://www.rfc-editor.org/rfc/rfc8037
[rfc8812]: https://www.rfc-editor.org/rfc/rfc8812
[rfc7638]: https://www.rfc-editor.org/rfc/rfc7638
[rfc9278]: https://www.rfc-editor.org/rfc/rfc9278
[rfc9864]: https://www.rfc-editor.org/rfc/rfc9864
[http-message-signatures]: https://github.com/socialweb-php/http-message-signatures
