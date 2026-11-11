<h1 align="center">socialweb/jwk</h1>

<p align="center">
    <a href="https://github.com/socialweb-php/jwk"><img src="https://img.shields.io/badge/source-socialweb/jwk-blue.svg" alt="Source Code"></a>
    <a href="https://packagist.org/packages/socialweb/jwk"><img src="https://img.shields.io/packagist/v/socialweb/jwk.svg?label=release" alt="Download Package"></a>
    <a href="https://php.net"><img src="https://img.shields.io/packagist/php-v/socialweb/jwk.svg?colorB=%238892BF" alt="PHP Programming Language"></a>
    <a href="https://github.com/socialweb-php/jwk/blob/main/COPYING.LESSER"><img src="https://img.shields.io/packagist/l/socialweb/jwk.svg?colorB=darkcyan&bust=1" alt="Read License"></a>
    <a href="https://github.com/socialweb-php/jwk/actions/workflows/continuous-integration.yml"><img src="https://img.shields.io/github/actions/workflow/status/socialweb-php/jwk/continuous-integration.yml?branch=main&logo=github" alt="Build Status"></a>
    <a href="https://codecov.io/gh/socialweb-php/jwk"><img src="https://img.shields.io/codecov/c/gh/socialweb-php/jwk?label=codecov&logo=codecov" alt="Codecov Code Coverage"></a>
</p>

## About

socialweb/jwk reads, writes, and converts JSON Web Keys (JWKs) and JWK Sets, as published in [RFC 7517][rfc7517].

Encrypting traffic with TLS keeps anyone between two applications from reading or changing what passes between them. It protects one connection at a time, though. When a message passes through a gateway, a load balancer, or a proxy that ends one TLS connection and opens another, the message is in the clear at that hop, and the receiver has no way to tell whether it changed there. HTTP Message Signatures close that gap: the sender signs the parts of the message that matter, and the receiver checks the signature with the sender's public key, however many hops lie between them.

JSON Web Keys are how senders publish those keys and receivers fetch them. A JWK is one key as JSON, and a JWK Set is the document a signer publishes with its current public keys, at a URL receivers know. OpenID Connect providers and OAuth2 authorization servers publish one at their `jwks_uri`, services within an enterprise that attach signed claims to their messages do the same, and ActivityPub servers publish a public key for each actor, most often as PEM text.

This package handles those keys. On the publishing side, it reads the private key `openssl` made, keeps the public half, and writes the set. On the receiving side, it parses a published set, refusing what the RFCs refuse so that a key object that exists is well formed, finds the key a signature names, and hands it to a verifier as the PEM text or OpenSSL key handle that library takes. It converts between PEM and JWK in both directions, so a key in either form can be published in either.

It implements the JWK and JWK Set objects of RFC 7517 and their common members, `use`, `key_ops`, `alg`, `kid`, `x5u`, `x5c`, `x5t`, and `x5t#S256`; the `RSA`, `EC`, and `oct` key types of [RFC 7518][rfc7518] section 6, the `OKP` key type of [RFC 8037][rfc8037] on `Ed25519`, `Ed448`, `X25519`, and `X448`, and the `secp256k1` curve of [RFC 8812][rfc8812]; the JWK Thumbprint of [RFC 7638][rfc7638] and the thumbprint URI of [RFC 9278][rfc9278]; and conversion between a JWK and the PEM forms OpenSSL reads and writes, in both directions, and to and from an OpenSSL key handle. A private key is checked against its public members, and members this package does not define are kept and written back, as RFC 7517 requires.

Signing and verifying belong to the library that takes the key: [socialweb/http-message-signatures][http-message-signatures] for HTTP message signatures, or any JWT library that takes a PEM key. This package depends on the OpenSSL extension and on no other package.

This project adheres to a [code of conduct](CODE_OF_CONDUCT.md). By participating in this project and its community, you are expected to uphold this code.

## Installation

Install this package as a dependency using [Composer](https://getcomposer.org).

```bash
composer require socialweb/jwk
```

## Usage

### Verifying with someone else's keys

When your application receives a signed HTTP message, a request or a response, it needs the sender's public key to check the signature. That means fetching the sender's key set, picking out the key the signature names, and handing that key to your verifier. This package does the middle step. Fetching is your HTTP client's job, and verifying is the signing library's.

`JwkSet::fromJson()` takes the JSON text of the set, the text already decoded with `json_decode()`, or an object that implements `JsonSerializable`, such as another set. Pass `publicOnly: true` when the set is someone else's: a verifier has no use for a private key or a symmetric (`oct`) key, and either one in a published set means something has gone wrong, so the parser refuses them.

A set may hold a key this package cannot use, such as a key type it does not implement. RFC 7517 says to ignore such a key and use the rest, so the parser sets it aside with its reason instead of throwing, and `$set->skipped` lists what was set aside. A verifier that wants nothing set aside checks that the list is empty.

`$keyId` is the identifier the signature names. A signer may name its key by `kid` or by thumbprint, so the example looks up both. RFC 7517 says the `kid` values in a set SHOULD be distinct, allowing a shared one only for equivalent keys of different types; the parser accepts a set where two keys share one, and `findByKeyId()` throws `AmbiguousKeyId` when it meets them. Pass a `KeyType` as the second argument to choose.

```php
use SocialWeb\Http\MessageSignatures\VerificationKey;
use SocialWeb\Jwk\JwkSet;

// The JWK Set your HTTP client fetched from the sender's site
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

foreach ($set->skipped as $skipped) {
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

`toPem()` returns the public key as a SubjectPublicKeyInfo PEM, whatever the key object holds, which is the form most libraries take. The last line builds a key for socialweb/http-message-signatures; a JWT library that verifies with a PEM public key takes the same string, and `toOpenSslKey()` returns the key as OpenSSL holds it, for code that calls the OpenSSL functions directly.

> [!NOTE]
> The example that follows is for [socialweb/http-message-signatures][http-message-signatures]. A JWT library has its own way of taking a key; give it the PEM text from `toPem()`, as the example above does.

In socialweb/http-message-signatures, that lookup belongs in a `KeyResolver`. When its verifier checks a message, it reads the key identifier from the signature and asks the resolver for the key with that identifier. The resolver below answers from a set the application fetched earlier. `$owner` is the identity the set belongs to, which the verifier reports on a verified result:

```php
use SocialWeb\Http\MessageSignatures\KeyLookup;
use SocialWeb\Http\MessageSignatures\KeyResolver;
use SocialWeb\Http\MessageSignatures\VerificationKey;
use SocialWeb\Jwk\JwkSet;

final class JwkSetKeyResolver implements KeyResolver
{
    public function __construct(
        private readonly JwkSet $set,
        private readonly string $owner,
    ) {
    }

    public function resolve(KeyLookup $lookup): ?VerificationKey
    {
        $jwk = $this->set->findByKeyId($lookup->keyId)
            ?? $this->set->findByThumbprint($lookup->keyId);

        if ($jwk === null) {
            return null;
        }

        return VerificationKey::fromPem($jwk->toPem(), owner: $this->owner);
    }

    public function refresh(KeyLookup $lookup): ?VerificationKey
    {
        return $this->resolve($lookup);
    }
}

$resolver = new JwkSetKeyResolver($set, 'https://example.com/users/amara');
```

A resolver that fetches the set itself would do so here, and `refresh()` is where it fetches again after a failure that a rotated key could explain. The README of socialweb/http-message-signatures says what the verifier checks before it asks for a key and where key policy, such as a minimum key size, belongs.

The key's members are readable after parsing: `$jwk->keyId`, `$jwk->algorithm`, `$jwk->use`, and `$jwk->keyOperations` hold the common members, each key class holds its own members as decoded bytes, and `additionalMembers()` returns the members this package does not define. The set itself is iterable and countable; `iterator_to_array($set)` gives its keys as an array.

### Publishing your keys

The other side of the exchange is your own keys. When your application signs the messages it sends, every receiver needs your public key to check them. Sending the key to each receiver ahead of time does not scale, and it breaks the moment you replace the key. So you publish it instead: your current public keys go in a JWK Set at a URL on your domain, and a receiver fetches the set when a signature of yours arrives.

Where that URL is depends on what you speak. An OpenID Connect provider or an OAuth2 authorization server lists it as `jwks_uri` in its metadata. For HTTP message signatures, the receiver's key resolver decides where to look, so pick a stable URL on your domain and name it in your documentation or in the key identifier your signatures use. Either way, the response has the media type `application/jwk-set+json`.

To build the set, read your private key, keep its public half, label it, and write the set. `Jwk::fromPem()` reads the text of a PEM file, such as the one `openssl genpkey` writes; "Generating keys" below shows how to make one. `toPublic()` returns the key with every private member removed. The `with` methods set the common members of RFC 7517, each returning a new key. `JwkSet::toJson()` writes the set with the members of each key in the order the RFCs list them.

The labels are for the receiver. `kid` is the name a signature uses to say which key signed it, so it must be unique within the set; the thumbprint is a good choice, and RFC 7638 suggests it as one. `use` says what the key is for, and `alg` which algorithm it signs with. The example publishes a current Ed25519 key beside an older RSA key, so that a message signed with either still verifies while receivers move to the new one.

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

echo $set->toJson() . "\n";
```

This prints the set on one line. With whitespace added and the RSA modulus shortened, it looks like this:

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

In a framework whose controllers return PSR-7 responses, the controller that serves the set writes that text to the response body and sets the media type. `$set` is the set built above, and `$responseFactory` is any PSR-17 response factory:

```php
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use SocialWeb\Jwk\JwkSet;

final class JwkSetController
{
    public function __construct(
        private readonly JwkSet $set,
        private readonly ResponseFactoryInterface $responseFactory,
    ) {
    }

    public function __invoke(): ResponseInterface
    {
        $response = $this->responseFactory
            ->createResponse(200)
            ->withHeader('Content-Type', 'application/jwk-set+json');
        $response->getBody()->write($this->set->toJson());

        return $response;
    }
}

$controller = new JwkSetController($set, $responseFactory);
```

Build the set once, when the application starts, rather than reading the key files on every request. A private key writes its private members, so call `toPublic()` before publishing, as the example does.

`Ed25519` is the algorithm name [RFC 9864][rfc9864] registers for signing with an Ed25519 key; `EdDSA`, the older name from RFC 8037, is deprecated by that RFC and still accepted by the parser, since this package reads what is sent. This package sets no `alg` on its own.

### Computing a thumbprint

A thumbprint is a name for a key that comes from the key itself. Two parties that hold the same public key compute the same thumbprint, whatever `kid` each gave it, so it works as a `kid` when you publish and as a lookup when a signature names a key that way. `thumbprint()` computes the JWK Thumbprint of RFC 7638, SHA-256 by default, and `thumbprintUri()` the URI form of RFC 9278. A private key gives the thumbprint of its public form. The key below is the Ed25519 public key of RFC 8037 appendix A.2, whose thumbprint appendix A.3 computes.

```php
use SocialWeb\Jwk\Jwk;

$jwk = Jwk::fromJson(<<<'JSON'
    {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
    JSON);

echo $jwk->thumbprint() . "\n";
echo $jwk->thumbprintUri() . "\n";
```

This prints:

```text
kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
urn:ietf:params:oauth:jwk-thumbprint:sha-256:kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
```

The thumbprint is computed from the parsed values, so whitespace and member order in the input do not change it. `HashAlgorithm::Sha384` and `Sha512` are accepted as the argument of both methods.

> [!WARNING]
> The thumbprint of an `oct` key is a hash of the key value itself and reveals information about the key, as RFC 7638 section 7 warns. Compute one only where the key is strong enough that the hash gives nothing away.

### Loading a key you were given

Keys reach an application in several forms: a file `openssl` wrote, a key another library already holds, a JWK in a request, or a published set.

`Jwk::fromPem()` reads every form `openssl` writes: a PKCS #8 private key, encrypted or not, a PKCS #1 `RSA PRIVATE KEY`, a SEC 1 `EC PRIVATE KEY`, a SubjectPublicKeyInfo `PUBLIC KEY`, a PKCS #1 `RSA PUBLIC KEY`, and a certificate, whose public key is read. `Jwk::fromOpenSslKey()` reads a key your code already holds as an `OpenSSLAsymmetricKey`.

- A key is given as PEM text, never as a path. Read the file yourself, as the examples do; a string that begins with `file://` is refused.
- An encrypted PEM needs its passphrase as the second argument: `Jwk::fromPem($pem, $passphrase)`. Without it, or with the wrong one, the key is refused as `ConversionFailed` with the reason `UnreadablePem`. A text that holds both a certificate and a private key that cannot be decrypted is refused the same way, not read for its certificate.
- A PKCS #8 private key that includes its public key, the version 2 form of RFC 5958, is read with OpenSSL 3.5.0 or later; an older OpenSSL refuses it as `UnreadablePem`. `openssl genpkey` writes the version 1 form, without the public key, which every OpenSSL reads.
- A DSA or DH key, an EC key on a curve this package does not implement, and an RSA key under the id-RSASSA-PSS algorithm identifier are refused as `ConversionFailed` with the reason `UnsupportedKey`.

`Jwk::fromJson()` and `JwkSet::fromJson()` take JSON text, the text already decoded with `json_decode()`, with or without `associative: true`, or an object that implements `JsonSerializable`, which is read as what its `jsonSerialize()` returns, so a key reads from another key. When a JSON object has two members with one name, PHP's parser keeps the lexically last, and so does this package, in a JWK and in a JWK Set alike; RFC 7517 allows either that or a refusal.

A refusal names what was wrong. A key that is not well formed is `InvalidJwk` with an `InvalidJwkReason` case and, when one member is at fault, its name; a set object that is not well formed, such as one without a `keys` member, is `InvalidJwkSet` with an `InvalidJwkSetReason` case. Every exception the package throws implements `SocialWeb\Jwk\Exception\JwkException`, so one `catch` covers them all. A value that JSON cannot hold at all, such as an object of a class other than `stdClass` or a closure, is a mistake in your code rather than in the document, and raises `InvalidArgument` before any member is read.

RFC 7517 and RFC 7518 say a few things a producer SHOULD or SHOULD NOT do that a parser cannot act on without changing the key, and this package accepts them as sent, without record: `use` and `key_ops` present together, which RFC 7517 section 4.3 says SHOULD NOT be used together, as long as they agree; a `key_ops` list that combines unrelated operations, such as `sign` with `encrypt`, which the same section says SHOULD NOT be used; an RSA private key with `d` alone, without the primes RFC 7518 section 6.3.2 says SHOULD be included; and the `EdDSA` algorithm name, which RFC 9864 deprecates. The one that does leave a trace is the `kid` values of a set, which RFC 7517 section 4.5 says SHOULD be distinct: the parser accepts a set where two keys share one, and `findByKeyId()` throws `AmbiguousKeyId` when it meets them, as "Verifying with someone else's keys" says.

### Storing a private key as a PEM file

Some keys reach your application as a JWK: a key service hands one out, or another application stored its key that way. OpenSSL and the tools built on it read keys from PEM files. `toPrivatePem()` writes a private key as PKCS #8, the form `openssl genpkey` writes, encrypted with AES-256-CBC when you give it a passphrase, and `Jwk::fromPem()` reads the file back with the same passphrase. The key below is the Ed25519 private key of RFC 8037 appendix A.1, and `$passphrase` is the passphrase your application gets from an environment variable.

```php
use SocialWeb\Jwk\Jwk;

$privateKey = Jwk::fromJson(<<<'JSON'
    {
        "kty": "OKP",
        "crv": "Ed25519",
        "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
    JSON);

file_put_contents('/etc/example/keys/ed25519.pem', $privateKey->toPrivatePem($passphrase));

$storedKey = Jwk::fromPem(file_get_contents('/etc/example/keys/ed25519.pem'), $passphrase);

echo $storedKey->thumbprint() . "\n";
```

This prints the thumbprint of the key read from the file, the one RFC 8037 appendix A.3 computes for this key:

```text
kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
```

- Without a passphrase, `toPrivatePem()` writes the key unencrypted. An empty string is refused as `InvalidArgument`; pass `null` for no encryption. Keep the file readable only by the user your application runs as.
- `toPem()` writes the public key as a SubjectPublicKeyInfo PEM.
- An RSA private key whose private members are `d` alone cannot be written as PKCS #8, which holds the primes, and is refused as `ConversionFailed` with the reason `MissingCrtMembers`; `toOpenSslKey()` still returns such a key, and it signs.
- An `oct` key has no PEM form.

### Generating keys

This package never generates a key. `openssl genpkey` does, and this package reads what it writes. Each command below makes one private key of a different type; run the one for the algorithm you sign with, and ignore the others. An RSA key signs with `RS256` and the other RSA algorithms, an EC key on P-256 with `ES256`, and an Ed25519 key with `Ed25519`. One key is enough; the publishing example holds two only to show a key being replaced.

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out p256.pem
openssl genpkey -algorithm Ed25519 -out ed25519.pem
```

Each command writes an unencrypted PKCS #8 private key. Keep the file outside the web root, readable only by the user your application runs as. Add `-aes-256-cbc` to encrypt it with a passphrase that `openssl` asks for; `fromPem()` then takes the passphrase as its second argument. Give the passphrase to your application through an environment variable, not in its code or configuration files. The public form to publish comes from `fromPem()` and `toPublic()`:

```php
use SocialWeb\Jwk\Jwk;

$privateKey = Jwk::fromPem(file_get_contents('/etc/example/keys/ed25519.pem'));

echo $privateKey->toPublic()->toJson() . "\n";
```

This prints a key like this:

```json
{"kty":"OKP","crv":"Ed25519","x":"HdIujjJCS1emHacaH_QNs_RVOSo3_S1-KBTvUpAuusg"}
```

### Private keys and debugging output

`var_dump()` and `print_r()` show a key with its private members redacted, and `serialize()` refuses a key. `var_export()` and an `(array)` cast bypass that and show the private members; do not log a key through either. The JSON form from `toJson()` is the serialization, and `fromJson()` the way back.

## Contributing

Contributions are welcome! To contribute, please familiarize yourself with [CONTRIBUTING.md](CONTRIBUTING.md).

## Coordinated vulnerability disclosure policy

Keeping user information safe and secure is a top priority, and we welcome the contribution of external security researchers. If you believe you've found a security issue in software that is maintained in this repository, please read [SECURITY.md](SECURITY.md) for instructions on submitting a vulnerability report.

## Copyright and license

socialweb/jwk is copyright © socialweb/jwk Contributors and licensed for use under the terms of the GNU Lesser General Public License (LGPL-3.0-or-later) as published by the Free Software Foundation. Please see [COPYING.LESSER](COPYING.LESSER), [COPYING](COPYING), and [NOTICE](NOTICE) for more information.

[rfc7517]: https://www.rfc-editor.org/rfc/rfc7517
[rfc7518]: https://www.rfc-editor.org/rfc/rfc7518
[rfc8037]: https://www.rfc-editor.org/rfc/rfc8037
[rfc8812]: https://www.rfc-editor.org/rfc/rfc8812
[rfc7638]: https://www.rfc-editor.org/rfc/rfc7638
[rfc9278]: https://www.rfc-editor.org/rfc/rfc9278
[rfc9864]: https://www.rfc-editor.org/rfc/rfc9864
[http-message-signatures]: https://github.com/socialweb-php/http-message-signatures
