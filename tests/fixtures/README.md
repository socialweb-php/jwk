# Test fixtures

The files under `generated/` were made with the `openssl` command, for cases no RFC example covers or for a form of an RFC key that the package's output is compared with byte for byte. The example keys the RFCs print are under `resources/` at the root of the repository, with a manifest and a `README.md` of their own.

## Generated keys and certificates

| File | Command |
| --- | --- |
| `rsa-three-primes.json` | A 2048-bit RSA private key with three primes, made with `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_primes:3` and written as a JWK with its third prime in `oth` |
| `dsa-public.pem` | A 1024-bit DSA public key, made with `openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:1024`, `openssl genpkey -paramfile`, and `openssl pkey -pubout` |
| `dh-public.pem` | A DH public key in the ffdhe2048 group, made with `openssl genpkey -algorithm DH -pkeyopt group:ffdhe2048` and `openssl pkey -pubout` |
| `ec-p256-compressed-certificate.pem` | A self-signed certificate whose P-256 public key is a compressed point (it begins with 03), made with `openssl ecparam -name prime256v1 -genkey -noout`, `openssl ec -conv_form compressed`, and `openssl req -x509 -new -key ... -subj /CN=socialweb-jwk-test -days 36500` |
| `rsa-pss-certificate.pem` | A self-signed certificate whose 2048-bit RSA key has the id-RSASSA-PSS algorithm identifier, made with `openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048` and the same `openssl req -x509` command; the test writes its modulus as a base64url literal, read with `openssl x509 -pubkey -noout | openssl rsa -pubin -modulus -noout` (the public exponent is 65537) |

The private keys behind the certificates and the DSA and DH keys are not kept.

## The RFC 9421 re-exports

RFC 9421 gives each private key in one PEM form, and the package writes PKCS #8 with the rsaEncryption identifier for an RSA key. The files below were made from the RFC's PEMs in `resources/rfc9421/` with the `openssl` command so that the package's output can be compared with OpenSSL's byte for byte.

| File | Made from | Command |
| --- | --- | --- |
| `test-key-rsa.private.pkcs8.pem` | `test-key-rsa.private.pem`, PKCS #1 | `openssl pkey -in test-key-rsa.private.pem` |
| `test-key-rsa.public.spki.pem` | `test-key-rsa.public.pem`, PKCS #1 | `openssl pkey -pubin -in test-key-rsa.public.pem` |
| `test-key-rsa-pss.private.rsa.pem` | `test-key-rsa-pss.private.pem`, PKCS #8 with the id-RSASSA-PSS identifier, which the package does not read | `openssl rsa -in test-key-rsa-pss.private.pem -traditional`, whose `RSA-PSS PRIVATE KEY` label was changed to `RSA PRIVATE KEY`, then `openssl pkey` |
| `test-key-ecc-p256.private.pkcs8.pem` | `test-key-ecc-p256.private.pem`, SEC 1 | `openssl pkey -in test-key-ecc-p256.private.pem` |
