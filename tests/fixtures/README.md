# Test fixtures

Each file holds one example from the specification named by its directory,
transcribed with the line breaks the specification inserted for display
removed. The file name gives the section or appendix the example comes from.

| Directory | Source |
| --- | --- |
| `rfc7517/` | RFC 7517, JSON Web Key (JWK): the EC key of section 3, the example JWK Sets of appendix A.1, A.2, and A.3, the key with a certificate chain of appendix B, and the plaintext RSA private key of appendix C.1 |
| `rfc7638/` | RFC 7638, JSON Web Key (JWK) Thumbprint: the RSA key of section 3.1, whose SHA-256 thumbprint the section computes |
| `rfc8037/` | RFC 8037, CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE): the Ed25519 keys of appendix A.1 and A.2, and the X25519 and X448 keys of appendix A.6 and A.7 |
| `rfc7520/` | RFC 7520, Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE): the keys of section 3, and the EC keys of figures 108, 111, 120, and 122 in sections 5.4 and 5.5 |
| `rfc8410/` | RFC 8410, Algorithm Identifiers for Ed25519, Ed448, X25519, and X448 for Use in the Internet X.509 Public Key Infrastructure: the Ed25519 public key PEM of section 10.1 and the two private key PEMs of section 10.3, one without the public key and one with an attribute and the public key |
| `rfc9421/` | RFC 9421, HTTP Message Signatures, appendix B.1: the PEMs and the JWK form of `test-key-rsa` (B.1.1), `test-key-rsa-pss` (B.1.2), `test-key-ecc-p256` (B.1.3), and `test-key-ed25519` (B.1.4), plus the re-exports listed below. The RFC says these keys MUST NOT be used for any purpose other than testing |
| `generated/` | Keys and certificates generated with the `openssl` command for cases no specification example covers: `rsa-three-primes.json`, a 2048-bit RSA private key with three primes, made with `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_primes:3` and written as a JWK with its third prime in `oth`; `dsa-public.pem`, a 1024-bit DSA public key, made with `openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:1024`, `openssl genpkey -paramfile`, and `openssl pkey -pubout`; `dh-public.pem`, a DH public key in the ffdhe2048 group, made with `openssl genpkey -algorithm DH -pkeyopt group:ffdhe2048` and `openssl pkey -pubout`; `ec-p256-compressed-certificate.pem`, a self-signed certificate whose P-256 public key is a compressed point (it begins with 03), made with `openssl ecparam -name prime256v1 -genkey -noout`, `openssl ec -conv_form compressed`, and `openssl req -x509 -new -key ... -subj /CN=socialweb-jwk-test -days 36500`; and `rsa-pss-certificate.pem`, a self-signed certificate whose 2048-bit RSA key has the id-RSASSA-PSS algorithm identifier, made with `openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048` and the same `openssl req -x509` command; the test writes its modulus as a base64url literal, read with `openssl x509 -pubkey -noout | openssl rsa -pubin -modulus -noout` (the public exponent is 65537). The private keys are not kept |

The test vectors of RFC 8032 section 7 and RFC 7748 section 6, which are
hexadecimal rather than JSON, are transcribed into the tests that use them.

## The RFC 9421 re-exports

RFC 9421 gives each private key in one PEM form, and the package writes
PKCS #8 with the rsaEncryption identifier for an RSA key. The files below
were made from the RFC's PEMs with the `openssl` command so that the
package's output can be compared with OpenSSL's byte for byte.

| File | Made from | Command |
| --- | --- | --- |
| `test-key-rsa.private.pkcs8.pem` | `test-key-rsa.private.pem`, PKCS #1 | `openssl pkey -in test-key-rsa.private.pem` |
| `test-key-rsa.public.spki.pem` | `test-key-rsa.public.pem`, PKCS #1 | `openssl pkey -pubin -in test-key-rsa.public.pem` |
| `test-key-rsa-pss.private.rsa.pem` | `test-key-rsa-pss.private.pem`, PKCS #8 with the id-RSASSA-PSS identifier, which the package does not read | `openssl rsa -in test-key-rsa-pss.private.pem -traditional`, whose `RSA-PSS PRIVATE KEY` label was changed to `RSA PRIVATE KEY`, then `openssl pkey` |
| `test-key-ecc-p256.private.pkcs8.pem` | `test-key-ecc-p256.private.pem`, SEC 1 | `openssl pkey -in test-key-ecc-p256.private.pem` |
