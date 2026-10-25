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
| `generated/` | Keys generated with the `openssl` command for cases no specification example covers: `rsa-three-primes.json`, a 2048-bit RSA private key with three primes, made with `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_primes:3` and written as a JWK with its third prime in `oth` |

The test vectors of RFC 8032 section 7 and RFC 7748 section 6, which are
hexadecimal rather than JSON, are transcribed into the tests that use them.
