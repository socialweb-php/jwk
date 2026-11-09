# RFC examples

The files in these directories are the example keys the RFCs print, kept so that the tests compare the package against the RFCs' own values. Each file holds one example, named for the section or appendix it comes from, with the line breaks the RFC inserted for display removed and nothing else changed. They are not part of the library, and they are left out of distribution archives.

| Directory | Source | License |
| --- | --- | --- |
| `rfc7517/` | [RFC 7517, JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517): the EC key of section 3, the example JWK Sets of appendix A.1, A.2, and A.3, the key with a certificate chain of appendix B, and the plaintext RSA private key of appendix C.1 | [IETF Trust Legal Provisions][tlp] |
| `rfc7520/` | [RFC 7520, Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)](https://www.rfc-editor.org/rfc/rfc7520): the keys of section 3, and the EC keys of figures 108, 111, 120, and 122 in sections 5.4 and 5.5 | [IETF Trust Legal Provisions][tlp] |
| `rfc7638/` | [RFC 7638, JSON Web Key (JWK) Thumbprint](https://www.rfc-editor.org/rfc/rfc7638): the RSA key of section 3.1, whose SHA-256 thumbprint the section computes | [IETF Trust Legal Provisions][tlp] |
| `rfc8037/` | [RFC 8037, CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)](https://www.rfc-editor.org/rfc/rfc8037): the Ed25519 keys of appendix A.1 and A.2, and the X25519 and X448 keys of appendix A.6 and A.7 | [IETF Trust Legal Provisions][tlp] |
| `rfc8410/` | [RFC 8410, Algorithm Identifiers for Ed25519, Ed448, X25519, and X448 for Use in the Internet X.509 Public Key Infrastructure](https://www.rfc-editor.org/rfc/rfc8410): the Ed25519 public key PEM of section 10.1 and the two private key PEMs of section 10.3, one without the public key and one with an attribute and the public key, a OneAsymmetricKey of version 2 (RFC 5958), which OpenSSL reads from release 3.5.0 | [IETF Trust Legal Provisions][tlp] |
| `rfc9421/` | [RFC 9421, HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421), appendix B.1: the PEMs and the JWK form of `test-key-rsa` (B.1.1), `test-key-rsa-pss` (B.1.2), `test-key-ecc-p256` (B.1.3), and `test-key-ed25519` (B.1.4). The RFC says these keys MUST NOT be used for any purpose other than testing | [IETF Trust Legal Provisions][tlp] |

[`manifest.json`](manifest.json) records the rest for each set: the RFC's URL and title, its copyright line, the license, the date the examples were transcribed, the sections and appendices they come from, and one SHA-256 checksum for the whole set.

The RFC text is copyright the IETF Trust and the document authors, under the IETF Trust Legal Provisions. None of these sets is a conformance suite, so no license here restricts changes to material used for a conformance claim; the files are kept as transcribed so that the tests check the RFCs' own values, and a test that needs a key no RFC prints uses a generated one from `tests/fixtures/generated/` instead.

The test vectors of RFC 8032 section 7 and RFC 7748 section 6, which are hexadecimal rather than JSON, are transcribed into the tests that use them. Files the package's own commands made, such as PEM re-exports and generated keys, are under `tests/fixtures/`, whose `README.md` gives the commands.

## Checking the examples

Run this from the root of the repository:

```bash
composer check-fixtures
```

It makes the checksum of each set again and compares it with the one in the manifest. A job in the continuous integration workflow runs the same check on every pull request and push to the main branch.

A checksum that differs from the one in the manifest means that a file has changed since it was transcribed. If this happens, restore the file from the RFC. Do not record a new checksum unless an example is being added or corrected on purpose, and say so in the commit.

## How the checksums are made

Each checksum is one SHA-256 value that covers a whole set of files. It changes if the content of any file changes, if a file is renamed, or if a file is added to or removed from the directory.

It is made in four steps:

1. List every file in the set's directory, by its path from that directory, with `./` in front.
2. Sort the paths byte by byte (`LC_ALL=C`), so that the order is the same on every system.
3. Compute the SHA-256 of each file, which gives one line for each file: the value, two spaces, and the path.
4. Compute the SHA-256 of those lines. That value is the checksum.

`bin/check-fixtures.php` does this in PHP. The same checksum can be made without it. For `rfc7517/`:

```bash
(cd resources/rfc7517 && find . -type f | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256)
```

The command prints the checksum, followed by two spaces and a hyphen.

[tlp]: https://trustee.ietf.org/documents/trust-legal-provisions/
