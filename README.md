# x509-verif: X.509 Certificate Verification Tool

A command-line utility for verifying X.509 digital certificates against trusted anchor certificates. This tool leverages the robust parsing capabilities of [x509-parser](https://github.com/camelot-os/x509-parser) and the cryptographic verification features of [libecc](https://github.com/libecc/libecc).

## Features

- **X.509 Certificate Verification**: Validates certificates against trusted anchors
- **Multi-Algorithm Support**: Supports ECDSA, EdDSA, GOST, SM2, and other signature algorithms
- **RFC Compliance**: Implements standards from X.509 and related RFCs
- **Comprehensive Testing**: Includes test certificates and test harness
- **Secure Implementation**: Built with modern C11 standard and security hardening flags

## Dependencies

- **libecc**: Library for cryptographic signature verification
- **x509-parser**: X.509 certificate parsing library
- **Meson**: Build system (≥0.56)
- **GCC or Clang**: C compiler with C11 support

Both libecc and x509-parser are included as Meson subprojects in `subprojects/`.

## Quick Start

### Building from Source

1. **Prerequisites** - Ensure you have Meson and a C compiler installed:

```bash
# Debian/Ubuntu
sudo apt-get install meson gcc
# Fedora/RHEL
sudo dnf install meson gcc
# macOS with Homebrew
brew install meson gcc
```

2. **Configure the build**:

```bash
meson setup builddir
```

3. **Compile the project**:

```bash
meson compile -C builddir
```

4. **Install** (optional):

```bash
meson install -C builddir
```

The compiled binary `x509-verif` will be located in `builddir/x509-verif`.

### Usage Example

Verify a certificate using a self-signed anchor certificate:

```bash
# Using the provided test certificates
./builddir/x509-verif cert.der ed448-self-signed.der

# Or verify with any other certificate pair
./builddir/x509-verif path/to/certificate.der path/to/anchor.der
```

**Arguments:**

- `certificate.der`: The certificate to verify (binary DER format)
- `anchor.der`: The trusted anchor certificate for verification (binary DER format)

### Example Certificates

The project includes several test certificates for verification:

- `ed448-self-signed.der` - Self-signed Ed448 certificate
- `sm2-self-signed.der` - Self-signed SM2 certificate
- `rfc4491-bis.der`, `rfc4491-bis-cert2.der`, `rfc4491-bis-cert3.der` - RFC 4491 test vectors
- `artifacts/all-gost-sig2012/` - GOST signature algorithm test certificates

## Testing

### Building and running the test suite

Tests require the `with_tests` option:

```bash
meson setup builddir -Dwith_tests=true
meson compile -C builddir
meson test -C builddir
```

The suite is split into two categories described below.

### Basic unit tests (`basic` suite)

Two executables are built and registered as the `basic` Meson suite:

| Test | Binary | Description |
|------|--------|-------------|
| `test-sign` | `tests/test.c` | Round-trip ECDSA sign/verify smoke test using libecc |
| `test-streebog` | `tests/test-streebog.c` | GOST Streebog-256 hash vectors from GOST R 34.11-2012 |

Run only the basic suite:

```bash
meson test -C builddir --suite basic
```

### Artifact-based integration tests

A Python discovery script (`tests/list_cert_pairs.py`) is executed at Meson
**configure time** to enumerate all DER/CRT certificates found under the
`artifacts/` directory. For each certificate it selects a suitable anchor (the
certificate itself for self-signed certs, or the best-matching issuer for
non-self-signed ones) and emits one Meson test that calls `x509-verif
<cert> <anchor>`.

The script requires either the `cryptography` Python package or `openssl` on
`PATH` to parse subject/issuer fields.

#### Test suites produced

Each generated test is assigned to a named Meson suite:

| Suite | Source directory / pattern |
|-------|---------------------------|
| `artifact-gost-self-signed` | `artifacts/all-gosts-self-signed/` |
| `artifact-gost-2012` | `artifacts/all-gost-sig2012/` (self-signed) |
| `artifact-gost-2012-cross` | `artifacts/all-gost-sig2012/` (anchored) |
| `artifact-gost-ca` | `artifacts/all-gosts/*.crt` (self-signed CAs) |
| `artifact-gost-ca-cross` | `artifacts/all-gosts/*.crt` (anchored CAs) |
| `artifact-gost-cert-self` | `artifacts/all-gosts/*.der` (self-signed leaves) |
| `artifact-gost-cert-cross` | `artifacts/all-gosts/*.der` (anchored leaves) |
| `artifact-gost-exotic-self` | `artifacts/exotic/GOST/` (self-signed) |
| `artifact-gost-exotic-cross` | `artifacts/exotic/GOST/` (anchored) |
| `artifact-gost-roots` | `artifacts/exotic/gost-root/` (self-signed) |
| `artifact-gost-roots-cross` | `artifacts/exotic/gost-root/` (anchored) |
| `artifact-ed25519` | `artifacts/exotic/ED25519/` (self-signed) |
| `artifact-ed25519-cross` | `artifacts/exotic/ED25519/` (anchored) |
| `artifact-ed448` | Ed448 self-signed certs |
| `artifact-ed448-cross` | Ed448 anchored certs |
| `artifact-sm2` | SM2 self-signed certs |
| `artifact-sm2-cross` | SM2 anchored certs |
| `artifact-rfc4491` | RFC 4491 GOST test vectors |
| `artifact-ecc-root` | Top-level ECC self-signed roots |
| `artifact-tempo-cross` | `artifacts/tempo/` (anchored) |
| `artifact-artifact-self` | Catch-all for unclassified self-signed certs |
| `artifact-artifact-cross` | Catch-all for unclassified anchored certs |

#### Expected failures

Certificates whose verification is expected to fail (e.g. unsupported legacy
algorithms, intentionally invalid test vectors) are listed in
`tests/artifact_expected_failures.txt`, one relative path per line. The Meson
`should_fail` attribute is set accordingly so these tests are reported as
**Expected Fail** rather than **Fail**.

To run a specific artifact suite:

```bash
meson test -C builddir --suite artifact-ed448
```

## Advanced Build Options

Clean the build directory:

```bash
rm -rf builddir
```

## Project Structure

```
src/                      # Source code
├── main.c               # Main entry point
├── x509-verif.c/h       # Core verification logic
├── cert-extract.c/h     # Certificate parsing utilities
├── sig-verif.c/h        # Signature verification
├── libecc-compat.c      # LibECC compatibility layer
└── x509-parser-compat.c # X509Parser compatibility layer

tests/                   # Test suite
├── test.c                         # Basic ECDSA sign/verify test
├── test-streebog.c                # Streebog-256 hash test vectors
├── list_cert_pairs.py             # Configure-time discovery script
├── artifact_expected_failures.txt # Known-failing artifact certs
└── meson.build                    # Test registration

artifacts/               # Test certificate corpus
├── all-gosts/           # GOST CA and leaf certificates
├── all-gosts-self-signed/  # GOST self-signed certificates
├── all-gost-sig2012/    # GOST R 34.10-2012 certificates
├── exotic/              # ED25519, ED448, SM2, extra GOST roots
└── tempo/               # Anchored certificate chains

subprojects/             # External dependencies as Meson subprojects
├── libecc/              # LibECC library
└── x509-parser/         # X509 certificate parser
```

## Supported Algorithms

The tool supports verification of certificates signed with:

- RSA with PKCS#1 v1.5 padding
- ECDSA (NIST curves and others)
- EdDSA (Ed25519, Ed448)
- GOST algorithms (GOST R 34.10-2012)
- SM2 (Chinese cryptographic standard)

## Copyright and License

Copyright (C) 2021

This software is licensed under a dual BSD and GPL v2 license.
See [LICENSE](LICENSE) file at the root folder of the project.

## Authors

- Arnaud EBALARD (<mailto:arnaud.ebalard@ssi.gouv.fr>)
- Ryad BENADJILA (<mailto:ryad.benadjila@ssi.gouv.fr>)
- H2Lab Development Team (<mailto:bureau@h2lab.org>)
