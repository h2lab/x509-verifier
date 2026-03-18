# x509-verif: X.509 Certificate Verification Tool

A command-line utility for verifying X.509 digital certificates against trusted anchor certificates. This tool leverages the robust parsing capabilities of [x509-parser](https://github.com/ANSSI-FR/x509-parser) and the cryptographic verification features of [libecc](https://github.com/ANSSI-FR/libecc).

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

Run tests:

```bash
meson test -C builddir
```

## Advanced Build Options

Build with tests enabled:

```bash
meson setup builddir -Dwith_tests=true
meson compile -C builddir
meson test -C builddir
```

Clean the build directory:

```bash
rm -rf builddir
```

## Project Structure

```bash
src/                      # Source code
├── main.c               # Main entry point
├── x509-verif.c/h       # Core verification logic
├── cert-extract.c/h     # Certificate parsing utilities
├── sig-verif.c/h        # Signature verification
├── libecc-compat.c      # LibECC compatibility layer
└── x509-parser-compat.c # X509Parser compatibility layer

tests/                   # Test suite
├── test.c              # Signature verification tests
└── test-streebog.c     # GOST Streebog hash tests

subprojects/            # External dependencies as Meson subprojects
├── libecc/             # LibECC library
└── x509-parser/        # X509 certificate parser
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
