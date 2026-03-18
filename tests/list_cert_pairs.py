#!/usr/bin/env python3
"""list_cert_pairs.py <artifacts_dir>

Discovers cert-anchor test pairs under <artifacts_dir> for use with x509-verif.
Each line of stdout is emitted as:

    cert_path|anchor_path|suite_name|test_name|expected

Only certificates for which a usable anchor can be found under artifacts/ are
emitted. Self-signed certificates are tested against themselves. For non
self-signed certificates, anchors are selected deterministically from all
parseable certificates found under artifacts/.
"""

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import warnings


try:
    from cryptography import x509 as _x509
except ImportError:
    _x509 = None

try:
    from cryptography.utils import CryptographyDeprecationWarning
except Exception:
    CryptographyDeprecationWarning = None


warnings.filterwarnings(
    "ignore",
    message=r"Attribute's length must be >= 1 and <= 64, but it was .*",
)
if CryptographyDeprecationWarning is not None:
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


EXPECTED_FAILURES_FILE = Path(__file__).with_name("artifact_expected_failures.txt")


def load_expected_failures(path):
    if not path.is_file():
        return set()

    return {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


EXPECTED_FAILURES = load_expected_failures(EXPECTED_FAILURES_FILE)

GOST_GROUPS = {
    "all-gosts",
    "all-gosts-self-signed",
    "all-gost-sig2012",
    "exotic/GOST",
    "exotic/gost-root",
}


def _parse_with_cryptography(path):
    data = path.read_bytes()
    cert = _x509.load_der_x509_certificate(data)
    return cert.subject.rfc4514_string(), cert.issuer.rfc4514_string()


def _parse_with_openssl(path):
    import subprocess

    result = subprocess.run(
        [
            "openssl", "x509", "-noout", "-subject", "-issuer",
            "-nameopt", "RFC2253", "-inform", "DER", "-in", str(path),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return None, None

    subject = None
    issuer = None
    for line in result.stdout.splitlines():
        lowered = line.lower()
        if lowered.startswith("subject="):
            subject = line[8:].strip()
        elif lowered.startswith("issuer="):
            issuer = line[7:].strip()

    return subject, issuer


def get_subject_issuer(path):
    """Return (subject, issuer), or (None, None) if parsing fails."""
    if _x509 is not None:
        try:
            return _parse_with_cryptography(path)
        except Exception:
            pass

    try:
        return _parse_with_openssl(path)
    except Exception:
        return None, None


def iter_cert_files(artifacts):
    for path in sorted(artifacts.rglob("*")):
        if not path.is_file():
            continue
        if path.name.endswith(".der") or path.name.endswith(".crt"):
            yield path


def strip_cert_suffix(name):
    if name.endswith(".crt.der"):
        return name[:-8]
    if name.endswith(".der") or name.endswith(".crt"):
        return name.rsplit(".", 1)[0]
    return name


def path_group(rel_path):
    parts = rel_path.parts
    if not parts:
        return ""
    if parts[0] == "exotic" and len(parts) > 1:
        return "/".join(parts[:2])
    return parts[0]


def path_family(rel_path):
    group = path_group(rel_path)
    name = rel_path.name

    if group in GOST_GROUPS or name.startswith("rfc4491-bis"):
        return "gost"
    if group == "exotic/ED25519":
        return "ed25519"
    if group == "exotic/ED448" or name == "ed448-self-signed.der":
        return "ed448"
    if group == "exotic/SM2-SM3" or name == "sm2-self-signed.der":
        return "sm2"
    if name == "cert.der":
        return "ecc"
    return group


def is_named_ca(rel_path):
    name = rel_path.name
    return name.endswith(".crt") or name.endswith(".crt.der")


def classify_suite(rel_path, self_signed):
    parts = rel_path.parts
    name = rel_path.name
    head = parts[0] if parts else ""

    if head == "all-gosts-self-signed":
        return "gost-self-signed"
    if head == "all-gost-sig2012":
        return "gost-2012" if self_signed else "gost-2012-cross"
    if head == "all-gosts":
        if is_named_ca(rel_path):
            return "gost-ca" if self_signed else "gost-ca-cross"
        return "gost-cert-self" if self_signed else "gost-cert-cross"
    if head == "tempo":
        return "tempo" if self_signed else "tempo-cross"

    if head == "exotic" and len(parts) > 1:
        exotic_group = parts[1]
        if exotic_group == "ED25519":
            return "ed25519" if self_signed else "ed25519-cross"
        if exotic_group == "ED448":
            return "ed448" if self_signed else "ed448-cross"
        if exotic_group == "SM2-SM3":
            return "sm2" if self_signed else "sm2-cross"
        if exotic_group == "gost-root":
            return "gost-roots" if self_signed else "gost-roots-cross"
        if exotic_group == "GOST":
            return "gost-exotic-self" if self_signed else "gost-exotic-cross"

    if name == "ed448-self-signed.der":
        return "ed448"
    if name == "sm2-self-signed.der":
        return "sm2"
    if name.startswith("rfc4491-bis"):
        return "rfc4491"
    if name == "cert.der":
        return "ecc-root" if self_signed else "ecc-root-cross"

    return "artifact-self" if self_signed else "artifact-cross"


def classify_expected(rel_path):
    rel_name = rel_path.as_posix()
    if rel_name in EXPECTED_FAILURES or rel_path.name in EXPECTED_FAILURES:
        return "fail"
    return "pass"


def make_test_name(rel_path):
    return "/".join(part.replace('.', '_') for part in rel_path.parts)


def choose_anchor(cert_rel, candidates, parsed_info):
    cert_group = path_group(cert_rel)
    cert_top = cert_rel.parts[0] if cert_rel.parts else ""
    cert_family = path_family(cert_rel)

    def sort_key(anchor_path):
        anchor_rel = anchor_path.relative_to(_ARTIFACTS_ROOT)
        anchor_subject, anchor_issuer = parsed_info[anchor_path]
        anchor_group = path_group(anchor_rel)
        anchor_top = anchor_rel.parts[0] if anchor_rel.parts else ""
        anchor_family = path_family(anchor_rel)
        return (
            0 if anchor_subject == anchor_issuer else 1,
            0 if is_named_ca(anchor_rel) else 1,
            0 if anchor_group == cert_group else 1,
            0 if anchor_top == cert_top else 1,
            0 if anchor_family == cert_family else 1,
            len(anchor_rel.parts),
            anchor_rel.as_posix(),
        )

    return min(candidates, key=sort_key)


def parse_all(files, workers=32):
    parsed = {}

    def parse_one(path):
        subject, issuer = get_subject_issuer(path)
        return path, subject, issuer

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for path, subject, issuer in pool.map(parse_one, files):
            if subject is not None:
                parsed[path] = (subject, issuer)

    return parsed


def emit(cert, anchor, suite, test_name, expected):
    print(f"{cert}|{anchor}|{suite}|{test_name}|{expected}")


def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: list_cert_pairs.py <artifacts_dir>")

    artifacts = Path(sys.argv[1]).resolve()
    global _ARTIFACTS_ROOT
    _ARTIFACTS_ROOT = artifacts

    parsed = parse_all(list(iter_cert_files(artifacts)))
    subject_map = defaultdict(list)
    for path, (subject, _issuer) in parsed.items():
        subject_map[subject].append(path)

    pairs = []
    for cert_path in sorted(parsed):
        subject, issuer = parsed[cert_path]
        cert_rel = cert_path.relative_to(artifacts)
        if subject == issuer:
            pairs.append(
                (
                    cert_path,
                    cert_path,
                    classify_suite(cert_rel, True),
                    make_test_name(cert_rel),
                    classify_expected(cert_rel),
                )
            )
            continue

        anchors = subject_map.get(issuer)
        if not anchors:
            continue

        anchor_path = choose_anchor(cert_rel, anchors, parsed)
        pairs.append(
            (
                cert_path,
                anchor_path,
                classify_suite(cert_rel, False),
                make_test_name(cert_rel),
                classify_expected(cert_rel),
            )
        )

    for cert_path, anchor_path, suite, test_name, expected in pairs:
        emit(cert_path, anchor_path, suite, test_name, expected)


if __name__ == "__main__":
    _ARTIFACTS_ROOT = Path(".")
    main()
