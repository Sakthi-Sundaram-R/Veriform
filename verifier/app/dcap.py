"""Full Intel TDX DCAP quote verification — the complete chain of trust, done
offline with no paid service.

The cert-chain check (verify.py) proves the quote carries genuine Intel
collateral. This goes the whole way: it verifies every signature that links
Intel's Root CA down to the report_data, so a quote passes only if a real
Intel-certified attestation key actually signed this exact report.

TDX quote v4 layout (offsets in bytes):
    [0:48]      header
    [48:632]    TD report (584B) — measurements + report_data (last 64B)
    [632:636]   signature section length
    [636:700]   ECDSA-P256 signature over header||TD_report, by the att key
    [700:764]   attestation public key (raw x||y)
    [764:766]   certification data type (6 = QE report + chain)
    [766:770]   certification data size
    [770:1154]  QE report (384B SGX report; report_data = last 64B)
    [1154:1218] QE report signature, by the PCK cert
    [1218:1220] QE auth data size
    [1220:…]    QE auth data
    …           PCK certificate chain (PEM: PCK → Platform CA → Root)

Chain of trust verified here:
    Intel Root CA → PCK cert → signs QE report →
    QE report binds the attestation key → att key signs the TD report →
    TD report carries report_data (Veriform's decision binding)

HONEST NOTE: the dstack simulator serves a real captured quote but patches
report_data in *after* capture — so full DCAP on a simulator-served quote
correctly FAILS at the att-key signature (the report was re-written after it
was signed). That's the point: this check distinguishes genuine unpatched
hardware output from a simulator, which is exactly the guarantee real silicon
adds. It passes on a real unpatched quote; it fails on a patched one.
"""

import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

INTEL_SGX_ROOT_CA_SPKI_SHA256 = (
    "a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e"
)

HEADER_LEN = 48
TD_REPORT_LEN = 584
SIGNED_END = HEADER_LEN + TD_REPORT_LEN  # 632
QE_REPORT_LEN = 384


def _p256_pubkey_from_raw(raw64: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + raw64)


def _der_sig(raw64: bytes) -> bytes:
    r = int.from_bytes(raw64[:32], "big")
    s = int.from_bytes(raw64[32:], "big")
    return utils.encode_dss_signature(r, s)


def _verify_ecdsa(pubkey, sig_raw: bytes, message: bytes) -> bool:
    try:
        pubkey.verify(_der_sig(sig_raw), message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def verify_full_dcap(quote_hex: str) -> dict:
    """Return {'ok': bool, 'checks': [{name, passed, detail}, ...]}."""
    checks = []

    def add(name, passed, detail):
        checks.append({"name": name, "passed": passed, "detail": detail})

    try:
        q = bytes.fromhex(quote_hex.removeprefix("0x"))
    except ValueError:
        return {"ok": False, "checks": [{"name": "parse", "passed": False,
                                         "detail": "quote is not valid hex"}]}
    if len(q) < 1218:
        return {"ok": False, "checks": [{"name": "parse", "passed": False,
                                         "detail": f"quote too short ({len(q)}B)"}]}

    ver = int.from_bytes(q[0:2], "little")
    tee = int.from_bytes(q[4:8], "little")
    if ver != 4 or tee != 0x81:
        add("quote_format", False, f"not a TDX v4 quote (ver={ver}, tee=0x{tee:x})")
        return {"ok": False, "checks": checks}
    add("quote_format", True, "TDX v4 quote")

    att_pubkey_raw = q[700:764]
    att_sig_raw = q[636:700]
    qe_report = q[770:770 + QE_REPORT_LEN]
    qe_report_sig = q[1154:1218]
    qe_auth_size = int.from_bytes(q[1218:1220], "little")
    qe_auth = q[1220:1220 + qe_auth_size]

    # 1. Attestation key signed the TD report (this fails on patched quotes).
    try:
        att_pub = _p256_pubkey_from_raw(att_pubkey_raw)
        ok = _verify_ecdsa(att_pub, att_sig_raw, q[0:SIGNED_END])
    except Exception as exc:
        ok = False
        add("att_key_signs_report", False, f"attestation key error: {exc}")
    else:
        add("att_key_signs_report", ok,
            "attestation key's signature over the TD report is valid"
            if ok else
            "attestation-key signature INVALID — the report was altered after "
            "signing (e.g. a simulator patched report_data)")

    # 2. The QE report binds this attestation key.
    binding = hashlib.sha256(att_pubkey_raw + qe_auth).digest()
    qe_report_data = qe_report[320:384]
    bound = qe_report_data[:32] == binding
    add("qe_binds_att_key", bound,
        "QE report commits to the attestation key" if bound else
        "QE report does not commit to the attestation key")

    # 3. Parse the PCK chain and verify the PCK cert signed the QE report.
    start = q.find(b"-----BEGIN CERTIFICATE-----")
    end = q.rfind(b"-----END CERTIFICATE-----")
    if start < 0 or end < 0:
        add("pck_signs_qe", False, "no PCK certificate chain in quote")
        add("chain_to_intel_root", False, "no certificate chain")
        return {"ok": False, "checks": checks}
    pem = q[start:end + len(b"-----END CERTIFICATE-----")]
    try:
        certs = x509.load_pem_x509_certificates(pem)
    except Exception as exc:
        add("pck_signs_qe", False, f"chain unparseable: {exc}")
        return {"ok": False, "checks": checks}

    pck = certs[0]
    try:
        pck.public_key().verify(_der_sig(qe_report_sig), qe_report,
                                ec.ECDSA(hashes.SHA256()))
        add("pck_signs_qe", True, "PCK certificate signed the QE report")
    except Exception:
        add("pck_signs_qe", False, "PCK certificate did NOT sign the QE report")

    # 4. Chain PCK -> Platform CA -> Root, and Root is Intel's pinned SGX Root.
    chain_ok = True
    for child, parent in zip(certs, certs[1:]):
        try:
            parent.public_key().verify(child.signature, child.tbs_certificate_bytes,
                                       ec.ECDSA(child.signature_hash_algorithm))
        except Exception:
            chain_ok = False
    from cryptography.hazmat.primitives import serialization
    root = certs[-1]
    spki = root.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    root_ok = hashlib.sha256(spki).hexdigest() == INTEL_SGX_ROOT_CA_SPKI_SHA256
    add("chain_to_intel_root", chain_ok and root_ok,
        "PCK chain validates and roots in the Intel SGX Root CA"
        if chain_ok and root_ok else
        "PCK chain does not validate to the Intel SGX Root CA")

    ok = all(c["passed"] for c in checks)
    return {"ok": ok, "checks": checks}
