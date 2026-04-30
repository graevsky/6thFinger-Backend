import base64
import hashlib
import os
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17"

_GOOGLE_ATTESTATION_ROOTS_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV\n"
    "BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw\n"
    "NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B\n"
    "AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS\n"
    "Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7\n"
    "tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj\n"
    "nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq\n"
    "C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ\n"
    "oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O\n"
    "JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg\n"
    "sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi\n"
    "igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M\n"
    "RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E\n"
    "aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um\n"
    "AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud\n"
    "IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD\n"
    "VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7\n"
    "174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC\n"
    "W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G\n"
    "tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx\n"
    "oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG\n"
    "1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF\n"
    "mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz\n"
    "lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw\n"
    "n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu\n"
    "zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo\n"
    "vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn\n"
    "w1IdYIg2Wxg7yHcQZemFQg==\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc\n"
    "MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET\n"
    "MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4\n"
    "WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex\n"
    "MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG\n"
    "EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt\n"
    "G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5\n"
    "Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB\n"
    "/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA\n"
    "MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH\n"
    "EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY\n"
    "uR2zh/80lQyu9vAFCj6E4AXc+osmRg==\n"
    "-----END CERTIFICATE-----\n"
)

_TAG_CLASS_UNIVERSAL = 0
_TAG_CLASS_CONTEXT = 2

_UNIVERSAL_BOOLEAN = 1
_UNIVERSAL_INTEGER = 2
_UNIVERSAL_BIT_STRING = 3
_UNIVERSAL_OCTET_STRING = 4
_UNIVERSAL_OBJECT_IDENTIFIER = 6
_UNIVERSAL_ENUMERATED = 10
_UNIVERSAL_SEQUENCE = 16
_UNIVERSAL_SET = 17

_KEY_PURPOSE_SIGN = 2
_ALGORITHM_EC = 3
_DIGEST_SHA_2_256 = 4
_EC_CURVE_P256 = 1

_SECURITY_LEVELS = {
    0: "SOFTWARE",
    1: "TRUSTED_ENVIRONMENT",
    2: "STRONGBOX",
}

_VERIFIED_BOOT_STATES = {
    0: "VERIFIED",
    1: "SELF_SIGNED",
    2: "UNVERIFIED",
    3: "FAILED",
}


class AttestationVerificationError(ValueError):
    """Raised when Android Key Attestation cannot be trusted."""


@dataclass(frozen=True)
class AndroidAttestationPolicy:
    expected_package: str
    expected_signing_cert_sha256: str
    allow_trusted_environment: bool
    allow_strongbox: bool
    require_verified_boot: bool
    require_device_locked: bool


@dataclass(frozen=True)
class VerifiedAndroidAttestation:
    public_key_der: bytes
    public_key_sha256: str
    package_name: str
    signing_cert_sha256: str
    attestation_security_level: str
    keymint_security_level: str
    verified_boot_state: str | None
    device_locked: bool | None


@dataclass(frozen=True)
class _DerNode:
    tag_class: int
    constructed: bool
    tag_number: int
    value: bytes
    raw: bytes


def is_client_attestation_enabled() -> bool:
    return os.getenv("CLIENT_ATTESTATION_ENABLED", "0").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def load_android_attestation_policy() -> AndroidAttestationPolicy:
    expected_package = (os.getenv("OFFICIAL_ANDROID_PACKAGE") or "").strip()
    expected_signing_cert_sha256 = normalize_sha256_fingerprint(
        os.getenv("OFFICIAL_ANDROID_CERT_SHA256") or ""
    )
    if not expected_package:
        raise AttestationVerificationError("OFFICIAL_ANDROID_PACKAGE is not configured")
    if not expected_signing_cert_sha256:
        raise AttestationVerificationError(
            "OFFICIAL_ANDROID_CERT_SHA256 is not configured"
        )

    return AndroidAttestationPolicy(
        expected_package=expected_package,
        expected_signing_cert_sha256=expected_signing_cert_sha256,
        allow_trusted_environment=_env_flag("ALLOW_TRUSTED_ENVIRONMENT", True),
        allow_strongbox=_env_flag("ALLOW_STRONGBOX", True),
        require_verified_boot=_env_flag("REQUIRE_VERIFIED_BOOT", True),
        require_device_locked=_env_flag("REQUIRE_DEVICE_LOCKED", True),
    )


def normalize_sha256_fingerprint(value: str) -> str:
    compact = "".join(ch for ch in value if ch.isalnum()).upper()
    if not compact:
        return ""
    if len(compact) != 64:
        raise AttestationVerificationError("SHA-256 fingerprint must have 64 hex chars")
    try:
        int(compact, 16)
    except ValueError as exc:
        raise AttestationVerificationError("SHA-256 fingerprint must be hex") from exc
    return ":".join(compact[i : i + 2] for i in range(0, len(compact), 2))


def verify_android_key_attestation(
    *,
    cert_chain_b64: list[str],
    expected_challenge: str,
    provided_public_key_b64: str,
    policy: AndroidAttestationPolicy,
) -> VerifiedAndroidAttestation:
    if not cert_chain_b64:
        raise AttestationVerificationError("Attestation certificate chain is empty")

    cert_chain_der = [
        _b64decode(blob, "attestation certificate") for blob in cert_chain_b64
    ]
    _verify_chain_with_openssl(cert_chain_der)

    attestation_cert_der = _find_attestation_certificate(cert_chain_der)
    cert_info = _parse_certificate(attestation_cert_der)

    provided_public_key_der = _b64decode(provided_public_key_b64, "public key")
    if provided_public_key_der != cert_info["subject_public_key_info"]:
        raise AttestationVerificationError(
            "publicKey does not match the attested certificate public key"
        )

    ext_value = cert_info["extensions"].get(ATTESTATION_EXTENSION_OID)
    if ext_value is None:
        raise AttestationVerificationError("Android attestation extension is missing")

    parsed = _parse_key_description(ext_value)
    _verify_security_levels(parsed, policy)

    expected_challenge_bytes = expected_challenge.encode("utf-8")
    if parsed["attestation_challenge"] != expected_challenge_bytes:
        raise AttestationVerificationError("Attestation challenge mismatch")

    purpose_values = set(parsed["purpose_values"])
    if _KEY_PURPOSE_SIGN not in purpose_values:
        raise AttestationVerificationError("Attested key is not authorized for SIGN")

    if parsed["algorithm"] != _ALGORITHM_EC:
        raise AttestationVerificationError("Attested key is not an EC key")

    if parsed["ec_curve"] != _EC_CURVE_P256:
        raise AttestationVerificationError("Attested key is not P-256")

    digest_values = set(parsed["digest_values"])
    if _DIGEST_SHA_2_256 not in digest_values:
        raise AttestationVerificationError("Attested key is not authorized for SHA-256")

    package_names = {pkg["package_name"] for pkg in parsed["package_infos"]}
    if policy.expected_package not in package_names:
        raise AttestationVerificationError("Package name mismatch in attestation")

    signing_digests = {
        normalize_sha256_fingerprint(digest) for digest in parsed["signature_digests"]
    }
    if policy.expected_signing_cert_sha256 not in signing_digests:
        raise AttestationVerificationError(
            "Signing certificate mismatch in attestation"
        )

    verified_boot_state = parsed["verified_boot_state"]
    device_locked = parsed["device_locked"]

    if policy.require_verified_boot and verified_boot_state != "VERIFIED":
        raise AttestationVerificationError("Verified Boot is required")

    if policy.require_device_locked and device_locked is not True:
        raise AttestationVerificationError("Device lock state does not satisfy policy")

    public_key_der = cert_info["subject_public_key_info"]
    return VerifiedAndroidAttestation(
        public_key_der=public_key_der,
        public_key_sha256=hashlib.sha256(public_key_der).hexdigest(),
        package_name=policy.expected_package,
        signing_cert_sha256=policy.expected_signing_cert_sha256,
        attestation_security_level=parsed["attestation_security_level"],
        keymint_security_level=parsed["keymint_security_level"],
        verified_boot_state=verified_boot_state,
        device_locked=device_locked,
    )


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _b64decode(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise AttestationVerificationError(f"Invalid base64 {label}") from exc


def _pem_from_der(cert_der: bytes) -> str:
    body = base64.encodebytes(cert_der).decode("ascii").replace("\n", "")
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return (
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join(lines)
        + "\n-----END CERTIFICATE-----\n"
    )


def _verify_chain_with_openssl(cert_chain_der: list[bytes]) -> None:
    base_dir = Path(os.getenv("CLIENT_ATTESTATION_TMP_DIR", ".attestation_tmp"))
    base_dir.mkdir(parents=True, exist_ok=True)
    suffix = secrets.token_hex(8)
    roots_path = base_dir / f"roots_{suffix}.pem"
    leaf_path = base_dir / f"leaf_{suffix}.pem"
    intermediates_path = base_dir / f"intermediates_{suffix}.pem"
    try:
        roots_path.write_text(_GOOGLE_ATTESTATION_ROOTS_PEM, encoding="ascii")
        leaf_path.write_text(_pem_from_der(cert_chain_der[0]), encoding="ascii")
        intermediates_path.write_text(
            "".join(_pem_from_der(cert) for cert in cert_chain_der[1:]),
            encoding="ascii",
        )

        cmd = ["openssl", "verify", "-CAfile", str(roots_path)]
        if len(cert_chain_der) > 1:
            cmd.extend(["-untrusted", str(intermediates_path)])
        cmd.append(str(leaf_path))

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise AttestationVerificationError(
            "openssl is not available on the server"
        ) from exc
    finally:
        for path in (roots_path, leaf_path, intermediates_path):
            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass

    if result.returncode != 0:
        stderr = (result.stderr or result.stdout or "").strip()
        raise AttestationVerificationError(
            f"Attestation certificate chain is not trusted: {stderr or 'openssl verify failed'}"
        )


def _find_attestation_certificate(cert_chain_der: list[bytes]) -> bytes:
    for cert_der in reversed(cert_chain_der):
        cert_info = _parse_certificate(cert_der)
        if ATTESTATION_EXTENSION_OID in cert_info["extensions"]:
            return cert_der
    raise AttestationVerificationError(
        "No certificate in the chain contains attestation data"
    )


def _parse_certificate(cert_der: bytes) -> dict:
    cert_node = _parse_single_der(cert_der)
    _expect_universal(cert_node, _UNIVERSAL_SEQUENCE, "Certificate")
    cert_children = _children(cert_node)
    if len(cert_children) < 1:
        raise AttestationVerificationError("Malformed X.509 certificate")

    tbs_certificate = cert_children[0]
    _expect_universal(tbs_certificate, _UNIVERSAL_SEQUENCE, "TBSCertificate")
    tbs_children = _children(tbs_certificate)

    idx = 0
    if (
        tbs_children
        and tbs_children[0].tag_class == _TAG_CLASS_CONTEXT
        and tbs_children[0].tag_number == 0
    ):
        idx += 1

    try:
        subject_public_key_info = tbs_children[idx + 5].raw
    except IndexError as exc:
        raise AttestationVerificationError(
            "Malformed X.509 subject public key info"
        ) from exc

    extensions: dict[str, bytes] = {}
    for child in tbs_children[idx + 6 :]:
        if child.tag_class != _TAG_CLASS_CONTEXT or child.tag_number != 3:
            continue
        ext_sequence = _single_child(child, "X.509 extensions")
        _expect_universal(ext_sequence, _UNIVERSAL_SEQUENCE, "X.509 extensions")
        for ext in _children(ext_sequence):
            ext_children = _children(ext)
            if len(ext_children) < 2:
                continue
            oid = _decode_oid(ext_children[0].value)
            value_node = ext_children[-1]
            _expect_universal(
                value_node, _UNIVERSAL_OCTET_STRING, "X.509 extension value"
            )
            extensions[oid] = value_node.value

    return {
        "subject_public_key_info": subject_public_key_info,
        "extensions": extensions,
    }


def _parse_key_description(extension_bytes: bytes) -> dict:
    key_desc = _parse_single_der(extension_bytes)
    _expect_universal(key_desc, _UNIVERSAL_SEQUENCE, "KeyDescription")
    fields = _children(key_desc)
    if len(fields) != 8:
        raise AttestationVerificationError("Unexpected KeyDescription field count")

    attestation_security_level = _security_level_name(_der_int(fields[1]))
    keymint_security_level = _security_level_name(_der_int(fields[3]))

    software_enforced = _parse_authorization_list(fields[6])
    hardware_enforced = _parse_authorization_list(fields[7])

    package_infos, signature_digests = _extract_attestation_application_id(
        hardware_enforced, software_enforced
    )
    purpose_values = _extract_set_of_ints(1, hardware_enforced, software_enforced)
    digest_values = _extract_set_of_ints(5, hardware_enforced, software_enforced)
    algorithm = _extract_single_int(2, hardware_enforced, software_enforced)
    ec_curve = _extract_single_int(10, hardware_enforced, software_enforced)
    device_locked, verified_boot_state = _extract_root_of_trust(
        hardware_enforced, software_enforced
    )

    return {
        "attestation_challenge": _der_octets(fields[4]),
        "attestation_security_level": attestation_security_level,
        "keymint_security_level": keymint_security_level,
        "purpose_values": purpose_values,
        "digest_values": digest_values,
        "algorithm": algorithm,
        "ec_curve": ec_curve,
        "package_infos": package_infos,
        "signature_digests": signature_digests,
        "device_locked": device_locked,
        "verified_boot_state": verified_boot_state,
    }


def _verify_security_levels(parsed: dict, policy: AndroidAttestationPolicy) -> None:
    allowed_levels = set()
    if policy.allow_trusted_environment:
        allowed_levels.add("TRUSTED_ENVIRONMENT")
    if policy.allow_strongbox:
        allowed_levels.add("STRONGBOX")

    if not allowed_levels:
        raise AttestationVerificationError(
            "No attestation security level is allowed by policy"
        )

    if parsed["attestation_security_level"] not in allowed_levels:
        raise AttestationVerificationError(
            f"Attestation security level {parsed['attestation_security_level']} is not allowed"
        )
    if parsed["keymint_security_level"] not in allowed_levels:
        raise AttestationVerificationError(
            f"KeyMint security level {parsed['keymint_security_level']} is not allowed"
        )


def _parse_authorization_list(node: _DerNode) -> dict[int, _DerNode]:
    _expect_universal(node, _UNIVERSAL_SEQUENCE, "AuthorizationList")
    return {
        child.tag_number: child
        for child in _children(node)
        if child.tag_class == _TAG_CLASS_CONTEXT
    }


def _extract_single_int(
    tag_number: int, *auth_lists: dict[int, _DerNode]
) -> int | None:
    context_node = _find_context(tag_number, *auth_lists)
    if context_node is None:
        return None
    child = _single_child(context_node, f"context tag {tag_number}")
    return _der_int(child)


def _extract_set_of_ints(
    tag_number: int, *auth_lists: dict[int, _DerNode]
) -> list[int]:
    context_node = _find_context(tag_number, *auth_lists)
    if context_node is None:
        return []
    set_node = _single_child(context_node, f"context tag {tag_number}")
    _expect_universal(set_node, _UNIVERSAL_SET, f"context tag {tag_number}")
    return [_der_int(child) for child in _children(set_node)]


def _extract_root_of_trust(
    *auth_lists: dict[int, _DerNode]
) -> tuple[bool | None, str | None]:
    context_node = _find_context(704, *auth_lists)
    if context_node is None:
        return None, None
    seq_node = _single_child(context_node, "rootOfTrust")
    _expect_universal(seq_node, _UNIVERSAL_SEQUENCE, "RootOfTrust")
    parts = _children(seq_node)
    if len(parts) < 3:
        raise AttestationVerificationError("Malformed RootOfTrust")

    _expect_universal(parts[1], _UNIVERSAL_BOOLEAN, "RootOfTrust.deviceLocked")
    _expect_universal(parts[2], _UNIVERSAL_ENUMERATED, "RootOfTrust.verifiedBootState")
    device_locked = parts[1].value != b"\x00"
    verified_boot_state = _verified_boot_state_name(_der_int(parts[2]))
    return device_locked, verified_boot_state


def _extract_attestation_application_id(
    *auth_lists: dict[int, _DerNode],
) -> tuple[list[dict[str, int | str]], list[str]]:
    context_node = _find_context(709, *auth_lists)
    if context_node is None:
        raise AttestationVerificationError("attestationApplicationId is missing")

    octets_node = _single_child(context_node, "attestationApplicationId")
    raw = _der_octets(octets_node)
    app_id = _parse_single_der(raw)
    _expect_universal(app_id, _UNIVERSAL_SEQUENCE, "AttestationApplicationId")
    fields = _children(app_id)
    if len(fields) != 2:
        raise AttestationVerificationError("Malformed AttestationApplicationId")

    package_infos_node, signature_digests_node = fields
    _expect_universal(
        package_infos_node, _UNIVERSAL_SET, "AttestationApplicationId.package_infos"
    )
    _expect_universal(
        signature_digests_node,
        _UNIVERSAL_SET,
        "AttestationApplicationId.signature_digests",
    )

    package_infos: list[dict[str, int | str]] = []
    for pkg_node in _children(package_infos_node):
        _expect_universal(pkg_node, _UNIVERSAL_SEQUENCE, "AttestationPackageInfo")
        pkg_fields = _children(pkg_node)
        if len(pkg_fields) != 2:
            raise AttestationVerificationError("Malformed AttestationPackageInfo")
        package_name = _der_octets(pkg_fields[0]).decode("utf-8")
        version = _der_int(pkg_fields[1])
        package_infos.append({"package_name": package_name, "version": version})

    digests = [
        _bytes_to_fingerprint(_der_octets(digest_node))
        for digest_node in _children(signature_digests_node)
    ]
    return package_infos, digests


def _find_context(tag_number: int, *auth_lists: dict[int, _DerNode]) -> _DerNode | None:
    for auth_list in auth_lists:
        node = auth_list.get(tag_number)
        if node is not None:
            return node
    return None


def _security_level_name(value: int) -> str:
    if value not in _SECURITY_LEVELS:
        raise AttestationVerificationError(f"Unknown security level {value}")
    return _SECURITY_LEVELS[value]


def _verified_boot_state_name(value: int) -> str:
    if value not in _VERIFIED_BOOT_STATES:
        raise AttestationVerificationError(f"Unknown verified boot state {value}")
    return _VERIFIED_BOOT_STATES[value]


def _bytes_to_fingerprint(data: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in data)


def _parse_single_der(data: bytes) -> _DerNode:
    node, end = _parse_der(data, 0)
    if end != len(data):
        raise AttestationVerificationError("Unexpected trailing DER data")
    return node


def _parse_der(data: bytes, offset: int) -> tuple[_DerNode, int]:
    start = offset
    if offset >= len(data):
        raise AttestationVerificationError("Unexpected end of DER input")

    first = data[offset]
    offset += 1
    tag_class = first >> 6
    constructed = bool(first & 0x20)
    tag_number = first & 0x1F
    if tag_number == 0x1F:
        tag_number = 0
        while True:
            if offset >= len(data):
                raise AttestationVerificationError("Incomplete DER tag number")
            nxt = data[offset]
            offset += 1
            tag_number = (tag_number << 7) | (nxt & 0x7F)
            if not (nxt & 0x80):
                break

    if offset >= len(data):
        raise AttestationVerificationError("Missing DER length")
    first_len = data[offset]
    offset += 1
    if first_len & 0x80:
        len_bytes = first_len & 0x7F
        if len_bytes == 0:
            raise AttestationVerificationError("Indefinite DER length is not supported")
        if offset + len_bytes > len(data):
            raise AttestationVerificationError("Incomplete DER length")
        length = int.from_bytes(data[offset : offset + len_bytes], "big")
        offset += len_bytes
    else:
        length = first_len

    end = offset + length
    if end > len(data):
        raise AttestationVerificationError("DER value exceeds available bytes")

    return (
        _DerNode(
            tag_class=tag_class,
            constructed=constructed,
            tag_number=tag_number,
            value=data[offset:end],
            raw=data[start:end],
        ),
        end,
    )


def _children(node: _DerNode) -> list[_DerNode]:
    if not node.constructed:
        raise AttestationVerificationError("DER node is not constructed")
    children: list[_DerNode] = []
    offset = 0
    while offset < len(node.value):
        child, offset = _parse_der(node.value, offset)
        children.append(child)
    return children


def _single_child(node: _DerNode, label: str) -> _DerNode:
    children = _children(node)
    if len(children) != 1:
        raise AttestationVerificationError(f"{label} must contain exactly one child")
    return children[0]


def _expect_universal(node: _DerNode, tag_number: int, label: str) -> None:
    if node.tag_class != _TAG_CLASS_UNIVERSAL or node.tag_number != tag_number:
        raise AttestationVerificationError(f"Unexpected DER type for {label}")


def _der_int(node: _DerNode) -> int:
    if node.tag_class != _TAG_CLASS_UNIVERSAL or node.tag_number not in (
        _UNIVERSAL_INTEGER,
        _UNIVERSAL_ENUMERATED,
    ):
        raise AttestationVerificationError("DER value is not an INTEGER/ENUMERATED")
    return int.from_bytes(node.value, "big", signed=False)


def _der_octets(node: _DerNode) -> bytes:
    _expect_universal(node, _UNIVERSAL_OCTET_STRING, "OCTET STRING")
    return node.value


def _decode_oid(value: bytes) -> str:
    if not value:
        raise AttestationVerificationError("Malformed OID")
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    current = 0
    for byte in value[1:]:
        current = (current << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            parts.append(str(current))
            current = 0
    if current != 0:
        raise AttestationVerificationError("Malformed OID continuation")
    return ".".join(parts)
