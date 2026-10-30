"""
C2PA Provenance & Claim Inspector.
Inspects and decodes embedded C2PA manifests, JUMBF boxes, and Anthropic / Claude claim markers.
"""

from __future__ import annotations

import base64
import os
import re
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from cryptography import x509
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


@dataclass
class CertificateInfo:
    subject: str = ""
    issuer: str = ""
    valid_from: str = ""
    valid_to: str = ""
    serial_number: str = ""


@dataclass
class ManifestInfo:
    found: bool = False
    manifest_urn: str = ""
    claim_generator: str = ""
    claim_generator_version: str = ""
    spec_version: str = ""
    software_agent: str = ""
    action: str = ""
    description: str = ""
    raw_size_bytes: int = 0
    locations: List[str] = field(default_factory=list)
    certificates: List[CertificateInfo] = field(default_factory=list)
    extra_markers: List[str] = field(default_factory=list)


@dataclass
class InspectionResult:
    path: str
    format: str
    file_size_bytes: int
    has_c2pa: bool = False
    has_anthropic_claims: bool = False
    manifest: Optional[ManifestInfo] = None
    summary_message: str = ""
    archive_details: Optional[List[InspectionResult]] = None


def _parse_x509_certificates(raw_data: bytes) -> List[CertificateInfo]:
    """Search for and decode DER X.509 certificates embedded in JUMBF payload."""
    if not HAS_CRYPTOGRAPHY:
        return []

    certs: List[CertificateInfo] = []
    seen_serials = set()
    n = len(raw_data)

    for i in range(n - 4):
        # DER SEQUENCE header is 0x30 0x82 (for certs > 255 bytes)
        if raw_data[i] == 0x30 and raw_data[i + 1] == 0x82:
            length = (raw_data[i + 2] << 8) | raw_data[i + 3]
            total_len = length + 4
            if i + total_len <= n and total_len >= 128:
                try:
                    der_bytes = raw_data[i : i + total_len]
                    cert = x509.load_der_x509_certificate(der_bytes)
                    serial = str(cert.serial_number)
                    if serial not in seen_serials:
                        seen_serials.add(serial)
                        certs.append(
                            CertificateInfo(
                                subject=cert.subject.rfc4514_string(),
                                issuer=cert.issuer.rfc4514_string(),
                                valid_from=str(cert.not_valid_before_utc),
                                valid_to=str(cert.not_valid_after_utc),
                                serial_number=serial,
                            )
                        )
                except Exception:
                    pass

    return certs


def _decode_jumbf_manifest(raw_jumbf: bytes, location_desc: str) -> ManifestInfo:
    """Extract metadata, assertions, claims, and certs from binary JUMBF manifest."""
    info = ManifestInfo(found=True, raw_size_bytes=len(raw_jumbf))
    info.locations.append(location_desc)

    # Manifest URN
    urn_match = re.search(rb"urn:c2pa:[a-f0-9\-]+", raw_jumbf, re.IGNORECASE)
    if urn_match:
        info.manifest_urn = urn_match.group(0).decode("ascii", errors="ignore")

    # Claim Generator
    if b"Anthropic Files" in raw_jumbf:
        info.claim_generator = "Anthropic Files"
        ver_match = re.search(rb"Anthropic Files[^\d]*(\d+\.\d+(?:\.\d+)?)", raw_jumbf)
        if ver_match:
            info.claim_generator_version = ver_match.group(1).decode("ascii")
    else:
        gen_match = re.search(rb"claim_generator_info.*?name([a-zA-Z0-9_\-\s]+)", raw_jumbf)
        if gen_match:
            info.claim_generator = gen_match.group(1).decode("ascii", errors="ignore").strip()

    # Spec version
    spec_match = re.search(rb"specVersion[^\d]*(\d+\.\d+(?:\.\d+)?)", raw_jumbf)
    if spec_match:
        info.spec_version = spec_match.group(1).decode("ascii")

    # Software Agent
    if b"Claude" in raw_jumbf:
        info.software_agent = "Claude"
    else:
        agent_match = re.search(rb"softwareAgent.*?name([a-zA-Z0-9_\-\s]+)", raw_jumbf)
        if agent_match:
            info.software_agent = agent_match.group(1).decode("ascii", errors="ignore").strip()

    # Action
    # In CBOR, the action string is encoded as (e.g. 0x78 0x1d 'com.anthropic.claude.provided') followed by 'jparameters'
    action_match = re.search(rb"com\.anthropic\.claude\.[a-zA-Z0-9_\-]+", raw_jumbf)
    if not action_match:
        action_match = re.search(rb"com\.anthropic\.[a-zA-Z0-9_\-]+", raw_jumbf)
    if action_match:
        act = action_match.group(0).decode("ascii", errors="ignore")
        # Strip trailing CBOR map keys like 'jparameters'
        for suffix in ["jparameters", "kparameters", "parameters"]:
            if act.endswith(suffix):
                act = act[: -len(suffix)]
                break
        info.action = act.rstrip("._-")
    else:
        act_match = re.search(rb"c2pa\.(?:opened|created|edited|placed)", raw_jumbf)
        if act_match:
            info.action = act_match.group(0).decode("ascii", errors="ignore")

    # Description
    desc_match = re.search(rb"(Claude provided this file[^\x00-\x1f\x7f-\xff]+)", raw_jumbf)
    if desc_match:
        # Clean up CBOR artifacts at end of string
        desc_str = desc_match.group(1).decode("utf-8", errors="ignore")
        # Description usually ends with period
        if "." in desc_str:
            desc_str = desc_str[: desc_str.rfind(".") + 1]
        info.description = desc_str.strip()

    # Extra markers
    if b"com.anthropic.origin-confidence" in raw_jumbf:
        info.extra_markers.append("com.anthropic.origin-confidence")
    if b"Anthropic PBC" in raw_jumbf or b"Anthropic, PBC" in raw_jumbf:
        info.extra_markers.append("Anthropic, PBC Entity Reference")

    # Parse X.509 certs
    info.certificates = _parse_x509_certificates(raw_jumbf)

    return info


def inspect_svg(data: bytes, path: str = "") -> InspectionResult:
    result = InspectionResult(
        path=path,
        format="SVG",
        file_size_bytes=len(data),
    )
    text = data.decode("utf-8", errors="replace")

    manifest_matches = list(re.finditer(r"<c2pa:manifest>(.*?)</c2pa:manifest>", text, flags=re.DOTALL))
    has_xmlns = bool(re.search(r"xmlns:c2pa=([\'\"]).*?\1", text))

    if manifest_matches or has_xmlns:
        result.has_c2pa = True
        locations = []
        if has_xmlns:
            locations.append("SVG root namespace: xmlns:c2pa")

        raw_jumbf = b""
        for m in manifest_matches:
            b64_content = m.group(1).strip()
            try:
                decoded = base64.b64decode(b64_content)
                raw_jumbf += decoded
            except Exception:
                pass

        if raw_jumbf:
            manifest_info = _decode_jumbf_manifest(raw_jumbf, "<metadata><c2pa:manifest>")
            for loc in locations:
                if loc not in manifest_info.locations:
                    manifest_info.locations.append(loc)
            result.manifest = manifest_info
            if "Anthropic Files" in manifest_info.claim_generator or "Claude" in manifest_info.software_agent or manifest_info.action.startswith("com.anthropic"):
                result.has_anthropic_claims = True
        else:
            result.manifest = ManifestInfo(found=True, locations=locations)

    # Check for comments or tags
    if re.search(r"<!--(?=.*?(?:anthropic|claude)).*?-->", text, flags=re.DOTALL | re.IGNORECASE):
        result.has_anthropic_claims = True

    if result.has_c2pa:
        gen = result.manifest.claim_generator if result.manifest else "Unknown"
        agent = result.manifest.software_agent if result.manifest else "Unknown"
        result.summary_message = f"C2PA manifest detected (Generator: '{gen}', Agent: '{agent}')"
    else:
        result.summary_message = "Clean - No C2PA or Anthropic provenance records found"

    return result


def inspect_png(data: bytes, path: str = "") -> InspectionResult:
    result = InspectionResult(path=path, format="PNG", file_size_bytes=len(data))
    PNG_SIG = b"\x89PNG\r\n\x1a\n"
    if not data.startswith(PNG_SIG):
        result.summary_message = "Invalid PNG signature"
        return result

    pos = 8
    n = len(data)
    manifest_chunks = []

    while pos < n:
        if pos + 8 > n:
            break
        chunk_len = struct.unpack(">I", data[pos : pos + 4])[0]
        chunk_type = data[pos + 4 : pos + 8].decode("latin1", errors="replace")
        pos += 8
        chunk_payload = data[pos : pos + chunk_len]
        pos += chunk_len + 4  # skip data + 4 bytes crc

        if chunk_type in ("caBX", "c2pa", "C2PA"):
            manifest_chunks.append((chunk_type, chunk_payload))
        elif chunk_type == "iTXt":
            parts = chunk_payload.split(b"\x00", 1)
            kw = parts[0].decode("latin1", errors="replace").lower()
            if any(k in kw for k in ["c2pa", "anthropic", "claude"]) or any(k in chunk_payload.lower() for k in [b"c2pa:manifest", b"anthropic files", b"com.anthropic"]):
                result.has_anthropic_claims = True
                result.has_c2pa = True
                manifest_chunks.append((f"iTXt:{kw}", chunk_payload))

    if manifest_chunks:
        result.has_c2pa = True
        raw_payload = b"".join(c[1] for c in manifest_chunks)
        locations = [f"PNG chunk: {c[0]}" for c in manifest_chunks]
        manifest_info = _decode_jumbf_manifest(raw_payload, ", ".join(locations))
        result.manifest = manifest_info
        if "Anthropic Files" in manifest_info.claim_generator or "Claude" in manifest_info.software_agent or manifest_info.action.startswith("com.anthropic"):
            result.has_anthropic_claims = True
        result.summary_message = f"C2PA manifest detected in {len(manifest_chunks)} PNG chunk(s)"
    else:
        result.summary_message = "Clean - No C2PA or Anthropic provenance records found"

    return result


def inspect_jpeg(data: bytes, path: str = "") -> InspectionResult:
    result = InspectionResult(path=path, format="JPEG", file_size_bytes=len(data))
    if not data.startswith(b"\xFF\xD8"):
        result.summary_message = "Invalid JPEG SOI marker"
        return result

    pos = 2
    n = len(data)
    app11_payloads = []
    locations = []

    while pos < n:
        if pos + 2 > n or data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        if marker in (0xD8, 0xD9) or (0xD0 <= marker <= 0xD7) or marker == 0x01:
            pos += 2
            if marker == 0xD9:
                break
            continue
        if marker == 0xDA:  # SOS
            break
        if pos + 4 > n:
            break
        seg_len = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
        seg_end = pos + 2 + seg_len
        payload = data[pos + 4 : seg_end]

        if marker == 0xEB:  # APP11
            if payload.startswith(b"JP") or b"c2pa" in payload or b"jumb" in payload:
                # Strip JP transport header (10 bytes: JP + instance 2B + seq 4B)
                box_payload = payload[10:] if len(payload) > 10 and payload.startswith(b"JP") else payload
                app11_payloads.append(box_payload)
                locations.append(f"JPEG APP11 (len={seg_len})")
        elif marker == 0xE1:  # APP1
            if any(k in payload.lower() for k in [b"c2pa", b"anthropic", b"claude"]):
                result.has_anthropic_claims = True
                locations.append(f"JPEG APP1 (XMP/EXIF with claim markers)")

        pos = seg_end

    if app11_payloads or locations:
        result.has_c2pa = True
        raw_payload = b"".join(app11_payloads)
        manifest_info = _decode_jumbf_manifest(raw_payload, ", ".join(locations))
        result.manifest = manifest_info
        if "Anthropic Files" in manifest_info.claim_generator or "Claude" in manifest_info.software_agent or manifest_info.action.startswith("com.anthropic"):
            result.has_anthropic_claims = True
        result.summary_message = f"C2PA manifest detected in {len(locations)} JPEG segment(s)"
    else:
        result.summary_message = "Clean - No C2PA or Anthropic provenance records found"

    return result


def inspect_webp(data: bytes, path: str = "") -> InspectionResult:
    result = InspectionResult(path=path, format="WebP", file_size_bytes=len(data))
    if not (data.startswith(b"RIFF") and data[8:12] == b"WEBP"):
        result.summary_message = "Invalid WebP signature"
        return result

    pos = 12
    n = len(data)
    found_chunks = []

    while pos < n:
        if pos + 8 > n:
            break
        fourcc = data[pos : pos + 4].decode("latin1", errors="replace")
        size = struct.unpack("<I", data[pos + 4 : pos + 8])[0]
        pos += 8
        payload = data[pos : pos + size]
        pos += size
        if size % 2 == 1 and pos < n:
            pos += 1

        if fourcc in ("caBX", "JUMB", "c2pa"):
            found_chunks.append((fourcc, payload))
        elif fourcc == "XMP " and any(k in payload.lower() for k in [b"c2pa", b"anthropic", b"claude"]):
            result.has_anthropic_claims = True
            found_chunks.append((fourcc, payload))

    if found_chunks:
        result.has_c2pa = True
        raw_payload = b"".join(c[1] for c in found_chunks)
        locations = [f"WebP chunk: {c[0]}" for c in found_chunks]
        manifest_info = _decode_jumbf_manifest(raw_payload, ", ".join(locations))
        result.manifest = manifest_info
        if "Anthropic Files" in manifest_info.claim_generator or "Claude" in manifest_info.software_agent or manifest_info.action.startswith("com.anthropic"):
            result.has_anthropic_claims = True
        result.summary_message = f"C2PA manifest detected in {len(found_chunks)} WebP chunk(s)"
    else:
        result.summary_message = "Clean - No C2PA or Anthropic provenance records found"

    return result


def inspect_zip(zip_path_or_bytes: str | bytes) -> InspectionResult:
    """Inspect all supported media files inside a ZIP archive."""
    if isinstance(zip_path_or_bytes, bytes):
        import io
        zf = zipfile.ZipFile(io.BytesIO(zip_path_or_bytes))
        path_str = "<memory.zip>"
        file_size = len(zip_path_or_bytes)
    else:
        zf = zipfile.ZipFile(zip_path_or_bytes)
        path_str = zip_path_or_bytes
        file_size = os.path.getsize(zip_path_or_bytes)

    sub_results: List[InspectionResult] = []
    has_any_c2pa = False
    has_any_anthropic = False

    with zf:
        for item in zf.infolist():
            ext = item.filename.lower().split(".")[-1]
            if ext in ("svg", "png", "jpg", "jpeg", "webp"):
                content = zf.read(item.filename)
                sub_res = inspect_bytes(content, ext, item.filename)
                sub_results.append(sub_res)
                if sub_res.has_c2pa:
                    has_any_c2pa = True
                if sub_res.has_anthropic_claims:
                    has_any_anthropic = True

    c2pa_count = sum(1 for r in sub_results if r.has_c2pa)
    total_media = len(sub_results)

    summary = f"Archive contains {total_media} media file(s), {c2pa_count} with C2PA/Anthropic provenance records"
    return InspectionResult(
        path=path_str,
        format="ZIP",
        file_size_bytes=file_size,
        has_c2pa=has_any_c2pa,
        has_anthropic_claims=has_any_anthropic,
        summary_message=summary,
        archive_details=sub_results,
    )


def inspect_bytes(data: bytes, ext: str, path: str = "") -> InspectionResult:
    ext_clean = ext.lower().lstrip(".")
    if ext_clean == "svg":
        return inspect_svg(data, path)
    elif ext_clean == "png":
        return inspect_png(data, path)
    elif ext_clean in ("jpg", "jpeg"):
        return inspect_jpeg(data, path)
    elif ext_clean == "webp":
        return inspect_webp(data, path)
    else:
        # Check by content signature
        if data.startswith(b"<?xml") or b"<svg" in data[:500]:
            return inspect_svg(data, path)
        elif data.startswith(b"\x89PNG"):
            return inspect_png(data, path)
        elif data.startswith(b"\xFF\xD8"):
            return inspect_jpeg(data, path)
        elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
            return inspect_webp(data, path)
        elif data.startswith(b"PK\x03\x04"):
            return inspect_zip(data)
        return InspectionResult(path=path, format="Unknown", file_size_bytes=len(data), summary_message="Unsupported format")


def inspect_file(file_path: str) -> InspectionResult:
    """Inspect a file on disk."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".zip":
        return inspect_zip(file_path)

    with open(file_path, "rb") as f:
        data = f.read()

    return inspect_bytes(data, ext, file_path)
