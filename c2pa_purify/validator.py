"""
C2PA Provenance & Integrity Validator.
Verifies that all C2PA provenance records and claim markers have been completely removed,
and ensures that the media file remains 100% valid and renderable.
"""

from __future__ import annotations

import io
import re
import struct
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from typing import List, Optional

try:
    from PIL import Image
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False


@dataclass
class ValidationReport:
    is_valid_format: bool = True
    is_fully_clean: bool = True
    format: str = "Unknown"
    format_error: str = ""
    traces_found: List[str] = field(default_factory=list)
    details: str = ""

    @property
    def passed(self) -> bool:
        return self.is_valid_format and self.is_fully_clean


def validate_svg(data: bytes) -> ValidationReport:
    report = ValidationReport(format="SVG")
    text = data.decode("utf-8", errors="replace")

    # 1. Structural XML validity
    try:
        ET.fromstring(text)
    except Exception as e:
        report.is_valid_format = False
        report.format_error = f"XML syntax error: {e}"

    # 2. Check for C2PA traces
    if "<c2pa:manifest" in text:
        report.is_fully_clean = False
        report.traces_found.append("Tag: <c2pa:manifest>")

    if re.search(r"xmlns:c2pa=([\'\"]).*?\1", text):
        report.is_fully_clean = False
        report.traces_found.append("Attribute: xmlns:c2pa")

    if re.search(r"<c2pa:[a-zA-Z0-9_\-]+", text):
        report.is_fully_clean = False
        report.traces_found.append("Tag prefix: <c2pa:...>")

    # 3. Check for Anthropic / Claude claims
    if "Anthropic Files" in text:
        report.is_fully_clean = False
        report.traces_found.append("Claim: 'Anthropic Files'")

    if "com.anthropic" in text:
        report.is_fully_clean = False
        report.traces_found.append("Claim: 'com.anthropic'")

    if "Claude provided this file" in text:
        report.is_fully_clean = False
        report.traces_found.append("Claim: 'Claude provided this file'")

    if report.passed:
        report.details = "100% Valid SVG - Zero C2PA or Anthropic traces remaining"
    else:
        report.details = f"Validation issues: {len(report.traces_found)} trace(s) found, format_valid={report.is_valid_format}"

    return report


def validate_png(data: bytes) -> ValidationReport:
    report = ValidationReport(format="PNG")
    PNG_SIG = b"\x89PNG\r\n\x1a\n"

    if not data.startswith(PNG_SIG):
        report.is_valid_format = False
        report.format_error = "Invalid PNG signature"
        return report

    # Pillow check if available
    if HAS_PILLOW:
        try:
            img = Image.open(io.BytesIO(data))
            img.verify()
        except Exception as e:
            report.is_valid_format = False
            report.format_error = f"PNG image verification failed: {e}"

    # Chunk trace check
    pos = 8
    n = len(data)
    while pos < n:
        if pos + 8 > n:
            break
        chunk_len = struct.unpack(">I", data[pos : pos + 4])[0]
        chunk_type = data[pos + 4 : pos + 8].decode("latin1", errors="replace")
        pos += 8
        payload = data[pos : pos + chunk_len]
        pos += chunk_len + 4

        if chunk_type in ("caBX", "c2pa", "C2PA"):
            report.is_fully_clean = False
            report.traces_found.append(f"PNG Chunk: {chunk_type}")

        if any(k in payload.lower() for k in [b"c2pa:manifest", b"anthropic files", b"com.anthropic"]):
            report.is_fully_clean = False
            report.traces_found.append(f"PNG Chunk payload: {chunk_type}")

    if report.passed:
        report.details = "100% Valid PNG - Zero C2PA or Anthropic traces remaining"
    else:
        report.details = f"Validation issues: {len(report.traces_found)} trace(s) found"

    return report


def validate_jpeg(data: bytes) -> ValidationReport:
    report = ValidationReport(format="JPEG")
    if not data.startswith(b"\xFF\xD8"):
        report.is_valid_format = False
        report.format_error = "Invalid JPEG SOI"
        return report

    if HAS_PILLOW:
        try:
            img = Image.open(io.BytesIO(data))
            img.verify()
        except Exception as e:
            report.is_valid_format = False
            report.format_error = f"JPEG verification failed: {e}"

    # Segment scan
    pos = 2
    n = len(data)
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
        if marker == 0xDA:
            break
        if pos + 4 > n:
            break
        seg_len = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
        seg_end = pos + 2 + seg_len
        payload = data[pos + 4 : seg_end]

        if marker == 0xEB and (payload.startswith(b"JP") or b"c2pa" in payload or b"jumb" in payload):
            report.is_fully_clean = False
            report.traces_found.append("JPEG APP11 (C2PA JUMBF)")
        if marker == 0xE1 and any(k in payload.lower() for k in [b"c2pa", b"anthropic files", b"com.anthropic"]):
            report.is_fully_clean = False
            report.traces_found.append("JPEG APP1 (Claim marker)")

        pos = seg_end

    if report.passed:
        report.details = "100% Valid JPEG - Zero C2PA or Anthropic traces remaining"
    else:
        report.details = f"Validation issues: {len(report.traces_found)} trace(s) found"

    return report


def validate_webp(data: bytes) -> ValidationReport:
    report = ValidationReport(format="WebP")
    if not (data.startswith(b"RIFF") and data[8:12] == b"WEBP"):
        report.is_valid_format = False
        report.format_error = "Invalid WebP signature"
        return report

    if HAS_PILLOW:
        try:
            img = Image.open(io.BytesIO(data))
            img.verify()
        except Exception as e:
            report.is_valid_format = False
            report.format_error = f"WebP verification failed: {e}"

    pos = 12
    n = len(data)
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
            report.is_fully_clean = False
            report.traces_found.append(f"WebP Chunk: {fourcc}")
        if fourcc == "XMP " and any(k in payload.lower() for k in [b"c2pa", b"anthropic files"]):
            report.is_fully_clean = False
            report.traces_found.append("WebP XMP (C2PA/Anthropic)")

    if report.passed:
        report.details = "100% Valid WebP - Zero C2PA or Anthropic traces remaining"
    else:
        report.details = f"Validation issues: {len(report.traces_found)} trace(s) found"

    return report


def validate_file(data: bytes, ext: str) -> ValidationReport:
    ext_clean = ext.lower().lstrip(".")
    if ext_clean == "svg":
        return validate_svg(data)
    elif ext_clean == "png":
        return validate_png(data)
    elif ext_clean in ("jpg", "jpeg"):
        return validate_jpeg(data)
    elif ext_clean == "webp":
        return validate_webp(data)
    else:
        if data.startswith(b"<?xml") or b"<svg" in data[:500]:
            return validate_svg(data)
        elif data.startswith(b"\x89PNG"):
            return validate_png(data)
        elif data.startswith(b"\xFF\xD8"):
            return validate_jpeg(data)
        elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
            return validate_webp(data)

        return ValidationReport(format="Unsupported", details="Unsupported format for deep validation")
