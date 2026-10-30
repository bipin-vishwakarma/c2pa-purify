"""
Unit tests for c2pa_purify.
"""

import io
import os
import struct
import xml.etree.ElementTree as ET
import zipfile
import zlib
import pytest
from PIL import Image

from c2pa_purify import (
    clean_bytes,
    clean_jpeg_bytes,
    clean_png_bytes,
    clean_svg_bytes,
    clean_webp_bytes,
    clean_zip_archive,
    inspect_bytes,
    inspect_file,
    validate_file,
)


@pytest.fixture
def real_svg_data() -> bytes:
    fixture_path = os.path.join(os.path.dirname(__file__), "sample_with_c2pa.svg")
    if os.path.exists(fixture_path):
        with open(fixture_path, "rb") as f:
            return f.read()

    zip_path = "Mrinal_29_10_2026.zip"
    if os.path.exists(zip_path):
        with zipfile.ZipFile(zip_path, "r") as z:
            first_file = z.namelist()[0]
            return z.read(first_file)

    raise FileNotFoundError("No sample SVG fixture found for tests.")


def test_svg_cleaning_real_file(real_svg_data: bytes):
    assert b"c2pa" in real_svg_data
    assert b"xmlns:c2pa" in real_svg_data

    cleaned, res = clean_svg_bytes(real_svg_data, "test.svg")
    assert res.modified is True
    assert res.bytes_stripped > 5000
    assert b"c2pa" not in cleaned
    assert b"Anthropic" not in cleaned
    assert b"Claude" not in cleaned

    # Must be valid XML
    root = ET.fromstring(cleaned.decode("utf-8"))
    assert root.tag.endswith("svg")

    # Validator check
    val = validate_file(cleaned, "svg")
    assert val.passed is True
    assert val.is_fully_clean is True


def test_inspector_real_file(real_svg_data: bytes):
    insp = inspect_bytes(real_svg_data, "svg", "test.svg")
    assert insp.has_c2pa is True
    assert insp.has_anthropic_claims is True
    assert insp.manifest is not None
    assert insp.manifest.claim_generator == "Anthropic Files"
    assert insp.manifest.software_agent == "Claude"
    assert insp.manifest.action == "com.anthropic.claude.provided"
    assert len(insp.manifest.certificates) >= 1
    assert "Anthropic Claude Content Signing" in insp.manifest.certificates[0].subject


def test_png_cleaning():
    img = Image.new("RGBA", (20, 20), color=(255, 100, 50, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    clean_png = buf.getvalue()

    # Inject caBX chunk after IHDR
    ihdr_pos = clean_png.find(b"IHDR")
    ihdr_len = struct.unpack(">I", clean_png[ihdr_pos - 4 : ihdr_pos])[0]
    ihdr_end = ihdr_pos + 4 + ihdr_len + 4

    fake_cabx_payload = b"JUMBF Fake C2PA Manifest with Anthropic Files"
    fake_cabx = (
        struct.pack(">I", len(fake_cabx_payload))
        + b"caBX"
        + fake_cabx_payload
        + struct.pack(">I", zlib.crc32(b"caBX" + fake_cabx_payload))
    )
    dirty_png = clean_png[:ihdr_end] + fake_cabx + clean_png[ihdr_end:]

    # Clean
    cleaned, res = clean_png_bytes(dirty_png, "test.png")
    assert res.modified is True
    assert b"caBX" not in cleaned
    assert b"Anthropic" not in cleaned

    # Image must be valid
    Image.open(io.BytesIO(cleaned)).verify()
    val = validate_file(cleaned, "png")
    assert val.passed is True


def test_jpeg_cleaning():
    img = Image.new("RGB", (20, 20), color=(50, 150, 250))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    clean_jpg = buf.getvalue()

    # Inject APP11 segment
    fake_app11_payload = b"JP\x02\x11\x00\x00\x00\x01jumbc2pa manifest Anthropic Claude"
    app11_len = 2 + len(fake_app11_payload)
    fake_app11 = b"\xFF\xEB" + struct.pack(">H", app11_len) + fake_app11_payload
    dirty_jpg = clean_jpg[:2] + fake_app11 + clean_jpg[2:]

    # Clean
    cleaned, res = clean_jpeg_bytes(dirty_jpg, "test.jpg")
    assert res.modified is True
    assert b"\xFF\xEB" not in cleaned
    assert b"Claude" not in cleaned

    Image.open(io.BytesIO(cleaned)).verify()
    val = validate_file(cleaned, "jpeg")
    assert val.passed is True


def test_webp_cleaning():
    img = Image.new("RGBA", (15, 15), color="green")
    buf = io.BytesIO()
    img.save(buf, format="WEBP")
    clean_webp_data = buf.getvalue()

    # Inject caBX chunk before end
    cabx_payload = b"C2PA JUMBF Manifest Data"
    cabx_chunk = b"caBX" + struct.pack("<I", len(cabx_payload)) + cabx_payload
    dirty_webp = clean_webp_data + cabx_chunk
    # Update RIFF size
    new_size = len(dirty_webp) - 8
    dirty_webp = dirty_webp[:4] + struct.pack("<I", new_size) + dirty_webp[8:]

    cleaned, res = clean_webp_bytes(dirty_webp, "test.webp")
    assert res.modified is True
    assert b"caBX" not in cleaned

    Image.open(io.BytesIO(cleaned)).verify()
    val = validate_file(cleaned, "webp")
    assert val.passed is True


def test_zip_archive_cleaning(tmp_path, real_svg_data: bytes):
    test_zip = tmp_path / "test_input.zip"
    out_zip = tmp_path / "test_cleaned.zip"

    with zipfile.ZipFile(test_zip, "w") as z:
        z.writestr("infographic1.svg", real_svg_data)
        z.writestr("notes.txt", "Untouched documentation file")

    res = clean_zip_archive(str(test_zip), str(out_zip))
    assert res.success is True
    assert res.files_modified == 1
    assert res.bytes_stripped > 0

    with zipfile.ZipFile(out_zip, "r") as z_out:
        cleaned_svg = z_out.read("infographic1.svg")
        assert b"c2pa" not in cleaned_svg
        assert z_out.read("notes.txt") == b"Untouched documentation file"
