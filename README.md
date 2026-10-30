# c2pa-purify 🛡️

> High-performance, 100% lossless sanitizer and forensics inspector for embedded **C2PA (Coalition for Content Provenance and Authenticity)** manifests, **JUMBF** metadata boxes, and **"Anthropic Files" / Claude** claim markers.

---

## 📖 Overview

When Anthropic's Claude models generate or export visual assets (such as `.svg`, `.png`, `.jpg`, and `.webp`), they automatically attach cryptographically signed provenance metadata:

- **SVG:** Embeds an `xmlns:c2pa="http://c2pa.org/manifest"` namespace and a base64-encoded `<metadata><c2pa:manifest>...</c2pa:manifest></metadata>` block (typically 5–8 KB of overhead).
- **PNG:** Injects a private ancillary `caBX` chunk or `iTXt` text chunks containing JUMBF data.
- **JPEG:** Injects segmented `APP11` (`0xFFEB`) markers containing JUMBF boxes and Adobe XMP packets.
- **WebP:** Injects `caBX`, `JUMB`, or `XMP ` chunks into the RIFF container.

These manifests contain digital claim records specifying:
- **Claim Generator:** `Anthropic Files 1.0.0` (C2PA Spec v2.4.0)
- **Software Agent:** `Claude`
- **Action Asserted:** `com.anthropic.claude.provided`
- **Claim Statement:** *"Claude provided this file at the request of a user and may have created or modified the file contents."*
- **X.509 Certificate:** Signed by `CN=Anthropic Claude Content Signing, O=Anthropic, PBC` issued by `CN=Anthropic Content Credentials Root CA`.

**`c2pa-purify`** cleanly parses, inspects, and strips these records without transcoding, recompression, or altering even a single pixel or vector coordinate of your artwork.

---

## ⚡ Key Capabilities

- **Lossless Sanitization:** Modifies only metadata wrappers (XML nodes, PNG chunks, JPEG APP11 segments, WebP RIFF chunks). Artwork and image data remain bit-for-bit identical.
- **Deep Forensics Inspector:** Decodes and displays manifest URNs, generator details, actions, and X.509 certificates before or without modifying files.
- **Direct ZIP Processing:** Automatically cleans all media files inside a `.zip` archive (e.g. bulk downloads from Claude Artifacts) in-place or to a new file, maintaining original timestamps and directory hierarchies.
- **Batch & Recursive Mode:** Cleans entire directory trees with live progress bars and summary tables.
- **Verification Engine:** Post-cleaning structural and cryptographic validation ensures zero provenance traces remain and output files are 100% valid.
- **Drag-and-Drop Web UI:** Built-in local web interface for browser-based inspection and one-click purification.
- **Python Library API:** Importable as a lightweight Python module.

---

## 🚀 Quick Start

### 1. Command-Line Usage

You can run `c2pa-purify` using the Windows batch launcher (`c2pa-purify.bat`), PowerShell launcher (`.\c2pa-purify.ps1`), or directly via `python c2pa_purify_cli.py`:

```bash
# Inspect embedded C2PA credentials and certificates in an SVG or image
c2pa-purify inspect "infographic.svg"

# Clean a single file to a new purified file
c2pa-purify clean "infographic.svg" -o "clean_infographic.svg"

# Clean a single file in-place (with optional .bak backup)
c2pa-purify clean "infographic.svg" --in-place --backup

# Clean all files inside a ZIP archive
c2pa-purify clean "Mrinal_29_10_2026.zip" -o "Mrinal_cleaned.zip"

# Clean all files inside a ZIP archive in-place
c2pa-purify clean "Mrinal_29_10_2026.zip" --in-place

# Scan an entire folder for C2PA provenance records
c2pa-purify scan ./infographics/

# Clean an entire directory
c2pa-purify clean ./infographics/ -o ./cleaned_infographics/

# Verify that a file is completely clean and renderable
c2pa-purify verify "clean_infographic.svg"
```

### 2. Launch Local Web UI

For a graphical drag-and-drop interface:

```bash
c2pa-purify web --port 8080
```

Open `http://127.0.0.1:8080` in your browser. Drag and drop any SVG, PNG, JPEG, WebP, or ZIP file to view its C2PA certificate details and download the purified asset.

---

## 🔍 Example Forensics Output

```
+------------------------- C2PA Forensics Inspection -------------------------+
| File: A Field Guide to Clouds-English-29 Oct 2026.svg                       |
| Format: SVG                                                                 |
| File Size: 20.0 KB                                                          |
| Status: C2PA PROVENANCE RECORD DETECTED                                     |
|                                                                             |
| [ Embedded Manifest Credentials ]                                           |
|   * Manifest URN:       urn:c2pa:7505d4d7-65ff-4953-85f2-409d2f7d5f92       |
|   * Claim Generator:    Anthropic Files 1.0.0                               |
|   * C2PA Spec Version:  2.4.0                                               |
|   * Software Agent:     Claude                                              |
|   * Action Asserted:    com.anthropic.claude.provided                       |
|   * Claim Statement:    "Claude provided this file at the request of a user |
| and may have created or modified the file contents."                        |
|   * Manifest Overhead:  5.6 KB (28.1% of file size)                         |
|   * Embedding Location: <metadata><c2pa:manifest>, SVG root namespace:      |
| xmlns:c2pa                                                                  |
|                                                                             |
| [ Cryptographic Signing Certificates ]                                      |
|   [1] Subject:    CN=Anthropic Claude Content Signing,O=Anthropic\, PBC     |
|       Issuer:     CN=Anthropic Content Credentials Root CA,O=Anthropic\,    |
| PBC                                                                         |
|       Validity:   2026-08-07 18:43:56+00:00 to 2028-08-06 19:43:56+00:00    |
|       Serial:     370496221669126734322377145003421948178272162560          |
|                                                                             |
+-----------------------------------------------------------------------------+
```

---

## 🐍 Python Library API

```python
from c2pa_purify import clean_bytes, clean_file, clean_zip_archive, inspect_file, validate_file

# 1. Inspect a file
info = inspect_file("graphic.svg")
if info.has_c2pa:
    print(f"Detected C2PA Generator: {info.manifest.claim_generator}")
    print(f"Software Agent: {info.manifest.software_agent}")
    print(f"Action: {info.manifest.action}")

# 2. Clean in-memory bytes
with open("graphic.svg", "rb") as f:
    raw_data = f.read()

clean_data, result = clean_bytes(raw_data, ext="svg")
print(f"Stripped {result.bytes_stripped} bytes ({result.reduction_percentage:.1f}%)")

# 3. Clean a ZIP archive
archive_result = clean_zip_archive("batch.zip", output_zip="batch_cleaned.zip")
print(f"Modified {archive_result.files_modified} files in archive.")

# 4. Validate output integrity
report = validate_file(clean_data, ext="svg")
assert report.passed is True
```

---

## 🧪 Testing

Run the full test suite with:

```bash
python -m pytest tests/ -v
```
