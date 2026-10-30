"""
C2PA Provenance & Claim Purifier Engine.
Strips C2PA manifests, JUMBF boxes, and Anthropic/Claude claim markers from SVG, PNG, JPEG, WebP, and ZIP files.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import struct
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple


@dataclass
class CleanResult:
    path: str
    format: str
    original_size: int
    cleaned_size: int
    bytes_stripped: int
    modified: bool
    items_removed: List[str] = field(default_factory=list)
    success: bool = True
    error_message: str = ""

    @property
    def reduction_percentage(self) -> float:
        if self.original_size == 0:
            return 0.0
        return (self.bytes_stripped / self.original_size) * 100.0


@dataclass
class ArchiveCleanResult:
    archive_path: str
    total_files: int
    media_files: int
    files_modified: int
    original_size: int
    cleaned_size: int
    bytes_stripped: int
    file_results: List[CleanResult] = field(default_factory=list)
    success: bool = True
    error_message: str = ""


@dataclass
class BatchCleanResult:
    total_inspected: int
    total_modified: int
    total_bytes_stripped: int
    results: List[CleanResult] = field(default_factory=list)


def clean_svg_bytes(svg_bytes: bytes, file_name: str = "") -> Tuple[bytes, CleanResult]:
    """Strip C2PA manifest, xmlns:c2pa, and Anthropic claim markers from SVG."""
    orig_len = len(svg_bytes)
    result = CleanResult(
        path=file_name,
        format="SVG",
        original_size=orig_len,
        cleaned_size=orig_len,
        bytes_stripped=0,
        modified=False,
    )

    try:
        text = svg_bytes.decode("utf-8", errors="replace")

        # 1. Check for <metadata> containing <c2pa:manifest>
        # Match <metadata ...> containing only whitespace and <c2pa:manifest>...</c2pa:manifest>
        def replace_metadata(match: re.Match) -> str:
            content = match.group(0)
            result.items_removed.append("<metadata><c2pa:manifest>")
            return ""

        text = re.sub(
            r"<metadata[^>]*>\s*<c2pa:manifest>.*?</c2pa:manifest>\s*</metadata>",
            replace_metadata,
            text,
            flags=re.DOTALL,
        )

        # 2. Standalone <c2pa:manifest> if still present inside a multi-item metadata block
        if "<c2pa:manifest" in text:
            result.items_removed.append("<c2pa:manifest>")
            text = re.sub(r"<c2pa:manifest>.*?</c2pa:manifest>", "", text, flags=re.DOTALL)

        # 3. Any other c2pa: prefixed tags (e.g. <c2pa:assertions>, <c2pa:claim>, etc.)
        other_c2pa_tags = re.findall(r"<c2pa:[a-zA-Z0-9_\-]+[^>]*>.*?</c2pa:[a-zA-Z0-9_\-]+>", text, flags=re.DOTALL)
        if other_c2pa_tags:
            result.items_removed.append(f"c2pa_tags({len(other_c2pa_tags)})")
            text = re.sub(r"<c2pa:[a-zA-Z0-9_\-]+[^>]*>.*?</c2pa:[a-zA-Z0-9_\-]+>", "", text, flags=re.DOTALL)

        # 4. Remove xmlns:c2pa="..." namespace attribute
        xmlns_matches = re.findall(r"\s+xmlns:c2pa(?::[a-zA-Z0-9_\-]+)?=([\'\"]).*?\1", text)
        if xmlns_matches:
            result.items_removed.append("xmlns:c2pa")
            text = re.sub(r"\s+xmlns:c2pa(?::[a-zA-Z0-9_\-]+)?=([\'\"]).*?\1", "", text)

        # 5. Remove empty <metadata></metadata> or <metadata/>
        empty_meta = re.findall(r"<metadata[^>]*>\s*</metadata>|<metadata[^>]*/>", text)
        if empty_meta:
            text = re.sub(r"<metadata[^>]*>\s*</metadata>|<metadata[^>]*/>", "", text)

        # 6. Remove XML comments referencing Anthropic or Claude
        comments = re.findall(r"<!--(?=.*?(?:anthropic|claude|c2pa)).*?-->", text, flags=re.DOTALL | re.IGNORECASE)
        if comments:
            result.items_removed.append(f"XML_comments({len(comments)})")
            text = re.sub(r"<!--(?=.*?(?:anthropic|claude|c2pa)).*?-->", "", text, flags=re.DOTALL | re.IGNORECASE)

        # 7. Clean up redundant blank lines at the top of file
        text = re.sub(r"^\s*\n", "", text)

        cleaned_bytes = text.encode("utf-8")
        result.cleaned_size = len(cleaned_bytes)
        result.bytes_stripped = orig_len - len(cleaned_bytes)
        result.modified = result.bytes_stripped > 0
        return cleaned_bytes, result

    except Exception as e:
        result.success = False
        result.error_message = str(e)
        return svg_bytes, result


def clean_png_bytes(png_bytes: bytes, file_name: str = "") -> Tuple[bytes, CleanResult]:
    """Strip caBX, c2pa, and claim markers from PNG chunks losslessly."""
    orig_len = len(png_bytes)
    result = CleanResult(
        path=file_name,
        format="PNG",
        original_size=orig_len,
        cleaned_size=orig_len,
        bytes_stripped=0,
        modified=False,
    )

    PNG_SIG = b"\x89PNG\r\n\x1a\n"
    if not png_bytes.startswith(PNG_SIG):
        result.success = False
        result.error_message = "Invalid PNG signature"
        return png_bytes, result

    pos = 8
    chunks = []

    while pos < len(png_bytes):
        if pos + 8 > len(png_bytes):
            break
        length = struct.unpack(">I", png_bytes[pos : pos + 4])[0]
        chunk_type = png_bytes[pos + 4 : pos + 8]
        pos += 8
        data = png_bytes[pos : pos + length]
        pos += length
        crc = png_bytes[pos : pos + 4]
        pos += 4

        remove = False
        type_str = chunk_type.decode("latin1", errors="replace")

        if type_str in ("caBX", "c2pa", "C2PA"):
            remove = True
            result.items_removed.append(f"PNG_Chunk:{type_str}")
        elif type_str == "iTXt":
            parts = data.split(b"\x00", 1)
            kw = parts[0].decode("latin1", errors="replace").lower()
            if any(k in kw for k in ["c2pa", "anthropic", "claude"]) or any(k in data.lower() for k in [b"c2pa:manifest", b"anthropic files", b"com.anthropic"]):
                remove = True
                result.items_removed.append(f"PNG_iTXt:{kw}")
        elif type_str in ("tEXt", "zTXt"):
            kw = data.split(b"\x00", 1)[0].decode("latin1", errors="replace").lower()
            if any(k in kw for k in ["c2pa", "anthropic", "claude"]) or any(k in data.lower() for k in [b"c2pa", b"anthropic", b"claude"]):
                remove = True
                result.items_removed.append(f"PNG_{type_str}:{kw}")
        elif type_str == "eXIf":
            if any(k in data.lower() for k in [b"c2pa", b"anthropic files", b"claude"]):
                remove = True
                result.items_removed.append("PNG_eXIf")

        if not remove:
            chunks.append(struct.pack(">I", length) + chunk_type + data + crc)

    cleaned_bytes = PNG_SIG + b"".join(chunks)
    result.cleaned_size = len(cleaned_bytes)
    result.bytes_stripped = orig_len - len(cleaned_bytes)
    result.modified = result.bytes_stripped > 0
    return cleaned_bytes, result


def clean_jpeg_bytes(jpeg_bytes: bytes, file_name: str = "") -> Tuple[bytes, CleanResult]:
    """Strip APP11 C2PA JUMBF segments and claim markers from JPEG losslessly."""
    orig_len = len(jpeg_bytes)
    result = CleanResult(
        path=file_name,
        format="JPEG",
        original_size=orig_len,
        cleaned_size=orig_len,
        bytes_stripped=0,
        modified=False,
    )

    if not jpeg_bytes.startswith(b"\xFF\xD8"):
        result.success = False
        result.error_message = "Invalid JPEG SOI marker"
        return jpeg_bytes, result

    pos = 2
    out = bytearray(b"\xFF\xD8")

    while pos < len(jpeg_bytes):
        if pos + 2 > len(jpeg_bytes):
            out.extend(jpeg_bytes[pos:])
            break

        if jpeg_bytes[pos] != 0xFF:
            out.extend(jpeg_bytes[pos:])
            break

        marker = jpeg_bytes[pos + 1]

        if marker == 0xFF:
            pos += 1
            continue

        # Standalone markers without payload
        if marker in (0xD8, 0xD9) or (0xD0 <= marker <= 0xD7) or marker == 0x01:
            out.extend(jpeg_bytes[pos : pos + 2])
            pos += 2
            if marker == 0xD9:
                out.extend(jpeg_bytes[pos:])
                break
            continue

        if marker == 0xDA:  # SOS (Start of Scan) - entropy stream follows
            if pos + 4 <= len(jpeg_bytes):
                length = struct.unpack(">H", jpeg_bytes[pos + 2 : pos + 4])[0]
                sos_header_end = pos + 2 + length
                out.extend(jpeg_bytes[pos:sos_header_end])
                out.extend(jpeg_bytes[sos_header_end:])
                break
            else:
                out.extend(jpeg_bytes[pos:])
                break

        if pos + 4 > len(jpeg_bytes):
            out.extend(jpeg_bytes[pos:])
            break

        length = struct.unpack(">H", jpeg_bytes[pos + 2 : pos + 4])[0]
        segment_end = pos + 2 + length
        if segment_end > len(jpeg_bytes):
            out.extend(jpeg_bytes[pos:])
            break

        payload = jpeg_bytes[pos + 4 : segment_end]
        remove = False

        if marker == 0xEB:  # APP11 (C2PA JUMBF box)
            if payload.startswith(b"JP") or b"c2pa" in payload or b"jumb" in payload:
                remove = True
                result.items_removed.append("JPEG_APP11:C2PA_JUMBF")
        elif marker == 0xE1:  # APP1 (XMP or EXIF)
            if payload.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
                if any(k in payload.lower() for k in [b"c2pa", b"anthropic", b"claude"]):
                    remove = True
                    result.items_removed.append("JPEG_APP1:XMP")
            elif payload.startswith(b"Exif\x00\x00"):
                if any(k in payload.lower() for k in [b"anthropic files", b"com.anthropic"]):
                    remove = True
                    result.items_removed.append("JPEG_APP1:EXIF")
        elif marker == 0xED:  # APP13 (Photoshop/IPTC)
            if any(k in payload.lower() for k in [b"c2pa", b"anthropic files"]):
                remove = True
                result.items_removed.append("JPEG_APP13:IPTC")
        elif marker == 0xFE:  # COM (Comment)
            if any(k in payload.lower() for k in [b"c2pa", b"anthropic", b"claude"]):
                remove = True
                result.items_removed.append("JPEG_COM")

        if not remove:
            out.extend(jpeg_bytes[pos:segment_end])

        pos = segment_end

    cleaned_bytes = bytes(out)
    result.cleaned_size = len(cleaned_bytes)
    result.bytes_stripped = orig_len - len(cleaned_bytes)
    result.modified = result.bytes_stripped > 0
    return cleaned_bytes, result


def clean_webp_bytes(webp_bytes: bytes, file_name: str = "") -> Tuple[bytes, CleanResult]:
    """Strip caBX, JUMB, and claim chunks from WebP losslessly."""
    orig_len = len(webp_bytes)
    result = CleanResult(
        path=file_name,
        format="WebP",
        original_size=orig_len,
        cleaned_size=orig_len,
        bytes_stripped=0,
        modified=False,
    )

    if not (webp_bytes.startswith(b"RIFF") and webp_bytes[8:12] == b"WEBP"):
        result.success = False
        result.error_message = "Invalid WebP signature"
        return webp_bytes, result

    pos = 12
    out_chunks = []
    vp8x_idx = None

    while pos < len(webp_bytes):
        if pos + 8 > len(webp_bytes):
            break
        fourcc = webp_bytes[pos : pos + 4]
        size = struct.unpack("<I", webp_bytes[pos + 4 : pos + 8])[0]
        pos += 8
        payload = webp_bytes[pos : pos + size]
        pos += size
        if size % 2 == 1 and pos < len(webp_bytes):
            pos += 1

        remove = False
        tag = fourcc.decode("latin1", errors="replace")

        if tag in ("caBX", "JUMB", "c2pa"):
            remove = True
            result.items_removed.append(f"WebP_Chunk:{tag}")
        elif tag == "XMP ":
            if any(k in payload.lower() for k in [b"c2pa", b"anthropic", b"claude"]):
                remove = True
                result.items_removed.append("WebP_Chunk:XMP")
        elif tag == "EXIF":
            if any(k in payload.lower() for k in [b"c2pa", b"anthropic files"]):
                remove = True
                result.items_removed.append("WebP_Chunk:EXIF")

        if not remove:
            pad = b"\x00" if (len(payload) % 2 == 1) else b""
            chunk_bytes = fourcc + struct.pack("<I", len(payload)) + payload + pad
            if tag == "VP8X":
                vp8x_idx = len(out_chunks)
            out_chunks.append(chunk_bytes)

    # Adjust VP8X header flags if XMP or EXIF chunk was removed
    if any(item == "WebP_Chunk:XMP" for item in result.items_removed) and vp8x_idx is not None:
        chunk = bytearray(out_chunks[vp8x_idx])
        chunk[8] &= ~0x04  # clear XMP bit
        out_chunks[vp8x_idx] = bytes(chunk)
    if any(item == "WebP_Chunk:EXIF" for item in result.items_removed) and vp8x_idx is not None:
        chunk = bytearray(out_chunks[vp8x_idx])
        chunk[8] &= ~0x08  # clear EXIF bit
        out_chunks[vp8x_idx] = bytes(chunk)

    payload_stream = b"".join(out_chunks)
    new_riff_size = 4 + len(payload_stream)
    new_header = b"RIFF" + struct.pack("<I", new_riff_size) + b"WEBP"
    cleaned_bytes = new_header + payload_stream

    result.cleaned_size = len(cleaned_bytes)
    result.bytes_stripped = orig_len - len(cleaned_bytes)
    result.modified = result.bytes_stripped > 0
    return cleaned_bytes, result


def clean_bytes(data: bytes, ext: str, file_name: str = "") -> Tuple[bytes, CleanResult]:
    ext_clean = ext.lower().lstrip(".")
    if ext_clean == "svg":
        return clean_svg_bytes(data, file_name)
    elif ext_clean == "png":
        return clean_png_bytes(data, file_name)
    elif ext_clean in ("jpg", "jpeg"):
        return clean_jpeg_bytes(data, file_name)
    elif ext_clean == "webp":
        return clean_webp_bytes(data, file_name)
    else:
        # Check by signature
        if data.startswith(b"<?xml") or b"<svg" in data[:500]:
            return clean_svg_bytes(data, file_name)
        elif data.startswith(b"\x89PNG"):
            return clean_png_bytes(data, file_name)
        elif data.startswith(b"\xFF\xD8"):
            return clean_jpeg_bytes(data, file_name)
        elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
            return clean_webp_bytes(data, file_name)

        return data, CleanResult(
            path=file_name,
            format="Unsupported",
            original_size=len(data),
            cleaned_size=len(data),
            bytes_stripped=0,
            modified=False,
        )


def clean_zip_archive(
    input_zip: str,
    output_zip: Optional[str] = None,
    in_place: bool = False,
    backup: bool = False,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
) -> ArchiveCleanResult:
    """Clean all media files inside a ZIP archive."""
    if not os.path.exists(input_zip):
        raise FileNotFoundError(f"Archive not found: {input_zip}")

    orig_zip_size = os.path.getsize(input_zip)
    dest_zip = output_zip if output_zip else (input_zip if in_place else input_zip.replace(".zip", "_purified.zip"))

    if backup and (in_place or dest_zip == input_zip):
        shutil.copy2(input_zip, input_zip + ".bak")

    # Use a temporary file during creation to support in-place writing safely
    temp_fd, temp_path = tempfile.mkstemp(suffix=".zip", dir=os.path.dirname(os.path.abspath(input_zip)))
    os.close(temp_fd)

    file_results: List[CleanResult] = []
    total_stripped = 0
    modified_count = 0

    try:
        with zipfile.ZipFile(input_zip, "r") as z_in, zipfile.ZipFile(
            temp_path, "w", compression=zipfile.ZIP_DEFLATED
        ) as z_out:
            items = z_in.infolist()
            total_items = len(items)

            for idx, item in enumerate(items):
                if progress_cb:
                    progress_cb(item.filename, idx + 1, total_items)

                raw_content = z_in.read(item.filename)
                ext = item.filename.lower().split(".")[-1]

                if ext in ("svg", "png", "jpg", "jpeg", "webp"):
                    cleaned_content, res = clean_bytes(raw_content, ext, item.filename)
                    file_results.append(res)
                    if res.modified:
                        modified_count += 1
                        total_stripped += res.bytes_stripped
                    z_out.writestr(item, cleaned_content)
                else:
                    z_out.writestr(item, raw_content)

        # Replace destination file
        if os.path.exists(dest_zip) and (dest_zip != temp_path):
            os.remove(dest_zip)
        os.replace(temp_path, dest_zip)

        new_zip_size = os.path.getsize(dest_zip)
        media_count = len(file_results)

        return ArchiveCleanResult(
            archive_path=dest_zip,
            total_files=total_items,
            media_files=media_count,
            files_modified=modified_count,
            original_size=orig_zip_size,
            cleaned_size=new_zip_size,
            bytes_stripped=orig_zip_size - new_zip_size,
            file_results=file_results,
            success=True,
        )

    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return ArchiveCleanResult(
            archive_path=input_zip,
            total_files=0,
            media_files=0,
            files_modified=0,
            original_size=orig_zip_size,
            cleaned_size=orig_zip_size,
            bytes_stripped=0,
            success=False,
            error_message=str(e),
        )


def clean_file(
    input_path: str,
    output_path: Optional[str] = None,
    in_place: bool = False,
    backup: bool = False,
) -> CleanResult:
    """Clean a single file or ZIP archive on disk."""
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"File not found: {input_path}")

    ext = os.path.splitext(input_path)[1].lower()

    if ext == ".zip":
        res_arch = clean_zip_archive(input_path, output_path, in_place=in_place, backup=backup)
        return CleanResult(
            path=input_path,
            format="ZIP",
            original_size=res_arch.original_size,
            cleaned_size=res_arch.cleaned_size,
            bytes_stripped=res_arch.bytes_stripped,
            modified=res_arch.files_modified > 0,
            items_removed=[f"Modified {res_arch.files_modified}/{res_arch.media_files} media files"],
            success=res_arch.success,
            error_message=res_arch.error_message,
        )

    with open(input_path, "rb") as f:
        data = f.read()

    cleaned_data, res = clean_bytes(data, ext, input_path)

    if not res.modified and not output_path and not in_place:
        return res

    dest = output_path if output_path else (input_path if in_place else _default_output_path(input_path))

    if backup and (in_place or dest == input_path):
        shutil.copy2(input_path, input_path + ".bak")

    # Atomic write
    temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(input_path)))
    os.close(temp_fd)
    with open(temp_path, "wb") as f:
        f.write(cleaned_data)

    if os.path.exists(dest) and (dest != temp_path):
        os.remove(dest)
    os.replace(temp_path, dest)
    res.path = dest
    return res


def clean_directory(
    dir_path: str,
    output_dir: Optional[str] = None,
    recursive: bool = True,
    in_place: bool = False,
    backup: bool = False,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
) -> BatchCleanResult:
    """Clean all supported media files and zip archives in a directory."""
    if not os.path.isdir(dir_path):
        raise NotADirectoryError(f"Directory not found: {dir_path}")

    supported_exts = {".svg", ".png", ".jpg", ".jpeg", ".webp", ".zip"}
    all_files = []

    if recursive:
        for root, _, files in os.walk(dir_path):
            for file in files:
                if os.path.splitext(file)[1].lower() in supported_exts:
                    all_files.append(os.path.join(root, file))
    else:
        for file in os.listdir(dir_path):
            full_path = os.path.join(dir_path, file)
            if os.path.isfile(full_path) and os.path.splitext(file)[1].lower() in supported_exts:
                all_files.append(full_path)

    total_files = len(all_files)
    batch_res = BatchCleanResult(total_inspected=total_files, total_modified=0, total_bytes_stripped=0)

    for idx, fpath in enumerate(all_files):
        if progress_cb:
            progress_cb(fpath, idx + 1, total_files)

        out_path = None
        if output_dir:
            rel_path = os.path.relpath(fpath, dir_path)
            out_path = os.path.join(output_dir, rel_path)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)

        res = clean_file(fpath, output_path=out_path, in_place=in_place, backup=backup)
        batch_res.results.append(res)
        if res.modified:
            batch_res.total_modified += 1
            batch_res.total_bytes_stripped += res.bytes_stripped

    return batch_res


def _default_output_path(file_path: str) -> str:
    base, ext = os.path.splitext(file_path)
    return f"{base}_purified{ext}"
