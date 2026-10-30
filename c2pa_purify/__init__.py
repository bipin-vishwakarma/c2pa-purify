"""
c2pa-purify: Professional tool to inspect, strip, and sanitize embedded C2PA provenance records,
JUMBF manifests, and Anthropic Files / Claude claim markers from SVGs, PNGs, JPEGs, WebPs, and ZIP archives.
"""

from .cleaner import (
    ArchiveCleanResult,
    BatchCleanResult,
    CleanResult,
    clean_bytes,
    clean_directory,
    clean_file,
    clean_jpeg_bytes,
    clean_png_bytes,
    clean_svg_bytes,
    clean_webp_bytes,
    clean_zip_archive,
)
from .inspector import (
    CertificateInfo,
    InspectionResult,
    ManifestInfo,
    inspect_bytes,
    inspect_file,
    inspect_jpeg,
    inspect_png,
    inspect_svg,
    inspect_webp,
    inspect_zip,
)
from .validator import (
    ValidationReport,
    validate_file,
    validate_jpeg,
    validate_png,
    validate_svg,
    validate_webp,
)

__version__ = "1.0.0"

__all__ = [
    "clean_file",
    "clean_directory",
    "clean_zip_archive",
    "clean_bytes",
    "clean_svg_bytes",
    "clean_png_bytes",
    "clean_jpeg_bytes",
    "clean_webp_bytes",
    "inspect_file",
    "inspect_bytes",
    "inspect_svg",
    "inspect_png",
    "inspect_jpeg",
    "inspect_webp",
    "inspect_zip",
    "validate_file",
    "validate_svg",
    "validate_png",
    "validate_jpeg",
    "validate_webp",
    "CleanResult",
    "ArchiveCleanResult",
    "BatchCleanResult",
    "InspectionResult",
    "ManifestInfo",
    "CertificateInfo",
    "ValidationReport",
]
