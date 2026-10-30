"""
Command-Line Interface for c2pa-purify.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from .cleaner import clean_directory, clean_file, clean_zip_archive
from .inspector import InspectionResult, inspect_file
from .validator import validate_file

console = Console()


def format_bytes(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} TB"


def render_inspection(result: InspectionResult) -> None:
    """Render a beautiful terminal report of the inspection."""
    if result.format == "ZIP":
        table = Table(title=f"Archive Inspection: [bold cyan]{os.path.basename(result.path)}[/bold cyan]")
        table.add_column("File in Archive", style="white")
        table.add_column("Format", style="dim")
        table.add_column("Size", justify="right")
        table.add_column("C2PA Present?", justify="center")
        table.add_column("Claim Generator", style="yellow")
        table.add_column("Software Agent", style="cyan")

        sub_list = result.archive_details or []
        for sub in sub_list:
            c2pa_badge = "[bold red]YES[/bold red]" if sub.has_c2pa else "[bold green]CLEAN[/bold green]"
            gen = sub.manifest.claim_generator if (sub.manifest and sub.manifest.claim_generator) else "-"
            agent = sub.manifest.software_agent if (sub.manifest and sub.manifest.software_agent) else "-"
            table.add_row(
                os.path.basename(sub.path),
                sub.format,
                format_bytes(sub.file_size_bytes),
                c2pa_badge,
                gen,
                agent,
            )

        console.print(table)
        total_c2pa = sum(1 for s in sub_list if s.has_c2pa)
        console.print(
            f"\n[bold]Archive Summary:[/bold] {len(sub_list)} media items inspected. "
            f"[bold red]{total_c2pa} files carry C2PA / Anthropic claim metadata[/bold red]."
        )
        return

    # Single media file
    status_color = "red" if result.has_c2pa else "green"
    status_text = "C2PA PROVENANCE RECORD DETECTED" if result.has_c2pa else "CLEAN - NO C2PA METADATA"

    panel_content = Text()
    panel_content.append(f"File: ", style="bold")
    panel_content.append(f"{result.path}\n", style="cyan")
    panel_content.append(f"Format: ", style="bold")
    panel_content.append(f"{result.format}\n", style="magenta")
    panel_content.append(f"File Size: ", style="bold")
    panel_content.append(f"{format_bytes(result.file_size_bytes)}\n", style="white")
    panel_content.append(f"Status: ", style="bold")
    panel_content.append(f"{status_text}\n\n", style=f"bold {status_color}")

    if result.manifest and result.manifest.found:
        m = result.manifest
        panel_content.append("[ Embedded Manifest Credentials ]\n", style="bold underline yellow")
        if m.manifest_urn:
            panel_content.append(f"  * Manifest URN:       {m.manifest_urn}\n", style="dim white")
        if m.claim_generator:
            panel_content.append(f"  * Claim Generator:    {m.claim_generator} {m.claim_generator_version}\n", style="yellow")
        if m.spec_version:
            panel_content.append(f"  * C2PA Spec Version:  {m.spec_version}\n", style="dim white")
        if m.software_agent:
            panel_content.append(f"  * Software Agent:     {m.software_agent}\n", style="cyan")
        if m.action:
            panel_content.append(f"  * Action Asserted:    {m.action}\n", style="green")
        if m.description:
            panel_content.append(f"  * Claim Statement:    \"{m.description}\"\n", style="italic white")
        if m.raw_size_bytes:
            pct = (m.raw_size_bytes / result.file_size_bytes * 100) if result.file_size_bytes else 0
            panel_content.append(f"  * Manifest Overhead:  {format_bytes(m.raw_size_bytes)} ({pct:.1f}% of file size)\n", style="dim white")

        if m.locations:
            panel_content.append(f"  * Embedding Location: {', '.join(m.locations)}\n", style="dim white")

        if m.certificates:
            panel_content.append("\n[ Cryptographic Signing Certificates ]\n", style="bold underline cyan")
            for idx, cert in enumerate(m.certificates, 1):
                panel_content.append(f"  [{idx}] Subject:    {cert.subject}\n", style="cyan")
                panel_content.append(f"      Issuer:     {cert.issuer}\n", style="dim cyan")
                panel_content.append(f"      Validity:   {cert.valid_from} to {cert.valid_to}\n", style="dim white")
                panel_content.append(f"      Serial:     {cert.serial_number}\n", style="dim white")

    console.print(Panel(panel_content, title="[bold]C2PA Forensics Inspection[/bold]", border_style=status_color))


def cmd_clean(args: argparse.Namespace) -> int:
    target = args.path
    if not os.path.exists(target):
        console.print(f"[bold red]Error:[/bold red] Target not found: {target}")
        return 1

    dry_run = getattr(args, "dry_run", False)
    in_place = getattr(args, "in_place", False)
    backup = getattr(args, "backup", False)
    output = getattr(args, "output", None)
    verify = getattr(args, "verify", False)
    recursive = getattr(args, "recursive", True)

    if dry_run:
        console.print("[bold yellow]*** DRY RUN MODE (No files will be modified) ***[/bold yellow]\n")

    # Directory
    if os.path.isdir(target):
        console.print(f"[bold cyan]Scanning directory:[/bold cyan] {target}")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total} files"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Processing media...", total=None)

            def progress_cb(filename: str, current: int, total: int) -> None:
                progress.update(task, total=total, completed=current, description=f"[cyan]Cleaning {os.path.basename(filename)}...")

            if dry_run:
                insp = inspect_file(target)
                return 0

            res = clean_directory(
                target,
                output_dir=output,
                recursive=recursive,
                in_place=in_place,
                backup=backup,
                progress_cb=progress_cb,
            )

        table = Table(title="Directory Cleaning Results")
        table.add_column("Files Inspected", justify="right")
        table.add_column("Files Modified", justify="right", style="green")
        table.add_column("Bytes Stripped", justify="right", style="cyan")

        table.add_row(
            str(res.total_inspected),
            str(res.total_modified),
            format_bytes(res.total_bytes_stripped),
        )
        console.print(table)
        return 0

    # ZIP Archive
    ext = os.path.splitext(target)[1].lower()
    if ext == ".zip":
        console.print(f"[bold cyan]Processing ZIP archive:[/bold cyan] {target}")
        if dry_run:
            insp = inspect_file(target)
            render_inspection(insp)
            return 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total} files"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Cleaning archive contents...", total=None)

            def progress_cb_zip(filename: str, current: int, total: int) -> None:
                progress.update(task, total=total, completed=current, description=f"[cyan]{os.path.basename(filename)}...")

            arch_res = clean_zip_archive(
                target,
                output_zip=output,
                in_place=in_place,
                backup=backup,
                progress_cb=progress_cb_zip,
            )

        if not arch_res.success:
            console.print(f"[bold red]Failed to clean archive:[/bold red] {arch_res.error_message}")
            return 1

        table = Table(title=f"Archive Cleaned: [bold green]{os.path.basename(arch_res.archive_path)}[/bold green]")
        table.add_column("Metric", style="bold")
        table.add_column("Value", style="cyan")

        table.add_row("Total Files in Archive", str(arch_res.total_files))
        table.add_row("Media Files Processed", str(arch_res.media_files))
        table.add_row("Files Sanitized & Stripped", f"[bold green]{arch_res.files_modified}[/bold green]")
        table.add_row("Original Archive Size", format_bytes(arch_res.original_size))
        table.add_row("Cleaned Archive Size", format_bytes(arch_res.cleaned_size))
        table.add_row("Total Space Stripped", f"[bold green]{format_bytes(arch_res.bytes_stripped)}[/bold green]")

        console.print(table)
        console.print(f"\n[bold green]Success![/bold green] All C2PA provenance and claim markers removed.")
        console.print(f"Purified output saved to: [bold cyan]{arch_res.archive_path}[/bold cyan]")
        return 0

    # Single media file
    if dry_run:
        insp = inspect_file(target)
        render_inspection(insp)
        return 0

    clean_res = clean_file(target, output_path=output, in_place=in_place, backup=backup)
    if not clean_res.success:
        console.print(f"[bold red]Cleaning failed:[/bold red] {clean_res.error_message}")
        return 1

    if clean_res.modified:
        console.print(f"[bold green]Purified successfully![/bold green] {target}")
        console.print(f"  * Items Removed:     {', '.join(clean_res.items_removed)}")
        console.print(f"  * Original Size:     {format_bytes(clean_res.original_size)}")
        console.print(f"  * Cleaned Size:      {format_bytes(clean_res.cleaned_size)}")
        console.print(
            f"  * Stripped Overhead: [bold green]{format_bytes(clean_res.bytes_stripped)}[/bold green] "
            f"({clean_res.reduction_percentage:.1f}%)"
        )
        console.print(f"  * Saved as:          [bold cyan]{clean_res.path}[/bold cyan]")
    else:
        console.print(f"[bold green]File is already clean.[/bold green] No C2PA records found: {target}")

    if verify:
        with open(clean_res.path, "rb") as f:
            v_data = f.read()
        v_report = validate_file(v_data, ext)
        if v_report.passed:
            console.print(f"  * Verification:      [bold green]PASSED[/bold green] ({v_report.details})")
        else:
            console.print(f"  * Verification:      [bold red]FAILED[/bold red] ({v_report.details})")

    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    target = args.path
    if not os.path.exists(target):
        console.print(f"[bold red]Error:[/bold red] Target not found: {target}")
        return 1

    if os.path.isdir(target):
        # Inspect all in directory
        console.print(f"[bold cyan]Inspecting directory:[/bold cyan] {target}\n")
        table = Table(title=f"Directory Inspection: {os.path.basename(target)}")
        table.add_column("File", style="white")
        table.add_column("Format", style="dim")
        table.add_column("Status", justify="center")
        table.add_column("Generator / Agent", style="yellow")
        table.add_column("Size", justify="right")

        c2pa_count = 0
        total_count = 0
        for root, _, files in os.walk(target):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in (".svg", ".png", ".jpg", ".jpeg", ".webp", ".zip"):
                    total_count += 1
                    fp = os.path.join(root, f)
                    res = inspect_file(fp)
                    if res.has_c2pa:
                        c2pa_count += 1
                        badge = "[bold red]C2PA DETECTED[/bold red]"
                        gen = res.manifest.claim_generator if res.manifest else "C2PA"
                        agent = res.manifest.software_agent if res.manifest else ""
                        claim_str = f"{gen} ({agent})" if agent else gen
                    else:
                        badge = "[bold green]CLEAN[/bold green]"
                        claim_str = "-"

                    table.add_row(
                        os.path.relpath(fp, target),
                        res.format,
                        badge,
                        claim_str,
                        format_bytes(res.file_size_bytes),
                    )

        console.print(table)
        console.print(f"\nTotal media files: {total_count} | [bold red]{c2pa_count} carry C2PA provenance[/bold red]")
        return 0

    res = inspect_file(target)
    render_inspection(res)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    target = args.path
    if not os.path.exists(target):
        console.print(f"[bold red]Error:[/bold red] Target not found: {target}")
        return 1

    ext = os.path.splitext(target)[1].lower()
    with open(target, "rb") as f:
        data = f.read()

    rep = validate_file(data, ext)
    if rep.passed:
        console.print(f"[bold green]VERIFICATION PASSED[/bold green] - {target}")
        console.print(f"  • {rep.details}")
        return 0
    else:
        console.print(f"[bold red]VERIFICATION FAILED[/bold red] - {target}")
        console.print(f"  • Format Valid: {rep.is_valid_format}")
        if rep.format_error:
            console.print(f"  • Format Error: {rep.format_error}")
        if rep.traces_found:
            console.print(f"  • Remaining Traces:")
            for t in rep.traces_found:
                console.print(f"    - [red]{t}[/red]")
        return 1


def cmd_web(args: argparse.Namespace) -> int:
    from .web_app import run_web_server

    port = getattr(args, "port", 8080)
    host = getattr(args, "host", "127.0.0.1")
    run_web_server(host=host, port=port)
    return 0


def interactive_menu() -> int:
    """Interactive console menu when launched with no arguments."""
    console.print(
        Panel.fit(
            "[bold cyan]C2PA Purifier & Metadata Sanitizer[/bold cyan]\n"
            "[dim]Lossless C2PA Provenance & Anthropic Files Claim Stripper[/dim]",
            border_style="cyan",
        )
    )

    while True:
        console.print("\n[bold]Select an option or drag and drop a file/archive here:[/bold]")
        console.print("  [bold green]1[/bold green]. Clean a file or ZIP archive (removes C2PA / Anthropic markers)")
        console.print("  [bold yellow]2[/bold yellow]. Inspect C2PA provenance records & signing certificates")
        console.print("  [bold cyan]3[/bold cyan]. Launch Web UI in browser (drag-and-drop)")
        console.print("  [bold magenta]4[/bold magenta]. Scan a directory for C2PA metadata")
        console.print("  [bold red]q[/bold red]. Exit")

        try:
            choice = input("\nEnter choice or drag & drop file here > ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0

        if not choice or choice.lower() in ("q", "quit", "exit"):
            return 0

        # Clean quotes if user dragged and dropped a file into the prompt
        cleaned_path = choice.strip('"').strip("'")

        if os.path.exists(cleaned_path):
            console.print(f"\n[cyan]Detected:[/cyan] {cleaned_path}")
            sub_choice = input("Action: [1] Purify (clean)  [2] Inspect  (Default: 1) > ").strip()
            if sub_choice == "2":
                args = argparse.Namespace(path=cleaned_path)
                cmd_inspect(args)
            else:
                mode = input("Output mode: [1] Create new purified file  [2] Overwrite in-place (Default: 1) > ").strip()
                in_place = mode == "2"
                backup = False
                if in_place:
                    bk = input("Create .bak backup first? (Y/n) > ").strip().lower()
                    backup = bk != "n"
                args = argparse.Namespace(
                    path=cleaned_path,
                    output=None,
                    in_place=in_place,
                    backup=backup,
                    dry_run=False,
                    verify=True,
                    recursive=True,
                )
                cmd_clean(args)
        elif choice == "1":
            target = input("Enter path of file, folder, or .zip archive to clean: ").strip().strip('"').strip("'")
            if not os.path.exists(target):
                console.print(f"[bold red]File not found:[/bold red] {target}")
                continue
            mode = input("Output mode: [1] Create new purified file  [2] Overwrite in-place (Default: 1) > ").strip()
            in_place = mode == "2"
            backup = False
            if in_place:
                bk = input("Create .bak backup first? (Y/n) > ").strip().lower()
                backup = bk != "n"
            args = argparse.Namespace(
                path=target,
                output=None,
                in_place=in_place,
                backup=backup,
                dry_run=False,
                verify=True,
                recursive=True,
            )
            cmd_clean(args)
        elif choice == "2":
            target = input("Enter path of file or .zip archive to inspect: ").strip().strip('"').strip("'")
            if not os.path.exists(target):
                console.print(f"[bold red]File not found:[/bold red] {target}")
                continue
            args = argparse.Namespace(path=target)
            cmd_inspect(args)
        elif choice == "3":
            cmd_web(argparse.Namespace(host="127.0.0.1", port=8080))
            return 0
        elif choice == "4":
            target = input("Enter directory path to scan (or press Enter for current directory): ").strip().strip('"').strip("'")
            target = target if target else "."
            if not os.path.isdir(target):
                console.print(f"[bold red]Directory not found:[/bold red] {target}")
                continue
            args = argparse.Namespace(path=target)
            cmd_inspect(args)
        else:
            console.print("[yellow]Invalid option. Please try again.[/yellow]")


def main(argv: Optional[List[str]] = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)

    # If no arguments provided (e.g. double-clicked .bat file), launch interactive menu
    if not raw_args:
        return interactive_menu()

    # If the first argument is a file/path and not a known subcommand or flag, default to 'clean'
    known_commands = {"clean", "inspect", "scan", "verify", "web", "-h", "--help", "-v", "--version"}
    if raw_args and raw_args[0] not in known_commands and not raw_args[0].startswith("-"):
        raw_args.insert(0, "clean")

    parser = argparse.ArgumentParser(
        prog="c2pa-purify",
        description="Strip C2PA provenance manifests, JUMBF boxes, and Anthropic Files/Claude claim markers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Clean a single SVG, PNG, or JPEG file
  c2pa-purify clean file.svg -o clean.svg
  c2pa-purify file.svg --in-place

  # Clean all 100 SVGs inside a ZIP archive in-place or to a new zip
  c2pa-purify clean Mrinal_29_10_2026.zip -o Mrinal_cleaned.zip
  c2pa-purify Mrinal_29_10_2026.zip --in-place --backup

  # Inspect embedded C2PA provenance and Anthropic signing certificates
  c2pa-purify inspect file.svg
  c2pa-purify inspect Mrinal_29_10_2026.zip

  # Launch the local drag-and-drop web UI
  c2pa-purify web --port 8080
        """,
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # clean subcommand
    p_clean = subparsers.add_parser("clean", help="Clean C2PA and Anthropic claims from files or archives")
    p_clean.add_argument("path", help="Path to file, directory, or .zip archive")
    p_clean.add_argument("-o", "--output", help="Output file or directory path")
    p_clean.add_argument("-i", "--in-place", action="store_true", help="Modify file(s) in-place")
    p_clean.add_argument("-b", "--backup", action="store_true", help="Create .bak backup before modifying in-place")
    p_clean.add_argument("-r", "--recursive", action="store_true", default=True, help="Recursively process directories")
    p_clean.add_argument("--dry-run", action="store_true", help="Preview modifications without writing to disk")
    p_clean.add_argument("--verify", action="store_true", help="Run verification check after cleaning")
    p_clean.set_defaults(func=cmd_clean)

    # inspect subcommand
    p_inspect = subparsers.add_parser("inspect", help="Inspect and display C2PA provenance and claim metadata")
    p_inspect.add_argument("path", help="Path to file, directory, or .zip archive")
    p_inspect.set_defaults(func=cmd_inspect)

    # scan subcommand
    p_scan = subparsers.add_parser("scan", help="Scan directory or archive for C2PA provenance records")
    p_scan.add_argument("path", help="Path to directory or .zip archive")
    p_scan.set_defaults(func=cmd_inspect)

    # verify subcommand
    p_verify = subparsers.add_parser("verify", help="Verify that a file is completely clean and structurally valid")
    p_verify.add_argument("path", help="Path to file")
    p_verify.set_defaults(func=cmd_verify)

    # web subcommand
    p_web = subparsers.add_parser("web", help="Launch local drag-and-drop web UI")
    p_web.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    p_web.add_argument("--port", type=int, default=8080, help="Port to bind (default: 8080)")
    p_web.set_defaults(func=cmd_web)

    args = parser.parse_args(raw_args)

    if not args.subcommand:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
