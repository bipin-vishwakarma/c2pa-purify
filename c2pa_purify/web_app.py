"""
Web Interface for c2pa-purify powered by FastAPI and modern HTML5 UI.
"""

from __future__ import annotations

import io
import json
import os
import zipfile
from dataclasses import asdict
from typing import Optional

from fastapi import FastAPI, File, HTTPException, Response, UploadFile
from fastapi.responses import HTMLResponse

from .cleaner import clean_bytes
from .inspector import inspect_bytes

app = FastAPI(title="C2PA Purifier", description="Strip C2PA and Anthropic provenance records")

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>C2PA Purifier & Provenance Sanitizer</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --accent: #58a6ff;
      --accent-hover: #79c0ff;
      --danger: #f85149;
      --success: #3fb950;
      --warning: #d29922;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --text-bright: #f0f6fc;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2.5rem 1rem;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
    }
    .container {
      width: 100%;
      max-width: 860px;
    }
    header {
      text-align: center;
      margin-bottom: 2rem;
    }
    h1 {
      font-size: 2.2rem;
      color: var(--text-bright);
      margin-bottom: 0.5rem;
      font-weight: 700;
      letter-spacing: -0.5px;
    }
    h1 span.badge {
      font-size: 0.85rem;
      vertical-align: middle;
      background: #1f6feb22;
      border: 1px solid #1f6feb;
      color: var(--accent);
      padding: 0.2rem 0.6rem;
      border-radius: 999px;
      margin-left: 0.5rem;
    }
    p.subtitle {
      color: var(--text-muted);
      font-size: 1.05rem;
    }
    .drop-zone {
      background: var(--card-bg);
      border: 2px dashed var(--border);
      border-radius: 12px;
      padding: 3rem 2rem;
      text-align: center;
      cursor: pointer;
      transition: all 0.2s ease;
      position: relative;
    }
    .drop-zone:hover, .drop-zone.dragover {
      border-color: var(--accent);
      background: #1c2128;
    }
    .drop-icon {
      font-size: 3rem;
      margin-bottom: 1rem;
      display: block;
    }
    .drop-zone h3 {
      font-size: 1.25rem;
      color: var(--text-bright);
      margin-bottom: 0.5rem;
    }
    .drop-zone p {
      color: var(--text-muted);
      font-size: 0.95rem;
      margin-bottom: 1rem;
    }
    .btn-row {
      display: flex;
      gap: 1rem;
      justify-content: center;
      margin-top: 1rem;
    }
    button, .file-label {
      background: #238636;
      color: #fff;
      border: none;
      padding: 0.65rem 1.4rem;
      font-size: 0.95rem;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      text-decoration: none;
    }
    button:hover, .file-label:hover { background: #2ea043; }
    button.btn-secondary {
      background: #21262d;
      color: var(--text-bright);
      border: 1px solid var(--border);
    }
    button.btn-secondary:hover { background: #30363d; }
    input[type="file"] { display: none; }

    .result-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      margin-top: 2rem;
      padding: 1.5rem;
      display: none;
      animation: fadeIn 0.25s ease;
    }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }

    .result-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1rem;
      margin-bottom: 1rem;
    }
    .status-pill {
      font-size: 0.85rem;
      font-weight: 700;
      padding: 0.25rem 0.75rem;
      border-radius: 999px;
    }
    .status-pill.danger { background: #f8514922; border: 1px solid var(--danger); color: var(--danger); }
    .status-pill.success { background: #3fb95022; border: 1px solid var(--success); color: var(--success); }

    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .meta-item {
      background: #0d1117;
      padding: 0.75rem 1rem;
      border-radius: 8px;
      border: 1px solid #21262d;
    }
    .meta-label {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-muted);
      margin-bottom: 0.25rem;
    }
    .meta-val {
      font-size: 0.95rem;
      font-weight: 600;
      color: var(--text-bright);
      word-break: break-all;
    }
    .details-box {
      background: #090d12;
      border: 1px solid #21262d;
      border-radius: 8px;
      padding: 1rem;
      font-family: monospace;
      font-size: 0.85rem;
      color: #7ee787;
      white-space: pre-wrap;
      max-height: 240px;
      overflow-y: auto;
      margin-bottom: 1.5rem;
    }
    .action-bar {
      display: flex;
      gap: 1rem;
      justify-content: flex-end;
    }
    footer {
      margin-top: 3rem;
      color: var(--text-muted);
      font-size: 0.85rem;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>C2PA Purifier <span class="badge">v1.0</span></h1>
      <p class="subtitle">Inspect, strip, and eliminate embedded C2PA provenance & Anthropic Files claim markers</p>
    </header>

    <div class="drop-zone" id="dropZone">
      <span class="drop-icon">🛡️</span>
      <h3>Drop your SVG, PNG, JPEG, WebP, or ZIP archive here</h3>
      <p>Instant lossless sanitization • Zero quality degradation • Local in-memory processing</p>
      <div class="btn-row">
        <label class="file-label" for="fileInput">Browse Files</label>
        <input type="file" id="fileInput" accept=".svg,.png,.jpg,.jpeg,.webp,.zip">
      </div>
    </div>

    <div class="result-card" id="resultCard">
      <div class="result-header">
        <div>
          <h3 id="resFileName" style="color:var(--text-bright)">filename.svg</h3>
          <span id="resFileSize" style="color:var(--text-muted); font-size:0.85rem">20 KB</span>
        </div>
        <span class="status-pill danger" id="resStatus">C2PA DETECTED</span>
      </div>

      <div class="meta-grid" id="metaGrid">
        <!-- Dynamically injected -->
      </div>

      <div class="details-box" id="detailsBox">Details will appear here...</div>

      <div class="action-bar">
        <button class="btn-secondary" id="btnInspectAgain">Inspect Again</button>
        <button id="btnPurifyDownload">✨ Purify & Download</button>
      </div>
    </div>

    <footer>
      Processed locally on your machine • 100% Offline • Preserves image rendering bit-for-bit
    </footer>
  </div>

  <script>
    let activeFile = null;

    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const resultCard = document.getElementById('resultCard');
    const resFileName = document.getElementById('resFileName');
    const resFileSize = document.getElementById('resFileSize');
    const resStatus = document.getElementById('resStatus');
    const metaGrid = document.getElementById('metaGrid');
    const detailsBox = document.getElementById('detailsBox');
    const btnPurifyDownload = document.getElementById('btnPurifyDownload');
    const btnInspectAgain = document.getElementById('btnInspectAgain');

    ['dragenter', 'dragover'].forEach(name => {
      dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
    });
    ['dragleave', 'drop'].forEach(name => {
      dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.remove('dragover'); });
    });

    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
      if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length) handleFile(e.target.files[0]);
    });

    function formatBytes(bytes) {
      if (!bytes) return '0 B';
      const k = 1024, dm = 1;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    async function handleFile(file) {
      activeFile = file;
      resFileName.textContent = file.name;
      resFileSize.textContent = formatBytes(file.size);
      resultCard.style.display = 'block';

      resStatus.className = 'status-pill';
      resStatus.textContent = 'ANALYZING...';
      detailsBox.textContent = 'Scanning metadata, JUMBF boxes, and claim assertions...';

      const formData = new FormData();
      formData.append('file', file);

      try {
        const resp = await fetch('/api/inspect', { credentials: 'omit', method: 'POST', body: formData });
        const data = await resp.json();
        renderInspectionData(data);
      } catch (err) {
        detailsBox.textContent = 'Inspection error: ' + err.message;
      }
    }

    function renderInspectionData(data) {
      metaGrid.innerHTML = '';

      if (data.has_c2pa) {
        resStatus.className = 'status-pill danger';
        resStatus.textContent = 'C2PA PROVENANCE RECORD DETECTED';
      } else {
        resStatus.className = 'status-pill success';
        resStatus.textContent = 'CLEAN - NO C2PA METADATA';
      }

      function addMeta(label, val) {
        if (!val) return;
        const d = document.createElement('div');
        d.className = 'meta-item';
        d.innerHTML = `<div class="meta-label">${label}</div><div class="meta-val">${val}</div>`;
        metaGrid.appendChild(d);
      }

      addMeta('Format', data.format);
      addMeta('File Size', formatBytes(data.file_size_bytes));

      if (data.manifest) {
        const m = data.manifest;
        addMeta('Claim Generator', m.claim_generator + (m.claim_generator_version ? ' ' + m.claim_generator_version : ''));
        addMeta('Software Agent', m.software_agent);
        addMeta('Action Asserted', m.action);
        addMeta('Overhead', formatBytes(m.raw_size_bytes));
      }

      let log = data.summary_message + '\n\n';
      if (data.manifest) {
        const m = data.manifest;
        if (m.manifest_urn) log += `• Manifest URN: ${m.manifest_urn}\n`;
        if (m.description) log += `• Statement: "${m.description}"\n`;
        if (m.locations && m.locations.length) log += `• Embedded In: ${m.locations.join(', ')}\n`;
        if (m.certificates && m.certificates.length) {
          log += `\n[ Signing Certificates ]\n`;
          m.certificates.forEach((c, i) => {
            log += `  [${i+1}] Subject: ${c.subject}\n      Issuer: ${c.issuer}\n      Validity: ${c.valid_from} to ${c.valid_to}\n`;
          });
        }
      }
      detailsBox.textContent = log;
    }

    btnPurifyDownload.addEventListener('click', async () => {
      if (!activeFile) return;
      btnPurifyDownload.disabled = true;
      btnPurifyDownload.textContent = 'Purifying...';

      const formData = new FormData();
      formData.append('file', activeFile);

      try {
        const resp = await fetch('/api/clean', { credentials: 'omit', method: 'POST', body: formData });
        if (!resp.ok) throw new Error('Purification failed');

        const blob = await resp.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;

        let outName = activeFile.name;
        const dotIdx = outName.lastIndexOf('.');
        if (dotIdx > 0) {
          outName = outName.substring(0, dotIdx) + '_purified' + outName.substring(dotIdx);
        } else {
          outName += '_purified';
        }
        a.download = outName;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        btnPurifyDownload.textContent = '✅ Downloaded Clean File!';
        setTimeout(() => {
          btnPurifyDownload.disabled = false;
          btnPurifyDownload.textContent = '✨ Purify & Download';
        }, 3000);

      } catch (err) {
        alert('Error: ' + err.message);
        btnPurifyDownload.disabled = false;
        btnPurifyDownload.textContent = '✨ Purify & Download';
      }
    });

    btnInspectAgain.addEventListener('click', () => {
      if (activeFile) handleFile(activeFile);
    });
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def get_index():
    return HTML_TEMPLATE


@app.post("/api/inspect")
async def api_inspect(file: UploadFile = File(...)):
    data = await file.read()
    ext = os.path.splitext(file.filename or "")[1].lower()
    res = inspect_bytes(data, ext, file.filename or "")
    return asdict(res)


@app.post("/api/clean")
async def api_clean(file: UploadFile = File(...)):
    data = await file.read()
    ext = os.path.splitext(file.filename or "")[1].lower()

    if ext == ".zip":
        in_buf = io.BytesIO(data)
        out_buf = io.BytesIO()
        with zipfile.ZipFile(in_buf, "r") as z_in, zipfile.ZipFile(
            out_buf, "w", compression=zipfile.ZIP_DEFLATED
        ) as z_out:
            for item in z_in.infolist():
                content = z_in.read(item.filename)
                item_ext = item.filename.lower().split(".")[-1]
                if item_ext in ("svg", "png", "jpg", "jpeg", "webp"):
                    cleaned, _ = clean_bytes(content, item_ext, item.filename)
                    z_out.writestr(item, cleaned)
                else:
                    z_out.writestr(item, content)

        cleaned_bytes = out_buf.getvalue()
        mime_type = "application/zip"
    else:
        cleaned_bytes, _ = clean_bytes(data, ext, file.filename or "")
        mime_map = {
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".webp": "image/webp",
        }
        mime_type = mime_map.get(ext, "application/octet-stream")

    return Response(
        content=cleaned_bytes,
        media_type=mime_type,
        headers={"Content-Disposition": f'attachment; filename="purified_{file.filename}"'},
    )


def run_web_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    import uvicorn
    from rich.console import Console

    c = Console()
    c.print(f"[bold green]Starting C2PA Purifier Web UI[/bold green] on [bold cyan]http://{host}:{port}[/bold cyan]")
    c.print("[dim]Drop files or zip archives in your browser to inspect and purify. Press Ctrl+C to stop.[/dim]")
    uvicorn.run(app, host=host, port=port, log_level="warning")
