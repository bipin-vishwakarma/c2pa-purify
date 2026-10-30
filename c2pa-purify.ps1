$ErrorActionPreference = "Continue"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Find Python executable
$pythonExe = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonExe = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonExe = "py"
} elseif (Test-Path "C:\Python314\python.exe") {
    $pythonExe = "C:\Python314\python.exe"
} elseif (Test-Path "C:\Python313\python.exe") {
    $pythonExe = "C:\Python313\python.exe"
}

if (-not $pythonExe) {
    Write-Host "[ERROR] Python was not found on your system." -ForegroundColor Red
    Write-Host "Please install Python 3.10+ from https://www.python.org/downloads/"
    pause
    exit 1
}

& $pythonExe "$scriptDir\c2pa_purify_cli.py" @args
