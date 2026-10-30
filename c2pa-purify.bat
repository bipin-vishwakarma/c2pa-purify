@echo off
setlocal enabledelayedexpansion
title C2PA Purifier

:: Change working directory to the folder containing this batch script
cd /d "%~dp0"

:: 1. Search for available Python executable
set "PYTHON_EXE="

where python >nul 2>&1
if !errorlevel! equ 0 (
    set "PYTHON_EXE=python"
    goto :PYTHON_FOUND
)

where py >nul 2>&1
if !errorlevel! equ 0 (
    set "PYTHON_EXE=py"
    goto :PYTHON_FOUND
)

if exist "C:\Python314\python.exe" (
    set "PYTHON_EXE=C:\Python314\python.exe"
    goto :PYTHON_FOUND
)

if exist "C:\Python313\python.exe" (
    set "PYTHON_EXE=C:\Python313\python.exe"
    goto :PYTHON_FOUND
)

for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    if exist "%%D\python.exe" (
        set "PYTHON_EXE=%%D\python.exe"
        goto :PYTHON_FOUND
    )
)

:PYTHON_NOT_FOUND
echo ============================================================
echo [ERROR] Python executable was not found on your system!
echo ============================================================
echo Please install Python (version 3.10 or newer) from:
echo   https://www.python.org/downloads/
echo Make sure to check the box "Add python.exe to PATH" during install.
echo ============================================================
echo.
pause
exit /b 1

:PYTHON_FOUND
:: 2. Check if run with arguments (or when a file is dragged and dropped onto this .bat)
if not "%~1"=="" (
    "%PYTHON_EXE%" "%~dp0c2pa_purify_cli.py" %*
    echo.
    echo ============================================================
    echo Process complete. Press any key to close this window...
    pause >nul
    exit /b !errorlevel!
)

:: 3. Interactive mode when double-clicked with no arguments
"%PYTHON_EXE%" "%~dp0c2pa_purify_cli.py"

if !errorlevel! neq 0 (
    echo.
    echo [Notice] Program finished with status code !errorlevel!.
    pause
)
