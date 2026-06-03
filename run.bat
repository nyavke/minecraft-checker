@echo off
chcp 65001 >nul 2>&1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"

:: ─── Find Python ──────────────────────────────────────────────────────────────
set PYTHON_EXE=
for /f "delims=" %%i in ('where python 2^>nul') do (
    if not defined PYTHON_EXE set PYTHON_EXE=%%i
)

:: If not in PATH — search common install locations
if not defined PYTHON_EXE (
    for %%p in (
        "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
        "C:\Python313\python.exe"
        "C:\Python312\python.exe"
        "C:\Program Files\Python313\python.exe"
        "C:\Program Files\Python312\python.exe"
        "C:\Program Files (x86)\Python313\python.exe"
    ) do (
        if exist %%p if not defined PYTHON_EXE set PYTHON_EXE=%%p
    )
)

:: ─── Install Python if not found ─────────────────────────────────────────────
if not defined PYTHON_EXE (
    echo.
    echo  [!] Python not found. Starting installation...
    echo.

    :: Use local installer if present next to this bat file
    set PY_INSTALLER=%~dp0python-3.13.9-amd64.exe
    if exist "%PY_INSTALLER%" (
        echo  [*] Using local installer: python-3.13.9-amd64.exe
        goto :do_install
    )

    :: Download from python.org
    set PY_URL=https://www.python.org/ftp/python/3.13.9/python-3.13.9-amd64.exe
    set PY_INSTALLER=%TEMP%\python-3.13.9-amd64.exe
    echo  [*] Downloading Python 3.13.9 (~27 MB)...
    powershell -NoProfile -Command ^
        "try { Invoke-WebRequest -Uri '%PY_URL%' -OutFile '%PY_INSTALLER%' -UseBasicParsing } " ^
        "catch { Write-Host '[!] Download failed: ' $_.Exception.Message; exit 1 }"

    if %errorlevel% neq 0 (
        echo  [!] Download failed. Download manually: https://www.python.org/downloads/
        pause & exit /b 1
    )

    :do_install
    echo  [*] Installing Python (this may take a minute)...
    start /wait "" "%PY_INSTALLER%" /passive InstallAllUsers=0 PrependPath=1 Include_test=0

    :: Search for newly installed python.exe in user profile
    for %%p in (
        "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    ) do (
        if exist %%p if not defined PYTHON_EXE set PYTHON_EXE=%%p
    )

    :: Also try system-wide
    if not defined PYTHON_EXE (
        for %%p in (
            "C:\Python313\python.exe"
            "C:\Program Files\Python313\python.exe"
        ) do (
            if exist %%p if not defined PYTHON_EXE set PYTHON_EXE=%%p
        )
    )

    if not defined PYTHON_EXE (
        echo.
        echo  [!] Python installed but not found. Close this window and run bat again.
        pause & exit /b 1
    )

    echo  [OK] Python installed: %PYTHON_EXE%
    echo.
)

:: ─── Install dependencies using the exact python path ─────────────────────────
"%PYTHON_EXE%" -c "import psutil" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [*] Installing dependencies...
    "%PYTHON_EXE%" -m pip install -r "%~dp0requirements.txt" --quiet
    if %errorlevel% neq 0 (
        echo  [!] Dependency install failed. Try running as Administrator.
        pause & exit /b 1
    )
    echo  [OK] Dependencies installed.
    echo.
)

:: ─── Run scanner ──────────────────────────────────────────────────────────────
"%PYTHON_EXE%" "%~dp0scan.py" %*
