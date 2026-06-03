@echo off
chcp 65001 >nul 2>&1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"

set PYTHON_EXE=

:: Check if python is already in PATH
for /f "delims=" %%i in ('where python 2^>nul') do (
    if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
)

:: Search common install locations if not in PATH
if not defined PYTHON_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if not defined PYTHON_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PYTHON_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if not defined PYTHON_EXE if exist "C:\Python313\python.exe" set "PYTHON_EXE=C:\Python313\python.exe"
if not defined PYTHON_EXE if exist "C:\Python312\python.exe" set "PYTHON_EXE=C:\Python312\python.exe"
if not defined PYTHON_EXE if exist "C:\Program Files\Python313\python.exe" set "PYTHON_EXE=C:\Program Files\Python313\python.exe"

:: -----------------------------------------------------------------------
:: Install Python if not found
:: -----------------------------------------------------------------------
if not defined PYTHON_EXE (
    echo.
    echo  [!] Python not found. Starting installation...
    echo.

    set "PY_INSTALLER=%~dp0python-3.13.9-amd64.exe"
    if exist "%~dp0python-3.13.9-amd64.exe" (
        echo  [*] Using local installer: python-3.13.9-amd64.exe
        goto :do_install
    )

    set "PY_INSTALLER=%TEMP%\python-3.13.9-amd64.exe"
    echo  [*] Downloading Python 3.13.9 (~27 MB)...
    powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.13.9/python-3.13.9-amd64.exe' -OutFile '%TEMP%\python-3.13.9-amd64.exe' -UseBasicParsing"
    if %errorlevel% neq 0 (
        echo  [!] Download failed. Get it from: https://www.python.org/downloads/
        pause
        exit /b 1
    )

    :do_install
    echo  [*] Installing Python...
    start /wait "" "%PY_INSTALLER%" /passive InstallAllUsers=0 PrependPath=1 Include_test=0

    :: Find newly installed python
    if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    if not defined PYTHON_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    if not defined PYTHON_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"

    if not defined PYTHON_EXE (
        echo  [!] Python installed but not found. Close and run bat again.
        pause
        exit /b 1
    )
    echo  [OK] Python installed: %PYTHON_EXE%
    echo.
)

:: -----------------------------------------------------------------------
:: Install dependencies
:: -----------------------------------------------------------------------
"%PYTHON_EXE%" -c "import psutil" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [*] Installing dependencies...
    "%PYTHON_EXE%" -m pip install -r "%~dp0requirements.txt" --quiet
    if %errorlevel% neq 0 (
        echo  [!] Failed to install dependencies. Try running as Administrator.
        pause
        exit /b 1
    )
    echo  [OK] Dependencies installed.
    echo.
)

:: -----------------------------------------------------------------------
:: Run scanner
:: -----------------------------------------------------------------------
"%PYTHON_EXE%" "%~dp0scan.py" %*
