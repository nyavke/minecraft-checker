@echo off
chcp 65001 >nul 2>&1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"

set PYTHON_EXE=

for /f "delims=" %%i in ('where python 2^>nul') do (
    if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
)

if not defined PYTHON_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if not defined PYTHON_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PYTHON_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if not defined PYTHON_EXE if exist "C:\Python313\python.exe" set "PYTHON_EXE=C:\Python313\python.exe"
if not defined PYTHON_EXE if exist "C:\Python312\python.exe" set "PYTHON_EXE=C:\Python312\python.exe"
if not defined PYTHON_EXE if exist "C:\Program Files\Python313\python.exe" set "PYTHON_EXE=C:\Program Files\Python313\python.exe"

if not defined PYTHON_EXE (
    echo [!] Python not found. Installing...
    set "PY_INSTALLER=%~dp0python-3.13.9-amd64.exe"
    if not exist "%~dp0python-3.13.9-amd64.exe" (
        echo [*] Downloading Python 3.13.9...
        powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.13.9/python-3.13.9-amd64.exe' -OutFile '%~dp0python-3.13.9-amd64.exe' -UseBasicParsing"
        if %errorlevel% neq 0 (
            echo [!] Download failed.
            pause
            exit /b 1
        )
    )
    echo [*] Installing Python...
    start /wait "" "%~dp0python-3.13.9-amd64.exe" /passive InstallAllUsers=0 PrependPath=1 Include_test=0
    if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    if not defined PYTHON_EXE (
        echo [!] Installation failed. Run the bat again.
        pause
        exit /b 1
    )
)

"%PYTHON_EXE%" -c "import psutil" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Installing dependencies...
    "%PYTHON_EXE%" -m pip install --upgrade pip
    "%PYTHON_EXE%" -m pip install -r "%~dp0requirements.txt" --quiet
    if %errorlevel% neq 0 (
        echo [!] Failed to install dependencies.
        pause
        exit /b 1
    )
)
clear >nul 2>&1 || cls >nul 2>&1
"%PYTHON_EXE%" "%~dp0scan.py" %*
