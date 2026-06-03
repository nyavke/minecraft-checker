@echo off
chcp 65001 >nul 2>&1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"

:: ─── Проверка Python ──────────────────────────────────────────────────────────
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [!] Python не найден. Начинаю установку...
    echo.

    :: Сначала ищем установщик рядом с bat-файлом
    set PY_INSTALLER=%~dp0python-3.13.9-amd64.exe
    if exist "%PY_INSTALLER%" (
        echo  [*] Найден локальный установщик: python-3.13.9-amd64.exe
        goto :install_python
    )

    :: Если нет — скачиваем
    set PY_URL=https://www.python.org/ftp/python/3.13.9/python-3.13.9-amd64.exe
    set PY_INSTALLER=%TEMP%\python-3.13.9-amd64.exe

    echo  [*] Скачивание Python 3.13.9 (~27 МБ)...
    powershell -NoProfile -Command ^
        "try { Invoke-WebRequest -Uri '%PY_URL%' -OutFile '%PY_INSTALLER%' -UseBasicParsing } " ^
        "catch { Write-Host '  Ошибка: ' $_.Exception.Message -ForegroundColor Red; exit 1 }"

    if %errorlevel% neq 0 (
        echo.
        echo  [!] Не удалось скачать Python.
        echo      Скачайте вручную: https://www.python.org/downloads/
        echo.
        pause
        exit /b 1
    )

    :install_python
    echo  [*] Запуск установщика Python...
    start /wait "" "%PY_INSTALLER%" /passive InstallAllUsers=1 PrependPath=1 Include_test=0

    :: Удаляем только если качали во временную папку
    if "%PY_INSTALLER%"=="%TEMP%\python-3.13.9-amd64.exe" (
        del "%PY_INSTALLER%" >nul 2>&1
    )

    :: Обновляем PATH в текущей сессии
    for /f "tokens=*" %%i in ('powershell -NoProfile -Command "[System.Environment]::GetEnvironmentVariable(\"Path\",\"Machine\")"') do set PATH=%%i;%PATH%

    python --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo.
        echo  [!] Перезапустите run.bat — PATH обновится в новом окне.
        echo.
        pause
        exit /b 1
    )

    echo  [OK] Python установлен успешно!
    echo.
)

:: ─── Установка зависимостей ───────────────────────────────────────────────────
python -c "import psutil" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [*] Установка зависимостей...
    pip install -r requirements.txt --quiet
    if %errorlevel% neq 0 (
        echo  [!] Ошибка установки зависимостей. Запустите от имени администратора.
        pause
        exit /b 1
    )
    echo  [OK] Зависимости установлены.
    echo.
)

:: ─── Запуск сканера ───────────────────────────────────────────────────────────
python scan.py %*
