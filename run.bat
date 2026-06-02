@echo off
chcp 65001 >nul 2>&1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"

:: ─── Проверка Python ──────────────────────────────────────────────────────────
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [!] Python не найден. Начинаю загрузку...
    echo.

    :: Скачиваем установщик Python 3.13 через PowerShell
    set PY_URL=https://www.python.org/ftp/python/3.13.3/python-3.13.3-amd64.exe
    set PY_INSTALLER=%TEMP%\python-installer.exe

    powershell -NoProfile -Command ^
        "Write-Host '  Скачивание Python 3.13.3...' -ForegroundColor Cyan; " ^
        "try { Invoke-WebRequest -Uri '%PY_URL%' -OutFile '%PY_INSTALLER%' -UseBasicParsing } " ^
        "catch { Write-Host '  Ошибка загрузки: ' $_.Exception.Message -ForegroundColor Red; exit 1 }"

    if %errorlevel% neq 0 (
        echo.
        echo  [!] Не удалось скачать Python.
        echo      Скачайте вручную: https://www.python.org/downloads/
        echo.
        pause
        exit /b 1
    )

    echo.
    echo  [*] Запуск установщика Python...
    echo      - Установите для всех пользователей
    echo      - Отметьте "Add Python to PATH"
    echo.

    :: Запускаем установщик (не тихо — чтобы пользователь мог выбрать путь и PATH)
    start /wait "" "%PY_INSTALLER%" /passive InstallAllUsers=1 PrependPath=1 Include_test=0

    :: Удаляем установщик
    del "%PY_INSTALLER%" >nul 2>&1

    :: Обновляем PATH в текущей сессии
    for /f "tokens=*" %%i in ('powershell -NoProfile -Command "[System.Environment]::GetEnvironmentVariable(\"Path\",\"Machine\")"') do set PATH=%%i;%PATH%

    :: Проверяем снова
    python --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo.
        echo  [!] Python установлен, но требуется перезапуск.
        echo      Закройте это окно и запустите run.bat снова.
        echo.
        pause
        exit /b 1
    )

    echo.
    echo  [OK] Python установлен успешно!
    echo.
)

:: ─── Установка зависимостей ───────────────────────────────────────────────────
python -c "import psutil" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [*] Установка зависимостей...
    pip install -r requirements.txt --quiet
    if %errorlevel% neq 0 (
        echo  [!] Ошибка установки зависимостей. Попробуйте запустить от имени администратора.
        pause
        exit /b 1
    )
    echo  [OK] Зависимости установлены.
    echo.
)

:: ─── Запуск сканера ───────────────────────────────────────────────────────────
python scan.py %*
