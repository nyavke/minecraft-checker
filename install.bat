@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
title PT Check — Установка зависимостей
cd /d "%~dp0"

echo.
echo  ==========================================
echo    PT Check  ^|  Установка зависимостей
echo  ==========================================
echo.

:: ══════════════════════════════════════════════════════════════════════════════
:: Поиск Python
:: ══════════════════════════════════════════════════════════════════════════════
set "PYTHON_EXE="

:: 1. Ищем в PATH (where python)
for /f "delims=" %%i in ('where python 2^>nul') do (
    if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
)

:: 2. Ищем py launcher (Windows Launcher)
if not defined PYTHON_EXE (
    for /f "delims=" %%i in ('where py 2^>nul') do (
        if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
    )
)

:: 3. Стандартные пути (user-install — официальный установщик python.org)
if not defined PYTHON_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if not defined PYTHON_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PYTHON_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if not defined PYTHON_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"

:: 4. Системная установка (all-users)
if not defined PYTHON_EXE if exist "C:\Python313\python.exe"                    set "PYTHON_EXE=C:\Python313\python.exe"
if not defined PYTHON_EXE if exist "C:\Python312\python.exe"                    set "PYTHON_EXE=C:\Python312\python.exe"
if not defined PYTHON_EXE if exist "C:\Python311\python.exe"                    set "PYTHON_EXE=C:\Python311\python.exe"
if not defined PYTHON_EXE if exist "C:\Python310\python.exe"                    set "PYTHON_EXE=C:\Python310\python.exe"
if not defined PYTHON_EXE if exist "C:\Program Files\Python313\python.exe"      set "PYTHON_EXE=C:\Program Files\Python313\python.exe"
if not defined PYTHON_EXE if exist "C:\Program Files\Python312\python.exe"      set "PYTHON_EXE=C:\Program Files\Python312\python.exe"
if not defined PYTHON_EXE if exist "C:\Program Files\Python311\python.exe"      set "PYTHON_EXE=C:\Program Files\Python311\python.exe"
if not defined PYTHON_EXE if exist "C:\Program Files\Python310\python.exe"      set "PYTHON_EXE=C:\Program Files\Python310\python.exe"
if not defined PYTHON_EXE if exist "C:\Program Files (x86)\Python313\python.exe" set "PYTHON_EXE=C:\Program Files (x86)\Python313\python.exe"
if not defined PYTHON_EXE if exist "C:\Program Files (x86)\Python312\python.exe" set "PYTHON_EXE=C:\Program Files (x86)\Python312\python.exe"

:: Python не найден — объяснить пользователю что делать
if not defined PYTHON_EXE (
    echo  [ОШИБКА] Python не найден в системе!
    echo.
    echo  Установите Python 3.13.9 вручную:
    echo.
    echo    1. Скачайте установщик:
    echo       https://www.python.org/ftp/python/3.13.9/python-3.13.9-amd64.exe
    echo.
    echo    2. Запустите установщик
    echo.
    echo    3. ОБЯЗАТЕЛЬНО поставьте галочку:
    echo       [v] Add Python to PATH
    echo.
    echo    4. Нажмите Install Now
    echo.
    echo    5. После установки ПЕРЕЗАПУСТИТЕ этот файл
    echo.
    pause
    exit /b 1
)

:: ══════════════════════════════════════════════════════════════════════════════
:: Проверка версии Python (нужен >= 3.10)
:: ══════════════════════════════════════════════════════════════════════════════
"%PYTHON_EXE%" -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if !errorlevel! neq 0 (
    "%PYTHON_EXE%" --version > "%TEMP%\_ptcheck_pyver.tmp" 2>&1
    set /p PY_VER_OLD= < "%TEMP%\_ptcheck_pyver.tmp"
    del "%TEMP%\_ptcheck_pyver.tmp" >nul 2>&1
    echo  [ОШИБКА] Слишком старый Python: !PY_VER_OLD!
    echo           Требуется Python 3.10 или выше.
    echo.
    echo  Скачайте Python 3.13.9:
    echo    https://www.python.org/ftp/python/3.13.9/python-3.13.9-amd64.exe
    echo.
    pause
    exit /b 1
)

:: Показываем найденную версию
"%PYTHON_EXE%" --version > "%TEMP%\_ptcheck_pyver.tmp" 2>&1
set /p PY_VER= < "%TEMP%\_ptcheck_pyver.tmp"
del "%TEMP%\_ptcheck_pyver.tmp" >nul 2>&1

echo  [OK] !PY_VER! найден
echo       Путь: %PYTHON_EXE%
echo.

:: ══════════════════════════════════════════════════════════════════════════════
:: Обновление pip
:: ══════════════════════════════════════════════════════════════════════════════
echo  [*] Обновляем pip...
"%PYTHON_EXE%" -m pip install --upgrade pip --quiet --no-warn-script-location
if !errorlevel! neq 0 (
    echo  [!] pip не обновился — не критично, продолжаем...
) else (
    echo  [OK] pip обновлён
)
echo.

:: ══════════════════════════════════════════════════════════════════════════════
:: Установка зависимостей
:: ══════════════════════════════════════════════════════════════════════════════
if not exist "%~dp0requirements.txt" (
    echo  [ОШИБКА] Файл requirements.txt не найден рядом с install.bat!
    echo           Убедитесь что вы не перемещали файлы проекта.
    pause
    exit /b 1
)

echo  [*] Устанавливаем зависимости из requirements.txt...
echo.
"%PYTHON_EXE%" -m pip install -r "%~dp0requirements.txt" --no-warn-script-location
if !errorlevel! neq 0 (
    echo.
    echo  [ОШИБКА] Не удалось установить зависимости!
    echo.
    echo  Возможные решения:
    echo    1. Запустите этот файл от имени Администратора
    echo       (ПКМ → Запуск от имени администратора)
    echo    2. Проверьте интернет-соединение
    echo    3. Установите вручную:
    echo       "%PYTHON_EXE%" -m pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)
echo.
echo  [OK] Зависимости установлены

:: ══════════════════════════════════════════════════════════════════════════════
:: Проверка — импортируем psutil
:: ══════════════════════════════════════════════════════════════════════════════
echo.
echo  [*] Проверка установленных пакетов...
"%PYTHON_EXE%" -c "import psutil; print('  [OK] psutil ' + psutil.__version__)"
if !errorlevel! neq 0 (
    echo  [!] psutil не установлен. Попробуйте запустить от имени Администратора.
    pause
    exit /b 1
)

:: ══════════════════════════════════════════════════════════════════════════════
:: Успех
:: ══════════════════════════════════════════════════════════════════════════════
echo.
echo  ==========================================
echo    ГОТОВО! Все зависимости установлены.
echo.
echo    Для запуска сканирования:
echo      python scan.py
echo.
echo    Или с параметрами:
echo      python scan.py --user ИМЯ_ПОЛЬЗОВАТЕЛЯ
echo  ==========================================
echo.
pause
