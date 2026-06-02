@echo on
chcp 65001 >nul 2>&1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"

:: Проверка Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python не найден. Установите Python 3.8+ и добавьте в PATH.
    pause
    exit /b 1
)

:: Установка зависимостей при необходимости
python -c "import psutil" >nul 2>&1
if errorlevel 1 (
    echo [*] Установка зависимостей...
    pip install -r requirements.txt
)

:: Запуск сканера
python scan.py %*
