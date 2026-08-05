@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul
set "PYTHONUTF8=1"

if not exist ".venv\Scripts\python.exe" (
    echo Preparando o ambiente Python do Ignotus...
    python -m venv .venv || exit /b 1
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt || exit /b 1
)

if not exist "bin\ignotus-engine.exe" (
    where go >nul 2>nul
    if not errorlevel 1 call "%~dp0build_engine.bat"
    if errorlevel 1 if exist "C:\Program Files\Go\bin\go.exe" call "%~dp0build_engine.bat"
)

if "%~1"=="" (
    ".venv\Scripts\python.exe" main.py --interactive
) else (
    ".venv\Scripts\python.exe" main.py %*
)
set "IGNOTUS_EXIT=%ERRORLEVEL%"

echo.
if not "%IGNOTUS_EXIT%"=="0" echo O Ignotus terminou com codigo %IGNOTUS_EXIT%.
if "%~1"=="" pause
exit /b %IGNOTUS_EXIT%
