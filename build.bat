@echo off
setlocal

where python >nul 2>nul
if errorlevel 1 (
  echo Python not found in PATH.
  exit /b 1
)

python -m pip --version >nul 2>nul
if errorlevel 1 (
  echo pip is not available.
  exit /b 1
)

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if exist dist rmdir /s /q dist
if exist build rmdir /s /q build
if exist Hex2Asc.spec del /q Hex2Asc.spec

set "ICON_FILE=%~dp0icon.ico"
if not exist "%ICON_FILE%" (
  echo icon.ico not found: %ICON_FILE%
  exit /b 1
)

echo Using icon: %ICON_FILE%

python -m PyInstaller --clean --noconfirm --onefile --noconsole --name Hex2Asc --icon "%ICON_FILE%" app.py

if exist dist\Hex2Asc.exe (
  echo.
  echo Build OK: %cd%\dist\Hex2Asc.exe
  exit /b 0
) else (
  echo.
  echo Build failed.
  exit /b 2
)
