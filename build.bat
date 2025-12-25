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

python -m PyInstaller --onefile --noconsole --name Hex2Asc app.py

if exist dist\Hex2Asc.exe (
  echo.
  echo Build OK: %cd%\dist\Hex2Asc.exe
  exit /b 0
) else (
  echo.
  echo Build failed.
  exit /b 2
)
