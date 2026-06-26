@echo off
setlocal
cd /d "%~dp0"

echo Installing dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 exit /b 1

echo Building USLocalityDNSDiscovery.exe...
python -m PyInstaller --noconfirm USLocalityDNSDiscovery.spec
if errorlevel 1 exit /b 1

echo.
echo Build complete: dist\USLocalityDNSDiscovery.exe
endlocal
