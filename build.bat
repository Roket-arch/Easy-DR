@echo off
REM Construit EasyDR-Setup.exe (Windows 10/11, Python 3.10+ et Inno Setup 6 requis)
python -m pip install -r requirements.txt pyinstaller || goto :err
python tools\build.py || goto :err
set ISCC="%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist %ISCC% set ISCC="%ProgramFiles%\Inno Setup 6\ISCC.exe"
%ISCC% installer\easydr.iss || goto :err
echo.
echo ===== Termine : dist\EasyDR-Setup.exe =====
exit /b 0
:err
echo ECHEC de la construction.
exit /b 1
