@echo off
:: Build script for AngeronaSensor.sys (WDM kernel driver)
:: Requires: WDK 11 + Visual Studio 2022, run from a WDK Developer Command Prompt

echo AngeronaSensor build script
echo ============================
echo IMPORTANT: Test in a VM with a snapshot before loading on real hardware.
echo.

if not exist "%WDKContentRoot%\include\wdm.h" (
    echo ERROR: WDK not detected. Install Windows Driver Kit 11 first.
    echo Download: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    exit /b 1
)

:: Build x64 Release
msbuild AngeronaSensor.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:TargetVersion=Windows10 ^
    /p:UseDebugLibraries=false ^
    /t:Rebuild

if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED.
    exit /b %ERRORLEVEL%
)

echo.
echo Build succeeded. Output: x64\Release\AngeronaSensor.sys
echo.
echo To load (test machine, test-signing enabled):
echo   sc create AngeronaSensor type= kernel binPath= %CD%\x64\Release\AngeronaSensor.sys
echo   sc start AngeronaSensor
echo   sc query AngeronaSensor
echo.
echo To unload:
echo   sc stop AngeronaSensor
echo   sc delete AngeronaSensor
