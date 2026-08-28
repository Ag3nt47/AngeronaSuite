@echo off
setlocal EnableExtensions
title Angerona Release Installer
set "ANGERONA_RELEASE_PS=%ProgramFiles%\Angerona\Install-Angerona-Release.ps1"
if not exist "%ANGERONA_RELEASE_PS%" (
    echo [ERROR] The portable package is upgrade-only.
    echo [ERROR] Public first install requires the signed Angerona MSIX.
    echo [ERROR] Classic Setup is restricted to a protected legacy migration.
    echo [ERROR] Enterprise clean install requires a separate governed deployment artifact.
    pause
    exit /b 1
)
if "%~1"=="" (
    echo [ERROR] Pass the original downloaded Angerona win64 ZIP as the first argument.
    echo [ERROR] Its adjacent .sha256 file is also required.
    pause
    exit /b 1
)
set "ANGERONA_RELEASE_ZIP=%~f1"

rem Verify the protected installed owner, ACLs, publisher, authorities, evidence,
rem and rollback floor before any UAC request. The elevated authority repeats the
rem same checks immediately before mutation.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "%ANGERONA_RELEASE_PS%" -CustodyPreflightOnly
if errorlevel 1 (
    echo [ERROR] Protected installed upgrade custody failed before elevation.
    pause
    exit /b 1
)

"%SystemRoot%\System32\net.exe" session >nul 2>&1
if errorlevel 1 (
    echo [*] Requesting Administrator privileges for the protected install ...
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$p=Start-Process -WindowStyle Hidden -FilePath ([IO.Path]::Combine([Environment]::SystemDirectory,'WindowsPowerShell\v1.0\powershell.exe')) -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',$env:ANGERONA_RELEASE_PS,'-ReleaseArchive',$env:ANGERONA_RELEASE_ZIP) -Verb RunAs -Wait -PassThru; exit $p.ExitCode"
    if errorlevel 1 (
        echo [ERROR] Elevated protected upgrade failed or was cancelled.
        pause
        exit /b 1
    )
    exit /b 0
)

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy RemoteSigned -File "%ANGERONA_RELEASE_PS%" -ReleaseArchive "%ANGERONA_RELEASE_ZIP%"
if errorlevel 1 (
    echo.
    echo [ERROR] Installation failed. Review the message above.
    pause
    exit /b 1
)
exit /b 0
