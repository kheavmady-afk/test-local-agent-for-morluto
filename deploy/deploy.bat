@echo off
rem ==============================================================================
rem REA (Reverse Engineer Anything) Windows Command Prompt Wrapper
rem ==============================================================================
setlocal EnableDelayedExpansion

where powershell >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy.ps1" %*
) else (
    echo [ERROR] PowerShell is required to execute deploy.ps1 on Windows.
    exit /b 1
)
