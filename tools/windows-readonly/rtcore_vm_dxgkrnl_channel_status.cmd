@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0rtcore_vm_dxgkrnl_channel_status.ps1" -EnableIfDisabled
echo.
echo Result saved to rtcore_vm_dxgkrnl_channel_status_result.txt
pause
