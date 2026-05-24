@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0rtcore_vm_gpu_tdr_collect.ps1"
echo.
echo Result saved to rtcore_vm_gpu_tdr_collect_result.txt
pause
