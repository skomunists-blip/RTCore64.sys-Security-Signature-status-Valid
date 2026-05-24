@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0rtcore_vm_gpu_telemetry_discovery.ps1" -DaysBack 3
echo.
echo Result saved to rtcore_vm_gpu_telemetry_discovery_result.txt
pause
