@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0rtcore_vm_gpu_cp_correlation_collect.ps1" -WindowMinutes 10 -AnchorFileName "rtcore_vm_controlled_diff_write_matrix_result.txt"
echo.
echo Result saved to rtcore_vm_gpu_cp_correlation_collect_result.txt
pause
