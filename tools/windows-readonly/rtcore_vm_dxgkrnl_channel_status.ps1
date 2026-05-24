param(
    [switch]$EnableIfDisabled
)

$ErrorActionPreference = 'Stop'
$reportPath = "$PSScriptRoot\rtcore_vm_dxgkrnl_channel_status_result.txt"
$log = [System.Collections.Generic.List[string]]::new()

$channels = @(
    'Microsoft-Windows-DxgKrnl/Admin',
    'Microsoft-Windows-DxgKrnl/Operational'
)

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [Security.Principal.WindowsPrincipal]::new($id)

$log.Add("TestType=DxgKrnl channel status check")
$log.Add("User=$($id.Name)")
$log.Add("Elevated=$($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))")
$log.Add("EnableIfDisabled=$EnableIfDisabled")
$log.Add(("CollectedAt={0:o}" -f (Get-Date)))
$log.Add("---")

# Language-independent existence check
$allChannels = @(& wevtutil el 2>$null)

foreach($ch in $channels){
    $exists = ($allChannels -contains $ch)
    $enabled = $false
    $raw = ""

    if($exists){
        $raw = (& wevtutil gl "$ch" 2>&1) -join [Environment]::NewLine
        $m = [regex]::Match($raw, '(?im)^\s*enabled:\s*(true|false)\s*$')
        if($m.Success){ $enabled = ($m.Groups[1].Value.ToLower() -eq 'true') }
    }

    $log.Add("Channel=$ch")
    $log.Add("Exists=$exists")
    $log.Add("EnabledBefore=$enabled")

    if($exists -and -not $enabled -and $EnableIfDisabled){
        & wevtutil sl "$ch" /e:true 2>$null | Out-Null
        Start-Sleep -Milliseconds 200
        $raw2 = (& wevtutil gl "$ch" 2>&1) -join [Environment]::NewLine
        $m2 = [regex]::Match($raw2, '(?im)^\s*enabled:\s*(true|false)\s*$')
        $enabledAfter = $enabled
        if($m2.Success){ $enabledAfter = ($m2.Groups[1].Value.ToLower() -eq 'true') }
        $log.Add("EnabledAfter=$enabledAfter")
        $log.Add("EnableAttempted=True")
    } else {
        $log.Add("EnableAttempted=False")
    }

    $log.Add("---")
}

($log -join [Environment]::NewLine) | Set-Content -Encoding UTF8 -Path $reportPath
Write-Output ($log -join [Environment]::NewLine)
