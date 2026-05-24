$ErrorActionPreference = 'Stop'
$reportPath = "$PSScriptRoot\rtcore_vm_gpu_tdr_collect_result.txt"
$log = [System.Collections.Generic.List[string]]::new()

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [Security.Principal.WindowsPrincipal]::new($id)

$log.Add("TestType=GPU/TDR artifact collection (safe)")
$log.Add("User=$($id.Name)")
$log.Add("Elevated=$($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))")
$log.Add("Mode=Read-only event collection; no IOCTL writes, no MMIO access")
$log.Add(("CollectedAt={0:o}" -f (Get-Date)))
$log.Add("---")

try {
    $since = (Get-Date).AddDays(-3)
    $providers = @(
        'Display',
        'Microsoft-Windows-DxgKrnl',
        'nvlddmkm',
        'amdkmdag',
        'igdkmd64'
    )

    $events = Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=$since } -ErrorAction SilentlyContinue |
        Where-Object { ($providers -contains $_.ProviderName) -or ($_.Id -in 4101,14,1,2) } |
        Sort-Object TimeCreated -Descending

    $log.Add("WindowDays=3")
    $log.Add("EventCount=$($events.Count)")
    $log.Add("---")

    $top = $events | Select-Object -First 80
    $i = 0
    foreach($e in $top){
        $msg = ($e.Message -replace '\r?\n',' ') -replace '\s+',' '
        if($msg.Length -gt 220){ $msg = $msg.Substring(0,220) + '...' }
        $log.Add(("Event[{0}].Time={1:o}" -f $i, $e.TimeCreated))
        $log.Add(("Event[{0}].Provider={1}" -f $i, $e.ProviderName))
        $log.Add(("Event[{0}].Id={1}" -f $i, $e.Id))
        $log.Add(("Event[{0}].Level={1}" -f $i, $e.LevelDisplayName))
        $log.Add(("Event[{0}].Message={1}" -f $i, $msg))
        $log.Add("---")
        $i++
    }

    # ASCII-only heuristic to avoid locale/encoding parser issues.
    $tdr = $events | Where-Object {
        ($_.Id -eq 4101) -or
        ($_.ProviderName -eq 'Display' -and ($_.LevelDisplayName -in @('Error','Warning')))
    }
    $log.Add("Summary.TdrLikeEvents=$($tdr.Count)")
    $log.Add("Conclusion=Artifact collection complete. Correlate timestamps with RTCore tests manually.")
}
catch{
    $log.Add("Exception=$($_.Exception.Message)")
}

($log -join [Environment]::NewLine) | Set-Content -Encoding UTF8 -Path $reportPath
Write-Output ($log -join [Environment]::NewLine)
