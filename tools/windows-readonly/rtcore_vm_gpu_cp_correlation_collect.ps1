param(
    [int]$WindowMinutes = 15,
    [string]$AnchorFileName = ""
)

$ErrorActionPreference = 'Stop'
$reportPath = "$PSScriptRoot\rtcore_vm_gpu_cp_correlation_collect_result.txt"
$log = [System.Collections.Generic.List[string]]::new()

function Add-EventLines {
    param(
        [System.Collections.Generic.List[string]]$L,
        [string]$Prefix,
        [System.Collections.IEnumerable]$Events,
        [int]$Max = 80
    )
    $i = 0
    foreach($e in ($Events | Select-Object -First $Max)){
        $msg = ($e.Message -replace '\r?\n',' ') -replace '\s+',' '
        if($msg.Length -gt 220){ $msg = $msg.Substring(0,220) + '...' }
        $L.Add(("{0}[{1}].Time={2:o}" -f $Prefix,$i,$e.TimeCreated))
        $L.Add(("{0}[{1}].Provider={2}" -f $Prefix,$i,$e.ProviderName))
        $L.Add(("{0}[{1}].Id={2}" -f $Prefix,$i,$e.Id))
        $L.Add(("{0}[{1}].Level={2}" -f $Prefix,$i,$e.LevelDisplayName))
        $L.Add(("{0}[{1}].Message={2}" -f $Prefix,$i,$msg))
        $L.Add("---")
        $i++
    }
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [Security.Principal.WindowsPrincipal]::new($id)

$log.Add("TestType=GPU CP correlation collection (safe)")
$log.Add("User=$($id.Name)")
$log.Add("Elevated=$($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))")
$log.Add("Mode=Read-only event correlation around controlled BAR test artifact")
$log.Add("WindowMinutes=$WindowMinutes")
$log.Add(("CollectedAt={0:o}" -f (Get-Date)))
$log.Add("---")

try {
    $anchorMode = "File"
    $anchorFile = $null
    $anchorCandidates = @(
        'rtcore_vm_controlled_diff_write_matrix_result.txt',
        'rtcore_vm_mapview_write_capability_probe_result.txt',
        'rtcore_vm_gpu_tdr_collect_result.txt'
    )
    if(-not [string]::IsNullOrWhiteSpace($AnchorFileName)){
        $anchorCandidates = @($AnchorFileName) + ($anchorCandidates | Where-Object { $_ -ne $AnchorFileName })
    }

    foreach($candidate in $anchorCandidates){
        $p = Join-Path $PSScriptRoot $candidate
        if(Test-Path $p){
            $anchorFile = $p
            break
        }
    }

    if($anchorFile){
        $anchor = (Get-Item $anchorFile).LastWriteTime
    } else {
        $anchorMode = "NowFallback"
        $anchor = Get-Date
    }

    $start = $anchor.AddMinutes(-1 * [Math]::Abs($WindowMinutes))
    $end   = $anchor.AddMinutes([Math]::Abs($WindowMinutes))

    $log.Add(("AnchorMode={0}" -f $anchorMode))
    $log.Add(("AnchorFile={0}" -f $(if($anchorFile){$anchorFile}else{"<none>"})))
    $log.Add(("AnchorLastWrite={0:o}" -f $anchor))
    $log.Add(("WindowStart={0:o}" -f $start))
    $log.Add(("WindowEnd={0:o}" -f $end))
    $log.Add("---")

    # System log subset (display/gpu-related providers + bugcheck source)
    $sysProviders = @(
        'Display',
        'Microsoft-Windows-DxgKrnl',
        'nvlddmkm',
        'amdkmdag',
        'igdkmd64',
        'Microsoft-Windows-WER-SystemErrorReporting'
    )
    $sys = Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=$start; EndTime=$end } -ErrorAction SilentlyContinue |
        Where-Object { $sysProviders -contains $_.ProviderName -or $_.Id -in 4101,1001,14,153,193,549,457 } |
        Sort-Object TimeCreated

    $log.Add("SystemEventCount=$($sys.Count)")
    Add-EventLines -L $log -Prefix 'SystemEvent' -Events $sys -Max 60

    # DxgKrnl Admin channel
    $dxgAdmin = @()
    try {
        $dxgAdmin = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-DxgKrnl/Admin'; StartTime=$start; EndTime=$end } -ErrorAction Stop |
            Sort-Object TimeCreated
    } catch {
        $dxgAdmin = @()
    }
    $log.Add("DxgKrnlAdminEventCount=$($dxgAdmin.Count)")
    Add-EventLines -L $log -Prefix 'DxgAdminEvent' -Events $dxgAdmin -Max 60

    # DxgKrnl Operational channel
    $dxgOp = @()
    try {
        $dxgOp = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-DxgKrnl/Operational'; StartTime=$start; EndTime=$end } -ErrorAction Stop |
            Sort-Object TimeCreated
    } catch {
        $dxgOp = @()
    }
    $log.Add("DxgKrnlOperationalEventCount=$($dxgOp.Count)")
    Add-EventLines -L $log -Prefix 'DxgOpEvent' -Events $dxgOp -Max 60

    $tdrLikeSystem = @($sys | Where-Object { $_.Id -eq 4101 -or $_.ProviderName -eq 'Display' })
    $log.Add("Summary.TdrLikeSystemEvents=$($tdrLikeSystem.Count)")
    $log.Add("Summary.DxgAdminEvents=$($dxgAdmin.Count)")
    $log.Add("Summary.DxgOperationalEvents=$($dxgOp.Count)")
    $log.Add("Conclusion=Correlation collection complete. Use timestamps to align with controlled BAR write run.")
}
catch{
    $log.Add("Exception=$($_.Exception.Message)")
}

($log -join [Environment]::NewLine) | Set-Content -Encoding UTF8 -Path $reportPath
Write-Output ($log -join [Environment]::NewLine)
