param(
    [int]$DaysBack = 3
)

$ErrorActionPreference = 'Stop'
$reportPath = "$PSScriptRoot\rtcore_vm_gpu_telemetry_discovery_result.txt"
$log = [System.Collections.Generic.List[string]]::new()

function Try-GetEnabledFlag {
    param([string]$ChannelName)
    try {
        $raw = (& wevtutil gl "$ChannelName" 2>&1) -join [Environment]::NewLine
        $m = [regex]::Match($raw, '(?im)^\s*enabled:\s*(true|false)\s*$')
        if($m.Success){ return $m.Groups[1].Value.ToLower() }
        return "unknown"
    } catch {
        return "error"
    }
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [Security.Principal.WindowsPrincipal]::new($id)

$log.Add("TestType=GPU telemetry discovery")
$log.Add("User=$($id.Name)")
$log.Add("Elevated=$($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))")
$log.Add("DaysBack=$DaysBack")
$log.Add(("CollectedAt={0:o}" -f (Get-Date)))
$log.Add("---")

try {
    $rx = '(?i)(dxg|d3d|display|graphics|gpu|dwm|video)'
    $channels = @(& wevtutil el 2>$null) | Where-Object { $_ -match $rx } | Sort-Object -Unique
    $log.Add("DiscoveredGpuLikeChannels=$($channels.Count)")
    $log.Add("---")

    foreach($ch in $channels){
        $enabled = Try-GetEnabledFlag -ChannelName $ch
        $log.Add("Channel=$ch")
        $log.Add("Enabled=$enabled")
        $log.Add("---")
    }

    $since = (Get-Date).AddDays(-1 * [Math]::Abs($DaysBack))
    $chanEventCount = 0
    foreach($ch in $channels){
        try {
            $cnt = @(Get-WinEvent -FilterHashtable @{ LogName=$ch; StartTime=$since } -ErrorAction Stop | Select-Object -First 1).Count
            if($cnt -gt 0){
                $chanEventCount++
                $log.Add("ChannelHasRecentEvents=$ch")
            }
        } catch {}
    }
    $log.Add("ChannelsWithRecentEvents=$chanEventCount")
    $log.Add("---")

    $sysProviders = @(
        'Display',
        'Microsoft-Windows-DxgKrnl',
        'nvlddmkm',
        'amdkmdag',
        'igdkmd64',
        'Microsoft-Windows-WER-SystemErrorReporting'
    )
    $sys = Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=$since } -ErrorAction SilentlyContinue |
        Where-Object { $sysProviders -contains $_.ProviderName -or $_.Id -in 4101,1001,14,153,193,549,457 } |
        Sort-Object TimeCreated -Descending
    $log.Add("SystemGpuLikeEventsLastDays=$($sys.Count)")
    $log.Add("---")

    $top = $sys | Select-Object -First 40
    $i = 0
    foreach($e in $top){
        $msg = ($e.Message -replace '\r?\n',' ') -replace '\s+',' '
        if($msg.Length -gt 180){ $msg = $msg.Substring(0,180) + '...' }
        $log.Add(("SystemEvent[{0}].Time={1:o}" -f $i, $e.TimeCreated))
        $log.Add(("SystemEvent[{0}].Provider={1}" -f $i, $e.ProviderName))
        $log.Add(("SystemEvent[{0}].Id={1}" -f $i, $e.Id))
        $log.Add(("SystemEvent[{0}].Level={1}" -f $i, $e.LevelDisplayName))
        $log.Add(("SystemEvent[{0}].Message={1}" -f $i, $msg))
        $log.Add("---")
        $i++
    }

    $wmivideo = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue
    $log.Add("VideoControllerCount=$($wmivideo.Count)")
    foreach($v in $wmivideo){
        $log.Add("Video.Name=$($v.Name)")
        $log.Add("Video.PNPDeviceID=$($v.PNPDeviceID)")
        $log.Add("Video.DriverVersion=$($v.DriverVersion)")
        $log.Add("---")
    }

    $providersRaw = (& logman query providers 2>$null)
    $gpuProviders = @($providersRaw | Where-Object { $_ -match $rx })
    $log.Add("GpuLikeProvidersFromLogman=$($gpuProviders.Count)")
    foreach($p in ($gpuProviders | Select-Object -First 80)){
        $line = ($p -replace '\s+',' ').Trim()
        if($line){ $log.Add("ProviderLine=$line") }
    }
    $log.Add("---")

    $log.Add("Conclusion=Discovery complete. Use discovered channels/providers as correlation sources for this VM.")
}
catch{
    $log.Add("Exception=$($_.Exception.Message)")
}

($log -join [Environment]::NewLine) | Set-Content -Encoding UTF8 -Path $reportPath
Write-Output ($log -join [Environment]::NewLine)
