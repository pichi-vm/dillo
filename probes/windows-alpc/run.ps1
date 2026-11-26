# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0
param([string]$Probe = './target/windows-alpc/probe.exe')
$ErrorActionPreference = 'Stop'
$Probe = (Resolve-Path $Probe).Path
$out = Split-Path $Probe
Start-Transcript -Path "$out/transcript.txt"
Write-Output ([Environment]::OSVersion.VersionString)
Get-FileHash $Probe
$failures = @()
foreach ($case in @('roundtrip', 'rights', 'invalid', 'partial', 'queued', 'reverse', 'waitable')) {
    $endpoint = 'vhost-alpc-' + [Guid]::NewGuid().ToString()
    $tail = @($endpoint)
    if ($case -ne 'roundtrip') { $tail += $case }
    $server = Start-Process $Probe -ArgumentList (@('server') + $tail) -PassThru -RedirectStandardOutput "$out/$case.out" -RedirectStandardError "$out/$case.err"
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while (!(Test-Path "$out/$case.out") -or !(Select-String -Path "$out/$case.out" -Pattern READY -Quiet)) {
            if ($server.HasExited -or [DateTime]::UtcNow -ge $deadline) { throw 'server startup deadline' }
            Start-Sleep -Milliseconds 50
        }
        & $Probe client @tail
        if ($LASTEXITCODE) { throw "client failed: $LASTEXITCODE" }
        if (!$server.WaitForExit(10000) -or $server.ExitCode -ne 0) { throw 'server failed' }
    } catch {
        $failures += "$case : $_"
        Write-Output "FAIL $case : $_"
    } finally {
        if (!$server.HasExited) { Stop-Process -Id $server.Id -Force }
        Get-Content "$out/$case.out", "$out/$case.err"
    }
}
try {
    & $Probe container ('vhost-alpc-' + [Guid]::NewGuid().ToString())
    if ($LASTEXITCODE) { throw "container failed: $LASTEXITCODE" }
} catch { $failures += "container : $_" }
Stop-Transcript
if ($failures.Count) { throw ($failures -join "`n") }
