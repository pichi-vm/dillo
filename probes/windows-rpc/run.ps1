# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'
$vsPath = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$environment = & cmd.exe /c "call `"$vsPath\Common7\Tools\VsDevCmd.bat`" -arch=x64 >nul && set"
if ($LASTEXITCODE) { throw 'Visual C++ environment setup failed' }
foreach ($entry in $environment) {
    if ($entry -match '^([^=]+)=(.*)$') {
        [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
}
$out = Join-Path $PSScriptRoot '../../target/windows-rpc'
New-Item -ItemType Directory -Force $out | Out-Null
$out = (Resolve-Path $out).Path
Push-Location $out
try {
    & midl.exe /nologo /env x64 /target NT100 /h probe.h /acf "$PSScriptRoot/probe.acf" "$PSScriptRoot/probe.idl"
    if ($LASTEXITCODE) { throw 'MIDL failed' }
    & cl.exe /nologo /W3 /WX /I. /DPROBE_SERVER "$PSScriptRoot/probe.c" probe_s.c /Feserver.exe /link Rpcrt4.lib Advapi32.lib
    if ($LASTEXITCODE) { throw 'server build failed' }
    & cl.exe /nologo /W3 /WX /I. "$PSScriptRoot/probe.c" probe_c.c /Feclient.exe /link Rpcrt4.lib Advapi32.lib
    if ($LASTEXITCODE) { throw 'client build failed' }
    & cl.exe /nologo /W3 /WX /I. "$PSScriptRoot/container.c" probe_c.c /Fecontainer.exe /link Rpcrt4.lib Advapi32.lib Userenv.lib
    if ($LASTEXITCODE) { throw 'container launcher build failed' }
    $endpoint = 'vhost-probe-' + [Guid]::NewGuid().ToString()
    $server = Start-Process ./server.exe -ArgumentList $endpoint -PassThru -RedirectStandardOutput server.out -RedirectStandardError server.err
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while (!(Test-Path server.out) -or !(Select-String -Path server.out -Pattern READY -Quiet)) {
            if ($server.HasExited -or [DateTime]::UtcNow -ge $deadline) { throw 'server did not become ready' }
            Start-Sleep -Milliseconds 50
        }
        & ./client.exe $endpoint
        if ($LASTEXITCODE) { throw "client failed: $LASTEXITCODE" }
        if (!$server.WaitForExit(5000) -or $server.ExitCode -ne 0) { throw 'server did not exit cleanly' }
        & ./container.exe
        if ($LASTEXITCODE) { throw "container probe failed: $LASTEXITCODE" }
    } finally {
        if (!$server.HasExited) { Stop-Process -Id $server.Id -Force }
        Get-Content server.out, server.err
    }
} finally { Pop-Location }
