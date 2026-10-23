# SPDX-FileCopyrightText: 2026 The Ternimal Authors
# SPDX-License-Identifier: AGPL-3.0-only
# Native Windows end-to-end test: build the exes, start a direct agent, and run
# a command on it through the full TLS + auth + mux path. Exercises the Windows
# code paths (PE binaries, cmd.exe via `cmd /c`, CreateProcess exec). The
# interactive ConPTY shell needs a real console and is not covered here.
$ErrorActionPreference = "Stop"

go build -o tern.exe  ./cmd/tern
go build -o ternd.exe ./cmd/ternd

$work = Join-Path $env:TEMP ("tern-e2e-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $work | Out-Null

# The agent and the client both read the token from the environment, never
# from the command line, where other local users could read it.
$env:TERN_TOKEN = (& .\tern.exe genkey).Trim()

function Wait-Hex($file) {
    for ($i = 0; $i -lt 100; $i++) {
        if (Test-Path $file) {
            $m = Select-String -Path $file -Pattern '[0-9a-f]{64}' | Select-Object -First 1
            if ($m) { return $m.Matches[0].Value }
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Host "----- agent log -----"
    if (Test-Path $file) { Get-Content $file }
    throw "timeout waiting for the agent fingerprint"
}

$alog = Join-Path $work "agent.err"
$agent = Start-Process -FilePath .\ternd.exe `
    -ArgumentList @("--addr", "127.0.0.1:2222", "--cert", (Join-Path $work "agent")) `
    -NoNewWindow -PassThru `
    -RedirectStandardError $alog -RedirectStandardOutput (Join-Path $work "agent.out")

try {
    $fp = Wait-Hex $alog
    Write-Host "agent fingerprint: $fp"
    $out = & .\tern.exe run --addr 127.0.0.1:2222 --fingerprint $fp -- cmd /c echo WIN_OK_42
    Write-Host "command output: $out"
    if ($out -notmatch "WIN_OK_42") { throw "FAIL: expected WIN_OK_42 in output" }
    Write-Host "WINDOWS E2E PASSED"
}
finally {
    if ($agent -and -not $agent.HasExited) { Stop-Process -Id $agent.Id -Force }
    Remove-Item Env:\TERN_TOKEN -ErrorAction SilentlyContinue
}
