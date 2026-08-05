param(
    [ValidateSet("windows", "linux")]
    [string]$Target = "windows"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$GoExecutable = (Get-Command go -ErrorAction SilentlyContinue).Source
if (-not $GoExecutable -and (Test-Path "C:\Program Files\Go\bin\go.exe")) {
    $GoExecutable = "C:\Program Files\Go\bin\go.exe"
}
if (-not $GoExecutable) {
    throw "Go não foi encontrado. Instale Go e execute novamente."
}

$env:GOOS = $Target
$env:GOARCH = "amd64"
$Extension = if ($Target -eq "windows") { ".exe" } else { "" }
$OutputPath = Join-Path $ProjectRoot "bin\ignotus-engine$Extension"

Push-Location (Join-Path $ProjectRoot "engine\go")
try {
    & $GoExecutable test ./...
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $GoExecutable build -trimpath -ldflags "-s -w" -o $OutputPath ./cmd/ignotus-engine
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

Write-Host "Motor criado em $OutputPath"
