param(
    [Parameter(Mandatory = $true)]
    [string]$SourcePath
)

$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath $SourcePath -Raw
Add-Type -TypeDefinition $source -Language CSharp
[Ignotus.RedMode.NativeProbe]::Inspect() | ConvertTo-Json -Depth 6 -Compress
