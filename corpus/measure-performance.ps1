param(
    [Parameter(Mandatory)][string]$Tool,
    [Parameter(Mandatory)][string]$Samples,
    [Parameter(Mandatory)][string]$Output,
    [ValidateRange(1, 100)][int]$Repeats = 3
)

$ErrorActionPreference = 'Stop'
$Tool = (Resolve-Path -LiteralPath $Tool).Path
$Samples = (Resolve-Path -LiteralPath $Samples).Path
if (Test-Path -LiteralPath $Output) { throw "Output must be a new directory: $Output" }
New-Item -ItemType Directory -Path $Output | Out-Null
$Output = (Resolve-Path -LiteralPath $Output).Path
$core = Join-Path (Split-Path -Parent $Tool) 'Cilantro.Core.dll'
$runtimeConfiguration = [IO.Path]::ChangeExtension($Tool, '.runtimeconfig.json')
[ordered]@{
    Tool = $Tool; ToolSha256 = (Get-FileHash -LiteralPath $Tool -Algorithm SHA256).Hash
    CoreSha256 = $(if (Test-Path -LiteralPath $core) { (Get-FileHash -LiteralPath $core -Algorithm SHA256).Hash })
    RuntimeConfigurationSha256 = $(if (Test-Path -LiteralPath $runtimeConfiguration) { (Get-FileHash -LiteralPath $runtimeConfiguration -Algorithm SHA256).Hash })
    Sdk = (& dotnet --version); Runtimes = @(& dotnet --list-runtimes)
    OS = [Runtime.InteropServices.RuntimeInformation]::OSDescription
    Processors = [Environment]::ProcessorCount; StartedUtc = [DateTime]::UtcNow.ToString('O')
    ServerGCOverride = $env:DOTNET_gcServer; HeapCountOverride = $env:DOTNET_GCHeapCount
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Output 'environment.json')
$runs = @()
$passes = @()
for ($repeat = 1; $repeat -le $Repeats; $repeat++) {
    foreach ($manifest in Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.manifest.json' | Sort-Object Name) {
        $destination = Join-Path $Output "$repeat/$($manifest.BaseName)"
        $timer = [Diagnostics.Stopwatch]::StartNew()
        & dotnet $Tool corpus run --manifest $manifest.FullName --samples $Samples --output $destination
        $exitCode = $LASTEXITCODE
        $timer.Stop()
        $outcomes = Get-Content -LiteralPath (Join-Path $destination 'corpus.outcomes.json') -Raw | ConvertFrom-Json
        $runs += [pscustomobject]@{
            Repeat = $repeat; Manifest = $manifest.Name; Seconds = $timer.Elapsed.TotalSeconds
            Passed = $outcomes.passed; Failed = $outcomes.failed; Missing = $outcomes.missing; ExitCode = $exitCode
        }
        $runs | Export-Csv -LiteralPath (Join-Path $Output 'runs.csv') -NoTypeInformation
        # Include child analyses: wall time includes following extracted assemblies too.
        foreach ($file in Get-ChildItem -LiteralPath $destination -Recurse -Filter '*.analysis.json') {
            $report = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
            foreach ($pass in $report.Passes) {
                $passes += [pscustomobject]@{
                    Repeat = $repeat; Manifest = $manifest.Name
                    Artifact = [IO.Path]::GetRelativePath($destination, $file.FullName)
                    Sha256 = $report.InputSha256; Pass = $pass.Pass
                    Seconds = ([timespan]$pass.Duration).TotalSeconds
                    Status = $pass.Status; Changes = $pass.Changes
                }
            }
        }
        $passes | Export-Csv -LiteralPath (Join-Path $Output 'passes.csv') -NoTypeInformation
        if ($exitCode -ne 0 -or $outcomes.failed -ne 0 -or $outcomes.missing -ne 0) {
            throw "Corpus validation failed or inputs missing; inspect $destination"
        }
    }
}
$runs | Format-Table
