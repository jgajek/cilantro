# Runs static recovery only. A successful run is not a complete-unprotection verdict.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Cli,
    [Parameter(Mandatory)][string]$Samples,
    [Parameter(Mandatory)][string]$Output,
    [string[]]$Manifests = @(),
    [string[]]$AdditionalInputs = @(),
    [ValidateRange(1,4)][int]$Concurrency = 2,
    [ValidateRange(1,2147483647)][int]$Steps = 192000000
)
$ErrorActionPreference = 'Stop'
$Cli = (Resolve-Path -LiteralPath $Cli).Path
$Samples = (Resolve-Path -LiteralPath $Samples).Path
$Output = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $Output) { throw 'Use a new output directory to avoid mixing runs.' }
if (!$Manifests.Count) {
    $Manifests = @('reactor-6-nonvirt.manifest.json','reactor-7-static.manifest.json','confuserex-1-static.manifest.json') |
        ForEach-Object { Join-Path $PSScriptRoot $_ }
}
$cases = @(
    foreach ($file in $Manifests) {
        $manifestPath = (Resolve-Path -LiteralPath $file).Path
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        foreach ($sample in $manifest.samples | Where-Object tier -ne 'oracle') {
            [pscustomobject]@{ Id="$($manifest.profile)/$($sample.id)"; Input=(Join-Path $Samples $sample.localName);
                ExpectedHash=$sample.sha256; ExpectedPayloads=@($sample.expectedPayloadSha256);
                Manifest=$manifestPath; Settings=$sample }
        }
    }
    foreach ($inputPath in $AdditionalInputs) {
        $resolved = (Resolve-Path -LiteralPath $inputPath).Path
        [pscustomobject]@{ Id="additional/$([IO.Path]::GetFileName($resolved))"; Input=$resolved;
            ExpectedHash=(Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant();
            ExpectedPayloads=@(); Manifest=$null; Settings=$null }
    }
)
if (@($cases | Group-Object Id | Where-Object Count -gt 1).Count) { throw 'Duplicate case identifiers.' }
foreach ($case in $cases) {
    $caseOutput = [IO.Path]::GetFullPath((Join-Path $Output $case.Id))
    if (!$caseOutput.StartsWith($Output.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)) { throw "Case identifier escapes output directory: $($case.Id)" }
}
New-Item -ItemType Directory -Path $Output | Out-Null
$cases | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $Output 'inputs.json')
$cliHash = (Get-FileHash -LiteralPath $Cli -Algorithm SHA256).Hash
$dependencies = @(Get-ChildItem -LiteralPath (Split-Path $Cli) -Filter '*.dll' | ForEach-Object {
    @{Name=$_.Name;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
})
@{Cli=$Cli;CliSha256=$cliHash;Dependencies=$dependencies;Steps=$Steps;Concurrency=$Concurrency;StartedUtc=[datetime]::UtcNow;
    Reconstruction=$true;RecursiveRecovery=$true;ManifestAssertionsApplied=$false} |
    ConvertTo-Json | Set-Content (Join-Path $Output 'configuration.json')
$outcomes = @($cases | ForEach-Object -Parallel {
    $ErrorActionPreference = 'Stop'
    $case = $_
    $directory = Join-Path $using:Output $case.Id
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $started = [datetime]::UtcNow
    try {
        $actual = (Get-FileHash -LiteralPath $case.Input -Algorithm SHA256).Hash
        if ($actual -ne $case.ExpectedHash) { throw 'Input hash does not match the pinned identity.' }
        $declarations = @{}
        $settings = $case.Settings
        $manifestDirectory = if ($case.Manifest) { Split-Path $case.Manifest } else { $null }
        if ($settings.declarations) {
            $declarations = Get-Content (Join-Path $manifestDirectory $settings.declarations) -Raw | ConvertFrom-Json -AsHashtable
        }
        if (!$declarations.ContainsKey('budgets')) { $declarations.budgets = @{} }
        $declarations.budgets.steps = [Math]::Max($using:Steps, [long]$declarations.budgets.steps)
        $declarationPath = Join-Path $directory 'declarations.json'
        $declarations | ConvertTo-Json -Depth 30 | Set-Content $declarationPath
        $arguments = @($case.Input,'--recover-embedded','--devirtualize','--status','--json',
            '--output',(Join-Path $directory ('cleaned' + [IO.Path]::GetExtension($case.Input))),
            '--report-dir',$directory,'--declarations',$declarationPath)
        if ($settings.hostProfile) { $arguments += @('--host-profile',(Join-Path $manifestDirectory $settings.hostProfile)) }
        foreach ($library in $settings.libraries) { $arguments += @('--library',(Join-Path $manifestDirectory $library)) }
        if ($settings.allowDeclaredCalls) { $arguments += '--allow-declared-calls' }
        $cliPath = $using:Cli
        if ([IO.Path]::GetExtension($cliPath) -eq '.dll') {
            & dotnet $cliPath @arguments > (Join-Path $directory 'run.json') 2> (Join-Path $directory 'stderr.txt')
        } else {
            & $cliPath @arguments > (Join-Path $directory 'run.json') 2> (Join-Path $directory 'stderr.txt')
        }
        $exitCode = $LASTEXITCODE
        $run = Get-Content (Join-Path $directory 'run.json') -Raw | ConvertFrom-Json
        if ($run.InputSha256 -ne $actual) { throw 'Input identity changed between the hash check and recovery.' }
        $missingPayloads = @($case.ExpectedPayloads | Where-Object { $_ -and $_ -notin @($run.Payloads.PayloadSha256) })
        $result = [pscustomobject]@{Id=$case.Id;InputSha256=$actual.ToLowerInvariant();ExitCode=$exitCode;
            Success=$run.Success;Verified=$run.Verified;MissingExpectedPayloads=$missingPayloads;
            Run=(Join-Path $directory 'run.json');Seconds=([datetime]::UtcNow-$started).TotalSeconds;Error=$null}
    } catch {
        $result = [pscustomobject]@{Id=$case.Id;Success=$false;Verified=$false;Error=$_.Exception.Message;
            Run=(Join-Path $directory 'run.json');Seconds=([datetime]::UtcNow-$started).TotalSeconds}
    }
    $result | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $directory 'outcome.json')
    $result
} -ThrottleLimit $Concurrency)
$outcomes | Sort-Object Id | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $Output 'completion.runs.json')
& (Join-Path $PSScriptRoot 'summarize-completion.ps1') -Directory $Output
if (@($outcomes | Where-Object { !$_.Success -or $_.Error -or $_.MissingExpectedPayloads.Count }).Count) { exit 1 }
