param([Parameter(Mandatory)][string]$ReportDirectory)
$ErrorActionPreference = 'Stop'
$manifest = Get-Content (Join-Path $PSScriptRoot 'reactor-6-nonvirt.manifest.json') -Raw | ConvertFrom-Json
$cases = @(
    @{ Id='qbjuef'; Run='qbjuef-run.json'; Helper='060003CD'; MinimumTypesRemoved=200 },
    @{ Id='mlfhntkcvb-payload'; Run='mlfhntkcvb-run.json'; Helper='06000672'; MinimumTypesRemoved=564 }
)
$outcomes = foreach ($case in $cases) {
    $issues = [Collections.Generic.List[string]]::new()
    try {
        $expected = @($manifest.samples | Where-Object id -eq $case.Id)
        if ($expected.Count -ne 1) { throw "Missing pinned corpus identity: $($case.Id)" }
        $run = Get-Content (Join-Path $ReportDirectory $case.Run) -Raw | ConvertFrom-Json
        $report = Get-Content $run.Wrote.Analysis -Raw | ConvertFrom-Json
        if ($run.InputSha256 -ne $expected[0].sha256 -or $report.InputSha256 -ne $run.InputSha256) {
            $issues.Add('Input identity does not match the pinned corpus sample.')
        }
        if (!$run.Success -or !$run.Verified -or !$report.VerificationPassed -or !(Test-Path -LiteralPath $run.Wrote.Cleaned)) {
            $issues.Add('A successful, structurally verified cleaned assembly is required.')
        }
        if ($run.RebuiltMethods -lt 1 -or $run.LiftedPrograms -lt 1) {
            $issues.Add('Both the method reconstruction and the additional initialization helper are required.')
        }
        if ($report.Recovery.RuntimeTypesRemoved -lt $case.MinimumTypesRemoved) {
            $issues.Add("Runtime cleanup regressed below $($case.MinimumTypesRemoved) removed types.")
        }
        $prefix = "$($case.Helper), lifted program 1, "
        $trials = @($report.Evidence | Where-Object {
            $_.Category -eq 'reconstruction-method-trial' -and $_.Message.StartsWith($prefix, [StringComparison]::Ordinal)
        })
        $cold = @($trials | Where-Object { $_.Message.Contains('cold start: Disagreed.') })
        $repeat = @($trials | Where-Object { $_.Message.Contains('repeat call: Agreed.') })
        if ($cold.Count -ne 1 -or
            !$cold[0].Message.Contains('A separate snapshot excluding VM-owned static roots matched') -or
            !$cold[0].Message.Contains('No shared modeled objects were found')) {
            $issues.Add('The cold helper trial must match captured non-VM state without shared modeled objects.')
        }
        if ($repeat.Count -ne 1) { $issues.Add('The repeat-call helper trial must match full captured state.') }
        if ($run.RebuiltCheck -ne 'disagreed') { $issues.Add('The observed full-state disagreement must remain visible.') }
        foreach ($hash in @($expected[0].expectedPayloadSha256)) {
            if ($hash -and $hash -notin $report.Payloads.PayloadSha256) { $issues.Add("Expected extracted payload is missing: $hash") }
        }
        [pscustomobject]@{
            Sample=$case.Id; Passed=($issues.Count -eq 0); Diagnostics=@($issues)
            RuntimeTypesRemoved=$report.Recovery.RuntimeTypesRemoved
            CleanedSha256=(Get-FileHash -LiteralPath $run.Wrote.Cleaned -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    } catch {
        $issues.Add($_.Exception.Message)
        [pscustomobject]@{ Sample=$case.Id; Passed=$false; Diagnostics=@($issues) }
    }
}
$outcomes | ConvertTo-Json -Depth 4
if (@($outcomes | Where-Object { !$_.Passed }).Count) { exit 1 }
