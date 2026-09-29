[CmdletBinding()]
param([Parameter(Mandatory)][string]$Directory)
$ErrorActionPreference = 'Stop'
$outcomes = @(Get-Content (Join-Path $Directory 'completion.runs.json') -Raw | ConvertFrom-Json)
$rows = @(foreach ($outcome in $outcomes) {
    if (!(Test-Path -LiteralPath $outcome.Run)) { continue }
    try { $root = Get-Content -LiteralPath $outcome.Run -Raw | ConvertFrom-Json } catch { continue }
    $nodes = @([pscustomobject]@{Depth=0;Status='root';Run=$root;Diagnostic=$null})
    if ($root.Wrote.Embedded) {
        $embedded = Get-Content -LiteralPath $root.Wrote.Embedded -Raw | ConvertFrom-Json
        $nodes = @($embedded.Nodes)
    }
    foreach ($node in $nodes) {
        $run = $node.Run
        if (!$run -or !$run.Wrote.Analysis) {
            [pscustomobject]@{Case=$outcome.Id;Depth=$node.Depth;Status=$node.Status;InputSha256=$node.Sha256;
                NeedsReview=$true;Diagnostic=$node.Diagnostic}
            continue
        }
        $report = Get-Content -LiteralPath $run.Wrote.Analysis -Raw | ConvertFrom-Json
        $metric = $report.Recovery
        $passes = @($report.Passes | Where-Object Status -in @('unsupported','failed','partial'))
        [pscustomobject]@{
            Case=$outcome.Id;Depth=$node.Depth;Status=$node.Status;InputSha256=$run.InputSha256;
            Module=$report.ModuleName;Success=$run.Success;Verified=$run.Verified;RebuiltCheck=$run.RebuiltCheck;
            RemainingStubs=$metric.RemainingMethodStubs;
            UnreplacedDetectedStrings=($metric.StringCallSites-$metric.ReplacedStringSites);
            SwitchCandidates=$metric.RemainingSwitchDispatchers;
            UnwalkedVmOperations=($metric.VirtualOperations-$metric.VirtualOperationsWalked);
            UnreadVmOperations=($metric.VirtualOperations-$metric.VirtualOperationsRead);
            VmStackDisagreements=$metric.VirtualDepthDisagreements;
            UnreachableInstructions=$metric.RemainingUnreachableInstructions;
            RebuiltMethods=$run.RebuiltMethods;LiftedPrograms=$run.LiftedPrograms;
            RuntimeTypesRemoved=$metric.RuntimeTypesRemoved;
            Blockers=@($report.Blockers);ContinuedPast=@($report.ContinuedPast);
            IncompletePasses=$passes;Resources=@($report.Resources);Payloads=@($run.Payloads);
            ReconstructionEvidence=@($report.Evidence | Where-Object Category -like 'reconstruction-*');
            ReconstructionDiagnostics=@($report.Passes | Where-Object Pass -eq 'virtualization-rebuild' | ForEach-Object Diagnostics);
            CleanupDiagnostics=@($report.Passes | Where-Object Pass -eq 'runtime-cleanup' | ForEach-Object Diagnostics);
            SlowestPasses=@($report.Passes | Sort-Object { [timespan]::Parse($_.Duration).TotalSeconds } -Descending |
                Select-Object -First 5 Pass,Duration,Changes,Status);
            Analysis=$run.Wrote.Analysis;Cleaned=$run.Wrote.Cleaned;
            NeedsReview=$true
        }
    }
})
$summary = [ordered]@{Schema='cilantro.completion-baseline/1';
    Note='Measurements, not a complete-unprotection verdict. Switches, unreachable code and unsupported passes require classification. Repeated hashes retain each recovery context.';
    RootRuns=$outcomes.Count;UnsuccessfulRoots=@($outcomes | Where-Object {!$_.Success}).Count;
    AssemblyObservations=$rows.Count;UniqueInputHashes=@($rows.InputSha256 | Where-Object {$_} | Sort-Object -Unique).Count;
    Runs=$outcomes;Assemblies=$rows}
$summary | ConvertTo-Json -Depth 60 | Set-Content (Join-Path $Directory 'completion.baseline.json')
$rows | Select-Object Case,Depth,Module,Success,Verified,RemainingStubs,UnreplacedDetectedStrings,
    SwitchCandidates,UnreadVmOperations,UnwalkedVmOperations,VmStackDisagreements,
    @{n='Blockers';e={@($_.Blockers).Count}},RebuiltCheck |
    Export-Csv (Join-Path $Directory 'completion.baseline.csv') -NoTypeInformation
[pscustomobject]$summary | Select-Object RootRuns,UnsuccessfulRoots,AssemblyObservations,UniqueInputHashes | Format-List
