[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Before,
    [Parameter(Mandatory)][string]$After,
    [Parameter(Mandatory)][string]$Output
)
$ErrorActionPreference = 'Stop'
$left = Get-Content -LiteralPath (Join-Path $Before 'completion.baseline.json') -Raw | ConvertFrom-Json
$right = Get-Content -LiteralPath (Join-Path $After 'completion.baseline.json') -Raw | ConvertFrom-Json
function Key($row) { "$($row.Case)|$($row.Depth)|$($row.InputSha256)" }
$old = @{}
foreach ($row in $left.Assemblies) { $old[(Key $row)] = $row }
$new = @{}
foreach ($row in $right.Assemblies) { $new[(Key $row)] = $row }
$changes = @(foreach ($key in @(@($old.Keys) + @($new.Keys) | Sort-Object -Unique)) {
    $a = $old[$key]; $b = $new[$key]
    if (!$a -or !$b) {
        [pscustomobject]@{Key=$key;Status=$(if (!$a) {'new-observation'} else {'missing-observation'})}
        continue
    }
    [pscustomobject]@{Key=$key;Status='compared';Module=$b.Module;
        SuccessBefore=$a.Success;SuccessAfter=$b.Success;VerifiedBefore=$a.Verified;VerifiedAfter=$b.Verified;
        SwitchMethodsBefore=$a.SwitchCandidates;SwitchMethodsAfter=$b.SwitchCandidates;
        UnwalkedVmBefore=$a.UnwalkedVmOperations;UnwalkedVmAfter=$b.UnwalkedVmOperations;
        UnreadVmBefore=$a.UnreadVmOperations;UnreadVmAfter=$b.UnreadVmOperations;
        VmStackDisagreementsBefore=$a.VmStackDisagreements;VmStackDisagreementsAfter=$b.VmStackDisagreements;
        UnreplacedDetectedStringsBefore=$a.UnreplacedDetectedStrings;UnreplacedDetectedStringsAfter=$b.UnreplacedDetectedStrings;
        RebuiltBefore=$a.RebuiltMethods;RebuiltAfter=$b.RebuiltMethods;
        PayloadsLost=@($a.Payloads.PayloadSha256 | Where-Object {$_ -and $_ -notin @($b.Payloads.PayloadSha256)});
        PayloadsAdded=@($b.Payloads.PayloadSha256 | Where-Object {$_ -and $_ -notin @($a.Payloads.PayloadSha256)});
        RebuiltCheckBefore=$a.RebuiltCheck;RebuiltCheckAfter=$b.RebuiltCheck;
        BlockersBefore=@($a.Blockers).Count;BlockersAfter=@($b.Blockers).Count}
})
$result = [ordered]@{Schema='cilantro.completion-comparison/1';
    Note='Differences require review; equal metrics do not establish equivalent behavior. Every root outcome and missing observation is retained.';
    RootsBefore=$left.Runs;RootsAfter=$right.Runs;Assemblies=$changes}
$result | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $Output
$changes | Where-Object {$_.Status -ne 'compared' -or $_.SwitchMethodsBefore -ne $_.SwitchMethodsAfter -or
    $_.SuccessBefore -ne $_.SuccessAfter -or $_.PayloadsLost.Count} |
    Select-Object Key,Status,SwitchMethodsBefore,SwitchMethodsAfter,SuccessAfter,PayloadsLost | Format-Table -AutoSize
