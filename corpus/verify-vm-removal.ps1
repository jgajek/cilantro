param(
    [Parameter(Mandatory)][string[]]$RunPath,
    [Parameter(Mandatory)][string]$ToolDirectory
)
$ErrorActionPreference = 'Stop'
# Metadata inspection only: assemblies under test are never loaded into the CLR.
Add-Type -Path (Join-Path $ToolDirectory 'dnlib.dll')
function Read-Nest($type) {
    $type
    foreach ($child in $type.NestedTypes) { Read-Nest $child }
}
$results = foreach ($path in $RunPath) {
    $issues = [Collections.Generic.List[string]]::new()
    $inputModule = $null
    $outputModule = $null
    try {
        $run = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $analysis = Get-Content -LiteralPath $run.Wrote.Analysis -Raw | ConvertFrom-Json
        $renames = Get-Content -LiteralPath $run.Wrote.Renames -Raw | ConvertFrom-Json -AsHashtable
        if (!$run.Verified -or !$analysis.VerificationPassed) { $issues.Add('Output did not pass structural verification.') }
        $inputHash = (Get-FileHash -LiteralPath $run.InputPath -Algorithm SHA256).Hash
        if ($inputHash -ine $run.InputSha256 -or $inputHash -ine $analysis.InputSha256) {
            throw 'The original input does not match the recorded input hash.'
        }
        $inputModule = [dnlib.DotNet.ModuleDefMD]::Load([IO.File]::ReadAllBytes($run.InputPath))
        $outputModule = [dnlib.DotNet.ModuleDefMD]::Load([IO.File]::ReadAllBytes($run.Wrote.Cleaned))
        $engines = [Collections.Generic.HashSet[dnlib.DotNet.TypeDef]]::new()
        foreach ($evidence in $analysis.Evidence | Where-Object Category -in @('virtualized-method','virtualized-program')) {
            if ($evidence.Message -match 'interpreter at (.+?)::([^ .]+)') {
                $typeName = $Matches[1]; $methodName = $Matches[2]
                $found = @($inputModule.GetTypes() | Where-Object {
                    $_.Name.String -ceq $typeName -and @($_.Methods | Where-Object { $_.Name.String -ceq $methodName }).Count -gt 0
                })
                if ($found.Count -ne 1) { throw "Cannot uniquely identify original VM engine: $($evidence.Message)" }
                [void]$engines.Add($found[0])
            }
        }
        if ($engines.Count -eq 0) { $issues.Add('No original VM engine was identified; absence cannot be established.') }
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($type in $outputModule.GetTypes()) { [void]$names.Add($type.FullName) }
        $retained = @(foreach ($engine in $engines) {
            foreach ($type in Read-Nest $engine) {
                $name = $type.FullName
                if ($renames.ContainsKey('T:' + $name)) { $name = $renames['T:' + $name].Substring(2) }
                if ($names.Contains($name)) { $name }
            }
        })
        if ($retained.Count) { $issues.Add("VM declarations remain: $($retained -join ', ')") }
        $rebuilt = @($outputModule.GetTypes() | ForEach-Object { $_.Methods } | Where-Object {
            @($_.CustomAttributes | Where-Object TypeFullName -eq 'Cilantro.RebuiltFromReadingAttribute').Count -gt 0
        })
        $expected = [int]$run.RebuiltMethods + [int]$run.LiftedPrograms
        if ($expected -eq 0 -or $rebuilt.Count -ne $expected -or @($rebuilt | Where-Object { !$_.HasBody }).Count) {
            $issues.Add('The reported reconstructed application methods must survive with CIL bodies.')
        }
        $changes = @(Get-Content -LiteralPath $run.Wrote.Changes -Raw | ConvertFrom-Json)
        $removedResources = @($changes | Where-Object Kind -eq 'remove-vm-resource' | ForEach-Object Location)
        foreach ($resource in $outputModule.Resources) {
            if ($resource.Name.String -cin $removedResources) { $issues.Add("Removed VM resource remains: $($resource.Name)") }
        }
        [pscustomobject]@{
            Run=$path; InputHash=$inputHash; Cleaned=$run.Wrote.Cleaned
            OutputHash=(Get-FileHash -LiteralPath $run.Wrote.Cleaned -Algorithm SHA256).Hash
            IdentifiedEngines=$engines.Count; RetainedVmTypes=$retained; RebuiltMethods=$rebuilt.Count
            RemovedVmResources=$removedResources; Passed=($issues.Count -eq 0); Diagnostics=@($issues)
        }
    } catch {
        [pscustomobject]@{ Run=$path; Passed=$false; Diagnostics=@($_.Exception.Message) }
    } finally {
        if ($null -ne $inputModule) { $inputModule.Dispose() }
        if ($null -ne $outputModule) { $outputModule.Dispose() }
    }
}
$results | ConvertTo-Json -Depth 5
if (@($results | Where-Object { !$_.Passed }).Count) { exit 1 }
