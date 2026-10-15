# Used by the VM removal audit. This inspects metadata and run records only.
function Test-RebuiltDisposition($InputModule, $OutputModule, $Analysis, $Changes, $Renames, [int]$ExpectedMethods, [int]$ExpectedPrograms) {
    $issues = [Collections.Generic.List[string]]::new()
    $expected = [Collections.Generic.List[object]]::new()
    $rebuiltChanges = @($Changes | Where-Object { $_.Pass -eq 'virtualization-rebuild' -and $_.Kind -eq 'rebuild-virtualized-method' })
    $liftedChanges = @($Changes | Where-Object { $_.Pass -eq 'virtualization-rebuild' -and $_.Kind -eq 'lift-virtualized-program' })
    if ($rebuiltChanges.Count -ne $ExpectedMethods -or $liftedChanges.Count -ne $ExpectedPrograms -or ($ExpectedMethods + $ExpectedPrograms) -eq 0) {
        $issues.Add('Reconstruction records do not account for the reported methods/programs.')
    }
    foreach ($change in $rebuiltChanges) {
        if ($change.Location -notmatch '^([0-9A-Fa-f]{8}) (.+)$') { $issues.Add('Malformed reconstructed method identity.'); continue }
        $token = [Convert]::ToUInt32($Matches[1], 16); $name = $Matches[2]
        $source = $InputModule.ResolveToken($token)
        if ($source -isnot [dnlib.DotNet.MethodDef] -or $source.FullName -cne $name -or
            @($Analysis.Evidence | Where-Object { $_.Category -eq 'virtualized-method' -and $_.Location -ceq $change.Location }).Count -ne 1) {
            $issues.Add("Original reconstructed method/provenance mismatch: $name"); continue
        }
        $expected.Add([pscustomobject]@{ Name=$name; Source=$source; Kind='method'; Token=$token })
    }
    foreach ($change in $liftedChanges) {
        if ($change.Location -notmatch '^([0-9A-Fa-f]{8}) IL_([0-9A-Fa-f]+)$') { $issues.Add('Malformed lifted caller identity.'); continue }
        $tokenText = $Matches[1]; $token = [Convert]::ToUInt32($tokenText, 16)
        $source = $InputModule.ResolveToken($token)
        if ($source -isnot [dnlib.DotNet.MethodDef] -or $change.Description -notmatch '^Gave program ([0-9]+) a method of its own ') {
            $issues.Add('Unresolved lifted caller/program identity.'); continue
        }
        $program = $Matches[1]
        $evidence = @($Analysis.Evidence | Where-Object { $_.Category -eq 'virtualized-program' -and
            $_.Location.StartsWith($tokenText + ' ' + $source.FullName + ' IL_', [StringComparison]::Ordinal) -and
            $_.Message.StartsWith('Program ' + $program + ' of the interpreter ', [StringComparison]::Ordinal) })
        if ($evidence.Count -ne 1) { $issues.Add("Lifted program has no unique detection evidence: $tokenText/$program"); continue }
        $expected.Add([pscustomobject]@{Name=('System.Void ' + $source.DeclaringType.FullName + '::LiftedProgram' + $program + '()');Source=$source;Kind='program';Token=$token})
    }
    $outputMethods = @($OutputModule.GetTypes() | ForEach-Object { $_.Methods })
    $marked = @($outputMethods | Where-Object { @($_.CustomAttributes | Where-Object TypeFullName -eq 'Cilantro.RebuiltFromReadingAttribute').Count })
    $removals = @($Changes | Where-Object Kind -eq 'remove-orphaned-rebuilt-method')
    $dispositions = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($item in $expected) {
        $name = $item.Name
        if (!$seen.Add($name)) { $issues.Add("Duplicate reconstructed identity: $name"); continue }
        $mapped = $name
        if ($Renames.ContainsKey('M:' + $name)) { $mapped = $Renames['M:' + $name].Substring(2) }
        elseif ($Renames.ContainsKey('T:' + $item.Source.DeclaringType.FullName)) {
            $mapped = $name.Replace($item.Source.DeclaringType.FullName + '::', $Renames['T:' + $item.Source.DeclaringType.FullName].Substring(2) + '::')
        }
        $present = @($outputMethods | Where-Object { $_.FullName -ceq $mapped -or $_.FullName -ceq $name })
        $removed = @($removals | Where-Object Location -CEQ $name)
        if ($present.Count -eq 1 -and $removed.Count -eq 0 -and $present[0].HasBody -and $marked.Contains($present[0])) {
            $dispositions.Add([pscustomobject]@{Original=$name;Output=$present[0].FullName;Disposition='preserved-cil';Basis='Marked reconstructed body survives.'}); continue
        }
        if ($present.Count -ne 0 -or $removed.Count -ne 1 -or $removed[0].Description -notmatch 'Removed body fingerprint: [0-9a-f]{64}\.$') {
            $issues.Add("Missing, duplicate or contradictory reconstructed disposition: $name"); continue
        }
        $basis = $null
        $retiredOwner = $null
        $closedPoolRecord = $removed[0].Pass -eq 'unused-reactor-pools' -and
            $removed[0].Description.StartsWith('Removed an exclusively owned initializer of a closed, wholly unused Reactor pool.', [StringComparison]::Ordinal)
        $orphanedPoolRecord = $removed[0].Pass -eq 'loader-runtime-cleanup' -and
            $removed[0].Description.StartsWith(('Removed the lifted body of orphaned original caller 0x{0:X8} after visibility, reachability and surviving-reference checks.' -f $item.Token), [StringComparison]::Ordinal)
        if ($item.Kind -eq 'program' -and ($closedPoolRecord -or $orphanedPoolRecord) -and
            $item.Source.DeclaringType.FullName -match '^<Module>\{[0-9a-fA-F-]{36}\}$') {
            $owner = $item.Source.DeclaringType.FullName
            if ($Renames.ContainsKey('T:' + $owner)) { $owner = $Renames['T:' + $owner].Substring(2) }
            if (@($OutputModule.GetTypes() | Where-Object FullName -CEQ $owner).Count -eq 0) {
                $basis = 'Retired Reactor pool; original caller and lifted holder owner physically absent.'
                $retiredOwner = $owner
            }
        }
        if ($item.Kind -eq 'method' -and $removed[0].Pass -match '(^|-)runtime-cleanup$' -and
            $removed[0].Description.StartsWith(('Removed the reconstructed body 0x{0:X8} from the direct dependencies of a fully replaced string resolver ' -f $item.Token), [StringComparison]::Ordinal) -and
            $item.Source.IsStatic -and !$item.Source.IsConstructor -and $item.Source.ReturnType.FullName -eq 'System.Void') {
            # Independently establish that the original body belongs to the same-owner
            # dependency graph of a string-returning method, rather than trusting a count.
            $pending = [Collections.Generic.Stack[dnlib.DotNet.MethodDef]]::new()
            foreach ($method in $item.Source.DeclaringType.Methods | Where-Object { $_.HasBody -and $_.ReturnType.FullName -eq 'System.String' }) { $pending.Push($method) }
            $visited = [Collections.Generic.HashSet[dnlib.DotNet.MethodDef]]::new()
            while ($pending.Count) {
                $method = $pending.Pop()
                if (!$visited.Add($method) -or !$method.HasBody) { continue }
                foreach ($instruction in $method.Body.Instructions) {
                    if ($instruction.Operand -is [dnlib.DotNet.IMethod]) {
                        $target = [dnlib.DotNet.Extensions]::ResolveMethodDef($instruction.Operand)
                        if ($null -ne $target -and $target.DeclaringType -eq $item.Source.DeclaringType) { $pending.Push($target) }
                    }
                }
            }
            if ($visited.Contains($item.Source)) { $basis = 'Replaced string-resolver dependency; original call-graph membership and physical absence verified.' }
        }
        if ($null -eq $basis) { $issues.Add("Unproved protector ownership for removed reconstructed body: $name"); continue }
        $references = @($outputMethods | Where-Object HasBody | ForEach-Object { $_.Body.Instructions } | Where-Object {
            $_.Operand -is [dnlib.DotNet.IMethod] -and ($_.Operand.FullName -ceq $name -or $_.Operand.FullName -ceq $mapped -or
                ($_.Operand -is [dnlib.DotNet.MethodDef] -and $null -eq $_.Operand.DeclaringType))
        })
        if ($references.Count) { $issues.Add("A surviving instruction still references the retired body: $name"); continue }
        if ($null -ne $retiredOwner) {
            $ownerReferences = @($outputMethods | Where-Object HasBody | ForEach-Object { $_.Body.Instructions } | Where-Object {
                $operand = $_.Operand
                (($operand -is [dnlib.DotNet.IMethod] -or $operand -is [dnlib.DotNet.IField]) -and
                    ($operand.DeclaringType.FullName -ceq $retiredOwner -or $operand.DeclaringType.FullName -ceq $item.Source.DeclaringType.FullName)) -or
                ($operand -is [dnlib.DotNet.ITypeDefOrRef] -and
                    ($operand.FullName -ceq $retiredOwner -or $operand.FullName -ceq $item.Source.DeclaringType.FullName))
            })
            if ($ownerReferences.Count) { $issues.Add("A surviving instruction still references the retired pool: $retiredOwner"); continue }
        }
        $dispositions.Add([pscustomobject]@{Original=$name;Output=$null;Disposition='retired-protector';Basis=$basis;Record=$removed[0]})
    }
    if (@($removals | Where-Object { !$seen.Contains($_.Location) }).Count) { $issues.Add('A removal record has no reconstructed source identity.') }
    if (@($dispositions | Where-Object Disposition -eq 'preserved-cil').Count -ne $marked.Count) { $issues.Add('Unexpected marked reconstructed methods remain outside the disposition ledger.') }
    [pscustomobject]@{Passed=($issues.Count -eq 0);Surviving=$marked.Count;Dispositions=@($dispositions);Diagnostics=@($issues)}
}
