param([Parameter(Mandatory)][string]$ToolDirectory)
$ErrorActionPreference='Stop'
Add-Type -Path (Join-Path $ToolDirectory 'dnlib.dll')
. (Join-Path $PSScriptRoot 'rebuilt-retirement.ps1')
function Add-Method($module, $owner, $name, $returnType) {
    $method=[dnlib.DotNet.MethodDefUser]::new($name,[dnlib.DotNet.MethodSig]::CreateStatic($returnType))
    $method.Attributes=[dnlib.DotNet.MethodAttributes]::Static -bor [dnlib.DotNet.MethodAttributes]::Private
    $method.Body=[dnlib.DotNet.Emit.CilBody]::new()
    $owner.Methods.Add($method)
    return $method
}
function Add-Return($method) { $method.Body.Instructions.Add([dnlib.DotNet.Emit.Instruction]::Create([dnlib.DotNet.Emit.OpCodes]::Ret)) }
$cases=@('preserved','renamed','missing-body','removed','unexplained','bad-reason','bad-fingerprint','duplicate','extra-removal','dangling-call','dangling-memberref','wrong-token','wrong-count','not-string-dependency','pool','pool-retained','pool-wrong-owner','pool-loader','pool-loader-wrong-token','pool-dangling')
$results=foreach($case in $cases) {
    $source=[dnlib.DotNet.ModuleDefUser]::new('benign.dll'); $source.Kind=[dnlib.DotNet.ModuleKind]::Dll
    $pool=$case.StartsWith('pool',[StringComparison]::Ordinal)
    $ownerName=if($pool -and $case -ne 'pool-wrong-owner'){'<Module>{1754a74b-161f-472b-9c73-7d84e24774c4}'}else{'Decoder'}
    $owner=[dnlib.DotNet.TypeDefUser]::new('',$ownerName,$source.CorLibTypes.Object.TypeDefOrRef)
    $source.Types.Add($owner)
    $build=Add-Method $source $owner 'Build' $source.CorLibTypes.Void; Add-Return $build
    $lookup=Add-Method $source $owner 'Lookup' $source.CorLibTypes.String
    if($case -ne 'not-string-dependency'){$lookup.Body.Instructions.Add([dnlib.DotNet.Emit.Instruction]::Create([dnlib.DotNet.Emit.OpCodes]::Call,$build))}
    $lookup.Body.Instructions.Add([dnlib.DotNet.Emit.Instruction]::Create([dnlib.DotNet.Emit.OpCodes]::Ldstr,'readable')); Add-Return $lookup
    $bytes=[IO.MemoryStream]::new(); $source.Write($bytes)
    $inputModule=[dnlib.DotNet.ModuleDefMD]::Load($bytes.ToArray()); $outputModule=[dnlib.DotNet.ModuleDefMD]::Load($bytes.ToArray())
    try {
        $inputOwner=@($inputModule.Types|Where-Object {$_.Name.String -ceq $ownerName})[0]
        $inputBuild=@($inputOwner.Methods|Where-Object {$_.Name.String -eq 'Build'})[0]
        $outputOwner=@($outputModule.Types|Where-Object {$_.Name.String -ceq $ownerName})[0]
        $outputBuild=@($outputOwner.Methods|Where-Object {$_.Name.String -eq 'Build'})[0]
        $token='{0:X8}' -f $inputBuild.MDToken.Raw
        $name=$inputBuild.FullName
        $location=$token+' '+$name
        $changes=[Collections.Generic.List[object]]::new(); $renames=@{}
        if($pool){
            $changes.Add([pscustomobject]@{Pass='virtualization-rebuild';Kind='lift-virtualized-program';Location=($token+' IL_0000');Description='Gave program 1 a method of its own and pointed the call that ran it through the engine at that method instead.'})
            $evidence=[pscustomobject]@{Category='virtualized-program';Location=($location+' IL_0000');Message='Program 1 of the interpreter at Engine::Run is run from the body of this method, which does other work besides.'}
            $name='System.Void '+$ownerName+'::LiftedProgram1()'
            if($case -ne 'pool-retained'){[void]$outputModule.Types.Remove($outputOwner)}
            if($case -eq 'pool-dangling'){
                $app=[dnlib.DotNet.TypeDefUser]::new('','App',$outputModule.CorLibTypes.Object.TypeDefOrRef); $outputModule.Types.Add($app)
                $call=Add-Method $outputModule $app 'Run' $outputModule.CorLibTypes.Void
                $oldOwner=[dnlib.DotNet.TypeRefUser]::new($outputModule,'',$ownerName,$outputModule)
                $oldCaller=[dnlib.DotNet.MemberRefUser]::new($outputModule,'Build',[dnlib.DotNet.MethodSig]::CreateStatic($outputModule.CorLibTypes.Void),$oldOwner)
                $call.Body.Instructions.Add([dnlib.DotNet.Emit.Instruction]::Create([dnlib.DotNet.Emit.OpCodes]::Call,$oldCaller)); Add-Return $call
            }
            $removal=[pscustomobject]@{Pass='unused-reactor-pools';Kind='remove-orphaned-rebuilt-method';Location=$name;Description=('Removed an exclusively owned initializer of a closed, wholly unused Reactor pool. Removed body fingerprint: '+('a'*64)+'.')}
            if($case.StartsWith('pool-loader',[StringComparison]::Ordinal)){
                $removal.Pass='loader-runtime-cleanup'
                $callerToken=if($case -eq 'pool-loader-wrong-token'){'0600FFFF'}else{$token}
                $removal.Description='Removed the lifted body of orphaned original caller 0x'+$callerToken+' after visibility, reachability and surviving-reference checks. Removed body fingerprint: '+('a'*64)+'.'
            }
            $changes.Add($removal)
        }else{
            $changes.Add([pscustomobject]@{Pass='virtualization-rebuild';Kind='rebuild-virtualized-method';Location=$location;Description='Written'})
            $evidence=[pscustomobject]@{Category='virtualized-method';Location=$location;Message='Body replaced by program 0 of the interpreter at Engine::Run.'}
            if($case -in @('preserved','renamed','missing-body')){
                $attribute=[dnlib.DotNet.TypeRefUser]::new($outputModule,'Cilantro','RebuiltFromReadingAttribute',$outputModule)
                $ctor=[dnlib.DotNet.MemberRefUser]::new($outputModule,'.ctor',[dnlib.DotNet.MethodSig]::CreateInstance($outputModule.CorLibTypes.Void),$attribute)
                $outputBuild.CustomAttributes.Add([dnlib.DotNet.CustomAttribute]::new($ctor))
                if($case -eq 'renamed'){$outputBuild.Name='Readable';$renames['M:'+$name]='M:'+$outputBuild.FullName}
                if($case -eq 'missing-body'){$outputBuild.Body=$null}
            }else{
                if($case -eq 'dangling-memberref'){
                    $outLookup=@($outputOwner.Methods|Where-Object {$_.Name.String -eq 'Lookup'})[0]
                    $outLookup.Body.Instructions[0].Operand=[dnlib.DotNet.MemberRefUser]::new($outputModule,'Build',[dnlib.DotNet.MethodSig]::CreateStatic($outputModule.CorLibTypes.Void),$outputOwner)
                }
                [void]$outputOwner.Methods.Remove($outputBuild)
                if($case -notin @('dangling-call','dangling-memberref')){
                    $outLookup=@($outputOwner.Methods|Where-Object {$_.Name.String -eq 'Lookup'})[0]
                    $outLookup.Body.Instructions.RemoveAt(0)
                }
                $reason='Removed the reconstructed body 0x'+$token+' from the direct dependencies of a fully replaced string resolver after visibility, reachability and surviving-reference checks. Removed body fingerprint: '+('a'*64)+'.'
                if($case -eq 'bad-reason'){$reason='Removed arbitrary application code. Removed body fingerprint: '+('a'*64)+'.'}
                if($case -eq 'bad-fingerprint'){$reason=$reason.Replace(('a'*64),'unknown')}
                $removal=[pscustomobject]@{Pass='runtime-cleanup';Kind='remove-orphaned-rebuilt-method';Location=$name;Description=$reason}
                if($case -ne 'unexplained'){$changes.Add($removal)}
                if($case -eq 'duplicate'){$changes.Add($removal)}
                if($case -eq 'extra-removal'){$changes.Add([pscustomobject]@{Pass='runtime-cleanup';Kind='remove-orphaned-rebuilt-method';Location='Unknown';Description=$reason})}
                if($case -eq 'wrong-token'){$changes[0].Location='0600FFFF '+$name}
            }
        }
        $methods=if($pool){0}elseif($case -eq 'wrong-count'){2}else{1}
        $programs=if($pool){1}else{0}
        $result=Test-RebuiltDisposition $inputModule $outputModule ([pscustomobject]@{Evidence=@($evidence)}) @($changes) $renames $methods $programs
        $expected=$case -in @('preserved','renamed','removed','pool','pool-loader')
        if($result.Passed -ne $expected){throw "$case expected $expected; diagnostics: $($result.Diagnostics -join '; ')"}
        [pscustomobject]@{Case=$case;ExpectedPass=$expected;ActualPass=$result.Passed}
    }finally{$inputModule.Dispose();$outputModule.Dispose();$source.Dispose();$bytes.Dispose()}
}
$results|ConvertTo-Json
