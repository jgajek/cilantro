param(
    [Parameter(Mandatory)][string]$OriginalCli,
    [Parameter(Mandatory)][string]$ForkCli,
    [string]$OutputRoot = 'samples/confuserex-generated',
    [string[]]$CaseNames,
    [string[]]$Editions = @('confuserex-1', 'confuserex-2')
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$output = [IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
$build = Join-Path $output 'build'
$probe = Join-Path $PSScriptRoot 'ConfuserExProbe/ConfuserExProbe.csproj'
dotnet build $probe -c Release -p:BaseOutputPath="$build/bin/" -p:BaseIntermediateOutputPath="$build/obj/" --configfile (Join-Path $PSScriptRoot 'nuget.config')
if ($LASTEXITCODE -ne 0) { throw 'Probe build failed.' }
$inputDir = Join-Path $build 'bin/Release/net48'
$oracleDir = Join-Path $output 'oracle'
New-Item -ItemType Directory -Path $oracleDir -Force | Out-Null
Copy-Item (Join-Path $inputDir 'ConfuserExProbe.exe') (Join-Path $oracleDir 'ConfuserExProbe.exe') -Force

$cases = [ordered]@{
    constants = @('constants')
    flow = @('ctrl flow')
    proxy = @('ref proxy')
    resources = @('resources')
    tamper = @('anti tamper')
    checks = @('anti debug', 'anti dump', 'anti ildasm')
    renamed = @('rename')
    'combined-no-rename' = @('constants', 'ctrl flow', 'ref proxy', 'resources', 'anti tamper', 'anti debug', 'anti dump', 'anti ildasm')
    combined = @('rename', 'constants', 'ctrl flow', 'ref proxy', 'resources', 'anti tamper', 'anti debug', 'anti dump', 'anti ildasm')
    'combined-strong' = @('rename', 'constants', 'ctrl flow', 'ref proxy:strong', 'resources', 'anti tamper', 'anti debug', 'anti dump', 'anti ildasm')
    'combined-dynamic-jit' = @('rename', 'constants:dynamic', 'ctrl flow', 'ref proxy:strong:expression', 'resources:dynamic', 'anti tamper:jit:dynamic', 'anti debug:win32', 'anti dump', 'anti ildasm')
    'combined-x86' = @('rename', 'constants:x86', 'ctrl flow', 'ref proxy:strong:x86', 'resources', 'anti tamper', 'anti debug', 'anti dump', 'anti ildasm')
    'constants-dynamic' = @('constants:dynamic')
    'constants-x86' = @('constants:x86')
    'resources-dynamic' = @('resources:dynamic')
    'proxy-strong' = @('ref proxy:strong')
    'proxy-strong-expression' = @('ref proxy:strong:expression')
    'proxy-strong-x86' = @('ref proxy:strong:x86')
    'tamper-jit' = @('anti tamper:jit')
    'tamper-jit-dynamic' = @('anti tamper:jit:dynamic')
    'tamper-normal-dynamic' = @('anti tamper:normal:dynamic')
    'tamper-anti' = @('anti tamper:Anti')
    'debug-win32' = @('anti debug:win32')
    'debug-antinet' = @('anti debug:antinet')
    'invalid-metadata' = @('invalid metadata')
    packed = @()
}
$captures = @()
foreach ($edition in @(@{ Id = 'confuserex-1'; Cli = $OriginalCli }, @{ Id = 'confuserex-2'; Cli = $ForkCli })) {
    if ($edition.Id -notin $Editions) { continue }
    foreach ($case in $cases.GetEnumerator()) {
        if ($CaseNames -and $case.Key -notin $CaseNames) { continue }
        $caseDir = Join-Path $output "$($edition.Id)/$($case.Key)"
        New-Item -ItemType Directory -Path $caseDir -Force | Out-Null
        $protections = ($case.Value | ForEach-Object {
            $parts = $_ -split ':'
            if ($parts.Count -eq 3) {
                $secondName = if ($parts[0] -eq 'ref proxy') { 'encoding' } else { 'key' }
                "<protection id=`"$($parts[0])`"><argument name=`"mode`" value=`"$($parts[1])`" /><argument name=`"$secondName`" value=`"$($parts[2])`" /></protection>"
            }
            elseif ($parts.Count -eq 2) {
                "<protection id=`"$($parts[0])`"><argument name=`"mode`" value=`"$($parts[1])`" /></protection>"
            }
            else { "<protection id=`"$_`" />" }
        }) -join ''
        $packer = if ($case.Key -eq 'packed') { '<packer id="compressor" />' } else { '' }
        $project = "<?xml version=`"1.0`"?><project baseDir=`"$inputDir`" outputDir=`"$caseDir`" seed=`"cilantro-2026`" xmlns=`"http://confuser.codeplex.com`"><rule preset=`"none`" pattern=`"true`">$protections</rule>$packer<module path=`"ConfuserExProbe.exe`" /></project>"
        $projectPath = Join-Path $caseDir 'fixture.crproj'
        [IO.File]::WriteAllText($projectPath, $project)
        & $edition.Cli -n $projectPath *> (Join-Path $caseDir 'protector.log')
        if ($LASTEXITCODE -ne 0) { throw "Protection failed: $($edition.Id)/$($case.Key)." }
        $assembly = Join-Path $caseDir 'ConfuserExProbe.exe'
        if (!(Test-Path $assembly)) { throw "Missing output: $assembly" }
        $captures += [ordered]@{
            id = "$($edition.Id)-$($case.Key)"
            protections = $case.Value
            localName = [IO.Path]::GetRelativePath((Join-Path $repo 'samples'), $assembly).Replace('\', '/')
            sha256 = (Get-FileHash $assembly -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
}
$captures | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $output 'captures.json')
