param(
 [string]$Source='C:/cilantro-verify/dotfuscator/signature-corpus',
 [string]$Output='C:/cilantro-verify/dotfuscator/macos-corpus',
 [ValidateSet('Package','Manifest','Recover','Compare')][string]$Stage='Package',
 [ValidatePattern('^[A-Za-z0-9_-]+$')][string]$RecoveryDirectory='cleaned'
)
$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$Source=[IO.Path]::GetFullPath($Source);$Output=[IO.Path]::GetFullPath($Output)
function Hash([string]$Path){(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()}
function Evidence([string]$Path){[ordered]@{path=$Path;sha256=(Hash $Path)}}
$samples=@();$records=@()
foreach($framework in @('net8.0','net10.0')){
 foreach($profile in @('all-signatures','renamed-reviewed')){
  $sourceFolder="$Source/$framework-$profile"
  $capture=Get-Content "$sourceFolder/fixture.json" -Raw | ConvertFrom-Json
  $name='DotfuscatorSignatures.dll'
  if((Hash "$sourceFolder/protected/$name") -cne $capture.ProtectedSha256 -or
     (Hash "$sourceFolder/oracle/$name") -cne $capture.OracleSha256 -or
     (Hash "$sourceFolder/config.xml") -cne $capture.ConfigSha256){throw 'Source capture identities changed'}
  foreach($rid in @('osx-x64','osx-arm64')){
   $id="$framework-$rid-$profile";$folder="$Output/$id"
   $local="dotfuscator-v2-macos/$id/$name"
   $input="$Output/samples/$local";$directory=Split-Path $input
   if($Stage -in @('Package','Manifest')){
    if($Stage -eq 'Package' -and (Test-Path $input)){throw "Package exists: $id"}
    $native="$sourceFolder/protected/runtimes/$rid/native/Runtime.Extensions.dylib"
    $oracle="dotfuscator-v2-macos/$framework-oracle/$name"
    if($Stage -eq 'Package'){
     New-Item -ItemType Directory -Force $directory,"$directory/runtimes/$rid/native" | Out-Null
     Copy-Item "$sourceFolder/protected/$name","$sourceFolder/protected/environment????????.bin" $directory
     Copy-Item $native "$directory/runtimes/$rid/native/Runtime.Extensions.dylib"
     New-Item -ItemType Directory -Force (Split-Path "$Output/samples/$oracle") | Out-Null
     Copy-Item "$sourceFolder/oracle/$name" "$Output/samples/$oracle"
    }
    if(!@($samples | Where-Object id -eq "$framework-oracle").Count){$samples += [ordered]@{id="$framework-oracle";tier='oracle';sha256=$capture.OracleSha256;localName=$oracle;expectedDetection='none';expectedCapabilities=@()}}
    $samples += [ordered]@{id=$id;tier='profiled';sha256=$capture.ProtectedSha256;localName=$local;expectedDetection='dotfuscator';expectedCapabilities=@();oracleSha256=$capture.OracleSha256;minimumRecoveredStringSites=$capture.ExpectedSites;maximumRemainingSwitchDispatchers=0;maximumUnreachableInstructions=0;requireOracleResourceParity=$true}
    if($Stage -eq 'Package'){
     New-Item -ItemType Directory -Force $folder | Out-Null
     [ordered]@{id=$id;sourceFixture=(Evidence "$sourceFolder/fixture.json");protected=(Evidence $input);native=(Evidence $native);rid=$rid;expectedSites=$capture.ExpectedSites} | ConvertTo-Json -Depth 5 | Set-Content "$folder/fixture.json"
    }
   }
   if((Hash $input) -cne $capture.ProtectedSha256){throw "Packaged input changed: $id"}
   if($Stage -eq 'Recover'){
    if(Test-Path "$folder/$RecoveryDirectory"){throw "Recovery output exists: $id"}
    & dotnet "$repo/src/Cilantro.Cli/bin/Release/net10.0/cilantro.dll" $input -o "$folder/$RecoveryDirectory" --json > "$folder/$RecoveryDirectory-recovery.json"
    if($LASTEXITCODE -ne 0){throw "Recovery failed: $id"}
   }
   if($Stage -eq 'Compare'){
    $recovery=Get-Content "$folder/$RecoveryDirectory-recovery.json" -Raw | ConvertFrom-Json
    $baseline=Get-Content "$sourceFolder/cleaned-recovery.json" -Raw | ConvertFrom-Json
    if(!$recovery.Success -or !$baseline.Success -or $recovery.InputSha256 -cne $capture.ProtectedSha256 -or
       $baseline.InputSha256 -cne $capture.ProtectedSha256 -or $recovery.Recovery.ConstantStringSites -ne $capture.ExpectedSites -or
       (Hash $recovery.Wrote.Cleaned) -cne (Hash $baseline.Wrote.Cleaned)){throw "Recovery comparison failed: $id"}
    $records += [ordered]@{id=$id;rid=$rid;recoveredSites=$recovery.Recovery.ConstantStringSites;remainingSwitchDispatchers=$recovery.Recovery.RemainingSwitchDispatchers;remainingUnreachableInstructions=$recovery.Recovery.RemainingUnreachableInstructions;runtimeTypesRemoved=$recovery.Recovery.RuntimeTypesRemoved;matchesWindowsRecovery=$true;recovery=(Evidence "$folder/$RecoveryDirectory-recovery.json");output=(Evidence $recovery.Wrote.Cleaned);windowsBaseline=(Evidence $baseline.Wrote.Cleaned)}
   }
   Write-Host "$Stage $id complete"
  }
 }
}
if($Stage -in @('Package','Manifest')){
 foreach($rid in @('osx-x64','osx-arm64')){
  [ordered]@{manifestVersion=1;profile="dotfuscator-7-native-$rid";description="Four $rid-only native companion packages from existing source-built AnyCPU CoreCLR captures. Static recovery comparisons only; macOS runtime execution is unvalidated.";samples=@($samples | Where-Object {$_.tier -eq 'oracle' -or $_.id.Contains($rid)})} | ConvertTo-Json -Depth 8 | Set-Content "$Output/dotfuscator-7-native-$rid.manifest.json"
 }
}
if($Stage -eq 'Compare'){$records | ConvertTo-Json -Depth 7 | Set-Content "$Output/$RecoveryDirectory-comparison.json"}
