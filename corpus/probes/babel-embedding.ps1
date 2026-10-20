param(
 [string]$Babel="$env:LOCALAPPDATA/Programs/BabelDesktop/babel.exe",
 [string]$Output='C:/cilantro-verify/babel/embedding',
 [ValidateSet('Protect','Manifest','Recover','Verify')][string]$Stage='Protect',
 [string]$Only='*',
 [ValidateSet('single','multiple','combined','nested','renamed','signed-renamed','signed-combined')][string[]]$Profiles=@('single','multiple','combined','nested'),
 [ValidatePattern('^[A-Za-z0-9_-]+$')][string]$CorpusProfile='babel-12-embedding',
 [string]$SigningKey,
 [ValidatePattern('^[A-Za-z0-9_-]+$')][string]$RecoveryDirectory='cleaned',
 [string]$PackageRoot='C:/cilantro-verify/samples'
)
$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$Output=[IO.Path]::GetFullPath($Output)
function Hash([string]$Path){(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()}
function Run([string]$Executable,[string[]]$Arguments,[int]$Seconds=120){
 $info=[Diagnostics.ProcessStartInfo]::new($Executable);$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $info.StandardOutputEncoding=[Text.Encoding]::UTF8;$info.StandardErrorEncoding=[Text.Encoding]::UTF8
 foreach($argument in $Arguments){$info.ArgumentList.Add($argument)}
 $process=[Diagnostics.Process]::new();$process.StartInfo=$info
 try{[void]$process.Start();$out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync();$done=$process.WaitForExit($Seconds*1000)
  if(!$done){$process.Kill($true);$process.WaitForExit()}
  $stdout=$out.GetAwaiter().GetResult();$stderr=$err.GetAwaiter().GetResult()
  if($env:BABEL_LICENSE){$stdout=$stdout.Replace($env:BABEL_LICENSE,'[redacted]');$stderr=$stderr.Replace($env:BABEL_LICENSE,'[redacted]')}
  [ordered]@{ExitCode=$process.ExitCode;TimedOut=(!$done);Stdout=$stdout;Stderr=$stderr}
 }finally{$process.Dispose()}
}
$baseOptions=@('--notypes','--nomethods','--nofields','--noproperties','--noevents','--nologo','--quiet','--strict-exit','--randomseed','8675309','--use','tagassembly=on')
$behavior=@()
$samples=@()
foreach($framework in @('net48','net8.0','net10.0')){foreach($profile in $Profiles){
 $id="$framework-$profile";if($id -notlike $Only){continue}
 $signed=$profile.StartsWith('signed-', [StringComparison]::Ordinal);$multiple=$profile -in @('multiple','combined','renamed','signed-renamed','signed-combined');$combined=$profile -in @('combined','signed-combined')
 $folder="$Output/$id";$extension=if($framework -eq 'net48'){'exe'}else{'dll'};$name="BabelEmbedProbe.$extension"
 if($Stage -eq 'Protect'){
  if(!$env:BABEL_LICENSE){throw 'Set BABEL_LICENSE to the supplied floating user key in this process; it is not stored in fixtures.'}
  if(Test-Path "$folder/protected/$name"){throw "Capture already exists: $id"}
  New-Item -ItemType Directory -Force "$folder/oracle","$folder/protected"|Out-Null
  $build=if($signed){'bin/signed/Release'}else{'bin/Release'}
  Get-ChildItem "$repo/corpus/probes/BabelEmbedding/App/$build/$framework" -File|Where-Object Extension -in @('.dll','.exe','.json')|Copy-Item -Destination "$folder/oracle"
  $library="$folder/oracle/BabelEmbedLibrary.dll";$leaf="$folder/oracle/BabelEmbedLeaf.dll"
  if($profile -eq 'nested'){
   New-Item -ItemType Directory -Force "$folder/nested"|Out-Null
   $nested=Run $Babel (@($library,'--output',"$folder/nested/BabelEmbedLibrary.dll",'--embed',$leaf,'--license',"floating:$env:BABEL_LICENSE")+$baseOptions)
   $nested|ConvertTo-Json|Set-Content "$folder/nested-protection.json"
   if($nested.ExitCode -ne 0 -or $nested.TimedOut){throw "Nested embedding failed: $id"}
   $library="$folder/nested/BabelEmbedLibrary.dll"
  }
  $options=$baseOptions+@('--embed',$library)
  if($multiple){$options+=@('--embed',$leaf)}
  if($profile -in @('renamed','signed-renamed','signed-combined')){$options=@($options|Where-Object {$_ -notin @('--notypes','--nomethods','--nofields','--noproperties','--noevents')})+@('--types','--methods','--fields','--properties','--events')}
  if($combined){$options+=@('--resourceencryption','--stringencryption','xor','--controlflow','switch=on','--proxy','all')}
  if($signed){if(!$SigningKey -or !(Test-Path -LiteralPath $SigningKey)){throw 'A local signing key for the benign probe is required.'};$options+=@('--keyfile',$SigningKey)}
  $result=Run $Babel (@("$folder/oracle/$name",'--output',"$folder/protected/$name",'--license',"floating:$env:BABEL_LICENSE")+$options)
  $result|ConvertTo-Json|Set-Content "$folder/protection.json"
  if($result.ExitCode -ne 0 -or $result.TimedOut -or !(Test-Path "$folder/protected/$name")){throw "Embedding failed: $id"}
  foreach($json in Get-ChildItem "$folder/oracle" -Filter '*.json'){if(!(Test-Path "$folder/protected/$($json.Name)")){Copy-Item -LiteralPath $json.FullName -Destination "$folder/protected/$($json.Name)"}}
  if($profile -eq 'single'){Copy-Item -LiteralPath $leaf -Destination "$folder/protected/BabelEmbedLeaf.dll"}
  if(Test-Path "$folder/protected/BabelEmbedLibrary.dll"){throw "Embedding verification would be masked by a plaintext library: $id"}
  if($profile -ne 'single' -and (Test-Path "$folder/protected/BabelEmbedLeaf.dll")){throw "Embedding verification would be masked by a plaintext leaf: $id"}
  [ordered]@{Id=$id;Framework=$framework;Profile=$profile;CompilerVersion=(Get-Item $Babel).VersionInfo.FileVersion;CompilerSha256=(Hash $Babel);Options=$options;OracleSha256=(Hash "$folder/oracle/$name");ProtectedSha256=(Hash "$folder/protected/$name");LibrarySha256=(Hash "$folder/oracle/BabelEmbedLibrary.dll");LeafSha256=(Hash $leaf);EmbeddedLibrarySha256=(Hash $library)}|ConvertTo-Json -Depth 5|Set-Content "$folder/fixture.json"
 }
 $fixture=Get-Content "$folder/fixture.json" -Raw|ConvertFrom-Json
 if((Hash "$folder/protected/$name") -cne $fixture.ProtectedSha256 -or (Hash "$folder/oracle/$name") -cne $fixture.OracleSha256){throw "Capture changed: $id"}
 if($Stage -eq 'Manifest'){
  foreach($kind in @('oracle','protected')){
   $destination="$PackageRoot/$CorpusProfile/$id/$kind";New-Item -ItemType Directory -Force $destination|Out-Null
   Copy-Item "$folder/$kind/*" $destination -Recurse -Force
  }
  $oracleId=if($signed){"$framework-signed-oracle"}else{"$framework-oracle"}
  if(!@($samples|Where-Object id -eq $oracleId).Count){$samples += [ordered]@{id=$oracleId;tier='oracle';sha256=$fixture.OracleSha256;localName="$CorpusProfile/$id/oracle/$name";expectedDetection='none';expectedCapabilities=@()}}
  $payloads=@($fixture.EmbeddedLibrarySha256);if($multiple){$payloads+= $fixture.LeafSha256}
  $report=Get-Content "$folder/$RecoveryDirectory/BabelEmbedProbe.analysis.json" -Raw|ConvertFrom-Json
  if($report.InputSha256 -cne $fixture.ProtectedSha256){throw "Recovery report does not match the protected capture: $id"}
  $retired=@($report.Payloads|Where-Object Origin -eq 'embeddedDependency'|Select-Object -ExpandProperty SourceResource -Unique)
  if($retired.Count -ne 1){throw "A complete embedding capture must identify one bundle: $id"}
  $samples += [ordered]@{id=$id;tier='profiled';sha256=$fixture.ProtectedSha256;localName="$CorpusProfile/$id/protected/$name";expectedDetection='babel';expectedCapabilities=@();oracleSha256=$fixture.OracleSha256;expectedPayloadSha256=$payloads;expectedRetiredResourceNames=$retired;maximumRemainingSwitchDispatchers=0;maximumUnreachableInstructions=0}
 }
 if($Stage -eq 'Recover'){
  if(Test-Path "$folder/$RecoveryDirectory"){throw "Recovery exists: $id/$RecoveryDirectory"}
  $recoveryOptions=@("$repo/src/Cilantro.Cli/bin/Release/net10.0/cilantro.dll","$folder/protected/$name",'-o',"$folder/$RecoveryDirectory",'--json')
  if($signed -and $SigningKey){$recoveryOptions+=@('--signing-key',$SigningKey)}
  $run=Run 'dotnet' $recoveryOptions 240
  $run|ConvertTo-Json|Set-Content "$folder/$RecoveryDirectory-recovery.json"
  if($run.ExitCode -ne 0 -or $run.TimedOut){throw "Recovery failed: $id"}
 }
 if($Stage -eq 'Verify'){
  $cleaned="$folder/$RecoveryDirectory/BabelEmbedProbe.cleaned.$extension"
  $kinds=@('oracle','protected');if(Test-Path $cleaned){$kinds+='cleaned';if($profile -eq 'single'){Copy-Item "$folder/protected/BabelEmbedLeaf.dll" "$folder/$RecoveryDirectory/BabelEmbedLeaf.dll" -Force}}
  $runs=@(foreach($kind in $kinds){
   $target=if($kind -eq 'cleaned'){$cleaned}else{"$folder/$kind/$name"}
   $config=if($kind -eq 'cleaned'){"$folder/protected/BabelEmbedProbe.runtimeconfig.json"}else{"$folder/$kind/BabelEmbedProbe.runtimeconfig.json"}
   if($framework -eq 'net48'){Run $target @() 30}else{Run 'dotnet' @('exec','--runtimeconfig',$config,$target) 30}
  })
  $match=@($runs|Where-Object {$_.ExitCode -ne 0 -or $_.TimedOut -or $_.Stdout -cne $runs[0].Stdout}).Count -eq 0
  $dependencies=@();if($kinds.Count -eq 3){$capture=Get-Content "$folder/$RecoveryDirectory-recovery.json" -Raw|ConvertFrom-Json;$manifest=$capture.Stdout|ConvertFrom-Json
   $dependencies=@(foreach($path in $manifest.Wrote.Dependencies){if(!(Test-Path -LiteralPath $path)){throw "A deployed dependency is missing: $path"};[ordered]@{Name=[IO.Path]::GetFileName($path);Sha256=(Hash $path);Length=(Get-Item -LiteralPath $path).Length}})
  }
  $scope=if($dependencies.Count){'Source/protected/cleaned embedding comparison with ordinary deployed dependency files'}else{'Source/protected/available-cleaned embedding comparison; generated loaders are retained'}
  $record=[ordered]@{Id=$id;Match=$match;Kinds=$kinds;Scope=$scope;Dependencies=$dependencies;Runs=$runs}
  $suffix=if($kinds.Count -eq 3){"$RecoveryDirectory-behavior"}else{'protected-behavior'}
  $record|ConvertTo-Json -Depth 5|Set-Content "$folder/$suffix.json";$behavior+=$record
  if(!$match){throw "Protected behavior failed: $id"}
 }
 Write-Host "$Stage $id complete"
}}
if($Stage -eq 'Manifest'){[ordered]@{manifestVersion=1;profile=$CorpusProfile;description='Licensed executable dependency embedding captures across net48/net8/net10. Static byte-exact extraction and complete reviewed loader retirement with ordinary dependency deployment; profiles and compiler options are pinned in provenance.';samples=$samples}|ConvertTo-Json -Depth 10|Set-Content "$Output/manifest.json"}
if($behavior.Count){$behavior|ConvertTo-Json -Depth 6|Set-Content "$Output/$suffix.json"}
