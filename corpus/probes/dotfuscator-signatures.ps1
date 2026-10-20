param(
 [string]$Dotfuscator='C:/Program Files (x86)/PreEmptive Protection Dotfuscator Professional 7.9.0/dotfuscator.exe',
 [string]$Output='C:/cilantro-verify/dotfuscator/signature-corpus',
 [ValidateSet('Protect','Manifest','Recover','Verify')][string]$Stage='Protect',
 [string[]]$Only=@('*'),
 [ValidatePattern('^[A-Za-z0-9_-]+$')][string]$RecoveryDirectory='cleaned'
)
$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$Output=[IO.Path]::GetFullPath($Output)
function Hash([string]$Path){(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()}
function Run([string]$Executable,[string[]]$Arguments,[string]$Directory,[int]$Seconds=60){
 $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$Executable;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
 $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $info.StandardOutputEncoding=[Text.Encoding]::UTF8;$info.StandardErrorEncoding=[Text.Encoding]::UTF8
 $info.WorkingDirectory=$Directory
 foreach($argument in $Arguments){$info.ArgumentList.Add($argument)}
 $process=[Diagnostics.Process]::new();$process.StartInfo=$info
 try{
  [void]$process.Start();$stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
  $finished=$process.WaitForExit($Seconds*1000)
  if(!$finished){$process.Kill($true);$process.WaitForExit()}
  [ordered]@{ExitCode=$process.ExitCode;TimedOut=(!$finished);Stdout=$stdout.GetAwaiter().GetResult();Stderr=$stderr.GetAwaiter().GetResult()}
 }finally{$process.Dispose()}
}
$samples=@();$outcomes=@()
foreach($framework in @('net48','net8.0','net10.0')){
 foreach($profile in @('all-signatures','renamed-reviewed')){
  $id="$framework-$profile";if(!@($Only | Where-Object {$id -like $_}).Count){continue}
  $folder=Join-Path $Output $id;$extension=if($framework -eq 'net48'){'exe'}else{'dll'}
  $name="DotfuscatorSignatures.$extension"
  if($Stage -eq 'Protect'){
   if(Test-Path "$folder/config.xml"){throw "Capture exists: $id"}
   New-Item -ItemType Directory -Force "$folder/oracle","$folder/protected" | Out-Null
   Get-ChildItem "$repo/corpus/probes/DotfuscatorSignatures/bin/Release/$framework" -File |
    Where-Object Extension -in @('.dll','.exe','.json') | Copy-Item -Destination "$folder/oracle"
   $rename=if($profile -eq 'all-signatures'){'/rename:off'}else{'/rename:on'}
   $flow=if($profile -eq 'all-signatures'){'/controlflow:off'}else{'/controlflow:high'}
   $generated=Run $Dotfuscator @('/nologo',"/in:-$([IO.Path]::GetFullPath("$folder/oracle/$name"))","/out:$([IO.Path]::GetFullPath("$folder/protected"))",'/prune:off',$rename,$flow,'/encrypt:on',"/genconfig:$([IO.Path]::GetFullPath("$folder/config.xml"))") $folder
   $generated | ConvertTo-Json | Set-Content "$folder/config-generation.json"
   if($generated.ExitCode -ne 0 -or $generated.TimedOut){throw "Config generation failed: $id"}
   $include=if($profile -eq 'all-signatures'){'<type name="SignatureCases\..*" regex="true" />'}else{'<type name="SignatureCases\..*" regex="true"><method name="^(?!(Matrix|Pointer|FunctionPointer)$).*" regex="true" /></type>'}
   $xml=Get-Content "$folder/config.xml" -Raw
   $xml=$xml.Replace('<stringencrypt />','<stringencrypt version="2"><includelist>'+$include+'</includelist></stringencrypt>')
   [IO.File]::WriteAllText("$folder/config.xml",$xml)
   $protected=Run $Dotfuscator @('/nologo',([IO.Path]::GetFullPath("$folder/config.xml"))) $folder 120
   $protected | ConvertTo-Json | Set-Content "$folder/protection.json"
   if($protected.ExitCode -ne 0 -or $protected.TimedOut -or !(Test-Path "$folder/protected/$name")){throw "Protection failed: $id"}
   [ordered]@{Id=$id;Framework=$framework;Profile=$profile;ExpectedSites=$(if($profile -eq 'renamed-reviewed'){17}elseif($framework -eq 'net48'){19}else{20});CompilerVersion=(Get-Item $Dotfuscator).VersionInfo.FileVersion;CompilerSha256=(Hash $Dotfuscator);ConfigSha256=(Hash "$folder/config.xml");OracleSha256=(Hash "$folder/oracle/$name");ProtectedSha256=(Hash "$folder/protected/$name")} | ConvertTo-Json | Set-Content "$folder/fixture.json"
  }
  $capture=Get-Content "$folder/fixture.json" -Raw | ConvertFrom-Json
  if((Hash "$folder/oracle/$name") -cne $capture.OracleSha256 -or (Hash "$folder/protected/$name") -cne $capture.ProtectedSha256){throw "Capture changed: $id"}
  if($Stage -eq 'Manifest'){
   $local="dotfuscator-signatures/$id/protected/$name";$destination=Split-Path "$Output/samples/$local"
   New-Item -ItemType Directory -Force $destination,"$destination/runtimes/win-x64/native" | Out-Null
   Copy-Item "$folder/protected/$name","$folder/protected/environment????????.bin" $destination
   Copy-Item "$folder/protected/runtimes/win-x64/native/Runtime.Extensions.dll" "$destination/runtimes/win-x64/native"
   $oracle="dotfuscator-signatures/$framework-oracle/$name"
   New-Item -ItemType Directory -Force (Split-Path "$Output/samples/$oracle") | Out-Null
   Copy-Item "$folder/oracle/$name" "$Output/samples/$oracle"
   if(!@($samples | Where-Object id -eq "$framework-oracle").Count){$samples += [ordered]@{id="$framework-oracle";tier='oracle';sha256=$capture.OracleSha256;localName=$oracle;expectedDetection='none';expectedCapabilities=@()}}
   $samples += [ordered]@{id=$id;tier='profiled';sha256=$capture.ProtectedSha256;localName=$local;expectedDetection='dotfuscator';expectedCapabilities=@();oracleSha256=$capture.OracleSha256;minimumRecoveredStringSites=$capture.ExpectedSites;maximumRemainingSwitchDispatchers=0;maximumUnreachableInstructions=0;requireOracleResourceParity=$true}
  }
  if($Stage -eq 'Recover'){
   if(Test-Path "$folder/$RecoveryDirectory"){throw "Recovery directory exists: $id"}
   $recovery=Run 'dotnet' @("$repo/src/Cilantro.Cli/bin/Release/net10.0/cilantro.dll","$folder/protected/$name",'-o',"$folder/$RecoveryDirectory",'--json') $folder 120
   $recovery.Stdout | Set-Content "$folder/$RecoveryDirectory-recovery.json"
   if($recovery.ExitCode -ne 0 -or $recovery.TimedOut){throw "Recovery failed: $id"}
  }
  if($Stage -eq 'Verify'){
   $recovery=Get-Content "$folder/$RecoveryDirectory-recovery.json" -Raw | ConvertFrom-Json
   if($recovery.InputSha256 -cne $capture.ProtectedSha256){throw "Recovery input mismatch: $id"}
   $runs=@(foreach($kind in @('oracle','protected','cleaned')){
    $target=if($kind -eq 'cleaned'){$recovery.Wrote.Cleaned}else{"$folder/$kind/$name"}
    if($framework -eq 'net48'){Run $target @() (Split-Path $target) 30}
    else{Run 'dotnet' @('exec','--runtimeconfig',"$folder/oracle/DotfuscatorSignatures.runtimeconfig.json",$target) (Split-Path $target) 30}
   })
   $healthy=@($runs | Where-Object {$_.TimedOut -or $_.ExitCode -ne 0}).Count -eq 0
   $protectedMatch=$healthy -and $runs[1].Stdout -ceq $runs[2].Stdout
   $sourceMatch=$healthy -and $runs[0].Stdout -ceq $runs[2].Stdout
   if(!$protectedMatch -or ($profile -eq 'renamed-reviewed' -and !$sourceMatch)){throw "Behavior mismatch: $id"}
   $outcomes += [ordered]@{Id=$id;ProtectedCleanedMatch=$protectedMatch;SourceCleanedMatch=$sourceMatch;ExpectedSites=$capture.ExpectedSites;Runs=$runs}
  }
  Write-Host "$Stage $id complete"
 }
}
if($Stage -eq 'Manifest'){[ordered]@{manifestVersion=1;profile='dotfuscator-7-signatures';description='Source-built native-key v2 signature matrix: generics, constructed/nested types, arrays, byrefs, pointers and constructors. All-signature producer controls preserve protected behavior; renamed reviewed profiles exclude producer-corrupted sites.';samples=$samples} | ConvertTo-Json -Depth 8 | Set-Content "$Output/dotfuscator-7-signatures.manifest.json"}
if($Stage -eq 'Verify'){$outcomes | ConvertTo-Json -Depth 8 | Set-Content "$Output/$RecoveryDirectory-behavior.json"}
