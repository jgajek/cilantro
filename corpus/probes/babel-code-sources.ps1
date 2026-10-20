param(
 [string]$Babel = "$env:LOCALAPPDATA/Programs/BabelDesktop/babel.exe",
 [string]$Output = 'C:/cilantro-verify/babel/code-sources',
 [string]$Only = '*',
 [ValidateSet('Protect','Recover','Verify','Manifest')][string]$Stage = 'Protect',
 [ValidatePattern('^[A-Za-z0-9_-]+$')][string]$RecoveryDirectory = 'cleaned',
 [string]$PackageRoot = 'C:/cilantro-verify/samples',
 [ValidateSet('password','external')][string]$ManifestProfile = 'password',
 [switch]$Combined
)
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
function Run([string]$Executable, [string[]]$Arguments, [int]$Seconds = 120) {
 $info = [Diagnostics.ProcessStartInfo]::new($Executable)
 $info.UseShellExecute = $false
 $info.CreateNoWindow = $true
 $info.RedirectStandardOutput = $true
 $info.RedirectStandardError = $true
 $info.StandardOutputEncoding = [Text.Encoding]::UTF8
 $info.StandardErrorEncoding = [Text.Encoding]::UTF8
 foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
 $process = [Diagnostics.Process]::new()
 $process.StartInfo = $info
 try {
  [void]$process.Start()
  $stdout = $process.StandardOutput.ReadToEndAsync()
  $stderr = $process.StandardError.ReadToEndAsync()
  $finished = $process.WaitForExit($Seconds * 1000)
  if (!$finished) { $process.Kill($true); $process.WaitForExit() }
  $outText = $stdout.GetAwaiter().GetResult()
  $errText = $stderr.GetAwaiter().GetResult()
  if ($env:BABEL_LICENSE) {
   $outText = $outText.Replace($env:BABEL_LICENSE, '[redacted]')
   $errText = $errText.Replace($env:BABEL_LICENSE, '[redacted]')
  }
  [pscustomobject]@{ExitCode=$process.ExitCode;TimedOut=(!$finished);Stdout=$outText;Stderr=$errText}
 } finally { $process.Dispose() }
}
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath($Output)
if ($Stage -eq 'Protect' -and !$env:BABEL_LICENSE) { throw 'Set BABEL_LICENSE in this process; license keys are never recorded.' }
$samples=@();$behaviors=@()
foreach($framework in @('net48','net8.0','net10.0')){foreach($profile in @('external','password')){
 if($Stage -eq 'Manifest' -and $profile -ne $ManifestProfile){continue}
 $id="$framework-$profile"; if ($id -notlike $Only) { continue }; $folder="$root/$id"; $ext=if($framework -eq 'net48'){'exe'}else{'dll'}
 if ($Stage -eq 'Protect') {
 if (Test-Path "$folder/protected") { throw "Capture exists: $folder" }
 New-Item -ItemType Directory -Force "$folder/oracle","$folder/protected"|Out-Null
 Get-ChildItem "$repo/corpus/probes/BabelCodeSources/bin/Release/$framework" -File | Where-Object Extension -in @('.exe','.dll','.json') | Copy-Item -Destination "$folder/oracle"
 $properties=if($profile -eq 'password'){'<Password>CILantro benign code-source password 73</Password><Internal>true</Internal>'}else{''}
 $rule='<Rules><Rule name="code source probe" feature="msil encryption" exclude="false"><Target>Methods</Target><Pattern>BabelCodeSources.Program::Encrypted*</Pattern><Properties><Source>probe-code</Source>'+$properties+'</Properties></Rule></Rules>'
 [IO.File]::WriteAllText("$folder/rules.xml",$rule)
 $options=@('--notypes','--nomethods','--nofields','--noproperties','--noevents','--nologo','--quiet','--strict-exit','--randomseed','1973','--use','tagassembly=on','--msilencryption','BabelCodeSources\.Program::Encrypted','--rules',"$folder/rules.xml")
 if($Combined){$options+=@('--stringencryption','xor','--resourceencryption','--proxy','all','--controlflow','switch=on')}
 $result=Run $babel (@("$folder/oracle/BabelCodeSources.$ext",'--output',"$folder/protected/BabelCodeSources.$ext",'--license',"floating:$env:BABEL_LICENSE")+$options)
 $result|ConvertTo-Json -Depth 5|Set-Content "$folder/protection.json"
 if ($result.ExitCode -ne 0 -or $result.TimedOut -or $result.Stdout -notmatch 'Number of encrypted methods: 1') { throw "Code-source capture failed or did not encrypt its method: $id" }
 [ordered]@{Id=$id;Framework=$framework;Profile=$profile;ExitCode=$result.ExitCode;Available=($result.ExitCode -eq 0);Options=$options;Files=@(Get-ChildItem "$folder/protected" -File|Select-Object Name,Length)}|ConvertTo-Json -Depth 5|Set-Content "$folder/fixture.json"
 Write-Host "$id exit=$($result.ExitCode)"
 }
 if ($Stage -eq 'Recover') {
  if(Test-Path "$folder/$RecoveryDirectory"){throw "Recovery exists: $folder/$RecoveryDirectory"}
  $arguments=@("$repo/src/Cilantro.Cli/bin/Release/net10.0/cilantro.dll","$folder/protected/BabelCodeSources.$ext",'-o',"$folder/$RecoveryDirectory",'--json')
  if($profile -eq 'external'){$arguments+=@('--babel-code-source',"$folder/protected/probe-code.eil")}
  $result=Run dotnet $arguments 180
  $result|ConvertTo-Json -Depth 5|Set-Content "$folder/$RecoveryDirectory-recovery.json"
  if($result.ExitCode -ne 0 -or $result.TimedOut){throw "Recovery failed: $id"}
  $report=Get-Content "$folder/$RecoveryDirectory/BabelCodeSources.analysis.json" -Raw|ConvertFrom-Json
  if($report.Recovery.RestoredMethodBodies -ne 1 -or $report.Recovery.RemainingMethodStubs -ne 0){throw "Method-code recovery remains incomplete: $id"}
 }
 if ($Stage -eq 'Verify') {
  $runs=@()
  foreach($kind in @('oracle','protected','cleaned')){
   $dir=if($kind -eq 'cleaned'){"$folder/$RecoveryDirectory"}else{"$folder/$kind"}
   if($kind -ne 'oracle'){Get-ChildItem "$folder/oracle" -Filter '*.json'|Copy-Item -Destination $dir}
   $path="$dir/BabelCodeSources$(if($kind -eq 'cleaned'){'.cleaned'}).$ext"
   $runs+=if($ext -eq 'exe'){Run $path @() 30}else{Run dotnet @('exec','--runtimeconfig',"$dir/BabelCodeSources.runtimeconfig.json",$path) 30}
  }
  $match=@($runs|Where-Object {$_.ExitCode -ne 0 -or $_.TimedOut}).Count -eq 0 -and $runs[0].Stdout -ceq $runs[1].Stdout -and $runs[0].Stdout -ceq $runs[2].Stdout
  $behaviors+=[ordered]@{Id=$id;Match=$match;Runs=$runs}
 }
 if ($Stage -eq 'Manifest') {
  $package="babel-12-$ManifestProfile$(if($Combined){'-combined'})";$name="BabelCodeSources.$ext"
  foreach($kind in @('oracle','protected')){$dest="$PackageRoot/$package/$id/$kind";New-Item -ItemType Directory -Force $dest|Out-Null;Copy-Item "$folder/$kind/$name" $dest}
  $oracle=(Get-FileHash "$folder/oracle/$name" -Algorithm SHA256).Hash.ToLowerInvariant()
  $samples+=[ordered]@{id="$framework-oracle";tier='oracle';sha256=$oracle;localName="$package/$id/oracle/$name";expectedDetection='none';expectedCapabilities=@()}
  $report=Get-Content "$folder/$RecoveryDirectory/BabelCodeSources.analysis.json" -Raw|ConvertFrom-Json
  if($report.Recovery.RestoredMethodBodies -ne 1 -or $report.Recovery.RemainingMethodStubs -ne 0){throw "Cannot baseline incomplete recovery: $id"}
  $sample=[ordered]@{id=$id;tier='profiled';sha256=(Get-FileHash "$folder/protected/$name" -Algorithm SHA256).Hash.ToLowerInvariant();localName="$package/$id/protected/$name";expectedDetection='babel';expectedCapabilities=@();oracleSha256=$oracle;expectedRestoredBodyCount=1;maximumRemainingStubs=0;maximumRemainingSwitchDispatchers=0;maximumUnreachableInstructions=0;maximumSurplusResources=0;requireOracleResourceParity=$true;expectedRetiredResourceNames=@($report.DecodedResources|ForEach-Object SourceResource)}
  if($profile -eq 'external'){
   Copy-Item "$folder/protected/probe-code.eil" "$PackageRoot/$package/$id/protected/probe-code.eil"
   $sample.babelCodeSources=@([ordered]@{localName="$package/$id/protected/probe-code.eil";sha256=(Get-FileHash "$folder/protected/probe-code.eil" -Algorithm SHA256).Hash.ToLowerInvariant()})
  }
  $samples+=$sample
 }
}}
if($Stage -eq 'Manifest'){
 if(!$samples.Count){throw 'No selected captures for this manifest profile.'}
 $description=if($ManifestProfile -eq 'external'){'Three licensed Babel 12.1 external method-code captures with source-built oracles and hash-pinned .eil companions. Explicit data-only snapshots feed bounded interpretation; restored bodies, zero encrypted stubs, resource parity and runtime behavior are verified.'}else{'Three licensed Babel 12.1 password-protected internal method-code captures with source-built oracles. PBKDF2-HMAC-SHA1, AES method-image recovery, exception/finally behavior and zero remaining encrypted method stubs. External code sources have a separate corpus.'}
 [ordered]@{manifestVersion=1;profile="babel-12-$ManifestProfile$(if($Combined){'-combined'})";description=$description;samples=$samples}|ConvertTo-Json -Depth 10|Set-Content "$root/$ManifestProfile-manifest.json"
}
if($Stage -eq 'Verify'){$behaviors|ConvertTo-Json -Depth 8|Set-Content "$root/$RecoveryDirectory-behavior.json";if(@($behaviors|Where-Object {!$_.Match}).Count){throw 'Code-source behavior mismatch'}}
