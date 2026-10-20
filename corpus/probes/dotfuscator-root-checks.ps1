param(
 [string]$Dotfuscator = 'C:/Program Files (x86)/PreEmptive Protection Dotfuscator Professional 7.9.0/dotfuscator.exe',
 [string]$Output = 'C:/cilantro-verify/dotfuscator/root-corpus',
 [string]$PackageRoot = 'C:/cilantro-verify/packages',
 [ValidateSet('Protect','Manifest','Recover','Verify')][string]$Stage = 'Protect',
 [string]$Only = '*',
 [ValidatePattern('^[A-Za-z0-9_-]+$')][string]$RecoveryDirectory = 'cleaned'
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$Output = [IO.Path]::GetFullPath($Output)
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant() }
function Run([string]$Executable, [string[]]$Arguments, [int]$Seconds = 120) {
 $info = [Diagnostics.ProcessStartInfo]::new($Executable)
 $info.UseShellExecute=$false; $info.CreateNoWindow=$true; $info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
 foreach($argument in $Arguments) { $info.ArgumentList.Add($argument) }
 $process=[Diagnostics.Process]::new(); $process.StartInfo=$info
 try {
  [void]$process.Start(); $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
  $finished=$process.WaitForExit($Seconds*1000)
  if(!$finished) { $process.Kill($true); $process.WaitForExit() }
  [pscustomobject]@{ExitCode=$process.ExitCode;TimedOut=(!$finished);Stdout=$stdout.GetAwaiter().GetResult();Stderr=$stderr.GetAwaiter().GetResult()}
 } finally { $process.Dispose() }
}
$profiles=[ordered]@{
 'root-none'=@('None','None','off','off',0)
 'root-method'=@('Exception','Method','off','off',0)
 'root-exit'=@('Exit','Method','off','off',0)
 'root-hang'=@('Hang','Method','off','off',0)
 'root-flow'=@('Exception','Method','on','high',1)
 'root-native'=@('Exception','Method','on','high',2)
}
$samples=@(); $behavior=@()
foreach($profile in $profiles.GetEnumerator()) {
 $id='net10.0-'+$profile.Key; if($id -notlike $Only) { continue }
 $settings=$profile.Value; $folder="$Output/$id"; $name='RootCheckProbe.dll'
 if($Stage -eq 'Protect') {
  if(Test-Path "$folder/protected/$name") { throw "Capture exists: $id" }
  New-Item -ItemType Directory -Force "$folder/oracle","$folder/protected" | Out-Null
  Get-ChildItem "$repo/corpus/probes/DotfuscatorRootChecks/bin/Release/net10.0" -File | Where-Object Extension -in @('.dll','.json') | Copy-Item -Destination "$folder/oracle"
  $encrypt=if($settings[4] -eq 0){'off'}else{'on'}
  $config=[IO.Path]::GetFullPath("$folder/config.xml")
  $generated=Run $Dotfuscator @('/nologo',"/in:-$([IO.Path]::GetFullPath("$folder/oracle/$name"))","/out:$([IO.Path]::GetFullPath("$folder/protected"))","/rename:$($settings[2])","/controlflow:$($settings[3])",'/prune:off',"/encrypt:$encrypt","/genconfig:$config")
  $generated | ConvertTo-Json | Set-Content "$folder/config-generation.json"
  if($generated.ExitCode -ne 0 -or $generated.TimedOut -or !(Test-Path $config)) { throw "Configuration generation failed: $id" }
  $referenceFramework='net10.0-android36.0'
  $paths=@("$PackageRoot/microsoft.android.ref.34/34.0.154/ref/net8.0") + @('microsoft.maui.controls.core','microsoft.maui.core','microsoft.maui.essentials' | ForEach-Object {"$PackageRoot/$_/10.0.100/lib/$referenceFramework"})
  foreach($path in $paths) { if(!(Test-Path $path)) { throw "Restore required Microsoft reference package: $path" } }
  $loadpaths=($paths | ForEach-Object {'<file dir="'+[Security.SecurityElement]::Escape([IO.Path]::GetFullPath($_))+'" />'}) -join ''
  $attributes='<extattributes><extattribute name="PreEmptive.Attributes.RootCheckAttribute"><type name="RootCheckProbe.Program"><method name="Guarded" signature="int32(int32)" /></type><propertylist><property name="Action" value="'+$settings[0]+'" /><property name="ApplicationNotificationSinkElement" value="'+$settings[1]+'" /><property name="ApplicationNotificationSinkOwner" value="RootCheckProbe.Program" /><property name="ApplicationNotificationSinkName" value="OnCheck" /></propertylist></extattribute></extattributes>'
  $xml=[IO.File]::ReadAllText($config).Replace('<loadpaths>','<loadpaths>'+$loadpaths).Replace('<smartobfuscation>',$attributes+'<smartobfuscation>')
  if($settings[4] -gt 0) { $xml=$xml.Replace('<stringencrypt />','<stringencrypt version="'+$settings[4]+'"><includelist><type name=".*" regex="true" /></includelist></stringencrypt>') }
  [IO.File]::WriteAllText($config,$xml)
  $result=Run $Dotfuscator @('/nologo',$config)
  $result | ConvertTo-Json | Set-Content "$folder/protection.json"
  if($result.ExitCode -ne 0 -or $result.TimedOut -or !(Test-Path "$folder/protected/$name") -or $result.Stdout -notmatch 'RootCheck:') { throw "Root Check injection failed: $id" }
  [ordered]@{Id=$id;CompilerVersion=(Get-Item $Dotfuscator).VersionInfo.FileVersion;CompilerSha256=(Hash $Dotfuscator);Settings=$settings;ReferencePaths=$paths;OracleSha256=(Hash "$folder/oracle/$name");ProtectedSha256=(Hash "$folder/protected/$name")} | ConvertTo-Json -Depth 4 | Set-Content "$folder/fixture.json"
 }
 $record=Get-Content "$folder/fixture.json" -Raw | ConvertFrom-Json
 if((Hash "$folder/oracle/$name") -cne $record.OracleSha256 -or (Hash "$folder/protected/$name") -cne $record.ProtectedSha256) { throw "Capture changed: $id" }
 if($Stage -eq 'Manifest') {
  foreach($kind in @('oracle','protected')) { $destination="$Output/samples/dotfuscator-7-root-checks/$id/$kind"; New-Item -ItemType Directory -Force $destination | Out-Null; Copy-Item "$folder/$kind/*" $destination -Recurse }
  if(!@($samples | Where-Object tier -eq oracle).Count) { $samples += [ordered]@{id='net10.0-oracle';tier='oracle';sha256=$record.OracleSha256;localName="dotfuscator-7-root-checks/$id/oracle/$name";expectedDetection='none';expectedCapabilities=@()} }
  $sample=[ordered]@{id=$id;tier='profiled';sha256=$record.ProtectedSha256;localName="dotfuscator-7-root-checks/$id/protected/$name";expectedDetection='dotfuscator';expectedCapabilities=@();oracleSha256=$record.OracleSha256;minimumNeutralizedCheckSites=1}
  if($settings[4] -gt 0) { $sample.minimumRecoveredStringSites=1 }
  $samples += $sample
 }
 if($Stage -eq 'Recover') {
  if(Test-Path "$folder/$RecoveryDirectory") { throw "Recovery exists: $id/$RecoveryDirectory" }
  $result=Run 'dotnet' @("$repo/src/Cilantro.Cli/bin/Release/net10.0/cilantro.dll","$folder/protected/$name",'-o',"$folder/$RecoveryDirectory",'--json') 180
  $result | ConvertTo-Json | Set-Content "$folder/$RecoveryDirectory-recovery.json"
 }
 if($Stage -eq 'Verify') {
  # These are desktop clean-verdict trials of repository-built CIL. The injected
  # Android checker is never executed; rooted/non-rooted device trials are separate.
  $oracleArgs=@('exec','--runtimeconfig',"$folder/oracle/RootCheckProbe.runtimeconfig.json","$folder/oracle/$name")
  if($settings[1] -eq 'Method') { $oracleArgs += '--clean-oracle' }
  $oracle=Run 'dotnet' $oracleArgs 30
  $cleaned=Run 'dotnet' @('exec','--runtimeconfig',"$folder/oracle/RootCheckProbe.runtimeconfig.json","$folder/$RecoveryDirectory/RootCheckProbe.cleaned.dll") 30
  $match=!$oracle.TimedOut -and !$cleaned.TimedOut -and $oracle.ExitCode -eq 0 -and $cleaned.ExitCode -eq 0 -and $oracle.Stdout -ceq $cleaned.Stdout
  $row=[ordered]@{Id=$id;Match=$match;Scope='Desktop source/cleaned clean-verdict comparison; no Android checker or device execution';Oracle=$oracle;Cleaned=$cleaned}
  $row | ConvertTo-Json -Depth 5 | Set-Content "$folder/behavior.json"; $behavior += $row
 }
 Write-Host "$Stage $id complete"
}
if($Stage -eq 'Manifest') { [ordered]@{manifestVersion=1;profile='dotfuscator-7-root-checks';description='Licensed Android-referenced .NET 10 Root Check captures. Static family review and desktop clean-verdict behavior only; no Android device execution.';samples=$samples} | ConvertTo-Json -Depth 8 | Set-Content "$Output/manifest.json" }
if($behavior.Count) { $behavior | ConvertTo-Json -Depth 6 | Set-Content "$Output/behavior.json"; if(@($behavior | Where-Object {!$_.Match}).Count) { throw 'Clean-verdict comparisons failed' } }
