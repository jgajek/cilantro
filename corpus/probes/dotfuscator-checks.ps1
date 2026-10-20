param(
 [string]$Dotfuscator = 'C:/Program Files (x86)/PreEmptive Protection Dotfuscator Professional 7.9.0/dotfuscator.exe',
 [string]$Output = 'C:/cilantro-verify/dotfuscator/check-corpus',
 [ValidateSet('Protect','Manifest','Recover','Verify','All')][string]$Stage = 'All',
 [string]$Only = '',
 [ValidatePattern('^[A-Za-z0-9_-]+$')][string]$RecoveryDirectory = 'cleaned',
 [ValidateSet('Basic','Mixed','All')][string]$Matrix = 'Basic'
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$Output = [IO.Path]::GetFullPath($Output)
$cli = Join-Path $repo 'src/Cilantro.Cli/bin/Release/net10.0/cilantro.dll'
New-Item -ItemType Directory -Force $Output | Out-Null
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Run([string]$Executable, [string[]]$Arguments, [int]$Seconds = 30) {
 $info = [Diagnostics.ProcessStartInfo]::new($Executable)
 $info.UseShellExecute = $false
 $info.CreateNoWindow = $true
 $info.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
 $info.RedirectStandardOutput = $true
 $info.RedirectStandardError = $true
 foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
 $process = [Diagnostics.Process]::new()
 $process.StartInfo = $info
 try {
  [void]$process.Start()
  $stdout = $process.StandardOutput.ReadToEndAsync()
  $stderr = $process.StandardError.ReadToEndAsync()
  $finished = $process.WaitForExit($Seconds * 1000)
  if (!$finished) { $process.Kill($true); $process.WaitForExit() }
  [pscustomobject]@{ ExitCode=$process.ExitCode; TimedOut=(!$finished); Stdout=$stdout.GetAwaiter().GetResult(); Stderr=$stderr.GetAwaiter().GetResult() }
 } finally { $process.Dispose() }
}
$configs = [ordered]@{
 'debug-method' = @('DebuggingCheckAttribute','Method','OnCheck','Exception','1')
 'tamper-method' = @('TamperCheckAttribute','Method','OnCheck','Exception','1')
 'combined-method' = @('DebuggingCheckAttribute,TamperCheckAttribute','Method','OnCheck','Exception','1')
 'debug-field' = @('DebuggingCheckAttribute','Field','detected','Exception','1')
 'debug-property' = @('DebuggingCheckAttribute','Property','Detection','Exception','1')
 'debug-delegate' = @('DebuggingCheckAttribute','Delegate','Callback','Exception','1')
 'debug-none' = @('DebuggingCheckAttribute','None','','Exception','1')
 'debug-exit' = @('DebuggingCheckAttribute','None','','Exit','1')
 'debug-hang' = @('DebuggingCheckAttribute','None','','Hang','1')
 'debug-probability' = @('DebuggingCheckAttribute','Method','OnCheck','Exception','0.5')
 'combined-flow' = @('DebuggingCheckAttribute,TamperCheckAttribute','Method','OnCheck','Exception','1','off','high','0')
 'combined-renamed' = @('DebuggingCheckAttribute,TamperCheckAttribute','Method','OnCheck','Exception','1','on','high','1')
 'combined-native' = @('DebuggingCheckAttribute,TamperCheckAttribute','Method','OnCheck','Exception','1','on','high','2')
}
$samples = @()
$comparisons = @()
foreach ($framework in @('net48','net8.0','net10.0')) {
 $extension = if ($framework -eq 'net48') { 'exe' } else { 'dll' }
 $name = "CheckProbe.$extension"
 foreach ($config in $configs.Keys) {
  $id = "$framework-$config"
  if ($Only -and $Only.Split(',') -notcontains $id) { continue }
  $settings = $configs[$config]
  if (($Matrix -eq 'Basic' -and $settings.Count -gt 5) -or ($Matrix -eq 'Mixed' -and $settings.Count -le 5)) { continue }
  $folder = Join-Path $Output $id
  if ($Stage -in @('Protect','All')) {
   if (Test-Path "$folder/protected/$name") { throw "Capture exists: $folder. Choose a fresh output directory." }
   New-Item -ItemType Directory -Force "$folder/oracle","$folder/protected" | Out-Null
   $built = Join-Path $repo "corpus/probes/DotfuscatorChecks/bin/Release/$framework"
   if (!(Test-Path "$built/$name")) { throw 'Build corpus/probes/DotfuscatorChecks first.' }
   Get-ChildItem $built -File | Where-Object Extension -in @('.exe','.dll','.json') | Copy-Item -Destination "$folder/oracle"
   $inputFile = [IO.Path]::GetFullPath("$folder/oracle/$name")
   $configFile = [IO.Path]::GetFullPath("$folder/config.xml")
   $rename = if ($settings.Count -gt 5) { $settings[5] } else { 'off' }
   $flow = if ($settings.Count -gt 5) { $settings[6] } else { 'off' }
   $encryptionVersion = if ($settings.Count -gt 5) { [int]$settings[7] } else { 0 }
   $encrypt = if ($encryptionVersion -gt 0) { 'on' } else { 'off' }
   $generated = Run $Dotfuscator @('/nologo',"/in:-$inputFile","/out:$([IO.Path]::GetFullPath("$folder/protected"))","/rename:$rename","/controlflow:$flow",'/prune:off',"/encrypt:$encrypt","/genconfig:$configFile") 120
   $generated | ConvertTo-Json | Set-Content "$folder/config-generation.json"
   if ($generated.ExitCode -ne 0 -or $generated.TimedOut -or !(Test-Path $configFile)) { throw "Configuration generation failed: $id" }
   $attributes = @($settings[0].Split(',') | ForEach-Object {
    '<extattribute name="PreEmptive.Attributes.'+$_+'"><type name="CheckProbe.Program"><method name="Guarded" signature="int32(int32)" /></type><propertylist>'+
     '<property name="Action" value="'+$settings[3]+'" /><property name="ActionProbability" value="'+$settings[4]+'" />'+
     '<property name="ApplicationNotificationSinkElement" value="'+$settings[1]+'" /><property name="ApplicationNotificationSinkOwner" value="CheckProbe.Program" />'+
     '<property name="ApplicationNotificationSinkName" value="'+$settings[2]+'" /></propertylist></extattribute>'
   }) -join ''
   $xml = [IO.File]::ReadAllText($configFile).Replace('<smartobfuscation>', '<extattributes>'+$attributes+'</extattributes><smartobfuscation>')
   if ($encryptionVersion -gt 0) { $xml = $xml.Replace('<stringencrypt />', '<stringencrypt version="'+$encryptionVersion+'"><includelist><type name=".*" regex="true" /></includelist></stringencrypt>') }
   [IO.File]::WriteAllText($configFile, $xml)
   $protected = Run $Dotfuscator @('/nologo',$configFile) 120
   $protected | ConvertTo-Json | Set-Content "$folder/protection.json"
   if ($protected.ExitCode -ne 0 -or $protected.TimedOut -or !(Test-Path "$folder/protected/$name")) { throw "Protection failed: $id" }
   [ordered]@{ Framework=$framework; Config=$config; DotfuscatorVersion=(Get-Item $Dotfuscator).VersionInfo.FileVersion; DotfuscatorSha256=(Hash $Dotfuscator); ConfigSha256=(Hash $configFile); OracleSha256=(Hash $inputFile); ProtectedSha256=(Hash "$folder/protected/$name") } |
    ConvertTo-Json | Set-Content "$folder/fixture.json"
   Write-Output "Protected $id"
  }
  $record = Get-Content "$folder/fixture.json" -Raw | ConvertFrom-Json
  if ((Hash "$folder/oracle/$name") -cne $record.OracleSha256 -or (Hash "$folder/protected/$name") -cne $record.ProtectedSha256) { throw "Captured identity changed: $id" }
  if ($Stage -in @('Protect','Manifest','All')) {
   $destination = "$Output/samples/dotfuscator-checks/$id"
   New-Item -ItemType Directory -Force $destination | Out-Null
   Copy-Item "$folder/protected/$name" $destination
   Get-ChildItem "$folder/protected" -Filter 'environment????????.bin' -File | Copy-Item -Destination $destination
   if (Test-Path "$folder/protected/runtimes/win-x64/native/Runtime.Extensions.dll") {
    New-Item -ItemType Directory -Force "$destination/runtimes/win-x64/native" | Out-Null
    Copy-Item "$folder/protected/runtimes/win-x64/native/Runtime.Extensions.dll" "$destination/runtimes/win-x64/native"
   }
   if (!($samples | Where-Object tier -eq 'oracle' | Where-Object sha256 -eq $record.OracleSha256)) {
    $oracleDirectory = "$Output/samples/dotfuscator-checks/$framework-oracle"
    New-Item -ItemType Directory -Force $oracleDirectory | Out-Null
    Copy-Item "$folder/oracle/$name" $oracleDirectory
    $samples += [ordered]@{id="$framework-check-oracle";tier='oracle';sha256=$record.OracleSha256;localName="dotfuscator-checks/$framework-oracle/$name";expectedDetection='none';expectedCapabilities=@()}
   }
   $sample = [ordered]@{id=$id;tier='detected';sha256=$record.ProtectedSha256;localName="dotfuscator-checks/$id/$name";expectedDetection='dotfuscator';expectedCapabilities=@();oracleSha256=$record.OracleSha256;requireOracleResourceParity=$true;minimumNeutralizedCheckSites=$settings[0].Split(',').Count;maximumRemainingSwitchDispatchers=0;maximumUnreachableInstructions=0}
   if ($settings.Count -gt 5 -and [int]$settings[7] -gt 0) { $sample.minimumRecoveredStringSites = 4 }
   $samples += $sample
  }
  if ($Stage -in @('Recover','All')) {
   if (Test-Path "$folder/$RecoveryDirectory") { throw "Recovery output exists: $folder/$RecoveryDirectory" }
   $recovery = Run 'dotnet' @($cli,"$folder/protected/$name",'-o',"$folder/$RecoveryDirectory",'--json') 120
   $recovery | ConvertTo-Json | Set-Content "$folder/recovery.json"
   if ($recovery.ExitCode -ne 0 -or $recovery.TimedOut) { throw "Recovery failed: $id" }
  }
  if ($Stage -in @('Verify','All')) {
   # Execute only the benign CheckProbe built from the sources in this repository.
   foreach ($notificationMode in @($false,$true)) {
    $runs = @()
    foreach ($kind in @('oracle','protected','cleaned')) {
     $runFolder = if ($kind -eq 'cleaned') { "$folder/$RecoveryDirectory" } else { "$folder/$kind" }
     if ($kind -ne 'oracle') { Get-ChildItem "$folder/oracle" -Filter '*.json' | Copy-Item -Destination $runFolder }
     $target = "$runFolder/CheckProbe$(if($kind -eq 'cleaned'){'.cleaned'}).$extension"
     $modeArguments = if ($notificationMode) { @('--notifications') } else { @() }
     $runs += if ($framework -eq 'net48') { Run $target $modeArguments } else { Run 'dotnet' (@('exec','--runtimeconfig',"$runFolder/CheckProbe.runtimeconfig.json",$target)+$modeArguments) }
    }
    $match = @($runs | Where-Object { $_.TimedOut -or $_.ExitCode -ne 0 }).Count -eq 0 -and $runs[1].Stdout -ceq $runs[2].Stdout
    if (!$notificationMode) { $match = $match -and $runs[0].Stdout -ceq $runs[1].Stdout }
    else {
     $expectedNotifications = if ($settings[1] -in @('Method','Property','Delegate')) { 2*$settings[0].Split(',').Count } else { 0 }
     $match = $match -and $runs[1].Stdout.Contains("Notifications:$expectedNotifications") -and $runs[0].Stdout.Contains('Notifications:0')
    }
    $suffix = if ($notificationMode) { 'notifications' } else { 'default' }
    [ordered]@{Id=$id;Mode=$suffix;Match=$match;Runs=$runs} | ConvertTo-Json -Depth 5 | Set-Content "$folder/behavior-$suffix.json"
    if (!$match) { throw "Behavior differs: $id/$suffix" }
    $comparisons += [ordered]@{Id=$id;Mode=$suffix;Match=$match}
   }
  }
 }
}
if ($Stage -in @('Protect','Manifest','All')) {
 $profile = if ($Matrix -eq 'Mixed') { 'dotfuscator-7-check-interactions' } elseif ($Matrix -eq 'All') { 'dotfuscator-7-checks-all' } else { 'dotfuscator-7-checks' }
 [ordered]@{manifestVersion=1;profile=$profile;description='Source-built Dotfuscator 7.9 debugging/integrity check probes across net48/net8.0/net10.0. The Basic matrix covers notification sinks and responses; Mixed combines both checks with high control flow, renaming and managed v1/native v2 strings. Default execution matches the source oracle; notification-mode execution matches protected behavior, including injected callback effects.';samples=$samples} |
  ConvertTo-Json -Depth 8 | Set-Content "$Output/manifest.json"
}
if ($comparisons.Count) { $comparisons | ConvertTo-Json | Set-Content "$Output/behavior.json" }
