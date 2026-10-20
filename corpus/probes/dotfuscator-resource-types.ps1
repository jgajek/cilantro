param(
 [string]$Dotfuscator = 'C:/Program Files (x86)/PreEmptive Protection Dotfuscator Professional 7.9.0/dotfuscator.exe',
 [string]$Output = 'C:/cilantro-verify/dotfuscator/resource-types-corpus',
 [string]$RecoveryDirectory = 'cleaned',
 [ValidateSet('Protect','Manifest','Recover','Verify','All')][string]$Stage = 'All'
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
$samples = @()
$comparisons = @()
foreach ($framework in @('net48','net8.0','net10.0')) {
 $extension = if ($framework -eq 'net48') { 'exe' } else { 'dll' }
 $name = "ResourceTypesProbe.$extension"
 $folder = Join-Path $Output $framework
 if ($Stage -in @('Protect','All')) {
  if (Test-Path "$folder/protected/$name") { throw "Capture exists: $folder. Choose a fresh output directory." }
  New-Item -ItemType Directory -Force "$folder/oracle","$folder/protected" | Out-Null
  $built = Join-Path $repo "corpus/probes/DotfuscatorResourceTypes/bin/Release/$framework"
  if (!(Test-Path "$built/$name")) { throw 'Build corpus/probes/DotfuscatorResourceTypes first.' }
  Get-ChildItem $built -File | Where-Object Extension -in @('.exe','.dll','.json') | Copy-Item -Destination "$folder/oracle"
  $inputFile = [IO.Path]::GetFullPath("$folder/oracle/$name")
  $configFile = [IO.Path]::GetFullPath("$folder/config.xml")
  $generated = Run $Dotfuscator @('/nologo',"/in:-$inputFile","/out:$([IO.Path]::GetFullPath("$folder/protected"))",'/rename:off','/controlflow:off','/prune:off','/encrypt:off',"/genconfig:$configFile") 120
  $generated | ConvertTo-Json | Set-Content "$folder/config-generation.json"
  if ($generated.ExitCode -ne 0 -or $generated.TimedOut -or !(Test-Path $configFile)) { throw "Configuration generation failed: $framework" }
  $xml = [IO.File]::ReadAllText($configFile)
  $xml = $xml.Replace('<sos', '<resourceencrypt><includelist><type name="ResourceTypesProbe.Secrets" /></includelist></resourceencrypt><sos')
  [IO.File]::WriteAllText($configFile, $xml)
  $protected = Run $Dotfuscator @('/nologo',$configFile) 120
  $protected | ConvertTo-Json | Set-Content "$folder/protection.json"
  if ($protected.ExitCode -ne 0 -or $protected.TimedOut -or !(Test-Path "$folder/protected/$name")) { throw "Protection failed: $framework" }
  [ordered]@{ Framework=$framework; DotfuscatorVersion=(Get-Item $Dotfuscator).VersionInfo.FileVersion; DotfuscatorSha256=(Hash $Dotfuscator); ConfigSha256=(Hash $configFile); OracleSha256=(Hash $inputFile); ProtectedSha256=(Hash "$folder/protected/$name") } |
   ConvertTo-Json | Set-Content "$folder/fixture.json"
 }
 $record = Get-Content "$folder/fixture.json" -Raw | ConvertFrom-Json
 if ((Hash "$folder/oracle/$name") -cne $record.OracleSha256 -or (Hash "$folder/protected/$name") -cne $record.ProtectedSha256) { throw "Captured identity changed: $framework" }
 if ($Stage -in @('Protect','Manifest','All')) {
  foreach ($kind in @('oracle','protected')) {
   $destination = "$Output/samples/dotfuscator-resource-types/$framework/$kind"
   New-Item -ItemType Directory -Force $destination | Out-Null
   Copy-Item "$folder/$kind/$name" $destination
  }
  $samples += [ordered]@{id="$framework-resource-oracle";tier='oracle';sha256=$record.OracleSha256;localName="dotfuscator-resource-types/$framework/oracle/$name";expectedDetection='none';expectedCapabilities=@()}
  $samples += [ordered]@{id="$framework-resources";tier='detected';sha256=$record.ProtectedSha256;localName="dotfuscator-resource-types/$framework/protected/$name";expectedDetection='dotfuscator';expectedCapabilities=@();oracleSha256=$record.OracleSha256;requireOracleResourceParity=$false;minimumResourcesRestored=1;maximumRemainingSwitchDispatchers=0;maximumUnreachableInstructions=0}
 }
 if ($Stage -in @('Recover','All')) {
  if (Test-Path "$folder/$RecoveryDirectory") { throw "Recovery output exists: $folder/$RecoveryDirectory" }
  $recovery = Run 'dotnet' @($cli,"$folder/protected/$name",'-o',"$folder/$RecoveryDirectory",'--json') 120
  $recovery | ConvertTo-Json | Set-Content "$folder/recovery.json"
  if ($recovery.ExitCode -ne 0 -or $recovery.TimedOut) { throw "Recovery failed: $framework" }
 }
 if ($Stage -in @('Verify','All')) {
  # Only execute the benign program built from DotfuscatorResourceTypes in this repository.
  $runs = @()
  foreach ($kind in @('oracle','protected',$RecoveryDirectory)) {
   if ($kind -ne 'oracle') { Get-ChildItem "$folder/oracle" -Filter '*.json' | Copy-Item -Destination "$folder/$kind" }
   $target = "$folder/$kind/ResourceTypesProbe$(if($kind -eq $RecoveryDirectory){'.cleaned'}).$extension"
   $runs += if ($framework -eq 'net48') { Run $target @() } else { Run 'dotnet' @('exec','--runtimeconfig',"$folder/$kind/ResourceTypesProbe.runtimeconfig.json",$target) }
  }
  $match = @($runs | Where-Object { $_.TimedOut -or $_.ExitCode -ne 0 }).Count -eq 0 -and $runs[1].Stdout -ceq $runs[2].Stdout
  $producerChangedTypes = $runs[0].Stdout -cne $runs[1].Stdout
  foreach ($key in @('Integer','Boolean','Decimal','Double','Character','Long')) {
   if ($runs[1].Stdout -cnotmatch "(?m)^${key}:System.Byte\[\]:") { throw "Expected recorded producer type conversion for $key ($framework)" }
  }
  [ordered]@{Framework=$framework;Match=$match;ProducerChangedPrimitiveTypes=$producerChangedTypes;Runs=$runs} | ConvertTo-Json -Depth 5 | Set-Content "$folder/behavior.json"
  if (!$match -or !$producerChangedTypes) { throw "Protected/cleaned behavior or recorded producer conversion differs: $framework" }
  $comparisons += [ordered]@{Framework=$framework;Match=$match;ProducerChangedPrimitiveTypes=$producerChangedTypes}
 }
}
if ($Stage -in @('Protect','Manifest','All')) {
 [ordered]@{manifestVersion=1;profile='dotfuscator-7-resource-types';description='Source-built Dotfuscator 7.9 resource-encryption probes across net48/net8.0/net10.0; mixed primitive resource entries, strings and binary values.';samples=$samples} |
  ConvertTo-Json -Depth 8 | Set-Content "$Output/manifest.json"
}
if ($comparisons.Count) { $comparisons | ConvertTo-Json | Set-Content "$Output/behavior.json" }
