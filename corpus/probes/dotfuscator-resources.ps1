param(
 [string]$Dotfuscator = 'C:/Program Files (x86)/PreEmptive Protection Dotfuscator Professional 7.9.0/dotfuscator.exe',
 [string]$Output = 'C:/cilantro-verify/dotfuscator/resource-corpus-final',
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
 $name = "ResourceProbe.$extension"
 $folder = Join-Path $Output $framework
 if ($Stage -in @('Protect','All')) {
  if (Test-Path "$folder/protected/$name") { throw "Capture exists: $folder. Choose a fresh output directory." }
  New-Item -ItemType Directory -Force "$folder/oracle","$folder/protected" | Out-Null
  $built = Join-Path $repo "corpus/probes/DotfuscatorResources/bin/Release/$framework"
  if (!(Test-Path "$built/$name")) { throw 'Build corpus/probes/DotfuscatorResources first.' }
  Get-ChildItem $built -File | Where-Object Extension -in @('.exe','.dll','.json') | Copy-Item -Destination "$folder/oracle"
  $inputFile = [IO.Path]::GetFullPath("$folder/oracle/$name")
  $configFile = [IO.Path]::GetFullPath("$folder/config.xml")
  $generated = Run $Dotfuscator @('/nologo',"/in:-$inputFile","/out:$([IO.Path]::GetFullPath("$folder/protected"))",'/rename:off','/controlflow:off','/prune:off','/encrypt:off',"/genconfig:$configFile") 120
  $generated | ConvertTo-Json | Set-Content "$folder/config-generation.json"
  if ($generated.ExitCode -ne 0 -or $generated.TimedOut -or !(Test-Path $configFile)) { throw "Configuration generation failed: $framework" }
  $xml = [IO.File]::ReadAllText($configFile)
  $xml = $xml.Replace('<sos', '<resourceencrypt><includelist><type name="ResourceProbe.Secrets" /></includelist></resourceencrypt><sos')
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
   $destination = "$Output/samples/dotfuscator-resources/$framework/$kind"
   New-Item -ItemType Directory -Force $destination | Out-Null
   Copy-Item "$folder/$kind/$name" $destination
  }
  $samples += [ordered]@{id="$framework-resource-oracle";tier='oracle';sha256=$record.OracleSha256;localName="dotfuscator-resources/$framework/oracle/$name";expectedDetection='none';expectedCapabilities=@()}
  $samples += [ordered]@{id="$framework-resources";tier='detected';sha256=$record.ProtectedSha256;localName="dotfuscator-resources/$framework/protected/$name";expectedDetection='dotfuscator';expectedCapabilities=@();oracleSha256=$record.OracleSha256;requireOracleResourceParity=$true;maximumRemainingSwitchDispatchers=0;maximumUnreachableInstructions=0}
 }
 if ($Stage -in @('Recover','All')) {
  if (Test-Path "$folder/$RecoveryDirectory") { throw "Recovery output exists: $folder/$RecoveryDirectory" }
  $recovery = Run 'dotnet' @($cli,"$folder/protected/$name",'-o',"$folder/$RecoveryDirectory",'--json') 120
  $recovery | ConvertTo-Json | Set-Content "$folder/recovery.json"
  if ($recovery.ExitCode -ne 0 -or $recovery.TimedOut) { throw "Recovery failed: $framework" }
 }
 if ($Stage -in @('Verify','All')) {
  # Only execute the benign program built from DotfuscatorResources in this repository.
  $runs = @()
  foreach ($kind in @('oracle','protected',$RecoveryDirectory)) {
   if ($kind -ne 'oracle') { Get-ChildItem "$folder/oracle" -Filter '*.json' | Copy-Item -Destination "$folder/$kind" }
   $target = "$folder/$kind/ResourceProbe$(if($kind -eq $RecoveryDirectory){'.cleaned'}).$extension"
   $runs += if ($framework -eq 'net48') { Run $target @() } else { Run 'dotnet' @('exec','--runtimeconfig',"$folder/$kind/ResourceProbe.runtimeconfig.json",$target) }
  }
  $match = @($runs | Where-Object { $_.TimedOut -or $_.ExitCode -ne 0 }).Count -eq 0 -and $runs[0].Stdout -ceq $runs[1].Stdout -and $runs[0].Stdout -ceq $runs[2].Stdout
  [ordered]@{Framework=$framework;Match=$match;Runs=$runs} | ConvertTo-Json -Depth 5 | Set-Content "$folder/behavior.json"
  if (!$match) { throw "Oracle/protected/cleaned behavior differs: $framework" }
  $comparisons += [ordered]@{Framework=$framework;Match=$match}
 }
}
if ($Stage -in @('Protect','Manifest','All')) {
 [ordered]@{manifestVersion=1;profile='dotfuscator-7-resources';description='Source-built Dotfuscator 7.9 resource-encryption probes across net48/net8.0/net10.0; strongly typed resource properties, Unicode, empty strings, binary values, raw-resource parity and ResourceManager cache reload.';samples=$samples} |
  ConvertTo-Json -Depth 8 | Set-Content "$Output/manifest.json"
}
if ($comparisons.Count) { $comparisons | ConvertTo-Json | Set-Content "$Output/behavior.json" }
