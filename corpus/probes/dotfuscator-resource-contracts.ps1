param(
 [string]$Dotfuscator = 'C:/Program Files (x86)/PreEmptive Protection Dotfuscator Professional 7.9.0/dotfuscator.exe',
 [string]$Output = 'C:/cilantro-verify/dotfuscator/resource-contracts',
 [ValidatePattern('^[A-Za-z0-9_-]+$')][string]$RecoveryDirectory = 'cleaned',
 [string]$Only = '',
 [ValidateSet('Protect','Manifest','Recover','Verify','All')][string]$Stage = 'All'
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$Output = [IO.Path]::GetFullPath($Output)
$cli = Join-Path $repo 'src/Cilantro.Cli/bin/Release/net10.0/cilantro.dll'
New-Item -ItemType Directory -Force $Output | Out-Null
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Companions([string]$Folder) {
 foreach ($kind in @('oracle','protected')) {
  foreach ($culture in @('fr','fr-CA')) {
   $relative = "$kind/$culture/ContractProbe.resources.dll"
   [ordered]@{path=$relative;sha256=(Hash "$Folder/$relative")}
  }
 }
}
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
 $name = "ContractProbe.$extension"
 foreach ($layout in @('contract','satellite-only')) {
 $id = "$framework-$layout"
 if ($Only -and $Only.Split(',') -notcontains $id) { continue }
 $folder = Join-Path $Output $id
 if ($Stage -in @('Protect','All')) {
  if (Test-Path "$folder/protected/$name") { throw "Capture exists: $folder. Choose a fresh output directory." }
  New-Item -ItemType Directory -Force "$folder/oracle","$folder/protected" | Out-Null
  $built = Join-Path $repo "corpus/probes/DotfuscatorResourceContracts/bin/$layout/Release/$framework"
  if (!(Test-Path "$built/$name")) { throw 'Build corpus/probes/DotfuscatorResourceContracts first.' }
  Copy-Item "$built/*" "$folder/oracle" -Recurse -Force
  $inputFile = [IO.Path]::GetFullPath("$folder/oracle/$name")
  $configFile = [IO.Path]::GetFullPath("$folder/config.xml")
  $generated = Run $Dotfuscator @('/nologo',"/in:-$inputFile","/out:$([IO.Path]::GetFullPath("$folder/protected"))",'/rename:off','/controlflow:off','/prune:off','/encrypt:off',"/genconfig:$configFile") 120
  $generated | ConvertTo-Json | Set-Content "$folder/config-generation.json"
  if ($generated.ExitCode -ne 0 -or $generated.TimedOut -or !(Test-Path $configFile)) { throw "Configuration generation failed: $framework" }
  $xml = [IO.File]::ReadAllText($configFile)
  $xml = $xml.Replace('<sos', '<resourceencrypt><includelist><type name="ContractProbe.Secrets" /></includelist></resourceencrypt><sos')
  [IO.File]::WriteAllText($configFile, $xml)
  $protected = Run $Dotfuscator @('/nologo',$configFile) 120
  $protected | ConvertTo-Json | Set-Content "$folder/protection.json"
  if ($protected.ExitCode -ne 0 -or $protected.TimedOut -or !(Test-Path "$folder/protected/$name")) { throw "Protection failed: $framework" }
  [ordered]@{ Framework=$framework; Layout=$layout; DotfuscatorVersion=(Get-Item $Dotfuscator).VersionInfo.FileVersion; DotfuscatorSha256=(Hash $Dotfuscator); ConfigSha256=(Hash $configFile); OracleSha256=(Hash $inputFile); ProtectedSha256=(Hash "$folder/protected/$name"); Companions=@(Companions $folder) } |
   ConvertTo-Json -Depth 6 | Set-Content "$folder/fixture.json"
 }
 $record = Get-Content "$folder/fixture.json" -Raw | ConvertFrom-Json
 if ((Hash "$folder/oracle/$name") -cne $record.OracleSha256 -or (Hash "$folder/protected/$name") -cne $record.ProtectedSha256) { throw "Captured identity changed: $framework" }
 if ($record.Companions.Count -ne 4) { throw "Missing captured satellite identities: $framework" }
 foreach ($companion in $record.Companions) {
  if ((Hash "$folder/$($companion.path)") -cne $companion.sha256) { throw "Captured satellite changed: $framework/$($companion.path)" }
 }
 if ($Stage -in @('Protect','Manifest','All')) {
  foreach ($kind in @('oracle','protected')) {
   $destination = "$Output/samples/dotfuscator-resource-contracts/$id/$kind"
   New-Item -ItemType Directory -Force $destination | Out-Null
   Copy-Item "$folder/$kind/*" $destination -Recurse -Force
  }
  $samples += [ordered]@{id="$id-oracle";tier='oracle';sha256=$record.OracleSha256;localName="dotfuscator-resource-contracts/$id/oracle/$name";expectedDetection='none';expectedCapabilities=@()}
  $samples += [ordered]@{id=$id;tier='detected';sha256=$record.ProtectedSha256;localName="dotfuscator-resource-contracts/$id/protected/$name";expectedDetection='dotfuscator';expectedCapabilities=@();oracleSha256=$record.OracleSha256;requireOracleResourceParity=$true;minimumResourcesRestored=$(if($layout -eq 'contract'){3}else{2});maximumRemainingSwitchDispatchers=0;maximumUnreachableInstructions=0}
 }
 if ($Stage -in @('Recover','All')) {
  if (Test-Path "$folder/$RecoveryDirectory") { throw "Recovery output exists: $folder/$RecoveryDirectory" }
  $recovery = Run 'dotnet' @($cli,"$folder/protected/$name",'-o',"$folder/$RecoveryDirectory",'--json') 120
  $recovery | ConvertTo-Json | Set-Content "$folder/recovery.json"
  if ($recovery.ExitCode -ne 0 -or $recovery.TimedOut) { throw "Recovery failed: $framework" }
 }
 if ($Stage -in @('Verify','All')) {
  # Only execute the benign program built from DotfuscatorResourceContracts in this repository.
  $runs = @()
  foreach ($kind in @('oracle','protected',$RecoveryDirectory)) {
   if ($kind -ne 'oracle') { Get-ChildItem "$folder/oracle" -Filter '*.json' | Copy-Item -Destination "$folder/$kind" }
   $target = "$folder/$kind/ContractProbe$(if($kind -eq $RecoveryDirectory){'.cleaned'}).$extension"
   $runs += if ($framework -eq 'net48') { Run $target @() } else { Run 'dotnet' @('exec','--runtimeconfig',"$folder/$kind/ContractProbe.runtimeconfig.json",$target) }
  }
  $match = @($runs | Where-Object { $_.TimedOut -or $_.ExitCode -ne 0 }).Count -eq 0 -and $runs[0].Stdout -ceq $runs[1].Stdout -and $runs[0].Stdout -ceq $runs[2].Stdout
  foreach ($prefix in @(":SATELLITE_$(if($layout -eq 'contract'){'neutral'}else{'fr'})",'fr:SATELLITE_fr','fr-CA:SATELLITE_fr-CA','fr-FR:SATELLITE_fr',"de-DE:SATELLITE_$(if($layout -eq 'contract'){'neutral'}else{'fr'})")) {
   if ($runs[0].Stdout -cnotmatch ('(?m)^' + [regex]::Escape($prefix) + ' protected resource:')) { throw "Missing expected culture selection: $framework/$prefix" }
  }
  [ordered]@{Id=$id;Framework=$framework;Layout=$layout;Match=$match;Runs=$runs} | ConvertTo-Json -Depth 5 | Set-Content "$folder/behavior.json"
  if (!$match) { throw "Oracle/protected/cleaned behavior differs: $framework" }
  $comparisons += [ordered]@{Id=$id;Framework=$framework;Layout=$layout;Match=$match}
 }
 }
}
if ($Stage -in @('Protect','Manifest','All')) {
 [ordered]@{manifestVersion=1;profile='dotfuscator-7-resource-contracts';description='Source-built Dotfuscator 7.9 resource-encryption probes across net48/net8.0/net10.0; version-2 owners with version-1 satellites, local/satellite-only resources, explicit neutral fallback, Unicode, binary values and cache reload.';samples=$samples} |
  ConvertTo-Json -Depth 8 | Set-Content "$Output/manifest.json"
}
if ($comparisons.Count) { $comparisons | ConvertTo-Json | Set-Content "$Output/behavior.json" }
