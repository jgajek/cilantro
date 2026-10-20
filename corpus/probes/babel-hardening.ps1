param(
 [string]$Babel = "$env:LOCALAPPDATA/Programs/BabelDesktop/babel.exe",
 [string]$Output = 'C:/cilantro-verify/babel/feature-audit',
 [ValidateSet('Protect','Manifest','Recover','Verify','All')][string]$Stage = 'Protect',
 [string]$Only = '*',
 [string]$Exclude = '',
 [ValidatePattern('^[A-Za-z0-9_-]+$')][string]$RecoveryDirectory = 'cleaned'
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$Output = [IO.Path]::GetFullPath($Output)
$cli = Join-Path $repo 'src/Cilantro.Cli/bin/Release/net10.0/cilantro.dll'
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
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
$matrix = [ordered]@{
 'metadata' = @('--reflection','4','--ildasm')
 'metadata-combined' = @('--reflection','4','--ildasm','--stringencryption','xor','--resourceencryption','--controlflow','switch=on')
 'flow-all' = @('--controlflow','goto=on','--controlflow','if=on','--controlflow','switch=on','--controlflow','case=on','--controlflow','call=on','--controlflow','chain=on')
}
$outcomes = @()
$samples = @()
foreach ($framework in @('net48','net8.0','net10.0')) {
 foreach ($entry in $matrix.GetEnumerator()) {
  $id = "$framework-$($entry.Key)"
  if ($id -notlike $Only -or ($Exclude -and $id -like $Exclude)) { continue }
  $extension = if ($framework -eq 'net48') { 'exe' } else { 'dll' }
  $name = "BabelProbe.$extension"
  $folder = Join-Path $Output $id
  if ($Stage -in @('Protect','All')) {
   if (!$env:BABEL_LICENSE) { throw 'Set BABEL_LICENSE to the floating trial user key in this process. Keys are never recorded in fixtures.' }
   if (Test-Path "$folder/protected/$name") { throw "Capture exists: $folder. Choose a fresh output directory." }
   New-Item -ItemType Directory -Force "$folder/oracle","$folder/protected" | Out-Null
   $built = Join-Path $repo "corpus/probes/BabelProbe/bin/Release/$framework"
   Get-ChildItem $built -File | Where-Object Extension -in @('.exe','.dll','.json') | Copy-Item -Destination "$folder/oracle"
   $options = @('--notypes','--nomethods','--nofields','--noproperties','--noevents','--nologo','--quiet','--strict-exit','--randomseed','12345678','--use','tagassembly=on') + $entry.Value
   $protection = Run $Babel (@("$folder/oracle/$name",'--output',"$folder/protected/$name",'--license',"floating:$env:BABEL_LICENSE") + $options)
   $protection | ConvertTo-Json | Set-Content "$folder/protection.json"
   if ($protection.Stdout -match 'License component .+ not available') {
    [ordered]@{Id=$id;Available=$false;Options=$options;Reason='Protection component unavailable in the supplied license';BabelVersion=(Get-Item $Babel).VersionInfo.FileVersion} | ConvertTo-Json -Depth 5 | Set-Content "$folder/unavailable.json"
    Write-Host "Unavailable under trial license: $id"
    continue
   }
   if ($protection.ExitCode -ne 0 -or $protection.TimedOut -or !(Test-Path "$folder/protected/$name")) { throw "Babel protection failed: $id. See protection.json." }
   [ordered]@{Id=$id;Framework=$framework;Options=$options;BabelVersion=(Get-Item $Babel).VersionInfo.FileVersion;BabelSha256=(Hash $Babel);OracleSha256=(Hash "$folder/oracle/$name");ProtectedSha256=(Hash "$folder/protected/$name")} | ConvertTo-Json -Depth 5 | Set-Content "$folder/fixture.json"
  }
  if (Test-Path "$folder/unavailable.json") { continue }
  $record = Get-Content "$folder/fixture.json" -Raw | ConvertFrom-Json
  if ((Hash "$folder/oracle/$name") -cne $record.OracleSha256 -or (Hash "$folder/protected/$name") -cne $record.ProtectedSha256) { throw "Capture identity changed: $id" }
  if ($Stage -eq 'Manifest') {
   $package = 'babel-12-hardening'
   foreach ($kind in @('oracle','protected')) {
    $destination = "C:/cilantro-verify/samples/$package/$id/$kind"
    New-Item -ItemType Directory -Force $destination | Out-Null
    Copy-Item "$folder/$kind/$name" $destination
   }
   if (!@($samples | Where-Object id -eq "$framework-oracle").Count) {
    $samples += [ordered]@{id="$framework-oracle";tier='oracle';sha256=$record.OracleSha256;localName="$package/$id/oracle/$name";expectedDetection='none';expectedCapabilities=@()}
   }
   $sample = [ordered]@{id=$id;tier='profiled';sha256=$record.ProtectedSha256;localName="$package/$id/protected/$name";expectedDetection='babel';expectedCapabilities=@();oracleSha256=$record.OracleSha256;maximumRemainingSwitchDispatchers=0;maximumUnreachableInstructions=0;requireOracleResourceParity=$true;maximumSurplusResources=0}
   if ($entry.Key -eq 'metadata-combined') {$sample.minimumResourcesRestored=1;$sample.minimumRecoveredStringSites=8}
   $samples += $sample
  }
  if ($Stage -in @('Recover','All')) {
   if (Test-Path "$folder/$RecoveryDirectory") { throw "Recovery exists: $folder/$RecoveryDirectory" }
   $recovery = Run 'dotnet' @($cli,"$folder/protected/$name",'-o',"$folder/$RecoveryDirectory",'--json') 180
   $recovery | ConvertTo-Json | Set-Content "$folder/$RecoveryDirectory-recovery.json"
  }
  if ($Stage -in @('Verify','All')) {
   # Execute only this repository's benign source-built probe.
   $runs = @()
   foreach ($kind in @('oracle','protected','cleaned')) {
    $runFolder = if ($kind -eq 'cleaned') { "$folder/$RecoveryDirectory" } else { "$folder/$kind" }
    if ($kind -ne 'oracle') { Get-ChildItem "$folder/oracle" -Filter '*.json' | Copy-Item -Destination $runFolder }
    $target = "$runFolder/BabelProbe$(if($kind -eq 'cleaned'){'.cleaned'}).$extension"
    $runs += if (!(Test-Path $target)) { [pscustomobject]@{ExitCode=-1;TimedOut=$false;Stdout='';Stderr='No output assembly emitted'} }
     elseif ($framework -eq 'net48') { Run $target @() 30 }
     else { Run 'dotnet' @('exec','--runtimeconfig',"$runFolder/BabelProbe.runtimeconfig.json",$target) 30 }
   }
   $match = @($runs | Where-Object {$_.TimedOut -or $_.ExitCode -ne 0}).Count -eq 0 -and $runs[0].Stdout -ceq $runs[1].Stdout -and $runs[0].Stdout -ceq $runs[2].Stdout
   $behavior = [ordered]@{Id=$id;Match=$match;Runs=$runs}
   $behavior | ConvertTo-Json -Depth 5 | Set-Content "$folder/behavior.json"
   $outcomes += $behavior
  }
  Write-Host "$Stage $id complete"
 }
}
if ($Stage -eq 'Manifest') {
 [ordered]@{manifestVersion=1;profile='babel-12-hardening';description='Nine licensed Babel 12.1 anti-reflection/anti-disassembly and all-control-flow captures across net48/net8/net10. Metadata normalization, marker removal, resource parity and behavior are measured independently.';samples=$samples} | ConvertTo-Json -Depth 8 | Set-Content "$Output/manifest.json"
}
if ($outcomes.Count) {
 $outcomes | ConvertTo-Json -Depth 5 | Set-Content "$Output/behavior.json"
 if (@($outcomes | Where-Object {!$_.Match}).Count) { throw 'Some Babel probe comparisons failed; see behavior.json.' }
}
