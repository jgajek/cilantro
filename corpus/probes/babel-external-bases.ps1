param(
 [string]$Babel = "$env:LOCALAPPDATA/Programs/BabelDesktop/babel.exe",
 [string]$Output = 'C:/cilantro-verify/babel/external-bases',
 [ValidateSet('Protect','Manifest','Recover','VerifyProtected','Verify')][string]$Stage = 'Protect',
 [string[]]$Only = @('*'),
 [ValidatePattern('^[A-Za-z0-9_-]+$')][string]$RecoveryDirectory = 'cleaned'
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$Output = [IO.Path]::GetFullPath($Output)
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant() }
function Run([string]$Executable, [string[]]$Arguments, [int]$Seconds = 120) {
 $info = [Diagnostics.ProcessStartInfo]::new()
 $info.FileName = $Executable
 $info.UseShellExecute = $false; $info.CreateNoWindow = $true
 $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
 $info.StandardOutputEncoding = [Text.Encoding]::UTF8; $info.StandardErrorEncoding = [Text.Encoding]::UTF8
 foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
 $process = [Diagnostics.Process]::new(); $process.StartInfo = $info
 try {
  [void]$process.Start()
  $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
  $finished = $process.WaitForExit($Seconds * 1000)
  if (!$finished) { $process.Kill($true); $process.WaitForExit() }
  $outText = $stdout.GetAwaiter().GetResult(); $errText = $stderr.GetAwaiter().GetResult()
  if ($env:BABEL_LICENSE) { $outText = $outText.Replace($env:BABEL_LICENSE,'[redacted]'); $errText = $errText.Replace($env:BABEL_LICENSE,'[redacted]') }
  [pscustomobject]@{ExitCode=$process.ExitCode;TimedOut=(!$finished);Stdout=$outText;Stderr=$errText}
 } finally { $process.Dispose() }
}
$profiles = [ordered]@{
 'error' = 'BabelExternalBaseProbe\.ErrorBox.*::Exchange'
 'list' = 'BabelExternalBaseProbe\.ListBox.*::Exchange'
 'plain' = 'BabelExternalBaseProbe\.PlainError::Exchange'
}
$outcomes = @()
$samples = @()
foreach ($framework in @('net48','net8.0','net10.0')) {
 foreach ($profile in $profiles.GetEnumerator()) {
  $id = "$framework-$($profile.Key)"; if (!@($Only | Where-Object { $id -like $_ }).Count) { continue }
  $extension = if ($framework -eq 'net48') { 'exe' } else { 'dll' }
  $name = "BabelExternalBaseProbe.$extension"; $folder = Join-Path $Output $id
  if ($Stage -eq 'Protect') {
   if (!$env:BABEL_LICENSE) { throw 'Set BABEL_LICENSE in this process to the authorized floating key. It is not recorded in fixtures.' }
   if (Test-Path "$folder/protected/$name") { throw "Capture exists: $id; choose a fresh output directory." }
   New-Item -ItemType Directory -Force "$folder/oracle","$folder/protected" | Out-Null
   Get-ChildItem (Join-Path $repo "corpus/probes/BabelExternalBaseProbe/bin/Release/$framework") -File |
    Where-Object Extension -in @('.exe','.dll','.json') | Copy-Item -Destination "$folder/oracle"
   $options = @('--notypes','--nomethods','--nofields','--noproperties','--noevents','--nologo','--quiet','--strict-exit','--randomseed','12345678','--use','tagassembly=on','--msilencryption',$profile.Value)
   $result = Run $Babel (@("$folder/oracle/$name",'--output',"$folder/protected/$name",'--license',"floating:$env:BABEL_LICENSE") + $options)
   $result | ConvertTo-Json | Set-Content "$folder/protection.json"
   if ($result.ExitCode -ne 0 -or $result.TimedOut -or !(Test-Path "$folder/protected/$name")) { throw "Babel failed: $id; see protection.json." }
   $countMatch = [regex]::Match($result.Stdout,'Number of encrypted methods:\s*(\d+)')
   if (!$countMatch.Success) { throw "No encrypted-method count for $id" }
   [ordered]@{Id=$id;Framework=$framework;Options=$options;EncryptedMethods=[int]$countMatch.Groups[1].Value;CompilerVersion=(Get-Item $Babel).VersionInfo.FileVersion;CompilerSha256=(Hash $Babel);OracleSha256=(Hash "$folder/oracle/$name");ProtectedSha256=(Hash "$folder/protected/$name")} |
    ConvertTo-Json -Depth 5 | Set-Content "$folder/fixture.json"
  }
  $record = Get-Content -Raw "$folder/fixture.json" | ConvertFrom-Json
  if ((Hash "$folder/oracle/$name") -cne $record.OracleSha256 -or (Hash "$folder/protected/$name") -cne $record.ProtectedSha256) { throw "Capture changed: $id" }
  if ($Stage -eq 'Manifest') {
   foreach ($kind in @('oracle','protected')) {
    $destination = "$Output/samples/babel-12-external-bases/$id/$kind"
    New-Item -ItemType Directory -Force $destination | Out-Null
    Copy-Item "$folder/$kind/$name" $destination
   }
   if (!@($samples | Where-Object id -eq "$framework-oracle").Count) {
    $samples += [ordered]@{id="$framework-oracle";tier='oracle';sha256=$record.OracleSha256;localName="babel-12-external-bases/$id/oracle/$name";expectedDetection='none';expectedCapabilities=@()}
   }
   $unsupported = $false
   $sample = [ordered]@{id=$id;tier=$(if ($unsupported) { 'exploratory' } else { 'profiled' });sha256=$record.ProtectedSha256;localName="babel-12-external-bases/$id/protected/$name";expectedDetection='babel';expectedCapabilities=@();oracleSha256=$record.OracleSha256}
   if ($unsupported) { $sample.expectUnsupportedReason = 'unsupported argument adaptation' }
   else { $sample.expectedRestoredBodyCount=$record.EncryptedMethods; $sample.maximumRemainingStubs=0; $sample.maximumSurplusResources=0; $sample.requireOracleResourceParity=$true }
   $samples += $sample
  }
  if ($Stage -eq 'Recover') {
   if (Test-Path "$folder/$RecoveryDirectory") { throw "Recovery exists: $id/$RecoveryDirectory" }
   $result = Run 'dotnet' @((Join-Path $repo 'src/Cilantro.Cli/bin/Release/net10.0/cilantro.dll'),"$folder/protected/$name",'-o',"$folder/$RecoveryDirectory",'--json') 180
   $result | ConvertTo-Json | Set-Content "$folder/$RecoveryDirectory-recovery.json"
  }
  if ($Stage -in @('Protect','VerifyProtected','Verify')) {
   $runs = @()
   $kinds = if ($Stage -in @('Protect','VerifyProtected')) { @('oracle','protected') } else { @('oracle','protected','cleaned') }
   foreach ($kind in $kinds) {
    $runFolder = if ($kind -eq 'cleaned') { "$folder/$RecoveryDirectory" } else { "$folder/$kind" }
    if ($kind -ne 'oracle') { Get-ChildItem "$folder/oracle" -Filter '*.json' | Copy-Item -Destination $runFolder }
    $target = "$runFolder/BabelExternalBaseProbe$(if ($kind -eq 'cleaned') { '.cleaned' }).$extension"
    $runs += if (!(Test-Path $target)) { [pscustomobject]@{ExitCode=-1;TimedOut=$false;Stdout='';Stderr='No emitted assembly'} }
     elseif ($framework -eq 'net48') { Run $target @() 30 }
     else { Run 'dotnet' @('exec','--runtimeconfig',"$runFolder/BabelExternalBaseProbe.runtimeconfig.json",$target) 30 }
   }
   $match = @($runs | Where-Object { $_.TimedOut -or $_.ExitCode -ne 0 -or $_.Stdout -cne $runs[0].Stdout }).Count -eq 0
   $protectedMatch = if ($runs.Count -eq 3) { !$runs[2].TimedOut -and $runs[2].ExitCode -eq 0 -and $runs[2].Stdout -ceq $runs[1].Stdout } else { $null }
   $verified = $match
   $outcome = [ordered]@{Id=$id;EncryptedMethods=$record.EncryptedMethods;Match=$match;CleanedMatchesProtected=$protectedMatch;Verified=$verified;Runs=$runs}
   if ($Stage -eq 'Verify') {
    $callerFolder = Join-Path $repo "corpus/probes/BabelExternalBaseCaller/bin/Release/$framework"
    $caller = "$callerFolder/BabelExternalBaseCaller.$extension"
    if (!(Test-Path $caller)) { throw "Build BabelExternalBaseCaller first: $framework" }
    $callerRuns = @()
    foreach ($kind in @('oracle','protected','cleaned')) {
     $target = if ($kind -eq 'cleaned') { "$folder/$RecoveryDirectory/BabelExternalBaseProbe.cleaned.$extension" } else { "$folder/$kind/$name" }
     $callerRuns += if ($framework -eq 'net48') { Run $caller @($target,$profile.Key) 30 }
      else { Run 'dotnet' @('exec','--runtimeconfig',"$callerFolder/BabelExternalBaseCaller.runtimeconfig.json",$caller,$target,$profile.Key) 30 }
    }
    $callerMatch = @($callerRuns | Where-Object { $_.TimedOut -or $_.ExitCode -ne 0 -or $_.Stdout -cne $callerRuns[0].Stdout -or $_.Stdout -match ':wrong' }).Count -eq 0
    $outcome.CallerMatches = $callerMatch; $outcome.CallerRuns = $callerRuns
    $outcome.Verified = $outcome.Verified -and $callerMatch
   }
   $outcome | ConvertTo-Json -Depth 5 | Set-Content "$folder/$Stage-behavior.json"; $outcomes += $outcome
  }
  Write-Host "$Stage $id complete ($($record.EncryptedMethods) encrypted methods)"
 }
}
if ($Stage -eq 'Manifest') {
 [ordered]@{manifestVersion=1;profile='babel-12-external-bases';description='External framework base method-image captures: generic Exception and List<T> owners, derived receivers and nongeneric Exception controls.';samples=$samples} |
  ConvertTo-Json -Depth 8 | Set-Content "$Output/manifest.json"
}
if ($outcomes.Count) {
 $outcomes | ConvertTo-Json -Depth 6 | Set-Content "$Output/$Stage-behavior.json"
 if (@($outcomes | Where-Object { !$_.Verified }).Count) { throw "Some benign method-shape comparisons failed; see $Stage-behavior.json." }
}
