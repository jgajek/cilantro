param(
 [string]$Reactor = 'C:/Program Files (x86)/Eziriz/.NET Reactor/dotNET_Reactor.Console.exe',
 [string]$Output = 'C:/cilantro-verify/review-trials/reactor75-ground-truth',
 [ValidateSet('Protect','Recover','Verify','All')][string]$Stage = 'All',
 [string]$Only = '',
 [switch]$RunProtected
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$Output = [IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Force -Path $Output | Out-Null
# Only the benign Probe built from this repository is executed by this script.
function Invoke-ProbeProcess([string]$Executable, [string[]]$Arguments, [int]$Seconds = 30) {
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
$configs = @{
 full = @('-necrobit','1','-virtualization','1','-stringencryption','1','-resourceencryption','1','-antitamp','1','-control_flow','1','-flow_level','9','-hide_calls','1','-obfuscation','1')
 necrobit = @('-necrobit','1','-virtualization','0','-stringencryption','0','-resourceencryption','0','-antitamp','0','-control_flow','0','-obfuscation','1')
 strings = @('-necrobit','0','-virtualization','0','-stringencryption','1','-resourceencryption','1','-antitamp','0','-control_flow','1','-flow_level','9','-obfuscation','1')
}
$fixtures = @()
foreach ($framework in @('net48','net8.0','net10.0')) {
 $extension = if ($framework -eq 'net48') { 'exe' } else { 'dll' }
 $built = Join-Path $repo "corpus/probes/Probe/bin/Release/$framework"
 foreach ($config in @('strings','necrobit','full')) {
  $id = "$framework-$config"
  if ($Only -and $Only.Split(',') -notcontains $id) { continue }
  $folder = Join-Path $Output $id
  $fixtures += [pscustomobject]@{Id=$id;Framework=$framework;Config=$config;Extension=$extension;Folder=$folder}
  if ($Stage -notin @('All','Protect')) { continue }
  New-Item -ItemType Directory -Force -Path "$folder/oracle","$folder/protected" | Out-Null
  foreach ($file in Get-ChildItem -LiteralPath $built -File) {
   if ($file.Extension -in @('.exe','.dll','.json')) { Copy-Item -LiteralPath $file.FullName -Destination "$folder/oracle" }
  }
  foreach ($file in Get-ChildItem "$folder/oracle" -Filter '*.json') { Copy-Item -LiteralPath $file.FullName -Destination "$folder/protected" }
  $arguments = @('-file',"$folder/oracle/Probe.$extension",'-targetfile',"$folder/protected/Probe.$extension",'-quiet','-nodialog') + $configs[$config]
  $result = Invoke-ProbeProcess $Reactor $arguments 120
  $result | ConvertTo-Json | Set-Content "$folder/protection.json"
  if ($result.TimedOut -or $result.ExitCode -ne 0 -or !(Test-Path "$folder/protected/Probe.$extension")) { throw "Protection failed: $id. See protection.json." }
  [pscustomobject]@{Framework=$framework;Config=$config;Arguments=$arguments;ReactorSha256=(Get-FileHash $Reactor).Hash;OracleSha256=(Get-FileHash "$folder/oracle/Probe.$extension").Hash;ProtectedSha256=(Get-FileHash "$folder/protected/Probe.$extension").Hash} | ConvertTo-Json -Depth 4 | Set-Content "$folder/fixture.json"
  Write-Output "Protected $id"
 }
}
if ($Stage -in @('All','Recover')) {
 $priorOutcomes = Join-Path $Output 'ground-truth.outcomes.json'
 if (Test-Path -LiteralPath $priorOutcomes) { Remove-Item -LiteralPath $priorOutcomes }
 $fixtures | ForEach-Object -Parallel {
  $fixture = $_
  $cli = Join-Path $using:repo 'src/Cilantro.Cli/bin/Release/net10.0/cilantro.dll'
  $dir = "$($fixture.Folder)/cleaned"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  # Runtime configuration is an input; an earlier execution result is not evidence for this output.
  $priorExecution = Join-Path $dir 'execution.json'
  if (Test-Path -LiteralPath $priorExecution) { Remove-Item -LiteralPath $priorExecution }
  foreach ($file in Get-ChildItem "$($fixture.Folder)/oracle" -File | Where-Object Name -in @('Probe.deps.json','Probe.runtimeconfig.json')) {
   Copy-Item -LiteralPath $file.FullName -Destination $dir
  }
  & dotnet $cli "$($fixture.Folder)/protected/Probe.$($fixture.Extension)" --generic-recovery --output "$dir/Probe.$($fixture.Extension)" --report-dir $dir --json > "$dir/run.json"
  Write-Output "Recovery $($fixture.Id): exit=$LASTEXITCODE"
 } -ThrottleLimit 2
}
if ($Stage -in @('All','Verify')) {
 $outcomes = @()
 foreach ($fixture in $fixtures) {
  $fixtureRecord = Get-Content "$($fixture.Folder)/fixture.json" -Raw | ConvertFrom-Json
  $run = Get-Content "$($fixture.Folder)/cleaned/run.json" -Raw | ConvertFrom-Json
  if ((Get-FileHash "$($fixture.Folder)/oracle/Probe.$($fixture.Extension)").Hash -ne $fixtureRecord.OracleSha256 -or
      (Get-FileHash "$($fixture.Folder)/protected/Probe.$($fixture.Extension)").Hash -ne $run.InputSha256) { throw "Fixture hashes changed: $($fixture.Id)" }
  $results = @{}
  foreach ($kind in $(if ($RunProtected) { @('oracle','protected','cleaned') } else { @('oracle','cleaned') })) {
   $path = "$($fixture.Folder)/$kind/Probe.$($fixture.Extension)"
   $result = if (!(Test-Path -LiteralPath $path)) { [pscustomobject]@{ExitCode=-1;TimedOut=$false;Stdout='';Stderr='No emitted assembly.'} } elseif ($fixture.Framework -eq 'net48') { Invoke-ProbeProcess $path @('--recovery-self-test') } else { Invoke-ProbeProcess 'dotnet' @($path,'--recovery-self-test') }
   $result | ConvertTo-Json | Set-Content "$($fixture.Folder)/$kind/execution.json"
   $results[$kind] = $result
  }
  $oracle = $results['oracle']; $cleaned = $results['cleaned']
  $run = Get-Content "$($fixture.Folder)/cleaned/run.json" -Raw | ConvertFrom-Json
  $protectedMatched = if ($RunProtected) { !$results.protected.TimedOut -and $results.protected.ExitCode -eq 0 -and $results.protected.Stdout -ceq $oracle.Stdout } else { $null }
  $matched = !$oracle.TimedOut -and !$cleaned.TimedOut -and $oracle.ExitCode -eq 0 -and $cleaned.ExitCode -eq 0 -and $oracle.Stdout -ceq $cleaned.Stdout -and ($oracle.Stdout -split '\r?\n' | Where-Object { $_ }).Count -eq 10
  $outcomes += [pscustomobject]@{Id=$fixture.Id;Matched=$matched;ProtectedMatched=$protectedMatched;RecoverySuccess=$run.Success;Verified=$run.Verified;RebuiltCheck=$run.RebuiltCheck;OracleExit=$oracle.ExitCode;CleanedExit=$cleaned.ExitCode;TimedOut=$cleaned.TimedOut;CleanedSha256=$(if (Test-Path "$($fixture.Folder)/cleaned/Probe.$($fixture.Extension)") { (Get-FileHash "$($fixture.Folder)/cleaned/Probe.$($fixture.Extension)").Hash } else { $null })}
  Write-Output "Verified $($fixture.Id): matched=$matched"
 }
 $outcomes | ConvertTo-Json -Depth 5 | Set-Content "$Output/ground-truth.outcomes.json"
 if ($outcomes.Where({!$_.Matched -or !$_.RecoverySuccess -or !$_.Verified}).Count) { exit 1 }
}
