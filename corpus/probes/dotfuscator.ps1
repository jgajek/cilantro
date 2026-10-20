param(
 [string]$Dotfuscator = 'C:/Program Files (x86)/PreEmptive Protection Dotfuscator Professional 7.9.0/dotfuscator.exe',
 [string]$Output = 'C:/cilantro-verify/dotfuscator/managed-corpus',
 [ValidateSet('Protect','Manifest','Recover','Verify','All')][string]$Stage = 'All',
 [string]$Only = '',
 [ValidateSet(1,2)][int]$StringEncryptionVersion = 1,
 [switch]$V2ExcludeArrayMethod,
 [ValidateSet('x64','x86','arm64')][string]$Architecture = 'x64',
 [ValidateSet('Windows','Linux')][string]$Platform = 'Windows',
 [string]$WslDistribution = 'Ubuntu-24.04',
 [string]$LinuxDotnet = '',
 [string]$LinuxEmulator = '/mnt/c/cilantro-verify/qemu-user/usr/bin/qemu-aarch64-static',
 [string]$LinuxSysroot = '/mnt/c/cilantro-verify/arm64-sysroot'
)
$ErrorActionPreference = 'Stop'
if ($Architecture -eq 'x86' -and $StringEncryptionVersion -ne 2) { throw 'The x86 corpus profile requires native-key v2 strings.' }
if ($Platform -eq 'Linux' -and ($Architecture -eq 'x86' -or $StringEncryptionVersion -ne 2)) { throw 'The Linux corpus profile requires x64/arm64 native-key v2 strings.' }
if ($Platform -eq 'Windows' -and $Architecture -eq 'arm64') { throw 'The reviewed ARM64 corpus uses Linux.' }
if (!$LinuxDotnet) { $LinuxDotnet = "/mnt/c/cilantro-verify/dotnet-linux-$Architecture/dotnet" }
$nativeLabel = if ($Platform -eq 'Linux') { "linux-$Architecture" } elseif ($Architecture -eq 'x86') { 'x86' } else { '' }
$nativeRid = if ($Platform -eq 'Linux') { "linux-$Architecture" } else { "win-$Architecture" }
$nativeFile = if ($Platform -eq 'Linux') { 'Runtime.Extensions.so' } else { 'Runtime.Extensions.dll' }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$Output = [IO.Path]::GetFullPath($Output)
$cli = Join-Path $repo 'src/Cilantro.Cli/bin/Release/net10.0/cilantro.dll'
New-Item -ItemType Directory -Force -Path $Output | Out-Null

# Execute only the benign Probe compiled from the sources beside this harness.
function Invoke-Bounded([string]$Executable, [string[]]$Arguments, [int]$Seconds = 30) {
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
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function WslPath([string]$Path) {
 $absolute = [IO.Path]::GetFullPath($Path)
 if ($absolute -notmatch '^([A-Za-z]):[\\/]') { throw "WSL probe path must be on a local Windows drive: $absolute" }
 '/mnt/' + $absolute.Substring(0,1).ToLowerInvariant() + '/' + $absolute.Substring(3).Replace('\','/')
}
$configs = [ordered]@{
 strings = @('/rename:off','/controlflow:off','/encrypt:on')
 flow = @('/rename:off','/controlflow:high','/encrypt:off')
 combined = @('/rename:off','/controlflow:high','/encrypt:on')
 renamed = @('/rename:on','/controlflow:high','/encrypt:on')
}
$samples = @()
$fixtures = @()
$frameworks = if ($Platform -eq 'Linux') { @('net8.0','net10.0') } else { @('net48','net8.0','net10.0') }
foreach ($framework in $frameworks) {
 $extension = if ($framework -eq 'net48') { 'exe' } else { 'dll' }
 $built = Join-Path $repo "corpus/probes/Probe/bin/$(if ($Architecture -ne 'x64') {"$Architecture/"})Release/$framework"
 foreach ($config in $configs.Keys) {
  $id = "$framework-$config"
  if ($Only -and $Only.Split(',') -notcontains $id) { continue }
  $folder = Join-Path $Output $id
  $fixtures += [pscustomobject]@{Id=$id;Framework=$framework;Config=$config;Extension=$extension;Folder=$folder}
  if ($Stage -notin @('All','Protect')) { continue }
  if (Test-Path "$folder/fixture.json") { throw "Fixture already captured: $id. Choose a fresh -Output directory." }
  if (Test-Path "$folder/protected/Probe.$extension") { throw "Unrecorded protected output already exists: $id. Choose a fresh -Output directory." }
  if (!(Test-Path "$built/Probe.$extension")) { throw "Build corpus/probes/Probe first: $framework" }
  if ($Architecture -ne 'x64') {
   $stream = [IO.File]::OpenRead("$built/Probe.$extension")
   $reader = [System.Reflection.PortableExecutable.PEReader]::new($stream)
   try {
    if ($Architecture -eq 'x86' -and ($reader.PEHeaders.CorHeader.Flags -band 2) -eq 0) { throw 'The x86 probe must have Requires32Bit set. Rebuild with -t:Rebuild -p:PlatformTarget=x86 -p:BaseOutputPath=bin/x86/.' }
    if ($Architecture -eq 'arm64' -and [int]$reader.PEHeaders.CoffHeader.Machine -ne 0xAA64) { throw 'Rebuild the ARM64 probe with -t:Rebuild -p:PlatformTarget=arm64 -p:BaseOutputPath=bin/arm64/.' }
   } finally { $reader.Dispose(); $stream.Dispose() }
  }
  New-Item -ItemType Directory -Force -Path "$folder/oracle","$folder/protected" | Out-Null
  Get-ChildItem -LiteralPath $built -File | Where-Object Extension -in @('.exe','.dll','.json') | Copy-Item -Destination "$folder/oracle"
  Get-ChildItem "$folder/oracle" -Filter '*.json' | Copy-Item -Destination "$folder/protected"
  # Dotfuscator's CLI parses Windows drive paths correctly with backslashes.
  $inputFile = [IO.Path]::GetFullPath("$folder/oracle/Probe.$extension")
  $protectedFolder = [IO.Path]::GetFullPath("$folder/protected")
  $configFile = [IO.Path]::GetFullPath("$folder/config.xml")
  $arguments = @("/in:-$inputFile","/out:$protectedFolder",'/prune:off',"/genconfig:$configFile") + $configs[$config]
  $generated = Invoke-Bounded $Dotfuscator $arguments 120
  $generated | ConvertTo-Json | Set-Content "$folder/config-generation.json"
  if ($generated.TimedOut -or $generated.ExitCode -ne 0 -or !(Test-Path $configFile)) { throw "Configuration generation failed: $id" }
  if ($config -ne 'flow') {
   # Enabling string encryption does not select any methods. Include the entire
   # source-built fixture explicitly and pin the selected encryption scheme.
   $xml = [IO.File]::ReadAllText($configFile)
   $xml = $xml.Replace('<stringencrypt />', "<stringencrypt version=`"$StringEncryptionVersion`"><includelist><type name=`".*`" regex=`"true`" /></includelist></stringencrypt>")
   if ($StringEncryptionVersion -eq 2 -and $V2ExcludeArrayMethod) {
    # The 7.9 protector emits a mismatched context for this Byte[] method.
    # Keep the original failing capture separately; use these 17-site probes
    # for three-way oracle/protected/cleaned behavior comparisons.
    $xml = $xml.Replace('<type name=".*" regex="true" />', '<type name="Probe.Program"><method name="^(?!TransformBuffer$).*" regex="true" /></type><type name="Probe.RecoveryGroundTruth" />')
   }
   [IO.File]::WriteAllText($configFile, $xml)
  }
  # /genconfig writes a configuration without building. Compile it separately.
  $arguments = @($configFile)
  $result = Invoke-Bounded $Dotfuscator $arguments 120
  $result | ConvertTo-Json | Set-Content "$folder/protection.json"
  if ($result.TimedOut -or $result.ExitCode -ne 0 -or !(Test-Path "$folder/protected/Probe.$extension")) {
   throw "Protection failed: $id. Check protection.json, including trial activation status."
  }
  [pscustomobject]@{Framework=$framework;Config=$config;Architecture=$Architecture;Platform=$Platform;StringEncryptionVersion=$StringEncryptionVersion;V2ExcludeArrayMethod=[bool]$V2ExcludeArrayMethod;Arguments=$arguments;DotfuscatorVersion=(Get-Item $Dotfuscator).VersionInfo.FileVersion;DotfuscatorSha256=(Hash $Dotfuscator);OracleSha256=(Hash $inputFile);ProtectedSha256=(Hash "$folder/protected/Probe.$extension")} |
   ConvertTo-Json -Depth 4 | Set-Content "$folder/fixture.json"
  Write-Output "Protected $id"
 }
}
if ($Stage -in @('All','Protect','Manifest')) {
 New-Item -ItemType Directory -Force "$Output/samples" | Out-Null
 foreach ($fixture in $fixtures) {
  $record = Get-Content "$($fixture.Folder)/fixture.json" -Raw | ConvertFrom-Json
  if ((Hash "$($fixture.Folder)/oracle/Probe.$($fixture.Extension)") -cne $record.OracleSha256 -or
      (Hash "$($fixture.Folder)/protected/Probe.$($fixture.Extension)") -cne $record.ProtectedSha256) { throw "Captured identities changed: $($fixture.Id)" }
  $oracleName = "dotfuscator-$($fixture.Framework)$(if ($nativeLabel) {"-$nativeLabel"})-oracle.$($fixture.Extension)"
  if (!($samples | Where-Object localName -eq $oracleName)) {
   Copy-Item "$($fixture.Folder)/oracle/Probe.$($fixture.Extension)" "$Output/samples/$oracleName"
   $samples += [ordered]@{id="$($fixture.Framework)-oracle";tier='oracle';sha256=$record.OracleSha256;localName=$oracleName;expectedDetection='none';expectedCapabilities=@()}
  }
  $sampleId = if ($StringEncryptionVersion -eq 1) { $fixture.Id } else { "$($fixture.Framework)-native-$(if ($nativeLabel) {"$nativeLabel-"})$($fixture.Config)" }
  $protectedName = if ($StringEncryptionVersion -eq 1) { "dotfuscator-$sampleId.$($fixture.Extension)" } else { "dotfuscator-v2$(if ($nativeLabel) {"-$nativeLabel"})/$($fixture.Id)/Probe.$($fixture.Extension)" }
  $packageDirectory = Split-Path "$Output/samples/$protectedName"
  New-Item -ItemType Directory -Force $packageDirectory | Out-Null
  Copy-Item "$($fixture.Folder)/protected/Probe.$($fixture.Extension)" "$Output/samples/$protectedName"
  if ($StringEncryptionVersion -eq 2) {
   Get-ChildItem "$($fixture.Folder)/protected" -Filter 'environment????????.bin' -File | Copy-Item -Destination $packageDirectory
   $nativeDirectory = Join-Path $packageDirectory "runtimes/$nativeRid/native"
   New-Item -ItemType Directory -Force $nativeDirectory | Out-Null
   Copy-Item "$($fixture.Folder)/protected/runtimes/$nativeRid/native/$nativeFile" $nativeDirectory
  }
  $entry = [ordered]@{id=$sampleId;tier='detected';sha256=$record.ProtectedSha256;localName=$protectedName;expectedDetection='dotfuscator';expectedCapabilities=@();oracleSha256=$record.OracleSha256;requireOracleResourceParity=$true;maximumRemainingSwitchDispatchers=0;maximumUnreachableInstructions=0}
  if ($fixture.Config -ne 'flow') {
   if ($StringEncryptionVersion -eq 1) { $entry.minimumRecoveredStringSites = 19 }
   else {
    # Complete recovery retires the unused native bridge and its platform switch.
    $configText = [IO.File]::ReadAllText("$($fixture.Folder)/config.xml")
    $entry.minimumRecoveredStringSites = if ($configText.Contains('^(?!TransformBuffer$).*')) { 17 } else { 19 }
   }
  }
  $samples += $entry
 }
 $profileName = if ($StringEncryptionVersion -eq 1) { 'dotfuscator-7-static' } else { "dotfuscator-7-native$(if ($nativeLabel) {"-$nativeLabel"})" }
 $description = if ($StringEncryptionVersion -eq 1) {
  'Dotfuscator Professional 7.9.0+2381db6511 source-built benign probes: managed string encryption (version=1), high control flow, combined and renamed configurations across net48/net8.0/net10.0. Pruning and runtime checks are disabled. Nine encrypted fixtures each restore all 19 decoder sites; all twelve protected fixtures leave zero dispatcher candidates. Native-key string encryption v2 is outside this profile. Executable behavior is gated separately by corpus/probes/dotfuscator.ps1.'
 } else { 'Dotfuscator 7.9 native-key v2 strings with signed per-input environment files and the reviewed native library. The 17-site validation probes exclude encryption in TransformBuffer because the protector itself corrupts that Byte[] method; retain the original 19-site capture separately to verify its existing replacement-character behavior.' }
 [ordered]@{manifestVersion=1;profile=$profileName;description=$description;samples=$samples} |
  ConvertTo-Json -Depth 8 | Set-Content "$Output/$profileName.manifest.json"
}
if ($Stage -in @('All','Recover')) {
 foreach ($fixture in $fixtures) {
  $folder = $fixture.Folder
  $record = Get-Content "$folder/fixture.json" -Raw | ConvertFrom-Json
  if ((Hash "$folder/protected/Probe.$($fixture.Extension)") -cne $record.ProtectedSha256) { throw "Protected identity changed: $($fixture.Id)" }
  $cleanedFolder = "$folder/cleaned"
  $attempt = 2
  while (Test-Path -LiteralPath $cleanedFolder) { $cleanedFolder = "$folder/cleaned-$attempt"; $attempt++ }
  & dotnet $cli "$folder/protected/Probe.$($fixture.Extension)" -o $cleanedFolder --json > "$folder/recovery.json"
  if ($LASTEXITCODE -ne 0) { throw "Recovery failed: $($fixture.Id). See recovery.json." }
  $run = Get-Content "$folder/recovery.json" -Raw | ConvertFrom-Json
  if (!$run.Wrote.Cleaned) { throw "No cleaned output: $($fixture.Id)" }
  $stem = [IO.Path]::GetFileNameWithoutExtension($run.Wrote.Cleaned)
  foreach ($name in @('Probe.runtimeconfig.json','Probe.deps.json')) {
   if (Test-Path "$folder/oracle/$name") { Copy-Item "$folder/oracle/$name" (Join-Path (Split-Path $run.Wrote.Cleaned) ($stem + $name.Substring(5))) }
  }
 }
}
if ($Stage -in @('All','Verify')) {
 $outcomes = @()
 foreach ($fixture in $fixtures) {
  $folder = $fixture.Folder
  $record = Get-Content "$folder/fixture.json" -Raw | ConvertFrom-Json
  $run = Get-Content "$folder/recovery.json" -Raw | ConvertFrom-Json
  if ((Hash "$folder/oracle/Probe.$($fixture.Extension)") -cne $record.OracleSha256 -or
      (Hash "$folder/protected/Probe.$($fixture.Extension)") -cne $record.ProtectedSha256 -or
      $run.InputSha256 -ine $record.ProtectedSha256) { throw "Fixture identities changed: $($fixture.Id)" }
  foreach ($trial in @('default','self-test')) {
   $probeArguments = if ($trial -eq 'self-test') { @('--recovery-self-test') } else { @() }
   $results = @{}
   foreach ($kind in @('oracle','protected','cleaned')) {
    $path = if ($kind -eq 'cleaned') { $run.Wrote.Cleaned } else { "$folder/$kind/Probe.$($fixture.Extension)" }
    $hostPath = if ($Architecture -eq 'x86') { 'C:/Program Files (x86)/dotnet/dotnet.exe' } else { 'dotnet' }
    $linuxPrefix = if ($Architecture -eq 'arm64') { @($LinuxEmulator,'-L',"$LinuxSysroot/usr/aarch64-linux-gnu",'-E',"LD_LIBRARY_PATH=$LinuxSysroot/usr/aarch64-linux-gnu/lib:$LinuxSysroot/usr/lib/aarch64-linux-gnu",'-E','DOTNET_GCHeapHardLimit=0x40000000') } else { @() }
    $result = if ($Platform -eq 'Linux') { Invoke-Bounded 'wsl.exe' (@('-d',$WslDistribution,'--') + $linuxPrefix + @($LinuxDotnet,(WslPath $path)) + $probeArguments) }
     elseif ($fixture.Framework -eq 'net48') { Invoke-Bounded $path $probeArguments } else { Invoke-Bounded $hostPath (@($path) + $probeArguments) }
    $result | ConvertTo-Json | Set-Content "$folder/$kind.$trial.execution.json"
    $results[$kind] = $result
   }
   $oracle = $results.oracle
   $matched = !$oracle.TimedOut -and $oracle.ExitCode -eq 0 -and $oracle.Stdout.Length -gt 0
   foreach ($kind in @('protected','cleaned')) {
    $matched = $matched -and !$results[$kind].TimedOut -and $results[$kind].ExitCode -eq 0 -and
     $results[$kind].Stdout -ceq $oracle.Stdout -and $results[$kind].Stderr -ceq $oracle.Stderr
   }
   $outcomes += [pscustomobject]@{Id=$fixture.Id;Trial=$trial;Matched=$matched;RecoverySuccess=$run.Success;Verified=$run.Verified;CleanedSha256=(Hash $run.Wrote.Cleaned)}
   Write-Output "Verified $($fixture.Id) $trial`: $matched"
  }
 }
 $outcomes | ConvertTo-Json -Depth 5 | Set-Content "$Output/ground-truth.outcomes.json"
 if ($outcomes.Where({!$_.Matched -or !$_.RecoverySuccess -or !$_.Verified}).Count) { exit 1 }
}
