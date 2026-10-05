# Static unpacking only: invokes the supplied UPX executable, never an input DLL.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Run,
    [Parameter(Mandatory)][string]$Upx,
    [Parameter(Mandatory)][string]$Output,
    [ValidateRange(1,60)][int]$TimeoutSeconds = 30
)
$ErrorActionPreference = 'Stop'
$manifestPath = (Resolve-Path -LiteralPath $Run).Path
$tool = (Resolve-Path -LiteralPath $Upx).Path
$destination = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $destination) { throw 'Use a new output directory to preserve previous evidence.' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$payloads = @($manifest.Payloads | Where-Object Origin -eq 'nativeDependency')
if (!$payloads.Count) { throw 'The run contains no extracted native dependencies.' }

function Read-Pe([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $pe = $null
    try {
        $pe = [System.Reflection.PortableExecutable.PEReader]::new($stream)
        $headers = $pe.PEHeaders
        if (!$headers.PEHeader -or !$headers.SectionHeaders.Length) { throw 'No PE image headers.' }
        foreach ($section in $headers.SectionHeaders) {
            if ($section.SizeOfRawData -lt 0 -or $section.PointerToRawData -lt 0 -or
                ([long]$section.PointerToRawData + $section.SizeOfRawData) -gt $stream.Length) {
                throw 'A PE section extends outside the file.'
            }
        }
        [pscustomobject]@{ Managed=$pe.HasMetadata; Machine=$headers.CoffHeader.Machine.ToString();
            Sections=@($headers.SectionHeaders.Name); Length=$stream.Length }
    } finally {
        if ($pe) { $pe.Dispose() }
        $stream.Dispose()
    }
}

New-Item -ItemType Directory -Path $destination | Out-Null
$results = @(foreach ($payload in $payloads) {
    $record = [ordered]@{ Source=$payload.WrittenTo; SourceSha256=$payload.PayloadSha256;
        Status='failed'; Output=$null; OutputSha256=$null; Image=$null; ExitCode=$null;
        Diagnostic=$null; Log=$null }
    try {
        $source = (Resolve-Path -LiteralPath $payload.WrittenTo).Path
        $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($sourceHash -ne $payload.PayloadSha256) { throw 'Extracted file does not match the recorded payload hash.' }
        $before = Read-Pe $source
        if ('UPX0' -notin $before.Sections -or 'UPX1' -notin $before.Sections) {
            $record.Status = 'skipped'
            $record.Diagnostic = 'No UPX section pair; left unchanged.'
        } else {
            # Content-derived names cannot escape the output directory or collide by module name.
            $target = Join-Path $destination ($sourceHash + '.unpacked.dll')
            $record.Log = Join-Path $destination ($sourceHash + '.upx.log')
            if (Test-Path -LiteralPath $target) { throw 'Duplicate payload output; refusing to overwrite.' }
            $start = [Diagnostics.ProcessStartInfo]::new($tool)
            $start.UseShellExecute = $false
            $start.CreateNoWindow = $true
            $start.RedirectStandardOutput = $true
            $start.RedirectStandardError = $true
            foreach ($argument in @('-d', $source, '-o', $target)) { $start.ArgumentList.Add($argument) }
            $process = [Diagnostics.Process]::Start($start)
            try {
                $stdout = $process.StandardOutput.ReadToEndAsync()
                $stderr = $process.StandardError.ReadToEndAsync()
                if (!$process.WaitForExit($TimeoutSeconds * 1000)) {
                    $process.Kill($true)
                    $process.WaitForExit()
                    throw 'UPX exceeded the time limit.'
                }
                $record.ExitCode = $process.ExitCode
                ($stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()) |
                    Set-Content -LiteralPath $record.Log
                if ($process.ExitCode -ne 0) { throw "UPX exited with code $($process.ExitCode)." }
            } finally { $process.Dispose() }
            $after = Read-Pe $target
            if ($after.Machine -ne $before.Machine) { throw 'Unpacking changed the PE architecture.' }
            if ('UPX0' -in $after.Sections -and 'UPX1' -in $after.Sections) { throw 'UPX sections remain after unpacking.' }
            if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $sourceHash) {
                throw 'The packed source changed during unpacking.'
            }
            $record.Output = $target
            $record.OutputSha256 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
            $record.Image = $after
            $record.Status = 'unpacked'
            $record.Diagnostic = if ($after.Managed) {
                'Managed metadata exposed; run CILantro on this output to continue recovery.'
            } else { 'Native PE unpacked; native deprotection and behavioral equivalence are not established.' }
        }
    } catch { $record.Diagnostic = $_.Exception.Message }
    [pscustomobject]$record
})
$report = [ordered]@{ Schema='cilantro.native-unpacking/1'; CreatedUtc=[datetime]::UtcNow;
    Run=$manifestPath; RunSha256=(Get-FileHash -LiteralPath $manifestPath).Hash.ToLowerInvariant();
    Tool=$tool; ToolSha256=(Get-FileHash -LiteralPath $tool).Hash.ToLowerInvariant();
    TimeoutSeconds=$TimeoutSeconds; Results=$results }
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $destination 'native-unpacking.json')
$results | Format-Table Status,SourceSha256,Diagnostic -AutoSize
if (@($results | Where-Object Status -eq 'failed').Count) { exit 1 }
