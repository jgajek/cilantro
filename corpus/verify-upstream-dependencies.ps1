param(
    [Parameter(Mandatory)][string]$Manifest,
    [Parameter(Mandatory)][string[]]$CandidatePath
)
$ErrorActionPreference = 'Stop'
# This is a corpus provenance check, not a protection detector or recovery override.
# Reference artifacts must be independently obtained and reviewed before inclusion.
$references = @(Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json)
if (!$references.Count -or !$CandidatePath.Count) { throw 'Reference and candidate sets must be nonempty.' }
$known = @{}
foreach ($reference in $references) {
    if ($reference.Sha256 -notmatch '^[a-fA-F0-9]{64}$' -or
        !$reference.Source -or !$reference.Path) { throw 'Invalid reference record.' }
    $path = [IO.Path]::GetFullPath($reference.Path, (Split-Path ([IO.Path]::GetFullPath($Manifest))))
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -cne $reference.Sha256.ToLowerInvariant()) { throw "Reference hash mismatch: $path" }
    if ($known.ContainsKey($hash)) { throw "Duplicate reference hash: $hash" }
    $known[$hash] = $reference
}
$seen = @{}
$results = @(foreach ($candidate in $CandidatePath) {
    $path = [IO.Path]::GetFullPath($candidate)
    if ($seen.ContainsKey($path)) { throw "Duplicate candidate path: $path" }
    $seen[$path] = $true
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if (!$known.ContainsKey($hash)) { throw "No reviewed upstream reference matches: $path ($hash)" }
    [pscustomobject]@{Path=$path;Sha256=$hash;Source=$known[$hash].Source;Disposition='unchanged-upstream-dependency'}
})
[pscustomobject]@{Schema='cilantro.upstream-comparison/1';Verified=$true;Candidates=$results}