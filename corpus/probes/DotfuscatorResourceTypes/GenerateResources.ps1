param([Parameter(Mandatory)][string]$Output)
$ErrorActionPreference = 'Stop'
# Emit standard ResourceTypeCode values without serialized user objects or
# System.Resources.Extensions.
$writer = [Resources.ResourceWriter]::new([IO.Path]::GetFullPath($Output))
try {
 $writer.AddResource('Message', 'RESOURCE_TYPES mixed primitives café')
 $writer.AddResource('Integer', [object][int]-1234567)
 $writer.AddResource('Boolean', [object]$true)
 $writer.AddResource('Decimal', [object][decimal]12345.6789)
 $writer.AddResource('Double', [object][double]-1.25)
 $writer.AddResource('Character', [object][char]'Ω')
 $writer.AddResource('Long', [object][long]::MaxValue)
 $writer.AddResource('Bytes', [byte[]](0,1,127,128,254,255))
 $writer.Generate()
} finally { $writer.Dispose() }
