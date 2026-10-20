param([Parameter(Mandatory)][string]$Output)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $Output){throw 'Refusing to replace an existing signing key.'}
# Generate a disposable CAPI PRIVATEKEYBLOB for source-built strong-name tests.
# This key is unrelated to the Babel evaluation license and is never packaged.
$rsa=[Security.Cryptography.RSA]::Create(2048)
try{
 $parameters=$rsa.ExportParameters($true)
 $stream=[IO.MemoryStream]::new();$writer=[IO.BinaryWriter]::new($stream)
 try{
  $writer.Write([byte]7);$writer.Write([byte]2);$writer.Write([UInt16]0);$writer.Write([UInt32]0x2400)
  $writer.Write([UInt32]0x32415352);$writer.Write([UInt32]2048)
  [UInt32]$exponent=0;foreach($value in $parameters.Exponent){$exponent=($exponent -shl 8) -bor $value};$writer.Write($exponent)
  foreach($bytes in @($parameters.Modulus,$parameters.P,$parameters.Q,$parameters.DP,$parameters.DQ,$parameters.InverseQ,$parameters.D)){
   [Array]::Reverse($bytes);$writer.Write([byte[]]$bytes)
  }
  $writer.Flush();$file=[IO.File]::Open($Output,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Position=0;$stream.CopyTo($file)}finally{$file.Dispose()}
 }finally{$writer.Dispose();$stream.Dispose()}
}finally{$rsa.Dispose()}
