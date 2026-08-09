# Reactor 6 corpus

The committed manifest contains metadata only. Malware and oracle binaries are
stored in the authorized Malware Vault and downloaded into the ignored
`samples/` directory. Every local file is SHA-256 verified before analysis.

Protected and exploratory samples:

- `ad0c3182b18b5d7ba8771d830f4d51b4ada7e26f8d05223f4379e6312aba65fa`
  (`profiled`, `embedded_dotnet_Mlfhntkcvb.exe`)
- `c405398fc582e33bbbd37222b7360a6cfdc526146622141503de1ccf9de6174a`
  (`profiled`, `embedded_dotnet_Qafcakg.exe`)
- `c8fab65dedd9c62a35cfab7e318225c42cc838d57fe0a1f072b195a1a779523b`
  (`exploratory`, `Qbjuef.exe`)
- `8266fb6626cb3ad88b3cb7d5d5542a530b38230445af7ff76d102f8c49129b16`
  (`detected`, `Reason.PAC.dll`)
- `15931d5e8c20547c24c851dcb2e29b747699e8b81b925c46c2245269c93d1c91`
  (`detected`, `rsServiceController.dll`)
- `be4044e81a4db3af715af05a0c34ebcc7ca909b42469e6b79ea15bbbf68f0c0b`
  (`detected`, `rsDatabase.protected.dll`)

Validation-only deobfuscated counterparts:

- `82d2b678896ebb388c4ef9ea877e898d1ac2907d956deec4035faddda847dec0`
- `6cdf18c01fe19595d44022a587b3ecca978962013e78f006fdfb299aadbe33d9`
- `482100ea3682a84991de0e02dcce449ecd4bea6495999c1a05c95dd37facbd3d`

The counterparts are negative controls and structural oracles. They are not
used to derive algorithms, constants, keys, names, or output bytes.

Reproduce the normalized corpus result:

```bash
dotnet run --project src/ReactorUnpack.Cli -- corpus run \
  --manifest corpus/reactor-6-nonvirt.manifest.json \
  --samples samples \
  --output artifacts/corpus
```

The command returns nonzero for a missing or mismatched file, an unexpected
detection/capability result, a failed pass, or a profiled sample that cannot
emit verified output.
