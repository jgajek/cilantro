# Analyst workflows

Use CILantro to turn a protected input into artifacts you can inspect. Keep the untouched input, its SHA-256 and the command used for each trial. A cleaned assembly is an analysis copy, not a replacement for the original evidence.

## Recover a dropper and follow its payload

```text
cilantro sample.exe -o case/run-01
```

1. Open the HTML report named in **OUTPUT**. Check the recommended artifact and the root's result.
2. Follow the artifact tree. Distinguish an assembly observed at a load operation from a resource-only bundle or bundled library.
3. Open the **cleaned child** for a recovered managed stage. Retain its **extracted original** for independent comparison or another recovery attempt.
4. Review that child's remaining work and validation, not just the parent's. A wrapper can recover successfully while a child remains incomplete.
5. Continue into further stages when present. A loaded assembly is not necessarily the final malware payload, and file naming alone does not establish its role.

Use SHA-256 and parent-child links when correlating files. Different names can identify identical bytes; one assembly can be referenced by several parents. The recommended file is selected from extraction provenance, not malware-family attribution.

Supported native Reactor wrappers automatically continue into their managed stage. Ordinary CLI runs also follow further extracted managed assemblies; use `--no-recursion` to leave those further children extracted but uncleaned. A native root can have no root-level cleaned path while its child has a usable managed output. Managed-wrapper reassembly is available for supported shapes; do not assume every cleaned wrapper embeds every cleaned child.

## Read application code after cleanup

Open the recommended cleaned assembly in a .NET decompiler such as ILSpy or dnSpyEx. For navigation, start with the entry point, relevant callbacks and the call sites for behavior you are investigating. Follow explicit calls, recovered literals and child assembly loads rather than assuming the first large method is the payload.

Names such as `GeneratedType_…` and `generatedMethod_…` are replacement labels, not recovered source names. Use the rename map when comparing a report, the original metadata and the cleaned file. Renaming can shift method tokens; match the artifact and name map before using an old token as a location.

Reconstructed VM application bodies may carry `[RebuiltFromReading]`. This identifies reconstruction rather than decrypted original CIL. Read their comparison coverage and diagnostics. Missing markers are not a count of missing recovery: some reconstructed methods belonged to protector infrastructure and were legitimately retired.

Ordinary switches, async `MoveNext` state machines, exception handling and initialization helpers can remain. Their presence alone is not failed unflattening. A decompiler warning should be tied to a particular method and output hash before concluding that code was lost.

## Extract content without emitting cleaned assemblies

```text
cilantro sample.exe --analyze-only -o case/extraction
```

This still performs analysis and supported extraction, but suppresses cleaned root and child assemblies. It is useful when you want recovered bytes and provenance before reviewing transformations. It is not a passive header scan and can take as long as substantial recovery work.

Search the recovered code and resources for configuration and indicators using your normal analysis workflow. A `NAME.config.json` file, when produced, contains recovered constants; it is not a guarantee of complete C2, key or family-specific configuration recovery. Validate an indicator's use and stage before attributing it to the payload.

## Compare readable and conservative views

Use separate directories and the same untouched input:

```text
cilantro sample.exe -o case/default
cilantro sample.exe --strict -o case/strict
```

The first run favors readability and supported VM reconstruction. Strict mode stops at unknown behavior, disables implicit machine assumptions, and leaves identifiers and VM stubs unchanged. It may recover less or withhold output. These are different analysis policies; compare diagnostics and outputs before treating a difference as a bug.

For a name-sensitive comparison, use `--keep-names`. For investigation of protector internals, use `--keep-runtime`; for VM listing work without reconstruction, use `--no-devirtualize`. Those are diagnostic choices, not commands for maximum protector removal.

## Continue from an extracted child

If traversal stopped at a child, use its extracted original path from the report:

```text
cilantro "case/run-01/path-from-report/child.dll" -o case/child-trial
```

The path above is illustrative; copy the real path rather than guessing it. Record the parent hash and link so the new trial retains provenance. Prefer the extracted original over repeatedly cleaning an already transformed copy.

Recursive recovery currently has limits of depth 4, 32 processed artifacts and 256 MiB of aggregate input bytes, with the root counted in the artifact/byte budget. Read the actual graph's limit and status fields. A limit is a traversal boundary, not a declaration that remaining files are unprotected. The general interpreter budget option does not remove these fixed traversal limits.

## Handle bundled libraries

Dependencies are not necessarily payloads or protected assemblies. Keep their role separate from the malware entry stage. For an independently reviewed unprotected dependency, `--reviewed-dependencies` can preserve an exact hash match and record its source. It neither downloads a reference nor trusts a DLL merely because its filename looks familiar. See the [manifest example](quick-start.md#preserving-reviewed-dependencies).

Use `--library` when interpretation needs a specific managed dependency. That supplies code for static reading; it is a different purpose from declaring an extracted reference already reviewed.

## Save a useful case record

Keep the input and extracted-original hashes, tool version, exact command, stdout/stderr or JSON manifest, HTML report, child graph, change and rename maps, and any declarations/reference manifests. Retain the actual referenced dependency bytes when permitted by your evidence policy.

Reports can contain local paths, recovered strings, configuration values and embedded secrets. Review them before sharing. See [troubleshooting](troubleshooting.md#report-a-reproducible-problem) for the smallest useful issue report and [automation](agents.md) for machine-readable collection.
