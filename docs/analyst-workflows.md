# Investigate a protected sample

Start with the behavior you want to understand: a hidden process launch, an embedded payload, a command handler or a protected decoder. Use the recovered code and artifact tree to follow that behavior across stages.

The [before-and-after walkthrough](protection-removal.md) gives worked examples. This page shows how to apply the same approach to a case.

## Recover a dropper and follow its payload

```text
cilantro sample.exe -o case/run-01
```

Open the HTML report named in **OUTPUT**. Follow the recommended assembly and the artifact tree, then open the relevant cleaned child in ILSpy or dnSpyEx.

**Example:** a loader may yield both a resource-only assembly and a DLL observed at an in-memory load. Start with the loaded DLL for the next stage's code, and use the resource container when tracing where its bytes came from. The report's hashes and parent-child links connect the artifacts.

Check each stage's own result. A recovered wrapper can contain a child that still needs work. For supported native Reactor wrappers, recovery automatically continues into the directly extracted managed stage; the native root may have no cleaned file of its own.

Use `--no-recursion` when you want to inspect the loader and extracted originals before cleaning further managed children.

## Read application code after cleanup

Start at the entry point, a relevant callback or an API call associated with the behavior you are investigating. Follow its arguments, decoded strings and callers.

For a PowerShell launcher, trace the value assigned to `Arguments`. For an in-memory load, find the source of the byte array and the reflected type/method selected afterward. For a command handler, trace the response bytes into its branches and execution APIs.

Replacement names such as `generatedMethod_...` help navigation. Use the rename map to match them to the original metadata. A surviving `[RebuiltFromReading]` method came from VM reconstruction; its comparison details are in the report.

Some reconstructed methods belonged to the protector and are removed once their work is replaced. Application switches, async state machines and required initialization can remain. Use the method's role and callers to decide what still matters.

## Extract content without emitting cleaned assemblies

```text
cilantro sample.exe --analyze-only -o case/extraction
```

Use this when you want extracted originals and reports before reviewing rewritten assemblies. It still performs recovery work and can take time.

Search the extracted files, recovered code and resources with your usual analysis tools. A produced `NAME.config.json` contains recovered constants; trace each value to its use before treating it as a C2 address, key or configuration field.

## Compare readable and conservative views

Run both trials from the same untouched input:

```text
cilantro sample.exe -o case/default
cilantro sample.exe --strict -o case/strict
```

The default run enables readable replacement names, supported VM reconstruction and permissive interpretation with recorded assumptions. Strict mode stops at unknown behavior, disables implicit host assumptions and leaves names and VM stubs unchanged.

Compare the diagnostics at the point the runs diverge. If only one aspect matters, use a narrower control: `--keep-names` for names, `--keep-runtime` for protector support code, or `--no-devirtualize` for VM reconstruction.

## Continue from an extracted child

Copy the extracted original's path from the report and use a fresh case folder:

```text
cilantro "case/run-01/path-from-report/child.dll" -o case/child-trial
```

Keep the parent's hash and the extraction link with the new trial. Reusing the extracted original makes comparisons easier than repeatedly cleaning a transformed copy.

A recursive run processes up to depth 4, 32 artifacts and 256 MiB of aggregate input, with the root included and duplicate hashes shared. If the report names a traversal limit, continue from the relevant child as a separate case. An interpreter step-budget change does not alter these traversal limits.

## Handle bundled libraries

A dependency can be useful code without being the malware's entry stage. Check its identity and callers before deciding its role.

Use `--library FILE` when recovery needs to interpret a particular managed dependency. Use `--reviewed-dependencies FILE` when you have independently reviewed exact reference bytes and want matching extracted dependencies preserved. These solve different problems; the [manifest example](quick-start.md#preserving-reviewed-dependencies) explains the latter.

## Save a useful case record

Keep the untouched input, extracted originals, input/output hashes, tool version, exact commands, report, child graph, change/rename maps, and any supplied declarations or reference manifests.

A useful conclusion names the recovered behavior and remaining work: “The loader invokes this type and method in this extracted DLL; the child still has unresolved strings.” Use [reading the output](reading-the-output.md) to interpret the result and [troubleshooting](troubleshooting.md#report-a-reproducible-problem) to report a specific recovery problem.

Recovery outputs remain malware artifacts. Review reports for recovered secrets and private case data before sharing them.
