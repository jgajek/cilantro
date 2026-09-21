# Recovery architecture

CILantro reads PE metadata and CIL with dnlib and uses a bounded interpreter for supported recovery paths. It does not load the sample into the host CLR to invoke its methods. Modeled framework operations act on interpreter-owned values, heaps, resources, and streams.

## Pipeline

1. Inspect the input, identify supported protection, and preserve its identity and original bytes.
2. Recover supported encrypted method bodies and strings, then expose constants and call targets needed by later passes.
3. Simplify control flow, interpret supported VM programs, restore resources, and extract embedded assemblies.
4. Reconstruct supported VM bodies, revisit newly exposed cleanup opportunities, and remove attributable protector infrastructure where dependency checks permit it.
5. Rename eligible symbols, verify the transformed assembly, and emit files and reports under the configured success policy.
6. When requested, traverse extracted assemblies with shared hash deduplication and depth/count/byte limits. Supported native wrappers automatically continue through their managed stage.

This is a conceptual sequence. The authoritative pass ordering and dependencies are in `CilantroPipeline.CreateDefaultPasses`; several recovery/cleanup passes run again after other transformations expose new information.

## Evidence and assumptions

Recovery records observations, source locations, changes, host facts, blockers, and declared outcomes. Default interpretation can use a plausible host profile and continue past some unsupported operations. Strict interpretation refuses these implicit assumptions. Neither mode can recover bytes that are absent from the file or prove caller-supplied facts true.

Instruction and body transformations use transactions: capture the original, edit, verify, then commit. Failure or early exit restores uncommitted bodies and discards their pending change records. Changes to metadata, fields, and resources require their own ownership and rollback discipline.

## Removing protector code

Cleanup needs both attribution and dependency analysis. An unused application method is not automatically protector debris. Initializers may decrypt data while also setting state used later; removing the entire initializer can break that state even when its decryption work is obsolete.

Loader cleanup therefore distinguishes the loader body from type-initialization effects. Integrity specialization preserves argument evaluation and shared initialization while replacing only a proven signature-check verdict. Reflection, numeric token lookups, indirect dispatch, and external contracts can require keeping declarations that direct-call analysis would otherwise remove.

## Verification boundaries

Structural verification, bounded reconstruction comparisons, successful decompilation, and benign runtime-oracle testing answer different questions. Emission gates prevent selected incomplete stages from producing a cleaned assembly; optional stages can remain partial while useful output is written. `--fail-on-partial` strengthens that policy but is not an equivalence proof.

See [code organization](code-organization.md) for implementation entry points and [corpus validation](corpus.md) for reproducible checks. Earlier detailed experiments are preserved in [history](history/README.md).
