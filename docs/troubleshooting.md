# Troubleshooting recovery

Start with the exact input hash, tool version, command and final report. Use a new output directory for each changed trial. Do not repeat the same run expecting an unsupported instruction or missing fact to resolve itself.

## Match the symptom to the next action

| Symptom | What to inspect | Useful next action |
| --- | --- | --- |
| No cleaned file | Result, `Success`, emission diagnostics and `Wrote` | Check analysis-only/strict/partial policy and input validity. Inspect available reports and extracted files even after exit 1. |
| Native input has no cleaned root | Embedded graph and managed child result | Follow the extracted stage. A null root `Wrote.Cleaned` does not imply no managed output. |
| A recovered child is incomplete | That child's run, not only the parent's | Retry the extracted original in a separate directory after supplying a justified remedy. |
| No supported protector recognized | Detection and whether the file is original, already cleaned or a dependency | If generic cleanup is your intent, explicitly try `--generic-recovery`. It does not add support for an unknown protection. |
| Input was processed by another tool | Original metadata/resources and input provenance | Try the untouched protected sample. Missing bodies or metadata cannot reliably be guessed back. |
| Budget exhausted | The named pass, budget and blocker remedy | Raise only the relevant bound after checking the stalled path. More steps do not implement missing semantics. |
| Missing environment fact | Exact blocker key and the facts consulted | Supply a fact appropriate to the intended environment; record why it is justified. |
| Missing managed dependency | Requested identity and available matching file | Supply the specific file with `--library`, retaining its hash. |
| Unsupported API/instruction | Blocker details and affected method/stage | Report a reproducible case. Do not assert an arbitrary return value solely to make the run pass. |
| Decompiler error or strange code | Exact cleaned artifact, method and CIL | Compare extracted-original/decrypted/rebuilt provenance, inspect validation and check the method in IL view. |
| Many switches or tiny methods remain | Their callers, selectors and role | Distinguish application switches, async state machines and legitimate empty methods from protection. Counts alone are insufficient. |
| Assembly still contains resources | Resource role, references and child graph | Payloads, icons and bundled libraries may be required. High entropy alone is not ownership evidence. |
| Output later disappears | Filesystem/security-tool events and case storage | Follow your lab's handling policy; distinguish removal after recovery from a tool emission failure. |

## Long-running work

CLI runs automatically maintain `NAME.status.json` in the case folder. Through MCP, use `start_unpack` and `unpack_status`. Status reports identify the pass, process and elapsed time. The pass counter is not a reliable completion percentage: expensive interpretation can dominate one pass.

Large assemblies and virtualization can take minutes or longer. Check that the process is still alive and that status or CPU activity advances. An unchanged status file alone does not prove a hang; a stale file does not prove a process is still running. A polling timeout does not cancel background work. Do not launch duplicate runs into the same directory.

MCP cancellation is cooperative. Confirm the terminal state before reusing its output directory. A killed or failed process can leave partial artifacts; inspect the terminal result instead of treating the existence of a file as success.

## Supply facts or budgets deliberately

Read the blocker JSON and use its exact remedy keys. For example, a case that exhausts a step bound might use a declarations file containing:

```json
{
  "budgets": { "steps": 40000000 }
}
```

```text
cilantro sample.exe --declarations case.json -o case/retry
```

Choose a bound based on the reported limit; 40 million is only an example and may be lower than an adaptive allowance already in use. A smaller declaration does not necessarily reduce built-in limits. Host facts, libraries and asserted call outcomes are separate inputs. See [declarations](declarations.md).

`--allow-declared-calls` is an explicit opt-in to assertions, not an automatic fix. An assertion that a call returns true or does nothing can change what the tool believes about a path. Keep that qualification with the result.

## Reconstruction disagreement

Compare the raw verdict with the trial coverage and application-contract evidence. Deliberately removed protector caches or metadata can explain some differences, but application returns, exceptions, state changes or loaded bytes may reveal a real defect. Do not hide a disagreement by rerunning with a weaker policy.

For an unfamiliar sample, preserve the original and the affected rebuilt body/listing. Give the maintainer the exact method and discrepancy. `--no-devirtualize` can provide a diagnostic view with the original VM-backed code retained; it does not solve reconstruction.

## Payload missing or wrong file recommended

The recommendation follows observed extraction provenance. It is not a family classifier. Check every relevant child and its status, including discovered-but-unprocessed artifacts. A native file requires native analysis; a resource-only assembly may be a bundle rather than executable payload logic.

No extracted payload does not prove none exists. Unsupported codecs, unavailable keys, host-specific paths and traversal limits can prevent discovery. Downloaded stages are not fetched by CILantro. Keep the remaining-work report with the case rather than claiming exhaustive extraction.

## Report a reproducible problem

Include:

- CILantro version, OS/architecture and the exact command, with case-sensitive paths redacted as needed.
- Input SHA-256 and provenance: untouched protected original, extracted original, or previously rewritten file.
- Root/child relationship and the SHA-256 of the affected output.
- Expected behavior, observed behavior and the smallest affected method/resource you can identify.
- Relevant result, blocker, pass and validation details; declarations and dependency hashes if used.
- For decompiler failures, the decompiler/version and exact diagnostic, plus the corresponding CIL location.

Do not attach malware binaries to public issues. Arrange a suitable sharing channel with the maintainer. Review reports, declarations and recovered strings for credentials, private paths and other case data before publishing them. A useful report can begin with hashes and diagnostics even when the sample cannot be shared.
