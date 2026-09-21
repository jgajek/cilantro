# Declarations

Declarations supply information a static run cannot derive: host facts, dependency files, resource budgets, and explicitly authorized call outcomes. Start with a normal run and read its blockers before adding them.

```text
cilantro sample.exe --declarations case.json
```

## File format

Every section is optional. This example supplies facts and increases the interpreter step budget; use values appropriate to the case rather than copying host facts as evidence.

```json
{
  "name": "case-workstation",
  "facts": {
    "env:MachineName": "ANALYSIS-PC",
    "debugger:IsAttached": false
  },
  "libraries": ["./dependency.dll"],
  "budgets": { "steps": 40000000 }
}
```

| Section | Meaning |
| --- | --- |
| `facts` | Named host/environment values; use the exact key from the blocker |
| `libraries` | Specific managed assembly files whose IL may be interpreted; paths are relative to the declarations file |
| `budgets` | Interpreter `steps`, `allocatedBytes`, and `depth` limits |
| `passes` | A `skip` list of pass names for diagnostic runs |
| `calls` | Assertions about unsupported calls, enabled only by `--allow-declared-calls` |

Facts can be strings, integers, booleans, null for absence, or bytes expressed as `{ "base64": "..." }`. Recognized key families include environment, debugger, process, runtime, WMI, registry, volume, network, time, GUID, and native facts. See the [bundled profile](../profiles/windows-10-workstation.json) and the exact blocker keys rather than guessing their spelling.

`--host-profile` supplies facts separately and `--library` supplies individual dependencies. A host profile cannot be combined with declarations that also supply facts. Stated facts override default assumptions and are recorded as supplied evidence; they are not independently verified.

Step declarations raise a pass's allowance; a smaller number does not necessarily lower its built-in or adaptive budget. Some analyses have their own hard limits. Budget changes do not add missing API models or settle unknown behavior.

Controlled VM method comparisons also honor `budgets.steps`. Their default is four million steps per comparison machine; in repeat-call trials, original warm-up and measurement share that allowance. A larger declared limit can let expensive protector initialization finish, but does not skip initialization or turn an unsupported outcome into agreement. Each trial records its effective step limit.

## Call assertions

```json
{
  "calls": {
    "System.Boolean Vendor.Guard::Ok()": { "returns": true },
    "System.Void Vendor.Log::Flush()": { "inert": true }
  }
}
```

Run with `--allow-declared-calls` to enable these assertions. Each entry declares a return value or an inert void call, never both. They apply to unsupported calls after ordinary interpretation/modeling opportunities; they do not override a known implementation. Declared values carry declared provenance, and an inert assertion does not prove a loader frame can safely be deleted.

Do not convert a suggested inert declaration into a fact without checking its meaning. The tool cannot know whether an unsupported external call changes state relevant to the sample.

## Reading blockers and retrying

Each blocker records `Kind`, `Key`, `Detail`, `Where`, `Pass`, and `Times`. `Declare` is a human-readable suggestion. `Remedy` supplies structured `Section`, `Name`, `Value`, `Wants`, and `Flag` fields for automation.

| Blocker | Next step |
| --- | --- |
| Missing host fact | Supply a fact only if you can establish it for the intended environment |
| Missing dependency | Supply the specific assembly and retain its recorded hash |
| Budget exhausted | Consider raising the named allowance after inspecting the stopped work |
| Unsupported call | Add a model, or supply a justified call assertion with explicit opt-in |
| Unsupported body/instruction | Usually requires an implementation change |
| Unknown value | Investigate the earlier operation that produced it |
| Uncaught throw | Inspect the condition and supplied facts; it may be intentional sample behavior |

A non-null `Wants` means a value still needs to be supplied; a placeholder null must not be treated as an answer. A null remedy means there is no declaration-based fix identified for that stop. `MoreToDeclare` indicates available remedies, not permission to apply them blindly.

Pass exclusions are for diagnosis. Skipping an emission-gating pass withholds the cleaned assembly; `--fail-on-partial` makes other incomplete passes block as well. Reports and extracted files can still be produced.

After retrying, check unused/unconsulted declarations and compare the blocker set. Stop when no supported remedy or justified new information remains. See [automation](agents.md) for the MCP helper.
