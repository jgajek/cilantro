# Supply missing facts and dependencies

A recovery path may stop because it needs a machine setting, a managed dependency or more time to interpret a decoder. Read the blocker first, supply the missing input, then retry in a fresh case folder.

A declarations file collects those inputs in JSON:

```text
cilantro sample.exe --declarations case.json -o case/retry
```

## Choose the input that solves the blocker

| Blocker | Useful input |
| --- | --- |
| Missing environment value | A `facts` entry using the exact key from the report. |
| Missing managed dependency | `--library FILE`, or a `libraries` entry. |
| Step/allocation/depth budget exhausted | A larger relevant `budgets` allowance. |
| Unsupported external call | An implementation model, or a justified call assertion with explicit opt-in. |
| Unsupported CIL/body | Usually an implementation change. |
| Unknown value or uncaught exception | Investigate the earlier operation or condition before supplying an answer. |

**Example:** if recovery asks for a machine name and debugger state for the environment you are investigating, those facts can be recorded with a dependency and a step allowance:

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

The values are illustrative. Use facts established for the case; they are analyst-supplied inputs rather than observations made by CILantro.

## File format

Every section is optional:

| Section | Purpose |
| --- | --- |
| `facts` | Environment values requested by recovery. |
| `libraries` | Specific managed files whose IL may be interpreted; paths are relative to this JSON file. |
| `budgets` | `steps`, `allocatedBytes` and `depth` allowances. |
| `passes` | A `skip` list of pass names for diagnostic trials. |
| `calls` | Asserted outcomes for unsupported calls. |

Facts can be strings, integers, booleans, null for absence, or bytes as `{ "base64": "..." }`. Supported key families include environment, debugger, process, runtime, WMI, registry, volume, network, time, GUID and native facts. Copy exact keys from blockers; the [bundled profile](../profiles/windows-10-workstation.json) shows examples.

`--host-profile` supplies facts separately. It cannot be combined with declarations that also supply facts. Supplied facts override default assumptions and are recorded with the result.

## Raise a budget when work reaches its limit

A larger step allowance can let a decoder or initializer finish. It cannot implement an unsupported API. Check the reported limit before choosing a value: a smaller declaration does not necessarily lower an existing built-in or adaptive allowance.

VM comparisons also use `budgets.steps`. Their default is four million steps per comparison machine; original warm-up and measurement share that allowance in repeat-call trials. The [VM validation reference](assets/vm-validation-reference.md) describes the detailed bounds.

## Assert a call outcome only when you can justify it

A call assertion tells recovery how to handle an unsupported call. For example:

```json
{
  "calls": {
    "System.Boolean Vendor.Guard::Ok()": { "returns": true },
    "System.Void Vendor.Log::Flush()": { "inert": true }
  }
}
```

Enable these entries with `--allow-declared-calls`. Each entry supplies either a return value or an inert void call. Assertions apply after ordinary modeling/interpretation opportunities; they do not override a known implementation.

The assertion can change the recovered path. Record its basis and keep it with the result. Declaring a void call inert does not establish that an entire loader can be removed.

## Reading blockers and retrying

Blockers record `Kind`, `Key`, `Detail`, `Where`, `Pass` and `Times`. `Declare` gives a readable suggestion; `Remedy` contains structured `Section`, `Name`, `Value`, `Wants` and `Flag` fields for automation.

A non-null `Wants` means an answer is still needed. A null remedy means no declaration-based fix was identified. `MoreToDeclare` indicates available remedies.

After retrying, compare the blocker set and check whether the supplied declarations were consulted. If no justified new input remains, keep the partial result and report the affected path. See [automation](agents.md#declaration-loop) for the MCP helper.

Skipping an emission-gating pass withholds cleaned output. `--fail-on-partial` also withholds it for other incomplete passes; reports and extracted files can remain available.
