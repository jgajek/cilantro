# Assess recovery completeness

Use this page to decide whether a recovered assembly is ready for the next step of your investigation. Start with the artifact containing the behavior you need to understand, then check its code, remaining issues and extracted stages.

## Can I follow the behavior I am investigating?

Open the cleaned assembly and follow the relevant entry point, callback or command handler. Look for readable method bodies, meaningful API calls and the decoded values those calls consume.

A PowerShell string alone is less useful than the recovered method showing how its arguments reach `Process.Start`. A decoded URL is more useful when you can trace the request and response handling. The [before-and-after walkthrough](protection-removal.md) demonstrates those connections.

## Did recovery reach the right stage?

Inspect the report's artifact tree. A cleaned wrapper can still be only the loader; the relevant application code may be in a cleaned child. Keep the extracted original for each child and use its hash to connect it to the parent.

If a traversal limit left a child unprocessed, start a separate trial from that extracted original. [Analyst workflows](analyst-workflows.md#continue-from-an-extracted-child) explains how.

## What still needs investigation?

| Finding | Question to answer |
| --- | --- |
| Encrypted or empty-looking method | Is it a confirmed remaining protected body, or a legitimate small method? |
| Decoder calls | Are unresolved strings hiding the behavior you need, or does a retained call preserve initialization? |
| Dispatch loops | Is this protector flattening, or an application switch/state machine? |
| VM-backed stub | Was its program found and reconstructed? What stopped the next stage? |
| Remaining resources | Are they application data, a payload, a dependency or protector data? |
| Reconstruction disagreement | Which state or outcome differs, and does it affect the path you are investigating? |

Use **NEEDS REVIEW**, **REMAINING** and the affected method's diagnostics to answer these questions. A count of switches, resources or small methods is a starting point for inspection.

## What do successful checks establish?

A successful run met its configured policy. Structural verification checked the output's metadata and CIL. A reconstruction comparison describes the paths and state exercised in that trial. Keep these results distinct when writing your case notes.

A useful case conclusion is specific: “Recovered the command handler and identified its response branches; embedded child still needs analysis.” Avoid turning a produced file or a green status into a claim that every protection was removed.

See [reading the output](reading-the-output.md) for report fields, [support and limitations](compatibility.md) for coverage, and [validation results](status-report.md) for the project's test evidence. Contributors use the [corpus gates](corpus.md) to check a recovery change.
