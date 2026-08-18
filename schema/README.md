# The JSON CILantro writes

Five shapes, four files and one thing printed on standard output:

| Schema | What it describes |
| --- | --- |
| [`run.schema.json`](run.schema.json) | What `--json` prints: one run in one object, naming every file it wrote |
| [`analysis.schema.json`](analysis.schema.json) | `cilantro/NAME.analysis.json`, everything the run learned |
| [`blockers.schema.json`](blockers.schema.json) | `cilantro/NAME.blockers.json`, what stopped it and what to declare |
| [`config.schema.json`](config.schema.json) | `cilantro/NAME.config.json`, constants a protector kept out of the metadata that could not all go back into it |
| [`error.schema.json`](error.schema.json) | What `--json` prints instead when the run could not be attempted |

`corpus/schema/manifest.schema.json` is a different thing: an input the tool
reads, not an output it writes.

## What will not change without the version changing

Each of these carries its own version, and the promise is the same for all of
them:

- **A field will not be removed, renamed, or given a new meaning** while the
  major version stays where it is.
- **Fields will be added.** A reader that refuses unknown fields will break on
  the next release; one that ignores them will not. The schemas say
  `additionalProperties: false` so that *we* notice when something is added
  without being written down — that is a check on us, not a promise that your
  copy of the schema will validate a newer run.
- **A value that can be absent is `null` rather than missing.** Every field in
  the required list is present in every document.
- **Enumerations gain members.** `Kind` on a blocker and `Status` on a pass are
  the two worth handling defensively; treat one you do not know as the
  conservative case rather than as a parse failure.

The version lives in the document. `run.schema.json` documents carry
`"Schema": "cilantro.run/1"`; the report files carry `ToolVersion`, and
the shape follows the tool's own version. Check it before anything else, and
refuse a major version you were not written for rather than guessing.

### The one break, in 0.4.0

The tool was called ReactorUnpack up to 0.3.0, and these tokens were spelled
`reactorunpack.run/1` and `reactorunpack.error/1`. Renaming the tool renamed them,
which breaks a reader that matched the old string exactly. The version stayed at
`/1` deliberately: nothing about either shape changed, and moving to `/2` would
have told you to expect a change that is not there. If you pinned the old token,
this is the one place to look.

The output directory moved with it, from `reactorunpack/` to `cilantro/`, and
`run.schema.json` names every path a run wrote — so a caller that reads the
manifest rather than rebuilding paths from the convention needed no change for
that part.

## The one to read first

If you are driving the tool from a program, read `run.schema.json` and
[docs/agents.md](../docs/agents.md). The manifest is designed so that a caller
never has to rebuild a path from the naming convention or read a second file to
find out whether it is worth running again.
