# Fresh Reactor ground-truth probes (Windows)

These probes are benign programs built from the source in `Probe`. Their
`--recovery-self-test` entry point prints seven arithmetic/branch results and three
catch/finally results, including the final contents of a mutated byte array.

Run these contributor commands from a source checkout with the .NET 10 SDK.

Build CILantro and the three probe targets, then use an installed Reactor console
edition (a trial is sufficient):

```powershell
dotnet build src/Cilantro.Cli/Cilantro.Cli.csproj -c Release
dotnet build corpus/probes/Probe/Probe.csproj -c Release
pwsh -NoProfile -File corpus/probes/verify.ps1 -Stage Protect
pwsh -NoProfile -File corpus/probes/verify.ps1 -Stage Recover
pwsh -NoProfile -File corpus/probes/verify.ps1 -Stage Verify -RunProtected
```

Use `-Reactor` to specify the console executable and `-Output` to choose a trial
directory. The default output is
`C:/cilantro-verify/review-trials/reactor75-ground-truth`; the existing pinned
corpus and manifests are not overwritten. `-Only net48-necrobit` restricts a run.
`-Stage All` combines the three stages after building. Verification executes the
benign oracle and cleaned builds; `-RunProtected` additionally checks the freshly
protected builds. Each execution has a 30-second timeout.

The matrix covers net48, net8.0 and net10.0, each with strings/CFF, NecroBit-only,
and full protection. Each fixture records the protector command, protector hash,
oracle hash, protected hash, recovery report and process stdout/stderr. Verification
checks input hashes and writes `ground-truth.outcomes.json`; a cleaned/oracle
mismatch produces a nonzero verification exit code. `ProtectedMatched` separately
records whether the protected program matched its oracle when requested.

A successful CILantro run and structural verification are separate from a matching
execution. Keep failures in the results: they are precisely what these probes are
intended to expose. These ten cases cover the named methods and inputs, not all
possible program behavior or every virtualized handler. The trial protector says
its outputs expire after 14 days; regenerate them for later execution trials.
