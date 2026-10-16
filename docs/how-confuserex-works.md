# Recognize ConfuserEx protection

ConfuserEx and its forks can hide method bodies, values, calls and control flow independently. Start with the obstacle you can see in the decompiler, then check what recovery exposes.

The [malware walkthrough](protection-removal.md#confuserex) follows an encrypted command handler through recovery to HTTP requests, PowerShell execution and readable response decisions.

## Methods cannot be read: encrypted sections

Anti-tamper protection can encrypt a section containing method bodies. The original file then offers little useful code to a decompiler.

CILantro interprets supported section-decryption setup and restores the code and associated field data. This makes the method available for analysis; its strings and branches may still be obfuscated.

## Values are numeric lookups: constant encryption

A string such as `powershell` or `POST` can be replaced by an integer and a call to a generic decoder. Searching the original file for those strings may miss the behavior.

Resolving supported constants restores readable values at their use sites. Follow the recovered string into the API call that consumes it: a process name, an HTTP setting or a command-protocol marker.

## Arithmetic chooses the next block: control-flow flattening

A flattened method runs through a dispatcher instead of ordinary branches. Tracking the arithmetic state makes it hard to see the command handler's decisions.

Unflattening reconnects established transitions. In the walkthrough, the recovered handler clearly separates response `202`, which enters the script-processing path, from response `244`, which exits the process.

## Calls and names are difficult to follow

Reference proxies disguise call targets; invisible or obfuscated identifiers make navigation harder. Supported proxy resolution exposes targets, and replacement names make eligible declarations easier to find. Use the rename map to match them to the original metadata.

## What to check after recovery

Open the cleaned artifact and inspect its own remaining-work report. The pinned examples demonstrate encrypted-section recovery, constants and control-flow cleanup. Support for other forks, strong proxies, dedicated encrypted resources and packers depends on their implementation.

See [support and limitations](compatibility.md) for scope and [troubleshooting](troubleshooting.md) when a method remains unreadable. Contributors can find the pinned checks in [corpus validation](corpus.md).
