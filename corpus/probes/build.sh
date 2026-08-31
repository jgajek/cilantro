#!/usr/bin/env bash
#
# Regenerates the reactor-7-static corpus profile.
#
# The Reactor 7 samples are not malware and are not in the repository: they are built here from
# corpus/probes/Probe and protected by a licensed or demo copy of .NET Reactor. That is what gives
# this profile something the malware profiles cannot have -- the unprotected assembly, kept beside
# the protected one as an oracle, so method-body recovery can be scored against the real answer
# rather than against a judgement.
#
# The demo build of .NET Reactor stamps a 14-day expiry into what it protects. That does not affect
# static analysis or any hash in the manifest, but a protected probe stops *running* after two
# weeks, so re-run this script rather than trusting an old sample directory for a runtime check.
#
# Usage:
#   corpus/probes/build.sh --reactor /path/to/dotNET_Reactor [--samples samples] [--dotnet dotnet]
#
# Writes the probe assemblies into the samples directory and prints the id/sha256/localName of each,
# which is what corpus/reactor-7-static.manifest.json records.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
reactor=""
samples="$root/samples"
dotnet="$root/.dotnet/dotnet"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

while [ $# -gt 0 ]; do
    case "$1" in
        --reactor) reactor="$2"; shift 2 ;;
        --samples) samples="$2"; shift 2 ;;
        --dotnet) dotnet="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$reactor" ] || [ ! -x "$reactor" ]; then
    echo "Pass --reactor with the path to an executable dotNET_Reactor." >&2
    exit 2
fi

command -v "$dotnet" >/dev/null 2>&1 || [ -x "$dotnet" ] || {
    echo "No usable dotnet at '$dotnet'. Pass --dotnet." >&2
    exit 2
}

mkdir -p "$samples"

# Each target framework is built from the same source so that a blocker can be attributed. A gap
# that shows up on net8.0 and net10.0 but not net48 belongs to CoreCLR rather than to Reactor 7.
frameworks="net48 net8.0 net10.0"

# name:flags. "full" is everything Reactor offers that this tool claims to handle; the rest each
# isolate one layer, because a profile where every sample has every protection on cannot say which
# protection a regression belongs to.
configs=(
    "full:-necrobit 1 -virtualization 1 -stringencryption 1 -resourceencryption 1 -antitamp 1 -control_flow 1 -flow_level 9 -hide_calls 1 -obfuscation 1"
    "necrobit:-necrobit 1 -virtualization 0 -stringencryption 0 -resourceencryption 0 -antitamp 0 -control_flow 0 -obfuscation 1"
    "strings:-necrobit 0 -virtualization 0 -stringencryption 1 -resourceencryption 1 -antitamp 0 -control_flow 1 -flow_level 9 -obfuscation 1"
)

echo "Building probe assemblies..."
for framework in $frameworks; do
    "$dotnet" build "$root/corpus/probes/Probe/Probe.csproj" \
        -c Release -f "$framework" -o "$work/build/$framework" >/dev/null
done

emit() {
    # emit <id> <source-file> <destination-name>
    cp "$2" "$samples/$3"
    printf '  %-34s %s  %s\n' "$1" "$(sha256sum "$samples/$3" | cut -d' ' -f1)" "$3"
}

echo
echo "Probes (id, sha256, localName):"
for framework in $frameworks; do
    built="$work/build/$framework/Probe.dll"
    extension="dll"
    if [ ! -f "$built" ]; then
        built="$work/build/$framework/Probe.exe"
        extension="exe"
    fi
    slug="${framework//./}"

    emit "probe-$slug-oracle" "$built" "reactor7-probe-$slug.oracle.$extension"

    for entry in "${configs[@]}"; do
        config="${entry%%:*}"
        flags="${entry#*:}"
        stage="$work/protect/$framework/$config"
        mkdir -p "$stage"
        cp "$built" "$stage/Probe.$extension"
        # shellcheck disable=SC2086
        "$reactor" -file "$stage/Probe.$extension" $flags -quiet >"$stage/reactor.log" 2>&1 || {
            echo "Reactor failed for $framework/$config; see $stage/reactor.log" >&2
            exit 1
        }
        protected="$stage/Probe_Secure/Probe.$extension"
        [ -f "$protected" ] || { echo "No protected output for $framework/$config" >&2; exit 1; }
        emit "probe-$slug-$config" "$protected" "reactor7-probe-$slug.$config.$extension"
    done
done

echo
echo "Reactor 7 probes written to $samples."
echo "Update corpus/reactor-7-static.manifest.json with the hashes above."
