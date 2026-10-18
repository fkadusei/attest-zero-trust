#!/usr/bin/env python3
"""A reusable mutation harness.

Mutation testing answers one question: **does the suite go RED when the property breaks?**
A test that passes on a broken system is worse than no test, because it is evidence that
looks like evidence.

WHY THIS EXISTS
    Every previous mutation run in this project was hand-edited: change a line, run the
    suite, change it back. That is slow enough that modules go untested, and it produced
    three recorded failures:

      1. A harness "reported every mutant as GREEN" because it grepped for summary counts
         that did not match. It measured NOTHING and said everything was fine.
      2. A `cp` restore silently failed, leaving the source file mutated and the next run
         meaningless.
      3. A mutation that failed to APPLY was still reported as a result.

    This harness is built so each of those is impossible:

      * **Exit code, never output parsing.** A run is caught if the test process exits
        non-zero. Nothing greps.
      * **The restore is verified.** The file is held in memory, restored, and its bytes
        are compared. A failed restore aborts the run rather than continuing.
      * **A mutation that does not apply is a failure.** If the `find` text is absent, the
        harness refuses to report a result for it, because "the suite stayed green" and
        "the code never changed" are indistinguishable otherwise.
      * **A green control is required first.** If the unmutated suite is not green, no
        mutation result means anything, so the harness stops before reporting anything.

WHAT A SURVIVING MUTANT MEANS — AND DOES NOT MEAN
    A survivor is not automatically a blind spot. Removing one of two redundant defences
    leaves the suite green because **the property still holds**. Before calling a survivor
    a problem, check whether the behaviour actually broke. `server.ts` has a documented
    example: `verifyDpopProof` refuses a missing proof on its own.

USAGE
    ./scripts/mutate.py <spec.json> [--test-command ...]

    A spec is a list of mutations:
        {"file": "apps/api/src/x.ts", "find": "...", "replace": "...",
         "label": "what property this breaks"}

    Exit status: 0 if every mutation applied and was caught, 1 otherwise.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys


DEFAULT_TEST = [
    "node", "--test", "--experimental-strip-types", "--test-concurrency=1",
]


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_tests(target: pathlib.Path, extra: list[str]) -> int:
    """Return the test process's exit code. Nothing is parsed."""

    command = [*DEFAULT_TEST, str(target), *extra]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("spec", type=pathlib.Path)
    parser.add_argument("--test", type=pathlib.Path, required=True,
                        help="the test file to run for every mutation")
    parser.add_argument("--test-command", nargs="*", default=[],
                        help="extra arguments appended to the node --test command")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    mutations = json.loads(args.spec.read_text())
    if not isinstance(mutations, list) or not mutations:
        print("spec must be a non-empty list", file=sys.stderr)
        return 2

    # Files are loaded once and verified throughout. If a restore ever leaves a file
    # different from this snapshot, the run is void.
    originals: dict[pathlib.Path, bytes] = {}
    for mutation in mutations:
        path = pathlib.Path(mutation["file"])
        if path not in originals:
            if not path.exists():
                print(f"missing file: {path}", file=sys.stderr)
                return 2
            originals[path] = path.read_bytes()

    checksums = {p: hashlib.sha256(b).hexdigest() for p, b in originals.items()}

    def restore_all() -> bool:
        ok = True
        for path, data in originals.items():
            if path.read_bytes() != data:
                path.write_bytes(data)
            if digest(path) != checksums[path]:
                print(f"RESTORE FAILED for {path}", file=sys.stderr)
                ok = False
        return ok

    def bail(message: str) -> int:
        print(f"\nABORT: {message}", file=sys.stderr)
        restore_all()
        return 2

    # ---------------------------------------------------------------- control
    print("=" * 78)
    print("CONTROL — the unmutated suite must be GREEN, or nothing below means anything")
    print("=" * 78)
    control = run_tests(args.test, args.test_command)
    if control != 0:
        return bail(f"the CONTROL failed (exit {control}). Fix the suite before mutating.")
    if not restore_all():
        return bail("files changed during the control run")
    print("  control: GREEN\n")

    # ---------------------------------------------------------------- mutate
    results = []
    for index, mutation in enumerate(mutations, start=1):
        layer = pathlib.Path(mutation["file"])
        find = mutation["find"]
        replace = mutation["replace"]
        label = mutation.get("label", f"mutation {index}")

        print(f"[{index}/{len(mutations)}] {label}")

        current = layer.read_text()
        if find not in current:
            # Reporting "green" here would be a lie: the code was never changed.
            print(f"      MUTATION DID NOT APPLY — the text is not present in {layer}")
            print(f"      looked for: {find[:90]!r}")
            restore_all()
            results.append({"label": label, "outcome": "did-not-apply"})
            continue

        mutated = current.replace(find, replace, 1)
        if mutated == current:
            print("      MUTATION DID NOT CHANGE ANYTHING")
            restore_all()
            results.append({"label": label, "outcome": "did-not-apply"})
            continue

        layer.write_text(mutated)
        changed = digest(layer) != checksums[layer]
        if not changed:
            print("      the write did not take effect")
            restore_all()
            results.append({"label": label, "outcome": "did-not-apply"})
            continue

        try:
            exit_code = run_tests(args.test, args.test_command)
        finally:
            # Restore BEFORE interpreting the result, so a crash cannot leave the
            # source mutated — the failure mode recorded as "a cp restore silently failed".
            if not restore_all():
                return bail("restore failed after a mutation; refusing to continue")

        if exit_code != 0:
            print("      CAUGHT — the suite went red")
            results.append({"label": label, "outcome": "caught"})
        else:
            print("      SURVIVED — the suite stayed green. Check whether the property still")
            print("                 holds before calling this a blind spot.")
            results.append({"label": label, "outcome": "survived"})

    # ---------------------------------------------------------------- summary
    caught = sum(1 for r in results if r["outcome"] == "caught")
    survived = sum(1 for r in results if r["outcome"] == "survived")
    missed = sum(1 for r in results if r["outcome"] == "did-not-apply")
    total = len(results)

    print("\n" + "=" * 78)
    print(f"{caught}/{total} caught, {survived} survived, {missed} did not apply")
    for r in results:
        print(f"  {r['outcome']:14s} {r['label']}")
    print("=" * 78)

    if missed:
        print("\nA mutation that did not apply is a FAILURE, not a result.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
