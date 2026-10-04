#!/usr/bin/env python3
"""Validate the GitHub Actions workflows, strictly.

WHY THIS EXISTS

A CI change was pushed that GitHub rejected outright — the run failed in zero seconds
with "a workflow file issue". The cause was a step with **two `run:` keys**, produced by
an edit that inserted a new step at the wrong line and nested it inside an existing one.

Every check available at the time said the file was fine:

  * `python3 -c "import yaml; yaml.safe_load(...)"` — passed, because PyYAML's default
    behaviour for a duplicate key is to keep the last one and say nothing
  * `yaml.safe_load` again, counting jobs and steps — passed, and reported plausible
    numbers for a file GitHub would not run

A validator that accepts what the consumer rejects is not a validator. So the loader
below **refuses duplicate keys**, and that is the entire point of this script.

It also checks the two things that change together in this repository: every lab start
generates its credentials first, and every `docker compose` call is given `--env-file`,
because `.env` lives above the compose files and cannot be found without it.

Run it before pushing a workflow change. It is wired into the `docs` CI job so it runs
whether anyone remembers or not.
"""
from __future__ import annotations

import pathlib
import sys

import yaml

WORKFLOW_DIR = pathlib.Path(".github/workflows")


class StrictLoader(yaml.SafeLoader):
    """A SafeLoader that raises on a duplicate mapping key."""


def _no_duplicate_keys(loader: StrictLoader, node: yaml.MappingNode, deep: bool = False):
    seen: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        seen[key] = loader.construct_object(value_node, deep=deep)
    return seen


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicate_keys
)


def main() -> int:
    files = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
    if not files:
        print(f"no workflows found under {WORKFLOW_DIR}", file=sys.stderr)
        return 1

    failures = 0
    for path in files:
        try:
            document = yaml.load(path.read_text(), Loader=StrictLoader)
        except yaml.constructor.ConstructorError as error:
            # The line number is the useful part: a duplicate key is invisible in a
            # diff, and the file can be hundreds of lines long.
            print(
                f"{path}:{error.problem_mark.line + 1}: {error.problem} "
                f"— GitHub rejects this; PyYAML would have silently kept the last one",
                file=sys.stderr,
            )
            failures += 1
            continue
        except yaml.YAMLError as error:
            print(f"{path}: not valid YAML: {error}", file=sys.stderr)
            failures += 1
            continue

        for job_name, job in (document.get("jobs") or {}).items():
            steps = job.get("steps") or []
            composes = [
                step for step in steps
                if "docker compose" in str(step.get("run", ""))
                and "lab/" in str(step.get("run", ""))
            ]
            if not composes:
                continue

            missing_env = [s for s in composes if "--env-file" not in str(s.get("run", ""))]
            if missing_env:
                # Compose looks for .env beside the compose file or in the working
                # directory. The credentials live at lab/.env — above both compose
                # files — so a call without --env-file cannot find them and fails on a
                # required variable.
                print(
                    f"{path}: job {job_name!r}: {len(missing_env)} lab compose call(s) "
                    f"without --env-file",
                    file=sys.stderr,
                )
                failures += 1

            generates = any(
                step.get("name") == "Generate the lab credentials" for step in steps
            )
            if not generates:
                print(
                    f"{path}: job {job_name!r} starts a lab but never generates the "
                    f"credentials; lab/.env will not exist",
                    file=sys.stderr,
                )
                failures += 1

        print(f"{path}: ok ({len(document.get('jobs') or {})} jobs)")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
