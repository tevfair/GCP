#!/usr/bin/env python3
"""Generate a control-by-control OPA evidence report for GitHub Actions."""

import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import quote

POLICY_DIR = Path("Terraform/OPA Policies/Apigee")
CATALOG = POLICY_DIR / "controls.json"
POLICY = POLICY_DIR / "apigee_security.rego"
TESTS = POLICY_DIR / "apigee_security_test.rego"
RESULTS = Path("test-results.txt")
REPORT = Path("control-evidence.md")


def line_for(path: Path, pattern: str) -> int | None:
    expression = re.compile(pattern)
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        if expression.search(line):
            return number
    return None


def source_link(path: Path, line: int, label: str) -> str:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repository = os.environ.get("GITHUB_REPOSITORY", "tevfair/GCP")
    revision = os.environ.get("GITHUB_SHA", "main")
    encoded_path = quote(path.as_posix(), safe="/")
    return f"[{label}]({server}/{repository}/blob/{revision}/{encoded_path}#L{line})"


def main() -> int:
    controls = json.loads(CATALOG.read_text())
    output = RESULTS.read_text() if RESULTS.exists() else ""
    rows = []
    errors = []

    for control in controls:
        control_id = control["id"]
        test_name = control["test"]
        policy_line = line_for(POLICY, rf'"control":\s*"{re.escape(control_id)}"')
        test_line = line_for(TESTS, rf"^\s*{re.escape(test_name)}\s*\{{")
        passed = bool(re.search(rf"\.{re.escape(test_name)}:\s+PASS\b", output))

        evidence = []
        if policy_line:
            evidence.append(source_link(POLICY, policy_line, f"policy L{policy_line}"))
        else:
            errors.append(f"{control_id} has no matching policy implementation")

        if test_line:
            evidence.append(source_link(TESTS, test_line, f"test L{test_line}"))
        else:
            errors.append(f"{control_id} maps to missing test {test_name}")

        if not passed:
            errors.append(f"{control_id} test {test_name} did not pass")

        status = "Passed" if policy_line and test_line and passed else "Failed"
        requirement = control["requirement"].replace("|", "\\|")
        rows.append(
            f"| `{control_id}` | {requirement} | **{status}** | "
            f"{', '.join(evidence) or 'Missing'} | `{test_name}` |"
        )

    passed_count = sum("**Passed**" in row for row in rows)
    report = [
        "## Controls tested and evidence",
        "",
        f"**Coverage:** {passed_count}/{len(rows)} cataloged controls passed with policy and test evidence.",
        "",
        "| Control | Requirement | Result | Referenced evidence | Test executed |",
        "|---|---|---|---|---|",
        *rows,
        "",
        "### Evidence context",
        "",
        f"- Commit tested: `{os.environ.get('GITHUB_SHA', 'local')}`",
        f"- OPA version: `{os.environ.get('OPA_VERSION', 'unknown')}`",
        "- Evidence links are pinned to the exact commit tested by this workflow.",
        "- A control passes only when its implementation exists, its mapped unit test exists, and that test reports `PASS`.",
    ]

    if errors:
        report.extend(["", "### Evidence failures", "", *[f"- {error}" for error in errors]])

    REPORT.write_text("\n".join(report) + "\n")
    print(REPORT.read_text())
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
