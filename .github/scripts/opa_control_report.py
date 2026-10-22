#!/usr/bin/env python3
"""Generate a control-by-control OPA evidence report for GitHub Actions."""

import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import quote

POLICY_ROOT = Path("Terraform/OPA Policies")
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


def denial_logs(output: str) -> dict[str, dict[str, str]]:
    records = {}
    pattern = re.compile(r"EXPECTED_DENIAL control=(\S+) evidence=(\{.*\})")
    for match in pattern.finditer(output):
        control_id = match.group(1)
        try:
            records[control_id] = json.loads(match.group(2))
        except json.JSONDecodeError:
            continue
    return records


def markdown_text(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def main() -> int:
    output = RESULTS.read_text() if RESULTS.exists() else ""
    observed_denials = denial_logs(output)
    service_reports = []
    errors = []
    total_controls = 0
    passed_controls = 0

    for catalog in sorted(POLICY_ROOT.glob("*/controls.json")):
        service_dir = catalog.parent
        policies = sorted(
            path for path in service_dir.glob("*.rego") if not path.name.endswith("_test.rego")
        )
        tests = sorted(service_dir.glob("*_test.rego"))
        controls = json.loads(catalog.read_text())
        rows = []

        if len(policies) != 1 or len(tests) != 1:
            errors.append(
                f"{service_dir.name} must contain exactly one policy and one test file"
            )
            continue

        policy = policies[0]
        test_file = tests[0]
        service_passed = 0

        for control in controls:
            control_id = control["id"]
            test_name = control["test"]
            policy_line = line_for(policy, rf'"control":\s*"{re.escape(control_id)}"')
            test_line = line_for(test_file, rf"^\s*{re.escape(test_name)}\s*\{{")
            passed = bool(re.search(rf"\.{re.escape(test_name)}:\s+PASS\b", output))
            denial = observed_denials.get(control_id)

            evidence = []
            if policy_line:
                evidence.append(source_link(policy, policy_line, f"policy L{policy_line}"))
            else:
                errors.append(f"{control_id} has no matching policy implementation")

            if test_line:
                evidence.append(source_link(test_file, test_line, f"test L{test_line}"))
            else:
                errors.append(f"{control_id} maps to missing test {test_name}")

            if not passed:
                errors.append(f"{control_id} test {test_name} did not pass")
            if not denial:
                errors.append(f"{control_id} has no observed EXPECTED_DENIAL in OPA logs")

            status = "Passed" if policy_line and test_line and passed and denial else "Failed"
            if status == "Passed":
                service_passed += 1
            requirement = markdown_text(control["requirement"])
            if denial:
                address = markdown_text(denial.get("address", "n/a"))
                message = markdown_text(denial.get("message", "Missing denial message"))
                observed = f"`{address}`<br>{message}"
            else:
                observed = "**Missing from OPA log**"
            rows.append(
                f"| `{control_id}` | {requirement} | **{status}** | "
                f"{observed} | {', '.join(evidence) or 'Missing'} | `{test_name}` |"
            )

        total_controls += len(rows)
        passed_controls += service_passed
        service_reports.extend(
            [
                f"### {service_dir.name}",
                "",
                f"**Coverage:** {service_passed}/{len(rows)} controls passed with referenced evidence.",
                "",
                "| Control | Requirement | Result | Observed OPA denial | Source evidence | Test executed |",
                "|---|---|---|---|---|---|",
                *rows,
                "",
            ]
        )

    if total_controls == 0:
        errors.append("No control catalogs were found")

    report = [
        "## Controls tested and evidence",
        "",
        f"**Overall coverage:** {passed_controls}/{total_controls} cataloged controls passed with policy and test evidence.",
        "",
        *service_reports,
        "### Evidence context",
        "",
        f"- Commit tested: `{os.environ.get('GITHUB_SHA', 'local')}`",
        f"- OPA version: `{os.environ.get('OPA_VERSION', 'unknown')}`",
        "- Evidence links are pinned to the exact commit tested by this workflow.",
        "- `Passed` means the negative fixture produced the displayed denial and the OPA assertion passed.",
        "- The displayed denials are parsed directly from OPA's `EXPECTED_DENIAL` test logs, not inferred by the report generator.",
        "- The valid fixture separately logs `VALID_PLAN ... denials=0`.",
    ]

    if errors:
        report.extend(["", "### Evidence failures", "", *[f"- {error}" for error in errors]])

    REPORT.write_text("\n".join(report) + "\n")
    print(REPORT.read_text())
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
