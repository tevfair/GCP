#!/usr/bin/env python3
"""Publish the latest OPA control evidence in the repository README."""

import os
import sys
from pathlib import Path

README = Path("README.md")
EVIDENCE = Path("control-evidence.md")
START = "<!-- OPA_RESULTS_START -->"
END = "<!-- OPA_RESULTS_END -->"


def main() -> int:
    if not README.exists() or not EVIDENCE.exists():
        print("README.md or control-evidence.md is missing", file=sys.stderr)
        return 1

    readme = README.read_text()
    if START not in readme or END not in readme:
        print("README result markers are missing", file=sys.stderr)
        return 1

    evidence = EVIDENCE.read_text().strip()
    evidence = evidence.replace(
        "## Controls tested and evidence", "## Latest OPA control results", 1
    )
    run_url = (
        f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
        f"{os.environ.get('GITHUB_REPOSITORY', 'tevfair/GCP')}/actions/runs/"
        f"{os.environ.get('GITHUB_RUN_ID', '')}"
    )
    explanation = "\n".join(
        [
            "",
            f"**Workflow run:** [View complete OPA logs and downloadable evidence]({run_url})",
            "",
            "> **How to read these results:** Each row is a policy unit test. The test deliberately supplies a noncompliant Terraform-plan fixture, and `Observed OPA denial` is the actual rejection returned by OPA. `Passed` means OPA produced that expected denial and the assertion succeeded. This does not claim that a live, authenticated Terraform plan was evaluated.",
            "",
        ]
    )
    evidence = evidence.replace("\n", explanation, 1)

    before = readme.split(START, 1)[0]
    after = readme.split(END, 1)[1]
    README.write_text(f"{before}{START}\n\n{evidence}\n\n{END}{after}")
    print("README OPA results updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
