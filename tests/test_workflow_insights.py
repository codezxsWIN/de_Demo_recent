"""Presentation regressions, using local synthetic inputs and no network/model calls."""

import shutil
import subprocess
from pathlib import Path


def test_workflow_brief_preserves_evidence_and_validation_boundaries():
    node = shutil.which("node")
    assert node is not None, "Node is required for the workflow presentation contract"
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [node, "tests/synthetic/workflow_insights_check.mjs"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
