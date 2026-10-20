"""Pure presentation checks; no scanners, model calls or network requests."""

import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "scenario", ["stored", "running", "rejected", "preview", "partial", "priorities"]
)
def test_activity_workspace_preserves_evidence_and_explains_progress(scenario):
    node = shutil.which("node")
    assert node is not None, "MISSING node for UI presentation regression checks"
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [node, "tests/synthetic/synthetic_workflow_activity_check.mjs", scenario],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"PASS synthetic activity scenario: {scenario}" in result.stdout
