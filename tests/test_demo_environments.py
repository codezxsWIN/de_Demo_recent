"""Fixed demo shortcuts retain ordinary scan/consent boundaries."""

import shutil
import subprocess
from pathlib import Path


def test_demo_presets_use_correct_targets_and_preserve_explicit_execution():
    root = Path(__file__).resolve().parents[1]
    node = shutil.which("node")
    assert node, "Node is required for the demo selector regression"
    result = subprocess.run(
        [node, "tests/synthetic/demo_environments_check.mjs"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS: three demo presets" in result.stdout
    html = (root / "vulnassess/ui/static/workflow.html").read_text(encoding="utf-8")
    for value in ("harbordesk", "office", "iot"):
        assert f'value="{value}"' in html
    assert 'for="demo-environment"' in html
    assert 'id="demo-environments"' in html
    assert 'rel="noopener" hidden>Open environment' in html
