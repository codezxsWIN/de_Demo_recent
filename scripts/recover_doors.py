"""Recover missing Doors files from local Git and editor history without overwrites."""

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
REVISION = "e89252e7be14472f587276224256ab9ae02eea43"
DIRECTORIES = ("vulnassess/", "tests/", "scripts/", "config/", "docs/")
ROOT_FILES = {
    "pyproject.toml",
    "requirements.txt",
    "Makefile",
    "run_demo.py",
    "run_visual_simulation.py",
    "run_model_simulation.py",
    "run_research_simulation.py",
    "models/synthetic-role-model.json",
    ".github/copilot-instructions.md",
}
HISTORY_FILES = {
    "vulnassess/cli.py",
    "tests/test_ui.py",
    "tests/__init__.py",
    "scripts/check_ui_inputs.py",
    "scripts/check_ui_server.py",
    "scripts/generate_ui_swatches.py",
    "scripts/capture_ui_phase2.py",
    "docs/decisions.md",
    "docs/ui-contract.md",
    "docs/ui-phase-1.md",
    "docs/ui-phase-2.md",
    "docs/ui.md",
}


def git(*arguments: str) -> bytes:
    return subprocess.run(["git", *arguments], cwd=ROOT, check=True, capture_output=True).stdout


def history_sources() -> dict[str, Path]:
    sources: dict[str, Path] = {}
    history = Path(os.environ["APPDATA"]) / "Code" / "User" / "History"
    for index_path in history.glob("*/entries.json"):
        record = json.loads(index_path.read_text(encoding="utf-8"))
        resource = unquote(urlsplit(record.get("resource", "")).path)
        if len(resource) > 3 and resource[0] == "/" and resource[2] == ":":
            resource = resource[1:]
        try:
            relative = Path(resource).relative_to(ROOT).as_posix()
        except ValueError:
            continue
        if relative not in HISTORY_FILES and not relative.startswith("vulnassess/ui/"):
            continue
        entries = sorted(
            record.get("entries", []), key=lambda entry: entry["timestamp"], reverse=True
        )
        for entry in entries:
            snapshot = index_path.parent / entry["id"]
            if snapshot.is_file() and snapshot.stat().st_size:
                sources[relative] = snapshot
                stamp = datetime.fromtimestamp(entry["timestamp"] / 1000, timezone.utc)
                print(f"HISTORY: {relative}; {stamp.isoformat()}")
                break
    return sources


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="restore only paths that do not exist")
    arguments = parser.parse_args()
    historical = history_sources()
    tracked = git("ls-tree", "-r", "--name-only", REVISION).decode("utf-8").splitlines()
    candidates = {
        name for name in tracked if name in ROOT_FILES or name.startswith(DIRECTORIES)
    } | set(historical)
    restored = 0
    preserved = 0
    planned = 0
    for name in sorted(candidates):
        target = ROOT / name
        if target.exists() or target.is_symlink():
            preserved += 1
            continue
        if not target.resolve().is_relative_to(ROOT):
            raise ValueError(f"recovery path leaves workspace: {name}")
        content = (
            historical[name].read_bytes()
            if name in historical
            else git("show", f"{REVISION}:{name}")
        )
        digest = hashlib.sha256(content).hexdigest()
        if name.endswith(".py"):
            compile(content, str(target), "exec")
        planned += 1
        if arguments.apply:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as destination:
                destination.write(content)
            if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                raise RuntimeError(f"recovery verification failed: {name}")
            restored += 1
        print(f"{'RESTORED' if arguments.apply else 'PLANNED'}: {name}; sha256={digest}")
    print(f"EXISTING PATHS PRESERVED: {preserved}")
    print(
        f"MISSING PATHS {'RESTORED' if arguments.apply else 'CHECKED'}: {restored if arguments.apply else planned}"
    )
    print("No branch, existing file, database, or dependency was changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
