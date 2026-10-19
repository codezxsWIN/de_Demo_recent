"""Run the required quality gate on Windows, where `make` is usually absent.

Each stage is reported as PASS, FAIL or MISSING. A missing tool is never installed: the
script names the prerequisite and exits non-zero so the gate cannot be faked green.
"""

import subprocess
import sys
from importlib.util import find_spec
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
COVERAGE_FLOOR = 95

STAGES: tuple[tuple[str, str | None, tuple[str, ...]], ...] = (
    ("ruff lint", "ruff", ("-m", "ruff", "check", ".")),
    ("ruff format", "ruff", ("-m", "ruff", "format", "--check", ".")),
    ("pyright", None, (str(REPO_ROOT / "scripts" / "offline_pyright.py"),)),
    (
        "pytest + coverage",
        "pytest_cov",
        ("-m", "pytest", "--cov=vulnassess", f"--cov-fail-under={COVERAGE_FLOOR}"),
    ),
)


def _importable(module: str) -> bool:
    try:
        return find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _available(module: str) -> bool:
    # These stages execute python -m: a PATH executable cannot satisfy them.
    return _importable(module)


def main() -> int:
    missing: list[str] = []
    failed: list[str] = []
    for name, module, arguments in STAGES:
        if module is not None and not _available(module):
            print(f"MISSING {name}: {module} is not installed; a human must provision it")
            missing.append(name)
            continue
        print(f"RUN     {name}: {sys.executable} {' '.join(arguments)}")
        completed = subprocess.run([sys.executable, *arguments], cwd=REPO_ROOT, check=False)
        if completed.returncode == 0:
            print(f"PASS    {name}")
        elif name == "pyright" and completed.returncode == 127:
            # The offline launcher names the missing Node/bundle/guard above.
            print(f"MISSING {name}: offline checker prerequisite unavailable")
            missing.append(name)
        else:
            print(f"FAIL    {name}: exit {completed.returncode}")
            failed.append(name)

    print()
    if missing:
        print(f"GATE INCOMPLETE: missing prerequisites: {', '.join(missing)}")
    if failed:
        print(f"GATE FAILED: {', '.join(failed)}")
    if not missing and not failed:
        print("GATE PASSED")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
