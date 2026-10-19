"""Run only the installed Pyright JS bundle with a Node network-denial preload.

Discovery reads import metadata without importing the Python Pyright wrapper,
whose provisioning/update behavior is unsuitable for this offline gate. Nothing
is bootstrapped. The preload covers standard Node network APIs, not OS isolation.
"""

import os
import shutil
import subprocess
import sys
from importlib.util import find_spec
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GUARD = Path(__file__).resolve().with_name("offline_pyright_guard.cjs")
MISSING_EXIT = 127


def resolve_command() -> list[str]:
    """Find installed files only; never import or execute provisioning code."""
    node = shutil.which("node")
    if node is None:
        raise FileNotFoundError("Node.js executable 'node' on PATH")
    for prerequisite in (Path(node), GUARD):
        if not prerequisite.is_file():
            raise FileNotFoundError(str(prerequisite))
    try:
        spec = find_spec("pyright")
    except (ImportError, ValueError) as error:
        raise FileNotFoundError("installed pyright package metadata") from error
    roots = list(spec.submodule_search_locations or ()) if spec else []
    if not roots:
        raise FileNotFoundError("installed pyright package with dist/index.js")
    bundle = Path(roots[0]) / "dist"
    for prerequisite in (bundle / "index.js", bundle / "dist/pyright.js"):
        if not prerequisite.is_file():
            raise FileNotFoundError(str(prerequisite))
    return [node, str(bundle / "index.js")]


def main(arguments: list[str] | None = None) -> int:
    """Return the checker exit status, or 127 for a missing/unusable prerequisite."""
    try:
        command = resolve_command()
        checker_arguments = list(sys.argv[1:] if arguments is None else arguments)
        if not any(
            argument == "--pythonpath" or argument.startswith("--pythonpath=")
            for argument in checker_arguments
        ):
            checker_arguments[:0] = ["--pythonpath", sys.executable]
        # Replace ambient preloads/options in this child only. Quote paths for
        # NODE_OPTIONS itself; subprocess receives an argv list without a shell.
        environment = {**os.environ, "NODE_OPTIONS": f'--require="{GUARD.as_posix()}"'}
        completed = subprocess.run(
            [*command, *checker_arguments],
            cwd=REPO_ROOT,
            env=environment,
            check=False,
        )
    except OSError as error:
        print(f"MISSING offline Pyright prerequisite: {error}", file=sys.stderr)
        return MISSING_EXIT
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
