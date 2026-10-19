"""Scan orchestration: build the scanner commands, refuse everything out of scope.

Not run by the agent. Every command here is authored for a human to execute against an
authorised lab target; `run_scan` plans by default and only shells out when a human passes
`execute=True` from an interactive session.
"""

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from vulnassess.errors import AdapterError, ConfigError, ScopeError
from vulnassess.settings import Settings

NOT_RUN = "not run by the agent"
SUFFIX = {"nmap": ".xml", "nikto": ".json", "zap": ".json"}
BINARY = {"nmap": "nmap", "nikto": "nikto", "zap": "zap-baseline.py"}


def _nmap(target: str, out: Path) -> list[str]:
    return ["nmap", "-sV", "-O", "--script", "vulners", "-oX", str(out), target]


def _nikto(target: str, out: Path) -> list[str]:
    return ["nikto", "-h", f"http://{target}", "-Format", "json", "-output", str(out)]


def _zap(target: str, out: Path) -> list[str]:
    return ["zap-baseline.py", "-t", f"http://{target}", "-J", str(out)]


BUILDERS = {"nmap": _nmap, "nikto": _nikto, "zap": _zap}


@dataclass(frozen=True)
class ScanCommand:
    tool: str
    argv: tuple[str, ...]
    output: Path

    @property
    def notice(self) -> str:
        return f"[{self.tool}] {NOT_RUN}: {' '.join(self.argv)}"


def plan(
    settings: Settings, target_ip: str, tools: Sequence[str], out_dir: str | Path
) -> list[ScanCommand]:
    """Authorise, then build the argument lists. Pure: nothing is executed and nothing is written."""
    scope = settings.scope
    if scope.is_canary(target_ip):
        raise ScopeError(
            f"{target_ip} is the canary in {settings.config_dir / 'scope.yaml'}; "
            "it must never be scanned; no command was built"
        )
    if not scope.contains(target_ip) or scope.name(target_ip) is None:
        raise ScopeError(
            f"{target_ip} is not an explicitly listed target in "
            f"{settings.config_dir / 'scope.yaml'} "
            f"(allowed: {scope.allowed()}); no command was built"
        )
    unknown = [tool for tool in tools if tool not in BUILDERS]
    if unknown:
        raise ConfigError(f"unknown scanner {unknown[0]!r}; known: {sorted(BUILDERS)}")

    out_dir = Path(out_dir)
    commands = []
    for tool in tools:
        output = out_dir / f"{target_ip}-{tool}{SUFFIX[tool]}"
        commands.append(
            ScanCommand(tool=tool, argv=tuple(BUILDERS[tool](target_ip, output)), output=output)
        )
    return commands


def missing_binaries(tools: Sequence[str]) -> list[str]:
    return [BINARY[tool] for tool in tools if shutil.which(BINARY[tool]) is None]


def run_scan(
    settings: Settings,
    target_ip: str,
    tools: Sequence[str],
    out_dir: str | Path,
    execute: bool = False,
    timeout: float = 1800.0,
) -> dict:
    """Plan the scan. Executes only when a human passes execute=True; the agent never does."""
    commands = plan(settings, target_ip, tools, out_dir)
    absent = missing_binaries(tools)
    summary = {
        "target_ip": target_ip,
        "executed": False,
        "commands": [command.notice for command in commands],
        "outputs": {command.tool: str(command.output) for command in commands},
        "missing": absent,
    }
    if not execute:
        return summary
    if absent:
        raise ConfigError(f"MISSING scanner binary/binaries {absent}; a human must install them")

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    results = {}
    for command in commands:
        completed = subprocess.run(
            list(command.argv), capture_output=True, text=True, timeout=timeout, check=False
        )
        if completed.returncode != 0 and not command.output.is_file():
            raise AdapterError(
                f"{command.tool} exited {completed.returncode} and wrote no output to "
                f"{command.output}"
            )
        results[command.tool] = completed.returncode
    summary["executed"] = True
    summary["exit_codes"] = results
    return summary
