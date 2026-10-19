"""Pure gate logic and stubbed Node APIs; no real network or checker is launched."""

import os
import shutil
import subprocess
from importlib.machinery import ModuleSpec
from pathlib import Path

import pytest

from scripts import check, offline_pyright

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / "scripts/offline_pyright_guard.cjs"


@pytest.fixture
def installed_bundle(monkeypatch, tmp_path):
    package = tmp_path / "synthetic installed package" / "pyright"
    node = tmp_path / "synthetic node" / "node.exe"
    spec = ModuleSpec("pyright", loader=None, is_package=True)
    spec.submodule_search_locations = [str(package)]

    def find_spec(name):
        assert name == "pyright"
        return spec

    present = {node, GUARD, package / "dist/index.js", package / "dist/dist/pyright.js"}
    monkeypatch.setattr(offline_pyright, "find_spec", find_spec)
    monkeypatch.setattr(offline_pyright.shutil, "which", lambda name: str(node))
    monkeypatch.setattr(Path, "is_file", lambda path: path in present)
    return node, package, present


def test_resolve_only_installed_node_and_nested_bundle(installed_bundle):
    node, package, _ = installed_bundle
    assert offline_pyright.resolve_command() == [str(node), str(package / "dist/index.js")]


@pytest.mark.parametrize("missing", ["node", "index", "nested", "guard"])
def test_missing_file_fails_before_launch(installed_bundle, monkeypatch, capsys, missing):
    node, package, present = installed_bundle
    absent = {
        "node": node,
        "index": package / "dist/index.js",
        "nested": package / "dist/dist/pyright.js",
        "guard": GUARD,
    }[missing]
    present.remove(absent)

    def forbidden(*args, **kwargs):
        pytest.fail("a missing prerequisite must not launch a child")

    monkeypatch.setattr(offline_pyright.subprocess, "run", forbidden)
    assert offline_pyright.main([]) == 127
    output = capsys.readouterr().err
    assert "MISSING" in output and str(absent) in output


def test_missing_node_on_path_is_named(installed_bundle, monkeypatch, capsys):
    monkeypatch.setattr(offline_pyright.shutil, "which", lambda name: None)
    assert offline_pyright.main([]) == 127
    assert "MISSING" in capsys.readouterr().err


@pytest.mark.parametrize("discovery", ["absent", "namespace", "import-error", "value-error"])
def test_missing_package_metadata_never_imports_wrapper(
    installed_bundle, monkeypatch, capsys, discovery
):
    def find_spec(name):
        assert name == "pyright"
        if discovery == "import-error":
            raise ImportError("SYNTHETIC unavailable metadata")
        if discovery == "value-error":
            raise ValueError("SYNTHETIC unavailable metadata")
        if discovery == "namespace":
            return ModuleSpec("pyright", loader=None)
        return None

    monkeypatch.setattr(offline_pyright, "find_spec", find_spec)
    assert offline_pyright.main([]) == 127
    output = capsys.readouterr().err
    assert "MISSING" in output and "pyright" in output


@pytest.mark.parametrize("returncode", [0, 1, 2, 7])
def test_child_only_preload_replaces_inherited_options_and_forwards_exit(
    installed_bundle, monkeypatch, returncode
):
    node, package, _ = installed_bundle
    monkeypatch.setenv("NODE_OPTIONS", "--require=synthetic-untrusted-loader.cjs")
    parent_environment = dict(os.environ)
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        assert kwargs["env"] is not os.environ
        assert kwargs["env"]["NODE_OPTIONS"] == f'--require="{GUARD.as_posix()}"'
        assert kwargs["cwd"] == ROOT
        assert kwargs["check"] is False
        return subprocess.CompletedProcess(argv, returncode)

    monkeypatch.setattr(offline_pyright.subprocess, "run", run)
    assert offline_pyright.main(["--version", "synthetic path.py"]) == returncode
    assert calls[0][0] == [
        str(node),
        str(package / "dist/index.js"),
        "--pythonpath",
        offline_pyright.sys.executable,
        "--version",
        "synthetic path.py",
    ]
    assert len(calls) == 1
    assert dict(os.environ) == parent_environment


@pytest.mark.parametrize(
    "arguments",
    [["--pythonpath", "synthetic interpreter"], ["--pythonpath=synthetic interpreter"]],
)
def test_explicit_pythonpath_is_preserved(installed_bundle, monkeypatch, arguments):
    node, package, _ = installed_bundle
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(offline_pyright.subprocess, "run", run)
    monkeypatch.setattr(offline_pyright.sys, "argv", ["offline_pyright.py", *arguments])
    assert offline_pyright.main() == 0
    assert calls == [[str(node), str(package / "dist/index.js"), *arguments]]


def test_launch_error_is_nonzero_and_named(installed_bundle, monkeypatch, capsys):
    def run(*args, **kwargs):
        raise OSError("SYNTHETIC executable cannot be started")

    monkeypatch.setattr(offline_pyright.subprocess, "run", run)
    assert offline_pyright.main([]) == 127
    assert "MISSING" in capsys.readouterr().err


def test_path_executable_does_not_make_python_module_available(monkeypatch):
    monkeypatch.setattr(check, "find_spec", lambda name: None)
    monkeypatch.setattr(shutil, "which", lambda name: "synthetic-path-only-executable")
    assert check._available("synthetic_module") is False


@pytest.mark.parametrize("error", [ImportError, ValueError])
def test_unusable_module_metadata_is_unavailable(monkeypatch, error):
    def find_spec(name):
        raise error("SYNTHETIC invalid metadata")

    monkeypatch.setattr(check, "find_spec", find_spec)
    assert check._available("synthetic_module") is False


@pytest.mark.parametrize(
    "returncode,label", [(0, "PASS"), (1, "FAIL"), (2, "FAIL"), (127, "MISSING")]
)
def test_gate_routes_to_offline_launcher_and_reports_result(monkeypatch, capsys, returncode, label):
    stage = next(stage for stage in check.STAGES if stage[0] == "pyright")
    monkeypatch.setattr(check, "STAGES", (stage,))
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, returncode)

    monkeypatch.setattr(check.subprocess, "run", run)
    assert check.main() == (0 if returncode == 0 else 1)
    assert calls == [[check.sys.executable, str(ROOT / "scripts/offline_pyright.py")]]
    output = capsys.readouterr().out
    assert f"{label}" in output
    if returncode:
        assert "GATE PASSED" not in output


def test_gate_does_not_run_unimportable_module(monkeypatch, capsys):
    monkeypatch.setattr(check, "STAGES", (("synthetic stage", "absent", ("-m", "absent")),))
    monkeypatch.setattr(check, "find_spec", lambda name: None)

    def run(*args, **kwargs):
        pytest.fail("a PATH executable is not a python -m module")

    monkeypatch.setattr(check.subprocess, "run", run)
    assert check.main() == 1
    assert "MISSING synthetic stage" in capsys.readouterr().out


def test_make_and_ci_use_offline_launcher_without_changing_provisioning():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "$(PYTHON) scripts/offline_pyright.py" in makefile
    assert "run: python scripts/offline_pyright.py" in ci
    assert "-m pyright" not in makefile + ci
    assert "pyright==1.1.411" in ci
    assert "--cov-fail-under=95" in makefile + ci


# Every tested original is replaced BEFORE loading the guard. Even a missing or
# broken guard can only reach these fail-fast stubs, never real networking APIs.
GUARD_TEST = r"""
const assert = require('node:assert/strict');
const targets = [];
function target(owner, names) {
    for (const name of names) targets.push([owner, name]);
}
const net = require('node:net');
target(net, ['connect', 'createConnection', 'createServer']);
target(net.Socket.prototype, ['connect']);
target(net.Server.prototype, ['listen']);
const tls = require('node:tls');
target(tls, ['connect', 'createServer', 'TLSSocket']);
for (const name of ['http', 'https']) {
    const api = require('node:' + name);
    target(api, ['request', 'get', 'createServer']);
    target(api.Agent.prototype, ['createConnection']);
    target(api.globalAgent, ['createConnection']);
}
const http2 = require('node:http2');
target(http2, ['connect', 'createServer', 'createSecureServer']);
const dgram = require('node:dgram');
target(dgram, ['createSocket']);
target(dgram.Socket.prototype, [
    'bind', 'connect', 'send', 'sendto', 'addMembership', 'addSourceSpecificMembership'
]);
target(dgram, ['Socket']);
const dns = require('node:dns');
const queries = [
    'lookup', 'lookupService', 'resolve', 'resolve4', 'resolve6', 'resolveAny',
    'resolveCaa', 'resolveCname', 'resolveMx', 'resolveNaptr', 'resolveNs',
    'resolvePtr', 'resolveSoa', 'resolveSrv', 'resolveTxt', 'reverse'
];
target(dns, queries);
target(dns.Resolver.prototype, queries.filter(name => !name.startsWith('lookup')));
target(dns.promises, queries);
target(dns.promises.Resolver.prototype, queries.filter(name => !name.startsWith('lookup')));
// Synthetic web globals also exercise Node versions where these are absent.
target(globalThis, ['fetch', 'WebSocket', 'EventSource']);
for (const [owner, name] of targets) {
    const original = owner[name];
    const stub = function syntheticOriginal() {
        throw new Error('SYNTHETIC ORIGINAL REACHED: ' + name);
    };
    // Preserve prototype identity so guarding a constructor's methods still
    // reaches the previously stubbed prototype. Never call the constructor.
    if (typeof original === 'function' && original.prototype) stub.prototype = original.prototype;
    owner[name] = stub;
}
require(process.argv[1]);
function denied(action) {
    assert.throws(action, error => error.code === 'ERR_OFFLINE_NETWORK');
}
for (const [owner, name] of targets) denied(() => owner[name]());
async function main() {
    const esmNet = await import('node:net');
    const esmDns = await import('node:dns/promises');
    denied(() => esmNet.connect());
    denied(() => esmDns.resolve());
    console.log('DENIED ' + targets.length + ' stubbed APIs and ESM exports');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
"""


@pytest.mark.parametrize("load_guard", [False, True])
def test_guard_blocks_stubbed_network_apis_in_node_child(load_guard):
    node = shutil.which("node")
    assert node is not None, "MISSING: installed Node.js executable 'node' on PATH"
    assert Path(node).is_file(), f"MISSING: {node}"
    assert GUARD.is_file(), f"MISSING: {GUARD}"
    # No preload runs before the stubs. Ambient NODE_OPTIONS is discarded.
    environment = {**os.environ, "NODE_OPTIONS": ""}
    script = GUARD_TEST if load_guard else GUARD_TEST.replace("require(process.argv[1]);", "")
    completed = subprocess.run(
        [node, "-e", script, str(GUARD)],
        env=environment,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if load_guard:
        assert completed.returncode == 0, completed.stdout + completed.stderr
        assert "DENIED" in completed.stdout and "stubbed APIs and ESM exports" in completed.stdout
    else:
        # A removed guard produces a safe, observable red result, not networking.
        assert completed.returncode != 0
        assert "SYNTHETIC ORIGINAL REACHED" in completed.stderr
