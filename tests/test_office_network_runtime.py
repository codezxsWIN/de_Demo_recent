"""Real protocol checks: VULNASSESS_NETWORK_LABS=1 python -m pytest <this file>."""

import asyncio
import ftplib
import io
import ipaddress
import json
import os
import socket
import threading
import time
from contextlib import ExitStack, suppress

import pytest

from labs.service_networks import office

_SOCKET_METHODS = {
    name: getattr(socket.socket, name)
    for name in ("bind", "connect", "connect_ex", "send", "sendall", "sendto")
}
_CREATE_CONNECTION = socket.create_connection
_GETADDRINFO = socket.getaddrinfo
runtime = pytest.mark.skipif(
    os.environ.get("VULNASSESS_NETWORK_LABS") != "1",
    reason="Set VULNASSESS_NETWORK_LABS=1 to bind the fixed office lab ports",
)


@pytest.fixture(autouse=True)
def offline_transport_guard(monkeypatch):
    """Permit real loopback traffic only, including asyncio's internal socketpair."""

    def check(address):
        assert ipaddress.ip_address(address[0]).is_loopback, address

    for name, original in _SOCKET_METHODS.items():

        def local(sock, *args, _name=name, _original=original, **kwargs):
            if sock.family in (socket.AF_INET, socket.AF_INET6):
                if _name in ("bind", "connect", "connect_ex"):
                    check(args[0])
                elif _name == "sendto":
                    check(args[-1])
                else:
                    check(sock.getpeername())
            return _original(sock, *args, **kwargs)

        monkeypatch.setattr(socket.socket, name, local)

    def connect(address, *args, **kwargs):
        check(address)
        return _CREATE_CONNECTION(address, *args, **kwargs)

    def resolve(host, *args, **kwargs):
        assert ipaddress.ip_address(host).is_loopback
        return _GETADDRINFO(host, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(socket, "getaddrinfo", resolve)


@pytest.fixture
def dependencies():
    return (
        pytest.importorskip("asyncssh"),
        pytest.importorskip("impacket.smbconnection"),
        pytest.importorskip("pyftpdlib"),
    )


@pytest.fixture
def smb_servers(monkeypatch):
    """Observe actual server resource counts while exercising real clients."""
    servers = {}
    original = office._smb_service

    def capture(smbserver, smb, smb2, root, port, password, bind_host=office.HOST):
        service = original(smbserver, smb, smb2, root, port, password, bind_host)
        servers[port] = service.getServer()
        return service

    monkeypatch.setattr(office, "_smb_service", capture)
    return servers


def _wait_until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "Server resources were not released"
        time.sleep(0.01)


def _client_count(server):
    with server.clients_lock:
        return len(server.clients)


def _ftp(port):
    client = ftplib.FTP(timeout=4)
    client.connect(office.HOST, port)
    # Use the real address in the server's PASV reply, rather than ftplib's
    # default substitution of the control connection's peer address.
    client.trust_server_pasv_ipv4_address = True
    return client


def _smb(module, port):
    return module.SMBConnection("OFFICE-LAB", office.HOST, sess_port=port, timeout=4)


def _assert_closed():
    for port in (*office.PORTS, *office.PASSIVE_PORTS):
        with socket.socket() as client:
            client.settimeout(0.3)
            assert client.connect_ex((office.HOST, port)) != 0, port
    assert not [t.name for t in threading.enumerate() if t.name.startswith("office-")]


@runtime
def test_actual_ftp_anonymous_read_and_protected_denial(tmp_path, dependencies):
    def probe(records):
        credentials = next(record for record in records if record["port"] == 2122)
        for port in (2121, 2122):
            with _ftp(port) as client:
                if port == 2122:
                    with pytest.raises(ftplib.error_perm, match="530"):
                        client.login("anonymous", "fictional@example.invalid")
                    client.login(credentials["username"], credentials["password"])
                else:
                    client.login("anonymous", "fictional@example.invalid")
                host, passive_port = client.makepasv()
                assert host == office.HOST
                assert passive_port in office.PASSIVE_PORTS
                data = bytearray()
                client.retrbinary(f"RETR {office.PROOF_NAME}", data.extend)
                assert data == b"VulnAssess office network proof\n"
                for filename in (office.PROOF_NAME, "new.txt"):
                    with pytest.raises(ftplib.error_perm, match="550"):
                        client.storbinary(f"STOR {filename}", io.BytesIO(b"not permitted"))
                with pytest.raises(ftplib.error_perm, match="550"):
                    client.delete(office.PROOF_NAME)
                with pytest.raises(ftplib.error_perm, match="502"):
                    client.sendcmd("PORT 127,0,0,2,120,1")
                with pytest.raises(ftplib.error_perm, match="502"):
                    client.sendcmd("EPRT |1|127.0.0.2|30721|")
                with pytest.raises(ftplib.error_perm, match="550"):
                    client.retrbinary("RETR ../outside.txt", lambda data: None)

    async def run():
        async with office.start(tmp_path / "office") as records:
            assert len(records) == 6
            assert {record["host"] for record in records} == {office.HOST}
            assert {record["port"] for record in records} == set(office.PORTS)
            json.dumps(records)
            await asyncio.to_thread(probe, records)
        _assert_closed()

    (tmp_path / "outside.txt").write_bytes(b"must never be served")
    asyncio.run(run())
    assert (tmp_path / "office" / office.PROOF_NAME).read_bytes() == office.PROOF


@runtime
def test_ftp_passive_range_exhaustion_never_uses_random_port(tmp_path, dependencies):
    def probe():
        with ExitStack() as stack:
            for port in office.PASSIVE_PORTS:
                occupied = stack.enter_context(socket.socket())
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    occupied.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                occupied.bind((office.HOST, port))
                occupied.listen()
            with _ftp(2121) as client:
                client.login()
                with pytest.raises(ftplib.error_temp, match="425"):
                    client.makepasv()

    async def run():
        async with office.start(tmp_path):
            await asyncio.to_thread(probe)
        _assert_closed()

    asyncio.run(run())


@runtime
def test_actual_ssh_authentication_and_no_execution_or_forwarding(tmp_path, dependencies):
    asyncssh = dependencies[0]

    async def run():
        async with office.start(tmp_path) as records:
            options = dict(host=office.HOST, known_hosts=None, agent_path=None, client_keys=[])
            async with asyncssh.connect(
                **options, port=2222, username="admin", password="admin"
            ) as connection:
                with pytest.raises(asyncssh.ChannelOpenError):
                    await connection.run("echo forbidden", timeout=2)
                with pytest.raises(asyncssh.ChannelOpenError):
                    await connection.create_process()
                with pytest.raises(asyncssh.ChannelOpenError):
                    await connection.start_sftp_client()
                with pytest.raises(asyncssh.ChannelOpenError):
                    await connection.open_connection(office.HOST, 2121)
                with pytest.raises(asyncssh.ChannelListenError):
                    await connection.forward_remote_port(office.HOST, 0, office.HOST, 2121)

            with pytest.raises(asyncssh.PermissionDenied):
                await asyncssh.connect(**options, port=2222, username="admin", password="incorrect")
            with pytest.raises(asyncssh.PermissionDenied):
                await asyncssh.connect(**options, port=2223, username="admin", password="admin")
            methods = await asyncssh.get_server_auth_methods(office.HOST, 2223, username="auditor")
            assert methods == ["publickey"]
            protected = next(record for record in records if record["port"] == 2223)
            key = asyncssh.import_private_key(protected["private_key"])
            async with asyncssh.connect(
                office.HOST,
                2223,
                username="auditor",
                known_hosts=None,
                agent_path=None,
                client_keys=[key],
            ) as connection:
                with pytest.raises(asyncssh.ChannelOpenError):
                    await connection.run("echo forbidden", timeout=2)
        _assert_closed()

    asyncio.run(run())


@runtime
def test_actual_smb_guest_read_signing_and_protected_denial(tmp_path, dependencies):
    module = dependencies[1]
    from impacket import smb3structs as smb2

    def probe(records):
        with ExitStack() as stack:
            guest = _smb(module, 1445)
            stack.callback(guest.close)
            assert guest.getDialect() == smb2.SMB2_DIALECT_002
            assert guest.isSigningRequired() is False
            guest.login("", "")
            data = bytearray()
            guest.getFile("TRAINING", office.PROOF_NAME, data.extend)
            assert data == b"VulnAssess office network proof\n"

            protected = _smb(module, 1446)
            stack.callback(protected.close)
            # Authentication denial alone is insufficient: attempt the actual
            # read, even if a library version allowed a fallback guest login.
            with suppress(module.SessionError):
                protected.login("", "")
            denied_data = bytearray()
            with pytest.raises(module.SessionError):
                protected.getFile("TRAINING", office.PROOF_NAME, denied_data.extend)
            assert not denied_data

            credentials = next(record for record in records if record["port"] == 1446)
            authorized = _smb(module, 1446)
            stack.callback(authorized.close)
            authorized.login(credentials["username"], credentials["password"])
            data = bytearray()
            authorized.getFile("TRAINING", office.PROOF_NAME, data.extend)
            assert data == office.PROOF

    async def run():
        async with office.start(tmp_path) as records:
            await asyncio.to_thread(probe, records)
        _assert_closed()

    asyncio.run(run())


@runtime
def test_actual_smb_writes_metadata_changes_and_traversal_denied(tmp_path, dependencies):
    module = dependencies[1]
    from impacket import smb3structs as smb2
    from impacket.nt_errors import STATUS_ACCESS_DENIED

    def probe(records):
        for port in (1445, 1446):
            client = _smb(module, port)
            try:
                if port == 1445:
                    client.login("", "")
                else:
                    credentials = next(record for record in records if record["port"] == port)
                    client.login(credentials["username"], credentials["password"])
                for path in (office.PROOF_NAME, "new.txt"):
                    with pytest.raises(module.SessionError) as error:
                        client.putFile("TRAINING", path, io.BytesIO(b"forbidden").read)
                    assert error.value.getErrorCode() == STATUS_ACCESS_DENIED
                tree = client.connectTree("TRAINING")
                handle = client.openFile(tree, office.PROOF_NAME, desiredAccess=smb2.FILE_READ_DATA)
                try:
                    with pytest.raises(module.SessionError) as error:
                        client.writeFile(tree, handle, b"forbidden")
                    assert error.value.getErrorCode() == STATUS_ACCESS_DENIED
                    with pytest.raises(module.SessionError) as error:
                        client.setInfo(tree, handle, smb2.SMB2_FILE_BASIC_INFO, b"\x00" * 40)
                    assert error.value.getErrorCode() == STATUS_ACCESS_DENIED
                finally:
                    client.closeFile(tree, handle)
                for operation in (
                    lambda: client.deleteFile("TRAINING", office.PROOF_NAME),
                    lambda: client.rename("TRAINING", office.PROOF_NAME, "renamed.txt"),
                    lambda: client.createDirectory("TRAINING", "new-directory"),
                    lambda: client.getFile("TRAINING", "../outside.txt", lambda data: None),
                ):
                    with pytest.raises(module.SessionError):
                        operation()
            finally:
                client.close()

    async def run():
        async with office.start(tmp_path / "office") as records:
            await asyncio.to_thread(probe, records)
        _assert_closed()

    (tmp_path / "outside.txt").write_bytes(b"must never be served")
    asyncio.run(run())
    assert list((tmp_path / "office").iterdir()) == [tmp_path / "office" / office.PROOF_NAME]
    assert (tmp_path / "office" / office.PROOF_NAME).read_bytes() == office.PROOF


@runtime
def test_smb_connection_admission_and_reuse(tmp_path, dependencies, smb_servers):
    module = dependencies[1]

    def probe(records):
        for port in (1445, 1446):
            server = smb_servers[port]
            credentials = next(record for record in records if record["port"] == port)

            def connect():
                client = _smb(module, port)
                try:
                    client.login(credentials.get("username", ""), credentials.get("password", ""))
                except BaseException:
                    client.close()
                    raise
                return client

            with ExitStack() as stack:
                clients = [connect() for _ in range(office.SMB_MAX_CONNECTIONS)]
                for client in clients:
                    stack.callback(client.close)
                assert _client_count(server) == office.SMB_MAX_CONNECTIONS
                workers = {thread for thread in server._threads if thread.is_alive()}
                assert len(workers) == office.SMB_MAX_CONNECTIONS
                for _ in range(3):
                    with socket.create_connection((office.HOST, port), timeout=2) as rejected:
                        assert rejected.recv(1) == b""
                assert _client_count(server) == office.SMB_MAX_CONNECTIONS
                assert {thread for thread in server._threads if thread.is_alive()} == workers

                clients[0].close()
                _wait_until(lambda: _client_count(server) == office.SMB_MAX_CONNECTIONS - 1)
                replacement = connect()
                stack.callback(replacement.close)
                assert _client_count(server) == office.SMB_MAX_CONNECTIONS
                data = bytearray()
                replacement.getFile("TRAINING", office.PROOF_NAME, data.extend)
                assert data == office.PROOF
            _wait_until(lambda: _client_count(server) == 0)

    async def run():
        async with office.start(tmp_path) as records:
            await asyncio.to_thread(probe, records)
        _assert_closed()

    asyncio.run(run())


@runtime
def test_smb_duplicate_open_ceiling_and_disconnect_closes_fds(
    tmp_path, dependencies, smb_servers, monkeypatch
):
    module = dependencies[1]
    from impacket.nt_errors import STATUS_INSUFF_SERVER_RESOURCES
    from impacket.smb3structs import FILE_READ_DATA

    opened = set()
    lock = threading.Lock()
    original_open, original_close = os.open, os.close

    def record_open(path, *args, **kwargs):
        handle = original_open(path, *args, **kwargs)
        if os.fspath(path) == str(tmp_path / office.PROOF_NAME):
            with lock:
                opened.add(handle)
        return handle

    def record_close(handle):
        original_close(handle)
        with lock:
            opened.discard(handle)

    def open_count():
        with lock:
            return len(opened)

    monkeypatch.setattr(os, "open", record_open)
    monkeypatch.setattr(os, "close", record_close)

    def probe(records):
        for port in (1445, 1446):
            credentials = next(record for record in records if record["port"] == port)
            client = _smb(module, port)
            try:
                client.login(credentials.get("username", ""), credentials.get("password", ""))
                tree = client.connectTree("TRAINING")
                handles = [
                    client.openFile(tree, office.PROOF_NAME, desiredAccess=FILE_READ_DATA)
                    for _ in range(office.SMB_MAX_OPEN_FILES)
                ]
                assert len(set(handles)) == office.SMB_MAX_OPEN_FILES
                assert open_count() == office.SMB_MAX_OPEN_FILES
                for _ in range(3):
                    with pytest.raises(module.SessionError) as error:
                        client.openFile(tree, office.PROOF_NAME, desiredAccess=FILE_READ_DATA)
                    assert error.value.getErrorCode() == STATUS_INSUFF_SERVER_RESOURCES
                    assert open_count() == office.SMB_MAX_OPEN_FILES
                client.closeFile(tree, handles.pop())
                assert open_count() == office.SMB_MAX_OPEN_FILES - 1
                handles.append(
                    client.openFile(tree, office.PROOF_NAME, desiredAccess=FILE_READ_DATA)
                )
                assert (
                    client.readFile(tree, handles[-1], bytesToRead=len(office.PROOF))
                    == office.PROOF
                )
                assert open_count() == office.SMB_MAX_OPEN_FILES
                # Drop transport with eight live handles, without SMB CLOSEs.
                client.getSMBServer().close_session()
                _wait_until(lambda: _client_count(smb_servers[port]) == 0)
                assert open_count() == 0
            finally:
                client.close()

    async def run():
        async with office.start(tmp_path) as records:
            await asyncio.to_thread(probe, records)
        _assert_closed()

    asyncio.run(run())


@runtime
def test_smb_idle_timeout_releases_admission_slot(tmp_path, dependencies, smb_servers, monkeypatch):
    monkeypatch.setattr(office, "SMB_READ_TIMEOUT", 0.25)

    def probe():
        server = smb_servers[1445]
        with socket.create_connection((office.HOST, 1445), timeout=2) as idle:
            _wait_until(lambda: _client_count(server) == 1)
            # Partial packet input must expire as well as a silent client.
            idle.sendall(b"\x00\x00")
            assert idle.recv(1) == b""
        _wait_until(lambda: _client_count(server) == 0)
        assert server.connection_slots.acquire(blocking=False)
        server.connection_slots.release()

    async def run():
        async with office.start(tmp_path):
            await asyncio.to_thread(probe)
        _assert_closed()

    asyncio.run(run())


@runtime
def test_ftp_connection_limit_and_slot_reuse(tmp_path, dependencies):
    def probe():
        with ExitStack() as stack:
            clients = []
            for _ in range(office.FTP_MAX_PER_IP):
                client = _ftp(2121)
                stack.callback(client.close)
                client.login()
                clients.append(client)
            with pytest.raises(ftplib.error_temp, match="421"):
                with _ftp(2121):
                    pass
            clients[0].quit()
            with _ftp(2121) as replacement:
                replacement.login()
                data = bytearray()
                replacement.retrbinary(f"RETR {office.PROOF_NAME}", data.extend)
                assert data == office.PROOF

    async def run():
        async with office.start(tmp_path):
            await asyncio.to_thread(probe)
        _assert_closed()

    asyncio.run(run())


@runtime
def test_ssh_admission_limit_and_connection_lifetime(tmp_path, dependencies, monkeypatch):
    asyncssh = dependencies[0]
    monkeypatch.setattr(office, "SSH_MAX_CONNECTIONS", 2)

    async def run():
        async with office.start(tmp_path):
            options = dict(
                host=office.HOST,
                port=2222,
                username="admin",
                password="admin",
                known_hosts=None,
                agent_path=None,
                client_keys=[],
            )
            async with asyncssh.connect(**options) as first:
                async with asyncssh.connect(**options):
                    with pytest.raises((asyncssh.ConnectionLost, ConnectionResetError)):
                        await asyncssh.connect(**options)
                # A completed disconnect must free capacity for another client.
                async with asyncssh.connect(**options):
                    assert not first.is_closed()
            monkeypatch.setattr(office, "SSH_CONNECTION_TTL", 0.25)
            async with asyncssh.connect(**options) as expiring:
                await asyncio.wait_for(expiring.wait_closed(), 2)
                assert expiring.is_closed()
        _assert_closed()

    asyncio.run(run())


@runtime
@pytest.mark.parametrize("conflict_port", [2122, 2223, 1446])
def test_port_conflict_rolls_back_every_listener(tmp_path, dependencies, conflict_port):
    async def run():
        with socket.socket() as occupied:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                occupied.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            occupied.bind((office.HOST, conflict_port))
            occupied.listen()
            with pytest.raises(OSError):
                async with office.start(tmp_path):
                    pytest.fail("A fixed service port was already occupied")
        _assert_closed()
        # A failed startup must leave the same root and all ports reusable.
        async with office.start(tmp_path):
            pass
        _assert_closed()

    asyncio.run(run())


@runtime
def test_shutdown_closes_active_clients_and_passive_listener(tmp_path, dependencies):
    asyncssh, module, _ = dependencies

    async def run():
        ftp = smb = ssh = None
        try:
            async with office.start(tmp_path):

                def connect_clients():
                    ftp = _ftp(2121)
                    ftp.login()
                    _, passive_port = ftp.makepasv()
                    smb = _smb(module, 1445)
                    smb.login("", "")
                    tree = smb.connectTree("TRAINING")
                    from impacket.smb3structs import FILE_READ_DATA

                    smb.openFile(tree, office.PROOF_NAME, desiredAccess=FILE_READ_DATA)
                    return ftp, smb, passive_port

                ftp, smb, passive_port = await asyncio.to_thread(connect_clients)
                assert passive_port in office.PASSIVE_PORTS
                ssh = await asyncssh.connect(
                    office.HOST,
                    2222,
                    username="admin",
                    password="admin",
                    known_hosts=None,
                    agent_path=None,
                    client_keys=[],
                )
            await asyncio.wait_for(ssh.wait_closed(), 2)
            assert ssh.is_closed()
            assert await asyncio.to_thread(ftp.sock.recv, 1024) == b""
            assert await asyncio.to_thread(smb.getSMBServer().get_socket().recv, 1024) == b""
            _assert_closed()
        finally:
            if ftp:
                ftp.close()
            if smb:
                await asyncio.to_thread(smb.close)
            if ssh:
                ssh.abort()

    asyncio.run(run())


@pytest.mark.parametrize("contents", [b"user file", b"VulnAssess office network proof\nextra"])
def test_fixture_rejects_nonfictional_contents(tmp_path, contents):
    (tmp_path / office.PROOF_NAME).write_bytes(contents)
    with pytest.raises(ValueError, match="exact lab proof"):
        office._fixture(tmp_path)
    assert (tmp_path / office.PROOF_NAME).read_bytes() == contents


def test_fixture_rejects_extra_files_and_hardlinks(tmp_path):
    (tmp_path / "private.txt").write_bytes(b"user file")
    with pytest.raises(ValueError, match="exact lab proof"):
        office._fixture(tmp_path)
    (tmp_path / "private.txt").unlink()
    source = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    source.write_bytes(office.PROOF)
    try:
        os.link(source, tmp_path / office.PROOF_NAME)
        with pytest.raises(ValueError, match="exact lab proof"):
            office._fixture(tmp_path)
    finally:
        source.unlink()
