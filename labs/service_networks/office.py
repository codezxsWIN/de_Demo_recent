"""Real, loopback-only FTP/SSH/SMB training services (optional dependencies)."""

from __future__ import annotations

import asyncio
import configparser
import os
import secrets
import socket
import threading
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager, suppress
from pathlib import Path

HOST = "127.0.0.2"
PROOF_NAME = "network-proof.txt"
PROOF = b"VulnAssess office network proof\n"
PORTS = (2121, 2122, 2222, 2223, 1445, 1446)
PASSIVE_PORTS = range(32200, 32210)
SMB_MAX_CONNECTIONS = 16  # Per listener, including unauthenticated clients.
SMB_MAX_OPEN_FILES = 8  # Per connection, including directory handles.
SMB_READ_TIMEOUT = 30
FTP_MAX_CONNECTIONS = 64  # Shared IOLoop descriptors, including data channels.
FTP_MAX_PER_IP = 16
FTP_IDLE_TIMEOUT = 30
SSH_MAX_CONNECTIONS = 16  # Shared by the two SSH listeners.
SSH_CONNECTION_TTL = 60


def _fixture(root: Path) -> Path:
    """Accept only an empty directory or our exact, single fictional fixture."""
    root = Path(os.path.abspath(root))
    for path in (root, *root.parents):
        if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
            raise ValueError("Office fixture directory must not contain links or junctions")
    root.mkdir(parents=True, exist_ok=True)
    entries = list(root.iterdir())
    proof = root / PROOF_NAME
    if entries:
        if (
            entries != [proof]
            or proof.is_symlink()
            or not proof.is_file()
            or proof.stat().st_nlink != 1
            or proof.stat().st_size != len(PROOF)
            or proof.read_bytes() != PROOF
        ):
            raise ValueError("Office root must be empty or contain only the exact lab proof file")
    else:
        with proof.open("xb") as stream:
            stream.write(PROOF)
    return root


class _FTPGroup:
    def __init__(self, loop):
        self.loop = loop
        self.stop = threading.Event()
        self.thread = None

    def start(self):
        def run():
            try:
                while not self.stop.is_set():
                    self.loop.loop(timeout=0.05, blocking=False)
            finally:
                self.loop.close()

        self.thread = threading.Thread(target=run, name="office-ftp", daemon=True)
        self.thread.start()

    async def close(self):
        self.stop.set()
        if self.thread is None:
            self.loop.close()
        else:
            await asyncio.to_thread(self.thread.join, 5)
            if self.thread.is_alive():
                raise RuntimeError("Office FTP thread did not stop")


def _smb_service(smbserver, smb, smb2, root, port, password, bind_host=HOST):
    """Adapt the audited Impacket 0.13.1 server lifecycle without RPC listeners.

    Upstream SimpleSMBServer.__init__ binds two private RPC sockets to 127.0.0.1,
    and stop() only calls server_close(), leaving serve_forever/clients alive.
    Initialise its underlying real SMBSERVER and config directly instead. All SMB
    negotiation, NTLM, tree, directory and read responses remain Impacket's own.
    No RPC helpers or named pipes are needed for the TRAINING disk share.
    """
    from impacket.nt_errors import (
        STATUS_ACCESS_DENIED,
        STATUS_INSUFF_SERVER_RESOURCES,
        STATUS_NOT_SUPPORTED,
        STATUS_SUCCESS,
    )

    class BoundedHandler(smbserver.SMBSERVERHandler):
        def handle(self):
            # The inherited handler overwrites socket timeouts for each packet
            # using this field; changing only socket.settimeout() is insufficient.
            self._SMBSERVERHandler__timeOut = SMB_READ_TIMEOUT
            super().handle()

    class ManagedServer(smbserver.SMBSERVER):
        def __init__(self, *args, **kwargs):
            self.clients = set()
            self.clients_lock = threading.Lock()
            self.connection_slots = threading.BoundedSemaphore(SMB_MAX_CONNECTIONS)
            self.ready = threading.Event()
            kwargs["handler_class"] = BoundedHandler
            super().__init__(*args, **kwargs)

        def service_actions(self):
            self.ready.set()

        def process_request(self, request, address):
            # Reject before ThreadingMixIn allocates a worker. Rejected sockets
            # never own a slot and therefore cannot release another client's.
            if not self.connection_slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            with self.clients_lock:
                self.clients.add(request)
            try:
                request.settimeout(SMB_READ_TIMEOUT)
                super().process_request(request, address)
            except BaseException:
                self.shutdown_request(request)
                # ThreadingMixIn appends the worker before start(); a failed
                # start must not leave an unjoinable entry for server_close().
                getattr(self._threads, "reap", lambda: None)()
                raise

        def shutdown_request(self, request):
            try:
                super().shutdown_request(request)
            finally:
                with self.clients_lock:
                    if request in self.clients:
                        self.clients.remove(request)
                        self.connection_slots.release()

        def removeConnection(self, name):
            # Impacket removes the connection record without closing open FDs.
            with suppress(Exception):
                data = self.getConnectionData(name, checkStatus=False)
                for opened in data.get("OpenedFiles", {}).values():
                    handle = opened.get("FileHandle", -1)
                    if handle >= 0:
                        with suppress(OSError):
                            os.close(handle)
            super().removeConnection(name)

    class OfficeSMBServer(smbserver.SimpleSMBServer):
        def __init__(self):
            config = configparser.ConfigParser()
            config.read_dict(
                {
                    "global": {
                        "server_name": "OFFICE-LAB",
                        "server_os": "Fictional training lab",
                        "server_domain": "TRAINING",
                        "log_file": "None",
                        "credentials_file": "",
                        "SMB2Support": "True",
                        "anonymous_logon": "no" if password else "yes",
                        "dump_hashes": "no",
                        "challenge": secrets.token_hex(8),
                    },
                    "TRAINING": {
                        "comment": "Fictional read-only office data",
                        "read only": "yes",
                        "share type": "0",
                        "path": str(root),
                    },
                }
            )
            # These are the two inherited SimpleSMBServer fields used by its
            # getServer(), addCredential(), and configuration setters.
            self._SimpleSMBServer__smbConfig = config
            self._SimpleSMBServer__server = ManagedServer((bind_host, port), config_parser=config)
            self.thread = None
            try:
                self.getServer().processConfigFile()
                if password:
                    from impacket.ntlm import compute_nthash

                    self.addCredential("auditor", 0, "", compute_nthash(password).hex())
                self._read_only_hooks()
            except BaseException:
                self.getServer().server_close()
                raise

        def _read_only_hooks(self):
            server = self.getServer()

            def session_setup(conn_id, server, packet):
                result = original_setup(conn_id, server, packet)
                data = server.getConnectionData(conn_id, checkStatus=False)
                # 0.13.1 unconditionally sets Authenticated=True even when
                # NTLM failed. Respect the actual authentication result.
                authenticated = result[2] == STATUS_SUCCESS
                if password:
                    authenticated = authenticated and data.get("user_name", "").lower() == "auditor"
                data["Authenticated"] = authenticated
                server.setConnectionData(conn_id, data)
                return result

            original_setup = server.hookSmb2Command(smb2.SMB2_SESSION_SETUP, session_setup)

            def deny_smb1(conn_id, server, command, packet, *extra):
                return [smb.SMBCommand(packet["Command"])], None, STATUS_NOT_SUPPORTED

            # Only SMB2 file access is offered; SMB1 negotiation may upgrade to
            # SMB2, but cannot select legacy mutation/authentication handlers.
            for command in range(256):
                if command != smb.SMB.SMB_COM_NEGOTIATE:
                    server.hookSmbCommand(command, deny_smb1)

            def deny_mutation(conn_id, server, packet):
                return [smb2.SMB2Error()], None, STATUS_ACCESS_DENIED

            def tree_connect(conn_id, server, packet):
                # Also check inside the handler: Impacket checks authentication
                # only once at the start of a compound SMB2 request.
                data = server.getConnectionData(conn_id, checkStatus=False)
                if not data.get("Authenticated"):
                    return deny_mutation(conn_id, server, packet)
                return original_tree(conn_id, server, packet)

            original_tree = server.hookSmb2Command(smb2.SMB2_TREE_CONNECT, tree_connect)

            for command in (smb2.SMB2_WRITE, smb2.SMB2_SET_INFO):
                server.hookSmb2Command(command, deny_mutation)

            write_access = (
                smb2.FILE_WRITE_DATA
                | smb2.FILE_APPEND_DATA
                | smb2.FILE_WRITE_EA
                | smb2.FILE_WRITE_ATTRIBUTES
                | smb2.DELETE
                | smb2.WRITE_DAC
                | smb2.WRITE_OWNER
                | smb2.GENERIC_WRITE
                | smb2.GENERIC_ALL
                | smb2.MAXIMUM_ALLOWED
            )

            def read_open(conn_id, server, packet):
                data = server.getConnectionData(conn_id, checkStatus=False)
                if not data.get("Authenticated"):
                    return deny_mutation(conn_id, server, packet)
                request = smb2.SMB2Create(packet["Data"])
                filename = request["Buffer"][: request["NameLength"]].decode("utf-16le")
                if (
                    filename not in ("", PROOF_NAME)
                    or request["CreateDisposition"] != smb2.FILE_OPEN
                    or request["DesiredAccess"] & write_access
                    or request["CreateOptions"] & smb2.FILE_DELETE_ON_CLOSE
                ):
                    return deny_mutation(conn_id, server, packet)
                # Requests for one connection run serially in its worker,
                # including compound CREATEs; check before opening an OS FD.
                if len(data.get("OpenedFiles", {})) >= SMB_MAX_OPEN_FILES:
                    return [smb2.SMB2Error()], None, STATUS_INSUFF_SERVER_RESOURCES
                return original_create(conn_id, server, packet)

            # Upstream readOnly=yes prevents data writes but not every metadata
            # mutation (e.g. FILE_BASIC_INFO). Deny these explicitly above.
            original_create = server.hookSmb2Command(smb2.SMB2_CREATE, read_open)

        def start(self):
            self.thread = threading.Thread(
                target=self.getServer().serve_forever,
                kwargs={"poll_interval": 0.05},
                name=f"office-smb-{port}",
                daemon=True,
            )
            self.thread.start()

        async def close(self):
            server = self.getServer()
            if self.thread is not None:
                # Wait for the serving loop before shutdown(), which otherwise
                # can deadlock if called before serve_forever() begins.
                if not await asyncio.to_thread(server.ready.wait, 5):
                    raise RuntimeError("Office SMB serving loop failed to start")
                await asyncio.to_thread(server.shutdown)
                with server.clients_lock:
                    clients = list(server.clients)
                for client in clients:
                    with suppress(OSError):
                        client.shutdown(socket.SHUT_RDWR)
                    client.close()
                await asyncio.to_thread(self.thread.join, 5)
            await asyncio.to_thread(server.server_close)
            if self.thread is not None and self.thread.is_alive():
                raise RuntimeError("Office SMB thread did not stop")

    return OfficeSMBServer()


@asynccontextmanager
async def start(
    root: Path, *, bind_host: str = HOST, restrict_anonymous: bool = False
) -> AsyncIterator[list[dict[str, object]]]:
    """Yield six JSON-compatible service records; exit closes all connections.

    The caller must keep its asyncio loop running while using the services.
    Run synchronous clients/probes via asyncio.to_thread() or another process.
    Protected credentials are generated per startup and returned only as lab
    metadata; no host keys, client keys, or passwords are read from user files.
    """
    from .binding import validate

    validate(bind_host, HOST)
    try:
        import asyncssh
        from impacket import smb, smb3structs, smbserver
        from pyftpdlib.authorizers import DummyAuthorizer
        from pyftpdlib.handlers import FTPHandler
        from pyftpdlib.ioloop import IOLoop
        from pyftpdlib.servers import FTPServer
    except ImportError as exc:
        raise RuntimeError("Office labs require pyftpdlib, asyncssh, and impacket") from exc

    root = _fixture(root)
    ftp_password = secrets.token_urlsafe(24)
    smb_password = secrets.token_urlsafe(24)
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    ssh_connections = set()
    ssh_listeners = []

    class LabSSH(asyncssh.SSHServer):
        def __init__(self, protected):
            self.protected = protected

        def connection_made(self, connection):
            self.connection = connection
            self.expiry = None
            if len(ssh_connections) >= SSH_MAX_CONNECTIONS:
                connection.abort()
                return
            ssh_connections.add(connection)
            # These authentication-only endpoints need no long-lived sessions.
            # A hard lifetime also bounds idle authenticated connections.
            self.expiry = asyncio.get_running_loop().call_later(
                SSH_CONNECTION_TTL, connection.abort
            )

        def connection_lost(self, exc):
            if self.expiry is not None:
                self.expiry.cancel()
            ssh_connections.discard(self.connection)

        def begin_auth(self, username):
            return True

        def password_auth_supported(self):
            return not self.protected

        def validate_password(self, username, password):
            return not self.protected and username == "admin" and password == "admin"

        def public_key_auth_supported(self):
            return self.protected

        def validate_public_key(self, username, key):
            return (
                self.protected and username == "auditor" and key == client_key.convert_to_public()
            )

        # SSHServer's default session, subsystem, TCP/UNIX forwarding and
        # listener callbacks all reject requests. No process/SFTP factory.

    async def close_ssh_clients():
        for listener in ssh_listeners:
            listener.close()
        connections = list(ssh_connections)
        for connection in connections:
            connection.abort()
        await asyncio.gather(*(connection.wait_closed() for connection in connections))
        # Python >=3.12 wait_closed() also waits for active connections, so
        # abort clients before awaiting listener shutdown.
        await asyncio.gather(*(listener.wait_closed() for listener in ssh_listeners))

    async with AsyncExitStack() as stack:
        ftp = _FTPGroup(IOLoop())
        stack.push_async_callback(ftp.close)

        class PassiveExhausted(Exception):
            pass

        class BoundedPassive(FTPHandler.passive_dtp):
            timeout = FTP_IDLE_TIMEOUT

            def bind(self, address):
                # pyftpdlib otherwise falls back to a random port when its
                # configured passive range is full.
                if (bind_host != "0.0.0.0" and address[0] != bind_host) or address[
                    1
                ] not in PASSIVE_PORTS:
                    self.close()
                    raise PassiveExhausted
                return super().bind(address)

        class BoundedData(FTPHandler.dtp_handler):
            timeout = FTP_IDLE_TIMEOUT

        for port, protected in ((2121, restrict_anonymous), (2122, True)):
            authorizer = DummyAuthorizer()
            if protected:
                authorizer.add_user("authorizedlab", ftp_password, str(root), perm="elr")
            else:
                authorizer.add_anonymous(str(root), perm="elr")

            class LabFTP(FTPHandler):
                passive_dtp = BoundedPassive
                dtp_handler = BoundedData
                passive_ports = PASSIVE_PORTS
                masquerade_address = None if bind_host == "0.0.0.0" else bind_host
                auth_failed_timeout = 0
                timeout = FTP_IDLE_TIMEOUT

                def ftp_PORT(self, line):
                    self.respond("502 Active FTP is disabled in this lab.")

                def ftp_EPRT(self, line):
                    self.respond("502 Active FTP is disabled in this lab.")

                def _make_epasv(self, extmode=False):
                    try:
                        super()._make_epasv(extmode)
                    except PassiveExhausted:
                        self.respond("425 Lab passive port range is busy.")

            LabFTP.authorizer = authorizer
            server = FTPServer((bind_host, port), LabFTP, ioloop=ftp.loop)
            server.max_cons = FTP_MAX_CONNECTIONS
            server.max_cons_per_ip = FTP_MAX_PER_IP
        ftp.start()

        stack.push_async_callback(close_ssh_clients)
        for port, protected in ((2222, False), (2223, True)):
            listener = await asyncssh.create_server(
                lambda protected=protected: LabSSH(protected),
                bind_host,
                port,
                server_host_keys=[host_key],
                config=None,
                authorized_client_keys=None,
                password_auth=not protected,
                public_key_auth=protected,
                kbdint_auth=False,
                host_based_auth=False,
                login_timeout=10,
            )
            ssh_listeners.append(listener)

        for port, password in ((1445, None), (1446, smb_password)):
            service = _smb_service(smbserver, smb, smb3structs, root, port, password, bind_host)
            stack.push_async_callback(service.close)
            service.start()
            if not await asyncio.to_thread(service.getServer().ready.wait, 5):
                raise RuntimeError("Office SMB serving loop failed to start")

        yield [
            {"host": bind_host, "port": 2121, "protocol": "ftp", "protected": restrict_anonymous},
            {
                "host": bind_host,
                "port": 2122,
                "protocol": "ftp",
                "protected": True,
                "username": "authorizedlab",
                "password": ftp_password,
            },
            {
                "host": bind_host,
                "port": 2222,
                "protocol": "ssh",
                "protected": False,
                "username": "admin",
                "password": "admin",
            },
            {
                "host": bind_host,
                "port": 2223,
                "protocol": "ssh",
                "protected": True,
                "username": "auditor",
                "private_key": client_key.export_private_key("openssh").decode("ascii"),
            },
            {
                "host": bind_host,
                "port": 1445,
                "protocol": "smb",
                "protected": False,
                "share": "TRAINING",
            },
            {
                "host": bind_host,
                "port": 1446,
                "protocol": "smb",
                "protected": True,
                "share": "TRAINING",
                "username": "auditor",
                "password": smb_password,
            },
        ]
