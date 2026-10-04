"""Servidor IMAP falso (en memoria) que imita la API de `imapclient.IMAPClient` usada por el conector.

Simula: capacidades (IDLE, STARTTLS, X-GM-EXT-1), login por password/XOAUTH2, SELECT/EXAMINE con
UIDVALIDITY/UIDNEXT/PERMANENTFLAGS, SEARCH (incluida la rareza de "N:*" de RFC 3501), FETCH con
BODY.PEEK[] y BODY.PEEK[HEADER] parciales (y marca \\Seen si se usa BODY[] sin PEEK en modo
lectura-escritura, como un server real), IDLE con avisos EXISTS, STORE de flags/labels, y fallas
inyectables por método.
"""

from __future__ import annotations

import re
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime

from imapclient.exceptions import CapabilityError, IMAPClientError, LoginError

DEFAULT_PERMANENTFLAGS = (b"\\Answered", b"\\Flagged", b"\\Deleted", b"\\Seen", b"\\Draft", b"\\*")


def eml(subject: str = "Hola", body: str = "Texto", size: int | None = None) -> bytes:
    msg = (
        f"From: Juan <juan@proveedor.com>\r\nTo: ventas@empresa.com\r\nSubject: {subject}\r\n"
        f"Message-ID: <{subject.replace(' ', '-')}@proveedor.com>\r\n\r\n{body}\r\n"
    ).encode()
    if size is not None and size > len(msg):
        msg += b"x" * (size - len(msg))
    return msg


def header_of(raw: bytes) -> bytes:
    """Como un server real para BODY[HEADER]: los headers con la línea en blanco que los cierra."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        i = raw.find(sep)
        if i >= 0:
            return raw[: i + len(sep)]
    return raw + b"\r\n"


@dataclass
class FakeMsg:
    raw: bytes
    internaldate: datetime
    flags: set[bytes] = field(default_factory=set)
    labels: set[str] = field(default_factory=set)
    size_override: int | None = None


@dataclass
class FakeFolder:
    uidvalidity: int = 1000
    uidnext: int = 1
    messages: dict[int, FakeMsg] = field(default_factory=dict)
    permanentflags: tuple[bytes, ...] | None = DEFAULT_PERMANENTFLAGS


class _FakeImaplib:
    def __init__(self) -> None:
        self.untagged_responses: dict = {}


class FakeServer:
    def __init__(
        self,
        *,
        capabilities: tuple[bytes, ...] = (b"IMAP4REV1", b"IDLE", b"UIDPLUS"),
        password: str = "app-pass",
        tokens: tuple[str, ...] = (),
        folders: tuple[str, ...] = ("INBOX",),
    ) -> None:
        self.lock = threading.RLock()
        self.capabilities = set(capabilities)
        self.password = password
        self.tokens = set(tokens)
        self.folders: dict[str, FakeFolder] = {f: FakeFolder() for f in folders}
        self.clients: list[FakeIMAPClientBase] = []
        self.calls: list[tuple[int, str, tuple]] = []
        self.failures: dict[str, list[BaseException]] = defaultdict(list)
        self.send_uidnext = True
        self.fail_body_uids: set[int] = set()
        self.gmail_label_must_exist = False
        self.created_folders: list[str] = []
        self._client_class: type[FakeIMAPClientBase] | None = None

    # ------------------------------------------------------------ control desde el test

    def deliver(
        self,
        folder: str = "INBOX",
        raw: bytes | None = None,
        *,
        internaldate: datetime | None = None,
        size_override: int | None = None,
    ) -> int:
        with self.lock:
            f = self.folders[folder]
            uid = f.uidnext
            f.uidnext += 1
            f.messages[uid] = FakeMsg(
                raw if raw is not None else eml(f"mail {uid}"),
                internaldate or datetime.now(UTC),
                size_override=size_override,
            )
            for c in self.clients:
                if c.closed or c.selected != folder:
                    continue
                if c.idling:
                    c.notify.set()
                else:
                    c._imap.untagged_responses.setdefault("EXISTS", []).append(str(len(f.messages)).encode())
        return uid

    def renumber(self, folder: str = "INBOX", new_validity: int = 2000) -> None:
        """Simula que el servidor regeneró la carpeta (UIDVALIDITY nuevo, UIDs nuevos)."""
        with self.lock:
            f = self.folders[folder]
            msgs = [f.messages[u] for u in sorted(f.messages)]
            f.uidvalidity = new_validity
            f.messages = {i + 1: m for i, m in enumerate(msgs)}
            f.uidnext = len(msgs) + 1

    def fail(self, method: str, exc: BaseException, times: int = 1) -> None:
        with self.lock:
            self.failures[method].extend([exc] * times)

    def maybe_fail(self, method: str) -> None:
        with self.lock:
            pending = self.failures.get(method)
            if pending:
                raise pending.pop(0)

    def record(self, client: FakeIMAPClientBase, method: str, *args) -> None:
        with self.lock:
            self.calls.append((client.cid, method, args))

    def calls_of(self, method: str) -> list[tuple[int, str, tuple]]:
        with self.lock:
            return [c for c in self.calls if c[1] == method]

    @property
    def client_class(self) -> type[FakeIMAPClientBase]:
        """Clase (una por server, cacheada) que reemplaza a `IMAPClient`; se puede parchear por test."""
        if self._client_class is None:
            server = self

            class FakeIMAPClient(FakeIMAPClientBase):
                def __init__(
                    self,
                    host,
                    port=None,
                    use_uid=True,
                    ssl=True,
                    stream=False,
                    ssl_context=None,
                    timeout=None,
                ):
                    super().__init__(server, host, port, use_uid, ssl, ssl_context, timeout)

            self._client_class = FakeIMAPClient
        return self._client_class


class FakeIMAPClientBase:
    def __init__(self, server: FakeServer, host, port, use_uid, ssl, ssl_context, timeout) -> None:
        self.server = server
        self.host, self.port, self.use_uid, self.ssl = host, port, use_uid, ssl
        self.ssl_context = ssl_context
        self.timeout = timeout
        self.starttls_context = None
        self.selected: str | None = None
        self.readonly: bool | None = None
        self.idling = False
        self.logged_in = False
        self.closed = False
        self.normalise_times = True
        self.notify = threading.Event()
        self._imap = _FakeImaplib()
        server.maybe_fail("connect")
        with server.lock:
            self.cid = len(server.clients)
            server.clients.append(self)
        server.record(self, "connect", host, port, ssl)

    # ------------------------------------------------------------ helpers

    def _folder(self) -> FakeFolder:
        if not self.logged_in:
            raise IMAPClientError("command illegal in state NONAUTH")
        if self.selected is None:
            raise IMAPClientError("no folder selected")
        return self.server.folders[self.selected]

    # ------------------------------------------------------------ conexión / auth

    def socket(self):
        return None

    def starttls(self, ssl_context=None):
        self.server.record(self, "starttls")
        if b"STARTTLS" not in self.server.capabilities:
            raise CapabilityError("Server does not support STARTTLS capability")
        self.starttls_context = ssl_context
        return b"Begin TLS negotiation now"

    def login(self, username, password):
        self.server.record(self, "login", username)  # nunca registrar el password
        self.server.maybe_fail("login")
        f"LOGIN {username} {password}".encode("ascii")  # como imaplib: UnicodeEncodeError si no es ASCII
        if password != self.server.password:
            raise LoginError("[AUTHENTICATIONFAILED] Invalid credentials (Failure)")
        self.logged_in = True
        return b"LOGIN completed"

    def oauth2_login(self, user, access_token, mech="XOAUTH2", vendor=None):
        self.server.record(self, "oauth2_login", user, access_token)
        if access_token not in self.server.tokens:
            raise LoginError("AUTHENTICATE failed.")
        self.logged_in = True
        return b"AUTHENTICATE completed"

    def capabilities(self):
        return tuple(sorted(self.server.capabilities))

    def has_capability(self, capability):
        cap = capability.encode() if isinstance(capability, str) else capability
        return cap.upper() in self.server.capabilities

    def logout(self):
        self.server.record(self, "logout")
        self.closed = True
        self.idling = False
        return b"LOGOUT completed"

    def shutdown(self):
        self.server.record(self, "shutdown")
        self.closed = True
        self.idling = False

    # ------------------------------------------------------------ carpetas

    def select_folder(self, folder, readonly=False):
        self.server.record(self, "select", folder, readonly)
        self.server.maybe_fail("select")
        if not self.logged_in:
            raise IMAPClientError("command illegal in state NONAUTH")
        with self.server.lock:
            if folder not in self.server.folders:
                raise IMAPClientError("select failed: [NONEXISTENT] Unknown Mailbox")
            f = self.server.folders[folder]
            self.selected, self.readonly = folder, readonly
            self._imap.untagged_responses = {"EXISTS": [str(len(f.messages)).encode()]}
            out = {
                b"EXISTS": len(f.messages),
                b"RECENT": 0,
                b"FLAGS": (b"\\Answered", b"\\Flagged", b"\\Deleted", b"\\Seen", b"\\Draft"),
                b"UIDVALIDITY": f.uidvalidity,
            }
            if self.server.send_uidnext:
                out[b"UIDNEXT"] = f.uidnext
            if f.permanentflags is not None:
                out[b"PERMANENTFLAGS"] = f.permanentflags
            if not readonly:
                out[b"READ-WRITE"] = True
            return out

    def folder_status(self, folder, what=None):
        self.server.record(self, "status", folder, tuple(what or ()))
        with self.server.lock:
            f = self.server.folders[folder]
            return {b"MESSAGES": len(f.messages), b"UIDNEXT": f.uidnext, b"UIDVALIDITY": f.uidvalidity}

    def create_folder(self, folder):
        self.server.record(self, "create", folder)
        self.server.created_folders.append(folder)
        return b"CREATE completed"

    # ------------------------------------------------------------ búsqueda / descarga

    def search(self, criteria="ALL", charset=None):
        crit = [criteria] if isinstance(criteria, str) else list(criteria)
        self.server.record(self, "search", tuple(crit))
        self.server.maybe_fail("search")
        with self.server.lock:
            f = self._folder()
            uids = sorted(f.messages)
            key = str(crit[0]).upper()
            if key == "ALL":
                return uids
            if key == "UID":
                spec = str(crit[1])
                if spec == "*":
                    return [uids[-1]] if uids else []
                if spec.endswith(":*"):
                    start = int(spec[:-2])
                    res = [u for u in uids if u >= start]
                    if not res and uids:
                        res = [uids[-1]]  # RFC 3501: "*" es el UID más alto, el rango no tiene orden
                    return res
                n = int(spec)
                return [n] if n in f.messages else []
            if key == "SINCE":
                d = crit[1]
                assert isinstance(d, date)
                return [u for u in uids if f.messages[u].internaldate.date() >= d]
            raise IMAPClientError(f"SEARCH no soportado por el fake: {crit}")

    def fetch(self, messages, data, modifiers=None):
        uids = [int(m) for m in messages]
        items = [str(d) for d in data]
        self.server.record(self, "fetch", tuple(uids), tuple(items))
        self.server.maybe_fail("fetch")
        out = {}
        with self.server.lock:
            f = self._folder()
            for seq, uid in enumerate(uids, start=1):
                msg = f.messages.get(uid)
                if msg is None:
                    continue
                item: dict = {b"SEQ": seq}
                for d in items:
                    du = d.upper()
                    if du == "RFC822.SIZE":
                        item[b"RFC822.SIZE"] = (
                            msg.size_override if msg.size_override is not None else len(msg.raw)
                        )
                    elif du == "INTERNALDATE":
                        dt = msg.internaldate
                        item[b"INTERNALDATE"] = (
                            dt.astimezone().replace(tzinfo=None) if self.normalise_times else dt
                        )
                    elif du.startswith("BODY.PEEK[HEADER]"):
                        if uid in self.server.fail_body_uids:
                            raise IMAPClientError(f"FETCH failed for UID {uid}")
                        header = header_of(msg.raw)
                        m = re.fullmatch(r"BODY\.PEEK\[HEADER\]<(\d+)\.(\d+)>", du)
                        if m:
                            start, count = int(m.group(1)), int(m.group(2))
                            item[f"BODY[HEADER]<{start}>".encode()] = header[start : start + count]
                        else:
                            item[b"BODY[HEADER]"] = header
                    elif du.startswith("BODY.PEEK[]"):
                        if uid in self.server.fail_body_uids:
                            raise IMAPClientError(f"FETCH failed for UID {uid}")
                        m = re.fullmatch(r"BODY\.PEEK\[\]<(\d+)\.(\d+)>", du)
                        if m:
                            start, count = int(m.group(1)), int(m.group(2))
                            item[f"BODY[]<{start}>".encode()] = msg.raw[start : start + count]
                        else:
                            item[b"BODY[]"] = msg.raw
                    elif du in ("BODY[]", "RFC822"):
                        item[b"BODY[]"] = msg.raw
                        if not self.readonly:
                            msg.flags.add(b"\\Seen")  # un server real marca leído sin PEEK
                    elif du == "FLAGS":
                        item[b"FLAGS"] = tuple(sorted(msg.flags))
                out[uid] = item
        return out

    # ------------------------------------------------------------ IDLE / NOOP

    def idle(self):
        self.server.record(self, "idle")
        if b"IDLE" not in self.server.capabilities:
            raise CapabilityError("Server does not support IDLE capability")
        self._folder()
        self.server.maybe_fail("idle")
        self.idling = True

    def idle_check(self, timeout=None):
        self.server.maybe_fail("idle_check")
        if not self.idling:
            raise IMAPClientError("not in IDLE")
        fired = self.notify.wait(timeout if timeout is not None else 5.0)
        if fired:
            self.notify.clear()
            with self.server.lock:
                n = len(self.server.folders[self.selected].messages)
            return [(n, b"EXISTS")]
        return []

    def idle_done(self):
        self.server.record(self, "idle_done")
        self.idling = False
        return (b"IDLE terminated", [])

    def noop(self):
        self.server.record(self, "noop")
        self.server.maybe_fail("noop")
        return (b"NOOP completed", [])

    # ------------------------------------------------------------ STORE

    def add_flags(self, messages, flags, silent=False):
        self.server.record(self, "add_flags", tuple(messages), tuple(flags), self.readonly)
        with self.server.lock:
            f = self._folder()
            if self.readonly:
                raise IMAPClientError("STORE failed: mailbox is read-only")
            for uid in messages:
                if uid in f.messages:
                    f.messages[uid].flags.update(fl.encode() if isinstance(fl, str) else fl for fl in flags)
        return None

    def add_gmail_labels(self, messages, labels, silent=False):
        self.server.record(self, "add_gmail_labels", tuple(messages), tuple(labels))
        if b"X-GM-EXT-1" not in self.server.capabilities:
            raise CapabilityError("Server does not support X-GM-EXT-1 capability")
        with self.server.lock:
            f = self._folder()
            if self.readonly:
                raise IMAPClientError("STORE failed: mailbox is read-only")
            for label in labels:
                if self.server.gmail_label_must_exist and label not in self.server.created_folders:
                    raise IMAPClientError("STORE failed: [NONEXISTENT] label")
            for uid in messages:
                if uid in f.messages:
                    f.messages[uid].labels.update(labels)
        return None
