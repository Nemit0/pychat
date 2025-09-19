import sys
import os
import json
import socket
import ssl
import struct
import hashlib
import hmac
import time
import threading
import asyncio
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple, List
from datetime import datetime, timedelta, timezone

from PyQt6 import QtWidgets, QtCore, QtGui

# Optional but strongly recommended dependency for certificate generation.
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except Exception:
    x509 = None  # We'll show a clear error dialog if missing.


# ----------------------------- Utility / Storage ------------------------------

APP_NAME = "virtualoffice_secure_chat"
DEFAULT_PORT = 50050
CONFIG_DIR = os.path.join(os.path.expanduser("~"), f".{APP_NAME}")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
CERT_PATH = os.path.join(CONFIG_DIR, "server_cert.pem")
KEY_PATH = os.path.join(CONFIG_DIR, "server_key.pem")

# PBKDF2 params for password->key derivation
KDF_ITERATIONS = 200_000
KDF_KEYLEN = 32

DEFAULT_CONFIG = {
    "server": {
        "port": DEFAULT_PORT,
        "iterations": KDF_ITERATIONS,
        "password_salt_hex": "",
        "derived_key_hex": "",
    },
    "known_peers": [
        {"name": "Localhost", "host": "127.0.0.1", "port": DEFAULT_PORT}
    ],
    "trusted_certs": {}
}


def ensure_paths():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)


def load_config() -> dict:
    ensure_paths()
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(cfg: dict):
    ensure_paths()
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def random_salt(n: int = 16) -> bytes:
    return os.urandom(n)


def derive_key_from_password(password: str, salt: bytes, iterations: int = KDF_ITERATIONS, dklen: int = KDF_KEYLEN) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=dklen)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def human_timestamp() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def pack_frame(payload_bytes: bytes) -> bytes:
    return struct.pack("!I", len(payload_bytes)) + payload_bytes


async def read_exactly(reader: asyncio.StreamReader, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = await reader.read(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while reading")
        data += chunk
    return data


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    header = await read_exactly(reader, 4)
    (length,) = struct.unpack("!I", header)
    if length > 10_000_000:
        raise ValueError("Frame too large")
    return await read_exactly(reader, length)


def get_my_ip_addresses() -> List[str]:
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ":" not in ip and not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    if not ips:
        ips.add("127.0.0.1")
    return sorted(ips)


# ----------------------- TLS Certificate Management --------------------------

def ensure_self_signed_cert() -> Tuple[str, str]:
    """
    Create a self-signed certificate and key if they don't exist.
    Returns (cert_path, key_path).
    """
    if os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH):
        return CERT_PATH, KEY_PATH

    if x509 is None:
        raise RuntimeError(
            "The 'cryptography' package is required to generate a certificate.\n"
            "Add 'cryptography' to your Briefcase project's requirements."
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"XX"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Unknown"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Unknown"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"VirtualOffice"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"virtualoffice.local"),
    ])

    alt_names = [x509.DNSName(u"virtualoffice.local"), x509.DNSName(u"localhost")]
    for ip in get_my_ip_addresses():
        try:
            alt_names.append(x509.IPAddress(socket.inet_aton(ip) and socket.inet_ntoa(socket.inet_aton(ip)) and ip))  # simple check
        except Exception:
            pass

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())  # FIX: required serial number
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    )

    cert = builder.sign(key, hashes.SHA256())

    with open(KEY_PATH, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return CERT_PATH, KEY_PATH


def tls_server_context() -> ssl.SSLContext:
    cert_path, key_path = ensure_self_signed_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


def tls_client_context() -> ssl.SSLContext:
    # We perform our own TOFU fingerprint pinning; disable default cert verification.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def cert_fingerprint_sha256(ssl_object: ssl.SSLObject) -> str:
    der = ssl_object.getpeercert(binary_form=True)
    return hashlib.sha256(der).hexdigest()


# -------------------------- Protocol Messages --------------------------------
# Messages are JSON-encoded, length-prefixed (4-byte big-endian size).
# Server -> Client:
#   AUTH_INFO: {"type":"AUTH_INFO","server_salt_hex":"...","challenge_hex":"...","iterations":int,"server_name":"..."}
#   AUTH_OK:   {"type":"AUTH_OK"}
#   AUTH_FAIL: {"type":"AUTH_FAIL","reason":"..."}
#   CHAT:      {"type":"CHAT","text":"...","sender":"...","timestamp":"..."}
# Client -> Server:
#   AUTH_RESPONSE: {"type":"AUTH_RESPONSE","hmac_hex":"...","client_name":"...","challenge_hex":"..."}
#   CHAT:          {"type":"CHAT","text":"...","sender":"...","timestamp":"..."}


def dumps(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def loads(b: bytes) -> dict:
    return json.loads(b.decode("utf-8"))


# --------------------------- Async Server ------------------------------------

class ChatServer:
    """
    TLS-encrypted asyncio server with password challenge-response auth.
    Broadcasts chat messages to all authenticated clients.
    """

    def __init__(self, cfg: dict, ui_bus: "UiBus"):
        self.cfg = cfg
        self.ui_bus = ui_bus
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.server: Optional[asyncio.base_events.Server] = None
        self.clients: Dict[asyncio.StreamWriter, Dict] = {}
        self._server_name = "Server"

    def current_port(self) -> int:
        return int(self.cfg["server"].get("port", DEFAULT_PORT))

    def server_key_material(self) -> Tuple[bytes, bytes, int]:
        salt_hex = self.cfg["server"].get("password_salt_hex") or ""
        derived_hex = self.cfg["server"].get("derived_key_hex") or ""
        iterations = int(self.cfg["server"].get("iterations", KDF_ITERATIONS))
        if not salt_hex or not derived_hex:
            return b"", b"", iterations
        return bytes.fromhex(salt_hex), bytes.fromhex(derived_hex), iterations

    async def start(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop
        ctx = tls_server_context()
        self.server = await asyncio.start_server(
            client_connected_cb=self.handle_client,
            host="0.0.0.0",
            port=self.current_port(),
            ssl=ctx,
            start_serving=True,
        )
        addrs = ", ".join(str(sock.getsockname()) for sock in self.server.sockets)
        self.ui_bus.emit_server_started(addrs)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
            self.ui_bus.emit_server_stopped()
        for w in list(self.clients.keys()):
            try:
                w.close()
            except Exception:
                pass
        self.clients.clear()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        try:
            salt, derived_key, iterations = self.server_key_material()
            if not salt or not derived_key:
                await self.send_json(writer, {"type": "AUTH_FAIL", "reason": "Server password not set"})
                writer.close()
                return

            challenge = os.urandom(16)
            auth_info = {
                "type": "AUTH_INFO",
                "server_salt_hex": salt.hex(),
                "challenge_hex": challenge.hex(),
                "iterations": iterations,  # tell client the KDF rounds
                "server_name": self._server_name,
            }
            await self.send_json(writer, auth_info)

            frame = await read_frame(reader)
            msg = loads(frame)
            if msg.get("type") != "AUTH_RESPONSE":
                writer.close()
                return

            client_name = msg.get("client_name", "Client")
            hmac_hex = msg.get("hmac_hex", "")
            if not self.verify_hmac(derived_key, bytes.fromhex(msg.get("challenge_hex", challenge.hex())), hmac_hex):
                await self.send_json(writer, {"type": "AUTH_FAIL", "reason": "Invalid password"})
                writer.close()
                return

            await self.send_json(writer, {"type": "AUTH_OK"})
            self.clients[writer] = {"name": client_name, "peer": str(peer)}
            await self.broadcast_system(f"{client_name} joined from {peer}")

            while True:
                data = await read_frame(reader)
                payload = loads(data)
                if payload.get("type") == "CHAT":
                    text = payload.get("text", "")
                    sender = payload.get("sender", client_name)
                    ts = payload.get("timestamp", human_timestamp())
                    await self.broadcast_chat(text, sender, ts)
        except Exception:
            pass
        finally:
            info = self.clients.pop(writer, None)
            try:
                writer.close()
            except Exception:
                pass
            if info:
                await self.broadcast_system(f"{info['name']} left")

    def verify_hmac(self, derived_key: bytes, challenge: bytes, client_hmac_hex: str) -> bool:
        expected = hmac.new(derived_key, challenge, hashlib.sha256).digest().hex()
        return hmac.compare_digest(expected, client_hmac_hex)

    async def send_json(self, writer: asyncio.StreamWriter, obj: dict):
        data = dumps(obj)
        writer.write(pack_frame(data))
        await writer.drain()

    async def broadcast_chat(self, text: str, sender: str, timestamp: str):
        msg = {"type": "CHAT", "text": text, "sender": sender, "timestamp": timestamp}
        self.ui_bus.emit_chat_message(f"{timestamp} [{sender}] {text}")
        dead = []
        for w in self.clients:
            try:
                await self.send_json(w, msg)
            except Exception:
                dead.append(w)
        for w in dead:
            self.clients.pop(w, None)

    async def broadcast_system(self, text: str):
        ts = human_timestamp()
        await self.broadcast_chat(text, "System", ts)


# ---------------------------- Async Client -----------------------------------

class ChatClient:
    """
    TLS-encrypted asyncio client with TOFU fingerprint pinning and password challenge.
    """

    def __init__(self, cfg: dict, ui_bus: "UiBus"):
        self.cfg = cfg
        self.ui_bus = ui_bus
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected_hostport: Optional[str] = None
        self._password_future: Optional[asyncio.Future] = None
        self.client_name = socket.gethostname()

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop

    def is_connected(self) -> bool:
        return self.writer is not None and not self.writer.is_closing()

    async def connect(self, host: str, port: int):
        await self.disconnect()
        ctx = tls_client_context()
        reader, writer = await asyncio.open_connection(host=host, port=port, ssl=ctx)
        ssl_obj: ssl.SSLObject = writer.get_extra_info("ssl_object")
        fp = cert_fingerprint_sha256(ssl_obj)
        key = f"{host}:{port}"
        trusted = self.cfg.get("trusted_certs", {})
        if key in trusted and trusted[key] != fp:
            writer.close()
            raise ConnectionError("Certificate fingerprint mismatch. Aborting connection.")
        elif key not in trusted:
            trusted[key] = fp
            self.cfg["trusted_certs"] = trusted
            save_config(self.cfg)

        self.reader, self.writer = reader, writer
        self.connected_hostport = key

        frame = await read_frame(self.reader)
        msg = loads(frame)
        if msg.get("type") != "AUTH_INFO":
            await self.disconnect()
            raise ConnectionError("Server did not send AUTH_INFO")

        server_salt_hex = msg.get("server_salt_hex", "")
        challenge_hex = msg.get("challenge_hex", "")
        server_name = msg.get("server_name", "Server")
        iterations = int(msg.get("iterations", self.cfg["server"].get("iterations", KDF_ITERATIONS)))

        password = await self.request_password_from_ui(host, port, server_name)
        if password is None or password == "":
            await self.disconnect()
            raise ConnectionError("Password entry canceled")

        salt = bytes.fromhex(server_salt_hex)
        derived = derive_key_from_password(password, salt, iterations=iterations)
        chal = bytes.fromhex(challenge_hex)
        hmac_hex = hmac.new(derived, chal, hashlib.sha256).digest().hex()

        auth_resp = {"type": "AUTH_RESPONSE", "hmac_hex": hmac_hex, "client_name": self.client_name, "challenge_hex": challenge_hex}
        await self.send_json(auth_resp)

        frame2 = await read_frame(self.reader)
        msg2 = loads(frame2)
        if msg2.get("type") != "AUTH_OK":
            await self.disconnect()
            raise ConnectionError("Authentication failed")

        self.ui_bus.emit_connected(key)
        self.loop.create_task(self.read_loop())

    async def disconnect(self):
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass
        self.reader, self.writer = None, None
        if self.connected_hostport:
            self.ui_bus.emit_disconnected()
        self.connected_hostport = None

    async def read_loop(self):
        try:
            while self.reader and not self.reader.at_eof():
                frame = await read_frame(self.reader)
                msg = loads(frame)
                if msg.get("type") == "CHAT":
                    text = msg.get("text", "")
                    sender = msg.get("sender", "Unknown")
                    ts = msg.get("timestamp", human_timestamp())
                    # Avoid duplicate echo for our own messages.
                    if sender == self.client_name:
                        continue
                    self.ui_bus.emit_chat_message(f"{ts} [{sender}] {text}")
        except Exception:
            pass
        finally:
            await self.disconnect()

    async def send_chat(self, text: str, sender: Optional[str] = None):
        if not self.is_connected():
            raise ConnectionError("Not connected")
        msg = {
            "type": "CHAT",
            "text": text,
            "sender": sender or self.client_name,
            "timestamp": human_timestamp(),
        }
        await self.send_json(msg)

    async def send_json(self, obj: dict):
        data = dumps(obj)
        self.writer.write(pack_frame(data))
        await self.writer.drain()

    async def request_password_from_ui(self, host: str, port: int, server_name: str) -> Optional[str]:
        if not self.loop:
            raise RuntimeError("Loop not set")
        fut: asyncio.Future = self.loop.create_future()
        self._password_future = fut
        self.ui_bus.emit_password_required(f"Enter password for {server_name} at {host}:{port}")
        return await fut

    def submit_password_from_ui(self, password: Optional[str]):
        if self._password_future and not self._password_future.done():
            def _set():
                try:
                    self._password_future.set_result(password)
                except Exception:
                    pass
            if self.loop:
                self.loop.call_soon_threadsafe(_set)


# ------------------------------ UI Bus (Signals) -----------------------------

class UiBus(QtCore.QObject):
    chatMessage = QtCore.pyqtSignal(str)
    connected = QtCore.pyqtSignal(str)
    disconnected = QtCore.pyqtSignal()
    serverStarted = QtCore.pyqtSignal(str)
    serverStopped = QtCore.pyqtSignal()
    passwordRequired = QtCore.pyqtSignal(str)

    def emit_chat_message(self, text: str):
        self.chatMessage.emit(text)

    def emit_connected(self, hostport: str):
        self.connected.emit(hostport)

    def emit_disconnected(self):
        self.disconnected.emit()

    def emit_server_started(self, info: str):
        self.serverStarted.emit(info)

    def emit_server_stopped(self):
        self.serverStopped.emit()

    def emit_password_required(self, prompt: str):
        self.passwordRequired.emit(prompt)


# ------------------------------ Network Thread -------------------------------

class NetworkThread(QtCore.QThread):
    """
    Runs an asyncio event loop for server and client in a dedicated thread.
    """
    def __init__(self, cfg: dict, ui_bus: UiBus):
        super().__init__()
        self.cfg = cfg
        self.ui_bus = ui_bus
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.server = ChatServer(cfg, ui_bus)
        self.client = ChatClient(cfg, ui_bus)

    def run(self):
        asyncio.run(self._main())

    async def _main(self):
        self.loop = asyncio.get_running_loop()
        self.client.set_loop(self.loop)
        while True:
            await asyncio.sleep(0.1)

    # Server control
    def start_server(self):
        if not self.loop:
            return
        async def _start():
            await self.server.start(self.loop)
        asyncio.run_coroutine_threadsafe(_start(), self.loop)

    def stop_server(self):
        if not self.loop:
            return
        async def _stop():
            await self.server.stop()
        asyncio.run_coroutine_threadsafe(_stop(), self.loop)

    # Client control
    def connect_client(self, host: str, port: int):
        if not self.loop:
            return
        async def _connect():
            try:
                await self.client.connect(host, port)
            except Exception as e:
                self.ui_bus.emit_chat_message(f"{human_timestamp()} [System] Connect failed: {e}")
        asyncio.run_coroutine_threadsafe(_connect(), self.loop)

    def disconnect_client(self):
        if not self.loop:
            return
        async def _disc():
            try:
                await self.client.disconnect()
            except Exception:
                pass
        asyncio.run_coroutine_threadsafe(_disc(), self.loop)

    def send_chat(self, text: str, sender: Optional[str] = None):
        if not self.loop:
            return
        async def _send():
            try:
                await self.client.send_chat(text, sender=sender)
            except Exception as e:
                self.ui_bus.emit_chat_message(f"{human_timestamp()} [System] Send failed: {e}")
        asyncio.run_coroutine_threadsafe(_send(), self.loop)

    def submit_password_from_ui(self, password: Optional[str]):
        self.client.submit_password_from_ui(password)


# ------------------------------ GUI Components -------------------------------

class StatusIndicator(QtWidgets.QFrame):
    def __init__(self):
        super().__init__()
        self.setFixedSize(16, 16)
        self.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.setAutoFillBackground(False)
        self._color = QtGui.QColor("#cc3333")
        self.setToolTip("Disconnected")

    def set_connected(self, connected: bool):
        self._color = QtGui.QColor("#33aa33") if connected else QtGui.QColor("#cc3333")
        self.setToolTip("Connected" if connected else "Disconnected")
        self.update()

    def paintEvent(self, event: QtGui.QPaintEvent):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        p.setPen(QtCore.Qt.PenStyle.NoPen)
        p.setBrush(QtGui.QBrush(self._color))
        r = min(self.width(), self.height()) - 2
        p.drawEllipse((self.width() - r)//2, (self.height() - r)//2, r, r)
        p.end()


class KnownPeersPage(QtWidgets.QWidget):
    requestConnect = QtCore.pyqtSignal(str, int)

    def __init__(self, cfg: dict):
        super().__init__()
        self.cfg = cfg
        layout = QtWidgets.QVBoxLayout(self)
        self.table = QtWidgets.QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Name", "Host", "Port"])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        btns = QtWidgets.QHBoxLayout()
        self.btn_add = QtWidgets.QPushButton("Add")
        self.btn_edit = QtWidgets.QPushButton("Edit")
        self.btn_del = QtWidgets.QPushButton("Delete")
        self.btn_connect = QtWidgets.QPushButton("Connect")
        btns.addWidget(self.btn_add)
        btns.addWidget(self.btn_edit)
        btns.addWidget(self.btn_del)
        btns.addStretch()
        btns.addWidget(self.btn_connect)
        layout.addLayout(btns)

        self.btn_add.clicked.connect(self.add_peer)
        self.btn_edit.clicked.connect(self.edit_peer)
        self.btn_del.clicked.connect(self.del_peer)
        self.btn_connect.clicked.connect(self.connect_selected)

        self.refresh()

    def refresh(self):
        peers = self.cfg.get("known_peers", [])
        self.table.setRowCount(len(peers))
        for i, p in enumerate(peers):
            self.table.setItem(i, 0, QtWidgets.QTableWidgetItem(p.get("name", "")))
            self.table.setItem(i, 1, QtWidgets.QTableWidgetItem(p.get("host", "")))
            self.table.setItem(i, 2, QtWidgets.QTableWidgetItem(str(p.get("port", DEFAULT_PORT))))

    def add_peer(self):
        name, ok = QtWidgets.QInputDialog.getText(self, "Add Peer", "Name:")
        if not ok or not name:
            return
        host, ok = QtWidgets.QInputDialog.getText(self, "Add Peer", "Host/IP:")
        if not ok or not host:
            return
        port, ok = QtWidgets.QInputDialog.getInt(self, "Add Peer", "Port:", DEFAULT_PORT, 1, 65535, 1)
        if not ok:
            return
        peers = self.cfg.get("known_peers", [])
        peers.append({"name": name, "host": host, "port": port})
        self.cfg["known_peers"] = peers
        save_config(self.cfg)
        self.refresh()

    def edit_peer(self):
        row = self.table.currentRow()
        if row < 0:
            return
        peers = self.cfg.get("known_peers", [])
        p = peers[row]
        name, ok = QtWidgets.QInputDialog.getText(self, "Edit Peer", "Name:", text=p.get("name", ""))
        if not ok or not name:
            return
        host, ok = QtWidgets.QInputDialog.getText(self, "Edit Peer", "Host/IP:", text=p.get("host", ""))
        if not ok or not host:
            return
        port, ok = QtWidgets.QInputDialog.getInt(self, "Edit Peer", "Port:", int(p.get("port", DEFAULT_PORT)), 1, 65535, 1)
        if not ok:
            return
        peers[row] = {"name": name, "host": host, "port": port}
        self.cfg["known_peers"] = peers
        save_config(self.cfg)
        self.refresh()

    def del_peer(self):
        row = self.table.currentRow()
        if row < 0:
            return
        peers = self.cfg.get("known_peers", [])
        if 0 <= row < len(peers):
            peers.pop(row)
        self.cfg["known_peers"] = peers
        save_config(self.cfg)
        self.refresh()

    def connect_selected(self):
        row = self.table.currentRow()
        if row < 0:
            return
        peers = self.cfg.get("known_peers", [])
        p = peers[row]
        self.requestConnect.emit(p.get("host", "127.0.0.1"), int(p.get("port", DEFAULT_PORT)))


class ServerChatPage(QtWidgets.QWidget):
    sendClicked = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        layout = QtWidgets.QVBoxLayout(self)
        self.chat_view = QtWidgets.QTextEdit()
        self.chat_view.setReadOnly(True)
        layout.addWidget(self.chat_view)
        h = QtWidgets.QHBoxLayout()
        self.input = QtWidgets.QLineEdit()
        self.btn_send = QtWidgets.QPushButton("Send")
        h.addWidget(self.input, 1)
        h.addWidget(self.btn_send)
        layout.addLayout(h)

        # Send message when Enter is pressed in the input field
        self.input.returnPressed.connect(self._send)

        self.btn_send.clicked.connect(self._send)

    def append_message(self, text: str):
        self.chat_view.append(text)

    def _send(self):
        text = self.input.text().strip()
        if text:
            self.sendClicked.emit(text)
            self.input.clear()


class DirectMessagesPage(QtWidgets.QWidget):
    requestConnect = QtCore.pyqtSignal(str, int)

    def __init__(self, default_port: int):
        super().__init__()
        layout = QtWidgets.QFormLayout(self)
        self.host_edit = QtWidgets.QLineEdit()
        self.port_spin = QtWidgets.QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(default_port)
        self.btn_connect = QtWidgets.QPushButton("Connect")
        layout.addRow("Host/IP:", self.host_edit)
        layout.addRow("Port:", self.port_spin)
        layout.addRow(self.btn_connect)
        self.btn_connect.clicked.connect(self._do_connect)

    def _do_connect(self):
        host = self.host_edit.text().strip()
        port = int(self.port_spin.value())
        if host:
            self.requestConnect.emit(host, port)


class ServerConfigPage(QtWidgets.QWidget):
    startServer = QtCore.pyqtSignal()
    stopServer = QtCore.pyqtSignal()

    def __init__(self, cfg: dict):
        super().__init__()
        self.cfg = cfg

        layout = QtWidgets.QVBoxLayout(self)

        form = QtWidgets.QFormLayout()
        self.port_spin = QtWidgets.QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(int(self.cfg["server"].get("port", DEFAULT_PORT)))
        self.btn_start = QtWidgets.QPushButton("Start Server")
        self.btn_stop = QtWidgets.QPushButton("Stop Server")
        self.status_lbl = QtWidgets.QLabel("Server not running")

        form.addRow("Listen Port:", self.port_spin)
        form.addRow(self.btn_start, self.btn_stop)
        form.addRow("Status:", self.status_lbl)
        layout.addLayout(form)

        group = QtWidgets.QGroupBox("Server Password")
        g_layout = QtWidgets.QFormLayout(group)
        self.btn_set_password = QtWidgets.QPushButton("Set / Change Password")
        g_layout.addRow(self.btn_set_password)
        layout.addWidget(group)

        ips_group = QtWidgets.QGroupBox("My IP Addresses")
        ips_layout = QtWidgets.QVBoxLayout(ips_group)
        self.ips_text = QtWidgets.QPlainTextEdit()
        self.ips_text.setReadOnly(True)
        ips_layout.addWidget(self.ips_text)
        layout.addWidget(ips_group)

        layout.addStretch()

        self.btn_start.clicked.connect(self.handle_start)
        self.btn_stop.clicked.connect(self.handle_stop)
        self.btn_set_password.clicked.connect(self.handle_set_password)
        self.port_spin.valueChanged.connect(self.handle_port_change)

        self.refresh_ips()

    def refresh_ips(self):
        ips = get_my_ip_addresses()
        self.ips_text.setPlainText("\n".join(f"{ip}:{self.port_spin.value()}" for ip in ips))

    def handle_port_change(self, val: int):
        self.cfg["server"]["port"] = int(val)
        save_config(self.cfg)
        self.refresh_ips()

    def handle_set_password(self):
        pw1, ok = QtWidgets.QInputDialog.getText(self, "Set Server Password", "Enter new password:", QtWidgets.QLineEdit.EchoMode.Password)
        if not ok or not pw1:
            return
        pw2, ok = QtWidgets.QInputDialog.getText(self, "Set Server Password", "Confirm new password:", QtWidgets.QLineEdit.EchoMode.Password)
        if not ok or pw1 != pw2:
            QtWidgets.QMessageBox.warning(self, "Password", "Password mismatch or canceled.")
            return
        salt = random_salt(16)
        derived = derive_key_from_password(pw1, salt, iterations=int(self.cfg["server"].get("iterations", KDF_ITERATIONS)))
        self.cfg["server"]["password_salt_hex"] = salt.hex()
        self.cfg["server"]["derived_key_hex"] = derived.hex()
        save_config(self.cfg)
        QtWidgets.QMessageBox.information(self, "Password", "Server password set successfully.")

    def handle_start(self):
        self.startServer.emit()

    def handle_stop(self):
        self.stopServer.emit()

    def set_status(self, text: str):
        self.status_lbl.setText(text)


# -------------------------------- Main Window --------------------------------

class virtualOffice(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("virtualoffice")
        self.resize(1000, 640)

        self.cfg = load_config()
        self.ui_bus = UiBus()
        self.net = NetworkThread(self.cfg, self.ui_bus)
        self.net.start()

        top_widget = QtWidgets.QWidget()
        top_layout = QtWidgets.QHBoxLayout(top_widget)
        self.indicator = StatusIndicator()
        self.conn_label = QtWidgets.QLabel("Disconnected")
        top_layout.addWidget(self.indicator)
        top_layout.addWidget(self.conn_label)
        top_layout.addStretch()

        nav = QtWidgets.QListWidget()
        nav.addItem("Known Addresses")
        nav.addItem("Server Chat")
        nav.addItem("Direct Messages")
        nav.addItem("My Server")
        nav.setFixedWidth(180)

        self.pages = QtWidgets.QStackedWidget()
        self.page_known = KnownPeersPage(self.cfg)
        self.page_chat = ServerChatPage()
        self.page_dm = DirectMessagesPage(default_port=int(self.cfg["server"].get("port", DEFAULT_PORT)))
        self.page_server = ServerConfigPage(self.cfg)
        self.pages.addWidget(self.page_known)
        self.pages.addWidget(self.page_chat)
        self.pages.addWidget(self.page_dm)
        self.pages.addWidget(self.page_server)

        central = QtWidgets.QWidget()
        main_layout = QtWidgets.QVBoxLayout(central)
        main_layout.addWidget(top_widget)
        body = QtWidgets.QHBoxLayout()
        body.addWidget(nav)
        body.addWidget(self.pages, 1)
        main_layout.addLayout(body)
        self.setCentralWidget(central)

        nav.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.page_known.requestConnect.connect(self.handle_connect)
        self.page_dm.requestConnect.connect(self.handle_connect)
        self.page_chat.sendClicked.connect(self.handle_send_chat)
        self.page_server.startServer.connect(self.handle_start_server)
        self.page_server.stopServer.connect(self.handle_stop_server)

        self.ui_bus.chatMessage.connect(self.page_chat.append_message)
        self.ui_bus.connected.connect(self.on_connected)
        self.ui_bus.disconnected.connect(self.on_disconnected)
        self.ui_bus.serverStarted.connect(self.on_server_started)
        self.ui_bus.serverStopped.connect(self.on_server_stopped)
        self.ui_bus.passwordRequired.connect(self.on_password_required)

        salt_hex = self.cfg["server"].get("password_salt_hex", "")
        derived_hex = self.cfg["server"].get("derived_key_hex", "")
        if not salt_hex or not derived_hex:
            QtWidgets.QMessageBox.information(self, "Setup",
                                              "Open 'My Server' and set a server password before others can connect.")

    def handle_connect(self, host: str, port: int):
        self.page_chat.append_message(f"{human_timestamp()} [System] Connecting to {host}:{port} ...")
        self.net.connect_client(host, port)

    def handle_send_chat(self, text: str):
        self.net.send_chat(text, sender=socket.gethostname())
        self.page_chat.append_message(f"{human_timestamp()} [(you)] {text}")

    def handle_start_server(self):
        try:
            ensure_self_signed_cert()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "TLS Error", str(e))
            return
        self.page_server.set_status("Starting...")
        self.net.start_server()

    def handle_stop_server(self):
        self.page_server.set_status("Stopping...")
        self.net.stop_server()

    def on_connected(self, hostport: str):
        self.indicator.set_connected(True)
        self.conn_label.setText(f"Connected to {hostport}")
        self.page_chat.append_message(f"{human_timestamp()} [System] Connected to {hostport}")

    def on_disconnected(self):
        self.indicator.set_connected(False)
        self.conn_label.setText("Disconnected")
        self.page_chat.append_message(f"{human_timestamp()} [System] Disconnected")

    def on_server_started(self, info: str):
        self.page_server.set_status(f"Listening on {info}")
        self.page_server.refresh_ips()
        self.page_chat.append_message(f"{human_timestamp()} [System] Server started on {info}")

    def on_server_stopped(self):
        self.page_server.set_status("Server not running")
        self.page_chat.append_message(f"{human_timestamp()} [System] Server stopped")

    def on_password_required(self, prompt: str):
        pw, ok = QtWidgets.QInputDialog.getText(self, "Server Password", prompt, QtWidgets.QLineEdit.EchoMode.Password)
        if ok:
            self.net.submit_password_from_ui(pw)
        else:
            self.net.submit_password_from_ui(None)


# --------------------------------- Entry Point -------------------------------

def main():
    ensure_paths()
    app = QtWidgets.QApplication(sys.argv)
    win = virtualOffice()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
