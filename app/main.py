import ipaddress
import base64
import hashlib
import os
import re
import secrets
import selectors
import shutil
import socket
import socketserver
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import Flask, Response, abort, redirect, render_template, request, session, url_for
from flask import jsonify


DB_PATH = os.getenv("RDP_TOKEN_DB", "/data/rdp-token.db")
HTTP_HOST = os.getenv("RDP_TOKEN_HTTP_HOST", "127.0.0.1")
HTTP_PORT = int(os.getenv("RDP_TOKEN_HTTP_PORT", "18081"))
SECRET = os.getenv("RDP_TOKEN_SECRET", "")
BOOTSTRAP_ADMIN = os.getenv("RDP_TOKEN_BOOTSTRAP_ADMIN_SERIAL", "").upper().replace(":", "")
CA_FILE = os.getenv("RDP_TOKEN_CA_FILE", "/certs/client-ca.pem")
CRL_FILE = os.getenv("RDP_TOKEN_CRL_FILE", "/certs/client.crl.pem")
MANAGED_CA_FILE = os.getenv(
    "RDP_TOKEN_MANAGED_CA_FILE", "/data/crl/client-ca-chain.pem",
)
MANAGED_CRL_FILE = os.getenv(
    "RDP_TOKEN_MANAGED_CRL_FILE", "/data/crl/client.crl.pem",
)
CRL_URL = os.getenv(
    "RDP_TOKEN_CRL_URL",
    "https://pki.example.invalid/crl/client-ca.crl",
)
CRL_MAX_BYTES = 2 * 1024 * 1024
DISPLAY_TIMEZONE_NAME = os.getenv("RDP_TOKEN_TIMEZONE", "Europe/Moscow")
CLAIM_SECONDS = int(os.getenv("RDP_TOKEN_CLAIM_SECONDS", "50"))
PUBLIC_RDP_HOST = os.getenv("RDP_TOKEN_PUBLIC_RDP_HOST", "rdp.example.invalid")
PORT_MIN = int(os.getenv("RDP_TOKEN_PORT_MIN", "60000"))
PORT_MAX = int(os.getenv("RDP_TOKEN_PORT_MAX", "60999"))
RECOVERY_CODE_SECONDS = 30 * 60
RECOVERY_SESSION_SECONDS = 30 * 60
ADMIN_SESSION_SECONDS = 30 * 60
CHALLENGE_SECONDS = 30
CHALLENGE_LIMIT = 512

admin_challenges = {}
admin_challenges_lock = threading.Lock()

if not 1 <= PORT_MIN <= PORT_MAX <= 65535:
    raise RuntimeError("RDP token gateway port range is invalid")

if len(SECRET) < 32:
    raise RuntimeError("RDP_TOKEN_SECRET must contain at least 32 characters")

app = Flask(__name__)
app.secret_key = SECRET
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Strict")


def now_text():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def db():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with db() as con:
        con.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS tokens (
            serial TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            subject TEXT NOT NULL DEFAULT '',
            issuer TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL CHECK(role IN ('USER','ADMIN')),
            enabled INTEGER NOT NULL DEFAULT 1,
            last_seen TEXT
        );
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            internal_ip TEXT NOT NULL,
            internal_port INTEGER NOT NULL DEFAULT 3389,
            gateway_port INTEGER NOT NULL UNIQUE,
            enabled INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS token_targets (
            token_serial TEXT NOT NULL REFERENCES tokens(serial) ON DELETE CASCADE,
            target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            PRIMARY KEY(token_serial,target_id)
        );
        CREATE TABLE IF NOT EXISTS pending_tokens (
            serial TEXT PRIMARY KEY,
            subject TEXT NOT NULL DEFAULT '',
            issuer TEXT NOT NULL DEFAULT '',
            source_ip TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS access_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_serial TEXT NOT NULL,
            target_id INTEGER NOT NULL,
            source_ip TEXT NOT NULL,
            state TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            bytes_client INTEGER NOT NULL DEFAULT 0,
            bytes_server INTEGER NOT NULL DEFAULT 0,
            detail TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS recovery_codes (
            code_hash TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            used_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS recovery_sessions (
            session_hash TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS admin_sessions (
            session_hash TEXT PRIMARY KEY,
            token_serial TEXT NOT NULL REFERENCES tokens(serial) ON DELETE CASCADE,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        """)
        columns = {row[1] for row in con.execute("PRAGMA table_info(access_log)")}
        if "target_name" not in columns:
            con.execute("ALTER TABLE access_log ADD COLUMN target_name TEXT NOT NULL DEFAULT ''")
            con.execute("UPDATE access_log SET target_name=COALESCE("
                        "(SELECT name FROM targets WHERE targets.id=access_log.target_id),'')")
        con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('port_min',?)",
                    (str(PORT_MIN),))
        con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('port_max',?)",
                    (str(PORT_MAX),))


def normalize_serial(value):
    return "".join(c for c in value.upper() if c in "0123456789ABCDEF")


def secret_hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def create_recovery_code():
    init_db()
    code = "RDPREC-" + secrets.token_urlsafe(24)
    now = int(time.time())
    with db() as con:
        con.execute("DELETE FROM recovery_codes WHERE used_at IS NULL")
        con.execute("DELETE FROM recovery_sessions")
        con.execute("INSERT INTO recovery_codes(code_hash,created_at,expires_at) VALUES(?,?,?)",
                    (secret_hash(code), now, now + RECOVERY_CODE_SECONDS))
    return code


def api_admin():
    authorization = request.headers.get("Authorization", "")
    if authorization.startswith("Bearer "):
        session_value = authorization[7:].strip()
        now = int(time.time())
        with db() as con:
            admin_row = con.execute(
                "SELECT s.expires_at,t.* FROM admin_sessions s "
                "JOIN tokens t ON t.serial=s.token_serial "
                "WHERE s.session_hash=? AND t.role='ADMIN' AND t.enabled=1",
                (secret_hash(session_value),),
            ).fetchone()
            row = con.execute("SELECT expires_at FROM recovery_sessions WHERE session_hash=?",
                              (secret_hash(session_value),)).fetchone()
            con.execute("DELETE FROM recovery_sessions WHERE expires_at<=?", (now,))
            con.execute("DELETE FROM admin_sessions WHERE expires_at<=?", (now,))
        if admin_row is not None and admin_row["expires_at"] > now:
            return admin_row, request.headers.get("X-Real-IP", request.remote_addr or "")
        if row is None or row["expires_at"] <= now:
            abort(401, "Administrative session expired")
        return {"role": "RECOVERY", "serial": "RECOVERY"}, request.headers.get("X-Real-IP", request.remote_addr or "")
    return require_admin()


def api_json():
    if request.headers.get("X-RDP-Token-Client") != "windows":
        abort(400, "Unsupported API client")
    return request.get_json(force=False, silent=False) or {}


def gateway_port_available(port):
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def gateway_port_range(con=None):
    owns_connection = con is None
    if owns_connection:
        con = db()
    try:
        values = dict(con.execute(
            "SELECT key,value FROM settings WHERE key IN ('port_min','port_max')"))
        port_min = int(values.get("port_min", PORT_MIN))
        port_max = int(values.get("port_max", PORT_MAX))
        if not 1 <= port_min <= port_max <= 65535:
            return PORT_MIN, PORT_MAX
        return port_min, port_max
    finally:
        if owns_connection:
            con.close()


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


def require_csrf():
    expected = session.get("csrf", "")
    provided = request.form.get("csrf", "")
    if not expected or not provided or not secrets.compare_digest(expected, provided):
        abort(400, "CSRF validation failed")


def client_identity():
    # The edge nginx only requests the certificate. Trust and revocation are
    # checked here so Windows does not need the private CA installed locally.
    verify_leaf_certificate()
    serial = normalize_serial(request.headers.get("X-Client-Serial", ""))
    if not serial:
        abort(403, "Client certificate serial is missing")
    subject = request.headers.get("X-Client-Subject", "")
    issuer = request.headers.get("X-Client-Issuer", "")
    remote_ip = request.headers.get("X-Real-IP", request.remote_addr or "")
    with db() as con:
        row = con.execute("SELECT * FROM tokens WHERE serial=?", (serial,)).fetchone()
        if row is None and serial == BOOTSTRAP_ADMIN:
            con.execute("INSERT INTO tokens(serial,label,subject,issuer,role,enabled,last_seen) "
                        "VALUES(?,?,?,?, 'ADMIN',1,?)",
                        (serial, "Первичный администратор", subject, issuer, now_text()))
            row = con.execute("SELECT * FROM tokens WHERE serial=?", (serial,)).fetchone()
        if row is None:
            seen = now_text()
            con.execute(
                "INSERT INTO pending_tokens(serial,subject,issuer,source_ip,first_seen,last_seen) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(serial) DO UPDATE SET "
                "subject=excluded.subject,issuer=excluded.issuer,source_ip=excluded.source_ip,"
                "last_seen=excluded.last_seen",
                (serial, subject, issuer, remote_ip, seen, seen))
            con.commit()
            abort(403, "Token is awaiting administrator approval")
        if not row["enabled"]:
            abort(403, "Token is disabled")
        con.execute("UPDATE tokens SET subject=?,issuer=?,last_seen=? WHERE serial=?",
                    (subject, issuer, now_text(), serial))
        return dict(row), remote_ip


def require_admin():
    token, remote_ip = client_identity()
    if token["role"] != "ADMIN":
        abort(404)
    return token, remote_ip


def verify_leaf_certificate():
    encoded = request.headers.get("X-Client-Cert", "")
    pem = urllib.parse.unquote(encoded)
    if "-----BEGIN CERTIFICATE-----" not in pem:
        abort(403, "Client certificate was not forwarded")
    valid, _identity, _detail = validate_client_certificate(pem)
    if not valid:
        abort(403, "Certificate is revoked or CRL verification failed")


def validate_client_certificate(pem):
    """Validate a presented leaf and return its identity without trusting headers."""
    fd, path = tempfile.mkstemp(prefix="rdp-token-", suffix=".pem")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(pem)
        errors = []
        for ca_path, crl_path, label in (
            (MANAGED_CA_FILE, MANAGED_CRL_FILE, "managed"),
            (CA_FILE, CRL_FILE, "legacy"),
        ):
            if not os.path.isfile(ca_path) or not os.path.isfile(crl_path):
                continue
            valid, detail = _certificate_valid_for_crl_pair(path, ca_path, crl_path)
            if valid:
                serial_result = subprocess.run(
                    ["/usr/bin/openssl", "x509", "-in", path, "-noout", "-serial"],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                serial = normalize_serial(serial_result.stdout.partition("=")[2])
                identity = {
                    "serial": serial,
                    "subject": _openssl_identity(path, "x509", "subject"),
                    "issuer": _openssl_identity(path, "x509", "issuer"),
                    "ca": label,
                }
                if serial:
                    return True, identity, "OK"
                return False, {}, "Не удалось прочитать серийный номер сертификата"
            errors.append(f"{label}: {detail}")
        if not errors:
            return False, {}, "No CA and CRL pair is configured"
        return False, {}, "; ".join(errors)
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _verify_challenge_signature(certificate_pem, challenge, signature):
    cert_fd, cert_path = tempfile.mkstemp(prefix="rdp-token-cert-", suffix=".pem")
    data_fd, data_path = tempfile.mkstemp(prefix="rdp-token-data-", suffix=".bin")
    sig_fd, sig_path = tempfile.mkstemp(prefix="rdp-token-signature-", suffix=".bin")
    pub_path = cert_path + ".pub"
    try:
        with os.fdopen(cert_fd, "w", encoding="ascii") as handle:
            handle.write(certificate_pem)
        with os.fdopen(data_fd, "wb") as handle:
            handle.write(challenge)
        with os.fdopen(sig_fd, "wb") as handle:
            handle.write(signature)
        public_key = subprocess.run(
            ["/usr/bin/openssl", "x509", "-in", cert_path, "-pubkey", "-noout"],
            capture_output=True, timeout=10, check=False,
        )
        if public_key.returncode != 0:
            return False
        with open(pub_path, "wb") as handle:
            handle.write(public_key.stdout)
        verified = subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-verify", pub_path,
             "-signature", sig_path, data_path],
            capture_output=True, timeout=10, check=False,
        )
        return verified.returncode == 0
    finally:
        for candidate in (cert_path, data_path, sig_path, pub_path):
            try:
                os.unlink(candidate)
            except FileNotFoundError:
                pass


def _read_crl(path):
    last_error = ""
    for inform in ("PEM", "DER"):
        result = subprocess.run(
            ["/usr/bin/openssl", "crl", "-inform", inform, "-in", path,
             "-noout", "-issuer", "-lastupdate", "-nextupdate", "-crlnumber"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode == 0:
            values = {}
            for line in result.stdout.splitlines():
                key, marker, value = line.partition("=")
                if marker:
                    values[key.strip().lower()] = value.strip()
            text_result = subprocess.run(
                ["/usr/bin/openssl", "crl", "-inform", inform, "-in", path,
                 "-noout", "-text"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            text_value = text_result.stdout if text_result.returncode == 0 else ""
            return {
                "format": inform,
                "issuer": values.get("issuer", ""),
                "last_update_raw": values.get("lastupdate", ""),
                "next_update_raw": values.get("nextupdate", ""),
                "crl_number": values.get("crlnumber", ""),
                "revoked_count": text_value.count("Serial Number:"),
            }
        last_error = (result.stderr or result.stdout).strip()
    raise RuntimeError("Файл не является CRL: " + (last_error or "неизвестный формат"))


def _crl_time(value):
    if not value:
        return None
    parsed = parsedate_to_datetime(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone()


def _display_time(value):
    if value is None:
        return ""
    try:
        display_zone = ZoneInfo(DISPLAY_TIMEZONE_NAME)
    except ZoneInfoNotFoundError:
        display_zone = timezone.utc
    return value.astimezone(display_zone).strftime("%d.%m.%Y %H:%M %Z")


def _verify_crl_signature(path, inform, ca_file=MANAGED_CA_FILE):
    result = subprocess.run(
        ["/usr/bin/openssl", "crl", "-inform", inform, "-in", path,
         "-noout", "-verify", "-CAfile", ca_file],
        capture_output=True, text=True, timeout=10, check=False,
    )
    return result.returncode == 0, (result.stderr or result.stdout).strip()


def _openssl_identity(path, object_type, field, inform=None):
    command = ["/usr/bin/openssl", object_type]
    if inform:
        command.extend(["-inform", inform])
    command.extend(["-in", path, "-noout", f"-{field}", "-nameopt", "RFC2253"])
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=10, check=False,
    )
    if result.returncode != 0:
        return ""
    return result.stdout.strip().partition("=")[2].strip()


def _certificate_valid_for_crl_pair(certificate_path, ca_path, crl_path):
    chain = subprocess.run(
        ["/usr/bin/openssl", "verify", "-CAfile", ca_path, certificate_path],
        capture_output=True, text=True, timeout=10, check=False,
    )
    if chain.returncode != 0:
        return False, (chain.stderr or chain.stdout).strip()
    try:
        metadata = _read_crl(crl_path)
        last_update = _crl_time(metadata["last_update_raw"])
        next_update = _crl_time(metadata["next_update_raw"])
    except (RuntimeError, ValueError) as exc:
        return False, str(exc)
    now = datetime.now().astimezone()
    if not last_update or not next_update or last_update > now or next_update <= now:
        return False, "CRL ещё не действует или уже просрочен"
    signature_valid, signature_error = _verify_crl_signature(
        crl_path, metadata["format"], ca_path,
    )
    if not signature_valid:
        return False, signature_error or "Неверная подпись CRL"
    certificate_issuer = _openssl_identity(certificate_path, "x509", "issuer")
    crl_issuer = _openssl_identity(crl_path, "crl", "issuer", metadata["format"])
    if not certificate_issuer or certificate_issuer != crl_issuer:
        return False, "CRL выпущен другим CA"
    serial_result = subprocess.run(
        ["/usr/bin/openssl", "x509", "-in", certificate_path, "-noout", "-serial"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    if serial_result.returncode != 0:
        return False, "Не удалось прочитать серийный номер сертификата"
    certificate_serial = normalize_serial(serial_result.stdout.partition("=")[2])
    text_result = subprocess.run(
        ["/usr/bin/openssl", "crl", "-inform", metadata["format"], "-in", crl_path,
         "-noout", "-text"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    if text_result.returncode != 0:
        return False, "Не удалось прочитать список отозванных сертификатов"
    revoked_serials = {
        normalize_serial(value)
        for value in re.findall(r"Serial Number:\s*([0-9A-Fa-f:]+)", text_result.stdout)
    }
    if certificate_serial in revoked_serials:
        return False, "Сертификат отозван"
    return True, "OK"


def crl_status():
    status = {
        "url": CRL_URL,
        "local_file": MANAGED_CRL_FILE,
        "file_name": os.path.basename(urllib.parse.urlparse(CRL_URL).path),
        "available": False,
        "signature_valid": False,
        "current": False,
        "issuer": "",
        "last_update": "",
        "next_update": "",
        "crl_number": "",
        "revoked_count": 0,
        "downloaded_at": "",
        "error": "",
    }
    try:
        metadata = _read_crl(MANAGED_CRL_FILE)
        signature_valid, signature_error = _verify_crl_signature(
            MANAGED_CRL_FILE, metadata["format"],
        )
        last_update = _crl_time(metadata["last_update_raw"])
        next_update = _crl_time(metadata["next_update_raw"])
        now = datetime.now().astimezone()
        status.update({
            "available": True,
            "signature_valid": signature_valid,
            "current": bool(signature_valid and last_update and next_update
                            and last_update <= now and next_update > now),
            "issuer": metadata["issuer"],
            "last_update": _display_time(last_update),
            "next_update": _display_time(next_update),
            "crl_number": metadata["crl_number"],
            "revoked_count": metadata["revoked_count"],
            "downloaded_at": _display_time(datetime.fromtimestamp(
                os.path.getmtime(MANAGED_CRL_FILE), tz=timezone.utc,
            )),
            "error": "" if signature_valid else (signature_error or "Неверная подпись CRL"),
        })
    except (OSError, RuntimeError, ValueError) as exc:
        status["error"] = str(exc)
    return status


def refresh_crl():
    parsed_url = urllib.parse.urlparse(CRL_URL)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise RuntimeError("CRL URL должен использовать HTTPS")
    request_value = urllib.request.Request(
        CRL_URL, headers={"User-Agent": "RDP-Token CRL updater/1.0"},
    )
    try:
        with urllib.request.urlopen(request_value, timeout=20) as response:
            if response.status != 200:
                raise RuntimeError(f"CRL сервер вернул HTTP {response.status}")
            source = response.read(CRL_MAX_BYTES + 1)
    except Exception as exc:
        raise RuntimeError(f"Не удалось скачать CRL: {exc}") from exc
    if len(source) > CRL_MAX_BYTES:
        raise RuntimeError("CRL превышает допустимый размер 2 МиБ")

    directory = os.path.dirname(MANAGED_CRL_FILE)
    os.makedirs(directory, exist_ok=True)
    source_fd, source_path = tempfile.mkstemp(prefix="crl-download-", dir=directory)
    normalized_fd, normalized_path = tempfile.mkstemp(prefix="crl-verified-", dir=directory)
    os.close(normalized_fd)
    try:
        with os.fdopen(source_fd, "wb") as handle:
            handle.write(source)
        metadata = _read_crl(source_path)
        last_update = _crl_time(metadata["last_update_raw"])
        next_update = _crl_time(metadata["next_update_raw"])
        now = datetime.now().astimezone()
        if not last_update or not next_update or last_update > now or next_update <= now:
            raise RuntimeError("Скачанный CRL ещё не действует или уже просрочен")
        signature_valid, signature_error = _verify_crl_signature(
            source_path, metadata["format"],
        )
        if not signature_valid:
            raise RuntimeError("Подпись CRL не соответствует доверенному CA: "
                               + (signature_error or "проверка не пройдена"))
        conversion = subprocess.run(
            ["/usr/bin/openssl", "crl", "-inform", metadata["format"],
             "-in", source_path, "-out", normalized_path, "-outform", "PEM"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if conversion.returncode != 0:
            raise RuntimeError("Не удалось преобразовать CRL в PEM")
        if os.path.exists(MANAGED_CRL_FILE):
            shutil.copy2(MANAGED_CRL_FILE, MANAGED_CRL_FILE + ".previous")
        os.chmod(normalized_path, 0o644)
        os.replace(normalized_path, MANAGED_CRL_FILE)
    finally:
        for temporary in (source_path, normalized_path):
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    return crl_status()


class GateState:
    def __init__(self):
        self.lock = threading.RLock()
        self.pending = {}
        self.active = set()
        self.servers = {}

    def grant(self, target_id, serial, web_ip):
        now = time.monotonic()
        with self.lock:
            self.pending[target_id] = {"serial": serial, "web_ip": web_ip,
                                       "deadline": now + CLAIM_SECONDS}
        print(f"RDP GRANT target={target_id} web_ip={web_ip} window={CLAIM_SECONDS}s", flush=True)

    def claim(self, target_id, source_ip):
        now = time.monotonic()
        with self.lock:
            pending = self.pending.get(target_id)
            if not pending or pending["deadline"] <= now:
                self.pending.pop(target_id, None)
                print(f"RDP DENY target={target_id} source={source_ip} reason=no_valid_grant", flush=True)
                return ""
            serial = pending["serial"]
            key = (target_id, serial)
            bound_ip = pending.get("rdp_ip")
            if bound_ip is not None and bound_ip != source_ip:
                print(f"RDP DENY target={target_id} source={source_ip} reason=source_ip_mismatch", flush=True)
                return ""
            if any(active_target == target_id for active_target, _ in self.active):
                print(f"RDP DENY target={target_id} source={source_ip} reason=session_active", flush=True)
                return ""
            # Bind the first TCP source, retaining the ORIGINAL deadline for retries.
            # Claim/reservation is atomic; never extend the window on retry/finish.
            pending["rdp_ip"] = source_ip
            self.active.add(key)
            print(f"RDP CLAIM target={target_id} source={source_ip} "
                  f"retry={int(bound_ip is not None)} remaining={pending['deadline'] - now:.1f}s", flush=True)
            return serial

    def finish(self, target_id, serial):
        with self.lock:
            self.active.discard((target_id, serial))

    def start_target(self, target):
        target = dict(target)
        with self.lock:
            if target["id"] in self.servers:
                return
            handler = make_rdp_handler(target)
            server = ThreadedTcpServer(("0.0.0.0", target["gateway_port"]), handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.servers[target["id"]] = server
            print(f"LISTEN target={target['id']} gateway={target['gateway_port']} "
                  f"internal={target['internal_ip']}:{target['internal_port']}", flush=True)

    def stop_target(self, target_id):
        with self.lock:
            server = self.servers.pop(target_id, None)
            self.pending.pop(target_id, None)
        if server is not None:
            server.shutdown()
            server.server_close()
            print(f"STOP target={target_id}", flush=True)

    def restart_target(self, target):
        self.stop_target(target["id"])
        self.start_target(target)


gate = GateState()


class ThreadedTcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_rdp_handler(target):
    class RdpHandler(socketserver.BaseRequestHandler):
        def handle(self):
            source_ip = self.client_address[0]
            serial = gate.claim(target["id"], source_ip)
            if not serial:
                return
            log_id = None
            upstream = None
            started = time.monotonic()
            operation = "connect upstream"
            client_bytes = server_bytes = 0
            close_detail = ""
            try:
                upstream = socket.create_connection(
                    (target["internal_ip"], target["internal_port"]), timeout=10)
                print(f"RDP CONNECTED target={target['id']} source={source_ip} "
                      f"upstream={target['internal_ip']}:{target['internal_port']}", flush=True)
                with db() as con:
                    cur = con.execute(
                        "INSERT INTO access_log(token_serial,target_id,target_name,source_ip,state,started_at) "
                        "VALUES(?,?,?,?,'ACTIVE',?)",
                        (serial, target["id"], target["name"], source_ip, now_text()))
                    log_id = cur.lastrowid
                self.request.setblocking(False)
                upstream.setblocking(False)
                poller = selectors.DefaultSelector()
                peers = {self.request: upstream, upstream: self.request}
                directions = {self.request: "client", upstream: "server"}
                pending = {self.request: bytearray(), upstream: bytearray()}
                poller.register(self.request, selectors.EVENT_READ)
                poller.register(upstream, selectors.EVENT_READ)
                try:
                    while True:
                        for key, events in poller.select(timeout=1):
                            current = key.fileobj
                            if events & selectors.EVENT_READ:
                                operation = f"read {directions[current]}"
                                try:
                                    data = current.recv(65536)
                                except BlockingIOError:
                                    data = None
                                if data == b"":
                                    close_detail = f"{directions[current]} closed connection"
                                    break
                                if data:
                                    destination = peers[current]
                                    pending[destination].extend(data)
                                    poller.modify(
                                        destination,
                                        selectors.EVENT_READ | selectors.EVENT_WRITE)
                                    if directions[current] == "client":
                                        client_bytes += len(data)
                                    else:
                                        server_bytes += len(data)
                            if events & selectors.EVENT_WRITE and pending[current]:
                                operation = f"write {directions[current]}"
                                try:
                                    sent = current.send(pending[current])
                                except BlockingIOError:
                                    sent = 0
                                if sent:
                                    del pending[current][:sent]
                                if not pending[current]:
                                    poller.modify(current, selectors.EVENT_READ)
                        else:
                            continue
                        break
                finally:
                    poller.close()
                    upstream.close()
            except OSError as exc:
                close_detail = f"proxy error ({operation}): {exc}"
                if log_id is None:
                    with db() as con:
                        con.execute(
                            "INSERT INTO access_log(token_serial,target_id,target_name,source_ip,state,started_at,ended_at,detail) "
                            "VALUES(?,?,?,?,'FAILED',?,?,?)",
                            (serial, target["id"], target["name"], source_ip,
                             now_text(), now_text(), str(exc)))
            finally:
                if upstream is not None:
                    upstream.close()
                # Always release the in-memory slot, even if writing the log fails.
                gate.finish(target["id"], serial)
                print(f"RDP CLOSED target={target['id']} source={source_ip} "
                      f"duration={time.monotonic() - started:.1f}s "
                      f"client_bytes={client_bytes} server_bytes={server_bytes} "
                      f"reason={close_detail or 'handler terminated'}", flush=True)
                if log_id is not None:
                    with db() as con:
                        con.execute("UPDATE access_log SET state='CLOSED',ended_at=?,"
                                    "bytes_client=?,bytes_server=?,detail=? WHERE id=?",
                                    (now_text(), client_bytes, server_bytes,
                                     close_detail, log_id))
    return RdpHandler


@app.get("/")
def portal():
    if not request.headers.get("X-Client-Cert"):
        return render_template("token_required.html"), 403
    token, client_ip = client_identity()
    with db() as con:
        targets = con.execute(
            "SELECT t.* FROM targets t JOIN token_targets g ON g.target_id=t.id "
            "WHERE g.token_serial=? AND t.enabled=1 ORDER BY t.name", (token["serial"],)).fetchall()
        recent = con.execute(
            "SELECT l.*,t.name FROM access_log l JOIN targets t ON t.id=l.target_id "
            "WHERE l.token_serial=? ORDER BY l.id DESC LIMIT 20", (token["serial"],)).fetchall()
    return render_template("portal.html", token=token, targets=targets, recent=recent,
                           public_host=PUBLIC_RDP_HOST, client_ip=client_ip)


@app.post("/open")
def open_access():
    require_csrf()
    token, remote_ip = client_identity()
    selected = {int(value) for value in request.form.getlist("target") if value.isdigit()}
    with db() as con:
        allowed_targets = con.execute(
            "SELECT t.* FROM targets t JOIN token_targets g ON g.target_id=t.id "
            "WHERE g.token_serial=? AND t.enabled=1", (token["serial"],)).fetchall()
    opened = []
    for target in allowed_targets:
        if target["id"] in selected:
            gate.grant(target["id"], token["serial"], remote_ip)
            opened.append(target)
    return render_template("opened.html", token=token, targets=opened,
                           claim_seconds=CLAIM_SECONDS, public_host=PUBLIC_RDP_HOST)


@app.get("/rdp/<int:target_id>.rdp")
def download_rdp(target_id):
    token, _ = client_identity()
    with db() as con:
        target = con.execute(
            "SELECT t.* FROM targets t JOIN token_targets g ON g.target_id=t.id "
            "WHERE g.token_serial=? AND t.id=? AND t.enabled=1",
            (token["serial"], target_id)).fetchone()
    if target is None:
        abort(404)
    content = (f"full address:s:{PUBLIC_RDP_HOST}:{target['gateway_port']}\r\n"
               "prompt for credentials:i:0\r\n"
               "authentication level:i:2\r\n"
               "enablecredsspsupport:i:1\r\n"
               "redirectclipboard:i:1\r\n"
               "redirectsmartcards:i:0\r\n")
    safe_name = "".join(c if c.isalnum() or c in "-_" else "-" for c in target["name"])
    return Response(content, mimetype="application/x-rdp",
                    headers={"Content-Disposition": f'attachment; filename="{safe_name}.rdp"'})


@app.get("/admin")
def admin():
    current_token, _ = require_admin()
    with db() as con:
        tokens = con.execute("SELECT * FROM tokens ORDER BY label").fetchall()
        pending_tokens = con.execute(
            "SELECT * FROM pending_tokens ORDER BY last_seen DESC").fetchall()
        targets = con.execute("SELECT * FROM targets ORDER BY name").fetchall()
        grants = con.execute(
            "SELECT g.token_serial,g.target_id,k.label token_label,t.name target_name,"
            "t.internal_ip,t.internal_port,t.gateway_port "
            "FROM token_targets g JOIN tokens k ON k.serial=g.token_serial "
            "JOIN targets t ON t.id=g.target_id ORDER BY k.label,t.name").fetchall()
        logs = con.execute(
            "SELECT l.*,COALESCE(t.name,l.target_name,'Удалённая система') name,k.label "
            "FROM access_log l LEFT JOIN targets t ON t.id=l.target_id "
            "LEFT JOIN tokens k ON k.serial=l.token_serial ORDER BY l.id DESC LIMIT 100").fetchall()
        port_min, port_max = gateway_port_range(con)
        active_sessions = con.execute(
            "SELECT COUNT(*) FROM access_log WHERE state='ACTIVE' AND ended_at IS NULL"
        ).fetchone()[0]
        used_range_ports = {row["gateway_port"] for row in targets
                            if port_min <= row["gateway_port"] <= port_max}
        free_ports = sum(
            1 for port in range(port_min, port_max + 1)
            if port not in used_range_ports and gateway_port_available(port))
    with gate.lock:
        listening_ids = set(gate.servers)
    return render_template("admin.html", token=current_token,
                           tokens=tokens, targets=targets, grants=grants,
                           logs=logs, current_token=current_token,
                           pending_tokens=pending_tokens,
                           port_min=port_min, port_max=port_max,
                           active_sessions=active_sessions, free_ports=free_ports,
                           listening_ids=listening_ids, crl=crl_status())


@app.post("/admin/crl/refresh")
def admin_refresh_crl():
    require_csrf(); require_admin()
    try:
        refresh_crl()
    except RuntimeError as exc:
        abort(409, str(exc))
    return redirect(url_for("admin") + "#crl")


@app.post("/admin/token")
def admin_add_token():
    require_csrf(); require_admin()
    serial = normalize_serial(request.form.get("serial", ""))
    label = request.form.get("label", "").strip()
    role = request.form.get("role", "USER")
    if not serial or not label or role not in {"USER", "ADMIN"}:
        abort(400)
    with db() as con:
        con.execute("INSERT INTO tokens(serial,label,role,enabled) VALUES(?,?,?,1) "
                    "ON CONFLICT(serial) DO UPDATE SET label=excluded.label,role=excluded.role",
                    (serial, label, role))
        con.execute("DELETE FROM pending_tokens WHERE serial=?", (serial,))
    return redirect(url_for("admin"))


@app.post("/admin/token/approve")
def admin_approve_token():
    require_csrf(); require_admin()
    serial = normalize_serial(request.form.get("serial", ""))
    label = request.form.get("label", "").strip()
    role = request.form.get("role", "USER")
    if not serial or not label or role not in {"USER", "ADMIN"}:
        abort(400)
    with db() as con:
        pending = con.execute(
            "SELECT subject,issuer FROM pending_tokens WHERE serial=?", (serial,)).fetchone()
        if pending is None:
            abort(404, "Pending token was not found")
        con.execute(
            "INSERT INTO tokens(serial,label,subject,issuer,role,enabled) VALUES(?,?,?,?,?,1) "
            "ON CONFLICT(serial) DO UPDATE SET label=excluded.label,subject=excluded.subject,"
            "issuer=excluded.issuer,role=excluded.role,enabled=1",
            (serial, label, pending["subject"], pending["issuer"], role))
        con.execute("DELETE FROM pending_tokens WHERE serial=?", (serial,))
    return redirect(url_for("admin"))


def other_active_admins(con, serial):
    return con.execute(
        "SELECT COUNT(*) FROM tokens WHERE role='ADMIN' AND enabled=1 AND serial<>?",
        (serial,)).fetchone()[0]


@app.post("/admin/token/update")
def admin_update_token():
    require_csrf(); require_admin()
    serial = normalize_serial(request.form.get("serial", ""))
    label = request.form.get("label", "").strip()
    role = request.form.get("role", "USER")
    enabled = 1 if request.form.get("enabled") == "1" else 0
    if not serial or not label or role not in {"USER", "ADMIN"}:
        abort(400)
    with db() as con:
        row = con.execute("SELECT role,enabled FROM tokens WHERE serial=?", (serial,)).fetchone()
        if row is None:
            abort(404)
        removes_active_admin = (row["role"] == "ADMIN" and row["enabled"]
                                and (role != "ADMIN" or not enabled))
        if removes_active_admin and other_active_admins(con, serial) == 0:
            abort(409, "The last active administrator cannot be disabled or demoted")
        con.execute("UPDATE tokens SET label=?,role=?,enabled=? WHERE serial=?",
                    (label, role, enabled, serial))
    return redirect(url_for("admin"))


@app.post("/admin/token/delete")
def admin_delete_token():
    require_csrf(); require_admin()
    serial = normalize_serial(request.form.get("serial", ""))
    with db() as con:
        row = con.execute("SELECT role,enabled FROM tokens WHERE serial=?", (serial,)).fetchone()
        if row is None:
            abort(404)
        if row["role"] == "ADMIN" and row["enabled"] and other_active_admins(con, serial) == 0:
            abort(409, "The last active administrator cannot be deleted")
        con.execute("DELETE FROM tokens WHERE serial=?", (serial,))
    return redirect(url_for("admin"))


@app.post("/admin/target")
def admin_add_target():
    require_csrf(); require_admin()
    name = request.form.get("name", "").strip()
    internal_ip = str(ipaddress.ip_address(request.form.get("internal_ip", "")))
    internal_port = int(request.form.get("internal_port", "3389"))
    if not name or not 1 <= internal_port <= 65535:
        abort(400)
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        port_min, port_max = gateway_port_range(con)
        used_ports = {row["gateway_port"] for row in con.execute(
            "SELECT gateway_port FROM targets WHERE gateway_port BETWEEN ? AND ?",
            (port_min, port_max))}
        gateway_port = next(
            (port for port in range(port_min, port_max + 1)
             if port not in used_ports and gateway_port_available(port)), None)
        if gateway_port is None:
            abort(409, "No free RDP gateway ports")
        cur = con.execute("INSERT INTO targets(name,internal_ip,internal_port,gateway_port,enabled) "
                          "VALUES(?,?,?,?,1)", (name, internal_ip, internal_port, gateway_port))
        target = con.execute("SELECT * FROM targets WHERE id=?", (cur.lastrowid,)).fetchone()
    gate.start_target(target)
    return redirect(url_for("admin"))


@app.post("/admin/target/update")
def admin_update_target():
    require_csrf(); require_admin()
    target_id = int(request.form.get("target_id", "0"))
    name = request.form.get("name", "").strip()
    internal_ip = str(ipaddress.ip_address(request.form.get("internal_ip", "")))
    internal_port = int(request.form.get("internal_port", "3389"))
    gateway_port = int(request.form.get("gateway_port", "0"))
    port_min, port_max = gateway_port_range()
    if (not name or not 1 <= internal_port <= 65535
            or not port_min <= gateway_port <= port_max):
        abort(400, f"Gateway port must be between {port_min} and {port_max}")
    try:
        with db() as con:
            current = con.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
            if current is None:
                abort(404)
            conflict = con.execute(
                "SELECT 1 FROM targets WHERE gateway_port=? AND id<>?",
                (gateway_port, target_id)).fetchone()
            if conflict is not None:
                abort(409, "Gateway port is already used by another system")
            if gateway_port != current["gateway_port"] and not gateway_port_available(gateway_port):
                abort(409, "Gateway port is occupied by another process")
            con.execute("UPDATE targets SET name=?,internal_ip=?,internal_port=?,gateway_port=? "
                        "WHERE id=?", (name, internal_ip, internal_port, gateway_port, target_id))
            target = con.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    except sqlite3.IntegrityError:
        abort(409, "Gateway port is already used by another system")
    gate.restart_target(target)
    return redirect(url_for("admin"))


@app.post("/admin/settings/ports")
def admin_update_port_range():
    require_csrf(); require_admin()
    port_min = int(request.form.get("port_min", "0"))
    port_max = int(request.form.get("port_max", "0"))
    if not 1024 <= port_min <= port_max <= 65535:
        abort(400, "Port range must be between 1024 and 65535")
    if port_max - port_min > 999:
        abort(400, "Port range cannot contain more than 1000 ports")
    with db() as con:
        con.execute("INSERT INTO settings(key,value) VALUES('port_min',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(port_min),))
        con.execute("INSERT INTO settings(key,value) VALUES('port_max',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(port_max),))
    return redirect(url_for("admin"))


@app.post("/admin/target/delete")
def admin_delete_target():
    require_csrf(); require_admin()
    target_id = int(request.form.get("target_id", "0"))
    with db() as con:
        target = con.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
        if target is None:
            abort(404)
    gate.stop_target(target_id)
    with db() as con:
        con.execute("UPDATE access_log SET target_name=? WHERE target_id=? AND target_name=''",
                    (target["name"], target_id))
        con.execute("DELETE FROM targets WHERE id=?", (target_id,))
    return redirect(url_for("admin"))


@app.post("/admin/grant")
def admin_add_grant():
    require_csrf(); require_admin()
    serial = normalize_serial(request.form.get("serial", ""))
    target_id = int(request.form.get("target_id", "0"))
    with db() as con:
        con.execute("INSERT OR IGNORE INTO token_targets(token_serial,target_id) VALUES(?,?)",
                    (serial, target_id))
    if request.headers.get("X-Requested-With") == "RDP-Token-Fetch":
        return Response(status=204)
    return redirect(url_for("admin"))


@app.post("/admin/grant/delete")
def admin_delete_grant():
    require_csrf(); require_admin()
    serial = normalize_serial(request.form.get("serial", ""))
    target_id = int(request.form.get("target_id", "0"))
    with db() as con:
        con.execute("DELETE FROM token_targets WHERE token_serial=? AND target_id=?",
                    (serial, target_id))
    if request.headers.get("X-Requested-With") == "RDP-Token-Fetch":
        return Response(status=204)
    return redirect(url_for("admin"))


@app.post("/api/recovery/exchange")
def api_recovery_exchange():
    data = api_json()
    code = str(data.get("code", "")).strip()
    if not code.startswith("RDPREC-"):
        abort(401, "Invalid recovery code")
    now = int(time.time())
    session_value = secrets.token_urlsafe(32)
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute(
            "SELECT expires_at,used_at FROM recovery_codes WHERE code_hash=?",
            (secret_hash(code),)).fetchone()
        if row is None or row["used_at"] is not None or row["expires_at"] <= now:
            abort(401, "Invalid or expired recovery code")
        con.execute("UPDATE recovery_codes SET used_at=? WHERE code_hash=?",
                    (now, secret_hash(code)))
        con.execute("DELETE FROM recovery_sessions")
        con.execute("INSERT INTO recovery_sessions(session_hash,created_at,expires_at) VALUES(?,?,?)",
                    (secret_hash(session_value), now, now + RECOVERY_SESSION_SECONDS))
    response = jsonify({"session": session_value, "expires_in": RECOVERY_SESSION_SECONDS})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/admin/session")
def api_admin_session():
    api_json()
    token, _ = require_admin()
    now = int(time.time())
    session_value = secrets.token_urlsafe(32)
    with db() as con:
        con.execute("DELETE FROM admin_sessions WHERE token_serial=? OR expires_at<=?",
                    (token["serial"], now))
        con.execute(
            "INSERT INTO admin_sessions(session_hash,token_serial,created_at,expires_at) "
            "VALUES(?,?,?,?)",
            (secret_hash(session_value), token["serial"], now, now + ADMIN_SESSION_SECONDS),
        )
    response = jsonify({"session": session_value, "expires_in": ADMIN_SESSION_SECONDS})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/admin/challenge")
def api_admin_challenge():
    data = api_json()
    certificate_pem = str(data.get("certificate_pem", ""))
    if "-----BEGIN CERTIFICATE-----" not in certificate_pem:
        abort(400, "Client certificate is missing")
    valid, identity, detail = validate_client_certificate(certificate_pem)
    if not valid:
        abort(403, detail)
    with db() as con:
        token = con.execute(
            "SELECT * FROM tokens WHERE serial=? AND role='ADMIN' AND enabled=1",
            (identity["serial"],),
        ).fetchone()
    if token is None:
        abort(403, "Token is not an enabled administrator")

    now = int(time.time())
    challenge_id = secrets.token_urlsafe(24)
    challenge = b"RDP-Token admin login\x00" + secrets.token_bytes(32)
    with admin_challenges_lock:
        expired = [key for key, item in admin_challenges.items()
                   if item["expires_at"] <= now]
        for key in expired:
            admin_challenges.pop(key, None)
        while len(admin_challenges) >= CHALLENGE_LIMIT:
            oldest = min(admin_challenges, key=lambda key: admin_challenges[key]["created_at"])
            admin_challenges.pop(oldest, None)
        admin_challenges[challenge_id] = {
            "created_at": now,
            "expires_at": now + CHALLENGE_SECONDS,
            "certificate_pem": certificate_pem,
            "serial": identity["serial"],
            "challenge": challenge,
        }
    response = jsonify({
        "challenge_id": challenge_id,
        "challenge": base64.b64encode(challenge).decode("ascii"),
        "algorithm": "SHA256",
        "expires_in": CHALLENGE_SECONDS,
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/admin/challenge/verify")
def api_admin_challenge_verify():
    data = api_json()
    challenge_id = str(data.get("challenge_id", ""))
    try:
        signature = base64.b64decode(str(data.get("signature", "")), validate=True)
    except (ValueError, TypeError):
        abort(400, "Signature is not valid Base64")
    now = int(time.time())
    with admin_challenges_lock:
        item = admin_challenges.pop(challenge_id, None)
    if item is None or item["expires_at"] <= now:
        abort(401, "Challenge is invalid, expired or already used")
    with db() as con:
        token = con.execute(
            "SELECT * FROM tokens WHERE serial=? AND role='ADMIN' AND enabled=1",
            (item["serial"],),
        ).fetchone()
    if token is None:
        abort(403, "Token is not an enabled administrator")
    if not signature or not _verify_challenge_signature(
            item["certificate_pem"], item["challenge"], signature):
        abort(401, "Token signature verification failed")

    session_value = secrets.token_urlsafe(32)
    with db() as con:
        con.execute("DELETE FROM admin_sessions WHERE token_serial=? OR expires_at<=?",
                    (item["serial"], now))
        con.execute(
            "INSERT INTO admin_sessions(session_hash,token_serial,created_at,expires_at) "
            "VALUES(?,?,?,?)",
            (secret_hash(session_value), item["serial"], now, now + ADMIN_SESSION_SECONDS),
        )
    response = jsonify({"session": session_value, "expires_in": ADMIN_SESSION_SECONDS})
    response.headers["Cache-Control"] = "no-store"
    return response


def admin_state_payload():
    with db() as con:
        tokens = [dict(row) for row in con.execute("SELECT * FROM tokens ORDER BY label")]
        pending = [dict(row) for row in con.execute(
            "SELECT * FROM pending_tokens ORDER BY last_seen DESC")]
        targets = [dict(row) for row in con.execute("SELECT * FROM targets ORDER BY name")]
        grants = [dict(row) for row in con.execute(
            "SELECT g.token_serial,g.target_id,k.label token_label,t.name target_name "
            "FROM token_targets g JOIN tokens k ON k.serial=g.token_serial "
            "JOIN targets t ON t.id=g.target_id ORDER BY k.label,t.name")]
        logs = [dict(row) for row in con.execute(
            "SELECT l.*,COALESCE(t.name,l.target_name,'Удалённая система') name,k.label "
            "FROM access_log l LEFT JOIN targets t ON t.id=l.target_id "
            "LEFT JOIN tokens k ON k.serial=l.token_serial ORDER BY l.id DESC LIMIT 100")]
        port_min, port_max = gateway_port_range(con)
        active_sessions = con.execute(
            "SELECT COUNT(*) FROM access_log WHERE state='ACTIVE' AND ended_at IS NULL"
        ).fetchone()[0]
        used_ports = {row["gateway_port"] for row in targets
                      if port_min <= row["gateway_port"] <= port_max}
        free_ports = sum(1 for port in range(port_min, port_max + 1)
                         if port not in used_ports and gateway_port_available(port))
    return {"tokens": tokens, "pending_tokens": pending, "targets": targets,
            "grants": grants, "logs": logs, "port_min": port_min,
            "port_max": port_max, "active_sessions": active_sessions,
            "free_ports": free_ports, "crl": crl_status()}


@app.get("/api/admin/state")
def api_admin_state():
    api_admin()
    response = jsonify(admin_state_payload())
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/admin/action")
def api_admin_action():
    api_admin()
    data = api_json()
    action = data.get("action")
    result_payload = {"ok": True}
    if action == "crl_refresh":
        try:
            result_payload["crl"] = refresh_crl()
        except RuntimeError as exc:
            abort(409, str(exc))
    elif action == "token_approve":
        serial = normalize_serial(str(data.get("serial", "")))
        label, role = str(data.get("label", "")).strip(), str(data.get("role", "USER"))
        if not serial or not label or role not in {"USER", "ADMIN"}:
            abort(400)
        with db() as con:
            pending = con.execute("SELECT subject,issuer FROM pending_tokens WHERE serial=?",
                                  (serial,)).fetchone()
            if pending is None:
                abort(404, "Pending token was not found")
            con.execute("INSERT INTO tokens(serial,label,subject,issuer,role,enabled) VALUES(?,?,?,?,?,1) "
                        "ON CONFLICT(serial) DO UPDATE SET label=excluded.label,subject=excluded.subject,"
                        "issuer=excluded.issuer,role=excluded.role,enabled=1",
                        (serial, label, pending["subject"], pending["issuer"], role))
            con.execute("DELETE FROM pending_tokens WHERE serial=?", (serial,))
    elif action == "token_register":
        serial = normalize_serial(str(data.get("serial", "")))
        label, role = str(data.get("label", "")).strip(), str(data.get("role", "USER"))
        subject = str(data.get("subject", "")).strip()
        issuer = str(data.get("issuer", "")).strip()
        if not serial or not label or not subject or not issuer or role not in {"USER", "ADMIN"}:
            abort(400, "Certificate serial, subject, issuer, label and role are required")
        with db() as con:
            if con.execute("SELECT 1 FROM tokens WHERE serial=?", (serial,)).fetchone():
                abort(409, "Token is already registered")
            con.execute(
                "INSERT INTO tokens(serial,label,subject,issuer,role,enabled) VALUES(?,?,?,?,?,1)",
                (serial, label, subject, issuer, role),
            )
            con.execute("DELETE FROM pending_tokens WHERE serial=?", (serial,))
    elif action == "token_update":
        serial = normalize_serial(str(data.get("serial", "")))
        label, role = str(data.get("label", "")).strip(), str(data.get("role", "USER"))
        enabled = 1 if data.get("enabled", True) else 0
        if not serial or not label or role not in {"USER", "ADMIN"}:
            abort(400)
        with db() as con:
            row = con.execute("SELECT role,enabled FROM tokens WHERE serial=?", (serial,)).fetchone()
            if row is None:
                abort(404)
            removes = row["role"] == "ADMIN" and row["enabled"] and (role != "ADMIN" or not enabled)
            if removes and other_active_admins(con, serial) == 0:
                abort(409, "The last active administrator cannot be disabled or demoted")
            con.execute("UPDATE tokens SET label=?,role=?,enabled=? WHERE serial=?",
                        (label, role, enabled, serial))
            if "target_ids" in data:
                target_ids = sorted({int(value) for value in data.get("target_ids", [])})
                known_ids = {row[0] for row in con.execute("SELECT id FROM targets")}
                if not set(target_ids) <= known_ids:
                    abort(400, "Unknown target in access list")
                con.execute("DELETE FROM token_targets WHERE token_serial=?", (serial,))
                con.executemany(
                    "INSERT INTO token_targets(token_serial,target_id) VALUES(?,?)",
                    [(serial, target_id) for target_id in target_ids],
                )
    elif action == "token_delete":
        serial = normalize_serial(str(data.get("serial", "")))
        with db() as con:
            row = con.execute("SELECT role,enabled FROM tokens WHERE serial=?", (serial,)).fetchone()
            if row is None:
                abort(404)
            if row["role"] == "ADMIN" and row["enabled"] and other_active_admins(con, serial) == 0:
                abort(409, "The last active administrator cannot be deleted")
            con.execute("DELETE FROM tokens WHERE serial=?", (serial,))
    elif action == "target_add":
        name = str(data.get("name", "")).strip()
        internal_ip = str(ipaddress.ip_address(str(data.get("internal_ip", ""))))
        internal_port = int(data.get("internal_port", 3389))
        if not name or not 1 <= internal_port <= 65535:
            abort(400)
        with db() as con:
            con.execute("BEGIN IMMEDIATE")
            port_min, port_max = gateway_port_range(con)
            used = {row["gateway_port"] for row in con.execute(
                "SELECT gateway_port FROM targets WHERE gateway_port BETWEEN ? AND ?", (port_min, port_max))}
            gateway_port = next((port for port in range(port_min, port_max + 1)
                                 if port not in used and gateway_port_available(port)), None)
            if gateway_port is None:
                abort(409, "No free RDP gateway ports")
            cursor = con.execute("INSERT INTO targets(name,internal_ip,internal_port,gateway_port,enabled) "
                                 "VALUES(?,?,?,?,1)", (name, internal_ip, internal_port, gateway_port))
            target = con.execute("SELECT * FROM targets WHERE id=?", (cursor.lastrowid,)).fetchone()
        gate.start_target(target)
    elif action == "target_update":
        target_id = int(data.get("target_id", 0))
        name = str(data.get("name", "")).strip()
        internal_ip = str(ipaddress.ip_address(str(data.get("internal_ip", ""))))
        internal_port, gateway_port = int(data.get("internal_port", 3389)), int(data.get("gateway_port", 0))
        enabled = 1 if data.get("enabled", True) else 0
        port_min, port_max = gateway_port_range()
        if not name or not 1 <= internal_port <= 65535 or not port_min <= gateway_port <= port_max:
            abort(400)
        with db() as con:
            current = con.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
            if current is None:
                abort(404)
            if con.execute("SELECT 1 FROM targets WHERE gateway_port=? AND id<>?",
                           (gateway_port, target_id)).fetchone():
                abort(409, "Gateway port is already used")
            if gateway_port != current["gateway_port"] and not gateway_port_available(gateway_port):
                abort(409, "Gateway port is occupied")
            con.execute("UPDATE targets SET name=?,internal_ip=?,internal_port=?,gateway_port=?,enabled=? WHERE id=?",
                        (name, internal_ip, internal_port, gateway_port, enabled, target_id))
            target = con.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
        if enabled:
            gate.restart_target(target)
        else:
            gate.stop_target(target_id)
    elif action == "target_delete":
        target_id = int(data.get("target_id", 0))
        with db() as con:
            target = con.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
            if target is None:
                abort(404)
        gate.stop_target(target_id)
        with db() as con:
            con.execute("UPDATE access_log SET target_name=? WHERE target_id=? AND target_name=''",
                        (target["name"], target_id))
            con.execute("DELETE FROM targets WHERE id=?", (target_id,))
    elif action == "ports_update":
        port_min, port_max = int(data.get("port_min", 0)), int(data.get("port_max", 0))
        if not 1024 <= port_min <= port_max <= 65535 or port_max - port_min > 999:
            abort(400, "Invalid port range")
        with db() as con:
            con.execute("INSERT INTO settings(key,value) VALUES('port_min',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(port_min),))
            con.execute("INSERT INTO settings(key,value) VALUES('port_max',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(port_max),))
    elif action in {"grant_add", "grant_delete"}:
        serial = normalize_serial(str(data.get("serial", "")))
        target_id = int(data.get("target_id", 0))
        with db() as con:
            if action == "grant_add":
                con.execute("INSERT OR IGNORE INTO token_targets(token_serial,target_id) VALUES(?,?)",
                            (serial, target_id))
            else:
                con.execute("DELETE FROM token_targets WHERE token_serial=? AND target_id=?",
                            (serial, target_id))
    else:
        abort(400, "Unknown action")
    return jsonify(result_payload)


def main():
    init_db()
    with db() as con:
        for target in con.execute("SELECT * FROM targets WHERE enabled=1"):
            gate.start_target(target)
    app.run(host=HTTP_HOST, port=HTTP_PORT, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
