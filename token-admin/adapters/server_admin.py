import json
import os
import platform
import re
import subprocess
import urllib.error
import urllib.request
from html import unescape
from pathlib import Path


def _curl_path():
    if platform.system() != "Windows":
        raise RuntimeError("Серверное управление сейчас поддерживается только в Windows")
    path = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "curl.exe"
    if not path.is_file():
        raise RuntimeError("Не найден штатный Windows curl.exe")
    return path


def _base_url(settings):
    port = "" if settings.server_port == 443 else f":{settings.server_port}"
    return f"https://{settings.server_address}{port}"


def _http_error_message(status: int, body: str) -> str:
    """Turn API JSON/plain/HTML errors into a short user-facing Russian message."""
    text = body.strip()
    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            text = str(payload.get("message") or payload.get("detail") or payload.get("error") or text)
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    text = unescape(re.sub(r"<[^>]+>", " ", text))
    text = " ".join(text.split())
    lowered = text.lower()
    if status == 409 and "last active administrator" in lowered:
        return ("Нельзя удалить единственного активного администратора. "
                "Сначала добавь и разреши другой токен с ролью ADMIN.")
    defaults = {
        400: "Сервер отклонил запрос.",
        401: "Сеанс не авторизован. Выполни вход заново.",
        403: "Недостаточно прав для выполнения операции.",
        404: "Запрошенный объект не найден.",
        409: "Операция конфликтует с текущим состоянием системы.",
        500: "Внутренняя ошибка сервера.",
    }
    return text or defaults.get(status, f"Ошибка сервера HTTP {status}.")


def _request(settings, path, auth=None, payload=None):
    if not auth or not auth.get("certificate"):
        return _request_native(settings, path, auth=auth, payload=payload)

    command = [str(_curl_path()), "--silent", "--show-error", "--max-time", "30",
               "--header", "X-RDP-Token-Client: windows"]
    if auth and auth.get("certificate"):
        command.extend(["--cert", rf"CurrentUser\MY\{auth['certificate']}"])
    if payload is not None:
        command.extend(["--header", "Content-Type: application/json", "--data-binary",
                        json.dumps(payload, ensure_ascii=False)])
    command.extend([_base_url(settings) + path, "--write-out", "\n%{http_code}"])
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
            timeout=35,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Сервер ответил, но Windows curl.exe не завершился за 35 секунд") from exc
    output = result.stdout.decode("utf-8", errors="replace")
    error = result.stderr.decode("utf-8", errors="replace").strip()
    if result.returncode != 0:
        raise RuntimeError(error or f"curl.exe: код {result.returncode}")
    body, _, status_text = output.rpartition("\n")
    try:
        status = int(status_text.strip())
    except ValueError:
        raise RuntimeError("Сервер вернул ответ без HTTP-статуса")
    if not 200 <= status < 300:
        raise RuntimeError(_http_error_message(status, body))
    return json.loads(body) if body.strip() else {}


def _request_native(settings, path, auth=None, payload=None):
    """HTTP for recovery sessions without exposing a bearer token in process arguments."""
    headers = {"X-RDP-Token-Client": "windows"}
    if auth and auth.get("session"):
        headers["Authorization"] = f"Bearer {auth['session']}"
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        _base_url(settings) + path,
        data=data,
        headers=headers,
        method="POST" if payload is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(_http_error_message(exc.code, body)) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"Нет ответа от сервера: {exc}") from exc
    return json.loads(body) if body.strip() else {}


def exchange_recovery_code(settings, code):
    return _request(settings, "/api/recovery/exchange", payload={"code": code})


def exchange_certificate_session(settings, certificate):
    return _request(
        settings,
        "/api/admin/session",
        auth={"certificate": certificate},
        payload={},
    )


def load_admin_state(settings, auth):
    return _request(settings, "/api/admin/state", auth=auth)


def admin_action(settings, auth, action, **values):
    return _request(settings, "/api/admin/action", auth=auth,
                    payload={"action": action, **values})
