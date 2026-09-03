import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class ClientSettings:
    server_address: str = "rdp.example.invalid"
    server_port: int = 443
    tls_server_name: str = "rdp.example.invalid"


def settings_path() -> Path:
    base = Path(os.getenv("APPDATA", Path.home())) / "RDP-Token"
    return base / "client.json"


def load_settings() -> ClientSettings:
    path = settings_path()
    if not path.is_file():
        return ClientSettings()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return ClientSettings(
            server_address=str(data.get("server_address", "rdp.example.invalid")).strip(),
            server_port=int(data.get("server_port", 443)),
            tls_server_name=str(data.get("tls_server_name", "rdp.example.invalid")).strip(),
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return ClientSettings()


def save_settings(settings: ClientSettings) -> None:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(asdict(settings), ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)
