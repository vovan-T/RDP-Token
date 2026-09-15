from dataclasses import dataclass, field


@dataclass
class TokenInfo:
    reader: str
    atr: str
    vendor: str
    model: str
    state: str
    error: str = ""
    label: str = ""
    serial: str = ""
    user_pin_attempts: str = "—"
    admin_pin_attempts: str = "—"
    memory: str = "—"
    slot_id: str = ""
    provider_id: str = ""
    provider_name: str = ""
    provider_path: str = ""
    key_options: list[str] = field(default_factory=list)
    objects: list[dict] = field(default_factory=list)
