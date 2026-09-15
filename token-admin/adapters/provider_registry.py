"""Discovery and selection of optional PKCS#11 provider packs.

Provider DLLs are deliberately external to the executable.  A provider can be
installed system-wide or placed under ``lib/providers/<provider-id>/`` beside
the application.  Only the best matching provider is opened for each physical
reader; this prevents duplicate slots and avoids probing every vendor DLL.
"""

from dataclasses import dataclass
import os
import platform
from pathlib import Path

from adapters.tool_paths import lib_dir


@dataclass(frozen=True)
class ProviderSpec:
    provider_id: str
    name: str
    filenames: tuple[str, ...]
    vendor_names: tuple[str, ...] = ()
    reader_markers: tuple[str, ...] = ()
    system_locations: tuple[str, ...] = ()
    generic: bool = False
    safe_write: bool = False


PROVIDERS = (
    ProviderSpec(
        "rutoken", "Rutoken PKCS#11",
        ("rtpkcs11ecp.dll", "rtPKCS11ECP.dll", "rtPKCS11.dll"),
        ("aktiv",), ("rutoken", "rutokn"),
        (r"%WINDIR%\System32",), safe_write=True,
    ),
    ProviderSpec(
        "esmart", "ESMART PKCS#11",
        ("isbc_pkcs11_main.dll",), ("isbc",), ("esmart",),
        (r"%WINDIR%\System32",), safe_write=True,
    ),
    ProviderSpec(
        "yubico", "Yubico PIV PKCS#11", ("libykcs11.dll",),
        ("yubico",), ("yubico", "yubikey"),
        (r"%ProgramFiles%\Yubico\Yubico PIV Tool\bin",),
    ),
    ProviderSpec(
        "smartcard-hsm", "SmartCard-HSM PKCS#11",
        ("sc-hsm-pkcs11.dll", "sc-hsm-pkcs.dll"),
        ("cardcontact",), ("smartcard-hsm", "sc-hsm", "starcos"),
        (r"%ProgramFiles%\CardContact\SmartCard-HSM Middleware",),
    ),
    ProviderSpec(
        "feitian", "FEITIAN ePass PKCS#11",
        ("eps2003csp11.dll", "ep2pk11.dll", "ngp11v211.dll"),
        ("feitian",), ("feitian", "epass2003", "epass3000", "epass"),
    ),
    ProviderSpec(
        "jacarta", "JaCarta PKCS#11", ("jcPKCS11-2.dll", "asepkcs.dll"),
        ("aladdin",), ("jacarta", "aladdin"),
    ),
    ProviderSpec(
        "safenet", "SafeNet/eToken PKCS#11",
        ("eTPKCS11.dll", "IDPrimePKCS1164.dll", "eToken.dll", "FKMeToken.dll"),
        ("thales", "safenet", "gemalto"),
        ("safenet", "etoken", "idprime", "gemalto", "thales"),
        (r"%WINDIR%\System32",),
    ),
    ProviderSpec(
        "opensc", "OpenSC universal PKCS#11",
        ("opensc-pkcs11.dll",), (), (),
        (r"%ProgramFiles%\OpenSC Project\OpenSC\pkcs11", r"%WINDIR%\System32"),
        generic=True,
    ),
)


def _expand(path: str) -> Path:
    expanded = os.path.expandvars(path)
    # Python does not expand %NAME% on non-Windows hosts.  Diagnostics should
    # still remain deterministic there and simply report the provider absent.
    return Path(expanded)


def _candidate_paths(spec: ProviderSpec):
    root = lib_dir()
    directories = (root / "providers" / spec.provider_id, root)
    if platform.system() == "Windows":
        directories += tuple(_expand(item) for item in spec.system_locations)
    for directory in directories:
        for filename in spec.filenames:
            yield directory / filename


def installed_module(spec: ProviderSpec) -> Path | None:
    seen = set()
    for candidate in _candidate_paths(spec):
        identity = os.path.normcase(str(candidate.resolve(strict=False)))
        if identity in seen:
            continue
        seen.add(identity)
        if candidate.is_file():
            return candidate
    return None


def provider_status() -> list[dict]:
    result = []
    for spec in PROVIDERS:
        module = installed_module(spec)
        result.append({
            "id": spec.provider_id,
            "name": spec.name,
            "installed": module is not None,
            "module": str(module) if module else "",
            "generic": spec.generic,
            "safe_write": spec.safe_write,
            "filenames": list(spec.filenames),
        })
    return result


def providers_for(vendor: str, reader: str, model: str) -> list[tuple[ProviderSpec, Path]]:
    text = f"{vendor} {reader} {model}".casefold()
    exact, generic = [], []
    for spec in PROVIDERS:
        module = installed_module(spec)
        if module is None:
            continue
        if spec.generic:
            generic.append((spec, module))
            continue
        markers = spec.vendor_names + spec.reader_markers
        if any(marker.casefold() in text for marker in markers):
            exact.append((spec, module))
    return exact + generic


def provider_by_id(provider_id: str) -> tuple[ProviderSpec, Path] | None:
    for spec in PROVIDERS:
        if spec.provider_id == provider_id:
            module = installed_module(spec)
            return (spec, module) if module else None
    return None
