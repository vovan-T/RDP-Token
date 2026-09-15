#!/usr/bin/env python3
import tempfile
from pathlib import Path
from unittest.mock import patch

from token_admin_test_support import token_admin_path


ROOT = token_admin_path()
import sys
sys.path.insert(0, str(ROOT))

from adapters import provider_registry


def test_native_provider_precedes_opensc_fallback():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "providers" / "rutoken").mkdir(parents=True)
        (root / "providers" / "opensc").mkdir(parents=True)
        (root / "providers" / "rutoken" / "rtpkcs11ecp.dll").touch()
        (root / "providers" / "opensc" / "opensc-pkcs11.dll").touch()
        with patch.object(provider_registry, "lib_dir", return_value=root), \
             patch.object(provider_registry.platform, "system", return_value="Windows"):
            result = provider_registry.providers_for("Aktiv", "Aktiv Rutoken ECP", "Rutoken")
        assert [item[0].provider_id for item in result] == ["rutoken", "opensc"]


def test_unknown_reader_uses_only_generic_provider():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "providers" / "opensc").mkdir(parents=True)
        (root / "providers" / "opensc" / "opensc-pkcs11.dll").touch()
        with patch.object(provider_registry, "lib_dir", return_value=root), \
             patch.object(provider_registry.platform, "system", return_value="Windows"):
            result = provider_registry.providers_for("Не определён", "USB Reader", "Смарт-карта")
        assert [item[0].provider_id for item in result] == ["opensc"]


if __name__ == "__main__":
    test_native_provider_precedes_opensc_fallback()
    test_unknown_reader_uses_only_generic_provider()
    print("provider registry tests passed")
