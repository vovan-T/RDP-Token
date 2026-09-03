"""Read-only portable PKCS#11 probe for ESMART GOST D."""

import sys
from pathlib import Path

def main() -> int:
    project = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(project))
    from adapters.esmart_portable import probe_esmart

    result = probe_esmart(Path(sys.argv[1]))
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
