# Vovan-T Token Manager

Python 3.12 / Tkinter desktop sources. The UI is primarily Windows-oriented;
Linux PC/SC inventory is present, but Windows certificate-store integration and
most vendor administration paths are not portable equivalents.

## Run on Windows

Install the dependencies only with the workstation owner's approval:

```powershell
python -m pip install -r requirements.txt
python token_admin.py
```

The server address is configured with the settings button. The default is
`rdp.example.invalid`; replace it with your gateway name and HTTPS port.
`%APPDATA%\RDP-Token\client.json` stores these connection settings, not PINs.
Token-management state is loaded from the server. CSR/INF files and selected
exports are written locally; this application is not entirely stateless.

## Token support and prerequisites

- Rutoken: PC/SC inventory, SDK/PKCS#11 operations and Windows CSP/KSP integration
  depending on the actual model, installed providers and vendor tools.
- ESMART: PC/SC, vendor CLI/PKCS#11 and Windows certificate operations depending
  on the device and installed runtime.
- Other PC/SC devices: inventory; Windows KSP fallback only where a compatible
  provider is actually available. Generic compatibility is not promised.

Driver/runtime binaries are **not included**. See [vendor/README.md](vendor/README.md)
for the directories expected by the adapters. A source-only installation can
show missing-tool errors until those prerequisites are supplied. Remote USB
passthrough to the Docker gateway is not required.

The UI can inspect certificates/public keys, create keys and CSR requests,
install matching signed certificates, change PINs/labels and perform supported
initialization/formatting operations. Test with expendable tokens; these actions
can destroy existing private keys. PIN retry counters are hardware-enforced.
Some CLI-backed operations pass PINs in process arguments: see SECURITY.md.

## Local EXE build

The public release contains source archives, not the old development EXE with
private deployment defaults and vendor binaries. With PyInstaller already
installed in your selected Python environment, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\build-windows.ps1
```

The output is `dist\RDP-Token-Manager.exe`. The script bundles our assets but
does not bundle any vendor binaries. If needed for your own authorized deployment,
place vendor files in `dist\vendor\...` according to vendor/README.md. Review
redistribution terms before sharing them. This preview does not provide signed
installers or claim that every token works without driver installation.
