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

Driver/runtime binaries are **not included** in the public release. See
[vendor/README.md](vendor/README.md) for their sources and licensing boundary.
The current portable layout is one flat `lib` directory beside the EXE; source
runs use `token-admin/lib`. A source-only installation can show missing-tool
errors until those prerequisites are supplied. Remote USB passthrough to the
Docker gateway is not required.

The UI can inspect certificates/public keys, create keys and CSR requests,
install matching signed certificates, change PINs/labels and perform supported
initialization/formatting operations. Test with expendable tokens; these actions
can destroy existing private keys. PIN retry counters are hardware-enforced.
Some CLI-backed operations pass PINs in process arguments: see SECURITY.md.

The `Экспорт токена...` action writes a portable JSON token card containing only
public certificate identity and metadata. It never exports a private key or PIN.
An administrator can later choose `Добавить` -> `Из файла...` to register that
identity when the physical token cannot be connected to the administrator's PC.
Importing the card grants nothing by itself: the administrator still assigns the
token to selected systems in the management tab.

## Administrator login

Token Manager does not export a private key and does not send the PIN to the
gateway. The gateway returns a random one-use challenge valid for 30 seconds;
the selected token signs it locally and the gateway verifies the signature,
certificate chain, current CRL, registered certificate serial and ADMIN role.
The resulting bearer session is time-limited. Reusing the same challenge is
rejected.

RSA Rutoken models use their PKCS#11 module directly, including the selected
token serial and certificate CKA_ID. Other devices use the Windows provider only
when that provider exposes the certificate and its private key to the current
user. RSA and ECDSA are supported by that fallback; GOST signing still depends
on a compatible provider on both client and server. The older Windows-store
mTLS exchange remains in the source as a temporary compatibility fallback but
is no longer the normal UI login path.

## Local EXE build

The release may include an unsigned convenience EXE built from this public tree.
It does not contain private deployment defaults or vendor binaries. To build the
same source locally with PyInstaller already installed, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\build-windows.ps1
```

The output is `dist\RDP-Token-Manager.exe`. The script bundles our assets but
does not bundle any vendor binaries. If needed for your own authorized deployment,
place vendor files in `dist\lib\` according to vendor/README.md. Review
redistribution terms before sharing them. This preview does not provide signed
installers or claim that every token works without driver installation.

## Diagnostic log

The `Журнал` button in the bottom status bar opens an in-application viewer.
The complete rotating log is stored at
`%LOCALAPPDATA%\RDP-Token\logs\manager.log`. It records the PC/SC, PKCS#11,
Windows CSP/KSP and ESMART inventory stages, their duration and errors. It does
not record PINs, private keys, full certificate contents or recovery codes.

## Command diagnostics

The same executable can create a sanitized JSON report without opening the
main window:

```powershell
.\RDP-Token-Manager.exe --diagnose
```

To perform exactly one masked PIN check per supported token:

```powershell
.\RDP-Token-Manager.exe --test-tokens
```

PIN values are requested in separate protected dialogs. They cannot be passed
as command-line arguments and are not written to the report or diagnostic log.
Use `--report C:\path\report.json` to choose the output file and `--quiet` to
suppress the final completion dialog.
