# PKCS#11 provider packs

Obtain software from the manufacturers and accept their licenses yourself:

- Rutoken: https://www.rutoken.ru/support/download/
- Rutoken Linux: https://www.rutoken.ru/support/download/nix/
- ESMART: https://token.esmart.ru/downloads
- OpenSC: https://github.com/OpenSC/OpenSC/releases
- Yubico PIV: https://github.com/Yubico/yubico-piv-tool/releases
- SmartCard-HSM: https://github.com/CardContact/sc-hsm-embedded/releases
- FEITIAN: https://www.ftsafe.com/products/PKI/Standard/Specification
- JaCarta: https://www.aladdin-rd.ru/support/sdk/
- SafeNet/eToken: https://cpl.thalesgroup.com/access-management/security-applications/authentication-client-token-management

Windows x64 portable layout, relative to `token-admin/` when running source or
beside `RDP-Token-Manager.exe` in a packaged build:

```text
lib/rtpkcs11ecp.dll
lib/rtadmin.exe
lib/PKIClientCli.exe
lib/providers/opensc/opensc-pkcs11.dll
lib/providers/yubico/libykcs11.dll
lib/providers/smartcard-hsm/sc-hsm-pkcs11.dll
lib/providers/feitian/eps2003csp11.dll
lib/providers/jacarta/jcPKCS11-2.dll
lib/providers/safenet/eTPKCS11.dll
```

The registry also checks standard vendor installation paths.  It opens only
the first provider matching the physical PC/SC reader.  Native Rutoken/ESMART
providers have priority and OpenSC is the final fallback.  Do not copy every
DLL into the flat `lib` directory: a token may otherwise be exposed more than
once by different middleware.

`--providers` lists detected packs without opening a token:

```powershell
.\RDP-Token-Manager.exe --providers
```

`--test-providers --report provider-test.json` additionally loads each detected
module and enumerates its slots without logging in or changing token contents.

OpenSC and SmartCard-HSM are open-source projects, but their license files and
notices must accompany redistributed binaries. Closed vendor SDK/runtime files
must not be republished until their redistribution terms have been checked.

Include each official utility's accompanying runtime dependencies, not just the
named executable. Some ESMART paths also use the installed Windows System32
`isbc_pkcs11_main.dll`; install the appropriate official provider when required.
Installing a driver alone does not populate the CLI paths above.

Historical lab versions: rtadmin 3.2 and ESMART PKI Client/CLI 4.17. This is an
account of prior testing, not a claim these are the current vendor versions or
that any arbitrary firmware/library combination is supported.

For a locally built EXE, put the same `lib/` tree next to the EXE. The build does
not embed it. Verify signatures and distribution rights before using or sharing
vendor packages. The public source repository does not include closed vendor
installers, DLLs or SDK archives.
