# External vendor prerequisites (not distributed)

Obtain software from the manufacturers and accept their licenses yourself:

- Rutoken: https://www.rutoken.ru/support/download/
- Rutoken Linux: https://www.rutoken.ru/support/download/nix/
- ESMART: https://token.esmart.ru/downloads

Windows x64 portable layout, relative to `token-admin/` when running source or
beside `RDP-Token-Manager.exe` in a packaged build:

```text
lib/rtpkcs11ecp.dll
lib/rtadmin.exe
lib/PKIClientCli.exe
```

Include each official utility's accompanying runtime dependencies, not just the
named executable. Some ESMART paths also use the installed Windows System32
`isbc_pkcs11_main.dll`; install the appropriate official provider when required.
Installing a driver alone does not populate the CLI paths above.

Historical lab versions: rtadmin 3.2 and ESMART PKI Client/CLI 4.17. This is an
account of prior testing, not a claim these are the current vendor versions or
that any arbitrary firmware/library combination is supported.

For a locally built EXE, put the same flat `lib/` directory next to the EXE. The
build does not embed it. Verify signatures and distribution rights before using
or sharing vendor packages. No vendor installer, DLL, SDK archive or third-party
source tree is included in this repository.
