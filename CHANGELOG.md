# Changelog

## 0.7.3 — 2026-09-15

- Added ordered provider packs for Rutoken, ESMART, Yubico, SmartCard-HSM,
  FEITIAN, JaCarta, SafeNet/eToken and OpenSC.
- The client opens only the first provider that matches a physical PC/SC reader;
  OpenSC is a final fallback, preventing duplicate token rows.
- Added `--providers` and provider details to sanitized diagnostics.
- Generic providers are read-only except for one explicit PIN verification;
  destructive operations remain limited to tested native Rutoken/ESMART paths.

## 0.7.2 — 2026-09-15

- Added `--diagnose` for sanitized command-driven token inventory reports.
- Added `--test-tokens` for a single masked PIN check per supported token.
- Diagnostic reports exclude PINs, private keys and complete certificate bodies.

## 0.7.1 — 2026-09-09

- Token and certificate inventory now runs outside the Tk GUI thread.
- Added an indeterminate progress indicator and explicit busy status while scanning.
- Added a rotating local diagnostic journal with a built-in viewer.
- Inventory diagnostics identify PC/SC, Rutoken utility, PKCS#11, Windows CSP/KSP
  and ESMART stages without recording PINs or private-key material.
- Corrected the web access hint: a physical token with an accessible private key
  is required by the intended deployment model.

## 0.7.0 — 2026-09-09

- Added CRL management and signed token challenge authentication for administrators.
- Added portable token-card import/export and expanded Rutoken/ESMART handling.
- Added the 50-second mode 1 grant: established RDP is independent of the browser.
- Added a guarded Ubuntu installer for fresh `/opt/RDP-Token` deployments.
- Updated branding, dialogs, Windows metadata and portable Manager packaging.

## 0.1.0-preview.2 — 2026-09-03

- Added export of a selected token certificate as a portable public token card.
- Added offline import of that card into gateway administration.
- Added final Vovan-T branding for the web portal, browser favicon and Windows client.
- Updated Token Manager to 0.6.7; deployment addresses remain neutral examples.
- Release EXE excludes vendor binaries, private keys, PINs and deployment data.

## 0.1.0-preview.1 — 2026-09-03

- Initial public source package: Docker gateway, web management and desktop sources.
- Connection/retry window defaults to 50 seconds, one active TCP per target.
- RDP clipboard enabled; smart-card redirection and forced credential prompt disabled.
- Removed deployment-specific hostnames, bootstrap identity and server artifacts.
- Added installation guide, security limitations, isolated tests and CI workflow.
- Vendor binaries excluded; locally built desktop EXE resolves external vendor
  files beside the EXE. Window icons remain bundled resources.
- Existing production/lab deployment was not changed by packaging.
