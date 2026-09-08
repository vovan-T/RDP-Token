# Changelog

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
