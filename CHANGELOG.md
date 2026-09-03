# Changelog

## 0.1.0-preview.1 — 2026-09-03

- Initial public source package: Docker gateway, web management and desktop sources.
- Connection/retry window defaults to 50 seconds, one active TCP per target.
- RDP clipboard enabled; smart-card redirection and forced credential prompt disabled.
- Removed deployment-specific hostnames, bootstrap identity and server artifacts.
- Added installation guide, security limitations, isolated tests and CI workflow.
- Vendor binaries excluded; locally built desktop EXE resolves external vendor
  files beside the EXE. Window icons remain bundled resources.
- Existing production/lab deployment was not changed by packaging.
