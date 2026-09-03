# Validation for v0.1.0-preview.1

Performed during packaging on 2026-09-03:

- Compose configuration parsed using `.env.example`, without reading live secrets.
- Docker image built successfully in a separate temporary Ubuntu directory.
- Six gateway unit tests passed (50-second default, unauthenticated rejection,
  sequential single-use recovery, recovery expiry, authenticated RDP output).
- Five TCP proxy tests passed (atomic/concurrent claims, original retry deadline,
  different-IP rejection after first claim, single active target slot, loopback
  byte forwarding after heartbeat/window expiry, failed-upstream cleanup).
- Separate RDP response test passed: clipboard enabled, smartcards disabled,
  forced credential prompt disabled, missing target denied.
- Python syntax and tracked-file checks passed; deployment-specific domain/IP
  values and bootstrap certificate identifiers were removed from release sources.
- GUI module import passed on Windows Python 3.12 with cryptography 50.0.0,
  without starting the UI or touching tokens.

The final formatting cleanup does not change application behavior. The tests
ran against the final source mounted read-only inside the test image. No running
gateway was updated or restarted for packaging.

Not verified by this release check: full fresh TLS deployment, CA/CRL lifecycle,
hardware formatting/CSR operations, every vendor driver/model, newly built EXE,
cross-platform GUI parity, or resistance to a hostile Internet environment.
See SECURITY.md before deployment. Test success is not a security audit.
