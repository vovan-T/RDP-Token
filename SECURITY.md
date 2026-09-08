# Security status: laboratory preview

Do not deploy this release as an unrestricted Internet-facing security gateway.
It has not undergone an independent security audit. The packaging tests are not
a security certification.

## Known limitations

1. **First-connection race:** HTTPS certificate authorization opens a target TCP
   grant. Its first TCP source is accepted without comparing it with the web
   client's IP or proving possession of the certificate. A reachable unrelated
   client can claim that window. Later retries bind to the first source IP;
   clients sharing a NAT address are not distinguishable.
2. **No removal enforcement:** closing the browser or removing the physical token
   does not close established RDP. There is no browser heartbeat in mode 1.
   Expiring a grant only blocks new TCP connections.
3. **Trusted local boundary:** the Flask backend trusts certificate/identity
   headers supplied by nginx. Keep it on loopback on a dedicated trusted host;
   any untrusted local process or host-network container can reach it. Never
   publish this backend or permit header spoofing through another proxy.
4. **Single-process state:** pending grants, active slots and listeners live in
   process memory. Restarting the app closes RDP and clears grants. Do not switch
   to multiple WSGI workers or replicas without redesigning this state handling.
5. **HTTP server:** the current entry point uses Flask's development server with
   threading. There is no comprehensive rate limiting or resource-exhaustion
   hardening. Merely installing Gunicorn does not change this architecture.
6. **CA/identity scope:** identities are indexed by certificate serial, not by
   issuer plus serial. Use one dedicated client CA. Complex chains and CRL
   distribution need separate validation. CRLs must be refreshed operationally;
   missing/invalid/expired CRLs fail closed for certificate validation.
7. **Administrative sessions:** API bearer sessions are time-limited but are not
   revalidated against the CRL on every request. Emergency recovery is server
   operator access; protect host root, Docker access, the database and `.env`.
8. **Client PIN handling:** PINs are not intentionally stored in client settings
   or sent to the gateway, but some vendor CLI operations pass PINs in process
   arguments. Run Token Manager only on a trusted administrative workstation.
   Token formatting/deletion can irreversibly destroy keys; use test hardware.
9. **Target security remains necessary:** configure target RDP authentication,
   updates, account restrictions and network firewalling. The temporary TCP
   grant is not equivalent to certificate authentication of the RDP stream.

## Distribution hygiene

Deployment `.env`, databases, private keys, CA signing material, real CSR files,
packet captures, client work directories and vendor binaries are excluded from
Git and Docker build context. Do not add them to issues, releases or screenshots.
Back up `.env`, SQLite data and public trust material to protected storage.

Do not publish credentials in a vulnerability report. Use GitHub private
vulnerability reporting if enabled; otherwise ask the maintainer for a private
contact channel without including exploit details or secrets in a public issue.
