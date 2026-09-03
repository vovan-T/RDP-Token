# RDP-Token

![RDP-Token](app/static/brand/rdp-token-logo.png)

Certificate-authenticated web portal, time-limited TCP gateway for RDP, and
Vovan-T Token Manager desktop sources. **Laboratory preview — not a hardened
replacement for RD Gateway, VPN or a zero-trust access product.**

Интерфейс портала и клиента — на русском. [Установка и работа](docs/INSTALL.ru.md).
[Security limitations](SECURITY.md) must be read before deployment.

## What is included

- Docker Compose gateway: Python/Flask, SQLite, nginx TLS front end.
- Web management: certificates/tokens, systems, access assignments, port range,
  and connection journal.
- Windows-oriented Python/Tkinter Token Manager: local token inventory,
  CSR/certificate operations, portable public token-card export/import and
  remote gateway management.
- Isolated tests, Windows build instructions and deployment examples.

No deployment keys, certificates, databases, PINs, logs, vendor installers or
vendor libraries are distributed. The optional unsigned Windows EXE contains
only the public Python application and visual resources; vendor tools are
obtained separately under their own terms. See [Token Manager](token-admin/README.md).

## Connection model

Browser with client certificate -> HTTPS portal -> temporary RDP grant.
RDP client -> gateway TCP port -> target Windows/Linux RDP service.

- One web grant opens a **50-second** connection window.
- The first TCP connection binds the grant to its source IP. Retrying from that
  IP is allowed within the original window, after the previous TCP closes.
- Only one active TCP connection per target; different targets can be used
  simultaneously. A new grant does not permit parallel connections to the same
  target.
- An established TCP connection continues after the window expires.
- Browser closure or token removal **does not terminate an established RDP
  connection** in this version.
- The generated RDP file keeps clipboard redirection enabled, disables smart-card
  redirection, and does not force a new credential prompt. Windows policies still
  control whether saved credentials can be used.
- The gateway does not replace the target computer's Windows authentication.

**Important:** the first TCP source is not matched to the browser's IP. An
unrelated reachable client can race to consume an open grant. Use a restricted
lab network/firewall; do not expose the TCP range as a production security
boundary. See [SECURITY.md](SECURITY.md).

## Quick start

Requires an existing Linux Docker Engine with Compose, OpenSSL, a TLS server
certificate/private key, and a dedicated client CA with a current CRL. The
scripts do not install software or change firewall rules.

```sh
sh scripts/create-env.sh
vim .env
sudo sh scripts/prepare-data.sh
# Add certs/client-ca.pem and certs/client.crl.pem as described in certs/README.md.
sudo docker compose config --quiet
sudo docker compose up -d --build
sudo docker compose ps
```

Set the administrator **certificate serial number**, not the physical token's
serial, in `RDP_TOKEN_BOOTSTRAP_ADMIN_SERIAL`. Configure the hostname and TLS
paths before starting. The default examples use a deliberately invalid domain.
The default HTTPS listener is 18443; the app binds to loopback 18081. Either use
the explicit HTTPS port or configure a direct TCP 443 forwarding rule. RDP ports
start at 60000. Nothing configures NAT automatically.

## Tests

```sh
sudo docker build -t rdp-token-check .
sudo docker run --rm --network none --read-only --tmpfs /tmp:size=32m \
  -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONPATH=/src \
  -v "$PWD:/src:ro" -w /src rdp-token-check sh scripts/test.sh
```

Tests use temporary SQLite databases and loopback sockets. They do not touch
the live gateway, tokens or a real RDP desktop. Hardware operations and actual
Windows desktop behavior require separate client testing.

## Release status

`v0.1.0-preview.2` packages the laboratory implementation. Deployment-specific
defaults were replaced with examples; the tested grant/relay logic was retained.
The desktop client adds portable public token cards and the final Vovan-T visual
identity. Windows installer signing, driver redistribution and Linux feature
parity are not part of this release. No general open-source license is selected yet; public
visibility is not a grant of redistribution rights beyond applicable platform terms.

This is an independent project, not affiliated with Microsoft, Aktiv or ISBC.
