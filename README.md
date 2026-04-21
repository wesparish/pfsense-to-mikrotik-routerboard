# pfmk — pfSense → MikroTik config generator

Translate a pfSense XML backup into a RouterOS `.rsc` script you can review and
`/import` on a MikroTik router. Built to migrate a home or small-office firewall
off aging pfSense hardware onto a MikroTik RB3011 (or any RouterOS 7 device)
without starting from scratch.

The output is native RouterOS — no agent, no runtime dependency, no framework.
Read it, adjust what you need, `/import` it.

## What it does

Reads a pfSense XML backup and emits a single `.rsc` covering:

- System identity + timezone
- Ethernet + bridge + IP addresses, DHCP clients on the WAN(s)
- DHCP server pool, network, and static leases (dup-IP detection)
- DNS static entries, with per-domain drop filter
- WireGuard (NordVPN via NordLynx) — override-driven, placeholders for secrets
- Firewall filter rules — translated, originals preserved as comments,
  `chain=input` baseline auto-added, input-chain candidates auto-detected
- NAT — port forwards, baseline masquerade, outbound rules as reference
- Policy routing + mangle — LAN-through-VPN default, per-WAN bypass lists,
  WAN2 asymmetric-return fix
- DDNS updater scripts (GoDaddy + Cloudflare), credentials inlined from backup

Out of scope — see [docs/caveats.md](docs/caveats.md) for details:

- OpenVPN static-key (`p2p_shared_key`) site-to-site
- IPsec mobile roadwarrior
- Snort / Suricata / pfBlockerNG / Squid / SquidGuard / ClamAV
- IPv6

## Install

Python 3.10+. Uses [Poetry](https://python-poetry.org/) for dependency and
virtualenv management.

```bash
git clone <repo-url>
cd pfsense-to-mikrotik-routerboard
poetry install
```

If you prefer pip, the project is a standard PEP 517 package — `pip install .`
works too; you'll just manage the venv yourself.

## Quick start

```bash
# 1. Drop your pfSense XML backup into pfsense-configs/ (gitignored).
#    File can be named anything, e.g. config-pfsense.home-20260420.xml

# 2. Scaffold an overrides YAML from the backup:
poetry run pfmk init-overrides pfsense-configs/config-<name>.xml

# This writes overrides/<hostname>.yaml with:
#   - interface → ether guesses filled in
#   - bypass IPs extracted from pfSense gateway-pinned rules
#   - TODO markers where your input is required (NordVPN creds, etc.)

# 3. Open overrides/<hostname>.yaml, search for TODO, and fill in.

# 4. Generate:
poetry run pfmk generate \
    pfsense-configs/config-<name>.xml \
    --overrides overrides/<hostname>.yaml \
    --out output/mikrotik.rsc

# Add -v (or -vv) to see what's being parsed, translated, and skipped:
#   poetry run pfmk -v generate …

# 5. Read output/mikrotik.rsc end-to-end.
#    Pay attention to:  # SKIPPED  # NOTE  <FILL_IN_*>

# 6. On the MikroTik:
#    /import file-name=mikrotik.rsc verbose=yes
```

`poetry shell` drops you in the venv if you'd rather run `pfmk` and `pytest`
directly.

### Why two files

The **pfSense XML** is a snapshot of a running system — 100 firewall rules,
29 DHCP leases, 19 DNS entries, interface definitions using pfSense's
vocabulary (`wan`, `opt1`, `vtnet0`).

The **overrides YAML** is a design doc for the new system — physical port
assignments on this specific MikroTik (`opt1 → ether2`), semantic roles
(`WAN2 is ingress for K8s`), bridge membership, what to drop, the
WireGuard reshape. None of this can live in the backup.

`pfmk init-overrides` reads the XML and fills in everything it *can*
derive, with clearly-marked TODOs for the rest. See
[docs/migration-guide.md](docs/migration-guide.md) for the full flow.

## Tests

```bash
poetry run pytest
```

Runs against a synthetic fixture (no PII), so anyone can clone and verify.

## Docs

- [Migration guide](docs/migration-guide.md) — opinionated end-to-end flow
- [Architecture](docs/architecture.md) — how the generator is structured
- [Caveats](docs/caveats.md) — what doesn't translate and why
