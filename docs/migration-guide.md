# Migration guide: pfSense → MikroTik

The intended end-to-end flow for using this tool.

## Step 1 — Inventory

Open your pfSense XML backup and take stock of what you have. Specifically:

- `<system>` — hostname, domain, timezone
- `<interfaces>` — WAN, LAN, OPT* with IPs and DHCP/static mode
- `<dhcpd>` — scope ranges and static lease counts
- `<filter>` — firewall rule count
- `<nat>` — port forward + outbound rule counts
- `<openvpn>`, `<ovpnserver>`, `<ipsec>` — any VPN configs, server-or-client,
  static-key or cert-based
- `<installedpackages>` — Snort, Squid, pfBlockerNG, etc.
- `<dyndnses>` — DDNS entries

## Step 2 — Scope decisions

For each non-trivial area, decide: **translate**, **replace**, or **drop**.

| Area | What this tool does |
|---|---|
| Interfaces, bridge, addressing, DHCP client/server, static leases | translate |
| DNS static hosts + domain overrides | translate (with drop filter) |
| Firewall filter / NAT port forwards | translate (best-effort, review required) |
| Outbound NAT | baseline masquerade + original rules preserved as comments |
| DDNS (GoDaddy, Cloudflare) | translate, credentials inlined from backup |
| NordVPN OpenVPN client | translate → WireGuard (NordLynx) |
| OpenVPN server (p2p_shared_key) | **drop** (MikroTik can't do static-key) |
| OpenVPN server (cert-based) | not yet implemented |
| IPsec site-to-site / mobile | not yet implemented |
| Snort / Suricata / pfBlockerNG | **drop or replace** (no RouterOS equivalent) |
| Squid / SquidGuard / ClamAV | **drop or replace** |
| IPv6 | not yet implemented |

If you need something in the "replace" column, budget for a separate box
(mini PC, NUC, or small x86 VM) running the Linux equivalent. RouterOS is a
router, not a Swiss Army knife.

## Step 3 — Scaffold `overrides/yours.yaml`

Run `init-overrides` to generate a starting overrides file from the backup:

```bash
poetry run pfmk init-overrides path/to/config.xml
```

It writes `overrides/<hostname>.yaml` with:

- `interfaces.*` pre-populated based on pfSense's interface list (first
  DHCP WAN → ether1/egress, second → ether2/ingress, LAN → bridge-lan
  with the remaining ethers as members, pseudo-interfaces skipped)
- `routing.bypass.via_wan` / `via_wan2` populated from pfSense rules
  that had an explicit `<gateway>` — those are your current policy-routed
  hosts, grouped by which WAN they bypass to
- `target.routeros_version` set to a reasonable default
- `vpn.nordvpn.*` scaffolded with `<FILL_IN>`-style TODO placeholders
- `domains.keep/drop` with `keep` prefilled from the pfSense domain and
  `drop` empty (you fill in)

Open the file and search for `TODO`. You'll almost always need to:

- Fill in `vpn.nordvpn.{address, peer_pubkey, endpoint_host}` — see
  [obtaining NordVPN WireGuard credentials](#obtaining-nordvpn-wireguard-credentials)
- Add retired domains to `domains.drop`
- Review the scaffolded interface guesses against your actual wiring
- Toggle `skip: true` on any interface the scaffold left as active that you'd
  rather retire, or vice versa

`overrides/*.yaml` is gitignored (except `example.yaml`), so you can keep
personal IPs and non-secret config in your fork. If you'd rather start from
scratch than edit the scaffold, copy `overrides/example.yaml` and fill in by
hand.

## Step 4 — Generate and review

```bash
poetry run pfmk generate path/to/config.xml \
    --overrides overrides/yours.yaml \
    --out output/mikrotik.rsc
```

Read the **entire** output. Grep for:

- `# SKIPPED` — rules we couldn't translate (usually retired interface or
  unsupported protocol)
- `# NOTE:` — ambiguous translations with a reason
- `# pfSense rule:` — context header before each translated rule; compare
  to what the translation did
- `<FILL_IN_*>` — credentials that need to be replaced by hand

For any `# SKIPPED` you care about, either add what's missing to the
overrides file, or hand-edit the `.rsc`.

## Step 5 — Apply on the MikroTik

Lowest-risk order:

1. Unbox the MikroTik, upgrade to RouterOS 7.x latest.
2. Plug your laptop into ether3 (any LAN-to-be port).
3. Reach the router at the factory IP or via MAC-telnet from Winbox.
4. Copy `output/mikrotik.rsc` to the router via SCP or Winbox Files.
5. Run `/import file-name=mikrotik.rsc verbose=yes` and watch for syntax errors.
6. Fix any syntax issues; re-run until clean.
7. Verify: `/ip address print`, `/ip dhcp-server print`,
   `/interface wireguard peers print`, `/ip firewall filter print`.
8. Physically swap cables: WAN → ether1, WAN2 → ether2, LAN switch(es) → any
   of ether3–10. Unplug the pfSense.
9. Verify end-to-end: DHCP leases, DNS resolution, NordVPN connectivity
   (`:put [/ping 1.1.1.1]`), WAN2 port forwards land at your internal target.

Keep the pfSense powered off but wired for 24–48 hours in case you need to
roll back.

## Step 6 — Post-migration

- Enable DDNS schedulers after a manual successful run of each:
  `/system script run ddns-...` then `/system scheduler enable [find name=ddns-...]`
- For Cloudflare DDNS entries, follow the one-time curl shown in the script
  header to obtain `zone_id` and `record_id`, then replace the `<FILL_IN_*>`
  placeholders in the script body.
- Review `chain=forward` rules one more time for anything that should be in
  `chain=input` (see [caveats](caveats.md)).
- If you want pfSense-style default-block, add an explicit final
  `/ip firewall filter add chain=forward action=drop` rule. The emitter
  intentionally omits this to avoid locking you out on first apply.

## Obtaining NordVPN WireGuard credentials

NordVPN exposes WireGuard keys via their "NordLynx" setup, but only via API —
the web UI doesn't show the private key. The common flow:

1. Generate a NordVPN access token in your account dashboard.
2. Use the token to ask the API for your WireGuard private key and a server
   recommendation. Community scripts like `nordlynx-wireguard-manual` automate
   step 2; search the provider's docs or community forums for the current
   canonical method.
3. From the result, you need:
    - your **private key** (goes into `<FILL_IN>` in the `.rsc` — paste by hand
      before `/import`, or set after with
      `/interface wireguard set wg-nordvpn private-key="…"`)
    - the server's **public key** → `vpn.nordvpn.peer_pubkey`
    - the server's **hostname** → `vpn.nordvpn.endpoint_host`
    - your **tunnel-local /32** → `vpn.nordvpn.address` (commonly `10.5.0.2/32`)

The private key deliberately stays a placeholder in the generated `.rsc` so
the output can still be shared if needed.
