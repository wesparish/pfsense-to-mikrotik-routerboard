# Caveats

Things that don't translate cleanly, and what to do about them.

## OpenVPN static-key (`p2p_shared_key`) site-to-site

MikroTik's OpenVPN implementation requires PKI — cert-signed client and
server. It does not support the static-key / `p2p_shared_key` mode that
pfSense offers as a simple site-to-site option.

The emitter does **not** translate these. They appear in the pfSense backup,
we ignore them.

Options:

- Re-issue the tunnel as cert-based OpenVPN on both endpoints
- Replace with WireGuard (recommended — simpler, faster, widely supported)
- Keep the tunnel on a separate Linux box

## IPsec

Not yet implemented. The RouterOS equivalent is `/ip ipsec peer` +
`/ip ipsec identity` + `/ip ipsec mode-config` (mobile client auth) or
`/ip ipsec policy` (site-to-site). Both are doable — they just aren't
in this tool yet. PR or hand-write.

## Snort / Suricata / pfBlockerNG

No RouterOS equivalent exists. These are substantial IDS/IPS + threat-feed
packages that run outside the data plane.

Replacements:

- IDS/IPS: dedicated Suricata/Snort on an x86 mini PC, or a commercial
  appliance (Zenarmor, etc.) inline between your WAN and MikroTik.
- DNS-level blocking (the common pfBlockerNG use case): Pi-hole or AdGuard
  Home on a Raspberry Pi, set as the DNS server in your DHCP scope. Covers
  ad/tracker blocklists without needing anything in the router.

## Squid / SquidGuard / ClamAV

HTTP caching proxy, category-based web filter, AV scanning. RouterOS has a
deprecated `/ip web-proxy` but it's nowhere near Squid's feature set.

If you really need these, run Squid + the rest on a separate Linux box
and policy-route clients through it (via mangle + WPAD or explicit
proxy).

## IPv6

Not yet implemented. IPv6 rules (`<ipprotocol>inet6</ipprotocol>`) pass
through as `# SKIPPED (IPv6 rule not translated)`. IPv6 addressing in
`<interfaces>` is also skipped. Adding support means:

- Parser extension for IPv6 address/prefix
- Emitter extension: `/ipv6 address add`, `/ipv6 firewall filter/nat`,
  DHCPv6 / track-interface as appropriate
- Tests

Contributions welcome.

## chain=input vs chain=forward

pfSense anchors rules to an interface without distinguishing traffic *to*
the router from traffic *through* the router. RouterOS splits them into
`chain=input` (to the router) and `chain=forward` (through).

The emitter:

1. Prepends a `chain=input` baseline block — accept established/related,
    drop invalid, accept ICMP, accept from LAN, drop the rest. The router
    stays reachable from LAN, unreachable from WAN by default.
2. Auto-detects router-targeted rules by destination network — `wanip`,
    `lanip`, `opt1ip`, etc., and `(self)` — and emits those in
    `chain=input`. The translation is flagged with a comment so it's
    visible during review.
3. Emits everything else in `chain=forward`.

This covers most real cases but you should still skim the forward-chain
translations for anything that was about reaching the pfSense UI/SSH from
a specific source. Those may need to move to `chain=input` manually.

## NAT outbound

pfSense's "hybrid" mode stacks many auto-generated + manual srcnat rules.
The emitter does **not** try to reproduce each one. Instead it writes
two baseline masquerade rules:

- `LAN → WAN (ether1)` (unconditional)
- `LAN → WireGuard tunnel (wg-nordvpn)` (if NordVPN enabled)

…and preserves the original outbound rules as reference comments. If your
pfSense had specific srcnat behavior (source-port rewriting, 1:1 NAT,
per-source outbound to WAN2), review those reference comments and
hand-write the RouterOS equivalents.

## DHCP static-lease duplicate IPs

pfSense will save two static maps pointing at the same IP for different
MACs. RouterOS rejects this at import. The emitter includes both and tags
the second with `!! duplicate IP, also held by X` in the comment. Resolve
by removing the stale entry before `/import`.

## DDNS: Cloudflare zone/record IDs

pfSense's Cloudflare DDNS type uses email + global API key, no zone or
record IDs. The Cloudflare v4 API endpoint requires both IDs in the URL
path. The emitter inlines the email + API key from the backup, but leaves
`<FILL_IN_CLOUDFLARE_ZONE_ID>` and `<FILL_IN_CLOUDFLARE_RECORD_ID>` as
placeholders. The emitted script header contains a one-time curl you can
run to fetch both, then paste them into the script before enabling its
scheduler.

## WireGuard private key in `.rsc`

The NordVPN WireGuard private key is deliberately left as `<FILL_IN>` in
the emitted `/interface wireguard add` line rather than inlined. This
keeps the `.rsc` shareable (albeit lightly — other pfSense-derived info
still leaks) and forces a conscious paste step. Alternative: remove the
`<FILL_IN>` from the `.rsc` before `/import` and run
`/interface wireguard set wg-nordvpn private-key="…"` manually after.

## `<iface>ip` / `<iface>` source-network references

pfSense rules can say `<source><network>wanip</network></source>` which
means "the WAN interface's own IP" — a value only knowable at the time
the router actually has an address. Since WAN is DHCP in the typical
setup, the emitter can't resolve this at generation time. For source
networks, the emitter emits no `src-address` and adds a
`# NOTE: src network 'X' has no static CIDR — left unset` comment. Review
and tighten manually if the rule was restricting traffic.

For destination-network `<iface>ip` the emitter takes it as "targeting
the router" (see chain=input rules above) and does not emit
`dst-address`. RouterOS's `in-interface` match catches these packets
correctly because the router's own IP on that interface is always hit
when traffic arrives on that interface.
