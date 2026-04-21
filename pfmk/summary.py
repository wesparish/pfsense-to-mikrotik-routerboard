"""Human-readable summary of what the generated .rsc will do on the router.

Printed at the end of every `pfmk generate` run. The structure is ordered
by networking concept — what the physical ports become, how addressing
lands, what services run on LAN, how egress traffic is policy-routed,
what comes in on WAN2, VPN state, firewall rule counts, DDNS, and
action items the user still needs to handle before /import.
"""

import ipaddress

from pfmk.model import PfSenseConfig
from pfmk.overrides import Overrides


def render_summary(
    config: PfSenseConfig,
    overrides: Overrides,
    rendered: str,
) -> str:
    sections = [
        _header(),
        _physical_logical(config, overrides),
        _lan_services(config, overrides),
        _egress_policy(config, overrides),
        _inbound(config, overrides, rendered),
        _vpn(overrides),
        _firewall(rendered),
        _ddns(config, overrides),
        _action_items(config, overrides, rendered),
    ]
    return "\n".join(s for s in sections if s) + "\n"


# ──────────────────────────────────────────────────────────────────────
# Sections
# ──────────────────────────────────────────────────────────────────────

def _header() -> str:
    return "\n".join(
        [
            "",
            "╭─ mikrotik.rsc — summary " + "─" * 50,
        ]
    )


def _physical_logical(
    config: PfSenseConfig, overrides: Overrides
) -> str:
    lines = ["│", "│ Physical → logical"]

    iface_by_name = {i.name: i for i in config.interfaces}

    # Order: wan, opt1..5, lan, then any others.
    preferred = ["wan", "opt1", "opt2", "opt3", "opt4", "opt5", "lan"]
    seen: set[str] = set()
    ordered = [n for n in preferred if n in overrides.interfaces]
    ordered.extend(n for n in overrides.interfaces if n not in preferred)

    for name in ordered:
        mapping = overrides.interfaces[name]
        if mapping.skip:
            continue
        iface = iface_by_name.get(name)
        descr = iface.description if iface else name
        mode = _interface_mode_label(iface) if iface else "?"
        role = f"  ({mapping.role})" if mapping.role else ""
        target = mapping.target or "unassigned"

        if mapping.members:
            members_range = _format_range(mapping.members)
            addr = _static_cidr(iface) if iface else ""
            addr_bit = f"  {addr}" if addr else ""
            lines.append(
                f"│   {members_range:<14} → {target:<12} {descr}{role}{addr_bit}"
            )
        else:
            lines.append(
                f"│   {target:<14} → {descr:<12} {mode}{role}"
            )

        seen.add(name)

    # Skipped
    skipped = [n for n, m in overrides.interfaces.items() if m.skip]
    if skipped:
        lines.append(f"│   skipped: {', '.join(skipped)} (retired)")

    return "\n".join(lines)


def _lan_services(config: PfSenseConfig, overrides: Overrides) -> str:
    if not config.dhcp_scopes and not config.dns_hosts:
        return ""
    lines = ["│", "│ LAN services"]

    if config.dhcp_scopes:
        scope = config.dhcp_scopes[0]  # typical home case: single LAN scope
        lease_count = len(scope.static_leases)
        lines.append(
            f"│   DHCP server   {scope.range_from} – {scope.range_to}"
            f"   ({lease_count} static lease{'s' if lease_count != 1 else ''})"
        )
        if scope.dns_servers:
            lines.append(
                f"│                 dns-servers: {', '.join(scope.dns_servers)}"
            )

    if config.dns_hosts:
        drop = overrides.domains.drop
        kept = sum(1 for h in config.dns_hosts if not _dropped(h.domain, drop))
        dropped = len(config.dns_hosts) - kept
        dropped_bit = f", {dropped} dropped" if dropped else ""
        lines.append(
            f"│   DNS resolver  {kept} static host{'s' if kept != 1 else ''} kept{dropped_bit}"
        )

    return "\n".join(lines)


def _egress_policy(config: PfSenseConfig, overrides: Overrides) -> str:
    r = overrides.routing
    nv = overrides.nordvpn

    egress_iface = _role_target(overrides, "egress")
    ingress_iface = _role_target(overrides, "ingress")

    lines = ["│", "│ WAN egress policy"]

    if r.default_via == "nordvpn" and nv.enabled:
        lines.append(
            f"│   Default             → {nv.interface_name}   (NordVPN WireGuard)"
        )
    elif egress_iface:
        lines.append(f"│   Default             → {egress_iface}")

    if r.bypass.via_wan:
        ips = r.bypass.via_wan
        sample = ", ".join(ips[:3]) + (f", +{len(ips) - 3} more" if len(ips) > 3 else "")
        lines.append(
            f"│   Bypass → WAN       {len(ips):>2} host{'s' if len(ips) != 1 else ''}   ({sample})"
        )
    if r.bypass.via_wan2:
        ips = r.bypass.via_wan2
        sample = ", ".join(ips[:3]) + (f", +{len(ips) - 3} more" if len(ips) > 3 else "")
        lines.append(
            f"│   Bypass → WAN2      {len(ips):>2} host{'s' if len(ips) != 1 else ''}   ({sample})"
        )

    if ingress_iface:
        lines.append(
            f"│   WAN2 return path:  asymmetric-routing fix enabled"
        )

    return "\n".join(lines)


def _inbound(
    config: PfSenseConfig, overrides: Overrides, rendered: str
) -> str:
    if not config.nat_port_forwards:
        return ""
    total = len(config.nat_port_forwards)
    # Group by in-interface (resolved via mapping)
    by_iface: dict[str, int] = {}
    for pf in config.nat_port_forwards:
        mapping = overrides.interfaces.get(pf.interface)
        if mapping is None or mapping.skip or not mapping.target:
            by_iface.setdefault("(skipped)", 0)
            by_iface["(skipped)"] += 1
        else:
            by_iface.setdefault(mapping.target, 0)
            by_iface[mapping.target] += 1

    dst_nat_count = rendered.count("chain=dstnat ")

    lines = ["│", "│ Inbound (port forwards / dst-nat)"]
    for iface, count in sorted(by_iface.items()):
        if iface == "(skipped)":
            lines.append(
                f"│   {iface:<14}  {count} rule{'s' if count != 1 else ''} skipped"
            )
        else:
            lines.append(
                f"│   on {iface:<11}  {count} service{'s' if count != 1 else ''} exposed"
            )
    lines.append(
        f"│   total dst-nat rules emitted: {dst_nat_count} (tcp/udp expanded where applicable)"
    )
    return "\n".join(lines)


def _vpn(overrides: Overrides) -> str:
    nv = overrides.nordvpn
    if not nv.enabled:
        return ""
    lines = ["│", "│ VPN (WireGuard)"]
    endpoint = nv.endpoint_host or "<FILL_IN>"
    address = nv.address or "<FILL_IN>"
    lines.append(
        f"│   {nv.interface_name}   endpoint={endpoint}:{nv.endpoint_port}"
        f"  tunnel={address}"
    )
    return "\n".join(lines)


def _firewall(rendered: str) -> str:
    input_rules = rendered.count("\n/ip firewall filter add chain=input ")
    forward_rules = rendered.count("\n/ip firewall filter add chain=forward ")
    skipped = rendered.count("# SKIPPED (") + rendered.count("# SKIPPED\n")
    masquerade = rendered.count("action=masquerade")
    dup_leases = rendered.count("!! duplicate IP")

    lines = ["│", "│ Firewall"]
    lines.append(f"│   chain=input     {input_rules} rule{'s' if input_rules != 1 else ''}")
    lines.append(f"│   chain=forward   {forward_rules} rule{'s' if forward_rules != 1 else ''}")
    if skipped:
        lines.append(
            f"│   skipped         {skipped} rule{'s' if skipped != 1 else ''} (see # SKIPPED in output)"
        )
    lines.append(
        f"│   NAT srcnat      {masquerade} masquerade rule{'s' if masquerade != 1 else ''}"
    )
    if dup_leases:
        lines.append(
            f"│   warning:        {dup_leases} duplicate-IP DHCP lease{'s' if dup_leases != 1 else ''} flagged"
        )
    return "\n".join(lines)


def _ddns(config: PfSenseConfig, overrides: Overrides) -> str:
    active = [
        e
        for e in config.dyndns
        if e.enabled and not _dropped(e.domain, overrides.domains.drop)
    ]
    if not active:
        return ""
    by_provider: dict[str, list[str]] = {}
    for e in active:
        fqdn = e.domain if e.hostname == "@" else f"{e.hostname}.{e.domain}"
        by_provider.setdefault(e.provider, []).append(fqdn)

    lines = ["│", "│ Dynamic DNS"]
    for provider, fqdns in sorted(by_provider.items()):
        lines.append(
            f"│   {provider:<11}  {len(fqdns)} host{'s' if len(fqdns) != 1 else ''}   ({', '.join(fqdns)})"
        )
    lines.append(
        f"│   {len(active)} scheduler{'s' if len(active) != 1 else ''} emitted, all disabled pending manual verification"
    )
    return "\n".join(lines)


def _action_items(
    config: PfSenseConfig, overrides: Overrides, rendered: str
) -> str:
    items: list[str] = []

    # WireGuard placeholders
    if overrides.nordvpn.enabled:
        if not overrides.nordvpn.address:
            items.append("Set vpn.nordvpn.address in overrides (tunnel-local /32)")
        if not overrides.nordvpn.peer_pubkey:
            items.append("Set vpn.nordvpn.peer_pubkey in overrides")
        if not overrides.nordvpn.endpoint_host:
            items.append("Set vpn.nordvpn.endpoint_host in overrides")
        # Private key is always a placeholder by design
        items.append(
            'Paste WireGuard private key into /interface wireguard add line (replace <FILL_IN>)'
        )

    # Cloudflare zone/record IDs
    cf_count = sum(
        1
        for e in config.dyndns
        if e.enabled
        and e.provider == "cloudflare"
        and not _dropped(e.domain, overrides.domains.drop)
    )
    if cf_count:
        items.append(
            f"Fetch + fill Cloudflare zone_id/record_id for {cf_count} entry/entries "
            f"(see one-time curl in each script's header)"
        )

    # Duplicate-IP DHCP leases
    dup = rendered.count("!! duplicate IP")
    if dup:
        items.append(
            f"Resolve {dup} duplicate-IP DHCP lease{'s' if dup != 1 else ''} "
            f"(grep 'duplicate IP' in output)"
        )

    # Chain review
    items.append(
        "Skim chain=forward rules for any that should be chain=input (router-targeted)"
    )

    if not items:
        return ""
    lines = ["│", "│ Action items before /import"]
    for i, item in enumerate(items, 1):
        lines.append(f"│   [{i}] {item}")
    lines.append("╰" + "─" * 74)
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _interface_mode_label(iface) -> str:
    if iface.mode == "dhcp":
        return "DHCP"
    if iface.mode == "static" and iface.ipaddr and iface.subnet:
        return f"{iface.ipaddr}/{iface.subnet}"
    return iface.mode


def _static_cidr(iface) -> str:
    if iface.mode == "static" and iface.ipaddr and iface.subnet:
        try:
            return str(
                ipaddress.ip_network(
                    f"{iface.ipaddr}/{iface.subnet}", strict=False
                )
            )
        except ValueError:
            return ""
    return ""


def _role_target(overrides: Overrides, role: str) -> str | None:
    for mapping in overrides.interfaces.values():
        if mapping.role == role and not mapping.skip and mapping.target:
            return mapping.target
    return None


def _format_range(members: list[str]) -> str:
    """Compact run like ['ether3', ..., 'ether10'] → 'ether3-10'."""

    if not members:
        return ""
    if len(members) == 1:
        return members[0]

    import re

    nums = []
    prefix = None
    for m in members:
        match = re.match(r"(.+?)(\d+)$", m)
        if not match:
            return ", ".join(members)
        p, n = match.group(1), int(match.group(2))
        if prefix is None:
            prefix = p
        elif prefix != p:
            return ", ".join(members)
        nums.append(n)

    if nums == list(range(nums[0], nums[-1] + 1)):
        return f"{prefix}{nums[0]}-{nums[-1]}"
    return ", ".join(members)


def _dropped(domain: str, drop_list: list[str]) -> bool:
    if not domain:
        return False
    for d in drop_list:
        if domain == d or domain.endswith("." + d):
            return True
    return False
