"""Policy routing + mangle.

Three concerns, all override-driven (no pfSense field maps 1:1):

1. LAN traffic defaults through the WireGuard (NordVPN) tunnel.
2. LAN IPs in `routing.bypass.via_wan` go out WAN instead of the tunnel.
3. LAN IPs in `routing.bypass.via_wan2` go out WAN2 instead of the tunnel.
4. WAN2 ingress return-path: connections arriving on WAN2 (port forwards to
   internal targets like a K8s nginx-ingress) must return via WAN2, not the
   default WAN or the tunnel — connection-mark + routing-mark trick.

Evaluation order (passthrough=no on each so first match wins):
  a. mark more-specific bypass rules first (via_wan, via_wan2)
  b. mark WAN2-ingress return connections
  c. mark remaining LAN traffic as via-nordvpn
"""

import ipaddress

from pfmk.emitters._common import escape
from pfmk.model import Interface
from pfmk.overrides import (
    BypassLists,
    InterfaceMapping,
    RoutingOverrides,
    WireGuardNordVPN,
)


def emit(
    routing: RoutingOverrides,
    nordvpn: WireGuardNordVPN,
    interfaces: list[Interface],
    mappings: dict[str, InterfaceMapping],
) -> str:
    egress = _find_by_role(mappings, "egress")
    ingress = _find_by_role(mappings, "ingress")
    lan_mapping = mappings.get("lan")
    lan_iface = lan_mapping.target if lan_mapping and lan_mapping.target else None
    lan_cidr = _lan_cidr(interfaces)

    use_nordvpn = routing.default_via == "nordvpn" and nordvpn.enabled
    has_via_wan_bypass = bool(routing.bypass.via_wan) and egress
    has_via_wan2_bypass = bool(routing.bypass.via_wan2) and ingress
    want_wan2_return = ingress is not None

    if not (use_nordvpn or want_wan2_return or has_via_wan_bypass or has_via_wan2_bypass):
        return ""

    lines: list[str] = ["# ==== Routing & mangle ===="]

    # --- Address lists (one per bypass target) ---
    if has_via_wan_bypass:
        lines.append("")
        lines.append("# --- Bypass list: via WAN (skip NordVPN, egress ether1) ---")
        for ip in routing.bypass.via_wan:
            lines.append(
                f"/ip firewall address-list add list=bypass-to-wan "
                f'address={ip} comment="bypass → WAN"'
            )
    if has_via_wan2_bypass:
        lines.append("")
        lines.append("# --- Bypass list: via WAN2 (skip NordVPN, egress ether2) ---")
        for ip in routing.bypass.via_wan2:
            lines.append(
                f"/ip firewall address-list add list=bypass-to-wan2 "
                f'address={ip} comment="bypass → WAN2"'
            )

    # --- Custom routing tables ---
    lines.append("")
    lines.append("# --- Custom routing tables ---")
    if use_nordvpn:
        lines.append("/routing table add name=via-nordvpn fib disabled=no")
    if has_via_wan_bypass and egress:
        lines.append("/routing table add name=via-wan fib disabled=no")
    if want_wan2_return or has_via_wan2_bypass:
        lines.append("/routing table add name=via-wan2 fib disabled=no")

    # --- Routes in custom tables ---
    lines.append("")
    lines.append("# --- Default routes in custom tables ---")
    if use_nordvpn:
        lines.append(
            f"/ip route add dst-address=0.0.0.0/0 "
            f"gateway={nordvpn.interface_name} routing-table=via-nordvpn"
        )
    if has_via_wan_bypass and egress:
        lines.append(
            f"/ip dhcp-client set [find interface={egress}] "
            f"default-route-tables=main,via-wan"
        )
    if (want_wan2_return or has_via_wan2_bypass) and ingress:
        lines.append(
            f"/ip dhcp-client set [find interface={ingress}] "
            f"default-route-tables=main,via-wan2"
        )

    if not lan_iface:
        return "\n".join(lines)

    # --- Mangle (order matters; passthrough=no terminates) ---
    lines.append("")
    lines.append("# --- Mangle: policy-route LAN traffic ---")
    lines.append("# Order: specific bypass lists → NordVPN catch-all.")

    if has_via_wan_bypass:
        lines.append(
            f"/ip firewall mangle add chain=prerouting action=mark-routing "
            f"new-routing-mark=via-wan in-interface={lan_iface} "
            f"src-address-list=bypass-to-wan connection-state=new passthrough=no "
            f'comment="bypass via WAN"'
        )
    if has_via_wan2_bypass:
        lines.append(
            f"/ip firewall mangle add chain=prerouting action=mark-routing "
            f"new-routing-mark=via-wan2 in-interface={lan_iface} "
            f"src-address-list=bypass-to-wan2 connection-state=new passthrough=no "
            f'comment="bypass via WAN2"'
        )

    if use_nordvpn:
        parts = [
            "chain=prerouting",
            "action=mark-routing",
            "new-routing-mark=via-nordvpn",
            f"in-interface={lan_iface}",
            "dst-address-type=!local",
            "connection-state=new",
            "passthrough=no",
        ]
        if lan_cidr:
            parts.append(f"dst-address=!{lan_cidr}")
        parts.append('comment="LAN default via NordVPN"')
        lines.append("/ip firewall mangle add " + " ".join(parts))

    # --- WAN2 ingress return path (asymmetric-routing fix) ---
    if want_wan2_return:
        lines.append("")
        lines.append(
            "# --- WAN2 ingress return path (asymmetric-routing fix) ---"
        )
        lines.append(
            f"/ip firewall mangle add chain=prerouting action=mark-connection "
            f"new-connection-mark=wan2-in passthrough=yes in-interface={ingress} "
            f"connection-state=new "
            f'comment="mark new connections arriving on WAN2"'
        )
        lines.append(
            "/ip firewall mangle add chain=output action=mark-routing "
            "new-routing-mark=via-wan2 connection-mark=wan2-in passthrough=no "
            'comment="route router-originated return via WAN2"'
        )
        lines.append(
            f"/ip firewall mangle add chain=prerouting action=mark-routing "
            f"new-routing-mark=via-wan2 connection-mark=wan2-in "
            f"in-interface={lan_iface} passthrough=no "
            f'comment="route LAN-originated return via WAN2"'
        )

    return "\n".join(lines)


def _find_by_role(
    mappings: dict[str, InterfaceMapping], role: str
) -> str | None:
    for mapping in mappings.values():
        if mapping.role == role and not mapping.skip and mapping.target:
            return mapping.target
    return None


def _lan_cidr(interfaces: list[Interface]) -> str | None:
    for iface in interfaces:
        if iface.name == "lan" and iface.ipaddr and iface.subnet:
            return str(
                ipaddress.ip_network(
                    f"{iface.ipaddr}/{iface.subnet}", strict=False
                )
            )
    return None
