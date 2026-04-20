"""Translate pfSense <filter> rules into RouterOS /ip firewall filter commands.

Semantic caveat — pfSense and RouterOS frame firewalling differently:

- pfSense: rules are anchored to an interface (wan/lan/opt1) and evaluated on
  traffic arriving on that interface, regardless of whether it's destined for
  the router itself or for forwarding.
- RouterOS: rules live in named chains — `input` (to the router), `forward`
  (through the router), `output` (from the router).

This translator emits each pfSense rule as `chain=forward`, which covers
through-traffic (the majority of rules). A baseline `chain=input` block is
emitted once at the top with the standard RouterOS defaults (accept
established/related, drop invalid, accept LAN→router, accept ICMP, drop rest)
so the router itself stays reachable from LAN.

Users should review the translated rules against their original pfSense intent,
especially for rules that were about reaching the pfSense web UI or SSH — those
now belong in `chain=input`, not `chain=forward`.
"""

from pfmk.model import Endpoint, FilterRule, Interface
from pfmk.overrides import InterfaceMapping

# pfSense network references that mean "the router itself" — these belong in
# chain=input, not chain=forward. `(self)` is explicit; `<iface>ip` means the
# router's own IP on that interface.
_SELF_NETWORKS = {"(self)"}


def _is_self_network(net: str | None) -> bool:
    if not net:
        return False
    if net in _SELF_NETWORKS:
        return True
    # "wanip", "lanip", "opt1ip", etc.
    return net.endswith("ip") and net[:-2] in {
        "wan",
        "lan",
        "opt1",
        "opt2",
        "opt3",
        "opt4",
        "opt5",
    }


def emit(
    rules: list[FilterRule],
    interfaces: list[Interface],
    interface_mappings: dict[str, InterfaceMapping],
) -> str:
    lines: list[str] = [
        "# ==== Firewall filter ====",
        "# The baseline chain=input block below keeps the router itself",
        "# reachable from LAN. The forward-chain rules that follow are",
        "# translated from pfSense — review carefully, especially rules that",
        "# targeted the pfSense UI/SSH (those belong in chain=input).",
        "",
    ]

    lan_iface = _lan_target(interface_mappings)
    lines.extend(_input_chain_baseline(lan_iface))
    lines.append("")

    iface_nets = _interface_network_map(interfaces)

    for rule in rules:
        lines.extend(_translate_rule(rule, interface_mappings, iface_nets))

    return "\n".join(lines).rstrip()


def _lan_target(mappings: dict[str, InterfaceMapping]) -> str | None:
    lan = mappings.get("lan")
    return lan.target if lan and not lan.skip else None


def _input_chain_baseline(lan_iface: str | None) -> list[str]:
    lines = [
        "# --- chain=input baseline (router self-protection) ---",
        "/ip firewall filter add chain=input action=accept "
        'connection-state=established,related comment="accept established/related"',
        "/ip firewall filter add chain=input action=drop "
        'connection-state=invalid comment="drop invalid"',
        "/ip firewall filter add chain=input action=accept protocol=icmp "
        'comment="accept ICMP"',
    ]
    if lan_iface:
        lines.append(
            f"/ip firewall filter add chain=input action=accept "
            f'in-interface={lan_iface} comment="accept from LAN"'
        )
    lines.append(
        "/ip firewall filter add chain=input action=drop "
        'comment="drop everything else to router"'
    )
    return lines


def _interface_network_map(interfaces: list[Interface]) -> dict[str, str]:
    """Map pfSense interface names (and `<name>ip`) to something usable.

    Returns CIDR for the interface's static network (e.g. lan → 172.16.1.0/24),
    and single-IP for `<name>ip` references (e.g. lanip → 172.16.1.1).
    Interfaces without a static IP (DHCP WANs) are skipped — callers will
    emit a warning comment when referenced.
    """

    import ipaddress

    result: dict[str, str] = {}
    for iface in interfaces:
        if iface.ipaddr and iface.subnet:
            net = ipaddress.ip_network(
                f"{iface.ipaddr}/{iface.subnet}", strict=False
            )
            result[iface.name] = str(net)
            result[f"{iface.name}ip"] = iface.ipaddr
    return result


def _translate_rule(
    rule: FilterRule,
    mappings: dict[str, InterfaceMapping],
    iface_nets: dict[str, str],
) -> list[str]:
    header = _rule_header_comment(rule)

    if rule.ipprotocol == "inet6":
        return [f"{header}", f"# SKIPPED (IPv6 rule not translated): {rule.description}"]

    iface_names = [i.strip() for i in rule.interface.split(",") if i.strip()]
    mapped_ifaces: list[str] = []
    for iface_name in iface_names:
        mapping = mappings.get(iface_name)
        if mapping is None:
            return [f"{header}", f"# SKIPPED (no mapping for pfSense interface '{iface_name}')"]
        if mapping.skip or not mapping.target:
            return [f"{header}", f"# SKIPPED (pfSense interface '{iface_name}' is retired)"]
        mapped_ifaces.append(mapping.target)

    action = _translate_action(rule.action)
    if action is None:
        return [f"{header}", f"# SKIPPED (unsupported action '{rule.action}')"]

    # Rules targeting the router itself (dst=<iface>ip or dst=(self)) go in
    # chain=input, not chain=forward.
    target_self = _is_self_network(rule.destination.network)
    chain = "input" if target_self else "forward"

    protocols = _expand_protocol(rule.protocol)
    src_parts, src_warnings = _endpoint_to_params(rule.source, "src", iface_nets)
    dst_parts, dst_warnings = _endpoint_to_params(
        rule.destination, "dst", iface_nets
    )

    # For input-chain rules, suppress the "dst network has no static CIDR"
    # warning — it's expected that <iface>ip doesn't resolve; RouterOS knows
    # the router's own address list implicitly via in-interface.
    if target_self:
        dst_warnings = [
            w for w in dst_warnings if "has no static CIDR" not in w
        ]

    warnings = src_warnings + dst_warnings
    out: list[str] = [header]
    if target_self:
        out.append(
            "# Translated to chain=input (rule targets the router itself)."
        )
    for warning in warnings:
        out.append(f"# NOTE: {warning}")

    for iface in mapped_ifaces:
        for proto in protocols:
            parts = [
                f"chain={chain}",
                f"action={action}",
                f"in-interface={iface}",
            ]
            if proto:
                parts.append(f"protocol={proto}")
            parts.extend(src_parts)
            parts.extend(dst_parts)
            if rule.disabled:
                parts.append("disabled=yes")
            comment = rule.description or f"tracker={rule.tracker}"
            parts.append(f'comment="{_escape(comment)}"')
            out.append("/ip firewall filter add " + " ".join(parts))

    return out


def _rule_header_comment(rule: FilterRule) -> str:
    bits = [f"type={rule.action}", f"iface={rule.interface}"]
    if rule.protocol:
        bits.append(f"proto={rule.protocol}")
    if rule.description:
        bits.append(f"descr={rule.description!r}")
    return "# pfSense rule: " + " ".join(bits)


def _translate_action(action: str) -> str | None:
    return {
        "pass": "accept",
        "block": "drop",
        "reject": "reject",
        # "match" is a no-op in pfSense (used for tags/policy) — drop it.
    }.get(action)


def _expand_protocol(protocol: str | None) -> list[str | None]:
    """`tcp/udp` becomes two RouterOS rules; everything else is a single rule."""

    if protocol is None:
        return [None]
    if protocol == "tcp/udp":
        return ["tcp", "udp"]
    return [protocol]


def _endpoint_to_params(
    ep: Endpoint,
    role: str,                           # "src" or "dst"
    iface_nets: dict[str, str],
) -> tuple[list[str], list[str]]:
    parts: list[str] = []
    warnings: list[str] = []

    if ep.any or (not ep.address and not ep.network):
        pass  # no filter on address
    elif ep.address:
        addr = ep.address
        if ep.invert:
            addr = f"!{addr}"
        parts.append(f"{role}-address={addr}")
    elif ep.network:
        resolved = iface_nets.get(ep.network)
        if resolved is None:
            warnings.append(
                f"{role} network '{ep.network}' has no static CIDR — left unset"
            )
        else:
            addr = resolved
            if ep.invert:
                addr = f"!{addr}"
            parts.append(f"{role}-address={addr}")

    if ep.port:
        parts.append(f"{role}-port={ep.port.replace(':', '-')}")

    return parts, warnings


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
