from pfmk.model import Interface
from pfmk.overrides import InterfaceMapping


def emit(
    interfaces: list[Interface],
    mappings: dict[str, InterfaceMapping],
) -> str:
    ether_comments: list[str] = []
    bridge_lines: list[str] = []
    ip_address_lines: list[str] = []
    dhcp_client_lines: list[str] = []

    for iface in interfaces:
        if not iface.enabled:
            continue
        mapping = mappings.get(iface.name)
        if mapping is None or mapping.skip or not mapping.target:
            continue

        target = mapping.target
        descr = iface.description or iface.name.upper()

        if mapping.members:
            bridge_lines.append(
                f'/interface bridge add name={target} comment="{_escape(descr)}"'
            )
            for member in mapping.members:
                bridge_lines.append(
                    f"/interface bridge port add bridge={target} interface={member}"
                )
            if iface.mode == "static" and iface.ipaddr and iface.subnet:
                ip_address_lines.append(
                    f"/ip address add address={iface.ipaddr}/{iface.subnet} "
                    f'interface={target} comment="{_escape(descr)}"'
                )
        else:
            ether_comments.append(
                f'/interface ethernet set [find name={target}] comment="{_escape(descr)}"'
            )
            if iface.mode == "dhcp":
                dhcp_client_lines.append(
                    f"/ip dhcp-client add interface={target} disabled=no "
                    f'comment="{_escape(descr)}"'
                )
            elif iface.mode == "static" and iface.ipaddr and iface.subnet:
                ip_address_lines.append(
                    f"/ip address add address={iface.ipaddr}/{iface.subnet} "
                    f'interface={target} comment="{_escape(descr)}"'
                )

    parts: list[str] = ["# ==== Interfaces ===="]
    for group in (ether_comments, bridge_lines, ip_address_lines, dhcp_client_lines):
        if group:
            parts.append("\n".join(group))
    return "\n".join(parts)


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
