from pfmk.model import DhcpScope
from pfmk.overrides import InterfaceMapping


def emit(
    scopes: list[DhcpScope],
    interface_mappings: dict[str, InterfaceMapping],
) -> str:
    if not scopes:
        return ""

    lines: list[str] = ["# ==== DHCP server ===="]

    for scope in scopes:
        mapping = interface_mappings.get(scope.interface)
        if mapping is None or mapping.skip or not mapping.target:
            continue

        target_iface = mapping.target
        pool_name = f"{scope.interface}-pool"
        server_name = f"{scope.interface}-dhcp"

        lines.append(
            f"/ip pool add name={pool_name} "
            f"ranges={scope.range_from}-{scope.range_to}"
        )
        lines.append(
            f"/ip dhcp-server add name={server_name} interface={target_iface} "
            f"address-pool={pool_name} lease-time=1d disabled=no"
        )

        if scope.network:
            network_args = [f"address={scope.network}"]
            if scope.gateway:
                network_args.append(f"gateway={scope.gateway}")
            if scope.dns_servers:
                network_args.append(f"dns-server={','.join(scope.dns_servers)}")
            if scope.domain:
                network_args.append(f'domain="{_escape(scope.domain)}"')
            lines.append("/ip dhcp-server network add " + " ".join(network_args))

        seen_ips: dict[str, str] = {}
        for lease in scope.static_leases:
            label = lease.description or lease.hostname or ""
            dup_suffix = ""
            if lease.ipaddr in seen_ips:
                dup_suffix = f" !! duplicate IP, also held by {seen_ips[lease.ipaddr]}"
            seen_ips[lease.ipaddr] = lease.hostname or lease.mac
            lines.append(
                f"/ip dhcp-server lease add mac-address={lease.mac} "
                f"address={lease.ipaddr} server={server_name} "
                f'comment="{_escape(label + dup_suffix)}"'
            )

    return "\n".join(lines) if len(lines) > 1 else ""


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
