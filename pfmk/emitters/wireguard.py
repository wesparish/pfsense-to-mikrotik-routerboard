from pfmk.overrides import WireGuardNordVPN

_PLACEHOLDER = "<FILL_IN>"


def emit(cfg: WireGuardNordVPN) -> str:
    if not cfg.enabled:
        return ""

    lines: list[str] = [
        "# ==== WireGuard (NordVPN / NordLynx) ====",
        "# Values below with <FILL_IN> must be replaced before /import.",
        "# Obtain NordVPN WireGuard credentials with NordVPN's access-token flow:",
        "#   https://support.nordvpn.com/General-info/Tutorials/1905092252/",
        f"/interface wireguard add name={cfg.interface_name} "
        f'listen-port={cfg.listen_port} private-key="{_PLACEHOLDER}"',
    ]

    if cfg.address:
        lines.append(
            f"/ip address add interface={cfg.interface_name} address={cfg.address}"
        )
    else:
        lines.append(
            f"# TODO: /ip address add interface={cfg.interface_name} "
            f"address={_PLACEHOLDER}  (tunnel-local /32 from NordVPN)"
        )

    peer_pubkey = cfg.peer_pubkey or _PLACEHOLDER
    endpoint_host = cfg.endpoint_host or _PLACEHOLDER
    lines.append(
        f"/interface wireguard peers add interface={cfg.interface_name} "
        f'public-key="{peer_pubkey}" endpoint-address={endpoint_host} '
        f"endpoint-port={cfg.endpoint_port} allowed-address={cfg.allowed_address} "
        f"persistent-keepalive={cfg.persistent_keepalive}"
    )

    return "\n".join(lines)
