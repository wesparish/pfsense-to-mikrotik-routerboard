from pfmk.model import DnsHost, DomainOverride
from pfmk.overrides import DomainsOverrides


def emit(
    hosts: list[DnsHost],
    domain_overrides: list[DomainOverride],
    domains: DomainsOverrides,
) -> str:
    lines: list[str] = [
        "# ==== DNS ====",
        # LAN clients use the MikroTik as resolver (see DHCP network dns-server).
        "/ip dns set allow-remote-requests=yes",
    ]

    for host in hosts:
        if _dropped(host.domain, domains.drop):
            continue
        fqdn = f"{host.host}.{host.domain}" if host.domain else host.host
        if not fqdn or not host.ipaddr:
            continue
        comment = host.description or f"from {host.source}"
        if host.description:
            comment = f"{host.description} ({host.source})"
        lines.append(
            f"/ip dns static add name={fqdn} address={host.ipaddr} "
            f'comment="{_escape(comment)}"'
        )

    for do in domain_overrides:
        if _dropped(do.domain, domains.drop):
            continue
        lines.append(
            f"/ip dns static add type=FWD match-subdomain=yes "
            f"name={do.domain} forward-to={do.forward_to} "
            f'comment="conditional forward ({do.source})"'
        )

    return "\n".join(lines)


def _dropped(domain: str, drop_list: list[str]) -> bool:
    if not domain:
        return False
    for d in drop_list:
        if domain == d or domain.endswith("." + d):
            return True
    return False


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
