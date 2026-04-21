"""DDNS updater scripts for GoDaddy + Cloudflare.

RouterOS has no built-in multi-provider DDNS, so we emit one /system script
and one /system scheduler per pfSense dyndns entry. If the pfSense backup
has credentials (parsed by pfmk.parser), we inline them — the output .rsc
is gitignored so it's fine to contain secrets. Missing/dropped credentials
become <FILL_IN> placeholders.

Cloudflare uses the legacy X-Auth-Email + X-Auth-Key header pair (what
pfSense's "cloudflare" DDNS type stored). That works with either an old
global API key or a scoped API token. The Cloudflare v4 API still needs
zone_id + record_id in the PUT path — those are NOT in pfSense, so each
Cloudflare entry emits a stub with a one-time curl to fetch them.
"""

import logging

from pfmk.emitters._common import escape
from pfmk.model import DynDnsEntry
from pfmk.overrides import DomainsOverrides, InterfaceMapping

logger = logging.getLogger(__name__)

_SCHEDULE_INTERVAL = "5m"


def emit(
    entries: list[DynDnsEntry],
    mappings: dict[str, InterfaceMapping],
    domains: DomainsOverrides,
) -> str:
    active = [
        e
        for e in entries
        if e.enabled and not _dropped(e.domain, domains.drop)
    ]
    filtered = len(entries) - len(active)
    logger.info(
        "ddns: %d active, %d filtered (disabled or dropped domain)",
        len(active),
        filtered,
    )
    if not active:
        return ""

    lines: list[str] = [
        "# ==== Dynamic DNS ====",
        "# One script + scheduler per entry. Schedulers are disabled by",
        "# default — enable after verifying a manual run.",
    ]

    for entry in active:
        lines.append("")
        mapping = mappings.get(entry.interface)
        if mapping is None or mapping.skip or not mapping.target:
            lines.append(
                f"# SKIPPED {entry.provider} {entry.hostname}.{entry.domain} "
                f"(pfSense iface '{entry.interface}' retired/unmapped)"
            )
            continue

        if entry.provider == "godaddy":
            lines.extend(_godaddy(entry, mapping.target))
        elif entry.provider == "cloudflare":
            lines.extend(_cloudflare(entry, mapping.target))
        else:
            lines.append(
                f"# SKIPPED {entry.provider} {entry.hostname}.{entry.domain} "
                f"(provider '{entry.provider}' not supported by generator)"
            )

    return "\n".join(lines)


def _dropped(domain: str, drop_list: list[str]) -> bool:
    if not domain:
        return False
    for d in drop_list:
        if domain == d or domain.endswith("." + d):
            return True
    return False


def _script_name(provider: str, entry: DynDnsEntry) -> str:
    host_part = entry.hostname if entry.hostname != "@" else "apex"
    domain_part = entry.domain.replace(".", "-")
    return f"ddns-{provider}-{host_part}-{domain_part}"


def _quote(value: str) -> str:
    """Safe for enclosing in double quotes in a RouterOS script."""

    return value.replace("\\", "\\\\").replace('"', '\\"')


def _godaddy(entry: DynDnsEntry, iface: str) -> list[str]:
    name = _script_name("godaddy", entry)
    host = entry.hostname or "@"
    api_key = entry.username or "<FILL_IN_GODADDY_KEY>"
    api_secret = entry.password or "<FILL_IN_GODADDY_SECRET>"

    script = (
        "{\n"
        f'  :local domain "{_quote(entry.domain)}"\n'
        f'  :local host "{_quote(host)}"\n'
        f'  :local iface "{iface}"\n'
        f'  :local apiKey "{_quote(api_key)}"\n'
        f'  :local apiSecret "{_quote(api_secret)}"\n'
        '  :local addr [/ip address get [find interface=$iface] address]\n'
        '  :if ([:len $addr] = 0) do={ :log warning "ddns-godaddy: no addr on $iface"; :return }\n'
        '  :local ip [:pick $addr 0 [:find $addr "/"]]\n'
        '  :local data "[{\\\"data\\\":\\\"$ip\\\",\\\"ttl\\\":600}]"\n'
        '  /tool fetch mode=https http-method=put \\\n'
        '    url=("https://api.godaddy.com/v1/domains/$domain/records/A/$host") \\\n'
        '    http-header-field=("Authorization: sso-key $apiKey:$apiSecret,Content-Type: application/json") \\\n'
        '    http-data=$data output=none\n'
        '  :log info "ddns-godaddy updated $host.$domain -> $ip"\n'
        "}"
    )
    return [
        f"# {entry.description or f'godaddy {host}.{entry.domain}'}",
        f"/system script add name={name} source={script}",
        f'/system scheduler add name={name} interval={_SCHEDULE_INTERVAL} '
        f'on-event="/system script run {name}" disabled=yes '
        f'comment="run manually once to verify, then enable"',
    ]


def _cloudflare(entry: DynDnsEntry, iface: str) -> list[str]:
    name = _script_name("cloudflare", entry)
    fqdn = (
        entry.domain
        if entry.hostname == "@"
        else f"{entry.hostname}.{entry.domain}"
    )
    email = entry.username or "<FILL_IN_CLOUDFLARE_EMAIL>"
    api_key = entry.password or "<FILL_IN_CLOUDFLARE_API_KEY>"

    # One-time IDs fetch (shown as comment — not part of the script):
    id_fetch_note = (
        f"#   One-time: obtain zone_id and record_id:\n"
        f'#     curl -H "X-Auth-Email: {email}" -H "X-Auth-Key: {api_key}" \\\n'
        f"#       https://api.cloudflare.com/client/v4/zones?name={entry.domain}\n"
        f'#     curl -H "X-Auth-Email: {email}" -H "X-Auth-Key: {api_key}" \\\n'
        f'#       "https://api.cloudflare.com/client/v4/zones/<zone_id>/dns_records?name={fqdn}&type=A"'
    )

    script = (
        "{\n"
        f'  :local iface "{iface}"\n'
        f'  :local email "{_quote(email)}"\n'
        f'  :local apiKey "{_quote(api_key)}"\n'
        '  :local zoneId "<FILL_IN_CLOUDFLARE_ZONE_ID>"\n'
        '  :local recordId "<FILL_IN_CLOUDFLARE_RECORD_ID>"\n'
        '  :local addr [/ip address get [find interface=$iface] address]\n'
        '  :if ([:len $addr] = 0) do={ :log warning "ddns-cloudflare: no addr on $iface"; :return }\n'
        '  :local ip [:pick $addr 0 [:find $addr "/"]]\n'
        f'  :local data "{{\\\"type\\\":\\\"A\\\",\\\"name\\\":\\\"{_quote(fqdn)}\\\",\\\"content\\\":\\\"$ip\\\",\\\"ttl\\\":300,\\\"proxied\\\":false}}"\n'
        '  /tool fetch mode=https http-method=put \\\n'
        '    url=("https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records/$recordId") \\\n'
        '    http-header-field=("X-Auth-Email: $email,X-Auth-Key: $apiKey,Content-Type: application/json") \\\n'
        '    http-data=$data output=none\n'
        f'  :log info "ddns-cloudflare updated {fqdn} -> $ip"\n'
        "}"
    )
    return [
        f"# {entry.description or f'cloudflare {fqdn}'}",
        id_fetch_note,
        f"/system script add name={name} source={script}",
        f'/system scheduler add name={name} interval={_SCHEDULE_INTERVAL} '
        f'on-event="/system script run {name}" disabled=yes '
        f'comment="fill in zone/record IDs + verify run, then enable"',
    ]
