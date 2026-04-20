from pathlib import Path

from pfmk.emitters import dns as dns_emitter
from pfmk.overrides import DomainsOverrides
from pfmk.parser import parse_config

FIXTURE = Path(__file__).parent / "fixtures" / "minimal.xml"


def test_dns_parser_collects_from_both_sections():
    config = parse_config(FIXTURE)
    # 2 from dnsmasq + 1 from unbound = 3
    assert len(config.dns_hosts) == 3
    assert len(config.domain_overrides) == 1


def test_dns_emitter_filters_dropped_domains():
    config = parse_config(FIXTURE)
    domains = DomainsOverrides(drop=["gone.example", "retired.example"])
    rendered = dns_emitter.emit(
        config.dns_hosts, config.domain_overrides, domains
    )

    assert "# ==== DNS ====" in rendered
    assert "/ip dns set allow-remote-requests=yes" in rendered
    # Kept entries
    assert "name=keeper.local.test address=172.16.1.50" in rendered
    assert "name=server.local.test address=172.16.1.60" in rendered
    # Dropped
    assert "drop-me" not in rendered
    assert "retired.example" not in rendered


def test_dns_subdomain_match_in_drop_list():
    config = parse_config(FIXTURE)
    # Drop the parent — subdomain children must be dropped too
    domains = DomainsOverrides(drop=["example"])
    rendered = dns_emitter.emit(
        config.dns_hosts, config.domain_overrides, domains
    )
    assert "drop-me" not in rendered
    # local.test is not a subdomain of example → kept
    assert "keeper.local.test" in rendered
