from pathlib import Path

from pfmk.emitters import ddns as ddns_emitter
from pfmk.overrides import DomainsOverrides, InterfaceMapping
from pfmk.parser import parse_config

FIXTURE = Path(__file__).parent / "fixtures" / "minimal.xml"


def _mappings() -> dict[str, InterfaceMapping]:
    return {
        "wan": InterfaceMapping(target="ether1", role="egress"),
        "opt1": InterfaceMapping(target="ether2", role="ingress"),
        "lan": InterfaceMapping(target="bridge-lan", role="lan"),
    }


def test_parser_extracts_dyndns_entries():
    config = parse_config(FIXTURE)
    assert len(config.dyndns) == 3
    assert config.dyndns[0].provider == "godaddy"
    assert config.dyndns[1].provider == "cloudflare"
    assert config.dyndns[1].hostname == "@"


def test_emitter_embeds_credentials_from_backup():
    config = parse_config(FIXTURE)
    rendered = ddns_emitter.emit(
        config.dyndns, _mappings(), DomainsOverrides(drop=["gone.example"])
    )

    assert "# ==== Dynamic DNS ====" in rendered
    # GoDaddy: username + decoded password embedded directly
    assert "/system script add name=ddns-godaddy-wan-example-test" in rendered
    assert ':local apiKey "MY_GODADDY_KEY"' in rendered
    assert ':local apiSecret "SECRET"' in rendered
    assert "<FILL_IN_GODADDY_KEY>" not in rendered
    # Cloudflare: email + api key embedded, zone/record still placeholders
    assert "/system script add name=ddns-cloudflare-apex-example-test" in rendered
    assert ':local email "user@example.test"' in rendered
    assert "<FILL_IN_CLOUDFLARE_ZONE_ID>" in rendered
    assert "<FILL_IN_CLOUDFLARE_RECORD_ID>" in rendered
    # Uses legacy X-Auth headers
    assert "X-Auth-Email:" in rendered
    # Schedulers disabled by default
    assert "disabled=yes" in rendered
    # Domain drop filter worked — gone.example entry not present
    assert "gone.example" not in rendered


def test_emitter_empty_when_no_surviving_entries():
    config = parse_config(FIXTURE)
    # Drop everything via domain filter
    rendered = ddns_emitter.emit(
        config.dyndns,
        _mappings(),
        DomainsOverrides(drop=["example.test", "gone.example"]),
    )
    assert rendered == ""
