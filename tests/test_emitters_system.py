from pathlib import Path

from pfmk.emitters import system as system_emitter
from pfmk.overrides import TargetOverrides
from pfmk.parser import parse_config

FIXTURES = Path(__file__).parent / "fixtures"


def test_system_emitter_matches_golden():
    config = parse_config(FIXTURES / "minimal.xml")
    rendered = system_emitter.emit(config.system, TargetOverrides())
    expected = (FIXTURES / "expected_system.rsc").read_text().rstrip()
    assert rendered == expected


def test_overrides_take_precedence_over_parsed():
    config = parse_config(FIXTURES / "minimal.xml")
    target = TargetOverrides(hostname="renamed", timezone="UTC")
    rendered = system_emitter.emit(config.system, target)
    assert 'name="renamed"' in rendered
    assert 'time-zone-name="UTC"' in rendered
