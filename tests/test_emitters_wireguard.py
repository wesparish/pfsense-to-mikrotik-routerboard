from pfmk.emitters import wireguard as wg_emitter
from pfmk.overrides import WireGuardNordVPN


def test_disabled_emits_nothing():
    assert wg_emitter.emit(WireGuardNordVPN(enabled=False)) == ""


def test_empty_overrides_produce_placeholders():
    rendered = wg_emitter.emit(WireGuardNordVPN(enabled=True))
    assert "# ==== WireGuard" in rendered
    assert "<FILL_IN>" in rendered
    assert "TODO:" in rendered  # missing address → TODO line


def test_fully_filled_overrides_produce_active_commands():
    rendered = wg_emitter.emit(
        WireGuardNordVPN(
            enabled=True,
            address="10.5.0.2/32",
            peer_pubkey="PUB_KEY_BASE64",
            endpoint_host="us1234.nordvpn.com",
        )
    )
    assert "<FILL_IN>" in rendered  # private key still placeholder (always)
    assert "/ip address add interface=wg-nordvpn address=10.5.0.2/32" in rendered
    assert 'public-key="PUB_KEY_BASE64"' in rendered
    assert "endpoint-address=us1234.nordvpn.com" in rendered
    assert "TODO:" not in rendered
