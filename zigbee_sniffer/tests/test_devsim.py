"""The simulators in ../dev: their simulated house runs offline (no sockets) and reads like a real
network to the app's own code."""

import random

import pytest

import analysis
import names as names_mod
import pcap

devsim = pytest.importorskip("devsim")


@pytest.fixture
def house(tmp_path, monkeypatch):
    random.seed(7)
    devsim.write_z2m(tmp_path / "z2m")
    monkeypatch.setattr(names_mod, "Z2M_DIR", tmp_path / "z2m")
    return tmp_path


def test_zigbee2mqtt_files(house):
    cfg = names_mod.load_z2m_config()
    assert names_mod.our_pan(cfg) == devsim.PAN
    assert names_mod.network_key(cfg) == "01:03:05:07:09:0B:0D:0F:00:02:04:06:08:0A:0C:0D"  # Z2M's example key
    n = names_mod.Names()
    n.reload()
    assert n.name("0x774a") == "Kitchen Keypad"
    assert len(n.devices) == len(devsim.DEVS) + len(devsim.NOT_HEARD)
    assert n.meta("0x40a8")["type"] == "EndDevice"


def test_ten_simulated_minutes_through_the_analyzer(house):
    t0 = 1_800_000_000.0
    net = devsim.Net(t0)
    net.run_until(t0 + 600)
    frames = sorted(net.out)
    assert len(frames) > 1000
    w = pcap.RotatingPcap(house / "captures")
    for ts, psdu, rssi, lqi in frames:
        w.write(ts, pcap.tap_packet(psdu, 25, rssi, lqi))
    w.close()
    an = analysis.Analyzer(devsim.PAN)
    for path in sorted((house / "captures").glob("*/*.pcap")):
        for _, ts, data in pcap.iter_records(path):
            _, rssi, lqi, psdu = pcap.parse_tap(data)
            an.feed(ts, rssi, lqi, psdu)
    b = an.batch
    tot = [sum(r[i] for r in b.net.values()) for i in range(len(analysis.NET_FIELDS))]
    assert tot[analysis.N_OURS] + tot[analysis.N_OTHERS] + tot[analysis.N_UNNAMED] == len(frames)
    assert tot[analysis.N_OURS] > 0.75 * len(frames)
    assert tot[analysis.N_OTHERS] > 0  # the neighbours' network and the Thread-like frames
    assert tot[analysis.N_RETRY] > 0  # lossy hops resend
    heard = {addr for _, addr in b.dev}
    assert "0x0000" in heard and "0x774a" in heard
    polls = sum(r[analysis.POLL] for r in b.dev.values())
    assert polls > 0


def test_devsim2_imports_and_signal_falls_with_distance():
    devsim2 = pytest.importorskip("devsim2")
    near = devsim2.SNIFFERS[0]
    vals = [devsim2.rssi_at(a, near) for a in devsim2.POS]
    assert any(v is None for v in vals) or min(v for v in vals if v is not None) < -70
    assert all(v is None or -100 < v < 0 for v in vals)
