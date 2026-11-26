import math
import random

import mapping

N_TRUE, L_TRUE, SIGMA_A, NOISE = 2.7, 13.0, 4.0, 2.0
TWO = [(0, 4.0, 3.0), (1, 15.0, 8.0)]  # (level, x, y) of each sniffer in a 20 x 12 m house
ONE = TWO[:1]


def house(seed: int, sniffers, ndev: int = 60) -> list[dict]:
    """Devices on two floors, each with its own strength A; every sniffer hears each one at
    A - 10 n log10(d) - L floors + noise, and not at all below -100 dBm."""
    rnd = random.Random(seed)
    samples = []
    for i in range(ndev):
        lv, x, y, a = i % 2, rnd.uniform(1, 19), rnd.uniform(1, 11), rnd.gauss(-40, SIGMA_A)
        for slv, sx, sy in sniffers:
            fl = abs(lv - slv)
            d = max(0.5, math.sqrt((x - sx) ** 2 + (y - sy) ** 2 + (fl * 3.0) ** 2))
            r = a - 10 * N_TRUE * math.log10(d) - L_TRUE * fl + rnd.gauss(0, NOISE)
            if r > -100:
                samples.append({"device": f"d{i}", "d": d, "floors": fl, "rssi": r, "n": 40})
    return samples


def test_too_few_samples():
    m = mapping.fit(house(1, TWO)[:3])
    assert m["ok"] is False and m["samples"] == 3


def test_two_sniffers_recover_n_and_floor_loss():
    for seed in (1, 2, 3):
        m = mapping.fit(house(seed, TWO))
        assert m["ok"] and not m["n_fixed"] and m["floor_loss_fitted"]
        assert abs(m["n"] - N_TRUE) < 0.2, (seed, m["n"])
        assert abs(m["floor_loss"] - L_TRUE) < 2.5, (seed, m["floor_loss"])
        assert m["devices_with_strength"] == m["devices"]  # every device is heard by both sniffers


def test_one_sniffer_rmse_is_honest():
    """With one measurement per device its own strength can't be told from the walls: no device gets
    an offset, and the reported error includes the spread of device strengths (not about half of it)."""
    for seed in (1, 2, 3):
        samples = house(seed, ONE)
        m = mapping.fit(samples)
        assert m["ok"] and m["devices_with_strength"] == 0 and m["offsets"] == {}
        true_spread = math.sqrt(SIGMA_A ** 2 + NOISE ** 2)
        assert m["rmse"] >= 0.75 * true_spread, (seed, m["rmse"])


def test_two_sniffer_rmse_is_leave_one_out():
    """Each measurement is predicted without itself: the error can't drop below the noise."""
    m = mapping.fit(house(4, TWO))
    assert m["rmse"] >= 0.9 * NOISE


def test_negative_floor_loss_is_refit_without_it():
    rnd = random.Random(9)
    samples = []
    for i in range(30):
        fl = i % 2
        d = rnd.uniform(2, 15)
        r = -40 - 27 * math.log10(d) + 6 * fl + rnd.gauss(0, 1)  # other-floor devices *louder*: nonsense
        samples.append({"device": f"x{i}", "d": d, "floors": fl, "rssi": r, "n": 10})
    m = mapping.fit(samples)
    assert m["ok"] and m["floor_loss"] >= 0 and not m["floor_loss_fitted"]


def test_weights_cap_a_chatty_device():
    samples = house(5, TWO, ndev=30)
    base = mapping.fit(samples)
    samples[0] = dict(samples[0], n=10**9)  # sqrt-weighted and capped at 10: the same as n=100
    capped = mapping.fit(samples)
    samples[0] = dict(samples[0], n=100)
    same = mapping.fit(samples)
    assert capped["n"] == same["n"] and capped["rmse"] == same["rmse"]
    assert base["ok"]
