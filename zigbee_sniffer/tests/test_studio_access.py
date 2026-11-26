"""0.5.12: Zigbee Studio may GET a few read-only answers with its key. 0.5.13: and set up the
floor maps. Nothing else changes."""

import studio


def test_the_key_is_made_once_and_kept(tmp_path):
    f = tmp_path / "zigbee_sniffer" / "studio.key"
    k = studio.ensure_key(f, True)
    assert len(k) >= 32 and f.read_text().strip() == k
    assert studio.ensure_key(f, True) == k  # a restart keeps it, so Studio keeps working


def test_turning_it_off_removes_the_key(tmp_path):
    f = tmp_path / "studio.key"
    studio.ensure_key(f, True)
    assert studio.ensure_key(f, False) == ""
    assert not f.exists()
    assert studio.ensure_key(f, False) == ""  # already gone


def test_a_short_or_empty_key_file_is_replaced(tmp_path):
    f = tmp_path / "studio.key"
    f.write_text("short\n")
    k = studio.ensure_key(f, True)
    assert k != "short" and len(k) >= 32


def test_studio_reads_what_its_pages_need():
    k = "k" * 43
    for path in ("/api/status", "/api/overview", "/api/devices", "/api/device/0x072f", "/api/device/0xABCD",
                 "/api/mesh", "/api/live", "/api/map", "/api/map/coverage", "/api/map/floors/f1/image"):
        assert studio.allowed("GET", path, k, k), path


def test_studio_sets_up_the_floor_maps():
    k = "k" * 43
    for method, path in (("POST", "/api/map/floors"), ("POST", "/api/map/floors/1a2b3c4d"),
                         ("DELETE", "/api/map/floors/1a2b3c4d"), ("POST", "/api/map/floors/1a2b3c4d/image"),
                         ("POST", "/api/map/positions")):
        assert studio.allowed(method, path, k, k), (method, path)


def test_nothing_else_that_changes_decodes_or_downloads():
    k = "k" * 43
    for method, path in (("POST", "/api/channel"), ("POST", "/api/ping/0x072f"), ("POST", "/api/firmware/radio"),
                         ("POST", "/api/sniffer/moved"), ("POST", "/api/device/0x072f"), ("POST", "/api/map"),
                         ("POST", "/api/map/coverage"), ("DELETE", "/api/map/positions"), ("DELETE", "/api/map/floors"),
                         ("PUT", "/api/map/positions"), ("PATCH", "/api/map/floors/f1"),
                         ("DELETE", "/api/map/floors/f1/image"), ("POST", "/api/map/floors/f1/../../channel"),
                         ("POST", "/api/map/floors/f1/image/x"), ("POST", "/api/map/positions/"),
                         ("GET", "/api/decode"), ("GET", "/api/frame"), ("GET", "/api/captures"),
                         ("GET", "/api/trace/0x072f"), ("GET", "/api/sniffer"), ("GET", "/api/device/0x072f/hours"),
                         ("GET", "/download/2026-11-19/zigbee_2026-11-19_22.pcap"), ("GET", "/decoded/x"),
                         ("GET", "/"), ("GET", "/static/app.js"), ("GET", "/api/device/0x072f/../../decode"),
                         ("GET", "/api/status/"), ("GET", "/api/statusx"), ("GET", "/api/map/positions")):
        assert not studio.allowed(method, path, k, k), (method, path)


def test_no_key_or_a_wrong_key_gets_nothing():
    k = "k" * 43
    for method, path in (("GET", "/api/status"), ("POST", "/api/map/positions")):
        assert not studio.allowed(method, path, None, k)
        assert not studio.allowed(method, path, "", k)
        assert not studio.allowed(method, path, "x" * 43, k)
        assert not studio.allowed(method, path, k, "")  # option off: no key at all
        assert not studio.allowed(method, path, "", "")
