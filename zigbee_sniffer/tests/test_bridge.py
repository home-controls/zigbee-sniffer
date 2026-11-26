import hashlib
import struct

import bridge

ESP32_S3, ESP32_C6 = 9, 13


def app_desc(version: str, project: str) -> bytes:
    """esp_app_desc_t: magic, secure_version, reserved, version[32], project_name[32], time[16],
    date[16], idf_ver[32], ..."""
    pad = lambda s, n: s.encode().ljust(n, b"\0")
    desc = struct.pack("<II", bridge.APP_DESC_MAGIC, 0) + bytes(8) + pad(version, 32) + pad(project, 32) \
        + pad("12:00:00", 16) + pad("Nov  7 2026", 16) + pad("v5.5.6", 32)
    return desc.ljust(256, b"\0")


def esp_image(segments: list[bytes], chip: int = ESP32_S3, hash_appended: bool = True) -> bytes:
    """An ESP-IDF app image: 24-byte header, segments, padding so the checksum byte ends a 16-byte
    block, then (optionally) the SHA-256 of everything before."""
    hdr = bytearray(24)
    hdr[0], hdr[1] = 0xE9, len(segments)
    hdr[12:14] = chip.to_bytes(2, "little")
    hdr[23] = 1 if hash_appended else 0
    body = bytes(hdr)
    for i, seg in enumerate(segments):
        body += struct.pack("<II", 0x3C000020 + i * 0x10000, len(seg)) + seg
    body += b"\0" * (15 - len(body) % 16)
    checksum = 0xEF
    for seg in segments:
        for b in seg:
            checksum ^= b
    body += bytes([checksum])
    assert len(body) % 16 == 0
    if hash_appended:
        body += hashlib.sha256(body).digest()
    return body


def bridge_image(version="0.3.6+devkitc", project="zigbee_sniffer_bridge", chip=ESP32_S3, **kw) -> bytes:
    return esp_image([app_desc(version, project) + b"\x11" * 300, b"\x22" * 1001, b"\x33" * 7], chip=chip, **kw)


def test_good_image_hash():
    assert bridge.verify_hash(bridge_image()) is True


def test_odd_segment_lengths():
    for n in range(1, 40):
        assert bridge.verify_hash(esp_image([b"\x5a" * n])) is True, n


def test_corrupted_image():
    img = bytearray(bridge_image())
    img[400] ^= 0x01
    assert bridge.verify_hash(bytes(img)) is False


def test_truncated_image():
    img = bridge_image()
    assert bridge.verify_hash(img[:-5]) is False
    assert bridge.verify_hash(img[:200]) is False


def test_image_without_hash():
    assert bridge.verify_hash(bridge_image(hash_appended=False)) is None
    assert bridge.verify_hash(b"\xe9") is None


def test_image_info():
    info = bridge.image_info(bridge_image())
    assert info["project"] == "zigbee_sniffer_bridge" and info["target"] == "bridge"
    assert info["version"] == "0.3.6+devkitc" and info["chip"] == "ESP32-S3" and info["sha256"] is True


def test_check_image_bridge():
    info = bridge.image_info(bridge_image())
    assert bridge.check_image(info, "bridge", {"bridge": "0.3.5+devkitc"}) == []
    unknown = bridge.check_image(info, "bridge", {})
    assert len(unknown) == 1 and "unknown" in unknown[0]
    other_board = bridge.check_image(info, "bridge", {"bridge": "0.3.5"})
    assert other_board and "supermini" in other_board[0]


def test_check_image_refuses_damaged_and_wrong_target():
    img = bytearray(bridge_image())
    img[500] ^= 0xFF
    info = bridge.image_info(bytes(img))
    assert any("damaged" in p for p in bridge.check_image(info, "bridge", {"bridge": "0.3.5+devkitc"}))
    radio = bridge.image_info(bridge_image(version="0.2.3", project="zigbee_sniffer_radio", chip=ESP32_C6))
    probs = bridge.check_image(radio, "bridge", {"bridge": "0.3.5+devkitc"})
    assert any("not the bridge firmware" in p for p in probs) and any("ESP32-C6" in p for p in probs)
    assert bridge.check_image(radio, "radio", {}) == []  # a radio image needs no running version
