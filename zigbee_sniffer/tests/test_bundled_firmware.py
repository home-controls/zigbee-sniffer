"""The radio images that come with the app (built by the release, in the add-on image at /firmware)
are listed on the Sniffer page before the ones in /share, and can be picked by name like those."""

import importlib
import os
import sys

from test_bridge import ESP32_C6, esp_image, app_desc


def radio_image(version: str) -> bytes:
    return esp_image([app_desc(version, "zigbee_sniffer_radio") + b"\x11" * 300], chip=ESP32_C6)


def load_main(tmp_path, monkeypatch):
    for k, v in {"SNIFFER_DATA": tmp_path / "data", "SNIFFER_CARRY": tmp_path / "no-carry-over",
                 "SNIFFER_CAPTURES": tmp_path / "share" / "zigbee_captures"}.items():
        monkeypatch.setenv(k, str(v))
    (tmp_path / "data").mkdir()
    sys.modules.pop("main", None)
    main = importlib.import_module("main")
    bundled, shared = tmp_path / "firmware", tmp_path / "share" / "zigbee_sniffer" / "firmware"
    bundled.mkdir()
    shared.mkdir(parents=True)
    monkeypatch.setattr(main, "BUNDLED_DIR", bundled)
    monkeypatch.setattr(main, "FIRMWARE_DIR", shared)
    return main, bundled, shared


def test_bundled_images_come_first_and_resolve_by_name(tmp_path, monkeypatch):
    main, bundled, shared = load_main(tmp_path, monkeypatch)
    (bundled / "zigbee_sniffer_radio-0.3.0-c6.bin").write_bytes(radio_image("0.3.0"))
    (shared / "my-build.bin").write_bytes(radio_image("0.3.1-dev"))
    (shared / "notes.txt").write_text("not an image")

    files = main.firmware_files()
    assert [(f["name"], f["bundled"]) for f in files] == [("zigbee_sniffer_radio-0.3.0-c6.bin", True), ("my-build.bin", False)]
    assert files[0]["target"] == "radio" and files[0]["version"] == "0.3.0" and files[0]["chip"] == "ESP32-C6"

    assert main.firmware_path("zigbee_sniffer_radio-0.3.0-c6.bin") == bundled / "zigbee_sniffer_radio-0.3.0-c6.bin"
    assert main.firmware_path("my-build.bin") == shared / "my-build.bin"
    assert main.firmware_path("../firmware/my-build.bin") == shared / "my-build.bin"  # only the name counts
    assert main.firmware_path("notes.txt") is None
    assert main.firmware_path("missing.bin") is None


def test_a_bundled_name_hides_the_same_name_in_share(tmp_path, monkeypatch):
    main, bundled, shared = load_main(tmp_path, monkeypatch)
    (bundled / "radio.bin").write_bytes(radio_image("0.3.0"))
    (shared / "radio.bin").write_bytes(radio_image("0.2.9"))
    files = main.firmware_files()
    assert [(f["name"], f["version"], f["bundled"]) for f in files] == [("radio.bin", "0.3.0", True)]
    assert main.firmware_path("radio.bin") == bundled / "radio.bin"


def test_no_bundled_folder_outside_the_add_on(tmp_path, monkeypatch):
    main, bundled, shared = load_main(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "BUNDLED_DIR", tmp_path / "nowhere")
    (shared / "a.bin").write_bytes(radio_image("0.3.0"))
    assert [f["name"] for f in main.firmware_files()] == ["a.bin"]
    assert os.path.basename(main.firmware_path("a.bin")) == "a.bin"
