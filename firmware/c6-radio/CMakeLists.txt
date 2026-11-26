# Zigbee sniffer, radio half: Seeed XIAO ESP32C6 listening on one 802.15.4 channel.
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
set(COMPONENTS main)
# Firmware version: in the image, the radio status and the boot report.
set(PROJECT_VER "0.3.0")
project(zigbee_sniffer_radio)
