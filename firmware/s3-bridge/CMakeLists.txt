# Zigbee sniffer, Wi-Fi half: an ESP32-S3 serving the radio's frames over TCP.
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Board: supermini (ESP32-S3 Super Mini, the default) or devkitc (ESP32-S3-DevKitC-1-N16R8).
# Each board builds in its own folder with its own sdkconfig:
#   idf.py build
#   idf.py -B build-devkitc -D SNIFFER_BOARD=devkitc -D SDKCONFIG=sdkconfig.devkitc build
set(SNIFFER_BOARD "supermini" CACHE STRING "Bridge board: supermini or devkitc")
if(NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.board.${SNIFFER_BOARD}")
    message(FATAL_ERROR "No sdkconfig.board.${SNIFFER_BOARD}: SNIFFER_BOARD is supermini or devkitc")
endif()

# Wi-Fi name/password and the update token live in sdkconfig.secrets (git-ignored; copy
# sdkconfig.secrets.example). Defaults only apply when sdkconfig is (re)created.
set(SDKCONFIG_DEFAULTS "sdkconfig.defaults" "sdkconfig.board.${SNIFFER_BOARD}")
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.secrets")
    list(APPEND SDKCONFIG_DEFAULTS "sdkconfig.secrets")
endif()

set(COMPONENTS main)
# Firmware version: in the image (the update endpoint shows it) and in the HELLO to HA. Boards
# other than the Super Mini carry their name ("0.3.2+devkitc"); an update for another board is
# refused.
set(PROJECT_VER "0.3.6")
if(NOT SNIFFER_BOARD STREQUAL "supermini")
    string(APPEND PROJECT_VER "+${SNIFFER_BOARD}")
endif()
project(zigbee_sniffer_bridge)
