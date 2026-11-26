idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "." "../../protocol"
    PRIV_REQUIRES ieee802154 esp_driver_uart esp_driver_usb_serial_jtag esp_driver_gpio esp_timer esp_ringbuf app_update)

idf_build_get_property(radio_version PROJECT_VER)
string(REGEX MATCH "^([0-9]+)\.([0-9]+)\.([0-9]+)" radio_version_match "${radio_version}")
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    RADIO_VERSION_MAJOR=${CMAKE_MATCH_1} RADIO_VERSION_MINOR=${CMAKE_MATCH_2} RADIO_VERSION_PATCH=${CMAKE_MATCH_3})
