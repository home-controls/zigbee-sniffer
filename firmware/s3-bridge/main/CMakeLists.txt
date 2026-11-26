idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "." "../../protocol"
    PRIV_REQUIRES esp_wifi esp_netif esp_event nvs_flash esp_driver_uart esp_driver_gpio esp_timer esp_ringbuf lwip
                  esp_http_server app_update esp_app_format esp_partition)

idf_build_get_property(bridge_version PROJECT_VER)
target_compile_definitions(${COMPONENT_LIB} PRIVATE BRIDGE_VERSION="${bridge_version}")
