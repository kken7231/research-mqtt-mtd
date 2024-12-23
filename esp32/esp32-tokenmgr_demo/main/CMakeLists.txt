idf_component_register(SRCS "test.c" "main.c"
                    INCLUDE_DIRS "."
                    REQUIRES nvs_flash esp_wifi esp_netif tokenmgr espressif__mdns)
