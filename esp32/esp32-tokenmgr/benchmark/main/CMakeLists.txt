idf_component_register(SRCS "benchmark.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES nvs_flash esp_wifi  esp_netif tokenmgr unity mqtt)