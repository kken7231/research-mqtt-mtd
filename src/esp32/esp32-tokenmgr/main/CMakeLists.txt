idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    REQUIRES nvs_flash esp_system esp_wifi esp_event esp_netif freertos esp-tls mbedtls
                    EMBED_TXTFILES client1.pem client1.key)