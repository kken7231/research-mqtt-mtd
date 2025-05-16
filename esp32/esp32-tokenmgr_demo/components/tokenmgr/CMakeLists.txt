idf_component_register(SRCS "token_store.c" "payload_aead_type.c" "mqtt.c" "wifi.c" "util.c" "logger.c" "tokenmgr.c"
                    INCLUDE_DIRS "."
                    REQUIRES esp-tls mbedtls nvs_flash esp_wifi mqtt espressif__mdns log
                    EMBED_TXTFILES ../../../../certs/clients/client.key ../../../../certs/clients/client.pem)