idf_component_register(SRCS "tokenmgr.c"
                    INCLUDE_DIRS "include"
                    REQUIRES esp-tls mbedtls nvs_flash esp_wifi mqtt xtensa
                    EMBED_TXTFILES ../../../../certs/clients/client.key ../../../../certs/clients/client.pem)