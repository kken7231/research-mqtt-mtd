idf_component_register(SRCS "tokenmgr.c"
                    INCLUDE_DIRS "include"
                    REQUIRES esp-tls mbedtls nvs_flash
                    EMBED_TXTFILES client1.pem client1.key)
