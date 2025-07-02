cmake_minimum_required(VERSION 3.16)
project(mqttmtd_cli CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

add_library(mqttmtd STATIC
        src/libmqttmtd.h
        src/libmqttmtd.cpp
)

find_package(MbedTLS REQUIRED)
if (MbedTLS_FOUND)
    target_link_libraries(
            mqttmtd PRIVATE
            MbedTLS::mbedtls
    )
else()
    message(FATAL_ERROR "mbedTLS not found!")
endif()

add_executable(example_publish
        examples/publish.cpp
        examples/MQTTMTDPahoClient.h
        examples/MQTTMTDPahoClient.cpp
)
target_include_directories(
        example_publish PUBLIC
        src/
)

set(PAHO_BUILD_STATIC ON CACHE BOOL "Build Paho MQTT C as a static library" FORCE)
set(PAHO_BUILD_SHARED OFF CACHE BOOL "Build Paho MQTT C as a shared library" FORCE)
set(PAHO_WITH_SSL OFF CACHE BOOL "Build Paho MQTT C with SSL support" FORCE)
set(PAHO_ENABLE_TESTING OFF CACHE BOOL "Build Paho MQTT C tests" FORCE)
add_subdirectory(paho.mqtt.c)

target_link_libraries(
        example_publish PRIVATE
        mqttmtd
        paho-mqtt3c-static
        MbedTLS::mbedtls
        MbedTLS::mbedx509
        MbedTLS::mbedcrypto
)