cmake_minimum_required(VERSION 3.16)
project(mqttmtd_cli CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

add_library(mqttmtd STATIC
        src/libmqttmtd.h
        src/libmqttmtd.cpp
)

add_executable(example_publish
        examples/publish.cpp
        examples/MQTTMTDPahoClient.h
        examples/MQTTMTDPahoClient.cpp
)
target_include_directories(
        example_publish PUBLIC
        src/
        paho.mqtt.c/src
)

set(PAHO_BUILD_STATIC TRUE)
set(PAHO_BUILD_SHARED FALSE)
set(PAHO_WITH_SSL FALSE)
set(PAHO_ENABLE_TESTING FALSE)
add_subdirectory(paho.mqtt.c)

target_link_libraries(
        example_publish PRIVATE
        mqttmtd
        paho-mqtt3c-static
        mbedtls
        mbedx509
        mbedcrypto
)