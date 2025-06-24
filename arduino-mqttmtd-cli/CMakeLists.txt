cmake_minimum_required(VERSION 3.16)
project(MQTTMTDClient CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 20)

set(ARDUINO_PATH "$ENV{HOME}/Library/Arduino15")

set(ARDUINO_CORE_PATH "${ARDUINO_PATH}/packages/esp32/hardware/esp32/3.1.1/cores/esp32")
set(ARDUINO_LIBRARIES_PATH "${ARDUINO_PATH}/libraries")

set(ARDUINO_ESP32_LIBRARIES_PATH "${ARDUINO_PATH}/packages/esp32/hardware/esp32/3.1.1/libraries")
file(GLOB ARDUINO_ESP32_LIBRARIES_PATHS
        "${ARDUINO_ESP32_LIBRARIES_PATH}/*/src"
)
set(ARDUINO_USER_LIBRARIES_PATH "$ENV{HOME}/Documents/Arduino/libraries")
file(GLOB ARDUINO_USER_LIBRARIES_PATHS
        "${ARDUINO_USER_LIBRARIES_PATH}/*/src"
)

set(SRC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(MBEDTLS_INCLUDE_PATH "$ENV{HOME}/git/mbedtls/include")

add_library(MQTTMTDClient STATIC
        src/MQTTMTDClient.h
        src/MQTTMTDClient.cpp
        ../cpp-mqttmtd-cli/src/libmqttmtd.cpp
        ../cpp-mqttmtd-cli/src/libmqttmtd.h
        tests/test_publish.c
)
target_include_directories(
        MQTTMTDClient PUBLIC
        ${ARDUINO_CORE_PATH}
        ${ARDUINO_LIBRARIES_PATH}
        ${ARDUINO_ESP32_LIBRARIES_PATHS}
        ${ARDUINO_USER_LIBRARIES_PATHS}
        ${SRC_PATH}
        ${MBEDTLS_INCLUDE_PATH}
)
