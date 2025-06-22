cmake_minimum_required(VERSION 3.16)
project(MQTTMTDClient CXX)

set(CMAKE_CXX_STANDARD 11)

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
set(MBEDTLS_INCLUDE_PATH "~/git/mbedtls/include")

include_directories(
        ${ARDUINO_CORE_PATH}
        ${ARDUINO_LIBRARIES_PATH}
        ${ARDUINO_ESP32_LIBRARIES_PATHS}
        ${ARDUINO_USER_LIBRARIES_PATHS}
        ${SRC_PATH}
        ${MBEDTLS_INCLUDE_PATH}
)
add_library(MQTTMTDClient STATIC
        src/MQTTMTDClient.h
        src/MQTTMTDClient.cpp
)

# --- If you want to build an example sketch (optional) ---
# This helps with testing and ensuring everything links correctly.
# add_executable(example_sketch example/example_sketch.ino) # Replace with your example file
# target_link_libraries(example_sketch YourArduinoLibrary)