cmake_minimum_required(VERSION 3.10)

project(ota VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Set default OTA_RAM_FUNCTION definition if not provided by user
if(NOT DEFINED OTA_RAM_FUNCTION_DEFINITION)
    message(WARNING "OTA_RAM_FUNCTION_DEFINITION is not defined. This may cause runtime errors. Please define it in your toolchain file or CMake configuration.")
    set(OTA_RAM_FUNCTION_DEFINITION "func_name")
endif()

set(GENERATED_DIR "${CMAKE_BINARY_DIR}/generated")

# Generate OTA_RAM_FUNCTION header from template
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ota_ram_function.h.in"
    "${GENERATED_DIR}/ota_ram_function.h"
    @ONLY
)

file(GLOB LIBOTA_SOURCES "src/*.c")
file(GLOB LIBOTA_PUBLIC_HEADERS "include/libota/*.h")
file(GLOB LIBOTA_PRIVATE_HEADERS "include/internal/*.h")

add_library(${PROJECT_NAME} STATIC ${LIBOTA_SOURCES})


set(LIBOTA_MBEDTLS_CONFIG_FILES_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

set(MBEDTLS_CONFIG_FILE
    "${LIBOTA_MBEDTLS_CONFIG_FILES_DIR}/mbedtls_config.h"
    CACHE FILEPATH "mbedTLS config file")

set(TF_PSA_CRYPTO_CONFIG_FILE
    "${LIBOTA_MBEDTLS_CONFIG_FILES_DIR}/mbedtls_crypto_config.h"
    CACHE FILEPATH "mbedTLS crypto config file")

# Disable mbedTLS tests and examples
set(ENABLE_TESTING  OFF CACHE BOOL "Build Mbed TLS tests."    FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "Build Mbed TLS programs." FORCE)

# Add mbedTLS submodule
add_subdirectory(libs/mbedtls)

target_link_libraries(${PROJECT_NAME} PUBLIC
    mbedtls
    mbedx509
    mbedcrypto
)

set_target_properties(${PROJECT_NAME} PROPERTIES
  PUBLIC_HEADER "${LIBOTA_PUBLIC_HEADERS}")

target_include_directories(${PROJECT_NAME}
    PUBLIC include
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include/internal"
    PUBLIC "${GENERATED_DIR}"
    PUBLIC "${LIBOTA_MBEDTLS_CONFIG_FILES_DIR}")

# Install the library and headers
install(TARGETS ${PROJECT_NAME}
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include/libota
)

# Install generated headers
install(FILES "${GENERATED_DIR}/ota_ram_function.h"
    DESTINATION include/libota
)

# Create pkg-config file
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libota.pc.in"
    "${CMAKE_BINARY_DIR}/libota.pc"
    @ONLY
)

install(FILES "${CMAKE_BINARY_DIR}/libota.pc"
    DESTINATION lib/pkgconfig
)

# Print configuration summary
message(STATUS "")
message(STATUS "libota configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Library type: STATIC")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
