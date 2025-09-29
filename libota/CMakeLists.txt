cmake_minimum_required(VERSION 3.10)

project(ota VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Set default OTA_RAM_FUNCTION definition if not provided by user
if(NOT DEFINED OTA_RAM_FUNCTION_DEFINITION)
    message(WARNING "OTA_RAM_FUNCTION_DEFINITION is not defined. This may cause runtime errors. Please define it in your toolchain file or CMake configuration.")

    set(OTA_RAM_FUNCTION_DEFINITION "func_name")
endif()

# Generate OTA_RAM_FUNCTION header from template
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ota_ram_function.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/ota_ram_function.h"
    @ONLY
)

file(GLOB LIBOTA_SOURCES "src/*.c")
file(GLOB LIBOTA_HEADERS "include/*.h")

add_library(${PROJECT_NAME} STATIC ${LIBOTA_SOURCES})

set_target_properties(${PROJECT_NAME} PROPERTIES
  PUBLIC_HEADER "${LIBOTA_HEADERS}")

target_include_directories(${PROJECT_NAME}
    PUBLIC include
    PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/generated")

# Install the library and headers
install(TARGETS ${PROJECT_NAME}
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include/libota
)

# Install generated headers
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/generated/ota_ram_function.h"
    DESTINATION include/libota
)

# Create pkg-config file
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libota.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/libota.pc"
    @ONLY
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libota.pc"
    DESTINATION lib/pkgconfig
)

# Print configuration summary
message(STATUS "")
message(STATUS "libota configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Library type: STATIC")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
