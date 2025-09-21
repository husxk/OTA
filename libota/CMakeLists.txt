cmake_minimum_required(VERSION 3.10)

project(libota VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

file(GLOB LIBOTA_HEADERS "include/*.h")

add_library(ota INTERFACE)

set_target_properties(ota PROPERTIES
    VERSION ${PROJECT_VERSION}
    PUBLIC_HEADER "${LIBOTA_HEADERS}"
)

# Set include directories
target_include_directories(ota INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/libota>
)

# Install headers
install(TARGETS ota
    PUBLIC_HEADER DESTINATION include/libota
)

# Create pkg-config file
set(PC_NAME "${PROJECT_NAME}")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libota.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/${PC_NAME}.pc"
    @ONLY
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PC_NAME}.pc"
    DESTINATION lib/pkgconfig
)

# Print configuration summary
message(STATUS "")
message(STATUS "libota configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Library type: HEADER-ONLY")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")