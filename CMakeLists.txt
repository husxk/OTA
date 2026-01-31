cmake_minimum_required(VERSION 3.16)

# Root project
project(OTA VERSION 1.0.0 LANGUAGES C CXX ASM)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options
option(BUILD_LIBOTA_HOST "Build libota for host" ON)
option(BUILD_LIBOTA_PICO "Build libota for pico" OFF)
option(BUILD_CLIENT "Build client application" OFF)
option(BUILD_SERVER "Build server application" ON)

# Set default install prefix
if(NOT CMAKE_INSTALL_PREFIX)
    set(CMAKE_INSTALL_PREFIX "${CMAKE_SOURCE_DIR}/build/install" CACHE PATH "Install prefix")
endif()

include(ExternalProject)

# Libota build directories
set(LIBOTA_BIN_DIR "${CMAKE_BINARY_DIR}/libota")
set(LIBOTA_HOST_BINARY_DIR "${LIBOTA_BIN_DIR}/host")
set(LIBOTA_PICO_BINARY_DIR "${LIBOTA_BIN_DIR}/pico")

# Build libota for host
if(BUILD_LIBOTA_HOST)
    ExternalProject_Add(libota_host_ext
        SOURCE_DIR ${CMAKE_SOURCE_DIR}/libota
        BINARY_DIR ${LIBOTA_HOST_BINARY_DIR}
        CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX=${LIBOTA_HOST_BINARY_DIR}
        BUILD_ALWAYS OFF
        BUILD_BYPRODUCTS
            <INSTALL_DIR>/lib/libota.a
        INSTALL_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --target install
    )

    # Create imported target for libota_host
    add_library(libota_host STATIC IMPORTED GLOBAL)

    set_target_properties(libota_host PROPERTIES
        IMPORTED_LOCATION
            ${LIBOTA_HOST_BINARY_DIR}/lib/libota.a
    )

    add_dependencies(libota_host libota_host_ext)

    # Create include directory and set include directories
    file(MAKE_DIRECTORY ${LIBOTA_HOST_BINARY_DIR}/include/libota)
    target_include_directories(libota_host INTERFACE
        ${LIBOTA_HOST_BINARY_DIR}/include
    )

    # Link mbedTLS libraries that libota depends on
    #    add_library(mbedtls_host STATIC IMPORTED GLOBAL)
    #    set_target_properties(mbedtls_host PROPERTIES
    #        IMPORTED_LOCATION ${LIBOTA_HOST_BINARY_DIR}/lib/libmbedtls.a
    #    )
    add_library(mbedx509_host STATIC IMPORTED GLOBAL)
    set_target_properties(mbedx509_host PROPERTIES
        IMPORTED_LOCATION ${LIBOTA_HOST_BINARY_DIR}/lib/libmbedx509.a
    )
    add_library(mbedcrypto_host STATIC IMPORTED GLOBAL)
    set_target_properties(mbedcrypto_host PROPERTIES
        IMPORTED_LOCATION ${LIBOTA_HOST_BINARY_DIR}/lib/libmbedcrypto.a
    )

    # Link mbedTLS to libota_host so dependencies are propagated
    target_link_libraries(libota_host INTERFACE
        #        mbedtls_host
        mbedx509_host
        mbedcrypto_host
    )
endif()

# Build libota for pico
if(BUILD_LIBOTA_PICO)
    ExternalProject_Add(libota_pico_ext
        SOURCE_DIR ${CMAKE_SOURCE_DIR}/libota
        BINARY_DIR ${LIBOTA_PICO_BINARY_DIR}
        CMAKE_ARGS
            -DCMAKE_TOOLCHAIN_FILE=${CMAKE_SOURCE_DIR}/cmake/toolchain-pico.cmake
            -DCMAKE_INSTALL_PREFIX=${LIBOTA_PICO_BINARY_DIR}
            -DOTA_RAM_FUNCTION_DEFINITION="__attribute__((__noinline__)) __attribute__((section(\".time_critical.\" #func_name))) func_name"
        BUILD_ALWAYS OFF
        BUILD_BYPRODUCTS
            <INSTALL_DIR>/lib/libota.a
        INSTALL_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --target install
    )
    
    add_dependencies(libota_pico_ext mbedtls_config)

    # Create imported target for libota_pico
    add_library(libota_pico STATIC IMPORTED GLOBAL)

    set_target_properties(libota_pico PROPERTIES
        IMPORTED_LOCATION
            ${LIBOTA_PICO_BINARY_DIR}/lib/libota.a
    )

    add_dependencies(libota_pico libota_pico_ext)
    
    # Create include directory and set include directories
    # Point to include/ so that #include <libota/ota_server.h> works
    file(MAKE_DIRECTORY ${LIBOTA_PICO_BINARY_DIR}/include/libota)
    target_include_directories(libota_pico INTERFACE
        ${LIBOTA_PICO_BINARY_DIR}/include
    )
endif()

# Add client (depends on libota_pico)
if(BUILD_CLIENT)
    #    add_subdirectory(client)
endif()

# Add server (depends on libota_host)
if(BUILD_SERVER)
    add_subdirectory(server)
endif()
