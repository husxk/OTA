cmake_minimum_required(VERSION 3.16)

# Root project
project(OTA VERSION 1.0.0 LANGUAGES C CXX ASM)

# Options
option(BUILD_LIBOTA "Build libota library" ON)
option(BUILD_CLIENT "Build client application" ON)
option(BUILD_SERVER "Build server application" ON)

# Set default install prefix
if(NOT CMAKE_INSTALL_PREFIX)
    set(CMAKE_INSTALL_PREFIX "${CMAKE_SOURCE_DIR}/build/install" CACHE PATH "Install prefix")
endif()

# Add libota first (builds both host and pico)
if(BUILD_LIBOTA)
    add_subdirectory(libota)
endif()

# Add client (depends on libota_pico)
if(BUILD_CLIENT)
    add_subdirectory(client)
endif()

# Add server (depends on libota)
if(BUILD_SERVER)
    add_subdirectory(server)
endif()
