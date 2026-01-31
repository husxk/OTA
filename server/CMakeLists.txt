cmake_minimum_required(VERSION 3.16)
project(OTA_Server)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(MAIN_NAME ota_server)

# Collect source files from src directory
file(GLOB_RECURSE SOURCE_FILES "src/*.cpp")

add_executable(${MAIN_NAME} main.cpp ${SOURCE_FILES})

target_include_directories(${MAIN_NAME} PRIVATE include)

target_link_libraries(${MAIN_NAME} PRIVATE libota_host)

# Ensure libota_host is built before server
if(TARGET libota_host_ext)
    add_dependencies(${MAIN_NAME} libota_host_ext)
endif()

target_compile_options(${MAIN_NAME} PRIVATE -Wall -Wextra)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


