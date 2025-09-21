cmake_minimum_required(VERSION 3.16)
project(OTA_Server)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(BUILD_TESTS "Build tests" ON)

set(MAIN_NAME ota_server)

# Collect source files from src directory
file(GLOB_RECURSE SOURCE_FILES "src/*.cpp")

add_executable(${MAIN_NAME} main.cpp ${SOURCE_FILES})

target_include_directories(${MAIN_NAME} PRIVATE include)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBOTA REQUIRED libota)

target_include_directories(${MAIN_NAME} PRIVATE ${LIBOTA_INCLUDE_DIRS})
target_compile_options(${MAIN_NAME} PRIVATE ${LIBOTA_CFLAGS_OTHER})

target_compile_options(${MAIN_NAME} PRIVATE -Wall -Wextra)