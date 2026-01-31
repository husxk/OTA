cmake_minimum_required(VERSION 3.16)
include(${PICO_SDK_PATH}/external/pico_sdk_import.cmake)
include(${PICO_EXTRAS_PATH}/external/pico_extras_import.cmake)

set(MAIN_NAME device)

project(${MAIN_NAME} C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Collect source files from src directory (excluding main.c)
file(GLOB_RECURSE SOURCE_FILES "src/*.c")

set(SOURCES
    main.c
    ${SOURCE_FILES}
    )

# Reserve half of flash for OTA updates
set(PICO_FLASH_SIZE_BYTES "1024 * 1024")  # 1MB for flash
set(OTA_STORAGE_SIZE "1024 * 1024")       # 1MB for OTA

set(DEFINES
     WIFI_SSID=\"${WIFI_SSID}\"
     WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
     CYW43_HOST_NAME=\"${CONFIG_HOSTNAME}\"
     OTA_STORAGE_SIZE_BYTES=${OTA_STORAGE_SIZE}
    )

pico_sdk_init()

# Create custom flash region template with OTA storage
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/memmap.template.ld
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/memmap.ld
    @ONLY
)

add_executable(${MAIN_NAME}
       ${SOURCES}
       )

pico_set_linker_script(${MAIN_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/memmap.ld)

# Add memory usage reporting and dead code elimination
target_link_options(${MAIN_NAME} PRIVATE
    "-Wl,--gc-sections"
    "-Wl,--print-memory-usage"
)

target_compile_definitions(${MAIN_NAME} PRIVATE
       ${DEFINES}
       )

target_include_directories(${MAIN_NAME} PRIVATE
          ${CMAKE_CURRENT_LIST_DIR}
          ${CMAKE_CURRENT_LIST_DIR}/include
          ${CMAKE_CURRENT_LIST_DIR}/.. # for our common lwipopts
        )

        #find_package(PkgConfig REQUIRED)

        #pkg_check_modules(LIBOTA REQUIRED libota)

        #target_include_directories(${MAIN_NAME} PRIVATE ${LIBOTA_INCLUDE_DIRS})
        #target_compile_options(${MAIN_NAME} PRIVATE ${LIBOTA_CFLAGS_OTHER})

target_compile_options(${MAIN_NAME} PRIVATE
    -ffunction-sections
    -fdata-sections
)

target_link_libraries(${MAIN_NAME}
          pico_cyw43_arch_lwip_poll
          pico_stdlib
          hardware_spi
          hardware_pwm
          libota_pico
          #          ${LIBOTA_LDFLAGS}
        )

pico_add_extra_outputs(${MAIN_NAME})

pico_enable_stdio_usb(${MAIN_NAME} 1)
pico_enable_stdio_uart(${MAIN_NAME} 0)
