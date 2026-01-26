set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR ARM)

set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_C_COMPILER_WORKS 1)

# Set ARM Cortex-M0+ specific compiler flags
set(CMAKE_C_FLAGS "-mcpu=cortex-m0plus -mthumb -mfloat-abi=soft -ffunction-sections -fdata-sections")

# Set linker flags for dead code elimination and memory reporting
set(CMAKE_EXE_LINKER_FLAGS "-Wl,--gc-sections -Wl,--print-memory-usage")

# Define OTA_RAM_FUNCTION variables for template generation
# This matches Pico SDK's __no_inline_not_in_flash_func definition
set(OTA_RAM_FUNCTION_DEFINITION "__attribute__((__noinline__)) __attribute__((section(\".time_critical.\" #func_name))) func_name")
