# OTA_RAM_FUNCTION Template Configuration

The `libota` library uses a templated approach to generate the `OTA_RAM_FUNCTION` macro based on your platform's requirements.

## How it works

1. The library includes a template file: `cmake/ota_ram_function.h.in`
2. Your toolchain file defines CMake variable: `OTA_RAM_FUNCTION_DEFINITION`
3. CMake generates the appropriate header during build

## Required CMake Variable

Define this in your toolchain file:

```cmake
# The macro definition that places functions in RAM
set(OTA_RAM_FUNCTION_DEFINITION "your_platform_attributes func_name")
```
## Example

### Pico SDK
```cmake
set(OTA_RAM_FUNCTION_DEFINITION "__attribute__((__noinline__)) __attribute__((section(\".time_critical.\" #func_name))) func_name")
```

## Usage

1. Create your toolchain file with `OTA_RAM_FUNCTION_DEFINITION`
2. Build with: `cmake -DCMAKE_TOOLCHAIN_FILE=your_toolchain.cmake ..`
3. The generated `generated/ota_ram_function.h` will contain the correct macro for your platform

## Generated Header

The generated header will look like:
```c
#pragma once

#define OTA_RAM_FUNCTION(func_name) your_platform_attributes func_name
```

## Function Usage

Use the macro in your code like this:
```c
void OTA_RAM_FUNCTION(my_function)(int arg1, int arg2)
{
    // Function body - will be placed in RAM
}
```
