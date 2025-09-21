# libota - Over-The-Air Update Library (C) - Header Only

## Building

### Installation
```bash
mkdir build
cd build
cmake ..
make install
```

## Usage

The library will be installed to:
- Headers: `${CMAKE_INSTALL_PREFIX}/include/libota/`
- pkg-config: `${CMAKE_INSTALL_PREFIX}/lib/pkgconfig/libota.pc`

## CMake Integration

To use in your CMake project:
```cmake
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBOTA REQUIRED libota)
target_include_directories(your_target PRIVATE ${LIBOTA_INCLUDE_DIRS})
```
