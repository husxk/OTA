ESC := $(shell printf '\e')
RED := $(ESC)[0;31m
GREEN := $(ESC)[0;32m
PURPLE := $(ESC)[0;35m
ZERO := $(ESC)[0;0m

PROJECT_NAME := OTA_Server
MAIN_NAME := ota_server

all: build/ make

build/: CMakeLists.txt
	echo -e "$(GREEN)Configuring CMake build...$(ZERO)"
	mkdir -p build
	cd build && PKG_CONFIG_PATH=../../build/lib/pkgconfig cmake ..

make: build/
	echo -e "$(GREEN)Building $(PURPLE)$(MAIN_NAME)$(GREEN)...$(ZERO)"
	cd build && make

build/$(MAIN_NAME): make

run: build/$(MAIN_NAME)
	echo -e "$(GREEN)Running $(PURPLE)$(MAIN_NAME)$(GREEN)...$(ZERO)"
	cd build && ./$(MAIN_NAME)

clean:
	echo -e "$(RED)Cleaning build directory...$(ZERO)"
	rm -rf build/

.PHONY: make run clean
