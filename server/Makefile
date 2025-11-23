ESC := $(shell printf '\e')
RED := $(ESC)[0;31m
GREEN := $(ESC)[0;32m
PURPLE := $(ESC)[0;35m
ZERO := $(ESC)[0;0m

MAIN_NAME := ota_server
CERT_FILE := build/server.crt
KEY_FILE  := build/server.key

all: build/ make $(CERT_FILE) $(KEY_FILE)

build/: CMakeLists.txt
	echo -e "$(GREEN)Configuring CMake build...$(ZERO)"
	mkdir -p build
	cd build && PKG_CONFIG_PATH=../../build/x86/lib/pkgconfig cmake ..

make: build/
	echo -e "$(GREEN)Building $(PURPLE)$(MAIN_NAME)$(GREEN)...$(ZERO)"
	cd build && make

# Generate certificate and private key if they don't exist
$(CERT_FILE) $(KEY_FILE): scripts/generate_cert.sh
	echo -e "$(GREEN)Generating TLS certificate and private key...$(ZERO)"
	scripts/generate_cert.sh

build/$(MAIN_NAME): make

run: build/$(MAIN_NAME) build/device.bin $(CERT_FILE) $(KEY_FILE)
	echo -e "$(GREEN)Running $(PURPLE)$(MAIN_NAME)$(GREEN) with device.bin...$(ZERO)"
	cd build && ./$(MAIN_NAME) device.bin server.crt server.key

debug: build/$(MAIN_NAME) build/device.bin $(CERT_FILE) $(KEY_FILE)
	echo -e "$(GREEN)Running $(PURPLE)$(MAIN_NAME)$(GREEN) with device.bin...$(ZERO)"
	cd build && gdb --args ./$(MAIN_NAME) device.bin server.crt server.key


clean:
	echo -e "$(RED)Cleaning build directory...$(ZERO)"
	rm -rf build/

.PHONY: make run clean
