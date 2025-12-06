ESC := $(shell printf '\e')
RED := $(ESC)[0;31m
GREEN := $(ESC)[0;32m
PURPLE := $(ESC)[0;35m
ZERO := $(ESC)[0;0m

CONFIG_HOSTNAME := "pico_device"

CFLAGS += -DCONFIG_HOSTNAME=${CONFIG_HOSTNAME}

all: build/ ninja

wlan.ini:
	@ echo -ne "$(RED)Error: $(PURPLE)wlan.ini$(RED) file not found! "
	@ echo -e "$(ZERO)Check $(GREEN)README.md$(ZERO) for instructions."
	@ exit 1

checkenv_%:
	@ if [ "${${*}}" = "" ]; then \
		echo -ne "$(RED)Error: Environment variable $(PURPLE)$*$(ZERO) not set. "; \
		echo -e "$(ZERO)Check $(GREEN)README.md$(ZERO) for instructions."; \
		exit 1; \
	fi

pico_sdk: checkenv_PICO_SDK_PATH checkenv_PICO_EXTRAS_PATH

# Generate signing key header before build
signing_key.h: ../build/signing.pub scripts/generate_signing_key_header.sh
	@echo "Generating signing key header..."
	@scripts/generate_signing_key_header.sh ../build/signing.pub

build/: ./configure_wifi.sh wlan.ini pico_sdk signing_key.h
	CFLAGS="$(CFLAGS)" \
	CONFIG_HOSTNAME=$(CONFIG_HOSTNAME) \
	PKG_CONFIG_PATH=../build/pico/lib/pkgconfig \
	./configure_wifi.sh

ninja: build/
	ninja -C build/

build/device.uf2: ninja

flash: build/device.uf2
	scripts/rpiflash.sh $(RPI_USB)

term:
	scripts/picoterm.sh

clean:
	rm -rf build/
	rm cmake/memmap.ld

.PHONY: ninja flash term clean pico_sdk
