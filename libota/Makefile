CMAKE_INSTALL_PREFIX ?= $(PWD)/../build
TARGET ?= baremetal

all: mbedtls_config.h build/

build/: CMakeLists.txt
	CMAKE_INSTALL_PREFIX=$(CMAKE_INSTALL_PREFIX) scripts/build.sh

pico: mbedtls_config.h
	CMAKE_INSTALL_PREFIX=$(CMAKE_INSTALL_PREFIX) scripts/build-pico.sh

mbedtls_config.h mbedtls_crypto_config.h: scripts/configure_mbedtls.sh
	scripts/configure_mbedtls.sh $(TARGET)

install: build/
	CMAKE_INSTALL_PREFIX=$(CMAKE_INSTALL_PREFIX) scripts/install.sh

clean:
	rm -rf build/ mbedtls_config.h mbedtls_crypto_config.h

.PHONY: all pico install clean
