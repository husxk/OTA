CMAKE_INSTALL_PREFIX ?= $(PWD)/../build

all: build/

build/: CMakeLists.txt
	CMAKE_INSTALL_PREFIX=$(CMAKE_INSTALL_PREFIX) scripts/build.sh

pico: CMakeLists.txt
	CMAKE_INSTALL_PREFIX=$(CMAKE_INSTALL_PREFIX) scripts/build-pico.sh

install: build/
	CMAKE_INSTALL_PREFIX=$(CMAKE_INSTALL_PREFIX) scripts/install.sh

clean:
	rm -rf build/

.PHONY: all pico install clean