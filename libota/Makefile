all: build/

build/: CMakeLists.txt
	scripts/build.sh

install: build/
	scripts/install.sh

clean:
	rm -rf build/

.PHONY: all install clean