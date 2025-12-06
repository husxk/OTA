SIGNING_PRIVATE_KEY := build/signing.key
SIGNING_PUBLIC_KEY  := build/signing.pub

all: $(SIGNING_PRIVATE_KEY) $(SIGNING_PUBLIC_KEY)
	scripts/build.sh

# Generate signing keys in root build directory if they don't exist
$(SIGNING_PRIVATE_KEY) $(SIGNING_PUBLIC_KEY): scripts/generate_signing_keys.sh
	@echo "Generating signing key pair..."
	@scripts/generate_signing_keys.sh

clean:
	scripts/clean.sh

.PHONY: all clean
