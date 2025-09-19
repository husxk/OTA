#!/bin/sh

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
PURPLE='\033[0;35m'
ZERO='\033[0;0m'

# Find Pico device
DEVICE=$(ls /dev/serial/by-id/usb-Raspberry_Pi_Pico_* 2>/dev/null | head -1)

if [ -z "$DEVICE" ]
then
  echo -e "${RED}Error: No Pico W device found!${ZERO}"
  echo -e "${RED}Make sure the device is connected and in BOOTSEL mode${ZERO}"
  echo -e "${RED}Checked: /dev/serial/by-id/usb-Raspberry_Pi_Pico_*${ZERO}"
  exit 1
fi

echo -e "${GREEN}Found Pico W device: ${PURPLE}$DEVICE${ZERO}"
echo -e "${GREEN}Opening terminal with picocom...${ZERO}"
echo -e "${GREEN}Press Ctrl+A then X to exit${ZERO}"

sudo picocom --echo "$DEVICE"
