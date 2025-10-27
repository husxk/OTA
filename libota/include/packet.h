#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "protocol.h"
#include "platform.h"

#ifdef __cplusplus
extern "C" {
#endif


// OTA packet functions for creating and parsing binary protocol packets
// All functions use network byte order (big-endian) for multi-byte fields
// Functions return true on success, false on failure
// For write functions, actual bytes written are returned via 'written' parameter

bool OTA_packet_write_ack(uint8_t* buffer, size_t size, size_t* written);

bool OTA_packet_write_nack(uint8_t* buffer, size_t size, size_t* written);

bool OTA_packet_write_fin(uint8_t* buffer, size_t size, size_t* written);

bool OTA_packet_write_data(uint8_t* buffer, size_t size,
                           const uint8_t* data, size_t data_size, size_t* written);

uint8_t OTA_packet_get_type(const uint8_t* buffer, size_t size);

const uint8_t* OTA_packet_get_data(const uint8_t* buffer, size_t size);


#ifdef __cplusplus
}
#endif
