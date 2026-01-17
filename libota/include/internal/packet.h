#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "libota/protocol.h"
#include "internal/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

// OTA packet functions for creating and parsing binary protocol packets
// All functions use network byte order (big-endian) for multi-byte fields
// Functions return 0 on failure, or number of bytes written/parsed on success

size_t OTA_packet_write_ack(uint8_t* buffer, size_t size);

size_t OTA_packet_write_nack(uint8_t* buffer, size_t size);

size_t OTA_packet_write_fin(uint8_t* buffer,
                            size_t size,
                            const uint8_t* signature,
                            size_t signature_len);

size_t OTA_packet_write_data(uint8_t* buffer, size_t size, const uint8_t* data, size_t data_size);

uint8_t OTA_packet_get_type(const uint8_t* buffer, size_t size);

const uint8_t* OTA_packet_get_data(const uint8_t* buffer, size_t size);

const uint8_t* OTA_packet_get_fin_signature(const uint8_t* buffer,
                                            size_t size,
                                            size_t* signature_len);

#ifdef __cplusplus
}
#endif
