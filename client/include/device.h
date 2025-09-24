#pragma once

#include "pico/stdlib.h"
#include "libota/protocol.h"

#define TCP_BUF_SIZE 512

// OTA flash storage symbols from linker script
extern char __ota_storage_start__[];

#define OTA_STORAGE_START ((uint32_t)__ota_storage_start__)
#define OTA_STORAGE_SIZE  (OTA_STORAGE_SIZE_BYTES)  // Defined by CMake
#define OTA_STORAGE_END   (OTA_STORAGE_START + OTA_STORAGE_SIZE)

typedef struct
{
  struct tcp_pcb* client_pcb;
  uint8_t         recv_buffer[TCP_BUF_SIZE];
  uint16_t        recv_len;
  bool            connected;
  absolute_time_t last_reconnect_attempt;
} tcp_ctx_t;

typedef struct
{
  uint32_t  ota_addr;     // Current offset in OTA storage
  uint32_t  current_page;   // Current page number being written to
} ota_t;

typedef struct
{
  tcp_ctx_t tcp;
  ota_t ota;
} device_ctx_t;

int
init_device(device_ctx_t**);

void
tcp_work(device_ctx_t*);

bool
ota_write_packet_to_flash(device_ctx_t* ctx, const uint8_t* data, size_t size);

void
ota_reset_flash_offset(device_ctx_t* ctx);
