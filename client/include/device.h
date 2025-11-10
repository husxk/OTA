#pragma once

#include "pico/stdlib.h"
#include "libota/protocol.h"
#include "ota.h"

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
  uint32_t  current_page; // Current page number being written to
} ota_t;

typedef struct
{
  tcp_ctx_t tcp;
  ota_t ota;
  OTA_client_ctx ota_ctx;
  absolute_time_t update_timeout;  // Time when firmware update should be performed
  bool update_pending;             // True if update is scheduled
  uint32_t last_erased_sector;     // Last erased sector during firmware write
                                   // (for sector tracking)
} device_ctx_t;

int
init_device(device_ctx_t**);

void
tcp_work(device_ctx_t*);

bool
check_update_timeout(device_ctx_t* ctx);
