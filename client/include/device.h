#pragma once

#include "pico/stdlib.h"
#include "libota/protocol.h"
#include "ota.h"
#include "dht22.h"

#define TCP_BUF_SIZE 2048

// OTA flash storage symbols from linker script
extern char __ota_storage_start__[];

#define OTA_STORAGE_START ((uint32_t)__ota_storage_start__)
#define OTA_STORAGE_SIZE  (OTA_STORAGE_SIZE_BYTES)  // Defined by CMake
#define OTA_STORAGE_END   (OTA_STORAGE_START + OTA_STORAGE_SIZE)

// Simple pbuf queue node
typedef struct pbuf_queue_node
{
  struct pbuf* p;
  struct pbuf_queue_node* next;
} pbuf_queue_node_t;

typedef struct
{
  struct tcp_pcb* client_pcb;
  pbuf_queue_node_t* pbuf_queue_head;  // Queue of pbufs from lwip
  pbuf_queue_node_t* pbuf_queue_tail;
  pbuf_queue_node_t* current_node;      // Currently being consumed node
  uint16_t current_offset;              // Offset within current_node->p
  bool            connected;
  absolute_time_t last_reconnect_attempt;
  absolute_time_t connection_time;      // Time when TCP connection was established
  bool            handshake_started;    // True if TLS handshake has been initiated
} tcp_ctx_t;

typedef struct
{
  uint32_t  ota_addr;     // Current offset in OTA storage
  uint32_t  current_page; // Current page number being written to
} ota_t;

typedef struct
{
  absolute_time_t timeout;       // Next time to poll sensor
  dht22_data_t    data;          // Last measured values
} dht_ctx_t;

typedef struct
{
  tcp_ctx_t tcp;
  ota_t ota;
  OTA_client_ctx* ota_ctx;
  absolute_time_t update_timeout;  // Time when firmware update should be performed
  bool update_pending;             // True if update is scheduled
  uint32_t last_erased_sector;     // Last erased sector during firmware write
                                   // (for sector tracking)
  dht_ctx_t dht;
} device_ctx_t;

int
init_device(device_ctx_t**);

void
tcp_work(device_ctx_t*);

bool
check_update_timeout(device_ctx_t* ctx);

void
dht_work(device_ctx_t* ctx);
