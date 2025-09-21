#pragma once

#include "pico/stdlib.h"

#define TCP_BUF_SIZE 512

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
  tcp_ctx_t       tcp;
} device_ctx_t;

int
init_device(device_ctx_t**);

void
tcp_work(device_ctx_t*);
