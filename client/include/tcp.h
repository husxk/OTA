#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "device.h"

#define TCP_SERVER_PORT     8080
#define TCP_SERVER_IP       "192.168.1.10" 

bool
tcp_is_conn_active(device_ctx_t*);

void
tcp_work(device_ctx_t*);

bool
tcp_send_data(device_ctx_t* ctx, const char* data, size_t len);

bool
tcp_connect_to_server(device_ctx_t* ctx);

int
tcp_init_client(device_ctx_t* ctx);
