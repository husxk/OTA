#pragma once

#include "libota/ota_server.h"
#include "tcp_server.h"
#include "file_reader.h"
#include <cstdint>

struct server_context
{
    tcp_server* server;
    file_reader* reader;
    uint32_t packet_number;
};

int init_ota_server(OTA_server_ctx* ctx);
