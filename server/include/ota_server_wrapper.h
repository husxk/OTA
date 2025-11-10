#pragma once

#include "libota/ota_server.h"
#include "tcp_server.h"
#include "file_reader.h"
#include <cstdint>
#include <memory>
#include <string>
#include <cstdarg>

class server_context
{
public:
    server_context();
    ~server_context() = default;

    bool load_file(const std::string& file_path);
    bool run(uint16_t port);

private:
    void init_ota_server(OTA_server_ctx* ctx);

    static void transfer_send(void* user_ctx,
                              const uint8_t* data,
                              size_t size);

    static size_t transfer_receive(void* user_ctx,
                                   uint8_t* buffer,
                                   size_t max_size);

    static void transfer_error(void* user_ctx,
                               const char* error_msg);

    static void transfer_done(void* user_ctx,
                              uint32_t total_bytes);

    static void debug_log(void* user_ctx,
                          const char* format,
                          va_list args);

    static bool server_get_payload(void* user_ctx,
                                   const uint8_t** data,
                                   size_t* size);

    static void server_transfer_progress(void* user_ctx,
                                         uint32_t bytes_sent,
                                         uint32_t packet_number);

    std::unique_ptr<tcp_server> server;
    std::unique_ptr<file_reader> reader;

    uint32_t packet_number;
};
