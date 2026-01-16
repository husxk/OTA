#pragma once

#include "libota/ota_server.h"
#include "libota/ota_server_builder.h"
#include "libota/ota_common.h"
#include "tcp_server.h"
#include "file_reader.h"
#include "file_wrapper.h"
#include <cstdint>
#include <memory>
#include <string>
#include <cstdarg>
#include <vector>

class server_context
{
public:
    server_context();
    ~server_context();

    bool load_file(const std::string& file_path);
    bool load_pki(const std::string& cert_path, const std::string& key_path);
    bool load_signing_key(const std::string& signing_key_path);
    bool init();
    bool run(uint16_t port);

private:
    OTA_server_ctx* init_ota_server(void);

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

    static int entropy_callback(void* ctx, unsigned char* output, size_t len);

    std::unique_ptr<tcp_server> server;
    std::unique_ptr<file_reader> reader;
    file_wrapper urandom_file;

    // PKI data (certificate and private key for TLS)
    std::vector<unsigned char> cert_data;
    std::vector<unsigned char> key_data;

    // Signing key for image verification (separate from TLS key)
    std::vector<unsigned char> signing_key_data;

    // OTA server context (initialized in init())
    OTA_server_ctx* ota_ctx;

    uint32_t packet_number;
};
