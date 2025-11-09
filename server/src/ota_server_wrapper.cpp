#include "ota_server_wrapper.h"
#include "libota/ota_server.h"
#include "libota/protocol.h"
#include <cstdio>
#include <cstdarg>
#include <cstring>

static void transfer_send(void* user_ctx, const uint8_t* data, size_t size)
{
    server_context* ctx = static_cast<server_context*>(user_ctx);
    ctx->server->send_data(data, size);
}

static size_t transfer_receive(void* user_ctx, uint8_t* buffer, size_t max_size)
{
    server_context* ctx = static_cast<server_context*>(user_ctx);
    return ctx->server->receive_data(buffer, max_size);
}

static void transfer_error(void* user_ctx, const char* error_msg)
{
    (void) user_ctx;
    printf("OTA Error: %s\n", error_msg);
}

static void transfer_done(void* user_ctx, uint32_t total_bytes)
{
    (void) user_ctx;
    printf("OTA: Transfer completed successfully (%u bytes)\n", total_bytes);
}

static void debug_log(void* user_ctx, const char* format, va_list args)
{
    (void) user_ctx;
    vprintf(format, args);
}

static bool server_get_payload(void* user_ctx,
                               const uint8_t** data,
                               size_t* size)
{
    server_context* ctx = static_cast<server_context*>(user_ctx);

    static uint8_t payload_buffer[OTA_DATA_PAYLOAD_SIZE];

    if (ctx->reader->is_transfer_complete())
    {
        return false; // No more data
    }

    size_t bytes_read = ctx->reader->read_bytes(payload_buffer,
                                                OTA_DATA_PAYLOAD_SIZE);

    if (bytes_read == 0)
    {
        return false; // EOF or error
    }

    // Pad last packet with zeros if needed
    if (bytes_read < OTA_DATA_PAYLOAD_SIZE)
    {
        std::memset(payload_buffer + bytes_read,
                    0,
                    OTA_DATA_PAYLOAD_SIZE - bytes_read);
    }

    *data = payload_buffer;
    *size = OTA_DATA_PAYLOAD_SIZE;

    return true;
}

static void server_transfer_progress(void* user_ctx,
                                     uint32_t bytes_sent,
                                     uint32_t packet_number)
{
    server_context* ctx = static_cast<server_context*>(user_ctx);
    ctx->packet_number = packet_number;

    printf("Sent DATA packet #%u (%u/%zu bytes)\n",
           packet_number,
           bytes_sent,
           ctx->reader->get_file_size());

    ctx->reader->add_bytes_sent(OTA_DATA_PAYLOAD_SIZE);
}

int init_ota_server(OTA_server_ctx* ctx)
{
    if (!ctx)
    {
        return -1;
    }

    std::memset(ctx, 0, sizeof(*ctx));

    // Set common transfer callbacks
    ctx->common.callbacks.transfer_send_cb    = transfer_send;
    ctx->common.callbacks.transfer_receive_cb = transfer_receive;
    ctx->common.callbacks.transfer_error_cb   = transfer_error;
    ctx->common.callbacks.transfer_done_cb    = transfer_done;
    ctx->common.callbacks.debug_log_cb        = debug_log;

    // Set server-specific callbacks
    ctx->server_get_payload_cb       = server_get_payload;
    ctx->server_transfer_progress_cb = server_transfer_progress;

    return 0;
}
