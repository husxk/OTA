#include "ota_common.h"
#include "packet.h"
#include <stdarg.h>

void OTA_debug_log(OTA_common_ctx_t* common_ctx,
                   void* user_ctx,
                   const char* format,
                   ...)
{
    if (!common_ctx ||
        !common_ctx->callbacks.debug_log_cb)
    {
        return;
    }

    va_list args;
    va_start(args, format);

    common_ctx->callbacks.debug_log_cb(user_ctx, format, args);

    va_end(args);
}

bool OTA_send_ack_packet(OTA_common_ctx_t* common_ctx, void* user_ctx)
{
    if (!common_ctx ||
        !common_ctx->callbacks.transfer_send_cb)
    {
        return false;
    }

    uint8_t ack_buffer[OTA_ACK_PACKET_LENGTH];
    size_t ack_size;

    if (!OTA_packet_write_ack(ack_buffer, sizeof(ack_buffer), &ack_size))
    {
        return false;
    }

    common_ctx->callbacks.transfer_send_cb(user_ctx, ack_buffer, ack_size);
    return true;
}

bool OTA_send_nack_packet(OTA_common_ctx_t* common_ctx, void* user_ctx)
{
    if (!common_ctx ||
        !common_ctx->callbacks.transfer_send_cb)
    {
        return false;
    }

    uint8_t nack_buffer[OTA_NACK_PACKET_LENGTH];
    size_t nack_size;

    if (!OTA_packet_write_nack(nack_buffer, sizeof(nack_buffer), &nack_size))
    {
        return false;
    }

    common_ctx->callbacks.transfer_send_cb(user_ctx, nack_buffer, nack_size);
    return true;
}

bool OTA_send_fin_packet(OTA_common_ctx_t* common_ctx, void* user_ctx)
{
    if (!common_ctx ||
        !common_ctx->callbacks.transfer_send_cb)
    {
        return false;
    }

    uint8_t fin_buffer[OTA_FIN_PACKET_LENGTH];
    size_t fin_size;

    if (!OTA_packet_write_fin(fin_buffer, sizeof(fin_buffer), &fin_size))
    {
        return false;
    }

    common_ctx->callbacks.transfer_send_cb(user_ctx, fin_buffer, fin_size);
    OTA_debug_log(common_ctx, user_ctx, "OTA: FIN packet sent\n");

    return true;
}
