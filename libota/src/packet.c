#include "packet.h"
#include "platform.h"
#include "ota_client.h"

#include <string.h>

size_t OTA_packet_write_ack(uint8_t* buffer, size_t size)
{
    if (!buffer || size < OTA_ACK_PACKET_LENGTH)
    {
        return 0;
    }

    uint16_t length = htons(OTA_ACK_PACKET_LENGTH);
    memcpy(&buffer[OTA_COMMON_PACKET_LENGTH_POS], &length, sizeof(length));

    buffer[OTA_COMMON_PACKET_TYPE_POS] = OTA_ACK_TYPE;

    return OTA_ACK_PACKET_LENGTH;
}

size_t OTA_packet_write_nack(uint8_t* buffer, size_t size)
{
    if (!buffer || size < OTA_NACK_PACKET_LENGTH)
    {
        return 0;
    }

    uint16_t length = htons(OTA_NACK_PACKET_LENGTH);
    memcpy(&buffer[OTA_COMMON_PACKET_LENGTH_POS], &length, sizeof(length));

    buffer[OTA_COMMON_PACKET_TYPE_POS] = OTA_NACK_TYPE;

    return OTA_NACK_PACKET_LENGTH;
}

size_t OTA_packet_write_fin(uint8_t* buffer, size_t size)
{
    if (!buffer || size < OTA_FIN_PACKET_LENGTH)
    {
        return 0;
    }

    uint16_t length = htons(OTA_FIN_PACKET_LENGTH);
    memcpy(&buffer[OTA_COMMON_PACKET_LENGTH_POS], &length, sizeof(length));

    buffer[OTA_COMMON_PACKET_TYPE_POS] = OTA_FIN_TYPE;

    return OTA_FIN_PACKET_LENGTH;
}

uint8_t OTA_packet_get_type(const uint8_t* buffer, size_t size)
{
    if (!buffer || size < OTA_COMMON_PACKET_LENGTH)
    {
        return OTA_INVALID_TYPE;
    }

    uint16_t length;
    memcpy(&length, &buffer[OTA_COMMON_PACKET_LENGTH_POS], sizeof(length));
    length = ntohs(length);

    if (length != size)
    {
        return OTA_INVALID_TYPE;
    }

    uint8_t type = buffer[OTA_COMMON_PACKET_TYPE_POS];

    switch (type)
    {
        case OTA_ACK_TYPE:
            if (length != OTA_ACK_PACKET_LENGTH)
                return OTA_INVALID_TYPE;
            return type;

        case OTA_NACK_TYPE:
            if (length != OTA_NACK_PACKET_LENGTH)
                return OTA_INVALID_TYPE;
            return type;

        case OTA_DATA_TYPE:
            if (length != OTA_DATA_PACKET_LENGTH)
                return OTA_INVALID_TYPE;
            return type;

        case OTA_FIN_TYPE:
            if (length != OTA_FIN_PACKET_LENGTH)
                return OTA_INVALID_TYPE;
            return type;

        default:
            return OTA_INVALID_TYPE;
    }
}

size_t OTA_packet_write_data(uint8_t* buffer,
                              size_t size,
                              const uint8_t* data,
                              size_t data_size)
{
    if (!buffer || !data || size < OTA_DATA_PACKET_LENGTH)
    {
        return 0;
    }

    if (data_size != OTA_DATA_PAYLOAD_SIZE)
    {
        printf("ERROR: data_size (%zu) != OTA_DATA_PAYLOAD_SIZE (%d) - aborting as protocol guarantees are broken\n",
               data_size, OTA_DATA_PAYLOAD_SIZE);
        abort();
    }

    uint16_t length = htons(OTA_DATA_PACKET_LENGTH);
    memcpy(&buffer[OTA_COMMON_PACKET_LENGTH_POS], &length, sizeof(length));

    buffer[OTA_COMMON_PACKET_TYPE_POS] = OTA_DATA_TYPE;

    memcpy(&buffer[OTA_COMMON_PACKET_LENGTH], data, OTA_DATA_PAYLOAD_SIZE);

    return OTA_DATA_PACKET_LENGTH;
}

const uint8_t* OTA_packet_get_data(const uint8_t* buffer, size_t size)
{
    if (!buffer || size < OTA_DATA_PACKET_LENGTH)
    {
        return NULL;
    }

    uint16_t length;
    memcpy(&length, &buffer[OTA_COMMON_PACKET_LENGTH_POS], sizeof(length));
    length = ntohs(length);

    if (buffer[OTA_COMMON_PACKET_TYPE_POS] != OTA_DATA_TYPE ||
        length != OTA_DATA_PACKET_LENGTH)
    {
        return NULL;
    }

    return &buffer[OTA_COMMON_PACKET_LENGTH];
}

static void send_ack_packet_client(OTA_client_ctx* ctx, void* user_ctx)
{
    uint8_t ack_buffer[OTA_ACK_PACKET_LENGTH];
    size_t ack_size = OTA_packet_write_ack(ack_buffer, sizeof(ack_buffer));
    if (ack_size > 0)
    {
        ctx->transfer_send_cb(user_ctx, ack_buffer, ack_size);
    }
}

static void send_nack_packet_client(OTA_client_ctx* ctx, void* user_ctx)
{
    uint8_t nack_buffer[OTA_NACK_PACKET_LENGTH];
    size_t nack_size = OTA_packet_write_nack(nack_buffer, sizeof(nack_buffer));
    if (nack_size > 0)
    {
        ctx->transfer_send_cb(user_ctx, nack_buffer, nack_size);
    }
}

bool OTA_client_handle_data_packet(OTA_client_ctx* ctx,
                                    void* user_ctx,
                                    const uint8_t* buffer,
                                    size_t size)
{
    if (!ctx ||
        !ctx->transfer_store_cb ||
        !ctx->transfer_reset_cb ||
        !ctx->transfer_send_cb  ||
        !ctx->transfer_error_cb)
    {
        return false;
    }

    // Validate the packet
    const uint8_t* payload = OTA_packet_get_data(buffer, size);
    if (payload == NULL)
    {
        ctx->transfer_error_cb(user_ctx, "Invalid packet format");
        ctx->transfer_reset_cb(user_ctx);
        send_nack_packet_client(ctx, user_ctx);
        return false;
    }

    // Write data to storage
    if (!ctx->transfer_store_cb(user_ctx, payload, OTA_DATA_PAYLOAD_SIZE))
    {
        ctx->transfer_error_cb(user_ctx, "Failed to write data to storage");
        ctx->transfer_reset_cb(user_ctx);
        send_nack_packet_client(ctx, user_ctx);
        return false;
    }

    // Success, send ACK
    send_ack_packet_client(ctx, user_ctx);
    return true;
}
