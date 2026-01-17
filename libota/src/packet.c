#include "internal/packet.h"
#include "internal/platform.h"

#include <string.h>

size_t ota_packet_write_ack(uint8_t* buffer, size_t size)
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

size_t ota_packet_write_nack(uint8_t* buffer, size_t size)
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

size_t ota_packet_write_fin(uint8_t* buffer,
                            size_t size,
                            const uint8_t* signature,
                            size_t signature_len)
{
    if (!buffer || size < OTA_FIN_PACKET_LENGTH)
    {
        return 0;
    }

    // Signature must be exactly OTA_SHA512_SIGNATURE_LENGTH bytes (protocol requirement)
    if (!signature || signature_len != OTA_SHA512_SIGNATURE_LENGTH)
    {
        return 0;
    }

    uint16_t length = htons(OTA_FIN_PACKET_LENGTH);
    memcpy(&buffer[OTA_COMMON_PACKET_LENGTH_POS], &length, sizeof(length));

    buffer[OTA_COMMON_PACKET_TYPE_POS] = OTA_FIN_TYPE;

    // Copy signature (always OTA_SHA512_SIGNATURE_LENGTH bytes)
    memcpy(&buffer[OTA_FIN_SIGNATURE_POS], signature, OTA_SHA512_SIGNATURE_LENGTH);

    return OTA_FIN_PACKET_LENGTH;
}

uint8_t ota_packet_get_type(const uint8_t* buffer, size_t size)
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

size_t ota_packet_write_data(uint8_t* buffer,
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
        // Protocol violation: data size must match OTA_DATA_PAYLOAD_SIZE
        return 0;
    }

    uint16_t length = htons(OTA_DATA_PACKET_LENGTH);
    memcpy(&buffer[OTA_COMMON_PACKET_LENGTH_POS], &length, sizeof(length));

    buffer[OTA_COMMON_PACKET_TYPE_POS] = OTA_DATA_TYPE;

    memcpy(&buffer[OTA_COMMON_PACKET_LENGTH], data, OTA_DATA_PAYLOAD_SIZE);

    return OTA_DATA_PACKET_LENGTH;
}

const uint8_t* ota_packet_get_data(const uint8_t* buffer, size_t size)
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

const uint8_t* ota_packet_get_fin_signature(const uint8_t* buffer,
                                            size_t size,
                                            size_t* signature_len)
{
    if (!buffer || size < OTA_FIN_PACKET_LENGTH || !signature_len)
    {
        if (signature_len)
            *signature_len = 0;
        return NULL;
    }

    uint16_t length;
    memcpy(&length, &buffer[OTA_COMMON_PACKET_LENGTH_POS], sizeof(length));
    length = ntohs(length);

    if (buffer[OTA_COMMON_PACKET_TYPE_POS] != OTA_FIN_TYPE ||
        length != OTA_FIN_PACKET_LENGTH)
    {
        *signature_len = 0;
        return NULL;
    }

    // Return signature area (always OTA_SHA512_SIGNATURE_LENGTH bytes)
    *signature_len = OTA_SHA512_SIGNATURE_LENGTH;
    return &buffer[OTA_FIN_SIGNATURE_POS];
}
