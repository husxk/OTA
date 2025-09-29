#include "packet.h"
#include "platform.h"

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

size_t OTA_packet_write_data(uint8_t* buffer, size_t size, const uint8_t* data, size_t data_size)
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
