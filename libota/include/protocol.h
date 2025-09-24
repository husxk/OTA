#pragma once

/* common packet */
#define OTA_COMMON_PACKET_LENGTH_POS    0x0
#define OTA_COMMON_PACKET_TYPE_POS      0x2

#define OTA_COMMON_PACKET_LENGTH_SIZE   0x2
#define OTA_COMMON_PACKET_TYPE_SIZE     0x1

#define OTA_COMMON_PACKET_LENGTH        (OTA_COMMON_PACKET_LENGTH_SIZE + \
                                         OTA_COMMON_PACKET_TYPE_SIZE)

/* Invalid packet type */
#define OTA_INVALID_TYPE                0x00

/* ACK packet type */
#define OTA_ACK_TYPE                    0x01
#define OTA_ACK_PACKET_LENGTH           OTA_COMMON_PACKET_LENGTH

/* NACK packet type */
#define OTA_NACK_TYPE                   0x02
#define OTA_NACK_PACKET_LENGTH          OTA_COMMON_PACKET_LENGTH

/* DATA packet type */
#define OTA_DATA_TYPE                   0x03
#define OTA_DATA_PAYLOAD_SIZE           256
#define OTA_DATA_PACKET_LENGTH          (OTA_COMMON_PACKET_LENGTH + OTA_DATA_PAYLOAD_SIZE)

/* FIN packet type */
#define OTA_FIN_TYPE                    0x04
#define OTA_FIN_PACKET_LENGTH           OTA_COMMON_PACKET_LENGTH
