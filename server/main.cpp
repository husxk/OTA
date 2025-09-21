#include "tcp_server.h"
#include "libota/packet.h"
#include "libota/protocol.h"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <unistd.h>

int main()
{
    tcp_server server;
    
    printf("Starting echo server on port 8080...\n");
    
    if (!server.start_server(8080))
    {
        printf("Failed to start server\n");
        return 1;
    }
    
    printf("Server started successfully. Waiting for client...\n");
    
    // Wait for client connection
    if (!server.accept_client())
    {
        printf("Failed to accept client\n");
        server.stop_server();
        return 1;
    }
    
    printf("Client connected from: %s\n", server.get_client_ip().c_str());
    printf("OTA server ready. Sending DATA packets...\n");

    // OTA packet loop
    uint8_t send_buffer[OTA_DATA_PACKET_LENGTH];
    uint8_t recv_buffer[OTA_COMMON_PACKET_LENGTH];
    uint32_t packet_number = 1;
    
    while (server.has_client())
    {
        // Create DATA packet payload
        char payload[OTA_DATA_PAYLOAD_SIZE];
        snprintf(payload, sizeof(payload), "HELLO FROM SERVER %u", packet_number);
        
        // Send DATA packet
        size_t bytes_written = OTA_packet_write_data(send_buffer, sizeof(send_buffer),
                                                    (const uint8_t*) payload,
                                                     OTA_DATA_PAYLOAD_SIZE);

        if (bytes_written == 0)
        {
            printf("Failed to create DATA packet\n");
            break;
        }
        
        size_t bytes_sent = server.send_data(send_buffer, bytes_written);
        if (bytes_sent != bytes_written)
        {
            printf("Failed to send DATA packet\n");
            break;
        }

        printf("Sent DATA packet #%u: %s\n", packet_number, payload);

        // Wait for ACK/NACK response
        size_t bytes_received = server.receive_data(recv_buffer, sizeof(recv_buffer));
        if (bytes_received == 0)
        {
            printf("Client disconnected\n");
            break;
        }

        // Parse response
        uint8_t packet_type = OTA_packet_get_type(recv_buffer, bytes_received);
        switch (packet_type)
        {
            case OTA_ACK_TYPE:
                printf("Received ACK for packet #%u\n", packet_number);
                break;

            case OTA_NACK_TYPE:
                printf("Received NACK for packet #%u\n", packet_number);
                break;

            case OTA_INVALID_TYPE:
                printf("Received invalid packet for packet #%u\n", packet_number);
                break;

            default:
                printf("Received unknown packet type 0x%02X for packet #%u\n",
                       packet_type, packet_number);
                break;
        }

        packet_number++;

        // Wait 5 seconds between packets
        sleep(5);
    }

    server.disconnect_client();
    server.stop_server();

    printf("Echo server stopped\n");
    return 0;
}
