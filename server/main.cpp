#include "tcp_server.h"
#include "file_reader.h"
#include "libota/packet.h"
#include "libota/protocol.h"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <unistd.h>

static void print_usage(const char* program_name)
{
    printf("Usage: %s <file_path>\n", program_name);
    printf("  file_path: Path to the binary file to send via OTA\n");
    printf("\nExample:\n");
    printf("  %s firmware.bin\n", program_name);
}

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        print_usage(argv[0]);
        return 1;
    }

    const char* file_path = argv[1];
    int rc = 0;

    file_reader reader;
    if (!reader.load_file(file_path))
    {
        printf("Error: Cannot open file '%s'\n", file_path);
        return 1;
    }

    tcp_server server;
    
    printf("Starting OTA server on port 8080...\n");
    
    if (!server.start_server(8080))
    {
        printf("Failed to start server\n");
        return 1;
    }
    
    printf("Server started successfully. Waiting for client...\n");
    
    if (!server.accept_client())
    {
        printf("Failed to accept client\n");
        server.stop_server();
        return 1;
    }
    
    printf("Client connected from: %s\n", server.get_client_ip().c_str());

    printf("OTA server ready. Sending file data...\n");

    // OTA packet loop
    uint8_t send_buffer[OTA_DATA_PACKET_LENGTH];
    uint8_t recv_buffer[OTA_COMMON_PACKET_LENGTH];
    uint32_t packet_number = 1;

    while (server.has_client() && !reader.is_transfer_complete())
    {
        uint8_t payload[OTA_DATA_PAYLOAD_SIZE];
        size_t bytes_read = reader.read_bytes(payload, OTA_DATA_PAYLOAD_SIZE);

        if (bytes_read == 0)
        {
            printf("Error: Failed to read from file\n");
            break;
        }

        // Pad last packet with zeros if needed
        // OTA protocol requires fixed payload size (256 bytes) for all packets
        // If file doesn't divide evenly, last packet must be padded to
        // maintain protocol consistency
        if (bytes_read < OTA_DATA_PAYLOAD_SIZE)
        {
            memset(payload + bytes_read, 0, OTA_DATA_PAYLOAD_SIZE - bytes_read);
        }

        // Send DATA packet
        size_t bytes_written = OTA_packet_write_data(send_buffer, sizeof(send_buffer),
                                                     payload, OTA_DATA_PAYLOAD_SIZE);

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

        printf("Sent DATA packet #%u (%zu/%zu bytes)\n",
                packet_number,
                reader.get_bytes_sent() + bytes_read,
                reader.get_file_size());

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
                reader.add_bytes_sent(bytes_read);
                break;

            case OTA_NACK_TYPE:
                printf("Received NACK for packet #%u - transfer aborted\n",
                       packet_number);

                printf("Client rejected the data, stopping transfer\n");

                goto transfer_failed;

            case OTA_INVALID_TYPE:
                printf("Received invalid packet for packet #%u - transfer aborted\n",
                        packet_number);

                printf("Protocol error detected, stopping transfer\n");

                goto transfer_failed;

            default:
                printf("Received unknown packet type 0x%02X for packet #%u "
                       "- transfer aborted\n",
                       packet_type, packet_number);

                printf("Unknown protocol message, stopping transfer\n");
                goto transfer_failed;
        }

        packet_number++;
    }

transfer_failed:

    if (reader.is_transfer_complete())
    {
        printf("File transfer completed successfully!\n");
    }
    else
    {
        printf("File transfer failed (%zu/%zu bytes sent)\n", 
               reader.get_bytes_sent(), reader.get_file_size());
        rc = 1;
    }

    server.stop_server();
    printf("OTA server stopped\n");

    return rc;
}
