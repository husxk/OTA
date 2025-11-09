#include "tcp_server.h"
#include "file_reader.h"
#include "ota_server_wrapper.h"
#include "libota/ota_server.h"

#include <cstdio>
#include <cstdint>

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

    // Initialize OTA server context
    OTA_server_ctx ota_ctx;

    server_context server_ctx;
    server_ctx.server = &server;
    server_ctx.reader = &reader;
    server_ctx.packet_number = 0;

    if (init_ota_server(&ota_ctx) != 0)
    {
        printf("Failed to initialize OTA server\n");
        server.stop_server();
        return 1;
    }

    // Run OTA transfer using libota
    bool transfer_success = OTA_server_run_transfer(&ota_ctx, &server_ctx);

    if (!transfer_success)
    {
        printf("File transfer failed (%zu/%zu bytes sent)\n",
               reader.get_bytes_sent(), reader.get_file_size());
        rc = 1;
    }
    else
    {
        printf("File transfer completed successfully!\n");
    }

    server.stop_server();
    printf("OTA server stopped\n");

    return rc;
}
