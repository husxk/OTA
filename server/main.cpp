#include "tcp_server.h"
#include <cstdio>
#include <cstring>

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
    printf("Echo server ready. Send data to echo back...\n");
    
    // Echo loop
    uint8_t buffer[1024];
    while (server.has_client())
    {
        size_t bytes_received = server.receive_data(buffer, sizeof(buffer));
        
        if (bytes_received == 0)
        {
            printf("Client disconnected\n");
            break;
        }
        
        // Print received data to stdout
        printf("Received %zu bytes: ", bytes_received);
        for (size_t i = 0; i < bytes_received; i++)
        {
            printf("%c", buffer[i]);
        }
        printf("\n");
        
        // Echo data back to client
        size_t bytes_sent = server.send_data(buffer, bytes_received);
        if (bytes_sent != bytes_received)
        {
            printf("Failed to echo data back\n");
            break;
        }
        
        printf("Echoed %zu bytes back to client\n", bytes_sent);
    }
    
    server.disconnect_client();
    server.stop_server();
    
    printf("Echo server stopped\n");
    return 0;
}