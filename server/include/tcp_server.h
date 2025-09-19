#pragma once
#include <string>
#include <cstdint>

class tcp_server
{
public:
    tcp_server() = default;
    ~tcp_server();

    bool start_server(uint16_t port);
    void stop_server();
    bool is_running() const;

    bool accept_client();
    void disconnect_client();
    bool has_client() const;

    size_t send_data(const uint8_t* data, size_t size);
    size_t receive_data(uint8_t* buffer, size_t max_size);

    uint16_t get_port() const;
    std::string get_client_ip() const;

private:
    bool create_socket();
    bool bind_socket(uint16_t port);
    bool listen_for_connections();
    void close_socket();

    void handle_fatal_error(const char* operation) const;

    int server_socket = -1;
    int client_socket = -1;

    uint16_t port = 0;
    bool running = false;
    bool client_connected = false;

    std::string client_ip;
};
