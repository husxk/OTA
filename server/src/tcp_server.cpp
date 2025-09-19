#include "tcp_server.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>

tcp_server::~tcp_server()
{
    stop_server();
}

bool tcp_server::start_server(uint16_t server_port)
{
    if (running)
    {
        return false;
    }

    if (!create_socket())
    {
        return false;
    }

    if (!bind_socket(server_port))
    {
        close_socket();
        return false;
    }

    if (!listen_for_connections())
    {
        close_socket();
        return false;
    }

    port = server_port;
    running = true;
    return true;
}

void tcp_server::stop_server()
{
    if (client_connected)
    {
        disconnect_client();
    }

    if (running)
    {
        close_socket();
        running = false;
        port = 0;
    }
}

bool tcp_server::is_running() const
{
    return running;
}

bool tcp_server::accept_client()
{
    if (!running || client_connected)
    {
        return false;
    }

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
    if (client_socket < 0)
    {
        handle_fatal_error("accept");
    }

    client_ip = inet_ntoa(client_addr.sin_addr);
    client_connected = true;
    return true;
}

void tcp_server::disconnect_client()
{
    if (client_connected)
    {
        close(client_socket);
        client_socket = -1;
        client_connected = false;
        client_ip.clear();
    }
}

bool tcp_server::has_client() const
{
    return client_connected;
}

size_t tcp_server::send_data(const uint8_t* data, size_t size)
{
    if (!client_connected || !data)
    {
        return 0;
    }

    ssize_t bytes_sent = send(client_socket, data, size, 0);
    if (bytes_sent < 0)
    {
        handle_fatal_error("send");
    }

    return static_cast<size_t>(bytes_sent);
}

size_t tcp_server::receive_data(uint8_t* buffer, size_t max_size)
{
    if (!client_connected || !buffer)
    {
        return 0;
    }

    ssize_t bytes_received = recv(client_socket, buffer, max_size, 0);
    if (bytes_received < 0)
    {
        handle_fatal_error("recv");
    }

    return static_cast<size_t>(bytes_received);
}

uint16_t tcp_server::get_port() const
{
    return port;
}

std::string tcp_server::get_client_ip() const
{
    return client_ip;
}

bool tcp_server::create_socket()
{
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        handle_fatal_error("socket");
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        handle_fatal_error("setsockopt");
    }

    return true;
}

bool tcp_server::bind_socket(uint16_t server_port)
{
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(server_port);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        handle_fatal_error("bind");
    }

    return true;
}

bool tcp_server::listen_for_connections()
{
    if (listen(server_socket, 1) < 0)
    {
        handle_fatal_error("listen");
    }

    return true;
}

void tcp_server::close_socket()
{
    if (server_socket >= 0)
    {
        close(server_socket);
        server_socket = -1;
    }
}

void tcp_server::handle_fatal_error(const char* operation) const
{
    fprintf(stderr, "Error: tcp_server::%s failed: %s\n", operation, strerror(errno));
    abort();
}
