#include "ota_server_wrapper.h"
#include "libota/ota_common.h"
#include "libota/ota_server.h"
#include "libota/protocol.h"
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <memory>
#include <vector>
#include <fstream>
#include <cstdlib>

void server_context::transfer_send(void* user_ctx,
                                   const uint8_t* data,
                                   size_t size)
{
    server_context* ctx = static_cast<server_context*>(user_ctx);
    ctx->server->send_data(data, size);
}

size_t server_context::transfer_receive(void* user_ctx,
                                        uint8_t* buffer,
                                        size_t max_size)
{
    server_context* ctx = static_cast<server_context*>(user_ctx);
    return ctx->server->receive_data(buffer, max_size);
}

void server_context::transfer_error(void* user_ctx,
                                    const char* error_msg)
{
    (void) user_ctx;
    printf("OTA Error: %s\n", error_msg);
}

void server_context::transfer_done(void* user_ctx,
                                   uint32_t total_bytes)
{
    (void) user_ctx;
    printf("OTA: Transfer completed successfully (%u bytes)\n", total_bytes);
}

void server_context::debug_log(void* user_ctx,
                               const char* format,
                               va_list args)
{
    (void) user_ctx;
    vprintf(format, args);
}

bool server_context::server_get_payload(void* user_ctx,
                                        const uint8_t** data,
                                        size_t* size)
{
    server_context* ctx = static_cast<server_context*>(user_ctx);

    static uint8_t payload_buffer[OTA_DATA_PAYLOAD_SIZE];

    if (ctx->reader->is_transfer_complete())
    {
        return false; // No more data
    }

    size_t bytes_read = ctx->reader->read_bytes(payload_buffer,
                                                OTA_DATA_PAYLOAD_SIZE);

    if (bytes_read == 0)
    {
        return false; // EOF or error
    }

    // Pad last packet with zeros if needed
    if (bytes_read < OTA_DATA_PAYLOAD_SIZE)
    {
        std::memset(payload_buffer + bytes_read,
                    0,
                    OTA_DATA_PAYLOAD_SIZE - bytes_read);
    }

    *data = payload_buffer;
    *size = OTA_DATA_PAYLOAD_SIZE;

    return true;
}

void server_context::server_transfer_progress(void* user_ctx,
                                              uint32_t bytes_sent,
                                              uint32_t packet_number)
{
    server_context* ctx = static_cast<server_context*>(user_ctx);
    ctx->packet_number = packet_number;

    printf("Sent DATA packet #%u (%u/%zu bytes)\n",
           packet_number,
           bytes_sent,
           ctx->reader->get_file_size());

    ctx->reader->add_bytes_sent(OTA_DATA_PAYLOAD_SIZE);
}

int server_context::entropy_callback(void* ctx, unsigned char* output, size_t len)
{
    server_context* server_ctx = static_cast<server_context*>(ctx);

    if (!server_ctx ||
        !server_ctx->urandom_file.valid())
    {
        return -1;
    }

    size_t bytes_read = server_ctx->urandom_file.read(output, len);

    if (bytes_read != len)
    {
        return -1;
    }

    return 0;
}

server_context::server_context()
    : server(std::make_unique<tcp_server>())
    , reader(std::make_unique<file_reader>())
    , packet_number(0)
{
    // Open /dev/urandom for entropy generation
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom)
    {
        urandom_file.set(urandom);
    }
}

bool server_context::load_file(const std::string& file_path)
{
    return reader->load_file(file_path);
}

bool server_context::load_pki(const std::string& cert_path,
                              const std::string& key_path)
{
    // Read certificate file
    std::ifstream cert_file(cert_path, std::ios::binary);
    if (!cert_file.is_open())
    {
        printf("Error: Cannot open certificate file '%s'\n",
               cert_path.c_str());

        return false;
    }

    this->cert_data = std::vector<unsigned char>(
        std::istreambuf_iterator<char>(cert_file),
        std::istreambuf_iterator<char>());

    cert_file.close();

    if (this->cert_data.empty())
    {
        printf("Error: Certificate file '%s' is empty\n",
               cert_path.c_str());

        return false;
    }

    // Ensure null terminator for mbedTLS PEM parsing
    if (this->cert_data.back() != '\0')
    {
        cert_data.push_back('\0');
    }

    // Read private key file
    std::ifstream key_file(key_path, std::ios::binary);
    if (!key_file.is_open())
    {
        printf("Error: Cannot open private key file '%s'\n", key_path.c_str());
        this->cert_data.clear();
        return false;
    }

    this->key_data = std::vector<unsigned char>(
        std::istreambuf_iterator<char>(key_file),
        std::istreambuf_iterator<char>());

    key_file.close();

    // Ensure null terminator for mbedTLS PEM parsing
    if (this->key_data.back() != '\0')
    {
        this->key_data.push_back('\0');
    }

    if (this->key_data.empty())
    {
        printf("Error: Private key file '%s' is empty\n", key_path.c_str());
        cert_data.clear();
        return false;
    }

    printf("Loaded certificate (%zu bytes) and private key (%zu bytes)\n",
           this->cert_data.size(), this->key_data.size());

    return true;
}

bool server_context::load_signing_key(const std::string& signing_key_path)
{
    // Read signing key file
    std::ifstream key_file(signing_key_path, std::ios::binary);
    if (!key_file.is_open())
    {
        printf("Error: Cannot open signing key file '%s'\n",
               signing_key_path.c_str());
        return false;
    }

    this->signing_key_data = std::vector<unsigned char>(
        std::istreambuf_iterator<char>(key_file),
        std::istreambuf_iterator<char>());

    key_file.close();

    // Ensure null terminator for mbedTLS PEM parsing
    if (!this->signing_key_data.empty() &&
        this->signing_key_data.back() != '\0')
    {
        this->signing_key_data.push_back('\0');
    }

    if (this->signing_key_data.empty())
    {
        printf("Error: Signing key file '%s' is empty\n",
               signing_key_path.c_str());
        return false;
    }

    printf("Loaded signing key (%zu bytes)\n",
           this->signing_key_data.size());

    return true;
}

bool server_context::init()
{
    // Initialize OTA server context structure
    init_ota_server(&ota_ctx);

    // Enable TLS transport (must be called before OTA_server_init)
    if (OTA_enable_tls(&ota_ctx.common) != 0)
    {
        printf("Error: Failed to enable TLS transport\n");
        return false;
    }

    // Initialize TLS and OTA server (must be called after init_ota_server and TLS is enabled)
    if (OTA_server_init(&ota_ctx) != 0)
    {
        printf("Error: Failed to initialize OTA server\n");
        return false;
    }

    return true;
}

void server_context::init_ota_server(OTA_server_ctx* ctx)
{
    if (!ctx)
    {
        return;
    }

    std::memset(ctx, 0, sizeof(*ctx));

    // Set common transfer callbacks
    ctx->common.callbacks.transfer_send_cb    = transfer_send;
    ctx->common.callbacks.transfer_receive_cb = transfer_receive;
    ctx->common.callbacks.transfer_error_cb   = transfer_error;
    ctx->common.callbacks.transfer_done_cb    = transfer_done;
    ctx->common.callbacks.debug_log_cb        = debug_log;

    // Set entropy callback for TLS
    // Pass 'this' as context so entropy_callback can access urandom_file
    OTA_set_entropy_cb(entropy_callback, this);

    // Validate and set PKI data for TLS
    if (cert_data.empty())
    {
        printf("Error: Certificate data is empty. Call load_pki() before run()\n");
        exit(1);
    }

    if (key_data.empty())
    {
        printf("Error: Private key data is empty. Call load_pki() before run()\n");
        exit(1);
    }

    OTA_set_pki_data(&ctx->common,
                     cert_data.data(),
                     cert_data.size(),
                     key_data.data(),
                     key_data.size());

   // Set private key for SHA-512 signing (separate from TLS key)
    if (signing_key_data.empty())
    {
        printf("Error: Signing key data is empty. "
               "Call load_signing_key() before init()\n");
        exit(1);
    }

    if (OTA_set_sha512_private_key(&ctx->common,
                                    signing_key_data.data(),
                                    signing_key_data.size()) != 0)
    {
        printf("Error: Failed to set SHA-512 private key for signing\n");
        exit(1);
    }

    printf("SHA-512 signing private key loaded successfully\n");

    // Set server-specific callbacks
    ctx->server_get_payload_cb       = server_get_payload;
    ctx->server_transfer_progress_cb = server_transfer_progress;
}

bool server_context::run(uint16_t port)
{
    printf("Starting OTA server on port %u...\n", port);

    if (!this->server->start_server(port))
    {
        printf("Failed to start server\n");
        return false;
    }

    printf("Server started successfully. Waiting for client...\n");

    if (!this->server->accept_client())
    {
        printf("Failed to accept client\n");
        this->server->stop_server();
        return false;
    }

    printf("Client connected from: %s\n",
           this->server->get_client_ip().c_str());

    printf("OTA server ready. Sending file data...\n");

    // Run OTA transfer using libota
    bool transfer_success = OTA_server_run_transfer(&ota_ctx, this);

    // Cleanup OTA server resources
    OTA_server_cleanup(&ota_ctx);

    if (!transfer_success)
    {
        printf("File transfer failed (%zu/%zu bytes sent)\n",
               reader->get_bytes_sent(), reader->get_file_size());
    }
    else
    {
        printf("File transfer completed successfully!\n");
    }

    this->server->stop_server();
    printf("OTA server stopped\n");

    return transfer_success;
}
