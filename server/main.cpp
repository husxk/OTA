#include "ota_server_wrapper.h"
#include <cstdio>

static void print_usage(const char* program_name)
{
    printf("Usage: %s <file_path> <cert_path> <tls_key_path> <signing_key_path>\n",
           program_name);
    printf("  file_path:        Path to the binary file to send via OTA\n");
    printf("  cert_path:        Path to the certificate file (PEM format)\n");
    printf("  tls_key_path:     Path to the TLS private key file (PEM format)\n");
    printf("  signing_key_path: Path to the image signing private key file (PEM format)\n");
    printf("\nExample:\n");
    printf("  %s firmware.bin server.crt server.key signing.key\n", program_name);
}

int main(int argc, char* argv[])
{
    if (argc != 5)
    {
        print_usage(argv[0]);
        return 1;
    }

    const char* file_path        = argv[1];
    const char* cert_path        = argv[2];
    const char* tls_key_path     = argv[3];
    const char* signing_key_path = argv[4];

    server_context server_ctx;

    if (!server_ctx.load_file(file_path))
    {
        printf("Error: Cannot open file '%s'\n", file_path);
        return 1;
    }

    if (!server_ctx.load_pki(cert_path, tls_key_path))
    {
        printf("Error: Failed to load PKI data\n");
        return 1;
    }

    if (!server_ctx.load_signing_key(signing_key_path))
    {
        printf("Error: Failed to load signing key\n");
        return 1;
    }

    if (!server_ctx.init())
    {
        printf("Error: Failed to initialize OTA server\n");
        return 1;
    }

    if (!server_ctx.run(8080))
    {
        return 1;
    }

    return 0;
}
