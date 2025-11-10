#include "ota_server_wrapper.h"
#include <cstdio>

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

    server_context server_ctx;

    if (!server_ctx.load_file(file_path))
    {
        printf("Error: Cannot open file '%s'\n", file_path);
        return 1;
    }

    if (!server_ctx.run(8080))
    {
        return 1;
    }

    return 0;
}
