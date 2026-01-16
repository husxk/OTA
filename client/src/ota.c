#include <string.h>
#include <stdarg.h>
#include <stddef.h>

#include "ota.h"
#include "device.h"
#include "tcp.h"
#include "debug.h"
#include "signing_key.h"

#include "pico/stdlib.h"
#include "pico/rand.h"
#include "hardware/flash.h"
#include "lwip/pbuf.h"
#include "hardware/sync.h"
#include "hardware/watchdog.h"
#include "pico/bootrom.h"
#include "hardware/ticks.h"
#include "hardware/structs/psm.h"

// Entropy callback for TLS
// (same as pico_mbedtls)
int entropy_callback(void* ctx, unsigned char* output, size_t len)
{
    (void) ctx;

    size_t written = 0;
    while (written < len)
    {
        uint64_t rand_data = get_rand_64();
        size_t to_copy = (len - written < sizeof(rand_data)) ?
                         (len - written) : sizeof(rand_data);

        memcpy(output + written, &rand_data, to_copy);
        written += to_copy;
    }

    return 0;
}

static void transfer_send(void* user_ctx, const uint8_t* data, size_t size)
{
    device_ctx_t* ctx = (device_ctx_t*)user_ctx;
    tcp_send_data(ctx, (const char*)data, size);
}

static size_t transfer_receive(void* user_ctx, uint8_t* buffer, size_t max_size)
{
    device_ctx_t* ctx = (device_ctx_t*)user_ctx;

    if (!ctx || !buffer || max_size == 0)
        return 0;

    size_t total_copied = 0;

    // TODO: Simplify this loop
    while (total_copied < max_size)
    {
        // If no current node, take from queue head
        if (!ctx->tcp.current_node)
        {
            // No more data
            if (!ctx->tcp.pbuf_queue_head)
                break;

            ctx->tcp.current_node = ctx->tcp.pbuf_queue_head;
            ctx->tcp.pbuf_queue_head = ctx->tcp.pbuf_queue_head->next;

            if (!ctx->tcp.pbuf_queue_head)
                ctx->tcp.pbuf_queue_tail = NULL;

            ctx->tcp.current_offset = 0;
        }

        // Process current node
        struct pbuf* p = ctx->tcp.current_node->p;
        size_t remaining = p->tot_len - ctx->tcp.current_offset;
        size_t to_copy = (remaining < (max_size - total_copied)) ?
                         remaining : (max_size - total_copied);

        // Copy from current pbuf at current offset
        pbuf_copy_partial(p, buffer + total_copied, to_copy, ctx->tcp.current_offset);
        ctx->tcp.current_offset += to_copy;
        total_copied += to_copy;

        // If current node is finished, free it and move to next
        if (ctx->tcp.current_offset >= p->tot_len)
        {
            pbuf_free(p);
            pbuf_queue_node_t* node = ctx->tcp.current_node;
            ctx->tcp.current_node = node->next;
            free(node);
            ctx->tcp.current_offset = 0;
        }
    }

    return total_copied;
}

static void transfer_error(void* user_ctx, const char* error_msg)
{
    DEBUG("OTA: transfer error: %s\n", error_msg);
}

static void transfer_done(void* user_ctx, uint32_t total_bytes)
{
    device_ctx_t* ctx = (device_ctx_t*)user_ctx;
    DEBUG("OTA: transfer complete\n");

    // Schedule firmware update shortly after transfer completes
    ctx->update_pending = true;
    ctx->update_timeout = make_timeout_time_ms(5000);
}

static void debug_log(void* user_ctx, const char* format, va_list args)
{
    vprintf(format, args);
}

static void OTA_RAM_FUNCTION(firmware_reboot)(void)
{
  // Reset everything apart from ROSC and XOSC
   psm_hw->wdsel = PSM_WDSEL_BITS &
               ~(PSM_WDSEL_ROSC_BITS | PSM_WDSEL_XOSC_BITS);

  // Set up watchdog to reset the device
  watchdog_hw->ctrl = WATCHDOG_CTRL_TRIGGER_BITS;

  // wait for watchdog to power cycle
  while (true)
  {
  }
}

static void OTA_RAM_FUNCTION(firmware_read)(void* user_ctx,
                                            uint32_t current_addr,
                                            const uint8_t** data,
                                            size_t* size)
{
  // Copy data from OTA storage to buffer using RAM-resident memcpy
  static uint8_t page_buffer[FLASH_PAGE_SIZE];
  OTA_memcpy_ram(page_buffer, (uint8_t*)current_addr, FLASH_PAGE_SIZE);

  *data = page_buffer;
  *size = FLASH_PAGE_SIZE;
}

static void OTA_RAM_FUNCTION(firmware_prepare)(void* user_ctx)
{
  device_ctx_t* ctx = (device_ctx_t*)user_ctx;

  // Reset sector tracking for new firmware write
  ctx->last_erased_sector = 0;

  // At this point we do not care about saving interrupts.
  // After this is executed, memory will be overwritten.
  save_and_disable_interrupts();
}

static void OTA_RAM_FUNCTION(firmware_write)(void* user_ctx,
                                             uint32_t flash_addr,
                                             const uint8_t* data,
                                             size_t size)
{
  device_ctx_t* ctx = (device_ctx_t*)user_ctx;

  // Round down flash_addr to sector boundary:
  // clear lower bits to get sector start address
  const uint32_t current_sector = flash_addr & ~(FLASH_SECTOR_SIZE - 1);

  if (current_sector != ctx->last_erased_sector)
  {
    flash_range_erase(current_sector - XIP_BASE, FLASH_SECTOR_SIZE);
    ctx->last_erased_sector = current_sector;
  }

  flash_range_program(flash_addr - XIP_BASE, data, size);
}

static bool transfer_store(void* user_ctx, const uint8_t* data, size_t size)
{
  device_ctx_t* ctx = (device_ctx_t*)user_ctx;

  // Check if we would overflow the OTA storage
  if (ctx->ota.ota_addr + size > OTA_STORAGE_END)
  {
    DEBUG("OTA: Would overflow OTA storage (offset: %u, size: %zu, max: %u)\n",
          ctx->ota.ota_addr, size, OTA_STORAGE_SIZE);
    return false;
  }

  // Check if we need to erase a new sector (4096 bytes)
  if ((ctx->ota.ota_addr % FLASH_SECTOR_SIZE) == 0)
  {
    DEBUG("OTA: Erasing flash sector at 0x%08X\n", ctx->ota.ota_addr);

    const uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(ctx->ota.ota_addr - XIP_BASE, FLASH_SECTOR_SIZE);
    restore_interrupts(ints);
  }

  // Write data to flash (must be 256-byte aligned and multiple of 256 bytes)
  DEBUG("OTA: Writing %zu bytes to flash at 0x%08X (page: %u)\n",
        size, ctx->ota.ota_addr, ctx->ota.current_page);

  const uint32_t ints = save_and_disable_interrupts();
  flash_range_program(ctx->ota.ota_addr - XIP_BASE, data, size);
  restore_interrupts(ints);

  // Update offsets
  ctx->ota.ota_addr += size;
  ctx->ota.current_page++;

  DEBUG("OTA: Written packet, address: 0x%08X, page: %u\n",
        ctx->ota.ota_addr,
        ctx->ota.current_page);

  return true;
}

static void transfer_reset(void* user_ctx)
{
    device_ctx_t* ctx = (device_ctx_t*)user_ctx;

    ctx->ota.ota_addr = OTA_STORAGE_START;
    ctx->ota.current_page = 0;
}

OTA_client_ctx* init_ota(void)
{
    OTA_client_ctx* ctx;

    // Create builder
    OTA_client_builder_t* builder = OTA_client_builder_create();
    if (!builder)
    {
        return NULL;
    }

    // Set common transfer callbacks
    OTA_client_builder_set_transfer_send_cb(builder, transfer_send);
    OTA_client_builder_set_transfer_receive_cb(builder, transfer_receive);
    OTA_client_builder_set_transfer_error_cb(builder, transfer_error);
    OTA_client_builder_set_transfer_done_cb(builder, transfer_done);
    OTA_client_builder_set_debug_log_cb(builder, debug_log);

    // Set client storage callbacks
    OTA_client_builder_set_transfer_store_cb(builder, transfer_store);
    OTA_client_builder_set_transfer_reset_cb(builder, transfer_reset);

    // Set firmware update callbacks (RAM resident functions)
    OTA_client_builder_set_firmware_reboot_cb(builder, firmware_reboot);
    OTA_client_builder_set_firmware_read_cb(builder, firmware_read);
    OTA_client_builder_set_firmware_prepare_cb(builder, firmware_prepare);
    OTA_client_builder_set_firmware_write_cb(builder, firmware_write);

    // Set entropy callback for TLS
    if (OTA_client_builder_set_entropy_cb(builder, entropy_callback, NULL) != 0)
    {
        DEBUG("OTA: Failed to set entropy callback\n");
        OTA_client_builder_destroy(builder);
        return NULL;
    }

    // Set public key for SHA-512 signature verification
    const char* key_data_str = SIGNING_PUBLIC_KEY_DATA;
    size_t key_data_len = strlen(key_data_str) + 1;  // Include null terminator

    if (OTA_client_builder_set_sha512_public_key(builder,
                                                 (const unsigned char*)key_data_str,
                                                 key_data_len) != 0)
    {
        DEBUG("OTA: Failed to set SHA-512 public key for verification\n");
        OTA_client_builder_destroy(builder);
        return NULL;
    }

    // Enable TLS transport
    if (OTA_client_builder_enable_tls(builder) != 0)
    {
        DEBUG("OTA: Failed to enable TLS transport\n");
        OTA_client_builder_destroy(builder);
        return NULL;
    }

    // Build the context (fully initializes TLS, SHA-512, etc.)
    int error_code;
    ctx = OTA_client_builder_build(builder, &error_code);
    if (!ctx)
    {
        DEBUG("OTA: Failed to build context (error: %d)\n", error_code);
        OTA_client_builder_destroy(builder);
        return NULL;
    }

    // Destroy builder (no longer needed after build)
    OTA_client_builder_destroy(builder);

    return ctx;
}

