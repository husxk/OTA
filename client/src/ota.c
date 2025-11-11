#include <string.h>
#include <stdarg.h>

#include "ota.h"
#include "device.h"
#include "tcp.h"
#include "debug.h"

#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "hardware/watchdog.h"
#include "pico/bootrom.h"
#include "hardware/ticks.h"
#include "hardware/structs/psm.h"

static void transfer_send(void* user_ctx, const uint8_t* data, size_t size)
{
    device_ctx_t* ctx = (device_ctx_t*)user_ctx;
    tcp_send_data(ctx, (const char*)data, size);
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

int init_ota(OTA_client_ctx* ctx)
{
    if (!ctx)
        return -1;

    memset(ctx, 0, sizeof(*ctx));

    // Set common transfer callbacks
    ctx->common.callbacks.transfer_send_cb    = transfer_send;
    ctx->common.callbacks.transfer_receive_cb = NULL; // unused on client
    ctx->common.callbacks.transfer_error_cb   = transfer_error;
    ctx->common.callbacks.transfer_done_cb    = transfer_done;
    ctx->common.callbacks.debug_log_cb        = debug_log;

    // Set client storage callbacks
    ctx->transfer_store_cb = transfer_store;
    ctx->transfer_reset_cb  = transfer_reset;

    // Set firmware update callbacks (RAM resident functions)
    ctx->firmware_reboot_cb  = firmware_reboot;
    ctx->firmware_read_cb    = firmware_read;
    ctx->firmware_prepare_cb = firmware_prepare;
    ctx->firmware_write_cb   = firmware_write;

    return 0;
}

