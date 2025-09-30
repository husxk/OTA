#include <stdlib.h>
#include <string.h>

#include "device.h"
#include "tcp.h"
#include "debug.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include "pico/cyw43_arch.h"
#include "hardware/watchdog.h"
#include "hardware/flash.h"
#include "hardware/sync.h"

static void OTA_RAM_FUNCTION(ota_reboot_cb)(void)
{
  // Set up watchdog to power cycle the device
  watchdog_hw->ctrl = WATCHDOG_CTRL_ENABLE_BITS | WATCHDOG_CTRL_TRIGGER_BITS;
  watchdog_hw->load = 0;

  // wait for watchdog to power cycle
  while (true)
  {
    // Device will reset
  }
}

static void ota_pre_write_cb(void* ctx)
{
  // At this point we do not care about saving interrupts.
  // After this is executed, memory will be overwritten.
  save_and_disable_interrupts();
}

static void OTA_RAM_FUNCTION(ota_get_data_cb)(void* ctx,
                                              uint32_t current_addr,
                                              const uint8_t** data,
                                              size_t* size)
{
  // ctx is not used in this implementation
  (void)ctx;

  // Copy data from OTA storage to buffer using RAM-resident memcpy
  static uint8_t page_buffer[FLASH_PAGE_SIZE];
  OTA_memcpy_ram(page_buffer, (uint8_t*)current_addr, FLASH_PAGE_SIZE);

  *data = page_buffer;
  *size = FLASH_PAGE_SIZE;
}

static void OTA_RAM_FUNCTION(ota_write_flash_cb)(void* ctx,
                                                 uint32_t flash_addr,
                                                 const uint8_t* data,
                                                 size_t size)
{
  // Check if we need to erase a new sector (4096 bytes)
  static uint32_t last_erased_sector = 0;

  // Round down flash_addr to sector boundary:
  // clear lower bits to get sector start address
  const uint32_t current_sector = flash_addr & ~(FLASH_SECTOR_SIZE - 1);

  if (current_sector != last_erased_sector)
  {
    flash_range_erase(current_sector - XIP_BASE, FLASH_SECTOR_SIZE);
    last_erased_sector = current_sector;
  }

  flash_range_program(flash_addr - XIP_BASE, data, size);
}

static void
init_set_ota_ctx(device_ctx_t* ctx)
{
  ctx->ota_ctx.reboot_cb = ota_reboot_cb;
  ctx->ota_ctx.get_data_cb = ota_get_data_cb;
  ctx->ota_ctx.pre_write_cb = ota_pre_write_cb;
  ctx->ota_ctx.write_flash_cb = ota_write_flash_cb;
}

int
init_device(device_ctx_t** ctx)
{
  *ctx = malloc(sizeof(device_ctx_t));

  if(*ctx == NULL)
  {
    return -1;
  }

  memset(*ctx, 0, sizeof(device_ctx_t));

  // Initialize update timeout fields
  (*ctx)->update_pending = false;
  (*ctx)->update_timeout = 0;

  init_set_ota_ctx(*ctx);

  if (tcp_init_client(*ctx) != 0)
  {
    free(*ctx);
    return -1;
  }

  return 0;
}

bool
check_update_timeout(device_ctx_t* ctx)
{
  if (!ctx->update_pending)
  {
    return false;
  }

  absolute_time_t now = get_absolute_time();
  if (now >= ctx->update_timeout)
  {
    DEBUG("OTA: Update timeout reached, performing firmware update\n");

    // Clear the pending flag
    ctx->update_pending = false;

    // Perform the firmware update
    DEBUG("OTA: Starting flash update\n");
    DEBUG("OTA: OTA storage start: 0x%08X\n", OTA_STORAGE_START);
    DEBUG("OTA: OTA storage end: 0x%08X\n", ctx->ota.ota_addr);
    DEBUG("OTA: Flash start: 0x%08X\n", XIP_BASE);

    // Set up memory pointers for OTA update
    OTA_setup_memory(&ctx->ota_ctx, OTA_STORAGE_START, ctx->ota.ota_addr, XIP_BASE);

    // Call the library function to perform the actual flash update
    // If returns true, it will reboot the device and never return
    // If returns false, we will print an error message and return,
    //    update will not be performed
    if (!OTA_write_firmware(&ctx->ota_ctx, ctx))
    {
      DEBUG("OTA: ERROR! Flash update failed."
            "OTA library configuration is invalid or callbacks are not set up\n");
      return false;
    }

    return true;
  }

  return false;
}

