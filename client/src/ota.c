#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "ota.h"
#include "debug.h"
#include "device.h"
#include "tcp.h"

#include "pico/cyw43_arch.h"
#include "hardware/watchdog.h"
#include "hardware/flash.h"
#include "hardware/sync.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include "libota/packet.h"
#include "libota/protocol.h"

static void log_data_packet(const uint8_t* payload)
{
  DEBUG("OTA: Received DATA packet (%d bytes):\n", OTA_DATA_PAYLOAD_SIZE);
  MEMDUMP(payload, OTA_DATA_PAYLOAD_SIZE);
}

static void OTA_RAM_FUNCTION(ota_reboot_cb)(void)
{
  watchdog_hw->ctrl = WATCHDOG_CTRL_ENABLE_BITS | WATCHDOG_CTRL_TRIGGER_BITS;
  watchdog_hw->load = 0;

  while (true)
  {
    // Device will reset
  }
}

static void ota_pre_write_cb(void* ctx)
{
  save_and_disable_interrupts();
}

static void OTA_RAM_FUNCTION(ota_get_data_cb)(void* ctx,
                                              uint32_t current_addr,
                                              const uint8_t** data,
                                              size_t* size)
{
  (void)ctx;

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
  static uint32_t last_erased_sector = 0;
  const uint32_t current_sector = flash_addr & ~(FLASH_SECTOR_SIZE - 1);

  if (current_sector != last_erased_sector)
  {
    flash_range_erase(current_sector - XIP_BASE, FLASH_SECTOR_SIZE);
    last_erased_sector = current_sector;
  }

  flash_range_program(flash_addr - XIP_BASE, data, size);
}

static bool transfer_write_data_cb(void* ctx, const uint8_t* data, size_t size)
{
  device_ctx_t* device_ctx = (device_ctx_t*)ctx;
  log_data_packet(data);
  return ota_write_packet_to_flash(device_ctx, data, size);
}

static void transfer_reset_offset_cb(void* ctx)
{
  device_ctx_t* device_ctx = (device_ctx_t*)ctx;
  device_ctx->ota.ota_addr = OTA_STORAGE_START;
  device_ctx->ota.current_page = 0;
  DEBUG("OTA: Reset flash offsets to start\n");
}

static void transfer_send_data_cb(void* ctx, const uint8_t* data, size_t size)
{
  device_ctx_t* device_ctx = (device_ctx_t*)ctx;

  DEBUG("OTA: Transfer send data callback - %zu bytes\n", size);

  if (device_ctx->tcp.client_pcb != NULL)
  {
    err_t err = tcp_write(device_ctx->tcp.client_pcb, data, size, TCP_WRITE_FLAG_COPY);

    if (err == ERR_OK)
    {
      DEBUG("OTA: Sent %zu bytes successfully\n", size);
    }
    else
    {
      DEBUG("OTA: Failed to send %zu bytes\n", size);
    }
  }
}

static void transfer_on_error_cb(void* ctx, const char* error_msg)
{
  DEBUG("OTA: Transfer error: %s\n", error_msg);
}

static void transfer_complete_cb(void* ctx, uint32_t total_bytes)
{
  device_ctx_t* device_ctx = (device_ctx_t*)ctx;

  DEBUG("OTA: Transfer complete - total bytes written to flash: %u\n", total_bytes);

  device_ctx->update_pending = true;
  device_ctx->update_timeout = make_timeout_time_ms(1000);

  DEBUG("OTA: Update scheduled for 1 second from now\n");
}

static void debug_log_cb(void* ctx, const char* format, ...)
{
#ifdef DEBUG_LOGS
  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
#endif
}

int init_ota(ota_config_t* ota_ctx)
{
  if (ota_ctx == NULL)
  {
    DEBUG("OTA: Error - ota_ctx is NULL\n");
    return -1;
  }

  DEBUG("OTA: Initializing OTA callbacks\n");
  memset(ota_ctx, 0, sizeof(ota_config_t));

  ota_ctx->firmware_reboot_cb = ota_reboot_cb;
  ota_ctx->firmware_get_data_cb = ota_get_data_cb;
  ota_ctx->firmware_pre_write_cb = ota_pre_write_cb;
  ota_ctx->firmware_write_flash_cb = ota_write_flash_cb;

  ota_ctx->transfer_write_data_cb = transfer_write_data_cb;
  ota_ctx->transfer_reset_offset_cb = transfer_reset_offset_cb;
  ota_ctx->transfer_send_data_cb = transfer_send_data_cb;
  ota_ctx->transfer_on_error_cb = transfer_on_error_cb;
  ota_ctx->transfer_complete_cb = transfer_complete_cb;

  ota_ctx->debug_log_cb = debug_log_cb;

  DEBUG("OTA: OTA callbacks initialized successfully\n");
  return 0;
}

void setup_ota_memory(ota_config_t* ota_ctx,
                      uint32_t ota_storage_start,
                      uint32_t ota_storage_end,
                      uint32_t flash_start)
{
  DEBUG("OTA: Setting up memory configuration\n");
  DEBUG("OTA: OTA storage start: 0x%08X\n", ota_storage_start);
  DEBUG("OTA: OTA storage end: 0x%08X\n", ota_storage_end);
  DEBUG("OTA: Flash start: 0x%08X\n", flash_start);

  OTA_setup_memory(ota_ctx, ota_storage_start, ota_storage_end, flash_start);
}
