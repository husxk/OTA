#include "ota.h"

void OTA_RAM_FUNCTION(OTA_memcpy_ram)(void* dest, const void* src, size_t n)
{
  uint8_t* d = (uint8_t*)dest;
  const uint8_t* s = (const uint8_t*)src;

  for (size_t i = 0; i < n; i++)
  {
      d[i] = s[i];
  }
}

void OTA_setup_memory(ota_config_t* config,
                      uint32_t ota_storage_start,
                      uint32_t ota_storage_end,
                      uint32_t flash_start)
{
    if (!config)
        return;

    config->memory.ota_storage_start = ota_storage_start;
    config->memory.ota_storage_end = ota_storage_end;
    config->memory.flash_start = flash_start;
}

bool OTA_RAM_FUNCTION(OTA_write_firmware)(ota_config_t* config, void* ctx)
{
    if (!config || !config->reboot_cb || !config->get_data_cb ||
        !config->pre_write_cb || !config->write_flash_cb)
    {
        return false;
    }

    config->pre_write_cb(ctx);

    uint32_t flash_addr = config->memory.flash_start;
    uint32_t ota_addr = config->memory.ota_storage_start;

    while (ota_addr < config->memory.ota_storage_end)
    {
        // Get data from user callback
        const uint8_t* data;
        size_t size;

        config->get_data_cb(ctx, ota_addr, &data, &size);

        // Write data to main flash
        config->write_flash_cb(ctx, flash_addr, data, size);

        ota_addr += size;
        flash_addr += size;
    }

    // Reboot the device
    // Never return from this function
    config->reboot_cb();

    // This line will never be reached
    return true;
}
