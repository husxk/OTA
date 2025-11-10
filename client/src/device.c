#include <stdlib.h>
#include <string.h>

#include "device.h"
#include "tcp.h"
#include "debug.h"
#include "ota.h"
#include "libota/ota_client.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include "pico/cyw43_arch.h"
#include "hardware/watchdog.h"
#include "hardware/flash.h"
#include "hardware/sync.h"


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

  if (init_ota(&(*ctx)->ota_ctx) != 0)
  {
    DEBUG("OTA: Failed to initialize OTA callbacks\n");
    free(*ctx);
    return -1;
  }

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
    OTA_client_setup_memory(&ctx->ota_ctx, OTA_STORAGE_START,
                            ctx->ota.ota_addr, XIP_BASE);

    // Call the library function to perform the actual flash update
    // If returns true, it will reboot the device and never return
    // If returns false, we will print an error message and return,
    //    update will not be performed
    if (!OTA_client_write_firmware(&ctx->ota_ctx, ctx))
    {
      DEBUG("OTA: ERROR! Flash update failed.\n"
            "OTA library configuration is invalid or callbacks are not set up\n");
      return false;
    }

    return true;
  }

  return false;
}

