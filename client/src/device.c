#include <stdlib.h>
#include <string.h>

#include "device.h"
#include "tcp.h"
#include "debug.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include "pico/cyw43_arch.h"

int
init_device(device_ctx_t** ctx)
{
  *ctx = malloc(sizeof(device_ctx_t));

  if(*ctx == NULL)
  {
    return -1;
  }

  memset(*ctx, 0, sizeof(device_ctx_t));

  if (tcp_init_client(*ctx) != 0)
  {
    free(*ctx);
    return -1;
  }

  return 0;
}

