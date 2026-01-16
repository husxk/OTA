#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>

#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "hardware/gpio.h"

#include "lwip/ip_addr.h"
#include "lwip/netif.h"

#include "device.h"
#include "debug.h"
#include "tcp.h"
#include "ota.h"
#include "libota/ota_client.h"

static void
print_ip_address(void)
{
  struct netif* netif = netif_list;

  while (netif != NULL)
  {
    if (netif_is_up(netif) && netif_is_link_up(netif))
    {
      char ip_str[16];
      ip4addr_ntoa_r(&netif->ip_addr, ip_str, sizeof(ip_str));

      printf("Got IP from DHCP: %s\n", ip_str);
      break;
    }
    netif = netif->next;
  }
}

static void
init_leds(void)
{
  // Initialize GPIO pins for LEDs
  gpio_init(13);
  gpio_init(15);

  gpio_set_dir(13, GPIO_OUT);
  gpio_set_dir(15, GPIO_OUT);

//  gpio_put(13, 1);
  gpio_put(15, 1);
}

static int
workloop(device_ctx_t* ctx)
{
  cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);

  while(true)
  {
    tcp_work(ctx);

    dht_work(ctx);

    // Check if firmware update timeout has been reached
    // On success, the device will reboot, memory will be overwritten
    // and never return.
    // On failure, the device will continue running,
    // and we cant do anything about it - probably a bad configuration.
    check_update_timeout(ctx);

  }
}

static int
main_()
{
  log("Connecting to Wi-Fi...\n");

  if (cyw43_arch_wifi_connect_timeout_ms(
        WIFI_SSID,
        WIFI_PASSWORD,
        CYW43_AUTH_WPA2_AES_PSK,
        30000))
  {
      printf("Failed to connect.\n");
      return 1;
  }
  else
  {
      printf("Connected.\n");
      print_ip_address();
  }

  device_ctx_t* ctx;

  if(init_device(&ctx) != 0)
  {
    log("init_device failed!\n");
    free(ctx);
    return 1;
  }

  init_leds();

  const int ret = workloop(ctx);

  // Destroy OTA context (cleanup + free)
  OTA_client_destroy(ctx->ota_ctx);

  free(ctx);

  cyw43_arch_deinit();

  return ret;
}

int
main(void)
{
  stdio_init_all();

  if (cyw43_arch_init())
  {
    log("Failed to initialise: cyw43_arch_init()\n");
    return 1;
  }

  cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
  cyw43_arch_enable_sta_mode();

  WAIT_FOR_TERMINAL();
  sleep_ms(1500);

  while(true)
  {
    int ret = main_();

    if (ret)
      log("main() failed with %d\n", ret);

    sleep_ms(2000);
  }
}
