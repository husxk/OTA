#include "tcp.h"
#include "debug.h"

#include <stdarg.h>

#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/ip_addr.h"

#include "pico/cyw43_arch.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/bootrom.h"
#include "hardware/watchdog.h"
#include "hardware/structs/watchdog.h"

#include "libota/packet.h"
#include "libota/protocol.h"
#include "libota/ota.h"

static err_t
tcp_client_write(struct tcp_pcb* tpcb, const uint8_t *data, uint16_t size)
{
  return tcp_write(tpcb, data, size, TCP_WRITE_FLAG_COPY);
}

static void
log_data_packet(const uint8_t* payload)
{
  DEBUG("TCP: Received DATA packet (%d bytes):\n", OTA_DATA_PAYLOAD_SIZE);
  MEMDUMP(payload, OTA_DATA_PAYLOAD_SIZE);
}

static void
packet_handler(device_ctx_t* ctx, struct tcp_pcb* tpcb)
{
  const int total_len = ctx->tcp.recv_len;
  uint8_t* buffer     = ctx->tcp.recv_buffer;

  if(total_len == 0)
  {
    DEBUG("TCP: Received empty packet\n");
    return;
  }

  // Use libota to handle the data
  OTA_handle_data(&ctx->ota_ctx, ctx, buffer, total_len);

  // Reset buffer for next packet
  ctx->tcp.recv_len = 0;
}

bool
tcp_is_conn_active(device_ctx_t* ctx)
{
  return ctx->tcp.connected &&
         ctx->tcp.client_pcb != NULL &&
         ctx->tcp.client_pcb->state == ESTABLISHED;
}

static err_t
tcp_client_close(device_ctx_t* ctx)
{
  err_t err = ERR_OK;

  if (ctx->tcp.client_pcb != NULL)
  {
    tcp_arg(ctx->tcp.client_pcb, NULL);
    tcp_recv(ctx->tcp.client_pcb, NULL);
    tcp_err(ctx->tcp.client_pcb, NULL);

    err = tcp_close(ctx->tcp.client_pcb);

    if (err != ERR_OK)
    {
      DEBUG("TCP: Close failed: %s (code: %d)\n", lwip_strerr(err), err);
    }

    ctx->tcp.client_pcb = NULL;
  }

  ctx->tcp.connected = false;
  ctx->tcp.recv_len = 0;

  // now + 5 seconds
  ctx->tcp.last_reconnect_attempt = make_timeout_time_ms(5000);

  return err;
}

static void
tcp_client_recv_(device_ctx_t *ctx, struct tcp_pcb* tpcb, struct pbuf* p)
{
  DEBUG("TCP: tcp_client_recv %d\n", p->tot_len);

  if (p->tot_len == 0)
    return;

  /*
   * Receive the buffer
   *
   * TODO: We should probably call pbuf_copy_partial in a loop
   *       to make sure we receive everything.
   */
  const uint16_t buffer_left = TCP_BUF_SIZE - ctx->tcp.recv_len;
  ctx->tcp.recv_len +=
    pbuf_copy_partial(p, &ctx->tcp.recv_buffer[ctx->tcp.recv_len],
                      p->tot_len > buffer_left ? buffer_left : p->tot_len, 0);

  tcp_recved(tpcb, p->tot_len);
}

static err_t
tcp_client_recv(void* ctx_, struct tcp_pcb* tpcb, struct pbuf* p, err_t err)
{
  device_ctx_t *ctx = (device_ctx_t*)ctx_;

  if (!p)
  {
    DEBUG("TCP: Connection closed by server\n");
    ctx->tcp.connected = false;
    tcp_client_close(ctx);

    return err;
  }

  tcp_client_recv_(ctx, tpcb, p);

  //DEBUG("tcp_client_recv:\n");
  //hexdump(ctx->tcp.recv_buffer, ctx->tcp.recv_len);

  pbuf_free(p);

  packet_handler(ctx, tpcb);

  return ERR_OK;
}

static void
tcp_client_err(void* ctx_, err_t err)
{
  device_ctx_t *ctx = (device_ctx_t*)ctx_;

  DEBUG("TCP: Connection error: %s (code: %d)\n", lwip_strerr(err), err);
  ctx->tcp.connected = false;
  tcp_client_close(ctx);
}

static err_t
tcp_client_connected(void* ctx_, struct tcp_pcb* tpcb, err_t err)
{
  device_ctx_t *ctx = (device_ctx_t*)ctx_;

  if (err != ERR_OK)
  {
    DEBUG("TCP: Connection failed: %s (code: %d)\n", lwip_strerr(err), err);
    ctx->tcp.connected = false;
    return err;
  }

  log("TCP: Connected to server\n");
  ctx->tcp.connected = true;

  tcp_arg(tpcb, ctx);
  tcp_recv(tpcb, tcp_client_recv);
  tcp_err(tpcb, tcp_client_err);

  return ERR_OK;
}

bool
tcp_connect_to_server(device_ctx_t* ctx)
{
  DEBUG("TCP: Attempting to reconnect...\n");

  ip_addr_t server_ip;

  if (!ipaddr_aton(TCP_SERVER_IP, &server_ip))
  {
    DEBUG("TCP: Invalid server IP address: %s\n", TCP_SERVER_IP);
    return false;
  }

  log("TCP: Connecting to server %s:%d\n", TCP_SERVER_IP, TCP_SERVER_PORT);

  struct tcp_pcb* pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (!pcb)
  {
    DEBUG("TCP: Failed to create pcb\n");
    return false;
  }

  ctx->tcp.client_pcb = pcb;

  tcp_arg(pcb, ctx);
  tcp_err(pcb, tcp_client_err);

  err_t err = tcp_connect(pcb, &server_ip, TCP_SERVER_PORT, tcp_client_connected);

  if (err != ERR_OK)
  {
    DEBUG("TCP: Failed to connect to server\n");
    tcp_client_close(ctx);

    return false;
  }

  return true;
}

void
tcp_work(device_ctx_t* ctx)
{
  if (ctx->update_pending)
  {
    if (tcp_is_conn_active(ctx))
    {
      tcp_client_close(ctx);
    }

    return;
  }

  cyw43_arch_poll();

  // If disconnected, try to reconnect
  if (!tcp_is_conn_active(ctx))
  {
    absolute_time_t now = get_absolute_time();

    if (now >= ctx->tcp.last_reconnect_attempt)
    {
      if (ctx->tcp.client_pcb != NULL)
      {
        tcp_client_close(ctx);
      }

      tcp_connect_to_server(ctx);

      // now + 5 seconds
      ctx->tcp.last_reconnect_attempt = make_timeout_time_ms(5000);
    }
  }
}

bool
tcp_send_data(device_ctx_t* ctx, const char* data, size_t len)
{
  if (!tcp_is_conn_active(ctx))
  {
    return false;
  }

  err_t err = tcp_client_write(ctx->tcp.client_pcb, (const uint8_t*)data, len);

  return err == ERR_OK;
}

bool
ota_write_packet_to_flash(device_ctx_t* ctx, const uint8_t* data, size_t size)
{
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


int
tcp_init_client(device_ctx_t* ctx)
{
  ctx->tcp.client_pcb = NULL;
  ctx->tcp.recv_len = 0;
  ctx->tcp.connected = false;
  ctx->tcp.last_reconnect_attempt = 0;

  ctx->ota.ota_addr = OTA_STORAGE_START;
  ctx->ota.current_page = 0;

  // Try to connect, but don't fail if it doesn't work immediately
  // The reconnection logic in tcp_work() will handle retries
  tcp_connect_to_server(ctx);

  return 0;
}

