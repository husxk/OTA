#include "tcp.h"
#include "debug.h"

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

static bool
validate_data_packet(const uint8_t* buffer, size_t size)
{
  const uint8_t* payload = OTA_packet_get_data(buffer, size);

  if (payload != NULL)
  {
    log_data_packet(payload);
    return true;
  }
  else
  {
    DEBUG("TCP: Invalid DATA packet\n");
    return false;
  }
}

static void
send_ack_packet(struct tcp_pcb* tpcb)
{
  uint8_t ack_buffer[OTA_ACK_PACKET_LENGTH];
  size_t ack_size = OTA_packet_write_ack(ack_buffer, sizeof(ack_buffer));

  if (ack_size > 0)
  {
    err_t err = tcp_client_write(tpcb, ack_buffer, ack_size);
    if (err == ERR_OK)
    {
      DEBUG("TCP: Sent ACK\n");
    }
    else
    {
      DEBUG("TCP: Failed to send ACK\n");
    }
  }
}

static void
send_nack_packet(struct tcp_pcb* tpcb)
{
  uint8_t nack_buffer[OTA_NACK_PACKET_LENGTH];
  size_t nack_size = OTA_packet_write_nack(nack_buffer, sizeof(nack_buffer));

  if (nack_size > 0)
  {
    err_t err = tcp_client_write(tpcb, nack_buffer, nack_size);
    if (err == ERR_OK)
    {
      DEBUG("TCP: Sent NACK\n");
    }
    else
    {
      DEBUG("TCP: Failed to send NACK\n");
    }
  }
}

static void
handle_data_packet(device_ctx_t* ctx, struct tcp_pcb* tpcb, const uint8_t* buffer, size_t size)
{
  if (!validate_data_packet(buffer, size))
  {
    DEBUG("OTA: Invalid packet, resetting flash offset and sending NACK\n");
    ota_reset_flash_offset(ctx);
    send_nack_packet(tpcb);
    return;
  }

  const uint8_t* payload = OTA_packet_get_data(buffer, size);
  if (payload == NULL)
  {
    DEBUG("OTA: Failed to extract payload, resetting flash offset and sending NACK\n");
    ota_reset_flash_offset(ctx);
    send_nack_packet(tpcb);
    return;
  }

  if (!ota_write_packet_to_flash(ctx, payload, OTA_DATA_PAYLOAD_SIZE))
  {
    DEBUG("OTA: Failed to write packet to flash, resetting flash offset and sending NACK\n");
    ota_reset_flash_offset(ctx);
    send_nack_packet(tpcb);
    return;
  }

  send_ack_packet(tpcb);
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

  // Parse OTA packet
  uint8_t packet_type = OTA_packet_get_type(buffer, total_len);

  switch (packet_type)
  {
    case OTA_DATA_TYPE:
      handle_data_packet(ctx, tpcb, buffer, total_len);
      break;

    case OTA_ACK_TYPE:
      DEBUG("TCP: Received ACK packet\n");
      break;

    case OTA_NACK_TYPE:
      DEBUG("TCP: Received NACK packet\n");
      break;

    case OTA_FIN_TYPE:
      DEBUG("TCP: Received FIN packet - file transfer complete!\n"
            "TCP: Total bytes written to flash: %u\n",
            ctx->ota.ota_addr - OTA_STORAGE_START);

      send_ack_packet(tpcb);

      // Force lwIP to send the ACK packet immediately
      tcp_output(tpcb);

      // Set up update timeout for 1 second from now
      // This allows the device to send ACK and prepare before update
      ctx->update_pending = true;
      ctx->update_timeout = make_timeout_time_ms(1000);

      DEBUG("TCP: Update scheduled for 1 second from now\n");
      break;

    case OTA_INVALID_TYPE:
    default:
      DEBUG("TCP: Received invalid packet (type: 0x%02X)\n", packet_type);
      send_nack_packet(tpcb);
      break;
  }

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
      DEBUG("TCP: Close failed %d, calling abort\n", err);
      tcp_abort(ctx->tcp.client_pcb);
      err = ERR_ABRT;
    }

    ctx->tcp.client_pcb = NULL;
  }

  ctx->tcp.connected = false;
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

  DEBUG("tcp_client_err %d\n", err);
  ctx->tcp.connected = false;
  tcp_client_close(ctx);
}

static err_t
tcp_client_connected(void* ctx_, struct tcp_pcb* tpcb, err_t err)
{
  device_ctx_t *ctx = (device_ctx_t*)ctx_;

  if (err != ERR_OK)
  {
    DEBUG("TCP: Connection failed %d\n", err);
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

    tcp_close(pcb);
    ctx->tcp.client_pcb = NULL;

    return false;
  }

  return true;
}

void
tcp_work(device_ctx_t* ctx)
{
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

  DEBUG("OTA: Written packet, address: %u, page: %u\n",
        ctx->ota.ota_addr,
        ctx->ota.current_page);

  return true;
}

void
ota_reset_flash_offset(device_ctx_t* ctx)
{
  ctx->ota.ota_addr = OTA_STORAGE_START;
  ctx->ota.current_page = 0;
  DEBUG("OTA: Reset flash offsets to 0\n");
}

