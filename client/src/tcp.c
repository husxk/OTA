#include "tcp.h"
#include "debug.h"

#include <stdarg.h>
#include <stdlib.h>

#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/ip_addr.h"

#include "pico/cyw43_arch.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/bootrom.h"
#include "hardware/watchdog.h"
#include "hardware/structs/watchdog.h"

#include "ota.h"
#include "libota/ota_client.h"
#include "libota/ota_common.h"
#include "libota/tls_context.h"
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>

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
  // Only process if there's data in the pbuf queue
  // Data will be pulled via libota callbacks
  if (ctx->tcp.pbuf_queue_head || ctx->tcp.current_node)
  {
    OTA_client_handle_data(&ctx->ota_ctx, ctx);
  }
}

bool
tcp_is_conn_active(device_ctx_t* ctx)
{
  return ctx->tcp.connected &&
         ctx->tcp.client_pcb != NULL &&
         ctx->tcp.client_pcb->state == ESTABLISHED;
}

// Free all pbufs in queue
static void
tcp_free_pbuf_queue(device_ctx_t* ctx)
{
  // Free current node if any
  if (ctx->tcp.current_node)
  {
    if (ctx->tcp.current_node->p)
    {
      pbuf_free(ctx->tcp.current_node->p);
    }
    free(ctx->tcp.current_node);
    ctx->tcp.current_node = NULL;
    ctx->tcp.current_offset = 0;
  }

  // Free all queued pbufs
  pbuf_queue_node_t* node = ctx->tcp.pbuf_queue_head;
  while (node)
  {
    pbuf_queue_node_t* next = node->next;
    if (node->p)
    {
      pbuf_free(node->p);
    }
    // Free queue node (simple malloc or we could use a pool)
    free(node);
    node = next;
  }

  ctx->tcp.pbuf_queue_head = NULL;
  ctx->tcp.pbuf_queue_tail = NULL;
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

  // Free all queued pbufs
  tcp_free_pbuf_queue(ctx);

  // Restart TLS context for reconnection (preserves SHA-512 keys)
  OTA_tls_restart(&ctx->ota_ctx.common);

  // now + 5 seconds
  ctx->tcp.last_reconnect_attempt = make_timeout_time_ms(5000);

  return err;
}

static void
tcp_client_recv_(device_ctx_t *ctx, struct tcp_pcb* tpcb, struct pbuf* p)
{
  DEBUG("TCP: tcp_client_recv %d\n", p->tot_len);

  if (p->tot_len == 0)
  {
    pbuf_free(p); // Free empty pbuf
    return;
  }

  pbuf_queue_node_t* node =
    (pbuf_queue_node_t*) malloc(sizeof(pbuf_queue_node_t));

  if (!node)
  {
    DEBUG("TCP: Failed to allocate pbuf queue node\n");
    pbuf_free(p);
    return;
  }

  node->p = p;
  node->next = NULL;

  // Add to queue
  if (ctx->tcp.pbuf_queue_tail)
  {
    ctx->tcp.pbuf_queue_tail->next = node;
    ctx->tcp.pbuf_queue_tail = node;
  }
  else
  {
    ctx->tcp.pbuf_queue_head = node;
    ctx->tcp.pbuf_queue_tail = node;
  }

  // Acknowledge receipt to lwip
  tcp_recved(tpcb, p->tot_len);

  packet_handler(ctx, tpcb);
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
  ctx->tcp.connection_time = get_absolute_time(); // Record connection time
  ctx->tcp.handshake_started = false; // Reset handshake flag

  tcp_arg(tpcb, ctx);
  tcp_recv(tpcb, tcp_client_recv);
  tcp_err(tpcb, tcp_client_err);

  // Reinit TLS for new connection
  if (OTA_client_init(&ctx->ota_ctx) != 0)
  {
    DEBUG("TCP: Failed to reinitialize TLS for new connection\n");
    tcp_client_close(ctx);

    return ERR_ABRT;
  }

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
  else
  {
    // TODO: We should refactor this,
    //       maybe some kind of event queue
    //       that will dispatch this event once?

    // Start handshake
    if (ota_tls_is_enabled(&ctx->ota_ctx.common) &&
        !ota_tls_is_handshake_complete(&ctx->ota_ctx.common))
    {
      if (ctx->tcp.handshake_started)
        return;

      // Wait 0.5 seconds after TCP connection before starting handshake
      absolute_time_t now = get_absolute_time();

      // Calculate when handshake should start (connection_time + 500ms)
      // absolute_time_diff_us returns (now - connection_time) in microseconds
      int64_t diff_us = absolute_time_diff_us(ctx->tcp.connection_time, now);
      if (diff_us >= 500000) // 500ms = 500000 microseconds
      {
        // 0.5 seconds have passed, mark handshake as started
        ctx->tcp.handshake_started = true;
      }
      else
      {
        return;
      }

      OTA_client_handle_data(&ctx->ota_ctx, ctx);
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

int
tcp_init_client(device_ctx_t* ctx)
{
  ctx->tcp.client_pcb = NULL;
  ctx->tcp.pbuf_queue_head = NULL;
  ctx->tcp.pbuf_queue_tail = NULL;
  ctx->tcp.current_node = NULL;
  ctx->tcp.current_offset = 0;
  ctx->tcp.connection_time = 0; // Initialize to 0 (will be set on connection)
  ctx->tcp.handshake_started = false; // Initialize handshake flag
  ctx->tcp.connected = false;
  ctx->tcp.last_reconnect_attempt = 0;

  ctx->ota.ota_addr = OTA_STORAGE_START;
  ctx->ota.current_page = 0;

  // Try to connect, but don't fail if it doesn't work immediately
  // The reconnection logic in tcp_work() will handle retries
  tcp_connect_to_server(ctx);

  // now + 5 seconds
  ctx->tcp.last_reconnect_attempt = make_timeout_time_ms(5000);

  return 0;
}

