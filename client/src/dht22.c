#include "dht22.h"
#include "debug.h"
#include "gpio.h"
#include "misc.h"
#include "device.h"

static bool
transaction_(uint8_t *recv)
{
  // start transaction
  gpio_set_dir(DHT_PIN, GPIO_OUT);
  gpio_put(DHT_PIN, 0);

  sleep_ms(5);

  gpio_put(DHT_PIN, 1);
  sleep_us(20);

  gpio_set_dir(DHT_PIN, GPIO_IN);

  // skip dht response
  if(gpio_wait_for_timeout(DHT_PIN, 0, 500) == false)
    return false;

  if(gpio_wait_for_timeout(DHT_PIN, 1, 500) == false)
    return false;

  if(gpio_wait_for_timeout(DHT_PIN, 0, 500) == false)
    return false;

  // data transact starts here

  for (int i = 0, count = 0, offset = 7, byte = 0;
      i < DHT_BITS_NUM;
      i++)
  {
    // skip 50us before bit
    if(gpio_wait_for_timeout(DHT_PIN, 1, 500) == false)
      return false;

    // receive bit
    while (gpio_get(DHT_PIN) == 1)
    {
      count++;
      sleep_us(1);
    }

    unsigned char bit;

    // 26-28 us -> '0'
    // 70 us    -> '1'
    if (count < 40)
    {
      bit = 0;
    }
    else
    {
      bit = 1;
    }

    count = 0;
    recv[byte] |= bit << offset;

    offset--;
    if(offset == -1)
    {
      offset = 7;
      byte++;
    }
  }

  return true;
}

static bool
parse_data_(uint8_t* recv, dht22_data_t* out)
{
  // check checksum
  const uint8_t checksum = recv[4];
  const uint8_t sum = recv[0] + recv[1] + recv[2] + recv[3];

  if (checksum != sum)
  {
    DEBUG("Invalid data! expected: %#02X - calculated: %#02X\n", checksum, sum);
    return false;
  }

  uint16_t raw_humidity;
  msb_to_lsb(recv, &raw_humidity, 2);
  const float humidity = (float) raw_humidity / (float) 10;
  out->humidity = humidity;

  DEBUG("DHT22: Received humidity: %.2f\n", humidity);

  // MSB indicates signess of data
  // 1 -> temperature is negative
  // 0 -> temperature is positive
  // Rest of data is unsigned, so we need to check MSB
  // and set it 0, to correctly read temperature as unsigned value
  const bool is_negative = recv[2] & 0x80;
  recv[2]               &= 0x7F;

  uint16_t raw_temperature;
  msb_to_lsb(recv + 2, &raw_temperature, 2);

  float temperature = (float) raw_temperature / (float) 10;

  if (is_negative)
    temperature *= (-1);

  out->temperature = temperature;

  DEBUG("DHT22: Received temperature: %.2f\n", temperature);

  return true;
}

bool
dht22_transact(dht22_data_t* out)
{
  uint8_t recv[5];

  static_assert(sizeof(recv) * 8 == DHT_BITS_NUM,
      "Reserved memory does not fit for DHT response!\n");

  memset(recv, 0, sizeof(recv));

  DEBUG("\nStart DHT22 data transact!\n");

  if(transaction_(recv) == false)
    return false;

  DEBUG("\nEnd of DHT22 data transact!"
        "\nReceived data:\n");

  MEMDUMP(recv, 5);

  if(parse_data_(recv, out) == false)
    return false;

  return true;
}

void
dht22_init()
{
  gpio_init(DHT_PIN);
}
