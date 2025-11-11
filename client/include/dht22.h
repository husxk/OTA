#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "pico/stdlib.h"

#define DHT_PIN 16
#define DHT_BITS_NUM 40
#define DHT_TRANSACT_TIMEOUT_MS 5000

typedef struct
{
  float humidity;
  float temperature;
} dht22_data_t;

bool
dht22_transact(dht22_data_t*);

void
dht22_init();
