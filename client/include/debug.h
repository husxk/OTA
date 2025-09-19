#pragma once

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "pico/stdlib.h"

// TODO: implement logger and move it to logger scope
#define log(fmt, ...)     printf((fmt), ##__VA_ARGS__)

// TODO: this should be turn off by default and set in compile time
#define DEBUG_LOGS

#ifdef DEBUG_LOGS
  #define MEMDUMP(data, len)  hexdump((data), (len))
  #define DEBUG(fmt, ...)     printf((fmt), ##__VA_ARGS__)
  #define WAIT_FOR_TERMINAL() wait_for_serial()
#else
  #define MEMDUMP(data, len)
  #define DEBUG(fmt, ...)
  #define WAIT_FOR_TERMINAL()
#endif

void
hexdump(const unsigned char*, size_t);

void
wait_for_serial();


