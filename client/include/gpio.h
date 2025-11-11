#pragma once

void
gpio_wait_for(int pin, int state)
{
  while (gpio_get(pin) != state)
  {
    sleep_us(1);
  }
}

bool
gpio_wait_for_timeout(int pin, int state, size_t timeout)
{
  size_t count = 0;
  while (gpio_get(pin) != state)
  {
    if (count == timeout)
      return false;

    count++;
    sleep_us(1);
  }

  return true;
}
