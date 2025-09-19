#include "debug.h"

void
hexdump(const unsigned char* data, size_t len)
{
  int c;
  int p = 0;

  char dumpdata[16 * 3];
  char dumpdata2[17];

  memset(dumpdata,  '\0', 16 * 3);
  memset(dumpdata2, '\0', 17);

  const char hexChars[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

  DEBUG("hexdump len %u\n", len);

  while(p < len)
  {
    c = data[p];

    const int index  = p % 16;
    const int offset = 3 * index;

    dumpdata[offset]     = hexChars[(c >> 4) & 0x0F];
    dumpdata[offset + 1] = hexChars[c & 0x0F];
    dumpdata[offset + 2] = ' ';
    dumpdata2[index]     = (isprint(c) ? c : '.');

    if ((index == 15) || (p == len - 1))
    {
      dumpdata[16 * 3 - 1] = '\0';
      dumpdata2[16]        = '\0';
      DEBUG("%-48s   %s\n", dumpdata, dumpdata2);

      memset(dumpdata,  '\0', 16 * 3);
      memset(dumpdata2, '\0', 17);
    }

    p++;
  }
}

void
wait_for_serial()
{
  while (!stdio_usb_connected())
  {
    sleep_ms(100);
  }

  DEBUG("Serial connected, proceeding...\n");
}
