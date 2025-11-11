#include "misc.h"

void
msb_to_lsb(void* msb_, void* lsb_, size_t size)
{
  // indexes
  size_t start = 0;
  size_t end   = size - 1;

  uint8_t *msb = (uint8_t*) msb_;
  uint8_t *lsb = (uint8_t*) lsb_;

  while (start < size)
  {
    lsb[end] = msb[start];
    start++;
    end--;
  }
}
