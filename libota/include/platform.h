#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef htons

__attribute__((weak)) uint16_t htons(uint16_t hostshort)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((hostshort & 0xFF) << 8) | ((hostshort >> 8) & 0xFF);
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return hostshort;
#else
    #error "Byte order not defined. Please define __BYTE_ORDER__ or provide platform-specific htons/ntohs implementation."
#endif
}

#endif // htons

#ifndef ntohs

__attribute__((weak)) uint16_t ntohs(uint16_t netshort)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((netshort & 0xFF) << 8) | ((netshort >> 8) & 0xFF);
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return netshort;
#else
    #error "Byte order not defined. Please define __BYTE_ORDER__ or provide platform-specific htons/ntohs implementation."
#endif
}

#endif // ntohs

#ifdef __cplusplus
}
#endif
