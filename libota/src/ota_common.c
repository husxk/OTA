#include "ota_common.h"
#include <stdarg.h>

void OTA_debug_log(OTA_common_ctx_t* common_ctx,
                   void* user_ctx,
                   const char* format,
                   ...)
{
    if (!common_ctx ||
        !common_ctx->callbacks.debug_log_cb)
    {
        return;
    }

    va_list args;
    va_start(args, format);

    common_ctx->callbacks.debug_log_cb(user_ctx, format, args);

    va_end(args);
}
