// Minimal mbedTLS configuration

#define MBEDTLS_AES_C
#define MBEDTLS_AESNI_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_PLATFORM_C

#include "mbedtls/check_config.h"
