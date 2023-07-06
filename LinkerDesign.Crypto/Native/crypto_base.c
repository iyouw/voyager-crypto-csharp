#include <openssl/err.h>

#include "crypto_base.h"

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

void *linker_alloc(size_t length)
{
  return malloc(length);
}

void linker_free(void *ptr)
{
  if (NULL != ptr) free(ptr);
}