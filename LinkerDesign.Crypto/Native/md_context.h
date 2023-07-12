#ifndef LINKER_DESIGN_MD_CONTEXT_H
#define LINKER_DESIGN_MD_CONTEXT_H

#include "crypto_base.h"

#include <openssl/evp.h>

typedef struct MdContext {
  EVP_MD_CTX *ctx;
  const EVP_MD *type;
  unsigned char *msg_buf;
  size_t msg_buf_len;
} MdContext;


MdContext *md_context_create(enum MD_ALGORITHM algorithm, int buf_len);

int md_context_update(MdContext *context, ReadCallback readCallback);

int md_context_final(MdContext *context, WriteCallback writeCallback);

void md_context_free(MdContext *context);

#endif