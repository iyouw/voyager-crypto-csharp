#ifndef LINKER_DESIGN_AES_CONTEXT_H
#define LINKER_DESIGN_AES_CONTEXT_H

#include "crypto_base.h"

#include <openssl/evp.h>

typedef struct AesContext {
  EVP_CIPHER_CTX *ctx;
  const EVP_CIPHER *cipher;
  unsigned char *plaintext_buf;
  unsigned char *ciphertext_buf;
  int buf_len;
} AesContext;

AesContext *aes_context_create(enum AES_MODE mode, int key_size, int buf_len);

int aes_context_get_block_size(AesContext *context);

int aes_context_encrypt_init(AesContext *context, unsigned char *key, unsigned char *iv);

int aes_context_encrypt_update(AesContext *context, ReadCallback readCallback, WriteCallback writeCallback);

int aes_context_encrypt_final(AesContext *context, WriteCallback writeCallback);

int aes_context_decrypt_init(AesContext *context, unsigned char *key, unsigned char *iv);

int aes_context_decrypt_update(AesContext *context, ReadCallback readCallback, WriteCallback writeCallback);

int aes_context_decrypt_final(AesContext *context, WriteCallback writeCallback);

void aes_context_free(AesContext *context);

#endif