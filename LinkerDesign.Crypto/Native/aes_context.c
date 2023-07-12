#include "aes_context.h"

#include <string.h>

AesContext *aes_context_create(
  enum AES_MODE mode, 
  int key_size,
  int buf_len)
{
  int ctx_size = sizeof(AesContext);
  AesContext *context = (AesContext *)malloc(ctx_size);
  if (NULL == context)
    goto err;
  
  memset(context, 0, ctx_size);

  // allocate buffer
  const int read_block_size = resolve_aes_read_block_size(16, buf_len);

  if (NULL == (context->plaintext_buf = (unsigned char*)malloc(read_block_size)))
    goto err;
  
  if (NULL == (context->ciphertext_buf = (unsigned char*)malloc(read_block_size)))
    goto err;

  context->buf_len = read_block_size;

  // int cipher context
  if (NULL == (context->ctx = EVP_CIPHER_CTX_new()))
    goto err;
  
  if (NULL == (context->cipher = get_aes_cipher(mode, key_size)))
    goto err;
  
  return context;
err:
  aes_context_free(context);
  return NULL;
}

int aes_context_get_block_size(AesContext *context)
{
  if (NULL == context)
    goto err;
  
  return context->buf_len;
err:
  return -1;
}

int aes_context_encrypt_init(
  AesContext *context, 
  unsigned char *key, 
  unsigned char *iv)
{
  if (NULL == context)
    goto err;
  
  if (1 != (EVP_EncryptInit_ex(context->ctx, context->cipher, NULL, key, iv)))
    goto err;

  return 0;
err:
  return -1;
}

int aes_context_encrypt_update(
  AesContext *context, 
  ReadCallback readCallback, 
  WriteCallback writeCallback)
{
  int read_len;

  int len;

  if (NULL == context)
    goto err;
  
  while(0 < (read_len = (*readCallback)(context->plaintext_buf, context->buf_len)))
  {
    if (1 != EVP_EncryptUpdate(context->ctx, context->ciphertext_buf, &len, context->plaintext_buf, read_len))
      goto err;
    (*writeCallback)(context->ciphertext_buf, len);
  }

  return 0;
err:
  return -1;
}

int aes_context_encrypt_final(
  AesContext *context, 
  WriteCallback writeCallback)
{
  int len;
  if (NULL == context)
    goto err;
  
  if (1 != EVP_EncryptFinal_ex(context->ctx, context->ciphertext_buf, &len))
    goto err;

  (*writeCallback)(context->ciphertext_buf, len);

  return 0;
err:
  return -1;
}

int aes_context_decrypt_init(
  AesContext *context, 
  unsigned char *key, 
  unsigned char *iv)
{
  if (NULL == context)
    goto err;

  if (1 != EVP_DecryptInit_ex(context->ctx, context->cipher, NULL, key, iv))
    goto err;
  
  return 0;
err:
  return -1;
}

int aes_context_decrypt_update(
  AesContext *context, 
  ReadCallback readCallback, 
  WriteCallback writeCallback)
{
  int read_len;
  int len;

  if (NULL == context)
    goto err;
  
  while(0 < (read_len = (*readCallback)(context->ciphertext_buf, context->buf_len)))
  {
    if (1 != EVP_DecryptUpdate(context->ctx, context->plaintext_buf, &len, context->ciphertext_buf, read_len))
      goto err;
    (*writeCallback)(context->plaintext_buf, len);
  }

  return 0;
err:
  return -1;
}

int aes_context_decrypt_final(
  AesContext *context, 
  WriteCallback writeCallback)
{
  int len;

  if (NULL == context)
    goto err;
  
  if (1 != EVP_DecryptFinal_ex(context->ctx, context->plaintext_buf, &len))
    goto err;
  
  (*writeCallback)(context->plaintext_buf, len);

  return 0;
err:
  return -1;
}

void aes_context_free(AesContext *context)
{
  if (NULL == context) return;
  // free cipher context
  if (NULL != context->ctx)
    EVP_CIPHER_CTX_free(context->ctx);
  // free plaintext buffer
  if (NULL != context->plaintext_buf)
    free(context->plaintext_buf);
  // free ciphertext buffer
  if (NULL != context->ciphertext_buf)
    free(context->ciphertext_buf);
  // free context
  free(context);
}