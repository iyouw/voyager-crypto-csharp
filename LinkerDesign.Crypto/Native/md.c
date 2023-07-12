#include <openssl/evp.h>

#include "crypto_base.h"

int digest( 
  size_t buf_len,
  enum MD_ALGORITHM algorithm,
  ReadCallback readCallback,
  WriteCallback writeCallback)
{
  EVP_MD_CTX *ctx;
  const EVP_MD *type;

  unsigned char *message;
  unsigned char *digest;
  unsigned int digest_len;
  int byte_len;

  if (NULL == (message = malloc(buf_len)))
    goto err;

  if (!(ctx = EVP_MD_CTX_new()))
    goto err;
  
  if (NULL == (type = get_md_algorithm(algorithm)))
    goto err;

  if (1 != EVP_DigestInit_ex(ctx, type, NULL))
    goto err;

  while ((byte_len = (*readCallback)(message, buf_len)) > 0) {
    if (1 != EVP_DigestUpdate(ctx, message, byte_len))
      goto err;
  }

  if (!(digest = OPENSSL_malloc(EVP_MD_size(type))))
    goto err;
  
  if (1 != EVP_DigestFinal_ex(ctx, digest, &digest_len))
    goto err;
  
  (*writeCallback)(digest, digest_len);

  
  EVP_MD_CTX_free(ctx);
  OPENSSL_free(digest);
  free(message);
  return 0;
err:
  if (NULL != ctx) EVP_MD_CTX_free(ctx);
  if (NULL != digest) OPENSSL_free(digest);
  if (NULL != message) free(message);
  handleErrors();
  return -1;
}