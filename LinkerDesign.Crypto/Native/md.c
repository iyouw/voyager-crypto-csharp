#include <openssl/evp.h>

#include "crypto_base.h"

static const EVP_MD *get_algorithm(enum MD_ALGORITHM algorithm)
{
  const EVP_MD *res = NULL;
  switch (algorithm)
  {
    case SHA1:
      res = EVP_sha1();
      break;
    case SHA256:
      res = EVP_sha256();
      break;
    case SHA384:
      res = EVP_sha384();
    case SHA512:
      res = EVP_sha512();
      break;
    case MD5:
      res = EVP_md5();
      break;
    case MD5_SHA1:
      res = EVP_md5_sha1();
      break;
  }
  if (NULL == res)
  {
    fprintf(stderr, "Could not find the algorihtm");
    exit(EXIT_FAILURE);
  }
  return res;
}


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

  if (NULL == (message = malloc(buf_len)))
    goto err;

  if (!(ctx = EVP_MD_CTX_new()))
    goto err;
  
 if (NULL == (type = get_algorithm(algorithm)))
    goto err;

  if (1 != EVP_DigestInit_ex(ctx, type, NULL))
    goto err;

  int byte_len;

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