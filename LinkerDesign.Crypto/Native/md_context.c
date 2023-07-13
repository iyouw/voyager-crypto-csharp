#include "md_context.h"

#include <string.h>

MdContext* md_context_create(
  enum MD_ALGORITHM algorithm, 
  int buf_len)
{
  MdContext *context = (MdContext *)malloc(sizeof(MdContext));
  
  if (NULL == context)
    goto err;

  memset(context, 0, sizeof(MdContext));

  // init buffer
  if (NULL == (context->msg_buf = (unsigned char*)malloc(buf_len)))
    goto err;
  
  context->msg_buf_len = buf_len;

  // init md context
  if (NULL == (context->ctx = EVP_MD_CTX_new()))
    goto err;
  
  if (NULL == (context->type = get_md_algorithm(algorithm)))
    goto err;
  
  if (1 != EVP_DigestInit(context->ctx, context->type))
    goto err;
  
  return context;
err:
  md_context_free(context);
  return NULL;
}

int md_context_update(
  MdContext *context, 
  ReadCallback readCallback)
{
  int byte_len;

  if (NULL == context)
    goto err;
  
  while(0 < (byte_len = (*readCallback)(context->msg_buf, context->msg_buf_len)))
  {
    if (1 != EVP_DigestUpdate(context->ctx, context->msg_buf, byte_len))
      goto err;
  }

  return 0;
err:
  return -1;
}

int md_context_final(
  MdContext *context, 
  WriteCallback writeCallback)
{
  unsigned char *digest;
  unsigned int digest_len;

  if (NULL == context)
    goto err;

  if (NULL == (digest = OPENSSL_malloc(EVP_MD_size(context->type))))
    goto err;

  if (1 != EVP_DigestFinal_ex(context->ctx, digest, &digest_len))
    goto err;
  
  (*writeCallback)(digest, digest_len);

  OPENSSL_free(digest);

  return 0;
err:
  return -1;
}

void md_context_free(MdContext *context)
{
  if (NULL == context) return;
  if (NULL != context->msg_buf) 
    free(context->msg_buf);
  if (NULL != context->ctx)
    EVP_MD_CTX_free(context->ctx);
  free(context);
}