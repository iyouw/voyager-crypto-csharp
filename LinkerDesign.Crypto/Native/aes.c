#include <openssl/evp.h>
#include <openssl/rand.h>

#include "crypto_base.h"

void generate_aes_key(int length, WriteCallback callback)
{
    int byte_len = length >> 3;
    unsigned char *key = (unsigned char *)malloc(byte_len);
    RAND_bytes(key, byte_len);
    (*callback)(key, byte_len);
    free(key);
}

unsigned char *import_aes_key(int length) 
{
    return (unsigned char *)malloc(length);
}

void free_aes_key(unsigned char *key) 
{
    if (NULL != key) 
        free(key);
}

void generate_aes_iv(WriteCallback callback)
{
    const int size = 16;
    unsigned char iv[size];
    RAND_bytes(iv, size);
    (*callback)(iv, size);
}

unsigned char *import_aes_iv()
{
    return (unsigned char *)malloc(16);
}

void free_aes_iv(unsigned char *iv)
{
    if (NULL != iv)
        free(iv);
}

int aes_encrypt(
    int buf_len,
    unsigned char *key,
    unsigned char *iv,
    enum AES_MODE mode,
    int block_size,
    ReadCallback readCallback,
    WriteCallback writeCallback)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;

    int len;
    int read_len;
    unsigned char *plaintext;
    unsigned char *ciphertext;

    const int read_block_size = resolve_aes_read_block_size(16, buf_len);

    if (NULL == (plaintext = (unsigned char*)malloc(read_block_size)))
        goto err;
    
    if (NULL == (ciphertext = (unsigned char*)malloc(read_block_size)))
        goto err;

    if (!(ctx = EVP_CIPHER_CTX_new())) 
        goto err;
    
    if (NULL == (cipher = get_aes_cipher(mode, block_size)))
        goto err;

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
        goto err;
    
    // update
    while (0 < (read_len = (*readCallback)(plaintext, read_block_size)))
    {
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, read_len))
           goto err;
        (*writeCallback)(ciphertext, len);
    }

    // final
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext, &len))
       goto err;
    (*writeCallback)(ciphertext, len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    free(ciphertext);

    return 0;
err:
    if (NULL != ctx) EVP_CIPHER_CTX_free(ctx);
    if (NULL != plaintext) free(plaintext);
    if (NULL != ciphertext) free(ciphertext);
    handleErrors();
    return -1;
}

int aes_decrypt(
    int buf_len, 
    unsigned char *key, 
    unsigned char *iv, 
    enum AES_MODE mode,
    int block_size,
    ReadCallback readCallback,
    WriteCallback writeCallback)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;

    int len;
    int read_len;
    unsigned char *ciphertext;
    unsigned char *plaintext;

    const int read_block_size = resolve_aes_read_block_size(16, buf_len);

    if (NULL == (ciphertext = (unsigned char *)malloc(read_block_size)))
        goto err;
    
    if (NULL == (plaintext = (unsigned char *)malloc(read_block_size)))
        goto err;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        goto err;
    
    if (NULL == (cipher = get_aes_cipher(mode, block_size)))
        goto err;

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
        goto err;
    
    while( 0 < (read_len = (*readCallback)(ciphertext, read_block_size)))
    {
        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, read_len))
            goto err;
        (*writeCallback)(plaintext, len);
    }
    
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext, &len))
        goto err;

    (*writeCallback)(plaintext, len);

    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    free(plaintext);

    return 0;
err:
    if (NULL != ctx) EVP_CIPHER_CTX_free(ctx);
    if (NULL != ciphertext) free(ciphertext);
    if (NULL != plaintext) free(plaintext);
    handleErrors();
    return -1;
}