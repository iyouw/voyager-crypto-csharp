#include <openssl/evp.h>
#include <openssl/rand.h>

#include <math.h>
#include <string.h>

#include "crypto_base.h"
#include "stream.h"

static const EVP_CIPHER *get_cipher(enum AES_MODE mode, int key_length)
{
    const EVP_CIPHER *res = NULL;
    switch (mode)
    {
        case CTR:
            if (128 == key_length) 
            {
                res = EVP_aes_128_ctr();
            } 
            else if ( 192 == key_length) 
            {
                res = EVP_aes_192_ctr();
            } 
            else if (256 == key_length) 
            {
                res = EVP_aes_256_ctr();
            }
            break;
        case CBC:
            if (128 == key_length) 
            {
                res = EVP_aes_128_cbc();
            } 
            else if ( 192 == key_length) 
            {
                res = EVP_aes_192_cbc();
            } 
            else if (256 == key_length) 
            {
                res = EVP_aes_256_cbc();
            } 
            break;
    }

    if (NULL == res)fprintf(stderr, "Could not find the aes algorithm!\n");
    
    return res;
}

static int resolve_read_block_size(int block_size, int buf_len)
{
    int count = ceil((double)buf_len / block_size);
    return count * block_size;
}


void generate_aes_key(int length, WriteCallback callback)
{
    int byte_len = length >> 3;
    unsigned char key[byte_len];
    RAND_bytes(key, byte_len);
    (*callback)(key, byte_len);
}


void generate_aes_iv(int length, WriteCallback callback)
{
    unsigned char iv[length];
    RAND_bytes(iv, length);
    (*callback)(iv, length);
}

unsigned char* import_aes_key(int length)
{
    return malloc(length);
}

unsigned char* import_aes_iv(int length)
{
    return malloc(length);
}

void free_aes_key(unsigned char *key)
{
    if (NULL != key) free(key);
}

void free_aes_iv(unsigned char *iv)
{
    if (NULL != iv) free(iv);
}

int encrypt(
    int buf_len,
    unsigned char *key,
    unsigned char *iv,
    enum AES_MODE mode,
    int block_size,
    ReadCallback readCallback,
    WriteCallback callback)
{
    EVP_CIPHER_CTX *ctx;
    Stream *stream;
    const EVP_CIPHER *cipher;

    int len;
    int read_len;
    unsigned char *write_ptr;
    unsigned char *plaintext;

    const int read_block_size = resolve_read_block_size(16, buf_len);

    if (NULL == (plaintext = malloc(read_block_size + 1)))
        goto err;
    
    if (NULL == (stream = stream_create(read_block_size * 2)))
        goto err;

    if (!(ctx = EVP_CIPHER_CTX_new())) 
        goto err;
    
    if (NULL == (cipher = get_cipher(mode, block_size)))
        goto err;

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
        goto err;
    
    // update
   
    while (0 < (read_len = (*readCallback)(plaintext, read_block_size)))
    {
        stream_ensure_capacity(stream, read_block_size);
        write_ptr = stream_get_write_ptr(stream);
        if (1 != EVP_EncryptUpdate(ctx, write_ptr, &len, plaintext, read_len))
           goto err;
        stream_write(stream, len);
    }

    // final
    write_ptr = stream_get_write_ptr(stream);
    if(1 != EVP_EncryptFinal_ex(ctx, write_ptr, &len))
       goto err;
    stream_write(stream, len);

    // callback
    (*callback)(stream->data, stream->length);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    stream_free(stream);
    free(plaintext);
    return 0;
err:
    if (NULL != ctx) EVP_CIPHER_CTX_free(ctx);
    if (NULL != stream) stream_free(stream);
    if (NULL != plaintext) free(plaintext);
    handleErrors();
    return -1;
}


int decrypt(
    int buf_len, 
    unsigned char *key, 
    unsigned char *iv, 
    enum AES_MODE mode,
    int block_size,
    ReadCallback readCallback,
    WriteCallback writeCallback)
{
    EVP_CIPHER_CTX *ctx;
    Stream *stream;
    const EVP_CIPHER *cipher;

    int len;
    int read_len;
    unsigned char *write_ptr;
    unsigned char *ciphertext;

    const int read_block_size = resolve_read_block_size(16, buf_len);

    if (NULL == (ciphertext = malloc(read_block_size + 1)))
        goto err;
    
    if (NULL == (stream = stream_create(read_block_size * 2)))
        goto err;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        goto err;
    
    if (NULL == (cipher = get_cipher(mode, block_size)))
        goto err;

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
        goto err;
    
    while( 0 < (read_len = (*readCallback)(ciphertext, read_block_size)))
    {
        stream_ensure_capacity(stream, read_block_size);
        write_ptr = stream_get_write_ptr(stream);
        if (1 != EVP_DecryptUpdate(ctx, write_ptr, &len, ciphertext, read_len))
            goto err;
        stream_write(stream, len);
    }
    

    write_ptr = stream_get_write_ptr(stream);
    if (1 != EVP_DecryptFinal_ex(ctx, write_ptr, &len))
        goto err;
    stream_write(stream, len);

    (*writeCallback)(stream->data, stream->length);

    EVP_CIPHER_CTX_free(ctx);
    stream_free(stream);
    free(ciphertext);

    return 0;
err:
    if (NULL != ctx) EVP_CIPHER_CTX_free(ctx);
    if (NULL != stream) stream_free(stream);
    if (NULL != ciphertext) free(ciphertext);
    handleErrors();
    return -1;
}