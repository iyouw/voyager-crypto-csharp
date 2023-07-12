#ifndef LINKER_DESIGN_CRYPTO_BASE_H

#define LINKER_DESIGN_CRYPTO_BASE_H

#include <openssl/evp.h>

typedef int (*ReadCallback)(unsigned char *ptr, int len);
typedef void (*WriteCallback)(unsigned char *ptr, int len);

enum AES_MODE {
  CTR = 1,
  CBC,
};

enum MD_ALGORITHM {
  SHA1 = 1,
  SHA256,
  SHA384,
  SHA512,
  MD5,
  MD5_SHA1,
};

const EVP_CIPHER *get_aes_cipher(enum AES_MODE mode, int key_length);

int resolve_aes_read_block_size(int block_size, int buf_len);

const EVP_MD *get_md_algorithm(enum MD_ALGORITHM algorithm);

void handleErrors(void);
#endif