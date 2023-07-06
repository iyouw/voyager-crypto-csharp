#ifndef LINKER_DESIGN_CRYPTO_BASE_H

#define LINKER_DESIGN_CRYPTO_BASE_H

typedef void (*WriteCallback)(unsigned char *ptr, int len);
typedef int (*ReadCallback)(unsigned char *ptr, int len);

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

void handleErrors(void);
#endif