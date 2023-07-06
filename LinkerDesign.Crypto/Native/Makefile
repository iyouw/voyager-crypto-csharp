# which compiler
CC = cc

# where are include files kept
INCLUDE += -I.

# options for dev
CFLAGS += -g -Wall
CFLAGS += -fPIC -shared

# LD options
LDFLAGS += -lcrypto
LDFLAGS += -lm

crypto: aes.c md.c crypto_base.c stream.c crypto_base.h stream.h
	$(CC) $(INCLUDE) $(CFLAGS) -o $@.so aes.c md.c crypto_base.c stream.c $(LDFLAGS)

install:
	rm -rf ../lib/crypto.so
	mv crypto.so ../lib/crypto.so

clean:
	rm -rf *_r *.wasm *.js *.o *.so