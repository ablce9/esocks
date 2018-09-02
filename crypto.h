#ifndef EVS_ENCRYTOR_H
#define EVS_ENCRYTOR_H

#include <openssl/evp.h>
#include "evs-internal.h"

#define crypto_init() \
  do { CRYPTO_malloc_init(); ERR_load_crypto_strings(); \
    OpenSSL_add_all_algorithms(); } while(0)

int evs_encrypt(const EVP_CIPHER *cipher, u8 *plaintext, int plaintext_len, u8 *key);
int evs_decrypt(const EVP_CIPHER *cipher, u8 *plaintext, int plaintext_len, u8 *key);

#endif
