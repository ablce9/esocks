#ifndef EVS_ENCRYTOR_H
#define EVS_ENCRYTOR_H

#include "evs-internal.h"

#include <openssl/evp.h>
#include <openssl/err.h>

#define crypto_init() \
  do { CRYPTO_malloc_init(); \
    OpenSSL_add_all_algorithms(); ERR_load_crypto_strings(); \
} while(0)

#define crypto_shutdown() \
  do { OBJ_cleanup(); EVP_cleanup();					\
    CRYPTO_cleanup_all_ex_data(); ERR_remove_thread_state(NULL);	\
    ERR_free_strings(); } while(0)

int evs_encrypt(const EVP_CIPHER *cipher, EVP_CIPHER_CTX *ctx, u8 *out, u8 *in, int ilen, const u8 *key, const u8 *iv, _Bool sucessive);
int evs_decrypt(const EVP_CIPHER *cipher, EVP_CIPHER_CTX *ctx, u8 *out, u8 *in, int ilen, const u8 *key, const u8 *iv, _Bool sucessive);

#endif
