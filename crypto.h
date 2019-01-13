#ifndef esocks_openssl_crypto_h
#define esocks_openssl_crypto_h

#include "def.h"

#include <openssl/evp.h>
#include <openssl/err.h>

#define crypto_init() do { OPENSSL_malloc_init();			\
	OpenSSL_add_all_algorithms(); ERR_load_crypto_strings();	\
    } while (0)

#define crypto_shutdown() do { OBJ_cleanup();		\
	EVP_cleanup(); CRYPTO_cleanup_all_ex_data();	\
	ERR_free_strings();				\
    } while (0)

int openssl_encrypt(EVP_CIPHER_CTX *ctx, u8 *out, u8 *in, int ilen);
int openssl_decrypt(EVP_CIPHER_CTX *ctx, u8 *out, u8 *in, int ilen);

#endif
