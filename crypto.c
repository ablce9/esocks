#include <openssl/objects.h>
#include <openssl/conf.h>
#include <openssl/evp.h>

#include "evs-internal.h"
#include "crypto.h"
#include "evs_log.h"

// Symmetric encryption and decrytion.
int evs_encrypt(const EVP_CIPHER *cipher, EVP_CIPHER_CTX *ctx,
		u8 *out, u8 *in, int ilen, const u8 *key, const u8 *iv, _Bool successive)
{
  int outl, len;

  if (!successive)
    if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1))
      goto err;

  if (!EVP_EncryptUpdate(ctx, out, &len, in, ilen))
    goto err;

  outl = len;

  return (outl);

 err:
  fprintf(stderr, "error occurred\n");
  return (-1);
}

int evs_decrypt(const EVP_CIPHER *cipher, EVP_CIPHER_CTX *ctx,
		u8 *out, u8 *in, int ilen, const u8 *key, const u8 *iv, _Bool successive)
{
  int outl, len;

  if (!successive)
    if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 0))
      goto err;

  if (!EVP_DecryptUpdate(ctx, out, &len, in, ilen))
    goto err;

  outl = len;

  return (outl);

 err:
  fprintf(stderr, "error occurred\n");
  return (-1);
}
