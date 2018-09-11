#include <openssl/objects.h>
#include <openssl/conf.h>
#include <openssl/evp.h>

#include "evs-internal.h"
#include "crypto.h"

// Symmetric encryption and decrytion.
int openssl_encrypt(EVP_CIPHER_CTX *ctx, u8 *out, u8 *in, int ilen)
{
  int len = 0;

  if (!EVP_EncryptUpdate(ctx, out, &len, in, ilen))
    goto err;

  return len;

 err:
  fprintf(stderr, "error occurred\n");
  return (-1);
}

int openssl_decrypt(EVP_CIPHER_CTX *ctx, u8 *out, u8 *in, int ilen)
{
  int len = 0;

  if (!EVP_DecryptUpdate(ctx, out, &len, in, ilen))
    goto err;

  return len;

 err:
  fprintf(stderr, "error occurred\n");
  return (-1);
}
