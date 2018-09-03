#include <openssl/conf.h>
#include <openssl/evp.h>

#include "evs-internal.h"
#include "crypto.h"
#include "evs_log.h"

// Symmetric encryption and decrytion.
int
evs_encrypt(const EVP_CIPHER *cipher, const EVP_MD *dgst, u8 *out, u8 *in, int ilen,
	    u8 *passwd, int plen, u8 *key, u8 *iv)
{
  u8 *salt = NULL;

  EVP_CIPHER_CTX *ctx;
  int len, ciphertext_len;

  ctx = EVP_CIPHER_CTX_new();

  EVP_BytesToKey(cipher, dgst, salt, passwd, plen, 1, key, iv);

  if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1))
    goto err;

  if (!EVP_EncryptUpdate(ctx, out, &len, in, ilen))
    goto err;

  ciphertext_len = len;

  if (!EVP_EncryptFinal_ex(ctx, out + len, &len))
    goto err;

  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return (ciphertext_len);

 err:
  EVP_CIPHER_CTX_free(ctx);
  fprintf(stderr, "error occurred\n");
  return (-1);
}

int
evs_decrypt(const EVP_CIPHER *cipher, const EVP_MD *dgst, u8 *out, u8 *in, int ilen,
	    u8 *passwd, int plen, u8 *key, u8 *iv)
{
  u8 *salt = NULL;
  EVP_CIPHER_CTX *ctx;
  int len, ciphertext_len;

  ctx = EVP_CIPHER_CTX_new();

  EVP_BytesToKey(cipher, dgst, salt, passwd, plen, 1, key, iv);

  if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 0))
    goto err;

  if (!EVP_DecryptUpdate(ctx, out, &len, in, ilen))
    goto err;

  ciphertext_len = len;

  if (!EVP_DecryptFinal_ex(ctx, out + len, &len))
    goto err;

  ciphertext_len += len;

  out[ciphertext_len] = '\0';

  EVP_CIPHER_CTX_free(ctx);

  return (ciphertext_len);

 err:
  EVP_CIPHER_CTX_free(ctx);
  fprintf(stderr, "error occurred\n");
  return (-1);
}
