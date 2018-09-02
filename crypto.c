#include <openssl/conf.h>
#include <openssl/evp.h>

#include "evs-internal.h"
#include "crypto.h"
#include "evs_log.h"

// Symmetric encryption and decrytion.
int
evs_encrypt(const EVP_CIPHER *cipher, u8 *in, int ilen, u8 *key,
	    u8 *iv, u8 *out)
{
  u8 *salt = NULL;
  const EVP_MD *dgst;
  EVP_CIPHER_CTX *ctx;
  int len, ciphertext_len;

  dgst = EVP_md5();
  ctx = EVP_CIPHER_CTX_new();

  EVP_BytesToKey(cipher, dgst, salt, NULL, 0, 1, key, iv);

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
  fprintf(stderr, "error occurred\n");
  return (-1);
}

int
evs_decrypt(const EVP_CIPHER *cipher, u8 *in, int ilen, u8 *key,
	    u8 *iv, u8 *out)
{
  u8 *salt = NULL;
  const EVP_MD *dgst;
  EVP_CIPHER_CTX *ctx;
  int len, plaintext_len;

  dgst = EVP_md5();
  ctx = EVP_CIPHER_CTX_new();

  EVP_BytesToKey(cipher, dgst, salt, NULL, 0, 1, key, iv);

  if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 0))
    goto err;

  if (!EVP_DecryptUpdate(ctx, out, &len, in, ilen))
    goto err;

  plaintext_len = len;

  if (!EVP_DecryptFinal_ex(ctx, in + len, &len))
    goto err;

  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  out[plaintext_len] = '\0';

  return (plaintext_len);

 err:
  fprintf(stderr, "error occurred\n");
  return (-1);
}
