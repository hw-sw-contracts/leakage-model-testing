#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nettle-3.8/aes.h"
#include "nettle-3.8/base16.h"
#include "nettle-3.8/cbc.h"
#include "nettle-3.8/curve25519.h"
#include "nettle-3.8/ecc.h"
#include "nettle-3.8/eddsa.h"
#include "nettle-3.8/nettle-meta.h"
#include "nettle-3.8/salsa20.h"
#include "nettle-3.8/sha2.h"
#include "nettle-3.8/hmac.h"

#define AES_KEY_BITS 128
#define BLOCK_SIZE 16
#define DATA_SIZE 32
#define SALSA_DATA_SIZE 64
#define SALSA_KEY_SIZE 32
#define NETTLE_SHA512 216
#define NETTLE_AES128 176
#define KEY_PAIR_LEN 64

static void hex_print(const char *lbl, const void *pv, size_t len) {
  const unsigned char *p = (const unsigned char *)pv;
  printf("%s: ", lbl);
  if (NULL == pv)
    printf("NULL");
  else {
    size_t i = 0;
    for (; i < len; ++i)
      printf(" %02X ", *p++);
  }
  printf("\n");
}

void sha512(unsigned char hval[], const unsigned char data[],
            unsigned long len) {
  char ctx_sha512[NETTLE_SHA512] = {0};
  void *ctx = (void *)ctx_sha512;
  nettle_sha512.init(ctx);
  nettle_sha512.update(ctx, len, data);
  nettle_sha512.digest(ctx, SHA512_DIGEST_SIZE, hval);
}

void call_sha512() {
  assert(SHA512_DIGEST_SIZE == 64);
  unsigned char out[SHA512_DIGEST_SIZE] = {0};
  unsigned char in[DATA_SIZE] = {0};
  sha512(out, in, 0); // XXX
}

// input_length must be multiple of AES_BLOCK_SIZE
void aes_enc(uint8_t *output, uint8_t *input, size_t input_length,
             uint8_t key[AES_KEY_BITS / 8], uint8_t *iv) {
  char ctx_aes128[NETTLE_AES128] = {0};
  void *ctx = (void *)ctx_aes128;
  nettle_aes128.set_encrypt_key(ctx, key);
  cbc_encrypt(ctx, nettle_aes128.encrypt, nettle_aes128.block_size, iv,
              input_length, output, input);
}

// input_length must be multiple of AES_BLOCK_SIZE
void aes_dec(uint8_t *output, uint8_t *input, size_t input_length,
             uint8_t key[AES_KEY_BITS / 8], uint8_t *iv) {
  char ctx_aes128[NETTLE_AES128] = {0};
  void *ctx = (void *)ctx_aes128;
  nettle_aes128.set_decrypt_key(ctx, key);
  cbc_decrypt(ctx, nettle_aes128.decrypt, nettle_aes128.block_size, iv,
              input_length, output, input);
}

void call_aes() {
  uint8_t in[DATA_SIZE] = {0x00};
  uint8_t out[DATA_SIZE] = {0x00};
  uint8_t iv[BLOCK_SIZE] = {0x00};
  uint8_t key[BLOCK_SIZE] = {0x00};
  aes_enc(out, in, DATA_SIZE, key, iv);
  memset(iv, 0, nettle_aes128.block_size);
  aes_dec(out, out, DATA_SIZE, key, iv);
}

void salsa20(unsigned char *result, unsigned char *message,
             unsigned long long len, unsigned char *key, unsigned char *nonce) {
  struct salsa20_ctx ctx;
  salsa20_set_key(&ctx, SALSA_KEY_SIZE, key);
  salsa20_set_nonce(&ctx, nonce);
  salsa20_crypt(&ctx, len, result, message);
}

void call_salsa20() {
  unsigned char key[SALSA_KEY_SIZE] = {0};
  unsigned char nonce[SALSA20_NONCE_SIZE] = {0};
  unsigned char src[SALSA_DATA_SIZE] = {0};
  unsigned char dst[SALSA_DATA_SIZE] = {0};
  salsa20(dst, src, SALSA_DATA_SIZE, key, nonce);
}

void x25519_mul(unsigned char *q, const unsigned char *n,
                const unsigned char *p) {
  curve25519_mul(q, n, p);
}

void call_x25519() {
  unsigned char public_key[DATA_SIZE] = {0};
  unsigned char secret_key[DATA_SIZE] = {0};
  unsigned char out[DATA_SIZE] = {0};
  x25519_mul(out, public_key, secret_key);
}

void crypto_sign_ed25519(unsigned char *sm, unsigned long long *smlen_p,
                         unsigned char *m, unsigned long long mlen,
                         unsigned char *sk) {

  *smlen_p = mlen + KEY_PAIR_LEN;
  unsigned char *public_key = sk + 32;
  unsigned char *secret_key = sk;
  ed25519_sha512_sign(public_key, secret_key, mlen, m, sm);
  // copy message to the end of signature
  memcpy(sm + KEY_PAIR_LEN, m, mlen);
  // done
}

void call_ed25519() {
  unsigned char key[KEY_PAIR_LEN] = {0};
  unsigned char msg[DATA_SIZE] = {0};
  unsigned char sig[KEY_PAIR_LEN + DATA_SIZE] = {0};
  unsigned long long signed_message_len;
  crypto_sign_ed25519(sig, &signed_message_len, msg, sizeof(msg), key);
}

void hmac(unsigned char *out, unsigned char *message, unsigned long long len, unsigned char *key){
  struct hmac_sha512_ctx sha512_ctx;
  hmac_sha512_set_key(&sha512_ctx, DATA_SIZE, key);
  hmac_sha512_update(&sha512_ctx, len, message);
  hmac_sha512_digest(&sha512_ctx, DATA_SIZE, out);
}

void call_hmac() {
  unsigned char message[DATA_SIZE] = {0};
  unsigned char key[DATA_SIZE] = {0};
  unsigned char out[DATA_SIZE] = {0};
  hmac(out, message, sizeof(message), key);
}

int main() {
  call_salsa20();
  call_aes();
  call_sha512();
  call_x25519();
  call_ed25519();
  call_hmac();
  return 0;
}

struct hmac_sha512_ctx sha512_ctx;