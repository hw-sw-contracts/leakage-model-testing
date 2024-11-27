#include <assert.h>
#include <libjade.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DATA_SIZE 32
#define SALSA_DATA_SIZE 64
#define JADE_STREAM_XSALSA20_AMD64_REF_KEYBYTES 32
#define JADE_STREAM_XSALSA20_AMD64_REF_NONCEBYTES 24
#define JADE_ONETIMEAUTH_POLY1305_AMD64_REF_KEYBYTES 32
#define JADE_ONETIMEAUTH_POLY1305_AMD64_REF_BYTES 16
#define JADE_STREAM_SALSA20_SALSA20_AMD64_AVX_KEYBYTES 32
#define JADE_STREAM_SALSA20_SALSA20_AMD64_REF_NONCEBYTES 8
#define JADE_HASH_SHA512_AMD64_REF_BYTES 64


void crypto_stream_xor(uint8_t *output, const uint8_t *input,
                       uint64_t input_length, const uint8_t *nonce,
                       const uint8_t *key) {
  jade_stream_xsalsa20_amd64_ref_xor(output, input, input_length, nonce, key);
}

void call_crypto_stream_xor() {
  unsigned char key[JADE_STREAM_XSALSA20_AMD64_REF_KEYBYTES] = {0};
  unsigned char nonce[JADE_STREAM_XSALSA20_AMD64_REF_NONCEBYTES] = {0};
  unsigned char message[123] = {0};
  unsigned char out[sizeof(message)] = {0};
  crypto_stream_xor(out, message, sizeof(message), nonce, key);
}

void crypto_onetimeauth_poly1305(uint8_t *mac, const uint8_t *input,
                                 uint64_t input_length, const uint8_t *key) {
  jade_onetimeauth_poly1305_amd64_ref(mac, input, input_length, key);
}

void call_crypto_onetimeauth_poly1305() {
  unsigned char key[JADE_ONETIMEAUTH_POLY1305_AMD64_REF_KEYBYTES] = {0};
  unsigned char message[32] = {0};
  message[20] = 0xff;
  unsigned char mac[JADE_ONETIMEAUTH_POLY1305_AMD64_REF_BYTES];
  crypto_onetimeauth_poly1305(mac, message, sizeof(message), key);
}

void salsa20(unsigned char *result, unsigned char *message, unsigned long long len,
             unsigned char *key, unsigned char *nonce) {
  jade_stream_salsa20_salsa20_amd64_ref_xor(result, message, len, nonce, key);
}

void call_salsa20() {
  unsigned char key[JADE_STREAM_SALSA20_SALSA20_AMD64_AVX_KEYBYTES] = {0};
  unsigned char nonce[JADE_STREAM_SALSA20_SALSA20_AMD64_REF_NONCEBYTES] = {0};
  unsigned char src[SALSA_DATA_SIZE] = {0};
  unsigned char dst[SALSA_DATA_SIZE] = {0};
  salsa20(dst, src, SALSA_DATA_SIZE, key, nonce);
}

void x25519_mul(unsigned char *q, const unsigned char *n,
                const unsigned char *p) {
  jade_scalarmult_curve25519_amd64_ref5(q, n, p);
}

void call_x25519() {
  unsigned char public_key[DATA_SIZE] = {0};
  unsigned char secret_key[DATA_SIZE] = {0};
  unsigned char out[DATA_SIZE] = {0};
  x25519_mul(out, public_key, secret_key);
}

void sha512(uint8_t *hash, const uint8_t *input, uint64_t len) {
  jade_hash_sha512_amd64_ref(hash, input, len);
}

void call_jade_hash_sha512_amd64_ref() {
  assert(JADE_HASH_SHA512_AMD64_REF_BYTES == 64);
  unsigned char in[DATA_SIZE] = {0};
  unsigned char out[JADE_HASH_SHA512_AMD64_REF_BYTES] = {0};
  sha512(out, in, 0);
  printf("sha512: ");
  for (int i = 0; i < JADE_HASH_SHA512_AMD64_REF_BYTES; i++) {
    printf("%02x", out[i]);
  }
  printf("\n");
}

int main() {
  call_jade_hash_sha512_amd64_ref();
  call_x25519();
  call_salsa20();
  call_crypto_onetimeauth_poly1305();
  call_crypto_stream_xor();
  printf("all ok!\n");
}