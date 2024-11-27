#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "crypto/crypto.h"

#define SHA512_BYTES 64
#define SALSA_DATA_SIZE 64
#define SALSA_KEY_SIZE 32
#define POLY1305_SIZE 32
#define POLY1305_MAC 16
#define SALSA20_NONCE_SIZE 8
#define DATA_SIZE 32

void call_sha512() {
  unsigned char out[SHA512_BYTES];
  unsigned char in[32] = {0};
  sha512_rust(out, in, sizeof(in));
}

void salsa20(unsigned char *result, unsigned char *message,
             unsigned long long len, unsigned char *key, unsigned char *nonce) {
  for (int i=0; i<len; i++)
    result[i] = message[i];
  salsa20_rust(result, len, key, nonce);
}

void call_salsa20() {
  unsigned char key[SALSA_KEY_SIZE] = {0};
  unsigned char nonce[SALSA20_NONCE_SIZE] = {0};
  unsigned char src[SALSA_DATA_SIZE] = {0};
  unsigned char dst[SALSA_DATA_SIZE] = {0};
  salsa20(dst, src, SALSA_DATA_SIZE, key, nonce);
}

void crypto_stream_xor(unsigned char *result, unsigned char *message,
             unsigned long long len, unsigned char *nonce, unsigned char *key) {
  for (int i=0; i<len; i++)
    result[i] = message[i];
  xsalsa20_rust(result, len, key, nonce);
}

void call_stream_xor() {
  unsigned char key[SALSA_KEY_SIZE] = {0};
  unsigned char nonce[SALSA20_NONCE_SIZE] = {0};
  unsigned char src[SALSA_DATA_SIZE] = {0};
  unsigned char dst[SALSA_DATA_SIZE] = {0};
  crypto_stream_xor(dst, src, SALSA_DATA_SIZE, nonce, key);
}

void poly1305(unsigned char *mac, unsigned char *message, unsigned long long len, unsigned char *key){
  poly1305_rust(mac, message, len, key);
}

void call_poly1305() {
  unsigned char key[POLY1305_SIZE] = {0};
  unsigned char message[32] = {0};
  unsigned char mac[POLY1305_MAC];
  poly1305(mac, message, sizeof(message), key);
}

void x25519_mul(unsigned char *q, unsigned char *n, unsigned char *p) {
  x25519_rust(q, n, p);
}

void call_x25519() {
  unsigned char public_key[DATA_SIZE] = {0};
  unsigned char secret_key[DATA_SIZE] = {0};
  unsigned char out[DATA_SIZE] = {0};
  x25519_mul(out, public_key, secret_key);
}


int main() {
    call_sha512();
    call_salsa20();
    call_stream_xor();
    call_poly1305();
    call_x25519();
    return 0;
}