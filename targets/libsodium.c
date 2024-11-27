#include <assert.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SALSA_DATA_SIZE 64
#define SALSA_KEY_SIZE 32

void salsa20(unsigned char *result, unsigned char *message,
             unsigned long long len, unsigned char *key, unsigned char *nonce) {
  crypto_stream_salsa20_xor(result, message, len, nonce, key);
}

void call_crypto_stream_salsa20() {
  char out[SALSA_DATA_SIZE] = {0};
  char message[SALSA_DATA_SIZE] = {0};
  char key[SALSA_KEY_SIZE] = {0};
  unsigned char nonce[crypto_stream_salsa20_NONCEBYTES] = {0};
  salsa20(out, message, SALSA_DATA_SIZE, key, nonce);
}

void call_crypto_stream_xor() {
  assert(crypto_stream_KEYBYTES == 32);
  assert(crypto_stream_NONCEBYTES == 24);
  char key[crypto_stream_KEYBYTES] = {0};
  char nonce[crypto_stream_NONCEBYTES] = {0};
  char message[123] = {0};
  char out[sizeof(message)] = {0};
  crypto_stream_xor(out, message, sizeof(message), nonce, key);
}

void call_crypto_sign_ed25519() {
  assert(crypto_sign_ed25519_SECRETKEYBYTES == 64);
  assert(crypto_sign_ed25519_BYTES == 64);
  unsigned char key[crypto_sign_ed25519_SECRETKEYBYTES] = {0};
  unsigned char message[32] = {0};
  unsigned char signed_message[sizeof(message) + crypto_sign_ed25519_BYTES];
  unsigned long long signed_message_len;
  crypto_sign_ed25519(signed_message, &signed_message_len, message,
                      sizeof(message), key);
}

void call_crypto_hash_sha512() {
  assert(crypto_hash_sha512_BYTES == 64);
  char out[crypto_hash_sha512_BYTES];
  char in[32] = {0};
  crypto_hash_sha512(out, in, sizeof(in));
}

void call_crypto_onetimeauth_poly1305() {
  assert(crypto_onetimeauth_KEYBYTES == 32);
  assert(crypto_onetimeauth_BYTES == 16);
  char key[crypto_onetimeauth_KEYBYTES] = {0};
  char message[32] = {0};
  char mac[crypto_onetimeauth_BYTES];
  crypto_onetimeauth_poly1305(mac, message, sizeof(message), key);
}

void call_crypto_auth() {
  assert(crypto_auth_KEYBYTES == 32);
  assert(crypto_auth_BYTES == 32);
  char message[32] = {0};
  char key[crypto_auth_KEYBYTES] = {0};
  char out[crypto_auth_BYTES] = {0};
  // HMAC-SHA512-256
  crypto_auth(out, message, sizeof(message), key);
}

void x25519_mul(unsigned char *q, const unsigned char *n,
                const unsigned char *p) {
  int ret = crypto_scalarmult_curve25519(q, n, p);
}

void call_crypto_box_beforenm() {
  assert(crypto_box_PUBLICKEYBYTES == 32);
  assert(crypto_box_SECRETKEYBYTES == 32);
  assert(crypto_box_BEFORENMBYTES == 32);
  unsigned char public_key[crypto_box_PUBLICKEYBYTES] = {0};
  unsigned char secret_key[crypto_box_SECRETKEYBYTES] = {0};
  unsigned char out[crypto_box_BEFORENMBYTES] = {0};
  x25519_mul(out, public_key, secret_key);
}

int main() {
  call_crypto_stream_salsa20();
  call_crypto_stream_xor();
  call_crypto_sign_ed25519();
  call_crypto_hash_sha512();
  call_crypto_onetimeauth_poly1305();
  call_crypto_box_beforenm();
  call_crypto_auth();
  printf("all ok!\n");
}
