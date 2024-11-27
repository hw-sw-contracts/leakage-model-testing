#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define CONFIG_NO_SESSIONS
#define __UNIX__
#include <crypt.h>
#include <crypt/sha2.h>
#include <crypt/aes.h>

#define AES_KEY_BITS 128
#define AES_IV_SIZE 16

static void hex_print(const char* lbl, const void* pv, size_t len)
{
  const unsigned char * p = (const unsigned char*)pv;
  printf("%s: ", lbl);
  if (NULL == pv)
    printf("NULL");
  else
  {
    size_t i = 0;
    for (; i<len;++i)
      printf("%02X ", *p++);
  }
  printf("\n");
}

void call_sha512() {
  assert(SHA512_DIGEST_SIZE == 64);
  unsigned char out[SHA512_DIGEST_SIZE];
  unsigned char in[32] = {0};
  sha512(out, in, 0); // XXX
  printf("sha512: ");
  for (int i = 0; i < SHA512_DIGEST_SIZE; i++) {
    printf("%02x", out[i]);
  }
  printf("\n");
  sha512(out, in, 0); // XXX
  printf("sha512: ");
  for (int i = 0; i < SHA512_DIGEST_SIZE; i++) {
    printf("%02x", out[i]);
  }
  printf("\n");
}

// input_length must be multiple of AES_BLOCK_SIZE
void aes_enc(uint8_t* output, uint8_t* input, size_t input_length, uint8_t key[AES_KEY_BITS/8], uint8_t* iv) {
  aes_encrypt_ctx aes_ctx;
  aes_encrypt_key(key, AES_KEY_BITS, &aes_ctx);
  aes_cbc_encrypt(input, output, input_length, iv, &aes_ctx);
}

// input_length must be multiple of AES_BLOCK_SIZE
void aes_dec(uint8_t* output, uint8_t* input, size_t input_length, uint8_t key[AES_KEY_BITS/8], uint8_t* iv) {
  aes_decrypt_ctx aes_ctx;
  aes_decrypt_key(key, AES_KEY_BITS, &aes_ctx);
  aes_cbc_decrypt(input, output, input_length, iv, &aes_ctx);
}

#define _AES_INPUT_SIZE 23
#define AES_INPUT_SIZE ((_AES_INPUT_SIZE + AES_BLOCK_SIZE-1) & ~(AES_BLOCK_SIZE-1))
void call_aes() {
  uint8_t in[AES_INPUT_SIZE] = {0};
  uint8_t out[AES_INPUT_SIZE] = {0};
  uint8_t iv[AES_IV_SIZE] = {0};
  uint8_t key[AES_KEY_BITS/8] = {0};

  aes_enc(out, in, AES_INPUT_SIZE, key, iv);

  hex_print("key", key, AES_KEY_BITS/8);
  hex_print("input ", in, AES_INPUT_SIZE);
  hex_print("output", out, AES_INPUT_SIZE);

  memcpy(in, out, AES_INPUT_SIZE);
  memset(out, 0xCC, AES_INPUT_SIZE);
  memset(iv, 0, AES_IV_SIZE);
  aes_dec(out, in, AES_INPUT_SIZE, key, iv);

  hex_print("decryp", out, AES_INPUT_SIZE);
}

void call_sign_ed25519() {
  CRYPT_ENVELOPE cryptEnvelope;
}

int main() {
  call_sha512();
  call_aes();
  printf("all ok!\n");
}
