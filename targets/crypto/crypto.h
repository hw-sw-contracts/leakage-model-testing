#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

void x25519_rust(uint8_t *output, uint8_t *public_, uint8_t *secret);

void poly1305_rust(uint8_t *mac, uint8_t *msg, uintptr_t length, uint8_t *key);

void sha512_rust(uint8_t *output, uint8_t *input, uintptr_t length);

void salsa20_rust(uint8_t *message, uintptr_t length, uint8_t *key, uint8_t *nonce);

void xsalsa20_rust(uint8_t *message, uintptr_t length, uint8_t *key, uint8_t *nonce);
