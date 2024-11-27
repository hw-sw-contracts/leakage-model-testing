#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16
typedef uint32_t u32;
typedef uint64_t u64;

static void RotWord(u32 *x)
{
    unsigned char *w0;
    unsigned char tmp;

    w0 = (unsigned char *)x;
    tmp = w0[0];
    w0[0] = w0[1];
    w0[1] = w0[2];
    w0[2] = w0[3];
    w0[3] = tmp;
}

static void SubWord(u32 *w)
{
	static unsigned char table[] = {
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
	};
	unsigned char* w0 = (unsigned char*)w;
	for (int i = 0; i < 4; i++) {
		w0[i] = table[w0[i]];
	}
}

static u32 rcon(int round) {
	static unsigned char table[] = {
		0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
		0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
	};
	assert(round < sizeof(table)/sizeof(table[0]));
	return table[round];
}

// rd_key and prev_rd_key can point to the same address
static void inv_expand_key_round(unsigned char rd_key[AES_BLOCK_SIZE],
                                 unsigned char prev_rd_key[AES_BLOCK_SIZE],
                                 int round)
{
	u32* rd_key_w = (u32*)rd_key;
	u32* prev_rd_key_w = (u32*)prev_rd_key;
	for (int i = 3; i > 0; i--) {
		prev_rd_key_w[i] = rd_key_w[i] ^ rd_key_w[i-1];
	}

	u32 tmp1 = rd_key_w[0] ^ rcon(round);
	u32 tmp2 = prev_rd_key_w[3];
	RotWord(&tmp2);
	SubWord(&tmp2);
	prev_rd_key_w[0] = tmp1 ^ tmp2;
}

void inv_expand_key(unsigned char last_round_key[AES_BLOCK_SIZE])
{
	for (int r = 10; r > 0; r--) {
		inv_expand_key_round(last_round_key, last_round_key, r);
	}
}

void aes_enc(unsigned char* output, const unsigned char* input, int input_length,
             const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE])
{
	unsigned char iv_copy[AES_BLOCK_SIZE];
	memcpy(iv_copy, iv, AES_BLOCK_SIZE);
	AES_KEY aes_key;
	AES_set_encrypt_key(key, 128, &aes_key);
	AES_cbc_encrypt(input, output, input_length, &aes_key, iv_copy, AES_ENCRYPT);
}

void set_value(unsigned char key[AES_BLOCK_SIZE], u32 value)
{
	unsigned char* v = (unsigned char*)&value;
	key[0x0] = v[0];
	key[0x4] = v[1];
	key[0x8] = v[2];
	key[0xC] = v[3];
}

unsigned char* hex_to_bytes(const char* hex, int* bytes_len_ptr) {
	int hex_len = strlen(hex);
	assert((hex_len%2) == 0);
	int bytes_len = hex_len/2;
	unsigned char* bytes = malloc(bytes_len);
	for (int i = 0; i < bytes_len; i++) {
		sscanf(hex + i*2, "%2hhx", bytes + i);
	}
	*bytes_len_ptr = bytes_len;
	return bytes;
}

void print_hex(const unsigned char* b, int len) {
	for (int i = 0; i < len; i++) {
		printf("%02x", b[i]);
	}
	printf("\n");
}

// Arguments for each thread
struct args_t {
	const unsigned char* plain;
	int plain_len;
	const unsigned char* correct_cipher;
	int cipher_len;
	const unsigned char* iv;
	const unsigned char* last_round_key;
	int id;
	u32 value_start;
	u32 value_end;
};

void* worker(void* ptr)
{
	// Get arguments
	struct args_t* args = (struct args_t*)ptr;
	const unsigned char *plain = args->plain, *correct_cipher = args->correct_cipher,
		*iv = args->iv, *last_round_key = args->last_round_key;
	int plain_len = args->plain_len, cipher_len = args->cipher_len, id = args->id;
	u32 value_start = args->value_start, value_end = args->value_end;

	unsigned char* cipher = malloc(cipher_len);
	unsigned char key[AES_BLOCK_SIZE];

	// For each possible last round key, perform the inverse expansion algorithm,
	// encrypt the plaintext, and check if we got the correct ciphertext.
	for (u32 value = value_start; value != value_end; value++) {
		memcpy(key, last_round_key, AES_BLOCK_SIZE);
		set_value(key, value);

		inv_expand_key(key);
		aes_enc(cipher, plain, plain_len, key, iv);

		if (memcmp(cipher, correct_cipher, cipher_len) == 0) {
			print_hex(key, AES_BLOCK_SIZE);
			exit(0);
		}

		if (id == 0 && (value % 10000000) == 0) {
			printf("[%d] %.2f%%\n", id, (float)100*(value-value_start)/(value_end-value_start));
		}
	}
	return NULL;
}

int main(int argc, char** argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	if (argc < 5) {
		printf("args: plaintext ciphertext iv last_round_key\n");
		return EXIT_FAILURE;
	}

	// Get arguments and sanity checks
	int plain_len, cipher_len, iv_len, last_round_key_len;
	unsigned char *plain = hex_to_bytes(argv[1], &plain_len),
		*correct_cipher = hex_to_bytes(argv[2], &cipher_len),
		*iv = hex_to_bytes(argv[3], &iv_len),
		*last_round_key = hex_to_bytes(argv[4], &last_round_key_len);
	assert(cipher_len == ((plain_len + AES_BLOCK_SIZE - 1) & ~(AES_BLOCK_SIZE - 1)));
	assert(iv_len == AES_BLOCK_SIZE);
	assert(last_round_key_len == AES_BLOCK_SIZE);

	// Get number of cores
	int number_of_cores = sysconf(_SC_NPROCESSORS_ONLN);
	while (((1ull<<32) % number_of_cores) != 0)
		number_of_cores--;
	u64 step = (1ull << 32) / number_of_cores;
	printf("Starting with %d threads\n", number_of_cores);

	// Launch threads, pinning each one to a single core and dividing the work
	struct args_t args[number_of_cores];
	pthread_t threads[number_of_cores];
	pthread_attr_t thread_attr;
	cpu_set_t cpuset;
	pthread_attr_init(&thread_attr);
	for (int i = 0; i < number_of_cores; i++) {
		args[i] = (struct args_t) {
			.plain = plain,
			.plain_len = plain_len,
			.correct_cipher = correct_cipher,
			.cipher_len = cipher_len,
			.iv = iv,
			.last_round_key = last_round_key,
			.id = i,
			.value_start = i*step,
			.value_end = (i + 1)*step,
		};
		CPU_ZERO(&cpuset);
		CPU_SET(i, &cpuset);
		pthread_attr_setaffinity_np(&thread_attr, sizeof(cpuset), &cpuset);
		pthread_create(&threads[i], &thread_attr, worker, &args[i]);
	}

	// Wait for threads to finish
	for (int i = 0; i < number_of_cores; i++) {
		pthread_join(threads[i], NULL);
	}

	// Every thread finished without finding the key
	printf("Failed...");

	free(plain);
	free(correct_cipher);
	free(iv);
	free(last_round_key);
}