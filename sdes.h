#ifndef SDES_H
#define SDES_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Generate S-DES subkeys (K1, K2) from a 10-bit key held in the low bits of key10.
void sdes_generate_subkeys(uint16_t key10, uint8_t *K1, uint8_t *K2);

// Encrypt/decrypt a single 8-bit block (one byte) using S-DES.
uint8_t sdes_encrypt_byte(uint8_t in, uint8_t K1, uint8_t K2);
uint8_t sdes_decrypt_byte(uint8_t in, uint8_t K1, uint8_t K2);

// Convenience: convert a string like "1010011101" (10 chars) to a 10-bit integer.
int sdes_parse_key10_bits(const char *bits, uint16_t *out_key10);

// Modes
typedef enum { MODE_ECB = 0, MODE_CBC = 1, MODE_CTR = 2 } sdes_mode_t;

#ifdef __cplusplus
}
#endif

#endif // SDES_H