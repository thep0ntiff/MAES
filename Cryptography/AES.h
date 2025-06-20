#pragma once

#include <stdint.h>
#include <cstdint>

extern const uint8_t aes_sbox[16][16];
extern const uint8_t aes_invsbox[16][16];

extern uint8_t gf_mul[256][6];


#define KE_ROTWORD(x) ( ((x) << 8) | ((x) >> 24) )


void AddRoundKey(uint8_t state[][4], uint32_t w[]);

uint32_t SubWord(uint32_t word);

void KeyExpansion(uint8_t key[], uint32_t w[], int keysize);

void Encrypt(uint8_t in[], uint8_t out[], uint32_t key[], int key_size);
void Decrypt(uint8_t in[], uint8_t out[], uint32_t key[], int key_size);
