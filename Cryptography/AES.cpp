#include <stdint.h>
#include <iostream>
#include "AES.h"

void SubBytes(uint8_t state[][4]) {
    state[0][0] = aes_sbox[state[0][0] >> 4][state[0][0] & 0x0F];
	state[0][1] = aes_sbox[state[0][1] >> 4][state[0][1] & 0x0F];
	state[0][2] = aes_sbox[state[0][2] >> 4][state[0][2] & 0x0F];
	state[0][3] = aes_sbox[state[0][3] >> 4][state[0][3] & 0x0F];
	state[1][0] = aes_sbox[state[1][0] >> 4][state[1][0] & 0x0F];
	state[1][1] = aes_sbox[state[1][1] >> 4][state[1][1] & 0x0F];
	state[1][2] = aes_sbox[state[1][2] >> 4][state[1][2] & 0x0F];
	state[1][3] = aes_sbox[state[1][3] >> 4][state[1][3] & 0x0F];
	state[2][0] = aes_sbox[state[2][0] >> 4][state[2][0] & 0x0F];
	state[2][1] = aes_sbox[state[2][1] >> 4][state[2][1] & 0x0F];
	state[2][2] = aes_sbox[state[2][2] >> 4][state[2][2] & 0x0F];
	state[2][3] = aes_sbox[state[2][3] >> 4][state[2][3] & 0x0F];
	state[3][0] = aes_sbox[state[3][0] >> 4][state[3][0] & 0x0F];
	state[3][1] = aes_sbox[state[3][1] >> 4][state[3][1] & 0x0F];
	state[3][2] = aes_sbox[state[3][2] >> 4][state[3][2] & 0x0F];
	state[3][3] = aes_sbox[state[3][3] >> 4][state[3][3] & 0x0F];
}

void ShiftRows(uint8_t state[][4]) {
    int t;

	t = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = t;

	t = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = t;
	t = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = t;

	t = state[3][0];
	state[3][0] = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = t;
}

void MixColumns(uint8_t state[][4]) {
    uint8_t col[4];

	col[0] = state[0][0];
	col[1] = state[1][0];
	col[2] = state[2][0];
	col[3] = state[3][0];
	state[0][0] = gf_mul[col[0]][0];
	state[0][0] ^= gf_mul[col[1]][1];
	state[0][0] ^= col[2];
	state[0][0] ^= col[3];
	state[1][0] = col[0];
	state[1][0] ^= gf_mul[col[1]][0];
	state[1][0] ^= gf_mul[col[2]][1];
	state[1][0] ^= col[3];
	state[2][0] = col[0];
	state[2][0] ^= col[1];
	state[2][0] ^= gf_mul[col[2]][0];
	state[2][0] ^= gf_mul[col[3]][1];
	state[3][0] = gf_mul[col[0]][1];
	state[3][0] ^= col[1];
	state[3][0] ^= col[2];
	state[3][0] ^= gf_mul[col[3]][0];

	col[0] = state[0][1];
	col[1] = state[1][1];
	col[2] = state[2][1];
	col[3] = state[3][1];
	state[0][1] = gf_mul[col[0]][0];
	state[0][1] ^= gf_mul[col[1]][1];
	state[0][1] ^= col[2];
	state[0][1] ^= col[3];
	state[1][1] = col[0];
	state[1][1] ^= gf_mul[col[1]][0];
	state[1][1] ^= gf_mul[col[2]][1];
	state[1][1] ^= col[3];
	state[2][1] = col[0];
	state[2][1] ^= col[1];
	state[2][1] ^= gf_mul[col[2]][0];
	state[2][1] ^= gf_mul[col[3]][1];
	state[3][1] = gf_mul[col[0]][1];
	state[3][1] ^= col[1];
	state[3][1] ^= col[2];
	state[3][1] ^= gf_mul[col[3]][0];

	col[0] = state[0][2];
	col[1] = state[1][2];
	col[2] = state[2][2];
	col[3] = state[3][2];
	state[0][2] = gf_mul[col[0]][0];
	state[0][2] ^= gf_mul[col[1]][1];
	state[0][2] ^= col[2];
	state[0][2] ^= col[3];
	state[1][2] = col[0];
	state[1][2] ^= gf_mul[col[1]][0];
	state[1][2] ^= gf_mul[col[2]][1];
	state[1][2] ^= col[3];
	state[2][2] = col[0];
	state[2][2] ^= col[1];
	state[2][2] ^= gf_mul[col[2]][0];
	state[2][2] ^= gf_mul[col[3]][1];
	state[3][2] = gf_mul[col[0]][1];
	state[3][2] ^= col[1];
	state[3][2] ^= col[2];
	state[3][2] ^= gf_mul[col[3]][0];

	col[0] = state[0][3];
	col[1] = state[1][3];
	col[2] = state[2][3];
	col[3] = state[3][3];
	state[0][3] = gf_mul[col[0]][0];
	state[0][3] ^= gf_mul[col[1]][1];
	state[0][3] ^= col[2];
	state[0][3] ^= col[3];
	state[1][3] = col[0];
	state[1][3] ^= gf_mul[col[1]][0];
	state[1][3] ^= gf_mul[col[2]][1];
	state[1][3] ^= col[3];
	state[2][3] = col[0];
	state[2][3] ^= col[1];
	state[2][3] ^= gf_mul[col[2]][0];
	state[2][3] ^= gf_mul[col[3]][1];
	state[3][3] = gf_mul[col[0]][1];
	state[3][3] ^= col[1];
	state[3][3] ^= col[2];
	state[3][3] ^= gf_mul[col[3]][0];
}


void Encrypt(uint8_t in[], uint8_t out[], uint32_t key[], int keysize) {
    uint8_t state[4][4];

    state[0][0] = in[0];
    state[1][0] = in[1];
    state[2][0] = in[2];
    state[3][0] = in[3];
    state[0][1] = in[4];
    state[1][1] = in[5];
    state[2][1] = in[6];
    state[3][1] = in[7];
    state[0][2] = in[8];
    state[1][2] = in[9];
    state[2][2] = in[10];
    state[3][2] = in[11];
    state[0][3] = in[12];
    state[1][3] = in[13];
    state[2][3] = in[14];
    state[3][3] = in[15];

    AddRoundKey(state, &key[0]);
    SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state, &key[4]);
    SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state, &key[8]);
    SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state, &key[12]);
    SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state, &key[16]);
    SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state, &key[20]);
    SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state, &key[24]);
    SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state, &key[28]);
    SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state, &key[32]);
    SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state, &key[36]);

    if (keysize != 128) {
        SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state, &key[40]);
        SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state, &key[44]);
    

        if (keysize != 192) {
            SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state, &key[48]);
            SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state, &key[52]);
            SubBytes(state); ShiftRows(state); AddRoundKey(state, &key[56]);
        }
        else {
            SubBytes(state); ShiftRows(state); AddRoundKey(state, &key[48]);
        }
    }
    else {
        SubBytes(state); ShiftRows(state); AddRoundKey(state, &key[40]);
    }

    out[0] = state[0][0];
    out[1] = state[1][0];
    out[2] = state[2][0];
    out[3] = state[3][0];
    out[4] = state[0][1];
    out[5] = state[1][1];
    out[6] = state[2][1];
    out[7] = state[3][1];
    out[8] = state[0][2];
    out[9] = state[1][2];
    out[10] = state[2][2];
    out[11] = state[3][2];
    out[12] = state[0][3];
    out[13] = state[1][3];
    out[14] = state[2][3];
    out[15] = state[3][3];
    
}

void InvSubBytes(uint8_t state[][4])
{
	state[0][0] = aes_invsbox[state[0][0] >> 4][state[0][0] & 0x0F];
	state[0][1] = aes_invsbox[state[0][1] >> 4][state[0][1] & 0x0F];
	state[0][2] = aes_invsbox[state[0][2] >> 4][state[0][2] & 0x0F];
	state[0][3] = aes_invsbox[state[0][3] >> 4][state[0][3] & 0x0F];
	state[1][0] = aes_invsbox[state[1][0] >> 4][state[1][0] & 0x0F];
	state[1][1] = aes_invsbox[state[1][1] >> 4][state[1][1] & 0x0F];
	state[1][2] = aes_invsbox[state[1][2] >> 4][state[1][2] & 0x0F];
	state[1][3] = aes_invsbox[state[1][3] >> 4][state[1][3] & 0x0F];
	state[2][0] = aes_invsbox[state[2][0] >> 4][state[2][0] & 0x0F];
	state[2][1] = aes_invsbox[state[2][1] >> 4][state[2][1] & 0x0F];
	state[2][2] = aes_invsbox[state[2][2] >> 4][state[2][2] & 0x0F];
	state[2][3] = aes_invsbox[state[2][3] >> 4][state[2][3] & 0x0F];
	state[3][0] = aes_invsbox[state[3][0] >> 4][state[3][0] & 0x0F];
	state[3][1] = aes_invsbox[state[3][1] >> 4][state[3][1] & 0x0F];
	state[3][2] = aes_invsbox[state[3][2] >> 4][state[3][2] & 0x0F];
	state[3][3] = aes_invsbox[state[3][3] >> 4][state[3][3] & 0x0F];
}

void InvShiftRows(uint8_t state[][4])
{
	int t;

	t = state[1][3];
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = t;

	t = state[2][3];
	state[2][3] = state[2][1];
	state[2][1] = t;
	t = state[2][2];
	state[2][2] = state[2][0];
	state[2][0] = t;

	t = state[3][3];
	state[3][3] = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = t;
}

void InvMixColumns(uint8_t state[][4])
{
	int idx;
	uint8_t col[4], t;

	col[0] = state[0][0];
	col[1] = state[1][0];
	col[2] = state[2][0];
	col[3] = state[3][0];
	state[0][0] = gf_mul[col[0]][5];
	state[0][0] ^= gf_mul[col[1]][3];
	state[0][0] ^= gf_mul[col[2]][4];
	state[0][0] ^= gf_mul[col[3]][2];
	state[1][0] = gf_mul[col[0]][2];
	state[1][0] ^= gf_mul[col[1]][5];
	state[1][0] ^= gf_mul[col[2]][3];
	state[1][0] ^= gf_mul[col[3]][4];
	state[2][0] = gf_mul[col[0]][4];
	state[2][0] ^= gf_mul[col[1]][2];
	state[2][0] ^= gf_mul[col[2]][5];
	state[2][0] ^= gf_mul[col[3]][3];
	state[3][0] = gf_mul[col[0]][3];
	state[3][0] ^= gf_mul[col[1]][4];
	state[3][0] ^= gf_mul[col[2]][2];
	state[3][0] ^= gf_mul[col[3]][5];

	col[0] = state[0][1];
	col[1] = state[1][1];
	col[2] = state[2][1];
	col[3] = state[3][1];
	state[0][1] = gf_mul[col[0]][5];
	state[0][1] ^= gf_mul[col[1]][3];
	state[0][1] ^= gf_mul[col[2]][4];
	state[0][1] ^= gf_mul[col[3]][2];
	state[1][1] = gf_mul[col[0]][2];
	state[1][1] ^= gf_mul[col[1]][5];
	state[1][1] ^= gf_mul[col[2]][3];
	state[1][1] ^= gf_mul[col[3]][4];
	state[2][1] = gf_mul[col[0]][4];
	state[2][1] ^= gf_mul[col[1]][2];
	state[2][1] ^= gf_mul[col[2]][5];
	state[2][1] ^= gf_mul[col[3]][3];
	state[3][1] = gf_mul[col[0]][3];
	state[3][1] ^= gf_mul[col[1]][4];
	state[3][1] ^= gf_mul[col[2]][2];
	state[3][1] ^= gf_mul[col[3]][5];

	col[0] = state[0][2];
	col[1] = state[1][2];
	col[2] = state[2][2];
	col[3] = state[3][2];
	state[0][2] = gf_mul[col[0]][5];
	state[0][2] ^= gf_mul[col[1]][3];
	state[0][2] ^= gf_mul[col[2]][4];
	state[0][2] ^= gf_mul[col[3]][2];
	state[1][2] = gf_mul[col[0]][2];
	state[1][2] ^= gf_mul[col[1]][5];
	state[1][2] ^= gf_mul[col[2]][3];
	state[1][2] ^= gf_mul[col[3]][4];
	state[2][2] = gf_mul[col[0]][4];
	state[2][2] ^= gf_mul[col[1]][2];
	state[2][2] ^= gf_mul[col[2]][5];
	state[2][2] ^= gf_mul[col[3]][3];
	state[3][2] = gf_mul[col[0]][3];
	state[3][2] ^= gf_mul[col[1]][4];
	state[3][2] ^= gf_mul[col[2]][2];
	state[3][2] ^= gf_mul[col[3]][5];

	col[0] = state[0][3];
	col[1] = state[1][3];
	col[2] = state[2][3];
	col[3] = state[3][3];
	state[0][3] = gf_mul[col[0]][5];
	state[0][3] ^= gf_mul[col[1]][3];
	state[0][3] ^= gf_mul[col[2]][4];
	state[0][3] ^= gf_mul[col[3]][2];
	state[1][3] = gf_mul[col[0]][2];
	state[1][3] ^= gf_mul[col[1]][5];
	state[1][3] ^= gf_mul[col[2]][3];
	state[1][3] ^= gf_mul[col[3]][4];
	state[2][3] = gf_mul[col[0]][4];
	state[2][3] ^= gf_mul[col[1]][2];
	state[2][3] ^= gf_mul[col[2]][5];
	state[2][3] ^= gf_mul[col[3]][3];
	state[3][3] = gf_mul[col[0]][3];
	state[3][3] ^= gf_mul[col[1]][4];
	state[3][3] ^= gf_mul[col[2]][2];
	state[3][3] ^= gf_mul[col[3]][5];
}

void Decrypt(uint8_t in[], uint8_t out[], uint32_t key[], int keysize)
{
	uint8_t state[4][4];

	state[0][0] = in[0];
	state[1][0] = in[1];
	state[2][0] = in[2];
	state[3][0] = in[3];
	state[0][1] = in[4];
	state[1][1] = in[5];
	state[2][1] = in[6];
	state[3][1] = in[7];
	state[0][2] = in[8];
	state[1][2] = in[9];
	state[2][2] = in[10];
	state[3][2] = in[11];
	state[0][3] = in[12];
	state[1][3] = in[13];
	state[2][3] = in[14];
	state[3][3] = in[15];

	if (keysize > 128) {
		if (keysize > 192) {
			AddRoundKey(state, &key[56]);
			InvShiftRows(state); InvSubBytes(state); AddRoundKey(state, &key[52]); InvMixColumns(state);
			InvShiftRows(state); InvSubBytes(state); AddRoundKey(state, &key[48]); InvMixColumns(state);
		}
		else {
			AddRoundKey(state, &key[48]);
		}
		InvShiftRows(state); InvSubBytes(state); AddRoundKey(state, &key[44]); InvMixColumns(state);
		InvShiftRows(state); InvSubBytes(state); AddRoundKey(state, &key[40]); InvMixColumns(state);
	}
	else {
		AddRoundKey(state, &key[40]);
	}
	InvShiftRows(state); InvSubBytes(state); AddRoundKey(state, &key[36]); InvMixColumns(state);
	InvShiftRows(state); InvSubBytes(state); AddRoundKey(state, &key[32]); InvMixColumns(state);
	InvShiftRows(state); InvSubBytes(state); AddRoundKey(state, &key[28]); InvMixColumns(state);
	InvShiftRows(state); InvSubBytes(state); AddRoundKey(state, &key[24]); InvMixColumns(state);
	InvShiftRows(state); InvSubBytes(state); AddRoundKey(state, &key[20]); InvMixColumns(state);
	InvShiftRows(state); InvSubBytes(state); AddRoundKey(state, &key[16]); InvMixColumns(state);
	InvShiftRows(state); InvSubBytes(state); AddRoundKey(state, &key[12]); InvMixColumns(state);
	InvShiftRows(state); InvSubBytes(state); AddRoundKey(state, &key[8]); InvMixColumns(state);
	InvShiftRows(state); InvSubBytes(state); AddRoundKey(state, &key[4]); InvMixColumns(state);
	InvShiftRows(state); InvSubBytes(state); AddRoundKey(state, &key[0]);

	out[0] = state[0][0];
	out[1] = state[1][0];
	out[2] = state[2][0];
	out[3] = state[3][0];
	out[4] = state[0][1];
	out[5] = state[1][1];
	out[6] = state[2][1];
	out[7] = state[3][1];
	out[8] = state[0][2];
	out[9] = state[1][2];
	out[10] = state[2][2];
	out[11] = state[3][2];
	out[12] = state[0][3];
	out[13] = state[1][3];
	out[14] = state[2][3];
	out[15] = state[3][3];
}