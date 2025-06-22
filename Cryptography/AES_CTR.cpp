#include "AES_CTR.h"

void increment_counter(uint8_t counter[16]) {
    for (int i = 15; i >= 8; --i) {
        if (++counter[i]) break;
    }
}


void AES_CTR_crypt(const uint8_t *input, uint8_t *output, size_t length, uint32_t key_schedule[], const uint8_t iv[16]) {
    uint8_t counter[16];
    uint8_t keystream[16];
    std::memcpy(counter, iv, 16);

    for (size_t i = 0; i < length; i += 16) {
        // Encrypt the counter to produce the keystream
        Encrypt(counter, keystream, key_schedule, 256);

        size_t block_size = std::min<size_t>(16, length - i);

        for (size_t j = 0; j < block_size; j++) {
            output[i + j] = input[i + j] ^ keystream[j];
        }

        increment_counter(counter);
    }
}

