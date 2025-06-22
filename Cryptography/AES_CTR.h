#include "AES.h"

void increment_counter(uint8_t counter[16]);

void AES_CTR_crypt(const uint8_t* input, uint8_t* output, size_t length, uint32_t key_schedule[], const uint8_t iv[16]);
