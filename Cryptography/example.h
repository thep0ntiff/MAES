// Cryptography/example.h
#pragma once

#include <vector>
#include <string>
#include "AES.h"

void encryptText(const std::string& input_text,
                 std::vector<std::vector<uint8_t>>& encrypted_chunks,
                 uint32_t* key_schedule);

void decryptText(std::vector<std::vector<uint8_t>>& encrypted_chunks,
                 std::string& output_text,
                 uint32_t* key_schedule);
