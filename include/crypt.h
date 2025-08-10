
#pragma once

#include <vector>
#include <cstring>
#include "AES.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
#endif

void encryptText(const std::string& input_text,
                 std::vector<std::vector<uint8_t>>& encrypted_chunks,
                 uint32_t* key_schedule);

void decryptText(std::vector<std::vector<uint8_t>>& encrypted_chunks,
                 std::string& output_text,
                 uint32_t* key_schedule);
