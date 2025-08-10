#include "example.h"
#include "AES_CTR.h"
#include <cstdint>
#include <iostream>
#include <cstring>
#include <vector>
#include <arpa/inet.h>

void encryptText(const std::string& input_text, 
                 std::vector<std::vector<uint8_t>>& encrypted_chunks,
                 uint32_t* key_schedule) {
    // Generate and store IV
    uint8_t iv[16];
    generate_iv(iv);

    std::cout << "IV: ";
    for (int i = 0; i < 16; ++i)
        std::cout << std::hex << std::uppercase << (int)iv[i] << " ";
    std::cout << std::dec << "\n";

    // 1. Store IV as first chunk
    encrypted_chunks.emplace_back(iv, iv + 16);

    // 2. Encode plaintext length (as big-endian uint32_t)
    uint32_t len = htonl(static_cast<uint32_t>(input_text.size()));
    std::vector<uint8_t> len_chunk(4);
    std::memcpy(len_chunk.data(), &len, 4);

    // 3. Store length as second chunk
    encrypted_chunks.push_back(len_chunk);

    std::vector<uint8_t> ciphertext(input_text.size());
    AES_CTR_crypt(reinterpret_cast<const uint8_t*>(input_text.data()), ciphertext.data(), input_text.size(), key_schedule, iv);

    std::cout << "Plaintext: " << input_text << "\n";

    // 4. Split ciphertext into 16-byte chunks
    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        size_t chunk_size = std::min<size_t>(16, ciphertext.size() - i);
        std::vector<uint8_t> chunk(ciphertext.begin() + i, ciphertext.begin() + i + chunk_size);

        std::cout << "Ciphertext Chunk: " << (i / 16) << ": ";
        for (uint8_t b : chunk)
            std::cout << std::hex << std::uppercase << (int)b << " ";
        std::cout << std::dec << "\n";

        encrypted_chunks.push_back(std::move(chunk));
    }
}


void decryptText(
    std::vector<std::vector<uint8_t>>& encrypted_chunks,
    std::string& output_text,
    uint32_t* key_schedule
) {
    if (encrypted_chunks.size() < 2) {
        std::cerr << "[DECRYPT] Not enough chunks.\n";
        return;
    }

    // --- Extract IV ---
    uint8_t iv[16];
    if (encrypted_chunks[0].size() != 16) {
        std::cerr << "[DECRYPT] Invalid IV chunk size.\n";
        return;
    }
    std::memcpy(iv, encrypted_chunks[0].data(), 16);
    encrypted_chunks.erase(encrypted_chunks.begin());

    std::cout << "[DECRYPT] IV: ";
    for (int i = 0; i < 16; ++i)
        std::cout << std::hex << std::uppercase << (int)iv[i] << " ";
    std::cout << std::dec << "\n";

    // --- Extract Length ---
    if (encrypted_chunks[0].size() != 4) {
        std::cerr << "[DECRYPT] Invalid length chunk size.\n";
        return;
    }

    uint32_t declared_length;
    std::memcpy(&declared_length, encrypted_chunks[0].data(), 4);
    declared_length = ntohl(declared_length);
    encrypted_chunks.erase(encrypted_chunks.begin());

    std::cout << "[DECRYPT] Declared plaintext length: " << declared_length << "\n";

    // --- Rebuild ciphertext ---
    std::vector<uint8_t> ciphertext;
    for (size_t i = 0; i < encrypted_chunks.size(); ++i) {
        std::cout << "[DECRYPT] Ciphertext Chunk " << i << ": ";
        for (uint8_t b : encrypted_chunks[i])
            std::cout << std::hex << std::uppercase << (int)b << " ";
        std::cout << std::dec << "\n";

        ciphertext.insert(ciphertext.end(), encrypted_chunks[i].begin(), encrypted_chunks[i].end());
    }

    if (ciphertext.size() < declared_length) {
        std::cerr << "[DECRYPT] Ciphertext shorter than declared length.\n";
        return;
    }

    std::vector<uint8_t> plaintext(declared_length);
    AES_CTR_crypt(ciphertext.data(), plaintext.data(), declared_length, key_schedule, iv);

    output_text.assign(plaintext.begin(), plaintext.end());

}

