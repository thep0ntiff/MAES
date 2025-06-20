#include "AES.cpp"
#include <ios>
#include <iostream>
#include <string>
#include <vector>

void encryptText(const std::string& input_text, 
                 std::vector<std::vector<uint8_t> >& encrypted_chunks,
                 uint32_t* key_schedule) {
    // Split input_text into 16-byte chunks and encrypt each chunk - Encryption starts here
    std::cout << "Starting encryption..." << std::endl;
    for (size_t i = 0; i < input_text.size(); i += 16) {
        uint8_t chunk[16] = {0}; // Initialize with zeros
        
        // Copy up to 16 characters from input_text to the chunk
        std::memcpy(chunk, input_text.data() + i, std::min(16, (int)(input_text.size() - i)));
        
        std::cout << "Plaintext Chunk:" << i / 16 << ": ";
        for (int j = 0; j < 16; ++j) std::cout << std::hex << (int)chunk[j] << " ";
        std::cout << std::endl;

        // Encrypt the chunk
        uint8_t ciphertext[16] = {0};
        Encrypt(chunk, ciphertext, key_schedule, 256);
        
        std::cout << "Encrypted Chunk: " << i / 16 << ": ";
        for (int j = 0; j < 16; ++j) std::cout << std::hex << (int)ciphertext[j] << " ";
        std::cout << std::endl;
        
        // Store the encrypted chunk
        encrypted_chunks.push_back(std::vector<uint8_t>(ciphertext, ciphertext + 16));
    }
}

void decryptText(std::vector<std::vector<uint8_t> >& encrypted_chunks,
                 std::string& output_text, 
                 uint32_t* key_schedule) {

    std::cout << "Starting decryption..." << std::endl;
    
    // Decrypt each chunk and reassemble the text
    for (size_t i = 0; i < encrypted_chunks.size(); ++i) {
        uint8_t decrypted_chunk[16] = {0};
        
        // Decrypt the chunk
        Decrypt(encrypted_chunks[i].data(), decrypted_chunk, key_schedule, 256);
        
        std::cout << "Decrypted Chunk: " << i << ": ";
        for (int j = 0; j < 16; ++j) std::cout << std::hex << (int)decrypted_chunk[j] << " ";
        std::cout << std::endl;
        
        // Append the decrypted chunk to the output text
        output_text.append(reinterpret_cast<char*>(decrypted_chunk), 16);
    }
}

