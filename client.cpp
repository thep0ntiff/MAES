#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include "Cryptography/example.cpp"

#define PORT 8080

std::vector<std::vector<uint8_t> > encrypted_chunks;

uint8_t key[32] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,
                        0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,
                        0x1b,0x1c,0x1d,0x1e,0x1f };

uint32_t key_schedule[60];

void handle_send(int socket) {
    std::string message;
    KeyExpansion(key, key_schedule, 256);

    while (true) {
        std::cout << "Client: ";
        std::getline(std::cin, message);

        encrypted_chunks.clear();

        encryptText(message, encrypted_chunks, key_schedule);

        for (const auto& chunk : encrypted_chunks) {
            send(socket, chunk.data(), chunk.size(), 0);    
        }
    }
}

void handle_recv(int socket) {
    const int blocksize = 16; // AES block size
    char buffer[1024] = {0}; // Buffer for incoming encrypted data
    std::string decrypted_message; // String to hold the decrypted message
    std::vector<std::vector<uint8_t> > encrypted_chunks; // Vector to hold the encrypted chunks

    while (true) {
        int valread = read(socket, buffer, 1024);
        if (valread > 0) {
            encrypted_chunks.clear(); // Clear previous chunks

            // Process the buffer in blocksize chunks
            for (int i = 0; i < valread; i += blocksize) {
                int chunk_size = std::min(blocksize, valread - i);

                // Create a new chunk and copy data into it
                std::vector<uint8_t> chunk(blocksize, 0);
                std::memcpy(chunk.data(), buffer + i, chunk_size);

                // Add the chunk to the list of encrypted chunks
                encrypted_chunks.push_back(chunk);
            }

            // Decrypt the collected chunks
            decryptText(encrypted_chunks, decrypted_message, key_schedule);

            std::cout << "\r\033[K";
            // Display the decrypted message
            std::cout << "Server: " << decrypted_message << std::endl;
            std::cout << "CLient: " << std::flush;

            // Clear the decrypted message for the next iteration
            decrypted_message.clear();

            usleep(100000);
        }
    }
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;

    // Creating socket file descriptor
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address or Address not supported" << std::endl;
        return -1;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        return -1;
    }

    std::thread send_thread(handle_send, sock);
    std::thread recv_thread(handle_recv, sock);

    send_thread.join();
    recv_thread.join();

    // Close the socket
    close(sock);
    return 0;
}
