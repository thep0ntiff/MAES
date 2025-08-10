#include <cstdint>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <thread>
#include "include/crypt.h"


#define PORT 8080

std::vector<std::vector<uint8_t> > encrypted_chunks;

uint8_t key[32] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,
                        0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,
                        0x1b,0x1c,0x1d,0x1e,0x1f }; //TODO: Use a secure key management system

uint32_t key_schedule[60];

void handle_send(int socket) {
    std::string message;
    KeyExpansion(key, key_schedule, 256);

    while (true) {
        std::cout << "Server: ";
        std::getline(std::cin, message);

        encrypted_chunks.clear();

        encryptText(message, encrypted_chunks, key_schedule);
        
        std::vector<uint8_t> flat_buffer;
        
        for (const auto& chunk : encrypted_chunks) {
            flat_buffer.insert(flat_buffer.end(), chunk.begin(), chunk.end());
        }
        send(socket, flat_buffer.data(), flat_buffer.size(), 0);    
        
    }
}

void handle_recv(int socket) {
    const int buffer_size = 4096;
    uint8_t buffer[buffer_size] = {0};
    std::string decrypted_message;

    while (true) {
        int valread = read(socket, buffer, buffer_size);
        if (valread > 0) {
            std::vector<std::vector<uint8_t>> encrypted_chunks;

            if (valread < 20) {
                std::cerr << "[DECRYPT] Not enough data.\n";
                continue;
            }

            // 1. Extract IV (first 16 bytes)
            encrypted_chunks.emplace_back(buffer, buffer + 16);

            // 2. Extract length (next 4 bytes)
            encrypted_chunks.emplace_back(buffer + 16, buffer + 20);

            // 3. Remaining = ciphertext chunks
            for (int i = 20; i < valread; i += 16) {
                int chunk_size = std::min(16, valread - i);
                encrypted_chunks.emplace_back(buffer + i, buffer + i + chunk_size);
            }

            decryptText(encrypted_chunks, decrypted_message, key_schedule);

            std::cout << "\r\033[K";
            std::cout << "Client: " << decrypted_message << std::endl;
            std::cout << "Server: " << std::flush;

            decrypted_message.clear();
        }
    }
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int opt = 1;

    // Create a socket file descriptor
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket creation error");
        return -1;
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
        close(server_fd);
        return -1;
    }
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEPORT failed");
        close(server_fd);
        return -1;
    }

    // Define the server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket to the address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return -1;
    }

    // Start listening for connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        return -1;
    }

    std::cout << "Server is listening on port " << PORT << std::endl;

    // Accept a connection
    new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
    if (new_socket < 0) {
        perror("Accept failed");
        close(server_fd);
        return -1;
    }

    std::thread send_thread(handle_send, new_socket);
    std::thread receive_thread(handle_recv, new_socket);

    send_thread.join();
    receive_thread.join();

    // Close the sockets
    close(new_socket);
    close(server_fd);
    return 0;
}
