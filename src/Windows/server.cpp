#include <cstdint>
#include <iostream>
#include <cstring>
#include <thread>
#include <algorithm>
#include "server.h"
#include "crypt.h"

#include <cstdint>
#include <iostream>
#include <cstring>
#include <thread>
#include <vector>
#include <string>
#include <algorithm>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "server.h"
#include "crypt.h"

// Note: When using MinGW/GCC, add -lws2_32 to your linker flags
// #pragma comment(lib, "ws2_32.lib") // Only works with MSVC

#define PORT 8080

std::vector<std::vector<uint8_t> > encrypted_chunks;

uint8_t key[32] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,
                        0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,
                        0x1b,0x1c,0x1d,0x1e,0x1f };

uint32_t key_schedule[60];

void handle_send(SOCKET socket) {
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
        // Send all data, handling partial sends
        size_t total_sent = 0;
        size_t total_size = flat_buffer.size();
        while (total_sent < total_size) {
            int bytes_sent = send(socket, reinterpret_cast<const char*>(flat_buffer.data() + total_sent), 
                                static_cast<int>(total_size - total_sent), 0);
            if (bytes_sent == SOCKET_ERROR) {
                std::cerr << "Send failed with error: " << WSAGetLastError() << std::endl;
                break;
            }
            total_sent += bytes_sent;
        }
    }
}

void handle_recv(SOCKET socket) {
    const int buffer_size = 4096;
    uint8_t buffer[buffer_size] = {0};
    std::string decrypted_message;

    while (true) {
        // Clear buffer before each receive
        memset(buffer, 0, buffer_size);
        int valread = recv(socket, reinterpret_cast<char*>(buffer), buffer_size, 0);
        if (valread > 0) {
            std::vector<std::vector<uint8_t>> encrypted_chunks;

            if (valread < 20) {
                std::cerr << "[DECRYPT] Not enough data: " << valread << " bytes\n";
                continue;
            }

            // Debug: Print first few bytes of what we received
            std::cout << "Raw received bytes (first 25): ";
            for (int i = 0; i < std::min(25, valread); i++) {
                std::printf("%02X ", buffer[i]);
            }
            std::cout << std::endl;

            // Debug: Print received data size
            std::cout << "\n[DEBUG] Received " << valread << " bytes" << std::endl;

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
        else if (valread == 0) {
            std::cout << "Client disconnected." << std::endl;
            break;
        }
        else {
            std::cerr << "recv failed with error: " << WSAGetLastError() << std::endl;
            break;
        }
    }
}

int main() {
    WSADATA wsaData;
    SOCKET server_fd = INVALID_SOCKET, new_socket = INVALID_SOCKET;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int opt = 1;

    // Initialize Winsock
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        std::cerr << "WSAStartup failed with error: " << wsaResult << std::endl;
        return -1;
    }

    // Create a socket file descriptor
    server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_fd == INVALID_SOCKET) {
        std::cerr << "Socket creation error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return -1;
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt)) == SOCKET_ERROR) {
        std::cerr << "setsockopt SO_REUSEADDR failed with error: " << WSAGetLastError() << std::endl;
        closesocket(server_fd);
        WSACleanup();
        return -1;
    }

    // Note: SO_REUSEPORT is not available on Windows, so we skip it

    // Define the server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket to the address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR) {
        std::cerr << "Bind failed with error: " << WSAGetLastError() << std::endl;
        closesocket(server_fd);
        WSACleanup();
        return -1;
    }

    // Start listening for connections
    if (listen(server_fd, 3) == SOCKET_ERROR) {
        std::cerr << "Listen failed with error: " << WSAGetLastError() << std::endl;
        closesocket(server_fd);
        WSACleanup();
        return -1;
    }

    std::cout << "Server is listening on port " << PORT << std::endl;

    // Accept a connection
    new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen);
    if (new_socket == INVALID_SOCKET) {
        std::cerr << "Accept failed with error: " << WSAGetLastError() << std::endl;
        closesocket(server_fd);
        WSACleanup();
        return -1;
    }

    std::cout << "Client connected!" << std::endl;

    std::thread send_thread([new_socket]() { handle_send(new_socket); });
    std::thread receive_thread([new_socket]() { handle_recv(new_socket); });

    send_thread.join();
    receive_thread.join();

    // Close the sockets and cleanup Winsock
    closesocket(new_socket);
    closesocket(server_fd);
    WSACleanup();
    return 0;
}