#include "client.h"
#include "crypt.h"
#include <thread>
#include <algorithm>

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
        std::cout << "Client: ";
        std::getline(std::cin, message);

        encrypted_chunks.clear();
        encryptText(message, encrypted_chunks, key_schedule);

        // Flatten and send all chunks in one write
        std::vector<uint8_t> flat_buffer;
        for (const auto& chunk : encrypted_chunks)
            flat_buffer.insert(flat_buffer.end(), chunk.begin(), chunk.end());

            // Debug: Print first few bytes of what we're sending
            std::cout << "Sending " << flat_buffer.size() << " bytes:" << std::endl;
            std::cout << "First 20 bytes: ";
            for (size_t i = 0; i < std::min(size_t(20), flat_buffer.size()); i++) {
                std::printf("%02X ", flat_buffer[i]);
            }
            std::cout << std::endl;
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

            if (valread < 20) { // IV (16) + length (4)
                std::cerr << "[DECRYPT] Not enough data received: " << valread << " bytes\n";
                continue;
            }

            // Debug: Print received data size
            std::cout << "\n[DEBUG] Received " << valread << " bytes" << std::endl;

            // 1. Extract IV
            encrypted_chunks.emplace_back(buffer, buffer + 16);

            // 2. Extract length
            encrypted_chunks.emplace_back(buffer + 16, buffer + 20);

            // 3. Extract ciphertext chunks
            for (int i = 20; i < valread; i += 16) {
                int chunk_size = std::min(16, valread - i);
                encrypted_chunks.emplace_back(buffer + i, buffer + i + chunk_size);
            }

            // Decrypt
            decryptText(encrypted_chunks, decrypted_message, key_schedule);

            std::cout << "\r\033[K";
            std::cout << "Server: " << decrypted_message << std::endl;
            std::cout << "Client: " << std::flush;

            decrypted_message.clear();
        }
        else if (valread == 0) {
            std::cout << "Server disconnected." << std::endl;
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
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in serv_addr;

    // Initialize Winsock
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        std::cerr << "WSAStartup failed with error: " << wsaResult << std::endl;
        return -1;
    }

    // Creating socket file descriptor
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 address from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address or Address not supported" << std::endl;
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed with error: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    std::cout << "Connected to server!" << std::endl;

    std::thread send_thread([sock]() { handle_send(sock); });
    std::thread recv_thread([sock]() { handle_recv(sock); });

    send_thread.join();
    recv_thread.join();

    // Close the socket and cleanup Winsock
    closesocket(sock);
    WSACleanup();
    return 0;
}