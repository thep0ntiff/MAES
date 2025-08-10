#include "MAES/include/client.h"
#include "include/crypt.h"


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

        // Flatten and send all chunks in one write
        std::vector<uint8_t> flat_buffer;
        for (const auto& chunk : encrypted_chunks)
            flat_buffer.insert(flat_buffer.end(), chunk.begin(), chunk.end());

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

            if (valread < 20) { // IV (16) + length (4)
                std::cerr << "[DECRYPT] Not enough data received.\n";
                continue;
            }

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
