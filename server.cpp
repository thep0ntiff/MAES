#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
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
        std::cout << "Server: ";
        std::getline(std::cin, message);

        encrypted_chunks.clear();

        encryptText(message, encrypted_chunks, key_schedule);

        for (const auto& chunk : encrypted_chunks) {
            send(socket, chunk.data(), chunk.size(), 0);    
        }
    }
}

void handle_recv(int socket) {
    const int blocksize = 16;
    char buffer[1024] = {0};
    std::vector<std::vector<uint8_t> > encrypted_chunks;
    std::string decrypted_message;

    while (true) {
        int valread = read(socket, buffer, 1024);
        if (valread > 0) {
            encrypted_chunks.clear();
 
             for (int i = 0; i < valread; i += blocksize) {
                int chunk_size = std::min(blocksize, valread - i);

                std::vector<uint8_t> chunk(blocksize, 0);
                std::memcpy(chunk.data(), buffer + i, chunk_size);

                encrypted_chunks.push_back(chunk);
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
