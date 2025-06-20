CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wno-missing-braces
SRC_DIR = Cryptography


all: server client

server: server.cpp $(SRC_DIR)/AES.cpp $(SRC_DIR)/example.cpp
	$(CXX) $(CXXFLAGS) -o server server.cpp $(SRC_DIR)/AES.cpp $(SRC_DIR)/example.cpp

client: client.cpp $(SRC_DIR)/AES.cpp $(SRC_DIR)/example.cpp
	$(CXX) $(CXXFLAGS) -o client client.cpp $(SRC_DIR)/AES.cpp $(SRC_DIR)/example.cpp

clean:
	rm client server
