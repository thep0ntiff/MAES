CXX       := g++
INCLUDE_DIR := include
CXXFLAGS  := -std=c++17 -Wall -Wno-missing-braces -I$(INCLUDE_DIR) -I$(INCLUDE_DIR)/cryptography
SRC_DIR   := src/Cryptography
BIN_DIR   := bin

# Detect OS
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
    PLATFORM_DIR := src/Windows
    EXT := .exe
    RM := rm
    MKDIR := mkdir -p $(BIN_DIR)
    LINK_LIBS := -lws2_32
else
    DETECTED_OS := $(shell uname -s)
    PLATFORM_DIR := src/Unix
    EXT :=
    RM := rm -f
    MKDIR := mkdir -p $(BIN_DIR)
    LINK_LIBS := -lpthread
endif

COMMON_SRC := $(SRC_DIR)/AES.cpp \
              $(SRC_DIR)/AES_CTR.cpp \
              $(SRC_DIR)/crypt.cpp

SERVER_SRC := $(PLATFORM_DIR)/server.cpp
CLIENT_SRC := $(PLATFORM_DIR)/client.cpp

SERVER_BIN := $(BIN_DIR)/server$(EXT)
CLIENT_BIN := $(BIN_DIR)/client$(EXT)

all: $(SERVER_BIN) $(CLIENT_BIN)

$(SERVER_BIN): $(SERVER_SRC) $(COMMON_SRC)
	$(MKDIR)
	$(CXX) $(CXXFLAGS) -o $@ $(SERVER_SRC) $(COMMON_SRC) $(LINK_LIBS)

$(CLIENT_BIN): $(CLIENT_SRC) $(COMMON_SRC)
	$(MKDIR)
	$(CXX) $(CXXFLAGS) -o $@ $(CLIENT_SRC) $(COMMON_SRC) $(LINK_LIBS)

clean:
	$(RM) $(SERVER_BIN) $(CLIENT_BIN)

.PHONY: all clean