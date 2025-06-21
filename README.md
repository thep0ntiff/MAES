# 🔐 MAES — More AES Encryption Library

MAES is a lightweight C++ implementation of the **Advanced Encryption Standard (AES-ECB)**, built for learning, customization, and experimentation. It includes a simple **client-server chat application** that demonstrates encryption and decryption in real-time using your custom AES routines.

---

## 🚀 Features

- 📦 AES-ECB encryption and decryption
- 💬 Example client-server chat application
- 🧪 Chunk-based processing with debug output
- 🧰 Pure C++ — no external dependencies
- 🔍 Built-in debugging with hex dumps

---

## 🧠 How It Works

- Plaintext is split into 16-byte blocks
- Each block is encrypted using a custom `Encrypt()` function
- Encrypted blocks are transmitted or stored
- On the receiving side, blocks are decrypted with `Decrypt()`

```cpp
// Encrypt a message
Encrypt(chunk, ciphertext, key_schedule, 256);

// Decrypt a message
Decrypt(ciphertext, decrypted_chunk, key_schedule, 256);
```
## Usage

- If you just want the Library, just download the Cryptopgraphy folder.
- If you want to see it in action, compile everything with "make", then start both the server and client on seperate terminals.
- Type something and get automatic debug-messages about the encryption/decryption process.
