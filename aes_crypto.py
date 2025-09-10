# AES in Python Using cryptography Library
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Generate a 256-bit (32-byte) key
key = os.urandom(32)

# Generate a 128-bit (16-byte) IV
iv = os.urandom(16)

# Create cipher object using AES CBC mode
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()

# Example plaintext (must be a multiple of 16 bytes for CBC)
plaintext = b"This is 32 bytes long message!!"  # 32 bytes
# Padding manually for AES CBC mode
while len(plaintext) % 16 != 0:
    plaintext += b' '

# Encrypt
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

# Decrypt
decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

# Output
print("Key:", key.hex())
print("IV:", iv.hex())
print("Plaintext:", plaintext)
print("Ciphertext (hex):", ciphertext.hex())
print("Decrypted text:", decrypted_text)
