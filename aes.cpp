#include <iostream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;

int main() {
    std::string plaintext = "Crypto++ AES Demo";
    std::string ciphertext, decryptedtext;

    // Key and IV
    byte key[AES::DEFAULT_KEYLENGTH] = {0x00};
    byte iv[AES::BLOCKSIZE] = {0x00};

    // Encrypt
    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, sizeof(key), iv);
    StringSource(plaintext, true,
        new StreamTransformationFilter(encryptor,
            new StringSink(ciphertext)
        )
    );

    // Decrypt
    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, sizeof(key), iv);
    StringSource(ciphertext, true,
        new StreamTransformationFilter(decryptor,
            new StringSink(decryptedtext)
        )
    );

    // Output
    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Encrypted (hex): ";
    StringSource(ciphertext, true, new HexEncoder(new FileSink(std::cout)));
    std::cout << "\nDecrypted: " << decryptedtext << std::endl;

    return 0;
}
