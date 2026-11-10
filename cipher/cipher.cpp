#include <cryptopp/aes.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

constexpr std::size_t SALT_SIZE = 16;
constexpr unsigned int PBKDF2_ITERATIONS = 100000;

CryptoPP::SecByteBlock deriveKey(
    const std::string& password,
    const CryptoPP::SecByteBlock& salt)
{
    CryptoPP::SecByteBlock key(
        CryptoPP::AES::DEFAULT_KEYLENGTH
    );

    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;

    pbkdf.DeriveKey(
        key.data(),
        key.size(),
        0,
        reinterpret_cast<const CryptoPP::byte*>(password.data()),
        password.size(),
        salt.data(),
        salt.size(),
        PBKDF2_ITERATIONS
    );

    return key;
}

void encryptFile(
    const std::string& inputName,
    const std::string& outputName,
    const std::string& password)
{
    std::ifstream input(inputName, std::ios::binary);

    if (!input) {
        throw std::runtime_error(
            "не удалось открыть исходный файл"
        );
    }

    std::ofstream output(
        outputName,
        std::ios::binary | std::ios::trunc
    );

    if (!output) {
        throw std::runtime_error(
            "не удалось открыть выходной файл"
        );
    }

    CryptoPP::AutoSeededRandomPool random;
    CryptoPP::SecByteBlock salt(SALT_SIZE);
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);

    random.GenerateBlock(salt.data(), salt.size());
    random.GenerateBlock(iv.data(), iv.size());

    CryptoPP::SecByteBlock key = deriveKey(password, salt);

    output.write(
        reinterpret_cast<const char*>(salt.data()),
        static_cast<std::streamsize>(salt.size())
    );

    output.write(
        reinterpret_cast<const char*>(iv.data()),
        static_cast<std::streamsize>(iv.size())
    );

    if (!output) {
        throw std::runtime_error(
            "ошибка записи заголовка файла"
        );
    }

    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;

    encryption.SetKeyWithIV(
        key.data(),
        key.size(),
        iv.data(),
        iv.size()
    );

    CryptoPP::FileSource source(
        input,
        true,
        new CryptoPP::StreamTransformationFilter(
            encryption,
            new CryptoPP::FileSink(output)
        )
    );
}

void decryptFile(
    const std::string& inputName,
    const std::string& outputName,
    const std::string& password)
{
    std::ifstream input(inputName, std::ios::binary);

    if (!input) {
        throw std::runtime_error(
            "не удалось открыть зашифрованный файл"
        );
    }

    CryptoPP::SecByteBlock salt(SALT_SIZE);
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);

    input.read(
        reinterpret_cast<char*>(salt.data()),
        static_cast<std::streamsize>(salt.size())
    );

    input.read(
        reinterpret_cast<char*>(iv.data()),
        static_cast<std::streamsize>(iv.size())
    );

    if (!input) {
        throw std::runtime_error(
            "некорректный зашифрованный файл"
        );
    }

    std::ofstream output(
        outputName,
        std::ios::binary | std::ios::trunc
    );

    if (!output) {
        throw std::runtime_error(
            "не удалось открыть выходной файл"
        );
    }

    CryptoPP::SecByteBlock key = deriveKey(password, salt);

    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;

    decryption.SetKeyWithIV(
        key.data(),
        key.size(),
        iv.data(),
        iv.size()
    );

    CryptoPP::FileSource source(
        input,
        true,
        new CryptoPP::StreamTransformationFilter(
            decryption,
            new CryptoPP::FileSink(output)
        )
    );
}

int main(int argc, char* argv[])
{
    if (argc != 5) {
        std::cerr
            << "Использование:\n"
            << "  " << argv[0]
            << " encrypt <исходный файл> <выходной файл> <пароль>\n"
            << "  " << argv[0]
            << " decrypt <исходный файл> <выходной файл> <пароль>\n";

        return 1;
    }

    const std::string mode = argv[1];
    const std::string inputName = argv[2];
    const std::string outputName = argv[3];
    const std::string password = argv[4];

    if (inputName == outputName) {
        std::cerr
            << "Ошибка: исходный и выходной файлы должны отличаться.\n";
        return 1;
    }

    if (password.empty()) {
        std::cerr
            << "Ошибка: пароль не должен быть пустым.\n";
        return 1;
    }

    try {
        if (mode == "encrypt") {
            encryptFile(inputName, outputName, password);
            std::cout << "Файл успешно зашифрован.\n";
        }
        else if (mode == "decrypt") {
            decryptFile(inputName, outputName, password);
            std::cout << "Файл успешно расшифрован.\n";
        }
        else {
            std::cerr
                << "Ошибка: режим должен быть encrypt или decrypt.\n";
            return 1;
        }
    }
    catch (const CryptoPP::Exception& error) {
        std::cerr
            << "Ошибка Crypto++: "
            << error.what() << '\n';
        return 1;
    }
    catch (const std::exception& error) {
        std::cerr
            << "Ошибка: "
            << error.what() << '\n';
        return 1;
    }

    return 0;
}
