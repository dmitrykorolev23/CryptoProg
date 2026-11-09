#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>

#include <iostream>
#include <string>

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cerr << "Использование: " << argv[0]
                  << " <имя файла>\n";
        return 1;
    }

    try {
        std::string digest;
        CryptoPP::SHA256 hash;

        CryptoPP::FileSource source(
            argv[1],
            true,
            new CryptoPP::HashFilter(
                hash,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(digest),
                    false
                )
            )
        );

        std::cout << digest << '\n';
    }
    catch (const CryptoPP::Exception& error) {
        std::cerr << "Ошибка хеширования: "
                  << error.what() << '\n';
        return 1;
    }

    return 0;
}
