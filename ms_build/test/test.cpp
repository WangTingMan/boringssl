#include <openssl/digest.h>
#include <openssl/hmac.h>

#include <array>
#include <iostream>

static constexpr unsigned int kOctet32Length = 32;

int main()
{
    std::array<uint8_t, kOctet32Length> salt_256bit_;
    static constexpr unsigned int kLength = 6;
    std::array<uint8_t, EVP_MAX_MD_SIZE> result = {};
    uint8_t address[kLength];
    for (uint8_t i = 0; i < kLength; ++i)
    {
        address[i] = i;
    }

    unsigned int out_len = 0;
    const EVP_MD* p = EVP_sha256();
    ::HMAC(p, salt_256bit_.data(), salt_256bit_.size(),
        address, kLength, result.data(),
        &out_len);

    std::cout << "Hello World!\n";
}

