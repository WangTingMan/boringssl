#include <cstdint>
#include <cassert>
#include <cstdlib>

extern "C"
{

void ChaCha20_ctr32(uint8_t* out, const uint8_t* in, size_t in_len,
    const uint32_t key[8], const uint32_t counter[4])
{
    abort();
}

void chacha20_poly1305_open(uint8_t* out_plaintext,
    const uint8_t* ciphertext,
    size_t plaintext_len, const uint8_t* ad,
    size_t ad_len,
    union chacha20_poly1305_open_data* data)
{
    abort();
}

void chacha20_poly1305_seal(uint8_t* out_ciphertext,
    const uint8_t* plaintext,
    size_t plaintext_len, const uint8_t* ad,
    size_t ad_len,
    union chacha20_poly1305_seal_data* data)
{
    abort();
}

}
