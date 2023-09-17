#include <cstdint>
#include <cassert>
#include <cstdlib>
#include <string>

extern "C"
{

using u32 = uint32_t;
using u8 = uint8_t;

typedef union
{
    u32 u[16];
    u8 c[64];
} chacha_buf;

# define ROTATE(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

/* QUARTERROUND updates a, b, c, d with a ChaCha "quarter" round. */
# define QUARTERROUND(a,b,c,d) ( \
                x[a] += x[b], x[d] = ROTATE((x[d] ^ x[a]),16), \
                x[c] += x[d], x[b] = ROTATE((x[b] ^ x[c]),12), \
                x[a] += x[b], x[d] = ROTATE((x[d] ^ x[a]), 8), \
                x[c] += x[d], x[b] = ROTATE((x[b] ^ x[c]), 7)  )

# ifndef PEDANTIC
#  if defined(__GNUC__) && __GNUC__>=2 && \
      !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
#   if defined(__riscv_zbb) || defined(__riscv_zbkb)
#    if __riscv_xlen == 64
#    undef ROTATE
#    define ROTATE(x, n) ({ u32 ret;                   \
                        asm ("roriw %0, %1, %2"        \
                        : "=r"(ret)                    \
                        : "r"(x), "i"(32 - (n))); ret;})
#    endif
#    if __riscv_xlen == 32
#    undef ROTATE
#    define ROTATE(x, n) ({ u32 ret;                   \
                        asm ("rori %0, %1, %2"         \
                        : "=r"(ret)                    \
                        : "r"(x), "i"(32 - (n))); ret;})
#    endif
#   endif
#  endif
# endif

/*
 * This code does basic character mapping for IBM's TPF and OS/390 operating
 * systems. It is a modified version of the BS2000 table.
 *
 * Bijective EBCDIC (character set IBM-1047) to US-ASCII table: This table is
 * bijective - there are no ambiguous or duplicate characters.
 */
const unsigned char os_toascii[256] = {
    0x00, 0x01, 0x02, 0x03, 0x85, 0x09, 0x86, 0x7f, /* 00-0f: */
    0x87, 0x8d, 0x8e, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, /* ................ */
    0x10, 0x11, 0x12, 0x13, 0x8f, 0x0a, 0x08, 0x97, /* 10-1f: */
    0x18, 0x19, 0x9c, 0x9d, 0x1c, 0x1d, 0x1e, 0x1f, /* ................ */
    0x80, 0x81, 0x82, 0x83, 0x84, 0x92, 0x17, 0x1b, /* 20-2f: */
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x05, 0x06, 0x07, /* ................ */
    0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04, /* 30-3f: */
    0x98, 0x99, 0x9a, 0x9b, 0x14, 0x15, 0x9e, 0x1a, /* ................ */
    0x20, 0xa0, 0xe2, 0xe4, 0xe0, 0xe1, 0xe3, 0xe5, /* 40-4f: */
    0xe7, 0xf1, 0xa2, 0x2e, 0x3c, 0x28, 0x2b, 0x7c, /* ...........<(+| */
    0x26, 0xe9, 0xea, 0xeb, 0xe8, 0xed, 0xee, 0xef, /* 50-5f: */
    0xec, 0xdf, 0x21, 0x24, 0x2a, 0x29, 0x3b, 0x5e, /* &.........!$*);^ */
    0x2d, 0x2f, 0xc2, 0xc4, 0xc0, 0xc1, 0xc3, 0xc5, /* 60-6f: */
    0xc7, 0xd1, 0xa6, 0x2c, 0x25, 0x5f, 0x3e, 0x3f, /* -/.........,%_>? */
    0xf8, 0xc9, 0xca, 0xcb, 0xc8, 0xcd, 0xce, 0xcf, /* 70-7f: */
    0xcc, 0x60, 0x3a, 0x23, 0x40, 0x27, 0x3d, 0x22, /* .........`:#@'=" */
    0xd8, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* 80-8f: */
    0x68, 0x69, 0xab, 0xbb, 0xf0, 0xfd, 0xfe, 0xb1, /* .abcdefghi...... */
    0xb0, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, /* 90-9f: */
    0x71, 0x72, 0xaa, 0xba, 0xe6, 0xb8, 0xc6, 0xa4, /* .jklmnopqr...... */
    0xb5, 0x7e, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, /* a0-af: */
    0x79, 0x7a, 0xa1, 0xbf, 0xd0, 0x5b, 0xde, 0xae, /* .~stuvwxyz...[.. */
    0xac, 0xa3, 0xa5, 0xb7, 0xa9, 0xa7, 0xb6, 0xbc, /* b0-bf: */
    0xbd, 0xbe, 0xdd, 0xa8, 0xaf, 0x5d, 0xb4, 0xd7, /* .............].. */
    0x7b, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, /* c0-cf: */
    0x48, 0x49, 0xad, 0xf4, 0xf6, 0xf2, 0xf3, 0xf5, /* {ABCDEFGHI...... */
    0x7d, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, /* d0-df: */
    0x51, 0x52, 0xb9, 0xfb, 0xfc, 0xf9, 0xfa, 0xff, /* }JKLMNOPQR...... */
    0x5c, 0xf7, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, /* e0-ef: */
    0x59, 0x5a, 0xb2, 0xd4, 0xd6, 0xd2, 0xd3, 0xd5, /* \.STUVWXYZ...... */
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* f0-ff: */
    0x38, 0x39, 0xb3, 0xdb, 0xdc, 0xd9, 0xda, 0x9f /* 0123456789...... */
};

/*
 * The US-ASCII to EBCDIC (character set IBM-1047) table: This table is
 * bijective (no ambiguous or duplicate characters)
 */
const unsigned char os_toebcdic[256] = {
    0x00, 0x01, 0x02, 0x03, 0x37, 0x2d, 0x2e, 0x2f, /* 00-0f: */
    0x16, 0x05, 0x15, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, /* ................ */
    0x10, 0x11, 0x12, 0x13, 0x3c, 0x3d, 0x32, 0x26, /* 10-1f: */
    0x18, 0x19, 0x3f, 0x27, 0x1c, 0x1d, 0x1e, 0x1f, /* ................ */
    0x40, 0x5a, 0x7f, 0x7b, 0x5b, 0x6c, 0x50, 0x7d, /* 20-2f: */
    0x4d, 0x5d, 0x5c, 0x4e, 0x6b, 0x60, 0x4b, 0x61, /* !"#$%&'()*+,-./ */
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, /* 30-3f: */
    0xf8, 0xf9, 0x7a, 0x5e, 0x4c, 0x7e, 0x6e, 0x6f, /* 0123456789:;<=>? */
    0x7c, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, /* 40-4f: */
    0xc8, 0xc9, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, /* @ABCDEFGHIJKLMNO */
    0xd7, 0xd8, 0xd9, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, /* 50-5f: */
    0xe7, 0xe8, 0xe9, 0xad, 0xe0, 0xbd, 0x5f, 0x6d, /* PQRSTUVWXYZ[\]^_ */
    0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, /* 60-6f: */
    0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, /* `abcdefghijklmno */
    0x97, 0x98, 0x99, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, /* 70-7f: */
    0xa7, 0xa8, 0xa9, 0xc0, 0x4f, 0xd0, 0xa1, 0x07, /* pqrstuvwxyz{|}~. */
    0x20, 0x21, 0x22, 0x23, 0x24, 0x04, 0x06, 0x08, /* 80-8f: */
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x09, 0x0a, 0x14, /* ................ */
    0x30, 0x31, 0x25, 0x33, 0x34, 0x35, 0x36, 0x17, /* 90-9f: */
    0x38, 0x39, 0x3a, 0x3b, 0x1a, 0x1b, 0x3e, 0xff, /* ................ */
    0x41, 0xaa, 0x4a, 0xb1, 0x9f, 0xb2, 0x6a, 0xb5, /* a0-af: */
    0xbb, 0xb4, 0x9a, 0x8a, 0xb0, 0xca, 0xaf, 0xbc, /* ................ */
    0x90, 0x8f, 0xea, 0xfa, 0xbe, 0xa0, 0xb6, 0xb3, /* b0-bf: */
    0x9d, 0xda, 0x9b, 0x8b, 0xb7, 0xb8, 0xb9, 0xab, /* ................ */
    0x64, 0x65, 0x62, 0x66, 0x63, 0x67, 0x9e, 0x68, /* c0-cf: */
    0x74, 0x71, 0x72, 0x73, 0x78, 0x75, 0x76, 0x77, /* ................ */
    0xac, 0x69, 0xed, 0xee, 0xeb, 0xef, 0xec, 0xbf, /* d0-df: */
    0x80, 0xfd, 0xfe, 0xfb, 0xfc, 0xba, 0xae, 0x59, /* ................ */
    0x44, 0x45, 0x42, 0x46, 0x43, 0x47, 0x9c, 0x48, /* e0-ef: */
    0x54, 0x51, 0x52, 0x53, 0x58, 0x55, 0x56, 0x57, /* ................ */
    0x8c, 0x49, 0xcd, 0xce, 0xcb, 0xcf, 0xcc, 0xe1, /* f0-ff: */
    0x70, 0xdd, 0xde, 0xdb, 0xdc, 0x8d, 0x8e, 0xdf /* ................ */
};

# if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
#  define DECLARE_IS_ENDIAN const int ossl_is_little_endian = __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define IS_LITTLE_ENDIAN (ossl_is_little_endian)
#  define IS_BIG_ENDIAN (!ossl_is_little_endian)
#  if defined(L_ENDIAN) && (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#   error "L_ENDIAN defined on a big endian machine"
#  endif
#  if defined(B_ENDIAN) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#   error "B_ENDIAN defined on a little endian machine"
#  endif
#  if !defined(L_ENDIAN) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#   define L_ENDIAN
#  endif
#  if !defined(B_ENDIAN) && (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#   define B_ENDIAN
#  endif
# else
#  define DECLARE_IS_ENDIAN \
    const union { \
        long one; \
        char little; \
    } ossl_is_endian = { 1 }

#  define IS_LITTLE_ENDIAN (ossl_is_endian.little != 0)
#  define IS_BIG_ENDIAN    (ossl_is_endian.little == 0)
# endif

# define U32TO8_LITTLE(p, v) do { \
                                (p)[0] = (u8)(v >>  0); \
                                (p)[1] = (u8)(v >>  8); \
                                (p)[2] = (u8)(v >> 16); \
                                (p)[3] = (u8)(v >> 24); \
                                } while(0)

int ossl_toascii( int c )
{
    if( c < -128 || c > 256 || c == EOF )
        return c;
    /*
     * Adjust negatively signed characters.
     * This is not required for ASCII because any character that sign extends
     * is not seven bit and all of the checks are on the seven bit characters.
     * I.e. any check must fail on sign extension.
     */
    if( c < 0 )
        c += 256;
    return os_toascii[c];
}

/* chacha_core performs 20 rounds of ChaCha on the input words in
 * |input| and writes the 64 output bytes to |output|. */
static void chacha20_core( chacha_buf* output, const u32 input[16] )
{
    u32 x[16];
    int i;
    DECLARE_IS_ENDIAN;

    memcpy( x, input, sizeof( x ) );

    for( i = 20; i > 0; i -= 2 )
    {
        QUARTERROUND( 0, 4, 8, 12 );
        QUARTERROUND( 1, 5, 9, 13 );
        QUARTERROUND( 2, 6, 10, 14 );
        QUARTERROUND( 3, 7, 11, 15 );
        QUARTERROUND( 0, 5, 10, 15 );
        QUARTERROUND( 1, 6, 11, 12 );
        QUARTERROUND( 2, 7, 8, 13 );
        QUARTERROUND( 3, 4, 9, 14 );
    }

    if( IS_LITTLE_ENDIAN )
    {
        for( i = 0; i < 16; ++i )
            output->u[i] = x[i] + input[i];
    }
    else
    {
        for( i = 0; i < 16; ++i )
            U32TO8_LITTLE( output->c + 4 * i, ( x[i] + input[i] ) );
    }
}

/**
 * This function is from openssl source
 */
void ChaCha20_ctr32( unsigned char* out, const unsigned char* inp,
    size_t len, const unsigned int key[8],
    const unsigned int counter[4] )
{
    u32 input[16];
    chacha_buf buf;
    size_t todo, i;

    /* sigma constant "expand 32-byte k" in little-endian encoding */
    input[0] = ( ( u32 )ossl_toascii( 'e' ) ) | ( ( u32 )ossl_toascii( 'x' ) << 8 )
        | ( ( u32 )ossl_toascii( 'p' ) << 16 )
        | ( ( u32 )ossl_toascii( 'a' ) << 24 );
    input[1] = ( ( u32 )ossl_toascii( 'n' ) ) | ( ( u32 )ossl_toascii( 'd' ) << 8 )
        | ( ( u32 )ossl_toascii( ' ' ) << 16 )
        | ( ( u32 )ossl_toascii( '3' ) << 24 );
    input[2] = ( ( u32 )ossl_toascii( '2' ) ) | ( ( u32 )ossl_toascii( '-' ) << 8 )
        | ( ( u32 )ossl_toascii( 'b' ) << 16 )
        | ( ( u32 )ossl_toascii( 'y' ) << 24 );
    input[3] = ( ( u32 )ossl_toascii( 't' ) ) | ( ( u32 )ossl_toascii( 'e' ) << 8 )
        | ( ( u32 )ossl_toascii( ' ' ) << 16 )
        | ( ( u32 )ossl_toascii( 'k' ) << 24 );

    input[4] = key[0];
    input[5] = key[1];
    input[6] = key[2];
    input[7] = key[3];
    input[8] = key[4];
    input[9] = key[5];
    input[10] = key[6];
    input[11] = key[7];

    input[12] = counter[0];
    input[13] = counter[1];
    input[14] = counter[2];
    input[15] = counter[3];

    while( len > 0 )
    {
        todo = sizeof( buf );
        if( len < todo )
            todo = len;

        chacha20_core( &buf, input );

        for( i = 0; i < todo; i++ )
            out[i] = inp[i] ^ buf.c[i];
        out += todo;
        inp += todo;
        len -= todo;

        /*
         * Advance 32-bit counter. Note that as subroutine is so to
         * say nonce-agnostic, this limited counter width doesn't
         * prevent caller from implementing wider counter. It would
         * simply take two calls split on counter overflow...
         */
        input[12]++;
    }
}

void chacha20_poly1305_open(uint8_t* out_plaintext,
    const uint8_t* ciphertext,
    size_t plaintext_len, const uint8_t* ad,
    size_t ad_len,
    union chacha20_poly1305_open_data* data)
{
    /**
     * Where is the c code for this function? please tell me
     */
    abort();
}

void chacha20_poly1305_seal(uint8_t* out_ciphertext,
    const uint8_t* plaintext,
    size_t plaintext_len, const uint8_t* ad,
    size_t ad_len,
    union chacha20_poly1305_seal_data* data)
{
    /**
     * Where is the c code for this function? please tell me
     */
    abort();
}

}
