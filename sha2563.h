#ifndef SHA256_H
#define SHA256_H
#include <string>
 
class SHA256
{
protected:
    typedef unsigned char uint8;
    typedef unsigned int uint32;
    typedef unsigned long long uint64;
 
    const static uint32 sha256_k[];
    static const unsigned int SHA224_256_BLOCK_SIZE = (512/8);
    static const unsigned int MEM_LIMIT = 10000;
public:
    void init();
    void update(unsigned char *message, unsigned int len, unsigned char* digest);
    void rev_update(unsigned char *message, unsigned int len, unsigned char *digest);
    void pop(unsigned int* a);
    void push(unsigned int* a);  
    static const unsigned int DIGEST_SIZE = ( 256 / 8);
    uint32 mem[MEM_LIMIT];
    uint32 smem[MEM_LIMIT];
    unsigned char *pmem[MEM_LIMIT];
 
protected:
    void transform(unsigned char *message, unsigned int block_nb);
    void rev_transform();
    unsigned int m_tot_len;
    unsigned int m_len;
    unsigned int lp, pp, sp;
    unsigned char *m_block;
    uint32 m_h[8];
    uint32 w[64];
    uint32 wv[8];
    uint32 t1, t2;
};
 
std::string sha256(std::string input);
 
#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))
#define SHA2_UNPACK32(x, str)                 \
{                                             \
    *((str) + 3) = (uint8) ((x)      );       \
    *((str) + 2) = (uint8) ((x) >>  8);       \
    *((str) + 1) = (uint8) ((x) >> 16);       \
    *((str) + 0) = (uint8) ((x) >> 24);       \
}
#define REV_SHA2_UNPACK32(x, str)                 \
{                                             \
    *((str) + 3) -= (uint8) ((x)      );       \
    *((str) + 2) -= (uint8) ((x) >>  8);       \
    *((str) + 1) -= (uint8) ((x) >> 16);       \
    *((str) + 0) -= (uint8) ((x) >> 24);       \
}
#define SHA2_PACK32(str, x)                   \
{                                             \
    *(x) =   ((uint32) *((str) + 3)      )    \
           | ((uint32) *((str) + 2) <<  8)    \
           | ((uint32) *((str) + 1) << 16)    \
           | ((uint32) *((str) + 0) << 24);   \
}
#define REV_SHA2_PACK32(str, x)                   \
{                                             \
    *(x) -=   ((uint32) *((str) + 3)      )    \
           | ((uint32) *((str) + 2) <<  8)    \
           | ((uint32) *((str) + 1) << 16)    \
           | ((uint32) *((str) + 0) << 24);   \
}
#endif