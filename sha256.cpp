#include <cstring>
#include <fstream>
#include "sha256.h"
#include <iostream>

using namespace std;
 
const unsigned int SHA256::sha256_k[64] = //UL = uint32
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
 
void SHA256::rev_transform()
{



    unsigned char *sub_block;
    uint32 i = 0;
    uint32 j = 0;

    pp--;
    sub_block = pmem[pp];
    pmem[pp] = 0; 

    lp--;
    for (i += mem[lp], mem[lp] -= i; i > 0; i--) {

        lp--;
        for (j += mem[lp], mem[lp] -= j; j > 0; j--) {
            m_h[j - 1] -= wv[j - 1];
        }

        lp--;
        for (j += mem[lp], mem[lp] -= j; j > 0; j--) {

            lp--;
            wv[0] -= t1 + t2;
            wv[0] += mem[lp];
            mem[lp] -= wv[0];

            lp--;
            wv[1] -= wv[0];
            wv[1] += mem[lp];
            mem[lp] -= wv[1];

            lp--;
            wv[2] -= wv[1];
            wv[2] += mem[lp];
            mem[lp] -= wv[2];
         
            lp--;
            wv[3] -= wv[2];
            wv[3] += mem[lp];
            mem[lp] -= wv[3];

            lp--;
            wv[4] -= wv[3] + t1;
            wv[4] += mem[lp];
            mem[lp] -= wv[4];

            lp--;
            wv[5] -= wv[4];
            wv[5] += mem[lp];
            mem[lp] -= wv[5];

            lp--;
            wv[6] -= wv[5];
            wv[6] += mem[lp];
            mem[lp] -= wv[6];

            lp--;
            wv[7] -= wv[6];
            wv[7] += mem[lp];
            mem[lp] -= wv[7];

            lp--;
            t2 -= SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            t2 += mem[lp];
            mem[lp] -= t2;

            lp--;
            t1 -= wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
                + sha256_k[j - 1] + w[j - 1];
            t1 += mem[lp];
            mem[lp] -= t1;

        }

        lp--;
        for (j += mem[lp], mem[lp] -= j; j > 0; j--) {

            lp--;
            wv[j - 1] -= m_h[j - 1];
            wv[j - 1] += mem[lp];
            mem[lp] -= wv[j - 1];

        }

        lp--;
        for (j += mem[lp], mem[lp] -= j; j > 16; j--) {

            lp--;
            w[j - 1] -=  SHA256_F4(w[j -  2 - 1]) + w[j -  7 - 1] + SHA256_F3(w[j - 15 - 1]) + w[j - 16 - 1];
            w[j - 1] += mem[lp];
            mem[lp] -= w[j - 1];

        }

        for (; j > 0; j--) {

            lp--;
            REV_SHA2_PACK32(&sub_block[j - 1 << 2], &w[j - 1]);
            w[j - 1] += mem[lp];
            mem[lp] -= w[j - 1];

        }


        pp--;
        sub_block = 0;
        sub_block = pmem[lp];
  
    }

}

void SHA256::transform(unsigned char *message, unsigned int block_nb)
{

    unsigned char *sub_block;
    uint32 i;
    uint32 j;
    for (i = 0; i < (int) block_nb; i++) {

        pmem[pp] = sub_block;
        sub_block = 0;
        pp++;
        sub_block = message + (i << 6);

        for (j = 0; j < 16; j++) {

            
            mem[lp] += w[j];
            w[j] -= mem[lp];
            SHA2_PACK32(&sub_block[j << 2], &w[j]);
            lp++;

        }
        for (j = 16; j < 64; j++) {

            mem[lp] += w[j];
            w[j] -= mem[lp];
            w[j] =  SHA256_F4(w[j -  2]) + w[j -  7] + SHA256_F3(w[j - 15]) + w[j - 16];
            lp++;

        }

        mem[lp] += j;
        j -= mem[lp];
        lp++;

        for (j = 0; j < 8; j++) {

            mem[lp] += wv[j];
            wv[j] -= mem[lp];
            wv[j] += m_h[j];
            lp++;
    
        }

        mem[lp] += j;
        j -= mem[lp];
        lp++;

        for (j = 0; j < 64; j++) {

            mem[lp] += t1;
            t1 -= mem[lp];
            t1 += wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
                + sha256_k[j] + w[j];
            lp++;

            mem[lp] += t2;
            t2 -= mem[lp];
            t2 += SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            lp++;
  
            mem[lp] += wv[7];
            wv[7] -= mem[lp];
            wv[7] += wv[6];
            lp++;
  
            mem[lp] += wv[6];
            wv[6] -= mem[lp];
            wv[6] += wv[5];
            lp++;
 
            mem[lp] += wv[5];
            wv[5] -= mem[lp];
            wv[5] += wv[4];
            lp++;
 
            mem[lp] += wv[4];
            wv[4] -= mem[lp];
            wv[4] += wv[3] + t1;
            lp++;

            mem[lp] += wv[3];
            wv[3] -= mem[lp];
            wv[3] += wv[2];
            lp++;

            mem[lp] += wv[2];
            wv[2] -= mem[lp];
            wv[2] += wv[1];
            lp++;

            mem[lp] += wv[1];
            wv[1] -= mem[lp];
            wv[1] += wv[0];
            lp++;

            mem[lp] += wv[0];
            wv[0] -= mem[lp];
            wv[0] += t1 + t2;
            lp++;

        }

        mem[lp] += j;
        j -= mem[lp];
        lp++;

        for (j = 0; j < 8; j++) {
            m_h[j] += wv[j];
        }

        mem[lp] += j;
        j -= mem[lp];
        lp++;
    }

    mem[lp] += i;
    i -= mem[lp];
    lp++;

    pmem[pp] = sub_block;
    sub_block = 0;
    pp++;
}


 
void SHA256::init() //vengono inizializzate le 8 variabili che sono i numeri primi di non mi ricordo cosa.
{

    m_h[0] += 0x6a09e667;
    m_h[1] += 0xbb67ae85;
    m_h[2] += 0x3c6ef372;
    m_h[3] += 0xa54ff53a;
    m_h[4] += 0x510e527f;
    m_h[5] += 0x9b05688c;
    m_h[6] += 0x1f83d9ab;
    m_h[7] += 0x5be0cd19;
    m_len = 0;
    m_tot_len = 0;
    lp = 0;
    pp = 0;
    sp = 0;
}
 
void SHA256::update(unsigned char *message, unsigned int len) //i valori sono il mesasggio e la sua lunghezza
{

    unsigned int block_nb = 0;
    unsigned int new_len, rem_len, tmp_len;
    unsigned char *shifted_message;

    tmp_len += SHA224_256_BLOCK_SIZE - m_len; // il primo equivale a 512 / 8, quindi il numero di byte del blocco, mentre m_len equivale a 0 all'inizio
    
    rem_len += len < tmp_len ? len : tmp_len; // assegna a rem_len il minore fra la lunghezza del messaggio in byte e ciò che ci sta in tmp_len. tmp_len è all'inizio 64
    
    memcpy(&m_block[m_len], message, rem_len); // copia rem_len byte dentro il primo blocco di m_block
    
    if (m_len + len < SHA224_256_BLOCK_SIZE) { //se i byte del messaggio sono inferiori alla ai byte del blocco (64) questa funzione termina
        m_len += len;

        mem[lp] += tmp_len;
        tmp_len -= mem[lp];
        lp++;

        mem[lp] += rem_len;
        rem_len -= mem[lp];
        lp++;

        mem[lp] += 1;
        lp++;
    
        return;
    
    } else {

        mem[lp] += new_len;
        new_len -= mem[lp];
        lp++;
        new_len += len - rem_len; //

        cout << "block_nb: " << block_nb << endl;

        mem[lp] += block_nb;
        block_nb -= mem[lp];
        lp++;
        block_nb += new_len / SHA224_256_BLOCK_SIZE;
        cout << "block_nb: " << block_nb << endl;


        shifted_message = message + rem_len; //da capire come rendere reversibile

        transform(m_block, 1);
        transform(shifted_message, block_nb);

        mem[lp] += rem_len;
        rem_len -= mem[lp];
        lp++;
        rem_len += new_len % SHA224_256_BLOCK_SIZE;

        memcpy(&smem[sp], m_block, rem_len);
        sp += rem_len;
        memcpy(m_block, &shifted_message[block_nb << 6], rem_len);

        mem[lp] += m_len;
        m_len -= mem[lp];
        lp++;
        m_len += rem_len;

        m_tot_len += (block_nb + 1) << 6;

        cout << "block_nb: " << block_nb << endl;
        mem[lp] += block_nb;
        block_nb -= mem[lp];
        lp++;

        cout << "new_len: " << new_len << endl;
        mem[lp] += new_len;
        new_len -= mem[lp];
        lp++;

        cout << "rem_len: " << rem_len << endl;
        mem[lp] += rem_len;
        rem_len -= mem[lp];
        lp++;
    
        cout << "tmp_len: " << tmp_len << endl;
        mem[lp] += tmp_len;
        tmp_len -= mem[lp];
        lp++;

        pmem[pp] = shifted_message;
        shifted_message = 0;
        pp++;

        mem[lp] += 0;
        lp++;

    }

}

void SHA256::rev_update(unsigned char *message, unsigned int len) //i valori sono il mesasggio e la sua lunghezza
{
    unsigned int block_nb = 0;
    unsigned int new_len, rem_len, tmp_len;
    unsigned char *shifted_message;

    lp--;

    if (mem[lp] == 0) {

        pp--;
        shifted_message = 0;
        shifted_message = pmem[pp];

        lp--;
        tmp_len += mem[lp];
        mem[lp] -= tmp_len;

        lp--;
        rem_len += mem[lp];
        mem[lp] -= rem_len;
    
        lp--;
        new_len += mem[lp];
        mem[lp] -= new_len;

        lp--;
        block_nb += mem[lp];
        mem[lp] -= block_nb;

        m_tot_len -= (block_nb + 1) << 6;

        lp--;
        m_len -=  rem_len;
        m_len += mem[lp];
        mem[lp] -= m_len;

        sp -= rem_len;
        memcpy(m_block, &smem[sp], rem_len);
        memset(&smem[sp], 0, rem_len);

        lp--;
        rem_len -= new_len % SHA224_256_BLOCK_SIZE;
        rem_len += mem[lp];
        mem[lp] -= rem_len;
 
        rev_transform();
        rev_transform();

        shifted_message = 0;

        lp--;
        block_nb -= (new_len / SHA224_256_BLOCK_SIZE);
        block_nb += mem[lp];
        mem[lp] -= block_nb;

        lp--;
        new_len -= len - rem_len;
        new_len += mem[lp];
        mem[lp] -= new_len;

    } else {

        mem[lp]--;

        lp--;
        rem_len += mem[lp];
        mem[lp] -= rem_len;

        lp--;
        tmp_len += mem[lp];
        mem[lp] -= tmp_len;

        m_len -= len;

    }

    memset(&m_block[m_len],0,rem_len);

    if (len < tmp_len) {

        rem_len -= len;

    } else {

        rem_len -= tmp_len;

    }

    tmp_len -= SHA224_256_BLOCK_SIZE - m_len;
    cout << "lp: " << lp << endl;
    cout << "sp: " << sp << endl;
    cout << "pp: " << pp << endl;

    for (int k = 0; k < 100; k++) {

        cout <<mem[k] << endl;

    }
}
 
void SHA256::final(unsigned char *digest) //Questa parte si attua sull'ultimo blocc, ossia quello che presenta i bit a 0 e la lunnghezza del messaggio in 64 bit.
{
    unsigned int block_nb = 0;
    unsigned int pm_len = 0;
    unsigned int len_b = 0;
    int i = 0;

    block_nb += (1 + ((SHA224_256_BLOCK_SIZE - 9)                    
                     < (m_len % SHA224_256_BLOCK_SIZE)));  //block_nb diventa 1 se la lunghezza del messaggio è inferiore a 56 bit, 2 altrimenti

    len_b += (m_tot_len + m_len) << 3;

    pm_len += block_nb << 6;  //può essere o 64 o 128  

    memcpy(&smem[sp], m_block + m_len, pm_len - m_len);
    sp += pm_len - m_len;
    memset(m_block + m_len, 0, pm_len - m_len); //vengono aggiunti k bit 0

    m_block[m_len] += 0x80; // viene aggiunto il bit 1

    SHA2_UNPACK32(len_b, m_block + pm_len - 4); //credo che qua in qualche modo venga aggiunta la lunghezza del messaggio


    transform(m_block, block_nb);

    for (i = 0 ; i < 8; i++) {
        SHA2_UNPACK32(m_h[i], &digest[i << 2]);
    }

    mem[lp] += i;
    i -= mem[lp];
    lp++;

    mem[lp] += block_nb;
    block_nb -= mem[lp];
    lp++;

    mem[lp] += pm_len;
    pm_len -= mem[lp];
    lp++;
    
    mem[lp] += len_b;
    len_b -= mem[lp];
    lp++;
    
    cout << "lp: " << lp << endl;
    cout << "sp: " << sp << endl;
    cout << "pp: " << pp << endl;

}

void SHA256::rev_final(unsigned char *digest) //Questa parte si attua sull'ultimo blocc, ossia quello che presenta i bit a 0 e la lunnghezza del messaggio in 64 bit.
{
    unsigned int block_nb = 0;
    unsigned int pm_len = 0;
    unsigned int len_b = 0;
    int i = 0;

    lp--;
    len_b += mem[lp];
    mem[lp] -= len_b;

    lp--;
    pm_len += mem[lp];
    mem[lp] -= pm_len;

    lp--;
    block_nb += mem[lp];
    mem[lp] -= block_nb;

    lp--;

    for (i += mem[lp], mem[lp] -= i ; i > 0; i--) {
        REV_SHA2_UNPACK32(m_h[i], &digest[i << 2]); // capire cosa fa e rendere reversibile 
    }
    rev_transform();

    REV_SHA2_UNPACK32(len_b, m_block + pm_len - 4); //idem

    m_block[m_len] -= 0x80; // viene aggiunto il bit 1

    sp -= pm_len - m_len;
    memcpy(m_block + m_len, &smem[sp], pm_len - m_len);
    memset(&smem[sp], 0, pm_len - m_len);

    pm_len -= block_nb << 6;  //può essere o 64 o 128

    len_b -= (m_tot_len + m_len) << 3;

    block_nb -= (1 + ((SHA224_256_BLOCK_SIZE - 9)                    
                     < (m_len % SHA224_256_BLOCK_SIZE)));  //block_nb diventa 1 se la lunghezza del messaggio è inferiore a 56 bit, 2 altrimenti
    
}
 
std::string sha256(std::string input)
{
    
    unsigned char digest[SHA256::DIGEST_SIZE];
    memset(digest,0,SHA256::DIGEST_SIZE);
 
    SHA256 ctx = SHA256();
    ctx.init(); //inizializiamo le variabili
    ctx.update( (unsigned char*)input.c_str(), input.length());
    ctx.final(digest);
 
    char buf[2*SHA256::DIGEST_SIZE+1];
    buf[2*SHA256::DIGEST_SIZE] = 0;
    for (int i = 0; i < SHA256::DIGEST_SIZE; i++)
        sprintf(buf+i*2, "%02x", digest[i]);

    cout << endl << "invertiamo ->" << endl << endl;    
    ctx.rev_final(digest);    
    ctx.rev_update( (unsigned char*)input.c_str(), input.length());
    return std::string(buf);
}