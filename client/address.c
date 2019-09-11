/* addresses, T13.692-T13.720 $DVS:time$ */

#include <stdint.h>
#include <string.h>
#include "address.h"

static const uint8_t bits2mime[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static uint8_t mime2bits[256];

// intializes the address module
int xdag_address_init(void)
{
    int i;

    memset(mime2bits, 0xFF, 256);

    for (i = 0; i < 64; ++i) {
        mime2bits[bits2mime[i]] = i;
    }

    return 0;
}

// converts address to hash
/*
 用address反向推导出hash的z前24个字节的内容（算法见xdag_hash2address），剩下8字节置零。
 */
int xdag_address2hash(const char *address, xdag_hash_t hash)
{
    uint8_t *fld = (uint8_t *)hash;
    int i, c, d, n;

    for (int e = n = i = 0; i < 32; ++i) {
        do {
            if (!(c = (uint8_t)*address++))
                return -1;
            d = mime2bits[c];
        } while (d & 0xC0);
        e <<= 6;
        e |= d;
        n += 6;

        if (n >= 8) {
            n -= 8;
            *fld++ = e >> n;
        }
    }

    for (i = 0; i < 8; ++i) {
        *fld++ = 0;
    }

    return 0;
}

// converts hash to address
/*
 hash是32个字节。
 逻辑：32个循环，依次取每6位作为一个为一个整数（这是个小于64的整数），用每个整数去bits2mime（这是包含了64个字符的map）数组里查找对应的字符，组成32个字符的address。
 也就是说，这个查表的过程，只用了hash的32个字节里的前24个字节，最后8字节未使用，所以叫truncated。
 */
void xdag_hash2address(const xdag_hash_t hash, char *address)
{
    int c, d;
    const uint8_t *fld = (const uint8_t *)hash;

    for (int i = c = d = 0; i < 32; ++i) {
        if (d < 6) {
            d += 8;
            c <<= 8;
            c |= *fld++;
        }
        d -= 6;
        *address++ = bits2mime[c >> d & 0x3F];
    }
    *address = 0;
}

