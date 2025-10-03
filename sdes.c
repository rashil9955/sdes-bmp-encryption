#include "sdes.h"
#include <string.h>

// --- S-DES tables (Stallings) ---
// Permutation helpers expect 1-based positions in tables.
// P10: [3 5 2 7 4 10 1 9 8 6]
static const int P10[10] = {3,5,2,7,4,10,1,9,8,6};
// P8: [6 3 7 4 8 5 10 9]
static const int P8[8]  = {6,3,7,4,8,5,10,9};
// IP: [2 6 3 1 4 8 5 7]
static const int IP[8]  = {2,6,3,1,4,8,5,7};
// IP^-1: [4 1 3 5 7 2 8 6]
static const int IP_INV[8] = {4,1,3,5,7,2,8,6};
// EP: [4 1 2 3 2 3 4 1]
static const int EP[8]  = {4,1,2,3,2,3,4,1};
// P4: [2 4 3 1]
static const int P4[4]  = {2,4,3,1};

// S-boxes
static const int S0[4][4] = {
    {1,0,3,2},
    {3,2,1,0},
    {0,2,1,3},
    {3,1,3,2}
};
static const int S1[4][4] = {
    {0,1,2,3},
    {2,0,1,3},
    {3,0,1,0},
    {2,1,0,3}
};

// Get bit (1-based index from the left within 'n' bits)
static inline int get_bit(uint16_t x, int index_from_left, int nbits) {
    int pos_from_right = nbits - index_from_left;
    return (x >> pos_from_right) & 1;
}

// Permute 'in' with table 'tab' of length 'len', where tab entries are 1-based indices from the left in 'inbits' bits.
// Return result packed in the low 'len' bits.
static uint16_t permute(uint16_t in, const int *tab, int len, int inbits) {
    uint16_t out = 0;
    for (int i = 0; i < len; ++i) {
        int bit = get_bit(in, tab[i], inbits);
        out = (out << 1) | (bit & 1);
    }
    return out;
}

// Left-rotate 'val' within 'width' bits by 'sh' positions.
static uint16_t rol(uint16_t val, int sh, int width) {
    uint16_t mask = (1u << width) - 1;
    val &= mask;
    return ((val << sh) | (val >> (width - sh))) & mask;
}

void sdes_generate_subkeys(uint16_t key10, uint8_t *K1, uint8_t *K2) {
    // Apply P10
    uint16_t p10 = permute(key10, P10, 10, 10);
    // Split into left (bits 10..6) and right (bits 5..1), each 5 bits
    uint16_t left = (p10 >> 5) & 0x1F;
    uint16_t right = p10 & 0x1F;

    // LS-1
    left = rol(left, 1, 5);
    right = rol(right, 1, 5);
    uint16_t ls1 = (left << 5) | right;
    uint8_t k1 = (uint8_t) permute(ls1, P8, 8, 10);

    // LS-2 (total LS-3 from original)
    left = rol(left, 2, 5);
    right = rol(right, 2, 5);
    uint16_t ls2 = (left << 5) | right;
    uint8_t k2 = (uint8_t) permute(ls2, P8, 8, 10);

    if (K1) *K1 = k1;
    if (K2) *K2 = k2;
}

// Feistel f function: input 8 bits (L||R), subkey 8 bits, returns 8 bits ( (L xor F(R, K)) || R )
static uint8_t fk(uint8_t in, uint8_t subkey) {
    uint8_t L = (in >> 4) & 0x0F;
    uint8_t R = in & 0x0F;

    // Expand/permutation EP on R (4 bits -> 8 bits)
    uint8_t ep_in = R;
    uint8_t EPout = (uint8_t) permute(ep_in, EP, 8, 4);

    // XOR with subkey
    uint8_t x = EPout ^ subkey;

    // S-box lookups
    uint8_t left4  = (x >> 4) & 0x0F;
    uint8_t right4 = x & 0x0F;

    int r0 = ((left4 & 0x8) >> 2) | (left4 & 0x1);  // b1b4
    int c0 = (left4 >> 1) & 0x3;                    // b2b3
    int r1 = ((right4 & 0x8) >> 2) | (right4 & 0x1);
    int c1 = (right4 >> 1) & 0x3;

    int s0 = S0[r0][c0]; // 2 bits
    int s1 = S1[r1][c1]; // 2 bits
    uint8_t s = (uint8_t)((s0 << 2) | s1); // 4 bits

    // P4 on s
    uint8_t p4 = (uint8_t) permute(s, P4, 4, 4);

    // (L xor p4) || R
    uint8_t outL = L ^ p4;
    return (uint8_t)((outL << 4) | R);
}

static uint8_t ip(uint8_t x)     { return (uint8_t) permute(x, IP, 8, 8); }
static uint8_t ip_inv(uint8_t x) { return (uint8_t) permute(x, IP_INV, 8, 8); }

static uint8_t swap_halves(uint8_t x) { return (uint8_t)((x << 4) | (x >> 4)); }

uint8_t sdes_encrypt_byte(uint8_t in, uint8_t K1, uint8_t K2) {
    uint8_t x = ip(in);
    x = fk(x, K1);
    x = swap_halves(x);
    x = fk(x, K2);
    x = ip_inv(x);
    return x;
}

uint8_t sdes_decrypt_byte(uint8_t in, uint8_t K1, uint8_t K2) {
    // Reverse subkeys
    uint8_t x = ip(in);
    x = fk(x, K2);
    x = swap_halves(x);
    x = fk(x, K1);
    x = ip_inv(x);
    return x;
}

int sdes_parse_key10_bits(const char *bits, uint16_t *out_key10) {
    if (!bits || !out_key10) return -1;
    int n = 0;
    uint16_t k = 0;
    for (; bits[n] && bits[n] != '\n' && bits[n] != '\r'; ++n) {
        char ch = bits[n];
        if (ch == '0' || ch == '1') {
            k = (k << 1) | (ch - '0');
        } else if (ch == ' ' || ch == '\t') {
            continue;
        } else {
            return -2; // invalid char
        }
    }
    if (n < 10) return -3; // need at least 10 bits
    // Keep only low 10 bits (support longer inputs just in case)
    *out_key10 = k & 0x03FF;
    return 0;
}