// BMP Encrypt/Decrypt using S-DES in ECB/CBC/CTR modes.
// This file replaces the "placeholder" logic by calling sdes_* routines.
// It preserves the BMP header and encrypts only pixel data (starting at bfOffBits).

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "sdes.h"

static int read_uint32_le(const unsigned char *p) {
    return (int)(p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24));
}

static void trim_newline(char *s) {
    size_t n = strlen(s);
    while (n && (s[n-1]=='\n' || s[n-1]=='\r')) { s[--n] = '\0'; }
}

static int prompt_yesno(const char *q) {
    char buf[32];
    printf("%s [y/n]: ", q);
    if (!fgets(buf, sizeof(buf), stdin)) return -1;
    return (buf[0]=='y' || buf[0]=='Y') ? 1 : 0;
}

static int prompt_line(const char *q, char *out, size_t outsz) {
    printf("%s", q);
    if (!fgets(out, outsz, stdin)) return -1;
    trim_newline(out);
    return 0;
}

int main(void) {
    printf("=== S-DES BMP encrypt/decrypt (ECB/CBC/CTR) ===\n");

    int do_encrypt = prompt_yesno("Encrypt? (No means Decrypt)");
    if (do_encrypt < 0) { fprintf(stderr, "Input error.\n"); return 1; }

    char keybits[128];
    if (prompt_line("Enter 10-bit key as bits (e.g., 1010000010): ", keybits, sizeof(keybits)) != 0) {
        fprintf(stderr, "Key input error.\n"); return 1;
    }
    uint16_t key10 = 0;
    if (sdes_parse_key10_bits(keybits, &key10) != 0) {
        fprintf(stderr, "Invalid key string (need 10 bits of 0/1).\n"); return 1;
    }
    uint8_t K1=0, K2=0;
    sdes_generate_subkeys(key10, &K1, &K2);

    char mode_s[32];
    if (prompt_line("Mode (ECB/CBC/CTR): ", mode_s, sizeof(mode_s)) != 0) {
        fprintf(stderr, "Mode input error.\n"); return 1;
    }
    for (char *p=mode_s; *p; ++p) *p = toupper((unsigned char)*p);
    sdes_mode_t mode = MODE_ECB;
    if (strcmp(mode_s,"CBC")==0) mode = MODE_CBC;
    else if (strcmp(mode_s,"CTR")==0) mode = MODE_CTR;
    else if (strcmp(mode_s,"ECB")!=0) {
        fprintf(stderr, "Unknown mode. Use ECB, CBC, or CTR.\n"); return 1;
    }

    uint8_t iv_or_nonce = 0;
    if (mode != MODE_ECB) {
        char ivs[64];
        if (prompt_line(mode==MODE_CBC ? "Enter IV (8-bit, hex like 0xA3): " :
                                         "Enter CTR nonce/start (8-bit, hex like 0x17): ",
                        ivs, sizeof(ivs)) != 0) {
            fprintf(stderr, "IV/nonce input error.\n"); return 1;
        }
        if (strncasecmp(ivs,"0x",2)==0) {
            iv_or_nonce = (uint8_t) strtoul(ivs, NULL, 16);
        } else {
            iv_or_nonce = (uint8_t) strtoul(ivs, NULL, 10);
        }
    }

    char inpath[512], outpath[512];
    if (prompt_line("Input .bmp path: ", inpath, sizeof(inpath)) != 0) return 1;
    if (prompt_line("Output .bmp path: ", outpath, sizeof(outpath)) != 0) return 1;

    FILE *fi = fopen(inpath,"rb");
    if (!fi) { perror("open input"); return 1; }
    FILE *fo = fopen(outpath,"wb");
    if (!fo) { perror("open output"); fclose(fi); return 1; }

    // Read first 14+40=54 bytes to get bfOffBits at offset 10..13 (little endian)
    unsigned char header[54];
    size_t hr = fread(header,1,sizeof(header),fi);
    if (hr != sizeof(header)) { fprintf(stderr,"Not a BMP (short header)\n"); fclose(fi); fclose(fo); return 1; }

    if (header[0] != 'B' || header[1] != 'M') {
        fprintf(stderr,"Not a BMP (missing 'BM')\n");
        fclose(fi); fclose(fo); return 1;
    }
    int offBits = read_uint32_le(&header[10]);
    if (offBits < 54) offBits = 54; // basic safety

    // Write out everything up to offBits unchanged
    // We already have 54, but if offBits > 54, copy the rest
    fwrite(header,1,54,fo);
    if (offBits > 54) {
        int extra = offBits - 54;
        unsigned char *buf = (unsigned char*)malloc(extra);
        if (!buf) { fprintf(stderr,"OOM\n"); fclose(fi); fclose(fo); return 1; }
        size_t r = fread(buf,1,extra,fi);
        if ((int)r != extra) { fprintf(stderr,"Unexpected EOF reading palette/headers\n"); free(buf); fclose(fi); fclose(fo); return 1; }
        fwrite(buf,1,extra,fo);
        free(buf);
    }

    // Process the pixel data stream as bytes
    uint8_t chain = iv_or_nonce;     // for CBC: previous ciphertext; for CTR: counter
    int c;
    if (do_encrypt) {
        if (mode == MODE_ECB) {
            while ((c = fgetc(fi)) != EOF) {
                uint8_t out = sdes_encrypt_byte((uint8_t)c, K1, K2);
                fputc(out, fo);
            }
        } else if (mode == MODE_CBC) {
            uint8_t prev = chain;
            while ((c = fgetc(fi)) != EOF) {
                uint8_t x = (uint8_t)c ^ prev;
                uint8_t out = sdes_encrypt_byte(x, K1, K2);
                fputc(out, fo);
                prev = out;
            }
        } else { // CTR
            uint8_t ctr = chain;
            while ((c = fgetc(fi)) != EOF) {
                uint8_t keystream = sdes_encrypt_byte(ctr, K1, K2);
                uint8_t out = ((uint8_t)c) ^ keystream;
                fputc(out, fo);
                ctr++; // wraps naturally
            }
        }
    } else { // decrypt
        if (mode == MODE_ECB) {
            while ((c = fgetc(fi)) != EOF) {
                uint8_t out = sdes_decrypt_byte((uint8_t)c, K1, K2);
                fputc(out, fo);
            }
        } else if (mode == MODE_CBC) {
            uint8_t prev = chain;
            while ((c = fgetc(fi)) != EOF) {
                uint8_t dec = sdes_decrypt_byte((uint8_t)c, K1, K2);
                uint8_t out = dec ^ prev;
                fputc(out, fo);
                prev = (uint8_t)c;
            }
        } else { // CTR (same as enc)
            uint8_t ctr = chain;
            while ((c = fgetc(fi)) != EOF) {
                uint8_t keystream = sdes_encrypt_byte(ctr, K1, K2);
                uint8_t out = ((uint8_t)c) ^ keystream;
                fputc(out, fo);
                ctr++;
            }
        }
    }

    fclose(fi);
    fclose(fo);
    printf("Done. Wrote %s\n", outpath);
    return 0;
}