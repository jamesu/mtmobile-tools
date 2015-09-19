//
//  main.cpp
//  decryptArcTool
//
//  Created by MangoFusion on 17/09/2014.
//
//

#include <iostream>
#include <stdlib.h>
#include <assert.h>
#include "../zlib/zlib.h"
#include <vector>
#include <string>
#include <unordered_map>

#include <sys/stat.h>
#include <unistd.h>

bool gDebugMode = false;

/* Blowfish routines, after Bruce Schneier */
/* Written by David Madore <david.madore@ens.fr>, with code taken in
 * great part from Bruce Schneier. */
/* Public domain (1999/11/22) */

/* Note: these routines do not depend on endianness. */

/* === The header === */

/* Put this in blowfish.h if you don't like having everything in one
 * big file. */

#ifndef _DMADORE_BLOWFISH_H
#define _DMADORE_BLOWFISH_H

/* --- Basic blowfish routines --- */

#define NBROUNDS 16

struct blf_ctx {
   /* The subkeys used by the blowfish cipher */
   unsigned int P[NBROUNDS+2], S[4][256];
};

/* Encipher one 64-bit quantity (divided in two 32-bit quantities)
 * using the precalculated subkeys). */
void Blowfish_encipher (const struct blf_ctx *c,
                        unsigned int *xl, unsigned int *xr);

/* Decipher one 64-bit quantity (divided in two 32-bit quantities)
 * using the precalculated subkeys). */
void Blowfish_decipher (const struct blf_ctx *c,
                        unsigned int *xl, unsigned int *xr);

/* Initialize the cipher by calculating the subkeys from the key. */
void Blowfish_initialize (struct blf_ctx *c,
                          const unsigned char key[], int key_bytes);

/* --- Blowfish used in Electronic Code Book (ECB) mode --- */

struct blf_ecb_ctx {
   /* Whether we are encrypting (rather than decrypting) */
   char encrypt;
   /* The blowfish subkeys */
   struct blf_ctx c;
   /* The 64-bits of data being written */
   unsigned int dl, dr;
   /* Our position within the 64 bits (always between 0 and 7) */
   int b;
   /* The callback function to be called with every byte produced */
   void (* callback) (unsigned char byte, void *user_data);
   /* The user data to pass the the callback function */
   void *user_data;
};

/* Start an ECB Blowfish cipher session: specify whether we are
 * encrypting or decrypting, what key is to be used, and what callback
 * should be called for every byte produced. */
void Blowfish_ecb_start (struct blf_ecb_ctx *c, char encrypt,
                         const unsigned char key[], int key_bytes,
                         void (* callback) (unsigned char byte,
                                            void *user_data),
                         void *user_data);

/* Feed one byte to an ECB Blowfish cipher session. */
void Blowfish_ecb_feed (struct blf_ecb_ctx *c, unsigned char inb);

/* Stop an ECB Blowfish session (i.e. flush the remaining bytes). */
void Blowfish_ecb_stop (struct blf_ecb_ctx *c);

/* --- Blowfish used in Cipher Block Chaining (CBC) mode --- */

struct blf_cbc_ctx {
   /* Whether we are encrypting (rather than decrypting) */
   char encrypt;
   /* The blowfish subkeys */
   struct blf_ctx c;
   /* The 64-bits of data being written */
   unsigned int dl, dr;
   /* The last 64 bits of ciphertext */
   unsigned int ll, lr;
   /* Our position within the 64 bits (always between 0 and 7) */
   int b;
   /* The callback function to be called with every byte produced */
   void (* callback) (unsigned char byte, void *user_data);
   /* The user data to pass the the callback function */
   void *user_data;
};

/* Start a CBC Blowfish cipher session: specify whether we are
 * encrypting or decrypting, what key is to be used, and what callback
 * should be called for every byte produced. */
void Blowfish_cbc_start (struct blf_cbc_ctx *c, char encrypt,
                         const unsigned char key[], int key_bytes,
                         void (* callback) (unsigned char byte,
                                            void *user_data),
                         void *user_data);

/* Feed one byte to a CBC Blowfish cipher session. */
void Blowfish_cbc_feed (struct blf_cbc_ctx *c, unsigned char inb);

/* Stop a CBC Blowfish session (i.e. flush the remaining bytes). */
void Blowfish_cbc_stop (struct blf_cbc_ctx *c);

#endif /* not defined _DMADORE_BLOWFISH_H */

/* === The implementation === */

static unsigned int
F (const struct blf_ctx *bc, unsigned int x)
{
   unsigned char a, b, c, d;
   
   d = x & 0xff;
   x >>= 8;
   c = x & 0xff;
   x >>= 8;
   b = x & 0xff;
   x >>= 8;
   a = x & 0xff;
   return ((bc->S[0][a] + bc->S[1][b]) ^ bc->S[2][c]) + bc->S[3][d];
}

void
Blowfish_encipher (const struct blf_ctx *c,
                   unsigned int *xl, unsigned int *xr)
{
   unsigned int Xl, Xr, temp;
   int i;
   
   Xl = *xl;  Xr = *xr;
   for ( i=0 ; i<NBROUNDS ; i++ )
   {
      Xl = Xl ^ c->P[i];
      Xr = F (c, Xl) ^ Xr;
      temp = Xl;  Xl = Xr;  Xr = temp;
   }
   temp = Xl;  Xl = Xr;  Xr = temp;
   Xr = Xr ^ c->P[NBROUNDS];
   Xl = Xl ^ c->P[NBROUNDS+1];
   *xl = Xl;  *xr = Xr;
}

void
Blowfish_decipher (const struct blf_ctx *c,
                   unsigned int *xl, unsigned int *xr)
{
   unsigned int Xl, Xr, temp;
   int i;
   
   Xl = *xl;  Xr = *xr;
   for ( i=NBROUNDS+1 ; i>1 ; i-- )
   {
      Xl = Xl ^ c->P[i];
      Xr = F (c, Xl) ^ Xr;
      temp = Xl;  Xl = Xr;  Xr = temp;
   }
   temp = Xl;  Xl = Xr;  Xr = temp;
   Xr = Xr ^ c->P[1];
   Xl = Xl ^ c->P[0];
   *xl = Xl;  *xr = Xr;
}

/* The magical constants of the Blowfish cipher (used in initializing
 * the P array and the S-boxes): these are the hexadecimal digits of
 * pi = 3.243F6A8885A308D313198A2E03707344... */

static const unsigned int init_P[NBROUNDS+2] = {
   0x243f6a88UL, 0x85a308d3UL, 0x13198a2eUL, 0x03707344UL,
   0xa4093822UL, 0x299f31d0UL, 0x082efa98UL, 0xec4e6c89UL,
   0x452821e6UL, 0x38d01377UL, 0xbe5466cfUL, 0x34e90c6cUL,
   0xc0ac29b7UL, 0xc97c50ddUL, 0x3f84d5b5UL, 0xb5470917UL,
   0x9216d5d9UL, 0x8979fb1bUL,
};

static const unsigned int init_S[4][256] = {
   {
      0xd1310ba6UL, 0x98dfb5acUL, 0x2ffd72dbUL, 0xd01adfb7UL,
      0xb8e1afedUL, 0x6a267e96UL, 0xba7c9045UL, 0xf12c7f99UL,
      0x24a19947UL, 0xb3916cf7UL, 0x0801f2e2UL, 0x858efc16UL,
      0x636920d8UL, 0x71574e69UL, 0xa458fea3UL, 0xf4933d7eUL,
      0x0d95748fUL, 0x728eb658UL, 0x718bcd58UL, 0x82154aeeUL,
      0x7b54a41dUL, 0xc25a59b5UL, 0x9c30d539UL, 0x2af26013UL,
      0xc5d1b023UL, 0x286085f0UL, 0xca417918UL, 0xb8db38efUL,
      0x8e79dcb0UL, 0x603a180eUL, 0x6c9e0e8bUL, 0xb01e8a3eUL,
      0xd71577c1UL, 0xbd314b27UL, 0x78af2fdaUL, 0x55605c60UL,
      0xe65525f3UL, 0xaa55ab94UL, 0x57489862UL, 0x63e81440UL,
      0x55ca396aUL, 0x2aab10b6UL, 0xb4cc5c34UL, 0x1141e8ceUL,
      0xa15486afUL, 0x7c72e993UL, 0xb3ee1411UL, 0x636fbc2aUL,
      0x2ba9c55dUL, 0x741831f6UL, 0xce5c3e16UL, 0x9b87931eUL,
      0xafd6ba33UL, 0x6c24cf5cUL, 0x7a325381UL, 0x28958677UL,
      0x3b8f4898UL, 0x6b4bb9afUL, 0xc4bfe81bUL, 0x66282193UL,
      0x61d809ccUL, 0xfb21a991UL, 0x487cac60UL, 0x5dec8032UL,
      0xef845d5dUL, 0xe98575b1UL, 0xdc262302UL, 0xeb651b88UL,
      0x23893e81UL, 0xd396acc5UL, 0x0f6d6ff3UL, 0x83f44239UL,
      0x2e0b4482UL, 0xa4842004UL, 0x69c8f04aUL, 0x9e1f9b5eUL,
      0x21c66842UL, 0xf6e96c9aUL, 0x670c9c61UL, 0xabd388f0UL,
      0x6a51a0d2UL, 0xd8542f68UL, 0x960fa728UL, 0xab5133a3UL,
      0x6eef0b6cUL, 0x137a3be4UL, 0xba3bf050UL, 0x7efb2a98UL,
      0xa1f1651dUL, 0x39af0176UL, 0x66ca593eUL, 0x82430e88UL,
      0x8cee8619UL, 0x456f9fb4UL, 0x7d84a5c3UL, 0x3b8b5ebeUL,
      0xe06f75d8UL, 0x85c12073UL, 0x401a449fUL, 0x56c16aa6UL,
      0x4ed3aa62UL, 0x363f7706UL, 0x1bfedf72UL, 0x429b023dUL,
      0x37d0d724UL, 0xd00a1248UL, 0xdb0fead3UL, 0x49f1c09bUL,
      0x075372c9UL, 0x80991b7bUL, 0x25d479d8UL, 0xf6e8def7UL,
      0xe3fe501aUL, 0xb6794c3bUL, 0x976ce0bdUL, 0x04c006baUL,
      0xc1a94fb6UL, 0x409f60c4UL, 0x5e5c9ec2UL, 0x196a2463UL,
      0x68fb6fafUL, 0x3e6c53b5UL, 0x1339b2ebUL, 0x3b52ec6fUL,
      0x6dfc511fUL, 0x9b30952cUL, 0xcc814544UL, 0xaf5ebd09UL,
      0xbee3d004UL, 0xde334afdUL, 0x660f2807UL, 0x192e4bb3UL,
      0xc0cba857UL, 0x45c8740fUL, 0xd20b5f39UL, 0xb9d3fbdbUL,
      0x5579c0bdUL, 0x1a60320aUL, 0xd6a100c6UL, 0x402c7279UL,
      0x679f25feUL, 0xfb1fa3ccUL, 0x8ea5e9f8UL, 0xdb3222f8UL,
      0x3c7516dfUL, 0xfd616b15UL, 0x2f501ec8UL, 0xad0552abUL,
      0x323db5faUL, 0xfd238760UL, 0x53317b48UL, 0x3e00df82UL,
      0x9e5c57bbUL, 0xca6f8ca0UL, 0x1a87562eUL, 0xdf1769dbUL,
      0xd542a8f6UL, 0x287effc3UL, 0xac6732c6UL, 0x8c4f5573UL,
      0x695b27b0UL, 0xbbca58c8UL, 0xe1ffa35dUL, 0xb8f011a0UL,
      0x10fa3d98UL, 0xfd2183b8UL, 0x4afcb56cUL, 0x2dd1d35bUL,
      0x9a53e479UL, 0xb6f84565UL, 0xd28e49bcUL, 0x4bfb9790UL,
      0xe1ddf2daUL, 0xa4cb7e33UL, 0x62fb1341UL, 0xcee4c6e8UL,
      0xef20cadaUL, 0x36774c01UL, 0xd07e9efeUL, 0x2bf11fb4UL,
      0x95dbda4dUL, 0xae909198UL, 0xeaad8e71UL, 0x6b93d5a0UL,
      0xd08ed1d0UL, 0xafc725e0UL, 0x8e3c5b2fUL, 0x8e7594b7UL,
      0x8ff6e2fbUL, 0xf2122b64UL, 0x8888b812UL, 0x900df01cUL,
      0x4fad5ea0UL, 0x688fc31cUL, 0xd1cff191UL, 0xb3a8c1adUL,
      0x2f2f2218UL, 0xbe0e1777UL, 0xea752dfeUL, 0x8b021fa1UL,
      0xe5a0cc0fUL, 0xb56f74e8UL, 0x18acf3d6UL, 0xce89e299UL,
      0xb4a84fe0UL, 0xfd13e0b7UL, 0x7cc43b81UL, 0xd2ada8d9UL,
      0x165fa266UL, 0x80957705UL, 0x93cc7314UL, 0x211a1477UL,
      0xe6ad2065UL, 0x77b5fa86UL, 0xc75442f5UL, 0xfb9d35cfUL,
      0xebcdaf0cUL, 0x7b3e89a0UL, 0xd6411bd3UL, 0xae1e7e49UL,
      0x00250e2dUL, 0x2071b35eUL, 0x226800bbUL, 0x57b8e0afUL,
      0x2464369bUL, 0xf009b91eUL, 0x5563911dUL, 0x59dfa6aaUL,
      0x78c14389UL, 0xd95a537fUL, 0x207d5ba2UL, 0x02e5b9c5UL,
      0x83260376UL, 0x6295cfa9UL, 0x11c81968UL, 0x4e734a41UL,
      0xb3472dcaUL, 0x7b14a94aUL, 0x1b510052UL, 0x9a532915UL,
      0xd60f573fUL, 0xbc9bc6e4UL, 0x2b60a476UL, 0x81e67400UL,
      0x08ba6fb5UL, 0x571be91fUL, 0xf296ec6bUL, 0x2a0dd915UL,
      0xb6636521UL, 0xe7b9f9b6UL, 0xff34052eUL, 0xc5855664UL,
      0x53b02d5dUL, 0xa99f8fa1UL, 0x08ba4799UL, 0x6e85076aUL,
   },
   {
      0x4b7a70e9UL, 0xb5b32944UL, 0xdb75092eUL, 0xc4192623UL,
      0xad6ea6b0UL, 0x49a7df7dUL, 0x9cee60b8UL, 0x8fedb266UL,
      0xecaa8c71UL, 0x699a17ffUL, 0x5664526cUL, 0xc2b19ee1UL,
      0x193602a5UL, 0x75094c29UL, 0xa0591340UL, 0xe4183a3eUL,
      0x3f54989aUL, 0x5b429d65UL, 0x6b8fe4d6UL, 0x99f73fd6UL,
      0xa1d29c07UL, 0xefe830f5UL, 0x4d2d38e6UL, 0xf0255dc1UL,
      0x4cdd2086UL, 0x8470eb26UL, 0x6382e9c6UL, 0x021ecc5eUL,
      0x09686b3fUL, 0x3ebaefc9UL, 0x3c971814UL, 0x6b6a70a1UL,
      0x687f3584UL, 0x52a0e286UL, 0xb79c5305UL, 0xaa500737UL,
      0x3e07841cUL, 0x7fdeae5cUL, 0x8e7d44ecUL, 0x5716f2b8UL,
      0xb03ada37UL, 0xf0500c0dUL, 0xf01c1f04UL, 0x0200b3ffUL,
      0xae0cf51aUL, 0x3cb574b2UL, 0x25837a58UL, 0xdc0921bdUL,
      0xd19113f9UL, 0x7ca92ff6UL, 0x94324773UL, 0x22f54701UL,
      0x3ae5e581UL, 0x37c2dadcUL, 0xc8b57634UL, 0x9af3dda7UL,
      0xa9446146UL, 0x0fd0030eUL, 0xecc8c73eUL, 0xa4751e41UL,
      0xe238cd99UL, 0x3bea0e2fUL, 0x3280bba1UL, 0x183eb331UL,
      0x4e548b38UL, 0x4f6db908UL, 0x6f420d03UL, 0xf60a04bfUL,
      0x2cb81290UL, 0x24977c79UL, 0x5679b072UL, 0xbcaf89afUL,
      0xde9a771fUL, 0xd9930810UL, 0xb38bae12UL, 0xdccf3f2eUL,
      0x5512721fUL, 0x2e6b7124UL, 0x501adde6UL, 0x9f84cd87UL,
      0x7a584718UL, 0x7408da17UL, 0xbc9f9abcUL, 0xe94b7d8cUL,
      0xec7aec3aUL, 0xdb851dfaUL, 0x63094366UL, 0xc464c3d2UL,
      0xef1c1847UL, 0x3215d908UL, 0xdd433b37UL, 0x24c2ba16UL,
      0x12a14d43UL, 0x2a65c451UL, 0x50940002UL, 0x133ae4ddUL,
      0x71dff89eUL, 0x10314e55UL, 0x81ac77d6UL, 0x5f11199bUL,
      0x043556f1UL, 0xd7a3c76bUL, 0x3c11183bUL, 0x5924a509UL,
      0xf28fe6edUL, 0x97f1fbfaUL, 0x9ebabf2cUL, 0x1e153c6eUL,
      0x86e34570UL, 0xeae96fb1UL, 0x860e5e0aUL, 0x5a3e2ab3UL,
      0x771fe71cUL, 0x4e3d06faUL, 0x2965dcb9UL, 0x99e71d0fUL,
      0x803e89d6UL, 0x5266c825UL, 0x2e4cc978UL, 0x9c10b36aUL,
      0xc6150ebaUL, 0x94e2ea78UL, 0xa5fc3c53UL, 0x1e0a2df4UL,
      0xf2f74ea7UL, 0x361d2b3dUL, 0x1939260fUL, 0x19c27960UL,
      0x5223a708UL, 0xf71312b6UL, 0xebadfe6eUL, 0xeac31f66UL,
      0xe3bc4595UL, 0xa67bc883UL, 0xb17f37d1UL, 0x018cff28UL,
      0xc332ddefUL, 0xbe6c5aa5UL, 0x65582185UL, 0x68ab9802UL,
      0xeecea50fUL, 0xdb2f953bUL, 0x2aef7dadUL, 0x5b6e2f84UL,
      0x1521b628UL, 0x29076170UL, 0xecdd4775UL, 0x619f1510UL,
      0x13cca830UL, 0xeb61bd96UL, 0x0334fe1eUL, 0xaa0363cfUL,
      0xb5735c90UL, 0x4c70a239UL, 0xd59e9e0bUL, 0xcbaade14UL,
      0xeecc86bcUL, 0x60622ca7UL, 0x9cab5cabUL, 0xb2f3846eUL,
      0x648b1eafUL, 0x19bdf0caUL, 0xa02369b9UL, 0x655abb50UL,
      0x40685a32UL, 0x3c2ab4b3UL, 0x319ee9d5UL, 0xc021b8f7UL,
      0x9b540b19UL, 0x875fa099UL, 0x95f7997eUL, 0x623d7da8UL,
      0xf837889aUL, 0x97e32d77UL, 0x11ed935fUL, 0x16681281UL,
      0x0e358829UL, 0xc7e61fd6UL, 0x96dedfa1UL, 0x7858ba99UL,
      0x57f584a5UL, 0x1b227263UL, 0x9b83c3ffUL, 0x1ac24696UL,
      0xcdb30aebUL, 0x532e3054UL, 0x8fd948e4UL, 0x6dbc3128UL,
      0x58ebf2efUL, 0x34c6ffeaUL, 0xfe28ed61UL, 0xee7c3c73UL,
      0x5d4a14d9UL, 0xe864b7e3UL, 0x42105d14UL, 0x203e13e0UL,
      0x45eee2b6UL, 0xa3aaabeaUL, 0xdb6c4f15UL, 0xfacb4fd0UL,
      0xc742f442UL, 0xef6abbb5UL, 0x654f3b1dUL, 0x41cd2105UL,
      0xd81e799eUL, 0x86854dc7UL, 0xe44b476aUL, 0x3d816250UL,
      0xcf62a1f2UL, 0x5b8d2646UL, 0xfc8883a0UL, 0xc1c7b6a3UL,
      0x7f1524c3UL, 0x69cb7492UL, 0x47848a0bUL, 0x5692b285UL,
      0x095bbf00UL, 0xad19489dUL, 0x1462b174UL, 0x23820e00UL,
      0x58428d2aUL, 0x0c55f5eaUL, 0x1dadf43eUL, 0x233f7061UL,
      0x3372f092UL, 0x8d937e41UL, 0xd65fecf1UL, 0x6c223bdbUL,
      0x7cde3759UL, 0xcbee7460UL, 0x4085f2a7UL, 0xce77326eUL,
      0xa6078084UL, 0x19f8509eUL, 0xe8efd855UL, 0x61d99735UL,
      0xa969a7aaUL, 0xc50c06c2UL, 0x5a04abfcUL, 0x800bcadcUL,
      0x9e447a2eUL, 0xc3453484UL, 0xfdd56705UL, 0x0e1e9ec9UL,
      0xdb73dbd3UL, 0x105588cdUL, 0x675fda79UL, 0xe3674340UL,
      0xc5c43465UL, 0x713e38d8UL, 0x3d28f89eUL, 0xf16dff20UL,
      0x153e21e7UL, 0x8fb03d4aUL, 0xe6e39f2bUL, 0xdb83adf7UL,
   },
   {
      0xe93d5a68UL, 0x948140f7UL, 0xf64c261cUL, 0x94692934UL,
      0x411520f7UL, 0x7602d4f7UL, 0xbcf46b2eUL, 0xd4a20068UL,
      0xd4082471UL, 0x3320f46aUL, 0x43b7d4b7UL, 0x500061afUL,
      0x1e39f62eUL, 0x97244546UL, 0x14214f74UL, 0xbf8b8840UL,
      0x4d95fc1dUL, 0x96b591afUL, 0x70f4ddd3UL, 0x66a02f45UL,
      0xbfbc09ecUL, 0x03bd9785UL, 0x7fac6dd0UL, 0x31cb8504UL,
      0x96eb27b3UL, 0x55fd3941UL, 0xda2547e6UL, 0xabca0a9aUL,
      0x28507825UL, 0x530429f4UL, 0x0a2c86daUL, 0xe9b66dfbUL,
      0x68dc1462UL, 0xd7486900UL, 0x680ec0a4UL, 0x27a18deeUL,
      0x4f3ffea2UL, 0xe887ad8cUL, 0xb58ce006UL, 0x7af4d6b6UL,
      0xaace1e7cUL, 0xd3375fecUL, 0xce78a399UL, 0x406b2a42UL,
      0x20fe9e35UL, 0xd9f385b9UL, 0xee39d7abUL, 0x3b124e8bUL,
      0x1dc9faf7UL, 0x4b6d1856UL, 0x26a36631UL, 0xeae397b2UL,
      0x3a6efa74UL, 0xdd5b4332UL, 0x6841e7f7UL, 0xca7820fbUL,
      0xfb0af54eUL, 0xd8feb397UL, 0x454056acUL, 0xba489527UL,
      0x55533a3aUL, 0x20838d87UL, 0xfe6ba9b7UL, 0xd096954bUL,
      0x55a867bcUL, 0xa1159a58UL, 0xcca92963UL, 0x99e1db33UL,
      0xa62a4a56UL, 0x3f3125f9UL, 0x5ef47e1cUL, 0x9029317cUL,
      0xfdf8e802UL, 0x04272f70UL, 0x80bb155cUL, 0x05282ce3UL,
      0x95c11548UL, 0xe4c66d22UL, 0x48c1133fUL, 0xc70f86dcUL,
      0x07f9c9eeUL, 0x41041f0fUL, 0x404779a4UL, 0x5d886e17UL,
      0x325f51ebUL, 0xd59bc0d1UL, 0xf2bcc18fUL, 0x41113564UL,
      0x257b7834UL, 0x602a9c60UL, 0xdff8e8a3UL, 0x1f636c1bUL,
      0x0e12b4c2UL, 0x02e1329eUL, 0xaf664fd1UL, 0xcad18115UL,
      0x6b2395e0UL, 0x333e92e1UL, 0x3b240b62UL, 0xeebeb922UL,
      0x85b2a20eUL, 0xe6ba0d99UL, 0xde720c8cUL, 0x2da2f728UL,
      0xd0127845UL, 0x95b794fdUL, 0x647d0862UL, 0xe7ccf5f0UL,
      0x5449a36fUL, 0x877d48faUL, 0xc39dfd27UL, 0xf33e8d1eUL,
      0x0a476341UL, 0x992eff74UL, 0x3a6f6eabUL, 0xf4f8fd37UL,
      0xa812dc60UL, 0xa1ebddf8UL, 0x991be14cUL, 0xdb6e6b0dUL,
      0xc67b5510UL, 0x6d672c37UL, 0x2765d43bUL, 0xdcd0e804UL,
      0xf1290dc7UL, 0xcc00ffa3UL, 0xb5390f92UL, 0x690fed0bUL,
      0x667b9ffbUL, 0xcedb7d9cUL, 0xa091cf0bUL, 0xd9155ea3UL,
      0xbb132f88UL, 0x515bad24UL, 0x7b9479bfUL, 0x763bd6ebUL,
      0x37392eb3UL, 0xcc115979UL, 0x8026e297UL, 0xf42e312dUL,
      0x6842ada7UL, 0xc66a2b3bUL, 0x12754cccUL, 0x782ef11cUL,
      0x6a124237UL, 0xb79251e7UL, 0x06a1bbe6UL, 0x4bfb6350UL,
      0x1a6b1018UL, 0x11caedfaUL, 0x3d25bdd8UL, 0xe2e1c3c9UL,
      0x44421659UL, 0x0a121386UL, 0xd90cec6eUL, 0xd5abea2aUL,
      0x64af674eUL, 0xda86a85fUL, 0xbebfe988UL, 0x64e4c3feUL,
      0x9dbc8057UL, 0xf0f7c086UL, 0x60787bf8UL, 0x6003604dUL,
      0xd1fd8346UL, 0xf6381fb0UL, 0x7745ae04UL, 0xd736fcccUL,
      0x83426b33UL, 0xf01eab71UL, 0xb0804187UL, 0x3c005e5fUL,
      0x77a057beUL, 0xbde8ae24UL, 0x55464299UL, 0xbf582e61UL,
      0x4e58f48fUL, 0xf2ddfda2UL, 0xf474ef38UL, 0x8789bdc2UL,
      0x5366f9c3UL, 0xc8b38e74UL, 0xb475f255UL, 0x46fcd9b9UL,
      0x7aeb2661UL, 0x8b1ddf84UL, 0x846a0e79UL, 0x915f95e2UL,
      0x466e598eUL, 0x20b45770UL, 0x8cd55591UL, 0xc902de4cUL,
      0xb90bace1UL, 0xbb8205d0UL, 0x11a86248UL, 0x7574a99eUL,
      0xb77f19b6UL, 0xe0a9dc09UL, 0x662d09a1UL, 0xc4324633UL,
      0xe85a1f02UL, 0x09f0be8cUL, 0x4a99a025UL, 0x1d6efe10UL,
      0x1ab93d1dUL, 0x0ba5a4dfUL, 0xa186f20fUL, 0x2868f169UL,
      0xdcb7da83UL, 0x573906feUL, 0xa1e2ce9bUL, 0x4fcd7f52UL,
      0x50115e01UL, 0xa70683faUL, 0xa002b5c4UL, 0x0de6d027UL,
      0x9af88c27UL, 0x773f8641UL, 0xc3604c06UL, 0x61a806b5UL,
      0xf0177a28UL, 0xc0f586e0UL, 0x006058aaUL, 0x30dc7d62UL,
      0x11e69ed7UL, 0x2338ea63UL, 0x53c2dd94UL, 0xc2c21634UL,
      0xbbcbee56UL, 0x90bcb6deUL, 0xebfc7da1UL, 0xce591d76UL,
      0x6f05e409UL, 0x4b7c0188UL, 0x39720a3dUL, 0x7c927c24UL,
      0x86e3725fUL, 0x724d9db9UL, 0x1ac15bb4UL, 0xd39eb8fcUL,
      0xed545578UL, 0x08fca5b5UL, 0xd83d7cd3UL, 0x4dad0fc4UL,
      0x1e50ef5eUL, 0xb161e6f8UL, 0xa28514d9UL, 0x6c51133cUL,
      0x6fd5c7e7UL, 0x56e14ec4UL, 0x362abfceUL, 0xddc6c837UL,
      0xd79a3234UL, 0x92638212UL, 0x670efa8eUL, 0x406000e0UL,
   }, {
      0x3a39ce37UL, 0xd3faf5cfUL, 0xabc27737UL, 0x5ac52d1bUL,
      0x5cb0679eUL, 0x4fa33742UL, 0xd3822740UL, 0x99bc9bbeUL,
      0xd5118e9dUL, 0xbf0f7315UL, 0xd62d1c7eUL, 0xc700c47bUL,
      0xb78c1b6bUL, 0x21a19045UL, 0xb26eb1beUL, 0x6a366eb4UL,
      0x5748ab2fUL, 0xbc946e79UL, 0xc6a376d2UL, 0x6549c2c8UL,
      0x530ff8eeUL, 0x468dde7dUL, 0xd5730a1dUL, 0x4cd04dc6UL,
      0x2939bbdbUL, 0xa9ba4650UL, 0xac9526e8UL, 0xbe5ee304UL,
      0xa1fad5f0UL, 0x6a2d519aUL, 0x63ef8ce2UL, 0x9a86ee22UL,
      0xc089c2b8UL, 0x43242ef6UL, 0xa51e03aaUL, 0x9cf2d0a4UL,
      0x83c061baUL, 0x9be96a4dUL, 0x8fe51550UL, 0xba645bd6UL,
      0x2826a2f9UL, 0xa73a3ae1UL, 0x4ba99586UL, 0xef5562e9UL,
      0xc72fefd3UL, 0xf752f7daUL, 0x3f046f69UL, 0x77fa0a59UL,
      0x80e4a915UL, 0x87b08601UL, 0x9b09e6adUL, 0x3b3ee593UL,
      0xe990fd5aUL, 0x9e34d797UL, 0x2cf0b7d9UL, 0x022b8b51UL,
      0x96d5ac3aUL, 0x017da67dUL, 0xd1cf3ed6UL, 0x7c7d2d28UL,
      0x1f9f25cfUL, 0xadf2b89bUL, 0x5ad6b472UL, 0x5a88f54cUL,
      0xe029ac71UL, 0xe019a5e6UL, 0x47b0acfdUL, 0xed93fa9bUL,
      0xe8d3c48dUL, 0x283b57ccUL, 0xf8d56629UL, 0x79132e28UL,
      0x785f0191UL, 0xed756055UL, 0xf7960e44UL, 0xe3d35e8cUL,
      0x15056dd4UL, 0x88f46dbaUL, 0x03a16125UL, 0x0564f0bdUL,
      0xc3eb9e15UL, 0x3c9057a2UL, 0x97271aecUL, 0xa93a072aUL,
      0x1b3f6d9bUL, 0x1e6321f5UL, 0xf59c66fbUL, 0x26dcf319UL,
      0x7533d928UL, 0xb155fdf5UL, 0x03563482UL, 0x8aba3cbbUL,
      0x28517711UL, 0xc20ad9f8UL, 0xabcc5167UL, 0xccad925fUL,
      0x4de81751UL, 0x3830dc8eUL, 0x379d5862UL, 0x9320f991UL,
      0xea7a90c2UL, 0xfb3e7bceUL, 0x5121ce64UL, 0x774fbe32UL,
      0xa8b6e37eUL, 0xc3293d46UL, 0x48de5369UL, 0x6413e680UL,
      0xa2ae0810UL, 0xdd6db224UL, 0x69852dfdUL, 0x09072166UL,
      0xb39a460aUL, 0x6445c0ddUL, 0x586cdecfUL, 0x1c20c8aeUL,
      0x5bbef7ddUL, 0x1b588d40UL, 0xccd2017fUL, 0x6bb4e3bbUL,
      0xdda26a7eUL, 0x3a59ff45UL, 0x3e350a44UL, 0xbcb4cdd5UL,
      0x72eacea8UL, 0xfa6484bbUL, 0x8d6612aeUL, 0xbf3c6f47UL,
      0xd29be463UL, 0x542f5d9eUL, 0xaec2771bUL, 0xf64e6370UL,
      0x740e0d8dUL, 0xe75b1357UL, 0xf8721671UL, 0xaf537d5dUL,
      0x4040cb08UL, 0x4eb4e2ccUL, 0x34d2466aUL, 0x0115af84UL,
      0xe1b00428UL, 0x95983a1dUL, 0x06b89fb4UL, 0xce6ea048UL,
      0x6f3f3b82UL, 0x3520ab82UL, 0x011a1d4bUL, 0x277227f8UL,
      0x611560b1UL, 0xe7933fdcUL, 0xbb3a792bUL, 0x344525bdUL,
      0xa08839e1UL, 0x51ce794bUL, 0x2f32c9b7UL, 0xa01fbac9UL,
      0xe01cc87eUL, 0xbcc7d1f6UL, 0xcf0111c3UL, 0xa1e8aac7UL,
      0x1a908749UL, 0xd44fbd9aUL, 0xd0dadecbUL, 0xd50ada38UL,
      0x0339c32aUL, 0xc6913667UL, 0x8df9317cUL, 0xe0b12b4fUL,
      0xf79e59b7UL, 0x43f5bb3aUL, 0xf2d519ffUL, 0x27d9459cUL,
      0xbf97222cUL, 0x15e6fc2aUL, 0x0f91fc71UL, 0x9b941525UL,
      0xfae59361UL, 0xceb69cebUL, 0xc2a86459UL, 0x12baa8d1UL,
      0xb6c1075eUL, 0xe3056a0cUL, 0x10d25065UL, 0xcb03a442UL,
      0xe0ec6e0eUL, 0x1698db3bUL, 0x4c98a0beUL, 0x3278e964UL,
      0x9f1f9532UL, 0xe0d392dfUL, 0xd3a0342bUL, 0x8971f21eUL,
      0x1b0a7441UL, 0x4ba3348cUL, 0xc5be7120UL, 0xc37632d8UL,
      0xdf359f8dUL, 0x9b992f2eUL, 0xe60b6f47UL, 0x0fe3f11dUL,
      0xe54cda54UL, 0x1edad891UL, 0xce6279cfUL, 0xcd3e7e6fUL,
      0x1618b166UL, 0xfd2c1d05UL, 0x848fd2c5UL, 0xf6fb2299UL,
      0xf523f357UL, 0xa6327623UL, 0x93a83531UL, 0x56cccd02UL,
      0xacf08162UL, 0x5a75ebb5UL, 0x6e163697UL, 0x88d273ccUL,
      0xde966292UL, 0x81b949d0UL, 0x4c50901bUL, 0x71c65614UL,
      0xe6c6c7bdUL, 0x327a140aUL, 0x45e1d006UL, 0xc3f27b9aUL,
      0xc9aa53fdUL, 0x62a80f00UL, 0xbb25bfe2UL, 0x35bdd2f6UL,
      0x71126905UL, 0xb2040222UL, 0xb6cbcf7cUL, 0xcd769c2bUL,
      0x53113ec0UL, 0x1640e3d3UL, 0x38abbd60UL, 0x2547adf0UL,
      0xba38209cUL, 0xf746ce76UL, 0x77afa1c5UL, 0x20756060UL,
      0x85cbfe4eUL, 0x8ae88dd8UL, 0x7aaaf9b0UL, 0x4cf9aa7eUL,
      0x1948c25cUL, 0x02fb8a8cUL, 0x01c36ae4UL, 0xd6ebe1f9UL,
      0x90d4f869UL, 0xa65cdea0UL, 0x3f09252dUL, 0xc208e69fUL,
      0xb74e6132UL, 0xce77e25bUL, 0x578fdfe3UL, 0x3ac372e6UL,
   }
};

void
Blowfish_initialize (struct blf_ctx *c,
                     const unsigned char key[], int key_bytes)
{
   int i, j, k;
   unsigned int data, datal, datar;
   
   for ( i=0 ; i<NBROUNDS+2 ; i++ )
      c->P[i] = init_P[i];
   for ( i=0 ; i<256 ; i++ )
   {
      c->S[0][i] = init_S[0][i];
      c->S[1][i] = init_S[1][i];
      c->S[2][i] = init_S[2][i];
      c->S[3][i] = init_S[3][i];
   }
   j = 0;
   for ( i=0 ; i<NBROUNDS+2 ; i++ )
   {
      data = 0;
      for ( k=0 ; k<4 ; k++ )
      {
         data = (data<<8) | key[j];
         if ( ++j >= key_bytes )
            j = 0;
      }
      c->P[i] = c->P[i] ^ data;
   }
   datal = 0;  datar = 0;
   
   for ( i=0 ; i<NBROUNDS+2 ; i+=2 )
   {
      Blowfish_encipher (c, &datal, &datar);
      c->P[i] = datal;
      c->P[i+1] = datar;
   }
   for ( i=0 ; i<4 ; i++ )
      for ( j=0 ; j<256 ; j+=2 )
      {
         Blowfish_encipher (c, &datal, &datar);
         c->S[i][j] = datal;
         c->S[i][j+1] = datar;
      }
}

void
Blowfish_ecb_start (struct blf_ecb_ctx *c, char encrypt,
                    const unsigned char key[], int key_bytes,
                    void (* callback) (unsigned char byte, void *user_data),
                    void *user_data)
{
   c->encrypt = encrypt;
   Blowfish_initialize (&c->c, key, key_bytes);
   c->b = 0;
   c->dl = 0;
   c->dr = 0;
   c->callback = callback;
   c->user_data = user_data;
}

void
Blowfish_ecb_feed (struct blf_ecb_ctx *c, unsigned char inb)
{
   if ( c->b++ < 4 )
      c->dl = (c->dl)<<8 | inb;
   else
      c->dr = (c->dr)<<8 | inb;
   if ( c->b >= 8 )
   /* We have one block of data */
   {
      unsigned int xl, xr;
      
      xl = c->dl;  xr = c->dr;
      (c->encrypt ? Blowfish_encipher : Blowfish_decipher) (&c->c, &xl, &xr);
      c->callback ((xl>>24)&0xff, c->user_data);
      c->callback ((xl>>16)&0xff, c->user_data);
      c->callback ((xl>>8)&0xff, c->user_data);
      c->callback (xl&0xff, c->user_data);
      c->callback ((xr>>24)&0xff, c->user_data);
      c->callback ((xr>>16)&0xff, c->user_data);
      c->callback ((xr>>8)&0xff, c->user_data);
      c->callback (xr&0xff, c->user_data);
      c->b = 0;
      c->dl = 0;
      c->dr = 0;
   }
}

void
Blowfish_ecb_stop (struct blf_ecb_ctx *c)
{
   for ( ; c->b ; ) /* ``Cryptic'', isn't it? */
      Blowfish_ecb_feed (c, 0);
}

void
Blowfish_cbc_start (struct blf_cbc_ctx *c, char encrypt,
                    const unsigned char key[], int key_bytes,
                    void (* callback) (unsigned char byte, void *user_data),
                    void *user_data)
{
   c->encrypt = encrypt;
   Blowfish_initialize (&c->c, key, key_bytes);
   c->b = 0;
   c->dl = 0;
   c->dr = 0;
   c->ll = 0;
   c->lr = 0;
   c->callback = callback;
   c->user_data = user_data;
}

void
Blowfish_cbc_feed (struct blf_cbc_ctx *c, unsigned char inb)
{
   if ( c->b++ < 4 )
      c->dl = (c->dl)<<8 | inb;
   else
      c->dr = (c->dr)<<8 | inb;
   if ( c->b >= 8 )
   /* We have one block of data */
   {
      unsigned int xl, xr;
      
      xl = c->dl;  xr = c->dr;
      if ( c->encrypt )
      {
         xl ^= c->ll;
         xr ^= c->lr;
      }
      (c->encrypt ? Blowfish_encipher : Blowfish_decipher) (&c->c, &xl, &xr);
      if ( c->encrypt )
      {
         /* Keep encrypted block to encrypt next one */
         c->ll = xl;
         c->lr = xr;
      }
      else
      {
         xl ^= c->ll;
         xr ^= c->lr;
         /* Keep last block of ciphertext to decrypt next one */
         c->ll = c->dl;
         c->lr = c->dr;
      }
      c->callback ((xl>>24)&0xff, c->user_data);
      c->callback ((xl>>16)&0xff, c->user_data);
      c->callback ((xl>>8)&0xff, c->user_data);
      c->callback (xl&0xff, c->user_data);
      c->callback ((xr>>24)&0xff, c->user_data);
      c->callback ((xr>>16)&0xff, c->user_data);
      c->callback ((xr>>8)&0xff, c->user_data);
      c->callback (xr&0xff, c->user_data);
      c->b = 0;
      c->dl = 0;
      c->dr = 0;
   }
}

void
Blowfish_cbc_stop (struct blf_cbc_ctx *c)
{
   for ( ; c->b ; ) /* ``Cryptic'', isn't it? */
      Blowfish_cbc_feed (c, 0);
}

void printUsage()
{
   printf("DecryptArcTool\nUsage:\n\tdecryptArcTool <archive> <output Archive>\n");
}

#pragma pack(1)
typedef struct HeaderStruct
{
   unsigned int magic;
   unsigned short version;
   unsigned short numFiles;
} HeaderStruct;
#pragma pack()

#pragma pack(1)
typedef struct FileData
{
   char filename[64];
   unsigned int type;
   unsigned int zsize;
   union
   {
      unsigned int size;
      unsigned char sbytes[4];
   };
   unsigned int offset;
} FileData;
#pragma pack()

class Stream
{
public:
   Stream()
   {
      
   }
   
   virtual ~Stream()
   {
   }
   
   virtual unsigned int read(int numBytes, void* data) = 0;
   virtual unsigned int write(int numBytes, void* data) = 0;
   
   virtual void setStreamPos(unsigned int pos) = 0;
   virtual void advanceStreamPos(unsigned int pos) = 0;
   virtual unsigned int getStreamPos() = 0;
   virtual unsigned int getStreamSize() = 0;
   virtual bool isEOF() = 0;
};

class FileStream : public Stream
{
public:
   FileStream() :
   mFP(0)
   {
   }
   
   virtual ~FileStream()
   {
      close();
   }
   
   bool open(const char *path, const char *mode)
   {
      mFP = fopen(path, mode);
      return mFP != NULL;
   }
   
   void close()
   {
      if (mFP)
         fclose(mFP);
      mFP = NULL;
   }
   
   virtual unsigned int read(int numBytes, void* data)
   {
      return fread(data, 1, numBytes, mFP);
   }
   
   virtual unsigned int write(int numBytes, void* data)
   {
      return fwrite(data, 1, numBytes, mFP);
   }
   
   virtual void setStreamPos(unsigned int pos)
   {
      fseek(mFP, pos, SEEK_SET);
   }
   
   virtual void advanceStreamPos(unsigned int pos)
   {
      fseek(mFP, pos, SEEK_CUR);
   }
   
   virtual unsigned int getStreamPos()
   {
      return ftell(mFP);
   }
   
   virtual unsigned int getStreamSize()
   {
      int pos = ftell(mFP);
      fseek(mFP, 0, SEEK_END);
      int end = ftell(mFP);
      fseek(mFP, pos, SEEK_SET);
      return end;
   }
   
   virtual bool isEOF()
   {
      return feof(mFP);
   }

protected:
   
   FILE *mFP;
};

class CryptedFileStream : public FileStream
{
public:
   unsigned char mBuffer[2048];
   unsigned int mBufferPos;
   unsigned int mBufferSize;
   bool mWriting;
   struct blf_ctx mCryptState;
   
   CryptedFileStream(const char *key) :
   mBufferPos(0),
   mBufferSize(0),
   mWriting(false)
   {
      Blowfish_initialize(&mCryptState, (const unsigned char*)key, strlen((const char*)key));
   }
   
   bool open(const char *path, const char *mode)
   {
      if (FileStream::open(path, mode))
      {
         mWriting = strstr(mode, "w") != NULL;
         mBufferPos = 0;
         mBufferSize = 0;
         return true;
      }
      
      return false;
   }
   
   virtual unsigned int read(int numBytes, void* data)
   {
      unsigned char *ptr = (unsigned char*)data;
      unsigned int originalBytes = numBytes;
      if (mWriting)
         return 0;
      
      while (numBytes != 0)
      {
         int bytesAvailable = mBufferSize-mBufferPos;
         
         if (bytesAvailable == 0)
         {
            if (!flushBuffer()) // check for EOF
               break;
         }
         else
         {
            int bytesToRead = bytesAvailable > numBytes ? numBytes : bytesAvailable;
            memcpy(ptr, mBuffer+mBufferPos, bytesToRead);
            ptr += bytesToRead;
            mBufferPos += bytesToRead;
            numBytes -= bytesToRead;
         }
      }
      
      return originalBytes - numBytes;
   }
   
   virtual unsigned int write(int numBytes, void* data)
   {
      unsigned char *ptr = (unsigned char*)data;
      unsigned int originalBytes = numBytes;
      if (!mWriting)
         return 0;
      
      while (numBytes != 0)
      {
         int bytesAvailable = mBufferSize-mBufferPos;
         
         if (bytesAvailable == 0)
         {
            if (!flushBuffer()) // check for EOF
               break;
         }
         else
         {
            int bytesToWrite = bytesAvailable > numBytes ? numBytes : bytesAvailable;
            memcpy(ptr, mBuffer+mBufferPos, bytesToWrite);
            ptr += bytesToWrite;
            mBufferPos += bytesToWrite;
            numBytes -= bytesToWrite;
         }
      }
      
      return originalBytes - numBytes;
   }
   
   virtual void setStreamPos(unsigned int pos)
   {
      if (mWriting)
         flushBuffer();
      
      fseek(mFP, pos, SEEK_SET);
      
      flushBuffer();
   }
   
   virtual void advanceStreamPos(unsigned int pos)
   {
      if (mWriting)
         flushBuffer();
      
      fseek(mFP, pos, SEEK_CUR);
      
      flushBuffer();
   }
   
   bool flushBuffer()
   {
      if (mWriting)
      {
         // Make sure write is aligned
         int alignedOffset = mBufferPos % 8;
         if (alignedOffset > 0)
            mBufferPos += 8-alignedOffset;
         
         int bytesThisWrite = mBufferPos;
         int bytesProcessed = 0;
         
         while (bytesThisWrite != 0)
         {
            if (bytesThisWrite >= 8)
            {
               Blowfish_encipher(&mCryptState, (unsigned int*)&mBuffer[bytesProcessed], (unsigned int*)&mBuffer[bytesProcessed+4]);
            }
            
            bytesProcessed += 8;
            bytesThisWrite -= 8;
            
            //printf("bpo: %u %u\n", bytesProcessed, bytesThisWrite);
         }
         
         int bytesWritten = fwrite(mBuffer, 1, mBufferPos, mFP);
         mBufferPos = 0;
         mBufferSize = sizeof(mBuffer);
         memset(mBuffer, '\0', sizeof(mBuffer));
         
         if (bytesWritten <= 0)
            return false;
      }
      else
      {
         memset(mBuffer, '\0', sizeof(mBuffer));
         mBufferPos = 0;
         mBufferSize = fread(mBuffer, 1, sizeof(mBuffer), mFP);
         
         if (mBufferSize <= 0)
            return false;
         
         int bytesProcessed = 0;
         int paddedBytesThisRead = mBufferSize;
         
         // Decrypt buffer
         while (bytesProcessed < mBufferSize)
         {
            if (paddedBytesThisRead >= 8)
            {
               Blowfish_decipher(&mCryptState, (unsigned int*)&mBuffer[bytesProcessed], (unsigned int*)&mBuffer[bytesProcessed+4]);
               
               bytesProcessed += 8;
               paddedBytesThisRead -= 8;
            }
            else if (paddedBytesThisRead != 0)
            {
               // Lets just decipher anyway, hope there is no garbage
               Blowfish_decipher(&mCryptState, (unsigned int*)&mBuffer[bytesProcessed], (unsigned int*)&mBuffer[bytesProcessed+4]);
               
               bytesProcessed += paddedBytesThisRead;
               paddedBytesThisRead = 0;
            }
         }
      }
      
      return true;
   }
   
   virtual unsigned int getStreamPos()
   {
      return ftell(mFP) + mBufferPos;
   }
   
   virtual bool isEOF()
   {
      int bytesAvailable = mBufferSize-mBufferPos;
      return bytesAvailable == 0 && FileStream::isEOF();
   }
};


class ArchiveFile
{
public:
   HeaderStruct mHeader;
   std::vector<FileData> mFileInfos;
   
   bool mEncrypted;
   struct blf_ctx mCryptState;
   unsigned char mBuffer[131072];
   unsigned int mBufferPos;
   
   Stream *mInFile;
   FileStream *mDebugFile;
   
   // Map of type code -> resource extension
   static std::unordered_map<unsigned int, std::string> sIdToExtensionMap;
   static std::unordered_map<unsigned int, std::string> sExtensionToIdMap;
   
   ArchiveFile() :
   mInFile(NULL),
   mDebugFile(NULL),
   mBufferPos(0),
   mEncrypted(false)
   {
      const char *key = "";
      memset(&mCryptState, '\0', sizeof(mCryptState));
      Blowfish_initialize(&mCryptState, (const unsigned char*)key, strlen((const char*)key));
   }
   
   ~ArchiveFile()
   {
      
   }
   
   void setKey(const char *key)
   {
      if (key == NULL)
      {
         return;
      }
      
      memset(&mCryptState, '\0', sizeof(mCryptState));
      Blowfish_initialize(&mCryptState, (const unsigned char*)key, strlen((const char*)key));
   }
   
   // Reads memory from file, decrypting if neccesary
   int readData(void *data, unsigned int offset, unsigned int bytes)
   {
      unsigned char *ptr = (unsigned char*)data;
      if (mEncrypted)
      {
         // Decryptathon
         int alignedOffset = offset % 8;
         offset -= alignedOffset;
         
         // TBD: is there any case where offsets aren't aligned?
         //assert(alignedOffset == 0);
         
         if (mInFile->getStreamPos() != offset)
         {
            mInFile->setStreamPos(offset);
         }
         
         // Read buffer taking into account alignment
         int bytesRead = 0;
         while (bytesRead != bytes)
         {
            int bytesToRead = bytes - bytesRead;
            bytesToRead = bytesToRead > sizeof(mBuffer) ? sizeof(mBuffer) : bytesToRead;
            
            // Pad the read if we're not on an 8-byte alignment
            int alignedEndOffset = (bytesToRead % 8);
            
            if (alignedEndOffset > 0)
            {
               alignedEndOffset = 8-alignedEndOffset;
            }
            
            int paddedBytesThisRead = bytesToRead + alignedEndOffset;
            int bytesThisRead = mInFile->read(paddedBytesThisRead, mBuffer);
            if (bytesThisRead < bytesToRead)
            {
               printf("Failed to read file!\n");
               break;
            }
            
            // Decrypt buffer so far
            int bytesProcessed = 0;
            while (bytesProcessed < bytesThisRead)
            {
               if (paddedBytesThisRead >= 8)
               {
                  Blowfish_decipher(&mCryptState, (unsigned int*)&mBuffer[bytesProcessed], (unsigned int*)&mBuffer[bytesProcessed+4]);
                  
                  bytesProcessed += 8;
                  paddedBytesThisRead -= 8;
               }
               else if (paddedBytesThisRead != 0)
               {
                  // Lets just decipher anyway, hope there is no garbage
                  Blowfish_decipher(&mCryptState, (unsigned int*)&mBuffer[bytesProcessed], (unsigned int*)&mBuffer[bytesProcessed+4]);
                  
                  bytesProcessed += paddedBytesThisRead;
                  paddedBytesThisRead = 0;
               }
            }
            
            // Copy bytes out, taking into account any current offset
            memcpy(ptr, mBuffer + alignedOffset, bytesToRead);
            ptr += bytesToRead;
            bytesRead += bytesToRead;
            
            if (bytesRead > bytes)
            {
               assert(false);
            }
            
            // Reset any alignment offset since we should be ok now
            alignedOffset = 0;
         }
         
         if (gDebugMode) printf("Read %i bytes from file pos now %i\n", bytesRead, mInFile->getStreamPos());
      }
      else
      {
         // Seek, read. Simple.
         if (mInFile->getStreamPos() != offset)
         {
            mInFile->setStreamPos(offset);
         }
         
         // Read buffer taking into account alignment
         int bytesRead = 0;
         while (bytesRead != bytes)
         {
            int bytesToRead = bytes - bytesRead;
            bytesToRead = bytesToRead > sizeof(mBuffer) ? sizeof(mBuffer) : bytesToRead;
            
            int bytesThisRead = mInFile->read(bytesToRead, mBuffer);
            if (bytesThisRead != bytesToRead)
            {
               printf("Failed to read file!\n");
               return false;
            }
            
            // Copy bytes out, taking into account any current offset
            memcpy(data, mBuffer, bytesThisRead);
            bytesRead += bytesThisRead;
         }
      }
      
      return true;
   }
   
   int writeData(void *ptr, unsigned int bytes)
   {
      if (gDebugMode) printf("writeData %u\n", bytes);
      // Keep on writing
      unsigned int bytesWritten = 0;
      unsigned char *data = (unsigned char*)ptr;
      while (bytesWritten != bytes)
      {
         unsigned int bytesToWrite = bytes - bytesWritten;
         unsigned int bufferBytesLeft = sizeof(mBuffer) - mBufferPos;
         
         // Flush if neccesary
         if (bufferBytesLeft == 0)
         {
            // Cypt
            flushWriteBuffer();
            bufferBytesLeft = sizeof(mBuffer);
         }
         
         bytesToWrite = bytesToWrite > bufferBytesLeft ? bufferBytesLeft : bytesToWrite;
         
         // Copy bytes
         if (bytesToWrite > 0)
         {
            memcpy(mBuffer + mBufferPos, data, bytesToWrite);
            data += bytesToWrite;
         }
         
         mBufferPos += bytesToWrite;
         bufferBytesLeft -= bytesToWrite;
         bytesWritten += bytesToWrite;
      }
      
      return bytes;
   }
   
   // Begins writing archive, seeks to start of file data
   void beginWriteArchive(unsigned int numFiles, bool encrypted, Stream *outStream)
   {
      mEncrypted = encrypted;
      mHeader.magic = 1128485441;
      mHeader.numFiles = numFiles;
      mHeader.version = 7;
      mInFile = outStream;
      mBufferPos = 0;
      memset(mBuffer, '\0', sizeof(mBuffer));
      
      mInFile->write(sizeof(mHeader), &mHeader);
      mInFile->setStreamPos(sizeof(mHeader) + (numFiles * sizeof(FileData)));
      
      /*mDebugFile = new FileStream();
      mDebugFile->open("/Users/mangofusion/uncrypted.arc", "wb");
      mDebugFile->write(sizeof(mHeader), &mHeader);
      mDebugFile->setStreamPos(sizeof(mHeader) + (numFiles * sizeof(FileData)));*/
   }
   
   // Adds a file to the archive, writing it from storage. Also compresses it.
   bool addFile(const char *filename, Stream *stream)
   {
      unsigned char inBuffer[131072];
      unsigned char outBuffer[131072];
      FileData data;
      unsigned int status;
      
      // Strip out "./" in filename
      if (strncmp(filename, "./", 2) == 0)
      {
         filename += 2;
      }
      
      int nameLen = strlen(filename);
      
      // Find last "." in filename
      const char *ext = strrchr(filename, '.');
      if (ext != NULL)
      {
         nameLen = ext - filename;
         ext++;
      }
      else
      {
         printf("Skipping %s (no extension)\n", filename);
         return true;
      }
      
      if (nameLen > 63)
      {
         nameLen = 63;
      }
      
      // Fill in info
      strncpy(data.filename, filename, nameLen);
      data.type = getTypeFromExtension(ext);
      data.filename[nameLen] = '\0';
      data.offset = mInFile->getStreamPos();
      data.type = atoi(ext);
      
      if (data.offset % 8 != 0)
      {
         assert(false);
      }
      
      printf("Adding file %s (type %u)\n", data.filename, data.type);
      
      // Create zlib stream
      z_stream_s writeZlibStream;
      writeZlibStream.zalloc = Z_NULL;
      writeZlibStream.zfree = Z_NULL;
      writeZlibStream.opaque = Z_NULL;
      
      writeZlibStream.next_in   = inBuffer;
      writeZlibStream.avail_in  = sizeof(inBuffer);
      writeZlibStream.total_in  = 0;
      writeZlibStream.next_out  = outBuffer;
      writeZlibStream.avail_out = sizeof(outBuffer);
      writeZlibStream.total_out = 0;
      
      deflateInit(&writeZlibStream, Z_DEFAULT_COMPRESSION);
      
      unsigned int bytesRemaining = stream->getStreamSize();
      while (bytesRemaining != 0)
      {
         int bytesToRead = bytesRemaining > sizeof(inBuffer) ? sizeof(inBuffer) : bytesRemaining;
         
         int writeB = stream->read(bytesToRead, &inBuffer);
         if (writeB < bytesToRead)
         {
            deflateEnd(&writeZlibStream);
            printf("FAIL FREAD %u %i / %u\n", bytesToRead, writeB, bytesRemaining);
            return false;
         }
         
         // Compress buffer
         writeZlibStream.next_in  = inBuffer;
         writeZlibStream.avail_in = bytesToRead;
         
         while(writeZlibStream.avail_in != 0)
         {
            if (writeZlibStream.avail_out == 0)
            {
               // Dump buffer
               int bytesToWrite = sizeof(outBuffer);
               if (writeData(&outBuffer, bytesToWrite) < 1)
               {
                  // ABORT
                  bytesRemaining = 0;
                  printf("FAIL WRITE %u\n", bytesToWrite);
                  return false;
               }
               
               writeZlibStream.next_out  = outBuffer;
               writeZlibStream.avail_out = sizeof(outBuffer);
            }
            
            // Deflate
            status = deflate(&writeZlibStream, Z_NO_FLUSH);
         }
         
         bytesRemaining -= bytesToRead;
      }
      
      // Finish
      writeZlibStream.avail_in = 0;
      deflate(&writeZlibStream, Z_FINISH);
      int bytesToWrite = sizeof(outBuffer) - writeZlibStream.avail_out;
      writeData(&outBuffer, bytesToWrite);
      
      // Update data
      
      data.size = writeZlibStream.total_in + 0x40000000;
      data.zsize = writeZlibStream.total_out;
      
      deflateEnd(&writeZlibStream);
      
      mFileInfos.push_back(data);
      
      flushWriteBuffer();
      
      // Make sure pos is aligned
      unsigned int spos = mInFile->getStreamPos();
      if (spos % 8 != 0)
      {
         unsigned char padding[8];
         memset(padding, '\0', sizeof(padding));
         mInFile->write(8 - (spos % 8), &padding);
         // DEBUG mDebugFile->write(8 - (spos % 8), &padding);
      }
      
      return true;
   }
   
   // Completes archive
   void endWriteArchive()
   {
      flushWriteBuffer();
      
      mInFile->setStreamPos(8);
      // DEBUG mDebugFile->setStreamPos(8);
      
      writeData(&mFileInfos[0], mFileInfos.size() * sizeof(FileData));
      
      flushWriteBuffer();
      
      mInFile = NULL;
      // DEBUG delete mDebugFile;
   }
   
   void flushWriteBuffer()
   {
      if (gDebugMode) printf("flushWriteBuffer %u (%s)\n", mBufferPos, mBufferPos % 8 == 0 ? "ALIGNED" : "UNALIGNED");
      if (mBufferPos > 0)
      {
         unsigned int bytesThisWrite = mBufferPos;
         unsigned int bytesProcessed = 0;
         
         // Lets just pad these bytes to keep things simple
         if (bytesThisWrite % 8 != 0)
         {
            bytesThisWrite += 8 - ((int)bytesThisWrite % 8);
            mBufferPos = bytesThisWrite;
         }
         
         // Crypt buffer if we are encrypted
         if (mEncrypted)
         {
            // DEBUG mDebugFile->write(mBufferPos, &mBuffer);
            
            while (bytesThisWrite != 0)
            {
               if (bytesThisWrite >= 8)
               {
                  Blowfish_encipher(&mCryptState, (unsigned int*)&mBuffer[bytesProcessed], (unsigned int*)&mBuffer[bytesProcessed+4]);
               }
               
               bytesProcessed += 8;
               bytesThisWrite -= 8;
               
               //printf("bpo: %u %u\n", bytesProcessed, bytesThisWrite);
            }
         }
         
         // Make sure we are aligned
         if (mInFile->getStreamPos() % 8 != 0)
         {
            assert(false);
         }
         mInFile->write(mBufferPos, &mBuffer);
         
         memset(mBuffer, '\0', sizeof(mBuffer));
         mBufferPos = 0;
      }
   }
   
   bool extractFile(const FileData &file, Stream *stream)
   {
      // Seek and write it
      unsigned char inBuffer[131072];
      unsigned char outBuffer[131072];
      int status;
      unsigned int offset = file.offset;
      
      // Create zlib stream
      z_stream_s readZlibStream;
      readZlibStream.zalloc = Z_NULL;
      readZlibStream.zfree = Z_NULL;
      readZlibStream.opaque = Z_NULL;
      
      readZlibStream.next_in   = inBuffer;
      readZlibStream.avail_in  = 0;
      readZlibStream.total_in  = 0;
      readZlibStream.next_out  = outBuffer;
      readZlibStream.avail_out = sizeof(outBuffer) >  file.size ? file.size : sizeof(outBuffer);
      readZlibStream.total_out = 0;
      
      inflateInit(&readZlibStream);
      
      unsigned int compressedBytesRemaining = file.zsize;
      unsigned int bytesRemaining = file.size;
      unsigned int bytesThisChunk = readZlibStream.avail_out;
      bool eob = false;
      while (bytesRemaining != 0 && !eob)
      {
         while(readZlibStream.avail_out != 0)
         {
            if(readZlibStream.avail_in == 0)
            {
               // Deflate
               status = inflate(&readZlibStream, Z_SYNC_FLUSH);
               
               // Make sure we have enough data
               if (readZlibStream.total_out < file.size)
               {
                  // Fill up compressed buffer
                  int bytesToRead = compressedBytesRemaining > sizeof(inBuffer) ? sizeof(inBuffer) : compressedBytesRemaining;
                  
                  if (!readData(&inBuffer, offset, bytesToRead))
                  {
                     inflateEnd(&readZlibStream);
                     return false;
                  }
                  
                  readZlibStream.avail_in = bytesToRead;
                  readZlibStream.next_in = inBuffer;
                  compressedBytesRemaining -= bytesToRead;
                  offset += bytesToRead;
               }
            }
            
            // Deflate
            status = 0;
            if (readZlibStream.total_out < file.size)
            {
               status = inflate(&readZlibStream, Z_NO_FLUSH);
            }
            
            switch (status) {
               case Z_NEED_DICT:
               case Z_DATA_ERROR:
               case Z_MEM_ERROR:
               case Z_STREAM_ERROR:
                  printf("Compressed stream error!\n");
                  inflateEnd(&readZlibStream);
                  return false;
               case Z_BUF_ERROR:
                  printf("Buffer error\n");
                  break;
               case Z_STREAM_END:
                  eob = true;
                  readZlibStream.avail_in = 0;
                  break;
            }
         }
         
         // Dump buffer, reset output
         int bytesToWrite = bytesThisChunk - readZlibStream.avail_out;
         if (stream->write(bytesToWrite, &outBuffer) != bytesToWrite)
         {
            // ABORT
            return false;
         }
         bytesRemaining -= bytesToWrite;
         
         // Set output
         bytesToWrite = bytesRemaining > sizeof(outBuffer) ? sizeof(outBuffer) : bytesRemaining;
         readZlibStream.avail_out = bytesToWrite;
         readZlibStream.next_out = outBuffer;
         
         bytesThisChunk = readZlibStream.avail_out;
      }
      
      inflateEnd(&readZlibStream);
      
      return true;
   }
   
   unsigned int getTypeFromExtension(const char *extension)
   {
      return 0;
   }
   
   const char *getNameFromType(unsigned int type)
   {
      return "dat";
   }
   
   bool read(Stream* stream)
   {
      mInFile = stream;
      
      // Read header
      if (mInFile->read(8, &mHeader) < 1)
      {
         return false;
      }
      
      if (mHeader.magic == 1128485441)
      {
         mEncrypted = true;
      }
      else
      {
         printf("Not an ARCC file\n");
         return false;
      }
      
      // Read file infos
      mFileInfos.resize(mHeader.numFiles);
      readData(&mFileInfos[0], 8, sizeof(FileData) * mHeader.numFiles);
      
      // Correct file sizes
      for (int i=0; i<mFileInfos.size(); i++)
      {
         if (mFileInfos[i].size & 0x40000000)
         {
            mFileInfos[i].size -= 0x40000000;
         }
      }
      
      return true;
   }
   
   static void initExtensionMap()
   {
      // TODO
   }
};

static const char Base16Values[] = "0123456789ABCDEF";

inline unsigned char parse_key_digit(unsigned char c)
{
   if (c >= '0' && c <= '9')
      return c - '0';
   else if (c >= 'a' && c <= 'f')
      return 0xa + (c - 'a');
   else if (c >= 'A' && c <= 'F')
      return 0xa + (c - 'A');
   else
      return 0xFF;
}

void parse_key(const char *value, unsigned char *out, int outsize)
{
   int len = strlen(value);
   unsigned char *outptr = out;
   
   for (int Index = 0; Index < len; Index += 2)
   {
      if (Index == len-1)
      {
         unsigned char v = parse_key_digit(*value++);
         if (v  == 0xFF)
            break;
         *outptr++ = v;
      }
      else
      {
         unsigned char v1 = parse_key_digit(*value++);
         if (v1 == 0xFF)
            break;
         
         unsigned char v2 = parse_key_digit(*value++);
         if (v2 == 0xFF)
         {
            *outptr++ = v1;
            break;
         }
         
         *outptr++ = (v1 << 4) | (v2);
      }
      
      if (outptr - out >= outsize-1)
         break;
   }
   
   *outptr++ = '\0';
}

char sInKey[64];
char sInIAPKey[64];

bool get_arc_params(int argc, const char **argv, const char **inKey, const char **inIapKey, const char ***files, int *numFiles, const char **outputFolder)
{
   for (int i=0; i<argc; i++)
   {
      if (strlen(argv[i]) > 1 && argv[i][0] == '-')
      {
         const char *name = argv[i] + 1;
         
         if (strcasecmp(name, "key") == 0)
         {
            if (i+1 < argc)
            {
               if (strncmp(argv[i+1], "0x", 2) == 0)
               {
                  parse_key(argv[i+1]+2, (unsigned char*)&sInKey, sizeof(sInKey));
                  *inKey = &sInKey[0];
               }
               else
               {
                  *inKey = argv[i+1];
               }
               i++;
            }
         }
         else if (strcasecmp(name, "iapKey") == 0)
         {
            if (i+1 < argc)
            {
               if (strncmp(argv[i+1], "0x", 2) == 0)
               {
                  parse_key(argv[i+1]+2, (unsigned char*)&sInIAPKey, sizeof(sInIAPKey));
                  *inIapKey = &sInIAPKey[0];
               }
               else
               {
                  *inIapKey = argv[i+1];
               }
               i++;
            }
         }
         else if (strcasecmp(name, "cwd") == 0)
         {
            if (i+1 < argc)
            {
               *outputFolder = argv[i+1];
               i++;
            }
         }
         else if (strcasecmp(name, "dbg") == 0)
         {
            gDebugMode = true;
         }
         else
         {
            printUsage();
            return false;
         }
         continue;
      }
      
      // No more flags
      *numFiles = argc - i;
      *files = argv+i;
      break;
   }
   
   return true;
}


void fix_path(char *path)
{
   int len = strlen(path);
   for (int i=0; i<len; i++)
   {
      if (path[i] == '/' || path[i] == '\\')
         path[i] = '/';
   }
}

bool folder_exists(const char *path)
{
   // Sanitize path
   char folderpath[4096];
   strncpy(folderpath, path, sizeof(folderpath));
   folderpath[sizeof(folderpath)-1] = '\0';
   fix_path(folderpath);
   
   struct stat fStat;
   if (stat(folderpath, &fStat) < 0)
      return false;
   
   // if the file is a Directory then true
   if ( (fStat.st_mode & S_IFMT) == S_IFDIR)
      return true;
   
   return false;
}

bool create_folder(const char *path)
{
   // Sanitize path
   char folderpath[4096];
   char folderbuf[4096];
   strncpy(folderpath, path, sizeof(folderpath));
   folderpath[sizeof(folderpath)-1] = '\0';
   fix_path(folderpath);
   folderbuf[0] = '\0';
   
   // Iterate and create
   const char *ptr = folderpath;
   while((ptr = strchr(ptr, '/')) != NULL)
   {
      if (ptr - folderpath > 0)
      {
         strncpy(folderbuf, folderpath, ptr - folderpath);
         folderbuf[(ptr-folderpath)] = 0;
      }
      
      if (strlen(folderbuf) > 0 && !folder_exists(folderbuf))
      {
         if (mkdir(folderbuf, 0700) != 0)
            return false;
      }
      
      ptr++;
   }
   
   // Sort out final /
   if (strlen(path) > 0 && !folder_exists(path))
   {
      if (mkdir(path, 0700) != 0)
         return false;
   }
   
   return true;
}

int compress_files(int argc, const char *argv[])
{
   const char* inKey = NULL;
   const char* inIapKey = NULL;
   const char **filenames = NULL;
   const char *output_folder = getcwd(NULL, 0);
   int numFiles = 0;
   if (!get_arc_params(argc, argv, &inKey, &inIapKey, &filenames, &numFiles, &output_folder))
   {
      printUsage();
      return 1;
   }
   
   if (numFiles < 1)
   {
      printUsage();
      return 1;
   }
   
   ArchiveFile archive;
   archive.setKey(inKey);
   FileStream *outStream = inIapKey == NULL ? new FileStream : new CryptedFileStream(inIapKey);
   
   if (!outStream->open(filenames[0], "wb"))
   {
      printf("Error output file %s\n", argv[0]);
      delete outStream;
      return 1;
   }
   
   archive.beginWriteArchive(argc-1, inKey ? true : false, outStream);
   
   for (int i=1; i<numFiles; i++)
   {
      FileStream file;
      
      if (!file.open(filenames[i], "rb"))
      {
         printf("Couldn't open %s\n", argv[i]);
         delete outStream;
         return 1;
      }
      
      if (!archive.addFile(filenames[i], &file))
      {
         printf("Error adding %s\n", filenames[i]);
         delete outStream;
         return 1;
      }
   }
   
   archive.endWriteArchive();
   delete outStream;
   
   return 0;
}

int extract_files(int argc, const char *argv[])
{
   const char* inKey = NULL;
   const char* inIapKey = NULL;
   const char **filenames = NULL;
   const char *output_folder = getcwd(NULL, 0);
   int numFiles = 0;
   if (!get_arc_params(argc, argv, &inKey, &inIapKey, &filenames, &numFiles, &output_folder))
   {
      printUsage();
      return 1;
   }
   
   // Read everything
   ArchiveFile archive;
   archive.setKey(inKey);
   FileStream *inStream = inIapKey == NULL ? new FileStream : new CryptedFileStream(inIapKey);
   
   if (numFiles < 1)
   {
      printUsage();
      return 1;
   }
   
   const char *inFilename = filenames[0];
   
   if (!inStream->open(inFilename, "rb"))
   {
      printf("Error input file %s\n", inFilename);
      return 1;
   }
   
   if (!archive.read(inStream))
   {
      printf("Invalid archive file %s\n", inFilename);
      return 1;
   }
   
   char basepath[4096];
   char filepath[4096];
   strncpy(basepath, output_folder, sizeof(basepath));
   basepath[sizeof(basepath)-1] = '\0';
   
   // Make sure output exists
   if (!folder_exists(output_folder))
   {
      create_folder(output_folder);
   }
   
   // Strip off end '/'
   int len = strlen(basepath);
   if (basepath[len] == '/' || basepath[len] == '\\')
      basepath[len] = '\0';
   
   // Enumerate files in archive
   for (std::vector<FileData>::iterator file = archive.mFileInfos.begin(); file != archive.mFileInfos.end(); file++)
   {
      // Extract file
      FileStream outFile;
      
      // Sanitize path
      char folderpath[64];
      strncpy(folderpath, file->filename, 63);
      folderpath[63] = '\0';
      fix_path(folderpath);
      
      if (gDebugMode) printf("folderPath == %s\n", folderpath);
      
      snprintf(filepath, sizeof(filepath), "%s/%s.%u", basepath, folderpath, file->type);
      
      // Strip / off folder path
      
      
      char *folder = strrchr(filepath, '/');
      if (folder != NULL)
      {
         *folder = '\0';
         if (!folder_exists(filepath))
         {
            if (!create_folder(filepath))
            {
               printf("Failed to create folder %s\n", filepath);
               return 1;
            }
         }
         
         // Add back on!
         *folder = '/';
      }
      
      if (!outFile.open(filepath, "wb"))
      {
         printf("Failed to open %s\n", filepath);
         return 1;
      }
      
      printf("Extracting %s... [code %u , %x %x %x %x size %u offset %u]\n", filepath, file->type, file->sbytes[0], file->sbytes[1], file->sbytes[2], file->sbytes[3], file->size, file->offset);
      archive.extractFile(*file, &outFile);
   }
   
   delete inStream;
   
   return 0;
}

int dump_arc(int argc, const char *argv[])
{
   const char* inKey = NULL;
   const char* inIapKey = NULL;
   const char **filenames = NULL;
   const char *output_folder = getcwd(NULL, 0);
   int numFiles = 0;
   if (!get_arc_params(argc, argv, &inKey, &inIapKey, &filenames, &numFiles, &output_folder))
   {
      printUsage();
      return 1;
   }
   
   // Read everything
   ArchiveFile archive;
   archive.setKey(inKey);
   FileStream *inStream = inIapKey == NULL ? new FileStream : new CryptedFileStream(inIapKey);
   FileStream *outStream = new FileStream;
   
   if (numFiles < 2)
   {
      printUsage();
      return 1;
   }
   
   const char *inFilename = filenames[0];
   const char *outFilename = filenames[1];
   
   if (!inStream->open(inFilename, "rb"))
   {
      printf("Error input file %s\n", inFilename);
      return 1;
   }
   
   if (!archive.read(inStream))
   {
      printf("Invalid archive file %s\n", inFilename);
      return 1;
   }
   
   // Dump to output
   HeaderStruct header = archive.mHeader;
   //archive.mEncrypted = outKey != NULL;
   
   if (!outStream->open(outFilename, "wb"))
   {
      printf("Error output file %s\n", outFilename);
      return 1;
   }
   
   archive.setKey(NULL);
   outStream->write(8, &header);
   
   unsigned int size = inStream->getStreamSize()-8;
   unsigned char *data = (unsigned char*)malloc(size);
   
   archive.readData(data, 8, size);
   outStream->write(size, data);
   
   delete inStream;
   delete outStream;
   
   free(data);
   return 0;
}

int main(int argc, const char * argv[])
{
   if (argc < 3)
   {
      printUsage();
      return 1;
   }
   
   if (strcasecmp(argv[1], "create") == 0)
   {
      return compress_files(argc-2, argv+2);
   }
   else if (strcasecmp(argv[1], "extract") == 0)
   {
      return extract_files(argc-2, argv+2);
   }
   else if (strcasecmp(argv[1], "dump") == 0)
   {
      return dump_arc(argc-2, argv+2);
   }
   else
   {
      printUsage();
      return 1;
   }
   
   /*
   FILE *fIn = fopen(argv[1], "rb");
   if (!fIn)
   {
      printf("Error input file %s\n", argv[1]);
      return 1;
   }
   
   FILE *fOut = fopen(argv[2], "wb");
   if (!fIn)
   {
      printf("Error output file %s\n", argv[2]);
      return 1;
   }
   
   // First read the header from input
   int headerRead = fread(&header, 8, 1, fIn);
   if (headerRead == 0)
   {
      printf("Could not read header!\n");
      fclose(fIn);
      fclose(fOut);
      return 1;
   }
   
   if (header.magic != 1128485441)
   {
      printf("Not an ARCC file\n");
      fclose(fIn);
      fclose(fOut);
      return 1;
   }
   
   fwrite(&header, 8, 1, fOut);
   fseek(fIn, 8, SEEK_SET);
   
   int totalBytes = 0;
   
   while (!feof(fIn))
   {
      int bytesRead = fread(&buffer, 1, sizeof(buffer), fIn);
      int bytesProcessed = 0;
      int bytesLeft = bytesRead;
      
      while (bytesProcessed != bytesRead)
      {
         if (bytesLeft >= 8)
         {
            Blowfish_decipher(&c, (unsigned int*)&buffer[bytesProcessed], (unsigned int*)&buffer[bytesProcessed+4]);
         }
         else if (bytesLeft != 0)
         {
            // TODO
            printf("TODO: handle padding bytes\n");
            fclose(fIn);
            fclose(fOut);
            return 1;
         }
         
         bytesProcessed += 8;
         bytesLeft -= 8;
         totalBytes += 8;
      }
      
      fwrite(&buffer, 1, bytesProcessed, fOut);
   }
   
   fclose(fIn);
   printf("Decrypted %i bytes\n", totalBytes);
   
   // Seek input again
   fclose(fOut);
   
   fOut = fopen(argv[2], "rb");
   if (!fIn)
   {
      printf("Error reopening output file %s\n", argv[2]);
      return 1;
   }
   
   fseek(fOut, 8, SEEK_SET);
   
   // Print files
   printf("Files: %i [info size == %u]\n", header.numFiles, sizeof(FileData));
   FileData *files = (FileData*)malloc(sizeof(FileData) * header.numFiles);
   int readData = fread(files, sizeof(FileData), header.numFiles, fOut);
   
   if (readData == header.numFiles)
   {
      printf("Files: %i\n", header.numFiles);
      for (int i=0; i<header.numFiles; i++)
      {
         printf("\t[%s] type %u zsize %u size %u offset %u\n", files[i].filename, files[i].type, files[i].zsize, files[i].size, files[i].offset);
         
         z_stream strm;
         int ret = inflateInit(&strm);
         
         // Write to the end of the file for reference
         fseek(fOut, files[i].offset, SEEK_SET);
         int bytesLeft = files[i].zsize;
         
         if (ret != Z_OK)
            return ret;
         
         unsigned char *outData = (unsigned char*)malloc(files[i].size);
         unsigned char *endData = outData + files[i].size;
         unsigned char *outDataPtr = outData;
         
         while ((bytesLeft != 0 && ret != Z_STREAM_END))
         {
            int bytesToRead = bytesLeft > sizeof(buffer) ? sizeof(buffer) : bytesLeft;
            if (endData == outDataPtr)
               break;
            
            // Add to zlib state
            strm.avail_in = fread(buffer, 1, bytesToRead, fOut);
            
            if (strm.avail_in == 0)
               break;
            
            strm.next_in = buffer;
            // run inflate() on input until output buffer not full
            do {
               int startOut = strm.avail_out = endData - outDataPtr;
               strm.next_out = outDataPtr;
               
               ret = inflate(&strm, Z_NO_FLUSH);
               assert(ret != Z_STREAM_ERROR);
               switch (ret) {
                  case Z_NEED_DICT:
                     ret = Z_DATA_ERROR;
                  case Z_DATA_ERROR:
                  case Z_MEM_ERROR:
                     (void)inflateEnd(&strm);
                     return ret;
               }
               
               int haveBytes = startOut - strm.avail_out;
               outDataPtr += haveBytes;
               
            } while (strm.avail_out == 0);
            
            bytesLeft -= bytesToRead;
         }
         
         inflateEnd(&strm);
         
         free(outData);
      }
   }
   free(files);
   
   printf("---------------\n");
   
    fclose(fIn);
    fclose(fOut);*/
   
   
    return 0;
}

