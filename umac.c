/* $OpenBSD: umac.c,v 1.30 2026/03/03 09:57:26 dtucker Exp $ */
/* -----------------------------------------------------------------------
 *
 * umac.c -- C Implementation UMAC Message Authentication
 *
 * Version 0.93b of rfc4418.txt -- 2006 July 18
 *
 * For a full description of UMAC message authentication see the UMAC
 * world-wide-web page at https://fastcrypto.org/umac/
 * Please report bugs and suggestions to the UMAC webpage.
 *
 * Copyright (c) 1999-2006 Ted Krovetz
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and with or without fee, is hereby
 * granted provided that the above copyright notice appears in all copies
 * and in supporting documentation, and that the name of the copyright
 * holder not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior permission.
 *
 * Comments should be directed to Ted Krovetz (tdk@acm.org)
 *
 * ---------------------------------------------------------------------- */

 /* ////////////////////// IMPORTANT NOTES /////////////////////////////////
  *
  * 1) This version does not work properly on messages larger than 16MB
  *
  * 2) If you set the switch to use SSE2, then all data must be 16-byte
  *    aligned
  *
  * 3) When calling the function umac(), it is assumed that msg is in
  * a writable buffer of length divisible by 32 bytes. The message itself
  * does not have to fill the entire buffer, but bytes beyond msg may be
  * zeroed.
  *
  * 4) Three free AES implementations are supported by this implementation of
  * UMAC. Paulo Barreto's version is in the public domain and can be found
  * at http://www.esat.kuleuven.ac.be/~rijmen/rijndael/ (search for
  * "Barreto"). The only two files needed are rijndael-alg-fst.c and
  * rijndael-alg-fst.h. Brian Gladman's version is distributed with the GNU
  * Public license at http://fp.gladman.plus.com/AES/index.htm. It
  * includes a fast IA-32 assembly version. The OpenSSL crypto library is
  * the third.
  *
  * 5) With FORCE_C_ONLY flags set to 0, incorrect results are sometimes
  * produced under gcc with optimizations set -O3 or higher. Dunno why.
  *
  /////////////////////////////////////////////////////////////////////// */

/* ---------------------------------------------------------------------- */
/* --- User Switches ---------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#ifndef UMAC_OUTPUT_LEN
#define UMAC_OUTPUT_LEN     8  /* Allowable: 4, 8, 12, 16                  */
#endif

#எனில் UMAC_OUTPUT_LEN != 4 && UMAC_OUTPUT_LEN != 8 && \
    UMAC_OUTPUT_LEN != 12 && UMAC_OUTPUT_LEN != 16
# error UMAC_OUTPUT_LEN must be defined to 4, 8, 12 or 16
#endif

/* #define FORCE_C_ONLY        1  ANSI C and 64-bit integers req'd        */
/* #define AES_IMPLEMENTAION   1  1 = OpenSSL, 2 = Barreto, 3 = Gladman   */
/* #define SSE2                0  Is SSE2 is available?                   */
/* #define RUN_TESTS           0  Run basic correctness/speed tests       */
/* #define UMAC_AE_SUPPORT     0  Enable authenticated encryption         */

/* ---------------------------------------------------------------------- */
/* -- Global Includes --------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <endian.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stddef.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "umac.h"
#அந்தர்பாவ "misc.h"

/* ---------------------------------------------------------------------- */
/* --- Primitive Data Types ---                                           */
/* ---------------------------------------------------------------------- */

/* The following assumptions may need change on your system */
வகைவரை uint8_t	UINT8;  /* 1 byte   */
வகைவரை uint16_t	UINT16; /* 2 byte   */
வகைவரை uint32_t	UINT32; /* 4 byte   */
வகைவரை uint64_t	UINT64; /* 8 bytes  */
வகைவரை unsigned முழு	UWORD;  /* Register */

/* ---------------------------------------------------------------------- */
/* --- Constants -------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#define UMAC_சாவி_LEN           16  /* UMAC takes 16 bytes of external key */

/* Message "words" are read from memory in an endian-specific manner.     */
/* For this implementation to behave correctly, __LITTLE_ENDIAN__ must    */
/* be set true if the host computer is little-endian.                     */

#எனில் BYTE_ORDER == LITTLE_ENDIAN
#define __LITTLE_ENDIAN__ 1
#இல்லையெனில்
#define __LITTLE_ENDIAN__ 0
#endif

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Architecture Specific ------------------------------------------ */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */


/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Primitive Routines --------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */


/* ---------------------------------------------------------------------- */
/* --- 32-bit by 32-bit to 64-bit Multiplication ------------------------ */
/* ---------------------------------------------------------------------- */

#define MUL64(a,b) ((UINT64)((UINT64)(UINT32)(a) * (UINT64)(UINT32)(b)))

/* ---------------------------------------------------------------------- */
/* --- Endian Conversion --- Forcing assembly on some platforms           */
/* ---------------------------------------------------------------------- */

#எனில் (__LITTLE_ENDIAN__)
#define LOAD_UINT32_REVERSED(p)		get_u32(p)
#define STORE_UINT32_REVERSED(p,v)	put_u32(p,v)
#இல்லையெனில்
#define LOAD_UINT32_REVERSED(p)		get_u32_le(p)
#define STORE_UINT32_REVERSED(p,v)	put_u32_le(p,v)
#endif

#define LOAD_UINT32_LITTLE(p)		(get_u32_le(p))
#define STORE_UINT32_BIG(p,v)		put_u32(p, v)

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin KDF & PDF Section ---------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* UMAC uses AES with 16 byte block and key lengths */
#define AES_BLOCK_LEN  16

/* OpenSSL's AES */
#ifdef WITH_OPENSSL
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"
#ifndef USE_BUILTIN_RIJNDAEL
# include <openssl/aes.h>
#endif
வகைவரை AES_சாவி aes_int_சாவி[1];
#define aes_encryption(in,out,int_சாவி)                  \
  AES_encrypt((u_char *)(in),(u_char *)(out),(AES_சாவி *)int_சாவி)
#define aes_சாவி_setup(சாவி,int_சாவி)                      \
  AES_set_encrypt_சாவி((மாறிலி u_char *)(சாவி),UMAC_சாவி_LEN*8,int_சாவி)
#இல்லையெனில்
#அந்தர்பாவ "rijndael.h"
#define AES_ROUNDS ((UMAC_சாவி_LEN / 4) + 6)
வகைவரை UINT8 aes_int_சாவி[AES_ROUNDS+1][4][4];	/* AES internal */
#define aes_encryption(in,out,int_சாவி) \
  rijndaelEncrypt((u32 *)(int_சாவி), AES_ROUNDS, (u8 *)(in), (u8 *)(out))
#define aes_சாவி_setup(சாவி,int_சாவி) \
  rijndael_சாவி_Setup_Enc((u32 *)(int_சாவி), (மாறிலி unsigned எழுத்து *)(சாவி), \
  UMAC_சாவி_LEN*8)
#endif

/* The user-supplied UMAC key is stretched using AES in a counter
 * mode to supply all random bits needed by UMAC. The kdf function takes
 * an AES internal key representation 'key' and writes a stream of
 * 'nbytes' bytes to the memory pointed at by 'bufp'. Each distinct
 * 'ndx' causes a distinct byte stream.
 */
நிலையான வெறுமை kdf(வெறுமை *bufp, aes_int_சாவி சாவி, UINT8 ndx, முழு nbytes)
{
    UINT8 in_buf[AES_BLOCK_LEN] = {0};
    UINT8 out_buf[AES_BLOCK_LEN];
    UINT8 *dst_buf = (UINT8 *)bufp;
    முழு i;

    /* Setup the initial value */
    in_buf[AES_BLOCK_LEN-9] = ndx;
    in_buf[AES_BLOCK_LEN-1] = i = 1;

    போது (nbytes >= AES_BLOCK_LEN) {
        aes_encryption(in_buf, out_buf, சாவி);
        memcpy(dst_buf,out_buf,AES_BLOCK_LEN);
        in_buf[AES_BLOCK_LEN-1] = ++i;
        nbytes -= AES_BLOCK_LEN;
        dst_buf += AES_BLOCK_LEN;
    }
    எனில் (nbytes) {
        aes_encryption(in_buf, out_buf, சாவி);
        memcpy(dst_buf,out_buf,nbytes);
    }
    explicit_bzero(in_buf, அளவு(in_buf));
    explicit_bzero(out_buf, அளவு(out_buf));
}

/* The final UHASH result is XOR'd with the output of a pseudorandom
 * function. Here, we use AES to generate random output and
 * xor the appropriate bytes depending on the last bits of nonce.
 * This scheme is optimized for sequential, increasing big-endian nonces.
 */

வகைவரை கட்டமைப்பு {
    UINT8 cache[AES_BLOCK_LEN];  /* Previous AES output is saved      */
    UINT8 nonce[AES_BLOCK_LEN];  /* The AES input making above cache  */
    aes_int_சாவி prf_சாவி;         /* Expanded AES key for PDF          */
} pdf_ctx;

நிலையான வெறுமை pdf_init(pdf_ctx *pc, aes_int_சாவி prf_சாவி)
{
    UINT8 buf[UMAC_சாவி_LEN];

    kdf(buf, prf_சாவி, 0, UMAC_சாவி_LEN);
    aes_சாவி_setup(buf, pc->prf_சாவி);

    /* Initialize pdf and cache */
    memset(pc->nonce, 0, அளவு(pc->nonce));
    aes_encryption(pc->nonce, pc->cache, pc->prf_சாவி);
    explicit_bzero(buf, அளவு(buf));
}

நிலையான வெறுமை pdf_gen_xor(pdf_ctx *pc, மாறிலி UINT8 nonce[8],
    UINT8 buf[UMAC_OUTPUT_LEN])
{
    /* 'ndx' indicates that we'll be using the 0th or 1st eight bytes
     * of the AES output. If last time around we returned the ndx-1st
     * element, then we may have the result in the cache already.
     */

#எனில் (UMAC_OUTPUT_LEN == 4)
#define கீழ்_BIT_MASK 3
#அல்லதெனில் (UMAC_OUTPUT_LEN == 8)
#define கீழ்_BIT_MASK 1
#அல்லதெனில் (UMAC_OUTPUT_LEN > 8)
#define கீழ்_BIT_MASK 0
#endif
    ஒன்றிப்பு {
        UINT8 tmp_nonce_lo[4];
        UINT32 align;
    } t;
#எனில் கீழ்_BIT_MASK != 0
    முழு ndx = nonce[7] & கீழ்_BIT_MASK;
#endif
    *(UINT32 *)t.tmp_nonce_lo = ((மாறிலி UINT32 *)nonce)[1];
    t.tmp_nonce_lo[3] &= ~கீழ்_BIT_MASK; /* zero last bit */

    எனில் ( (((UINT32 *)t.tmp_nonce_lo)[0] != ((UINT32 *)pc->nonce)[1]) ||
         (((மாறிலி UINT32 *)nonce)[0] != ((UINT32 *)pc->nonce)[0]) )
    {
        ((UINT32 *)pc->nonce)[0] = ((மாறிலி UINT32 *)nonce)[0];
        ((UINT32 *)pc->nonce)[1] = ((UINT32 *)t.tmp_nonce_lo)[0];
        aes_encryption(pc->nonce, pc->cache, pc->prf_சாவி);
    }

#எனில் (UMAC_OUTPUT_LEN == 4)
    *((UINT32 *)buf) ^= ((UINT32 *)pc->cache)[ndx];
#அல்லதெனில் (UMAC_OUTPUT_LEN == 8)
    *((UINT64 *)buf) ^= ((UINT64 *)pc->cache)[ndx];
#அல்லதெனில் (UMAC_OUTPUT_LEN == 12)
    ((UINT64 *)buf)[0] ^= ((UINT64 *)pc->cache)[0];
    ((UINT32 *)buf)[2] ^= ((UINT32 *)pc->cache)[2];
#அல்லதெனில் (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)buf)[0] ^= ((UINT64 *)pc->cache)[0];
    ((UINT64 *)buf)[1] ^= ((UINT64 *)pc->cache)[1];
#endif
}

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin NH Hash Section ------------------------------------------ */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* The NH-based hash functions used in UMAC are described in the UMAC paper
 * and specification, both of which can be found at the UMAC website.
 * The interface to this implementation has two
 * versions, one expects the entire message being hashed to be passed
 * in a single buffer and returns the hash result immediately. The second
 * allows the message to be passed in a sequence of buffers. In the
 * multiple-buffer interface, the client calls the routine nh_update() as
 * many times as necessary. When there is no more data to be fed to the
 * hash, the client calls nh_final() which calculates the hash output.
 * Before beginning another hash calculation the nh_reset() routine
 * must be called. The single-buffer routine, nh(), is equivalent to
 * the sequence of calls nh_update() and nh_final(); however it is
 * optimized and should be preferred whenever the multiple-buffer interface
 * is not necessary. When using either interface, it is the client's
 * responsibility to pass no more than L1_KEY_LEN bytes per hash result.
 *
 * The routine nh_init() initializes the nh_ctx data structure and
 * must be called once, before any other PDF routine.
 */

 /* The "nh_aux" routines do the actual NH hashing work. They
  * expect buffers to be multiples of L1_PAD_BOUNDARY. These routines
  * produce output for all STREAMS NH iterations in one call,
  * allowing the parallel implementation of the streams.
  */

#define STREAMS (UMAC_OUTPUT_LEN / 4) /* Number of times hash is applied  */
#define L1_சாவி_LEN         1024     /* Internal key bytes                 */
#define L1_சாவி_SHIFT         16     /* Toeplitz key shift between streams */
#define L1_PAD_BOUNDARY      32     /* pad message to boundary multiple   */
#define ALLOC_BOUNDARY       16     /* Keep buffers aligned to this       */
#define HASH_BUF_BYTES       64     /* nh_aux_hb buffer multiple          */

வகைவரை கட்டமைப்பு {
    UINT8  nh_சாவி [L1_சாவி_LEN + L1_சாவி_SHIFT * (STREAMS - 1)]; /* NH Key */
    UINT8  data   [HASH_BUF_BYTES];    /* Incoming data buffer           */
    முழு next_data_empty;    /* Bookkeeping variable for data buffer.     */
    முழு bytes_hashed;       /* Bytes (out of L1_KEY_LEN) incorporated.   */
    UINT64 state[STREAMS];               /* on-line state     */
} nh_ctx;


#எனில் (UMAC_OUTPUT_LEN == 4)

நிலையான வெறுமை nh_aux(வெறுமை *kp, மாறிலி வெறுமை *dp, வெறுமை *hp, UINT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and
* then stored via hp pointer. The length of the data pointed at by "dp",
* "dlen", is guaranteed to be divisible by L1_PAD_BOUNDARY (32).  Key
* is expected to be endian compensated in memory at key setup.
*/
{
    UINT64 h;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    மாறிலி UINT32 *d = (மாறிலி UINT32 *)dp;
    UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
    UINT32 k0,k1,k2,k3,k4,k5,k6,k7;

    h = *((UINT64 *)hp);
    செய் {
        d0 = LOAD_UINT32_LITTLE(d+0); d1 = LOAD_UINT32_LITTLE(d+1);
        d2 = LOAD_UINT32_LITTLE(d+2); d3 = LOAD_UINT32_LITTLE(d+3);
        d4 = LOAD_UINT32_LITTLE(d+4); d5 = LOAD_UINT32_LITTLE(d+5);
        d6 = LOAD_UINT32_LITTLE(d+6); d7 = LOAD_UINT32_LITTLE(d+7);
        k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
        k4 = *(k+4); k5 = *(k+5); k6 = *(k+6); k7 = *(k+7);
        h += MUL64((k0 + d0), (k4 + d4));
        h += MUL64((k1 + d1), (k5 + d5));
        h += MUL64((k2 + d2), (k6 + d6));
        h += MUL64((k3 + d3), (k7 + d7));

        d += 8;
        k += 8;
    } போது (--c);
  *((UINT64 *)hp) = h;
}

#அல்லதெனில் (UMAC_OUTPUT_LEN == 8)

நிலையான வெறுமை nh_aux(வெறுமை *kp, மாறிலி வெறுமை *dp, வெறுமை *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 16 bytes of hash-state per call.
 */
{
  UINT64 h1,h2;
  UWORD c = dlen / 32;
  UINT32 *k = (UINT32 *)kp;
  மாறிலி UINT32 *d = (மாறிலி UINT32 *)dp;
  UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
  UINT32 k0,k1,k2,k3,k4,k5,k6,k7,
        k8,k9,k10,k11;

  h1 = *((UINT64 *)hp);
  h2 = *((UINT64 *)hp + 1);
  k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
  செய் {
    d0 = LOAD_UINT32_LITTLE(d+0); d1 = LOAD_UINT32_LITTLE(d+1);
    d2 = LOAD_UINT32_LITTLE(d+2); d3 = LOAD_UINT32_LITTLE(d+3);
    d4 = LOAD_UINT32_LITTLE(d+4); d5 = LOAD_UINT32_LITTLE(d+5);
    d6 = LOAD_UINT32_LITTLE(d+6); d7 = LOAD_UINT32_LITTLE(d+7);
    k4 = *(k+4); k5 = *(k+5); k6 = *(k+6); k7 = *(k+7);
    k8 = *(k+8); k9 = *(k+9); k10 = *(k+10); k11 = *(k+11);

    h1 += MUL64((k0 + d0), (k4 + d4));
    h2 += MUL64((k4 + d0), (k8 + d4));

    h1 += MUL64((k1 + d1), (k5 + d5));
    h2 += MUL64((k5 + d1), (k9 + d5));

    h1 += MUL64((k2 + d2), (k6 + d6));
    h2 += MUL64((k6 + d2), (k10 + d6));

    h1 += MUL64((k3 + d3), (k7 + d7));
    h2 += MUL64((k7 + d3), (k11 + d7));

    k0 = k8; k1 = k9; k2 = k10; k3 = k11;

    d += 8;
    k += 8;
  } போது (--c);
  ((UINT64 *)hp)[0] = h1;
  ((UINT64 *)hp)[1] = h2;
}

#அல்லதெனில் (UMAC_OUTPUT_LEN == 12)

நிலையான வெறுமை nh_aux(வெறுமை *kp, மாறிலி வெறுமை *dp, வெறுமை *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 24 bytes of hash-state per call.
*/
{
    UINT64 h1,h2,h3;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    மாறிலி UINT32 *d = (மாறிலி UINT32 *)dp;
    UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
    UINT32 k0,k1,k2,k3,k4,k5,k6,k7,
        k8,k9,k10,k11,k12,k13,k14,k15;

    h1 = *((UINT64 *)hp);
    h2 = *((UINT64 *)hp + 1);
    h3 = *((UINT64 *)hp + 2);
    k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
    k4 = *(k+4); k5 = *(k+5); k6 = *(k+6); k7 = *(k+7);
    செய் {
        d0 = LOAD_UINT32_LITTLE(d+0); d1 = LOAD_UINT32_LITTLE(d+1);
        d2 = LOAD_UINT32_LITTLE(d+2); d3 = LOAD_UINT32_LITTLE(d+3);
        d4 = LOAD_UINT32_LITTLE(d+4); d5 = LOAD_UINT32_LITTLE(d+5);
        d6 = LOAD_UINT32_LITTLE(d+6); d7 = LOAD_UINT32_LITTLE(d+7);
        k8 = *(k+8); k9 = *(k+9); k10 = *(k+10); k11 = *(k+11);
        k12 = *(k+12); k13 = *(k+13); k14 = *(k+14); k15 = *(k+15);

        h1 += MUL64((k0 + d0), (k4 + d4));
        h2 += MUL64((k4 + d0), (k8 + d4));
        h3 += MUL64((k8 + d0), (k12 + d4));

        h1 += MUL64((k1 + d1), (k5 + d5));
        h2 += MUL64((k5 + d1), (k9 + d5));
        h3 += MUL64((k9 + d1), (k13 + d5));

        h1 += MUL64((k2 + d2), (k6 + d6));
        h2 += MUL64((k6 + d2), (k10 + d6));
        h3 += MUL64((k10 + d2), (k14 + d6));

        h1 += MUL64((k3 + d3), (k7 + d7));
        h2 += MUL64((k7 + d3), (k11 + d7));
        h3 += MUL64((k11 + d3), (k15 + d7));

        k0 = k8; k1 = k9; k2 = k10; k3 = k11;
        k4 = k12; k5 = k13; k6 = k14; k7 = k15;

        d += 8;
        k += 8;
    } போது (--c);
    ((UINT64 *)hp)[0] = h1;
    ((UINT64 *)hp)[1] = h2;
    ((UINT64 *)hp)[2] = h3;
}

#அல்லதெனில் (UMAC_OUTPUT_LEN == 16)

நிலையான வெறுமை nh_aux(வெறுமை *kp, மாறிலி வெறுமை *dp, வெறுமை *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 24 bytes of hash-state per call.
*/
{
    UINT64 h1,h2,h3,h4;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    மாறிலி UINT32 *d = (மாறிலி UINT32 *)dp;
    UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
    UINT32 k0,k1,k2,k3,k4,k5,k6,k7,
        k8,k9,k10,k11,k12,k13,k14,k15,
        k16,k17,k18,k19;

    h1 = *((UINT64 *)hp);
    h2 = *((UINT64 *)hp + 1);
    h3 = *((UINT64 *)hp + 2);
    h4 = *((UINT64 *)hp + 3);
    k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
    k4 = *(k+4); k5 = *(k+5); k6 = *(k+6); k7 = *(k+7);
    செய் {
        d0 = LOAD_UINT32_LITTLE(d+0); d1 = LOAD_UINT32_LITTLE(d+1);
        d2 = LOAD_UINT32_LITTLE(d+2); d3 = LOAD_UINT32_LITTLE(d+3);
        d4 = LOAD_UINT32_LITTLE(d+4); d5 = LOAD_UINT32_LITTLE(d+5);
        d6 = LOAD_UINT32_LITTLE(d+6); d7 = LOAD_UINT32_LITTLE(d+7);
        k8 = *(k+8); k9 = *(k+9); k10 = *(k+10); k11 = *(k+11);
        k12 = *(k+12); k13 = *(k+13); k14 = *(k+14); k15 = *(k+15);
        k16 = *(k+16); k17 = *(k+17); k18 = *(k+18); k19 = *(k+19);

        h1 += MUL64((k0 + d0), (k4 + d4));
        h2 += MUL64((k4 + d0), (k8 + d4));
        h3 += MUL64((k8 + d0), (k12 + d4));
        h4 += MUL64((k12 + d0), (k16 + d4));

        h1 += MUL64((k1 + d1), (k5 + d5));
        h2 += MUL64((k5 + d1), (k9 + d5));
        h3 += MUL64((k9 + d1), (k13 + d5));
        h4 += MUL64((k13 + d1), (k17 + d5));

        h1 += MUL64((k2 + d2), (k6 + d6));
        h2 += MUL64((k6 + d2), (k10 + d6));
        h3 += MUL64((k10 + d2), (k14 + d6));
        h4 += MUL64((k14 + d2), (k18 + d6));

        h1 += MUL64((k3 + d3), (k7 + d7));
        h2 += MUL64((k7 + d3), (k11 + d7));
        h3 += MUL64((k11 + d3), (k15 + d7));
        h4 += MUL64((k15 + d3), (k19 + d7));

        k0 = k8; k1 = k9; k2 = k10; k3 = k11;
        k4 = k12; k5 = k13; k6 = k14; k7 = k15;
        k8 = k16; k9 = k17; k10 = k18; k11 = k19;

        d += 8;
        k += 8;
    } போது (--c);
    ((UINT64 *)hp)[0] = h1;
    ((UINT64 *)hp)[1] = h2;
    ((UINT64 *)hp)[2] = h3;
    ((UINT64 *)hp)[3] = h4;
}

/* ---------------------------------------------------------------------- */
#endif  /* UMAC_OUTPUT_LENGTH */
/* ---------------------------------------------------------------------- */


/* ---------------------------------------------------------------------- */

நிலையான வெறுமை nh_transform(nh_ctx *hc, மாறிலி UINT8 *buf, UINT32 nbytes)
/* This function is a wrapper for the primitive NH hash functions. It takes
 * as argument "hc" the current hash context and a buffer which must be a
 * multiple of L1_PAD_BOUNDARY. The key passed to nh_aux is offset
 * appropriately according to how much message has been hashed already.
 */
{
    UINT8 *சாவி;

    சாவி = hc->nh_சாவி + hc->bytes_hashed;
    nh_aux(சாவி, buf, hc->state, nbytes);
}

/* ---------------------------------------------------------------------- */

#எனில் (__LITTLE_ENDIAN__)
நிலையான வெறுமை endian_convert(வெறுமை *buf, UWORD bpw, UINT32 இலக்கம்_bytes)
/* We endian convert the keys on little-endian computers to               */
/* compensate for the lack of big-endian memory reads during hashing.     */
{
    UWORD iters = இலக்கம்_bytes / bpw;
    எனில் (bpw == 4) {
        UINT32 *p = (UINT32 *)buf;
        செய் {
            *p = LOAD_UINT32_REVERSED(p);
            p++;
        } போது (--iters);
    } இல்லையெனில் எனில் (bpw == 8) {
        UINT32 *p = (UINT32 *)buf;
        UINT32 t;
        செய் {
            t = LOAD_UINT32_REVERSED(p+1);
            p[1] = LOAD_UINT32_REVERSED(p);
            p[0] = t;
            p += 2;
        } போது (--iters);
    }
}
#define endian_convert_if_le(x,y,z) endian_convert((x),(y),(z))
#இல்லையெனில்
#define endian_convert_if_le(x,y,z) செய்{}போது(0)  /* Do nothing */
#endif

/* ---------------------------------------------------------------------- */

நிலையான வெறுமை nh_reset(nh_ctx *hc)
/* Reset nh_ctx to ready for hashing of new data */
{
    hc->bytes_hashed = 0;
    hc->next_data_empty = 0;
    hc->state[0] = 0;
#எனில் (UMAC_OUTPUT_LEN >= 8)
    hc->state[1] = 0;
#endif
#எனில் (UMAC_OUTPUT_LEN >= 12)
    hc->state[2] = 0;
#endif
#எனில் (UMAC_OUTPUT_LEN == 16)
    hc->state[3] = 0;
#endif

}

/* ---------------------------------------------------------------------- */

நிலையான வெறுமை nh_init(nh_ctx *hc, aes_int_சாவி prf_சாவி)
/* Generate nh_key, endian convert and reset to be ready for hashing.   */
{
    kdf(hc->nh_சாவி, prf_சாவி, 1, அளவு(hc->nh_சாவி));
    endian_convert_if_le(hc->nh_சாவி, 4, அளவு(hc->nh_சாவி));
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

நிலையான வெறுமை nh_update(nh_ctx *hc, மாறிலி UINT8 *buf, UINT32 nbytes)
/* Incorporate nbytes of data into a nh_ctx, buffer whatever is not an    */
/* even multiple of HASH_BUF_BYTES.                                       */
{
    UINT32 i,j;

    j = hc->next_data_empty;
    எனில் ((j + nbytes) >= HASH_BUF_BYTES) {
        எனில் (j) {
            i = HASH_BUF_BYTES - j;
            memcpy(hc->data+j, buf, i);
            nh_transform(hc,hc->data,HASH_BUF_BYTES);
            nbytes -= i;
            buf += i;
            hc->bytes_hashed += HASH_BUF_BYTES;
        }
        எனில் (nbytes >= HASH_BUF_BYTES) {
            i = nbytes & ~(HASH_BUF_BYTES - 1);
            nh_transform(hc, buf, i);
            nbytes -= i;
            buf += i;
            hc->bytes_hashed += i;
        }
        j = 0;
    }
    memcpy(hc->data + j, buf, nbytes);
    hc->next_data_empty = j + nbytes;
}

/* ---------------------------------------------------------------------- */

நிலையான வெறுமை zero_pad(UINT8 *p, முழு nbytes)
{
/* Write "nbytes" of zeroes, beginning at "p" */
    எனில் (nbytes >= (முழு)அளவு(UWORD)) {
        போது ((ptrdiff_t)p % அளவு(UWORD)) {
            *p = 0;
            nbytes--;
            p++;
        }
        போது (nbytes >= (முழு)அளவு(UWORD)) {
            *(UWORD *)p = 0;
            nbytes -= அளவு(UWORD);
            p += அளவு(UWORD);
        }
    }
    போது (nbytes) {
        *p = 0;
        nbytes--;
        p++;
    }
}

/* ---------------------------------------------------------------------- */

நிலையான வெறுமை nh_final(nh_ctx *hc, UINT8 *result)
/* After passing some number of data buffers to nh_update() for integration
 * into an NH context, nh_final is called to produce a hash result. If any
 * bytes are in the buffer hc->data, incorporate them into the
 * NH context. Finally, add into the NH accumulation "state" the total number
 * of bits hashed. The resulting numbers are written to the buffer "result".
 * If nh_update was never called, L1_PAD_BOUNDARY zeroes are incorporated.
 */
{
    முழு nh_len, nbits;

    எனில் (hc->next_data_empty != 0) {
        nh_len = ((hc->next_data_empty + (L1_PAD_BOUNDARY - 1)) &
                                                ~(L1_PAD_BOUNDARY - 1));
        zero_pad(hc->data + hc->next_data_empty,
                                          nh_len - hc->next_data_empty);
        nh_transform(hc, hc->data, nh_len);
        hc->bytes_hashed += hc->next_data_empty;
    } இல்லையெனில் எனில் (hc->bytes_hashed == 0) {
	nh_len = L1_PAD_BOUNDARY;
        zero_pad(hc->data, L1_PAD_BOUNDARY);
        nh_transform(hc, hc->data, nh_len);
    }

    nbits = (hc->bytes_hashed << 3);
    ((UINT64 *)result)[0] = ((UINT64 *)hc->state)[0] + nbits;
#எனில் (UMAC_OUTPUT_LEN >= 8)
    ((UINT64 *)result)[1] = ((UINT64 *)hc->state)[1] + nbits;
#endif
#எனில் (UMAC_OUTPUT_LEN >= 12)
    ((UINT64 *)result)[2] = ((UINT64 *)hc->state)[2] + nbits;
#endif
#எனில் (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)result)[3] = ((UINT64 *)hc->state)[3] + nbits;
#endif
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

நிலையான வெறுமை nh(nh_ctx *hc, மாறிலி UINT8 *buf, UINT32 padded_len,
               UINT32 unpadded_len, UINT8 *result)
/* All-in-one nh_update() and nh_final() equivalent.
 * Assumes that padded_len is divisible by L1_PAD_BOUNDARY and result is
 * well aligned
 */
{
    UINT32 nbits;

    /* Initialize the hash state */
    nbits = (unpadded_len << 3);

    ((UINT64 *)result)[0] = nbits;
#எனில் (UMAC_OUTPUT_LEN >= 8)
    ((UINT64 *)result)[1] = nbits;
#endif
#எனில் (UMAC_OUTPUT_LEN >= 12)
    ((UINT64 *)result)[2] = nbits;
#endif
#எனில் (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)result)[3] = nbits;
#endif

    nh_aux(hc->nh_சாவி, buf, result, padded_len);
}

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin UHASH Section -------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* UHASH is a multi-layered algorithm. Data presented to UHASH is first
 * hashed by NH. The NH output is then hashed by a polynomial-hash layer
 * unless the initial data to be hashed is short. After the polynomial-
 * layer, an inner-product hash is used to produce the final UHASH output.
 *
 * UHASH provides two interfaces, one all-at-once and another where data
 * buffers are presented sequentially. In the sequential interface, the
 * UHASH client calls the routine uhash_update() as many times as necessary.
 * When there is no more data to be fed to UHASH, the client calls
 * uhash_final() which
 * calculates the UHASH output. Before beginning another UHASH calculation
 * the uhash_reset() routine must be called. The all-at-once UHASH routine,
 * uhash(), is equivalent to the sequence of calls uhash_update() and
 * uhash_final(); however it is optimized and should be
 * used whenever the sequential interface is not necessary.
 *
 * The routine uhash_init() initializes the uhash_ctx data structure and
 * must be called once, before any other UHASH routine.
 */

/* ---------------------------------------------------------------------- */
/* ----- Constants and uhash_ctx ---------------------------------------- */
/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
/* ----- Poly hash and Inner-Product hash Constants --------------------- */
/* ---------------------------------------------------------------------- */

/* Primes and masks */
#define p36    ((UINT64)0x0000000FFFFFFFFBull)              /* 2^36 -  5 */
#define p64    ((UINT64)0xFFFFFFFFFFFFFFC5ull)              /* 2^64 - 59 */
#define m36    ((UINT64)0x0000000FFFFFFFFFull)  /* The low 36 of 64 bits */


/* ---------------------------------------------------------------------- */

வகைவரை கட்டமைப்பு uhash_ctx {
    nh_ctx hash;                          /* Hash context for L1 NH hash  */
    UINT64 poly_சாவி_8[STREAMS];           /* p64 poly keys                */
    UINT64 poly_accum[STREAMS];           /* poly hash result             */
    UINT64 ip_சாவிகள்[STREAMS*4];            /* Inner-product keys           */
    UINT32 ip_trans[STREAMS];             /* Inner-product translation    */
    UINT32 செய்தி_len;                       /* Total length of data passed  */
                                          /* to uhash */
} uhash_ctx;
வகைவரை கட்டமைப்பு uhash_ctx *uhash_ctx_t;

/* ---------------------------------------------------------------------- */


/* The polynomial hashes use Horner's rule to evaluate a polynomial one
 * word at a time. As described in the specification, poly32 and poly64
 * require keys from special domains. The following implementations exploit
 * the special domains to avoid overflow. The results are not guaranteed to
 * be within Z_p32 and Z_p64, but the Inner-Product hash implementation
 * patches any errant values.
 */

நிலையான UINT64 poly64(UINT64 cur, UINT64 சாவி, UINT64 data)
{
    UINT32 சாவி_hi = (UINT32)(சாவி >> 32),
           சாவி_lo = (UINT32)சாவி,
           cur_hi = (UINT32)(cur >> 32),
           cur_lo = (UINT32)cur,
           x_lo,
           x_hi;
    UINT64 X,T,res;

    X =  MUL64(சாவி_hi, cur_lo) + MUL64(cur_hi, சாவி_lo);
    x_lo = (UINT32)X;
    x_hi = (UINT32)(X >> 32);

    res = (MUL64(சாவி_hi, cur_hi) + x_hi) * 59 + MUL64(சாவி_lo, cur_lo);

    T = ((UINT64)x_lo << 32);
    res += T;
    எனில் (res < T)
        res += 59;

    res += data;
    எனில் (res < data)
        res += 59;

    திரும்பு res;
}


/* Although UMAC is specified to use a ramped polynomial hash scheme, this
 * implementation does not handle all ramp levels. Because we don't handle
 * the ramp up to p128 modulus in this implementation, we are limited to
 * 2^14 poly_hash() invocations per stream (for a total capacity of 2^24
 * bytes input to UMAC per tag, ie. 16MB).
 */
நிலையான வெறுமை poly_hash(uhash_ctx_t hc, UINT32 data_in[])
{
    முழு i;
    UINT64 *data=(UINT64*)data_in;

    க்கு (i = 0; i < STREAMS; i++) {
        எனில் ((UINT32)(data[i] >> 32) == 0xfffffffful) {
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_சாவி_8[i], p64 - 1);
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_சாவி_8[i], (data[i] - 59));
        } இல்லையெனில் {
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_சாவி_8[i], data[i]);
        }
    }
}


/* ---------------------------------------------------------------------- */


/* The final step in UHASH is an inner-product hash. The poly hash
 * produces a result not necessarily WORD_LEN bytes long. The inner-
 * product hash breaks the polyhash output into 16-bit chunks and
 * multiplies each with a 36 bit key.
 */

நிலையான UINT64 ip_aux(UINT64 t, UINT64 *ipkp, UINT64 data)
{
    t = t + ipkp[0] * (UINT64)(UINT16)(data >> 48);
    t = t + ipkp[1] * (UINT64)(UINT16)(data >> 32);
    t = t + ipkp[2] * (UINT64)(UINT16)(data >> 16);
    t = t + ipkp[3] * (UINT64)(UINT16)(data);

    திரும்பு t;
}

நிலையான UINT32 ip_reduce_p36(UINT64 t)
{
/* Divisionless modular reduction */
    UINT64 ret;

    ret = (t & m36) + 5 * (t >> 36);
    எனில் (ret >= p36)
        ret -= p36;

    /* return least significant 32 bits */
    திரும்பு (UINT32)(ret);
}


/* If the data being hashed by UHASH is no longer than L1_KEY_LEN, then
 * the polyhash stage is skipped and ip_short is applied directly to the
 * NH output.
 */
நிலையான வெறுமை ip_short(uhash_ctx_t ahc, UINT8 *nh_res, u_char *res)
{
    UINT64 t;
    UINT64 *nhp = (UINT64 *)nh_res;

    t  = ip_aux(0,ahc->ip_சாவிகள், nhp[0]);
    STORE_UINT32_BIG((UINT32 *)res+0, ip_reduce_p36(t) ^ ahc->ip_trans[0]);
#எனில் (UMAC_OUTPUT_LEN >= 8)
    t  = ip_aux(0,ahc->ip_சாவிகள்+4, nhp[1]);
    STORE_UINT32_BIG((UINT32 *)res+1, ip_reduce_p36(t) ^ ahc->ip_trans[1]);
#endif
#எனில் (UMAC_OUTPUT_LEN >= 12)
    t  = ip_aux(0,ahc->ip_சாவிகள்+8, nhp[2]);
    STORE_UINT32_BIG((UINT32 *)res+2, ip_reduce_p36(t) ^ ahc->ip_trans[2]);
#endif
#எனில் (UMAC_OUTPUT_LEN == 16)
    t  = ip_aux(0,ahc->ip_சாவிகள்+12, nhp[3]);
    STORE_UINT32_BIG((UINT32 *)res+3, ip_reduce_p36(t) ^ ahc->ip_trans[3]);
#endif
}

/* If the data being hashed by UHASH is longer than L1_KEY_LEN, then
 * the polyhash stage is not skipped and ip_long is applied to the
 * polyhash output.
 */
நிலையான வெறுமை ip_long(uhash_ctx_t ahc, u_char *res)
{
    முழு i;
    UINT64 t;

    க்கு (i = 0; i < STREAMS; i++) {
        /* fix polyhash output not in Z_p64 */
        எனில் (ahc->poly_accum[i] >= p64)
            ahc->poly_accum[i] -= p64;
        t  = ip_aux(0,ahc->ip_சாவிகள்+(i*4), ahc->poly_accum[i]);
        STORE_UINT32_BIG((UINT32 *)res+i,
                         ip_reduce_p36(t) ^ ahc->ip_trans[i]);
    }
}


/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */

/* Reset uhash context for next hash session */
நிலையான முழு uhash_reset(uhash_ctx_t pc)
{
    nh_reset(&pc->hash);
    pc->செய்தி_len = 0;
    pc->poly_accum[0] = 1;
#எனில் (UMAC_OUTPUT_LEN >= 8)
    pc->poly_accum[1] = 1;
#endif
#எனில் (UMAC_OUTPUT_LEN >= 12)
    pc->poly_accum[2] = 1;
#endif
#எனில் (UMAC_OUTPUT_LEN == 16)
    pc->poly_accum[3] = 1;
#endif
    திரும்பு 1;
}

/* ---------------------------------------------------------------------- */

/* Given a pointer to the internal key needed by kdf() and a uhash context,
 * initialize the NH context and generate keys needed for poly and inner-
 * product hashing. All keys are endian adjusted in memory so that native
 * loads cause correct keys to be in registers during calculation.
 */
நிலையான வெறுமை uhash_init(uhash_ctx_t ahc, aes_int_சாவி prf_சாவி)
{
    முழு i;
    UINT8 buf[(8*STREAMS+4)*அளவு(UINT64)];

    /* Zero the entire uhash context */
    memset(ahc, 0, அளவு(uhash_ctx));

    /* Initialize the L1 hash */
    nh_init(&ahc->hash, prf_சாவி);

    /* Setup L2 hash variables */
    kdf(buf, prf_சாவி, 2, அளவு(buf));    /* Fill buffer with index 1 key */
    க்கு (i = 0; i < STREAMS; i++) {
        /* Fill keys from the buffer, skipping bytes in the buffer not
         * used by this implementation. Endian reverse the keys if on a
         * little-endian computer.
         */
        memcpy(ahc->poly_சாவி_8+i, buf+24*i, 8);
        endian_convert_if_le(ahc->poly_சாவி_8+i, 8, 8);
        /* Mask the 64-bit keys to their special domain */
        ahc->poly_சாவி_8[i] &= ((UINT64)0x01ffffffu << 32) + 0x01ffffffu;
        ahc->poly_accum[i] = 1;  /* Our polyhash prepends a non-zero word */
    }

    /* Setup L3-1 hash variables */
    kdf(buf, prf_சாவி, 3, அளவு(buf)); /* Fill buffer with index 2 key */
    க்கு (i = 0; i < STREAMS; i++)
          memcpy(ahc->ip_சாவிகள்+4*i, buf+(8*i+4)*அளவு(UINT64),
                                                 4*அளவு(UINT64));
    endian_convert_if_le(ahc->ip_சாவிகள், அளவு(UINT64),
                                                  அளவு(ahc->ip_சாவிகள்));
    க்கு (i = 0; i < STREAMS*4; i++)
        ahc->ip_சாவிகள்[i] %= p36;  /* Bring into Z_p36 */

    /* Setup L3-2 hash variables    */
    /* Fill buffer with index 4 key */
    kdf(ahc->ip_trans, prf_சாவி, 4, STREAMS * அளவு(UINT32));
    endian_convert_if_le(ahc->ip_trans, அளவு(UINT32),
                         STREAMS * அளவு(UINT32));
    explicit_bzero(buf, அளவு(buf));
}

/* ---------------------------------------------------------------------- */

#எனில் 0
நிலையான uhash_ctx_t uhash_alloc(u_char சாவி[])
{
/* Allocate memory and force to a 16-byte boundary. */
    uhash_ctx_t ctx;
    u_char bytes_to_add;
    aes_int_சாவி prf_சாவி;

    ctx = (uhash_ctx_t)malloc(அளவு(uhash_ctx)+ALLOC_BOUNDARY);
    எனில் (ctx) {
        எனில் (ALLOC_BOUNDARY) {
            bytes_to_add = ALLOC_BOUNDARY -
                              ((ptrdiff_t)ctx & (ALLOC_BOUNDARY -1));
            ctx = (uhash_ctx_t)((u_char *)ctx + bytes_to_add);
            *((u_char *)ctx - 1) = bytes_to_add;
        }
        aes_சாவி_setup(சாவி,prf_சாவி);
        uhash_init(ctx, prf_சாவி);
    }
    திரும்பு (ctx);
}
#endif

/* ---------------------------------------------------------------------- */

#எனில் 0
நிலையான முழு uhash_free(uhash_ctx_t ctx)
{
/* Free memory allocated by uhash_alloc */
    u_char bytes_to_sub;

    எனில் (ctx) {
        எனில் (ALLOC_BOUNDARY) {
            bytes_to_sub = *((u_char *)ctx - 1);
            ctx = (uhash_ctx_t)((u_char *)ctx - bytes_to_sub);
        }
        விடுவி(ctx);
    }
    திரும்பு (1);
}
#endif
/* ---------------------------------------------------------------------- */

நிலையான முழு uhash_update(uhash_ctx_t ctx, மாறிலி u_char *உள்ளீடு, long len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and
 * hash each one with NH, calling the polyhash on each NH output.
 */
{
    UWORD bytes_hashed, bytes_remaining;
    UINT64 result_buf[STREAMS];
    UINT8 *nh_result = (UINT8 *)&result_buf;

    எனில் (ctx->செய்தி_len + len <= L1_சாவி_LEN) {
        nh_update(&ctx->hash, (மாறிலி UINT8 *)உள்ளீடு, len);
        ctx->செய்தி_len += len;
    } இல்லையெனில் {

         bytes_hashed = ctx->செய்தி_len % L1_சாவி_LEN;
         எனில் (ctx->செய்தி_len == L1_சாவி_LEN)
             bytes_hashed = L1_சாவி_LEN;

         எனில் (bytes_hashed + len >= L1_சாவி_LEN) {

             /* If some bytes have been passed to the hash function      */
             /* then we want to pass at most (L1_KEY_LEN - bytes_hashed) */
             /* bytes to complete the current nh_block.                  */
             எனில் (bytes_hashed) {
                 bytes_remaining = (L1_சாவி_LEN - bytes_hashed);
                 nh_update(&ctx->hash, (மாறிலி UINT8 *)உள்ளீடு, bytes_remaining);
                 nh_final(&ctx->hash, nh_result);
                 ctx->செய்தி_len += bytes_remaining;
                 poly_hash(ctx,(UINT32 *)nh_result);
                 len -= bytes_remaining;
                 உள்ளீடு += bytes_remaining;
             }

             /* Hash directly from input stream if enough bytes */
             போது (len >= L1_சாவி_LEN) {
                 nh(&ctx->hash, (மாறிலி UINT8 *)உள்ளீடு, L1_சாவி_LEN,
                                   L1_சாவி_LEN, nh_result);
                 ctx->செய்தி_len += L1_சாவி_LEN;
                 len -= L1_சாவி_LEN;
                 உள்ளீடு += L1_சாவி_LEN;
                 poly_hash(ctx,(UINT32 *)nh_result);
             }
         }

         /* pass remaining < L1_KEY_LEN bytes of input data to NH */
         எனில் (len > 0 && (unsigned long)len <= UINT32_MAX) {
             nh_update(&ctx->hash, (மாறிலி UINT8 *)உள்ளீடு, len);
             ctx->செய்தி_len += len;
         }
     }

    திரும்பு (1);
}

/* ---------------------------------------------------------------------- */

நிலையான முழு uhash_final(uhash_ctx_t ctx, u_char *res)
/* Incorporate any pending data, pad, and generate tag */
{
    UINT64 result_buf[STREAMS];
    UINT8 *nh_result = (UINT8 *)&result_buf;

    எனில் (ctx->செய்தி_len > L1_சாவி_LEN) {
        எனில் (ctx->செய்தி_len % L1_சாவி_LEN) {
            nh_final(&ctx->hash, nh_result);
            poly_hash(ctx,(UINT32 *)nh_result);
        }
        ip_long(ctx, res);
    } இல்லையெனில் {
        nh_final(&ctx->hash, nh_result);
        ip_short(ctx,nh_result, res);
    }
    uhash_reset(ctx);
    திரும்பு (1);
}

/* ---------------------------------------------------------------------- */

#எனில் 0
நிலையான முழு uhash(uhash_ctx_t ahc, u_char *செய்தி, long len, u_char *res)
/* assumes that msg is in a writable buffer of length divisible by */
/* L1_PAD_BOUNDARY. Bytes beyond msg[len] may be zeroed.           */
{
    UINT8 nh_result[STREAMS*அளவு(UINT64)];
    UINT32 nh_len;
    முழு extra_zeroes_needed;

    /* If the message to be hashed is no longer than L1_HASH_LEN, we skip
     * the polyhash.
     */
    எனில் (len <= L1_சாவி_LEN) {
	எனில் (len == 0)                  /* If zero length messages will not */
		nh_len = L1_PAD_BOUNDARY;  /* be seen, comment out this case   */
	இல்லையெனில்
		nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
        extra_zeroes_needed = nh_len - len;
        zero_pad((UINT8 *)செய்தி + len, extra_zeroes_needed);
        nh(&ahc->hash, (UINT8 *)செய்தி, nh_len, len, nh_result);
        ip_short(ahc,nh_result, res);
    } இல்லையெனில் {
        /* Otherwise, we hash each L1_KEY_LEN chunk with NH, passing the NH
         * output to poly_hash().
         */
        செய் {
            nh(&ahc->hash, (UINT8 *)செய்தி, L1_சாவி_LEN, L1_சாவி_LEN, nh_result);
            poly_hash(ahc,(UINT32 *)nh_result);
            len -= L1_சாவி_LEN;
            செய்தி += L1_சாவி_LEN;
        } போது (len >= L1_சாவி_LEN);
        எனில் (len) {
            nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
            extra_zeroes_needed = nh_len - len;
            zero_pad((UINT8 *)செய்தி + len, extra_zeroes_needed);
            nh(&ahc->hash, (UINT8 *)செய்தி, nh_len, len, nh_result);
            poly_hash(ahc,(UINT32 *)nh_result);
        }

        ip_long(ahc, res);
    }

    uhash_reset(ahc);
    திரும்பு 1;
}
#endif

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin UMAC Section --------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* The UMAC interface has two interfaces, an all-at-once interface where
 * the entire message to be authenticated is passed to UMAC in one buffer,
 * and a sequential interface where the message is presented a little at a
 * time. The all-at-once is more optimized than the sequential version and
 * should be preferred when the sequential interface is not required.
 */
கட்டமைப்பு umac_ctx {
    uhash_ctx hash;          /* Hash function for message compression    */
    pdf_ctx pdf;             /* PDF for hashed output                    */
    வெறுமை *free_ptr;          /* Address to free this struct via          */
} umac_ctx;

/* ---------------------------------------------------------------------- */

#எனில் 0
முழு umac_reset(கட்டமைப்பு umac_ctx *ctx)
/* Reset the hash function to begin a new authentication.        */
{
    uhash_reset(&ctx->hash);
    திரும்பு (1);
}
#endif

/* ---------------------------------------------------------------------- */

முழு umac_delete(கட்டமைப்பு umac_ctx *ctx)
/* Deallocate the ctx structure */
{
    எனில் (ctx) {
        எனில் (ALLOC_BOUNDARY)
            ctx = (கட்டமைப்பு umac_ctx *)ctx->free_ptr;
        freezero(ctx, அளவு(*ctx) + ALLOC_BOUNDARY);
    }
    திரும்பு (1);
}

/* ---------------------------------------------------------------------- */

கட்டமைப்பு umac_ctx *umac_new(மாறிலி u_char சாவி[])
/* Dynamically allocate a umac_ctx struct, initialize variables,
 * generate subkeys from key. Align to 16-byte boundary.
 */
{
    கட்டமைப்பு umac_ctx *ctx, *octx;
    size_t bytes_to_add;
    aes_int_சாவி prf_சாவி;

    octx = ctx = xcalloc(1, அளவு(*ctx) + ALLOC_BOUNDARY);
    எனில் (ctx) {
        எனில் (ALLOC_BOUNDARY) {
            bytes_to_add = ALLOC_BOUNDARY -
                              ((ptrdiff_t)ctx & (ALLOC_BOUNDARY - 1));
            ctx = (கட்டமைப்பு umac_ctx *)((u_char *)ctx + bytes_to_add);
        }
        ctx->free_ptr = octx;
        aes_சாவி_setup(சாவி, prf_சாவி);
        pdf_init(&ctx->pdf, prf_சாவி);
        uhash_init(&ctx->hash, prf_சாவி);
        explicit_bzero(prf_சாவி, அளவு(prf_சாவி));
    }

    திரும்பு (ctx);
}

/* ---------------------------------------------------------------------- */

முழு umac_final(கட்டமைப்பு umac_ctx *ctx, u_char tag[], மாறிலி u_char nonce[8])
/* Incorporate any pending data, pad, and generate tag */
{
    uhash_final(&ctx->hash, (u_char *)tag);
    pdf_gen_xor(&ctx->pdf, (மாறிலி UINT8 *)nonce, (UINT8 *)tag);

    திரும்பு (1);
}

/* ---------------------------------------------------------------------- */

முழு umac_update(கட்டமைப்பு umac_ctx *ctx, மாறிலி u_char *உள்ளீடு, long len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and   */
/* hash each one, calling the PDF on the hashed output whenever the hash- */
/* output buffer is full.                                                 */
{
    uhash_update(&ctx->hash, உள்ளீடு, len);
    திரும்பு (1);
}

/* ---------------------------------------------------------------------- */

#எனில் 0
முழு umac(கட்டமைப்பு umac_ctx *ctx, u_char *உள்ளீடு,
         long len, u_char tag[],
         u_char nonce[8])
/* All-in-one version simply calls umac_update() and umac_final().        */
{
    uhash(&ctx->hash, உள்ளீடு, len, (u_char *)tag);
    pdf_gen_xor(&ctx->pdf, (UINT8 *)nonce, (UINT8 *)tag);

    திரும்பு (1);
}
#endif

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- End UMAC Section ----------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
