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

#నిర్వచితం_కాకపోతే UMAC_OUTPUT_LEN
#నిర్వచించు UMAC_OUTPUT_LEN     8  /* Allowable: 4, 8, 12, 16                  */
#అయితే_ముగింపు

#ఒకవేళ UMAC_OUTPUT_LEN != 4 && UMAC_OUTPUT_LEN != 8 && \
    UMAC_OUTPUT_LEN != 12 && UMAC_OUTPUT_LEN != 16
# error UMAC_OUTPUT_LEN must be defined గమ్యం 4, 8, 12 or 16
#అయితే_ముగింపు

/* #define FORCE_C_ONLY        1  ANSI C and 64-bit integers req'd        */
/* #define AES_IMPLEMENTAION   1  1 = OpenSSL, 2 = Barreto, 3 = Gladman   */
/* #define SSE2                0  Is SSE2 is available?                   */
/* #define RUN_TESTS           0  Run basic correctness/speed tests       */
/* #define UMAC_AE_SUPPORT     0  Enable authenticated encryption         */

/* ---------------------------------------------------------------------- */
/* -- Global Includes --------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <endian.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stddef.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "umac.h"
#అన్తర్భావ "misc.h"

/* ---------------------------------------------------------------------- */
/* --- Primitive Data Types ---                                           */
/* ---------------------------------------------------------------------- */

/* The following assumptions may need change on your system */
రకనిర్వచనం uint8_t	UINT8;  /* 1 byte   */
రకనిర్వచనం uint16_t	UINT16; /* 2 byte   */
రకనిర్వచనం uint32_t	UINT32; /* 4 byte   */
రకనిర్వచనం uint64_t	UINT64; /* 8 bytes  */
రకనిర్వచనం గుర్తులేని పూర్ణాంకం	UWORD;  /*రిజిస్టరు*/

/* ---------------------------------------------------------------------- */
/* --- Constants -------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#నిర్వచించు UMAC_కీలకం_LEN           16  /* UMAC takes 16 bytes of external key */

/* Message "words" are read from memory in an endian-specific manner.     */
/* For this implementation to behave correctly, __LITTLE_ENDIAN__ must    */
/* be set true if the host computer is little-endian.                     */

#ఒకవేళ BYTE_ORDER == LITTLE_ENDIAN
#నిర్వచించు __LITTLE_ENDIAN__ 1
#లేకపోతే
#నిర్వచించు __LITTLE_ENDIAN__ 0
#అయితే_ముగింపు

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

#నిర్వచించు MUL64(a,b) ((UINT64)((UINT64)(UINT32)(a) * (UINT64)(UINT32)(b)))

/* ---------------------------------------------------------------------- */
/* --- Endian Conversion --- Forcing assembly on some platforms           */
/* ---------------------------------------------------------------------- */

#ఒకవేళ (__LITTLE_ENDIAN__)
#నిర్వచించు ఎక్కించు_UINT32_REVERSED(p)		get_u32(p)
#నిర్వచించు STORE_UINT32_REVERSED(p,v)	put_u32(p,v)
#లేకపోతే
#నిర్వచించు ఎక్కించు_UINT32_REVERSED(p)		get_u32_le(p)
#నిర్వచించు STORE_UINT32_REVERSED(p,v)	put_u32_le(p,v)
#అయితే_ముగింపు

#నిర్వచించు ఎక్కించు_UINT32_LITTLE(p)		(get_u32_le(p))
#నిర్వచించు STORE_UINT32_BIG(p,v)		put_u32(p, v)

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin KDF & PDF Section ---------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* UMAC uses AES with 16 byte block and key lengths */
#నిర్వచించు AES_ఖండం_LEN  16

/* OpenSSL's AES */
#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ "openbsd-compat/openssl-compat.h"
#నిర్వచితం_కాకపోతే USE_BUILTIN_RIJNDAEL
# include <openssl/aes.h>
#అయితే_ముగింపు
రకనిర్వచనం AES_కీలకం aes_int_కీలకం[1];
#నిర్వచించు aes_encryption(లోపల,బహిర్గతం,int_కీలకం)                  \
  AES_encrypt((u_char *)(లోపల),(u_char *)(బహిర్గతం),(AES_కీలకం *)int_కీలకం)
#నిర్వచించు aes_కీలకం_అమరిక(కీలకం,int_కీలకం)                      \
  AES_సమితి_encrypt_కీలకం((స్థిరరాశి u_char *)(కీలకం),UMAC_కీలకం_LEN*8,int_కీలకం)
#లేకపోతే
#అన్తర్భావ "rijndael.h"
#నిర్వచించు AES_విడతలు ((UMAC_కీలకం_LEN / 4) + 6)
రకనిర్వచనం UINT8 aes_int_కీలకం[AES_విడతలు+1][4][4];	/* AES internal */
#నిర్వచించు aes_encryption(లోపల,బహిర్గతం,int_కీలకం) \
  rijndaelEncrypt((u32 *)(int_కీలకం), AES_విడతలు, (u8 *)(లోపల), (u8 *)(బహిర్గతం))
#నిర్వచించు aes_కీలకం_అమరిక(కీలకం,int_కీలకం) \
  rijndael_కీలకం_అమరిక_Enc((u32 *)(int_కీలకం), (స్థిరరాశి గుర్తులేని అక్షరం *)(కీలకం), \
  UMAC_కీలకం_LEN*8)
#అయితే_ముగింపు

/* The user-supplied UMAC key is stretched using AES in a counter
 * mode to supply all random bits needed by UMAC. The kdf function takes
 * an AES internal key representation 'key' and writes a stream of
 * 'nbytes' bytes to the memory pointed at by 'bufp'. Each distinct
 * 'ndx' causes a distinct byte stream.
 */
స్థిర శూన్య kdf(శూన్య *bufp, aes_int_కీలకం కీలకం, UINT8 ndx, పూర్ణాంకం nbytes)
{
    UINT8 లోపల_buf[AES_ఖండం_LEN] = {0};
    UINT8 బహిర్గతం_buf[AES_ఖండం_LEN];
    UINT8 *dst_buf = (UINT8 *)bufp;
    పూర్ణాంకం i;

    /* Setup the initial value */
    లోపల_buf[AES_ఖండం_LEN-9] = ndx;
    లోపల_buf[AES_ఖండం_LEN-1] = i = 1;

    అయితే (nbytes >= AES_ఖండం_LEN) {
        aes_encryption(లోపల_buf, బహిర్గతం_buf, కీలకం);
        జ్ఞాపకం_నకలు(dst_buf,బహిర్గతం_buf,AES_ఖండం_LEN);
        లోపల_buf[AES_ఖండం_LEN-1] = ++i;
        nbytes -= AES_ఖండం_LEN;
        dst_buf += AES_ఖండం_LEN;
    }
    ఒకవేళ (nbytes) {
        aes_encryption(లోపల_buf, బహిర్గతం_buf, కీలకం);
        జ్ఞాపకం_నకలు(dst_buf,బహిర్గతం_buf,nbytes);
    }
    explicit_bzero(లోపల_buf, పరిమాణం(లోపల_buf));
    explicit_bzero(బహిర్గతం_buf, పరిమాణం(బహిర్గతం_buf));
}

/* The final UHASH result is XOR'd with the output of a pseudorandom
 * function. Here, we use AES to generate random output and
 * xor the appropriate bytes depending on the last bits of nonce.
 * This scheme is optimized for sequential, increasing big-endian nonces.
 */

రకనిర్వచనం నిర్మాణం {
    UINT8 cache[AES_ఖండం_LEN];  /* Previous AES output is saved      */
    UINT8 nonce[AES_ఖండం_LEN];  /* The AES input making above cache  */
    aes_int_కీలకం prf_కీలకం;         /* Expanded AES key for PDF          */
} pdf_ctx;

స్థిర శూన్య pdf_init(pdf_ctx *pc, aes_int_కీలకం prf_కీలకం)
{
    UINT8 buf[UMAC_కీలకం_LEN];

    kdf(buf, prf_కీలకం, 0, UMAC_కీలకం_LEN);
    aes_కీలకం_అమరిక(buf, pc->prf_కీలకం);

    /* Initialize pdf and cache */
    memset(pc->nonce, 0, పరిమాణం(pc->nonce));
    aes_encryption(pc->nonce, pc->cache, pc->prf_కీలకం);
    explicit_bzero(buf, పరిమాణం(buf));
}

స్థిర శూన్య pdf_gen_xor(pdf_ctx *pc, స్థిరరాశి UINT8 nonce[8],
    UINT8 buf[UMAC_OUTPUT_LEN])
{
    /* 'ndx' indicates that we'll be using the 0th or 1st eight bytes
     * of the AES output. If last time around we returned the ndx-1st
     * element, then we may have the result in the cache already.
     */

#ఒకవేళ (UMAC_OUTPUT_LEN == 4)
#నిర్వచించు దిగువ_బిట్టు_ముసుగు 3
#లేదావేళ (UMAC_OUTPUT_LEN == 8)
#నిర్వచించు దిగువ_బిట్టు_ముసుగు 1
#లేదావేళ (UMAC_OUTPUT_LEN > 8)
#నిర్వచించు దిగువ_బిట్టు_ముసుగు 0
#అయితే_ముగింపు
    సంఘం {
        UINT8 tmp_nonce_lo[4];
        UINT32 align;
    } t;
#ఒకవేళ దిగువ_బిట్టు_ముసుగు != 0
    పూర్ణాంకం ndx = nonce[7] & దిగువ_బిట్టు_ముసుగు;
#అయితే_ముగింపు
    *(UINT32 *)t.tmp_nonce_lo = ((స్థిరరాశి UINT32 *)nonce)[1];
    t.tmp_nonce_lo[3] &= ~దిగువ_బిట్టు_ముసుగు; /* zero last bit */

    ఒకవేళ ( (((UINT32 *)t.tmp_nonce_lo)[0] != ((UINT32 *)pc->nonce)[1]) ||
         (((స్థిరరాశి UINT32 *)nonce)[0] != ((UINT32 *)pc->nonce)[0]) )
    {
        ((UINT32 *)pc->nonce)[0] = ((స్థిరరాశి UINT32 *)nonce)[0];
        ((UINT32 *)pc->nonce)[1] = ((UINT32 *)t.tmp_nonce_lo)[0];
        aes_encryption(pc->nonce, pc->cache, pc->prf_కీలకం);
    }

#ఒకవేళ (UMAC_OUTPUT_LEN == 4)
    *((UINT32 *)buf) ^= ((UINT32 *)pc->cache)[ndx];
#లేదావేళ (UMAC_OUTPUT_LEN == 8)
    *((UINT64 *)buf) ^= ((UINT64 *)pc->cache)[ndx];
#లేదావేళ (UMAC_OUTPUT_LEN == 12)
    ((UINT64 *)buf)[0] ^= ((UINT64 *)pc->cache)[0];
    ((UINT32 *)buf)[2] ^= ((UINT32 *)pc->cache)[2];
#లేదావేళ (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)buf)[0] ^= ((UINT64 *)pc->cache)[0];
    ((UINT64 *)buf)[1] ^= ((UINT64 *)pc->cache)[1];
#అయితే_ముగింపు
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

#నిర్వచించు STREAMS (UMAC_OUTPUT_LEN / 4) /* Number of times hash is applied  */
#నిర్వచించు L1_కీలకం_LEN         1024     /* Internal key bytes                 */
#నిర్వచించు L1_కీలకం_జరుపు         16     /* Toeplitz key shift between streams */
#నిర్వచించు L1_PAD_BOUNDARY      32     /* pad message to boundary multiple   */
#నిర్వచించు ALLOC_BOUNDARY       16     /* Keep buffers aligned to this       */
#నిర్వచించు HASH_BUF_బైట్లు       64     /* nh_aux_hb buffer multiple          */

రకనిర్వచనం నిర్మాణం {
    UINT8  nh_కీలకం [L1_కీలకం_LEN + L1_కీలకం_జరుపు * (STREAMS - 1)]; /* NH Key */
    UINT8  దత్తాంశం   [HASH_BUF_బైట్లు];    /* Incoming data buffer           */
    పూర్ణాంకం తదుపరి_దత్తాంశం_ఖాళీలు;    /* Bookkeeping variable for data buffer.     */
    పూర్ణాంకం బైట్లు_hashed;       /* Bytes (out of L1_KEY_LEN) incorporated.   */
    UINT64 state[STREAMS];               /* on-line state     */
} nh_ctx;


#ఒకవేళ (UMAC_OUTPUT_LEN == 4)

స్థిర శూన్య nh_aux(శూన్య *kp, స్థిరరాశి శూన్య *dp, శూన్య *hp, UINT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and
* then stored via hp pointer. The length of the data pointed at by "dp",
* "dlen", is guaranteed to be divisible by L1_PAD_BOUNDARY (32).  Key
* is expected to be endian compensated in memory at key setup.
*/
{
    UINT64 h;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    స్థిరరాశి UINT32 *d = (స్థిరరాశి UINT32 *)dp;
    UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
    UINT32 k0,k1,k2,k3,k4,k5,k6,k7;

    h = *((UINT64 *)hp);
    చేయి {
        d0 = ఎక్కించు_UINT32_LITTLE(d+0); d1 = ఎక్కించు_UINT32_LITTLE(d+1);
        d2 = ఎక్కించు_UINT32_LITTLE(d+2); d3 = ఎక్కించు_UINT32_LITTLE(d+3);
        d4 = ఎక్కించు_UINT32_LITTLE(d+4); d5 = ఎక్కించు_UINT32_LITTLE(d+5);
        d6 = ఎక్కించు_UINT32_LITTLE(d+6); d7 = ఎక్కించు_UINT32_LITTLE(d+7);
        k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
        k4 = *(k+4); k5 = *(k+5); k6 = *(k+6); k7 = *(k+7);
        h += MUL64((k0 + d0), (k4 + d4));
        h += MUL64((k1 + d1), (k5 + d5));
        h += MUL64((k2 + d2), (k6 + d6));
        h += MUL64((k3 + d3), (k7 + d7));

        d += 8;
        k += 8;
    } అయితే (--c);
  *((UINT64 *)hp) = h;
}

#లేదావేళ (UMAC_OUTPUT_LEN == 8)

స్థిర శూన్య nh_aux(శూన్య *kp, స్థిరరాశి శూన్య *dp, శూన్య *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 16 bytes of hash-state per call.
 */
{
  UINT64 h1,h2;
  UWORD c = dlen / 32;
  UINT32 *k = (UINT32 *)kp;
  స్థిరరాశి UINT32 *d = (స్థిరరాశి UINT32 *)dp;
  UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
  UINT32 k0,k1,k2,k3,k4,k5,k6,k7,
        k8,k9,k10,k11;

  h1 = *((UINT64 *)hp);
  h2 = *((UINT64 *)hp + 1);
  k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
  చేయి {
    d0 = ఎక్కించు_UINT32_LITTLE(d+0); d1 = ఎక్కించు_UINT32_LITTLE(d+1);
    d2 = ఎక్కించు_UINT32_LITTLE(d+2); d3 = ఎక్కించు_UINT32_LITTLE(d+3);
    d4 = ఎక్కించు_UINT32_LITTLE(d+4); d5 = ఎక్కించు_UINT32_LITTLE(d+5);
    d6 = ఎక్కించు_UINT32_LITTLE(d+6); d7 = ఎక్కించు_UINT32_LITTLE(d+7);
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
  } అయితే (--c);
  ((UINT64 *)hp)[0] = h1;
  ((UINT64 *)hp)[1] = h2;
}

#లేదావేళ (UMAC_OUTPUT_LEN == 12)

స్థిర శూన్య nh_aux(శూన్య *kp, స్థిరరాశి శూన్య *dp, శూన్య *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 24 bytes of hash-state per call.
*/
{
    UINT64 h1,h2,h3;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    స్థిరరాశి UINT32 *d = (స్థిరరాశి UINT32 *)dp;
    UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
    UINT32 k0,k1,k2,k3,k4,k5,k6,k7,
        k8,k9,k10,k11,k12,k13,k14,k15;

    h1 = *((UINT64 *)hp);
    h2 = *((UINT64 *)hp + 1);
    h3 = *((UINT64 *)hp + 2);
    k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
    k4 = *(k+4); k5 = *(k+5); k6 = *(k+6); k7 = *(k+7);
    చేయి {
        d0 = ఎక్కించు_UINT32_LITTLE(d+0); d1 = ఎక్కించు_UINT32_LITTLE(d+1);
        d2 = ఎక్కించు_UINT32_LITTLE(d+2); d3 = ఎక్కించు_UINT32_LITTLE(d+3);
        d4 = ఎక్కించు_UINT32_LITTLE(d+4); d5 = ఎక్కించు_UINT32_LITTLE(d+5);
        d6 = ఎక్కించు_UINT32_LITTLE(d+6); d7 = ఎక్కించు_UINT32_LITTLE(d+7);
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
    } అయితే (--c);
    ((UINT64 *)hp)[0] = h1;
    ((UINT64 *)hp)[1] = h2;
    ((UINT64 *)hp)[2] = h3;
}

#లేదావేళ (UMAC_OUTPUT_LEN == 16)

స్థిర శూన్య nh_aux(శూన్య *kp, స్థిరరాశి శూన్య *dp, శూన్య *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 24 bytes of hash-state per call.
*/
{
    UINT64 h1,h2,h3,h4;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    స్థిరరాశి UINT32 *d = (స్థిరరాశి UINT32 *)dp;
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
    చేయి {
        d0 = ఎక్కించు_UINT32_LITTLE(d+0); d1 = ఎక్కించు_UINT32_LITTLE(d+1);
        d2 = ఎక్కించు_UINT32_LITTLE(d+2); d3 = ఎక్కించు_UINT32_LITTLE(d+3);
        d4 = ఎక్కించు_UINT32_LITTLE(d+4); d5 = ఎక్కించు_UINT32_LITTLE(d+5);
        d6 = ఎక్కించు_UINT32_LITTLE(d+6); d7 = ఎక్కించు_UINT32_LITTLE(d+7);
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
    } అయితే (--c);
    ((UINT64 *)hp)[0] = h1;
    ((UINT64 *)hp)[1] = h2;
    ((UINT64 *)hp)[2] = h3;
    ((UINT64 *)hp)[3] = h4;
}

/* ---------------------------------------------------------------------- */
#అయితే_ముగింపు  /* UMAC_OUTPUT_LENGTH */
/* ---------------------------------------------------------------------- */


/* ---------------------------------------------------------------------- */

స్థిర శూన్య nh_transform(nh_ctx *hc, స్థిరరాశి UINT8 *buf, UINT32 nbytes)
/* This function is a wrapper for the primitive NH hash functions. It takes
 * as argument "hc" the current hash context and a buffer which must be a
 * multiple of L1_PAD_BOUNDARY. The key passed to nh_aux is offset
 * appropriately according to how much message has been hashed already.
 */
{
    UINT8 *కీలకం;

    కీలకం = hc->nh_కీలకం + hc->బైట్లు_hashed;
    nh_aux(కీలకం, buf, hc->state, nbytes);
}

/* ---------------------------------------------------------------------- */

#ఒకవేళ (__LITTLE_ENDIAN__)
స్థిర శూన్య endian_convert(శూన్య *buf, UWORD bpw, UINT32 అంకె_బైట్లు)
/* We endian convert the keys on little-endian computers to               */
/* compensate for the lack of big-endian memory reads during hashing.     */
{
    UWORD iters = అంకె_బైట్లు / bpw;
    ఒకవేళ (bpw == 4) {
        UINT32 *p = (UINT32 *)buf;
        చేయి {
            *p = ఎక్కించు_UINT32_REVERSED(p);
            p++;
        } అయితే (--iters);
    } లేకపోతే ఒకవేళ (bpw == 8) {
        UINT32 *p = (UINT32 *)buf;
        UINT32 t;
        చేయి {
            t = ఎక్కించు_UINT32_REVERSED(p+1);
            p[1] = ఎక్కించు_UINT32_REVERSED(p);
            p[0] = t;
            p += 2;
        } అయితే (--iters);
    }
}
#నిర్వచించు endian_convert_if_le(x,y,z) endian_convert((x),(y),(z))
#లేకపోతే
#నిర్వచించు endian_convert_if_le(x,y,z) చేయి{}అయితే(0)  /* Do nothing */
#అయితే_ముగింపు

/* ---------------------------------------------------------------------- */

స్థిర శూన్య nh_reset(nh_ctx *hc)
/* Reset nh_ctx to ready for hashing of new data */
{
    hc->బైట్లు_hashed = 0;
    hc->తదుపరి_దత్తాంశం_ఖాళీలు = 0;
    hc->state[0] = 0;
#ఒకవేళ (UMAC_OUTPUT_LEN >= 8)
    hc->state[1] = 0;
#అయితే_ముగింపు
#ఒకవేళ (UMAC_OUTPUT_LEN >= 12)
    hc->state[2] = 0;
#అయితే_ముగింపు
#ఒకవేళ (UMAC_OUTPUT_LEN == 16)
    hc->state[3] = 0;
#అయితే_ముగింపు

}

/* ---------------------------------------------------------------------- */

స్థిర శూన్య nh_init(nh_ctx *hc, aes_int_కీలకం prf_కీలకం)
/* Generate nh_key, endian convert and reset to be ready for hashing.   */
{
    kdf(hc->nh_కీలకం, prf_కీలకం, 1, పరిమాణం(hc->nh_కీలకం));
    endian_convert_if_le(hc->nh_కీలకం, 4, పరిమాణం(hc->nh_కీలకం));
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

స్థిర శూన్య nh_update(nh_ctx *hc, స్థిరరాశి UINT8 *buf, UINT32 nbytes)
/* Incorporate nbytes of data into a nh_ctx, buffer whatever is not an    */
/* even multiple of HASH_BUF_BYTES.                                       */
{
    UINT32 i,j;

    j = hc->తదుపరి_దత్తాంశం_ఖాళీలు;
    ఒకవేళ ((j + nbytes) >= HASH_BUF_బైట్లు) {
        ఒకవేళ (j) {
            i = HASH_BUF_బైట్లు - j;
            జ్ఞాపకం_నకలు(hc->దత్తాంశం+j, buf, i);
            nh_transform(hc,hc->దత్తాంశం,HASH_BUF_బైట్లు);
            nbytes -= i;
            buf += i;
            hc->బైట్లు_hashed += HASH_BUF_బైట్లు;
        }
        ఒకవేళ (nbytes >= HASH_BUF_బైట్లు) {
            i = nbytes & ~(HASH_BUF_బైట్లు - 1);
            nh_transform(hc, buf, i);
            nbytes -= i;
            buf += i;
            hc->బైట్లు_hashed += i;
        }
        j = 0;
    }
    జ్ఞాపకం_నకలు(hc->దత్తాంశం + j, buf, nbytes);
    hc->తదుపరి_దత్తాంశం_ఖాళీలు = j + nbytes;
}

/* ---------------------------------------------------------------------- */

స్థిర శూన్య zero_pad(UINT8 *p, పూర్ణాంకం nbytes)
{
/* Write "nbytes" of zeroes, beginning at "p" */
    ఒకవేళ (nbytes >= (పూర్ణాంకం)పరిమాణం(UWORD)) {
        అయితే ((ptrdiff_t)p % పరిమాణం(UWORD)) {
            *p = 0;
            nbytes--;
            p++;
        }
        అయితే (nbytes >= (పూర్ణాంకం)పరిమాణం(UWORD)) {
            *(UWORD *)p = 0;
            nbytes -= పరిమాణం(UWORD);
            p += పరిమాణం(UWORD);
        }
    }
    అయితే (nbytes) {
        *p = 0;
        nbytes--;
        p++;
    }
}

/* ---------------------------------------------------------------------- */

స్థిర శూన్య nh_final(nh_ctx *hc, UINT8 *ఫలితం)
/* After passing some number of data buffers to nh_update() for integration
 * into an NH context, nh_final is called to produce a hash result. If any
 * bytes are in the buffer hc->data, incorporate them into the
 * NH context. Finally, add into the NH accumulation "state" the total number
 * of bits hashed. The resulting numbers are written to the buffer "result".
 * If nh_update was never called, L1_PAD_BOUNDARY zeroes are incorporated.
 */
{
    పూర్ణాంకం nh_len, nbits;

    ఒకవేళ (hc->తదుపరి_దత్తాంశం_ఖాళీలు != 0) {
        nh_len = ((hc->తదుపరి_దత్తాంశం_ఖాళీలు + (L1_PAD_BOUNDARY - 1)) &
                                                ~(L1_PAD_BOUNDARY - 1));
        zero_pad(hc->దత్తాంశం + hc->తదుపరి_దత్తాంశం_ఖాళీలు,
                                          nh_len - hc->తదుపరి_దత్తాంశం_ఖాళీలు);
        nh_transform(hc, hc->దత్తాంశం, nh_len);
        hc->బైట్లు_hashed += hc->తదుపరి_దత్తాంశం_ఖాళీలు;
    } లేకపోతే ఒకవేళ (hc->బైట్లు_hashed == 0) {
	nh_len = L1_PAD_BOUNDARY;
        zero_pad(hc->దత్తాంశం, L1_PAD_BOUNDARY);
        nh_transform(hc, hc->దత్తాంశం, nh_len);
    }

    nbits = (hc->బైట్లు_hashed << 3);
    ((UINT64 *)ఫలితం)[0] = ((UINT64 *)hc->state)[0] + nbits;
#ఒకవేళ (UMAC_OUTPUT_LEN >= 8)
    ((UINT64 *)ఫలితం)[1] = ((UINT64 *)hc->state)[1] + nbits;
#అయితే_ముగింపు
#ఒకవేళ (UMAC_OUTPUT_LEN >= 12)
    ((UINT64 *)ఫలితం)[2] = ((UINT64 *)hc->state)[2] + nbits;
#అయితే_ముగింపు
#ఒకవేళ (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)ఫలితం)[3] = ((UINT64 *)hc->state)[3] + nbits;
#అయితే_ముగింపు
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

స్థిర శూన్య nh(nh_ctx *hc, స్థిరరాశి UINT8 *buf, UINT32 padded_len,
               UINT32 unpadded_len, UINT8 *ఫలితం)
/* All-in-one nh_update() and nh_final() equivalent.
 * Assumes that padded_len is divisible by L1_PAD_BOUNDARY and result is
 * well aligned
 */
{
    UINT32 nbits;

    /* Initialize the hash state */
    nbits = (unpadded_len << 3);

    ((UINT64 *)ఫలితం)[0] = nbits;
#ఒకవేళ (UMAC_OUTPUT_LEN >= 8)
    ((UINT64 *)ఫలితం)[1] = nbits;
#అయితే_ముగింపు
#ఒకవేళ (UMAC_OUTPUT_LEN >= 12)
    ((UINT64 *)ఫలితం)[2] = nbits;
#అయితే_ముగింపు
#ఒకవేళ (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)ఫలితం)[3] = nbits;
#అయితే_ముగింపు

    nh_aux(hc->nh_కీలకం, buf, ఫలితం, padded_len);
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
#నిర్వచించు p36    ((UINT64)0x0000000FFFFFFFFBull)              /* 2^36 -  5 */
#నిర్వచించు p64    ((UINT64)0xFFFFFFFFFFFFFFC5ull)              /* 2^64 - 59 */
#నిర్వచించు m36    ((UINT64)0x0000000FFFFFFFFFull)  /* The low 36 of 64 bits */


/* ---------------------------------------------------------------------- */

రకనిర్వచనం నిర్మాణం uhash_ctx {
    nh_ctx hash;                          /* Hash context for L1 NH hash  */
    UINT64 poly_కీలకం_8[STREAMS];           /* p64 poly keys                */
    UINT64 poly_accum[STREAMS];           /* poly hash result             */
    UINT64 ip_కీలకాలు[STREAMS*4];            /* Inner-product keys           */
    UINT32 ip_trans[STREAMS];             /* Inner-product translation    */
    UINT32 సందేశం_len;                       /* Total length of data passed  */
                                          /* to uhash */
} uhash_ctx;
రకనిర్వచనం నిర్మాణం uhash_ctx *uhash_ctx_t;

/* ---------------------------------------------------------------------- */


/* The polynomial hashes use Horner's rule to evaluate a polynomial one
 * word at a time. As described in the specification, poly32 and poly64
 * require keys from special domains. The following implementations exploit
 * the special domains to avoid overflow. The results are not guaranteed to
 * be within Z_p32 and Z_p64, but the Inner-Product hash implementation
 * patches any errant values.
 */

స్థిర UINT64 poly64(UINT64 cur, UINT64 కీలకం, UINT64 దత్తాంశం)
{
    UINT32 కీలకం_hi = (UINT32)(కీలకం >> 32),
           కీలకం_lo = (UINT32)కీలకం,
           cur_hi = (UINT32)(cur >> 32),
           cur_lo = (UINT32)cur,
           x_lo,
           x_hi;
    UINT64 X,T,res;

    X =  MUL64(కీలకం_hi, cur_lo) + MUL64(cur_hi, కీలకం_lo);
    x_lo = (UINT32)X;
    x_hi = (UINT32)(X >> 32);

    res = (MUL64(కీలకం_hi, cur_hi) + x_hi) * 59 + MUL64(కీలకం_lo, cur_lo);

    T = ((UINT64)x_lo << 32);
    res += T;
    ఒకవేళ (res < T)
        res += 59;

    res += దత్తాంశం;
    ఒకవేళ (res < దత్తాంశం)
        res += 59;

    తిరిగి res;
}


/* Although UMAC is specified to use a ramped polynomial hash scheme, this
 * implementation does not handle all ramp levels. Because we don't handle
 * the ramp up to p128 modulus in this implementation, we are limited to
 * 2^14 poly_hash() invocations per stream (for a total capacity of 2^24
 * bytes input to UMAC per tag, ie. 16MB).
 */
స్థిర శూన్య poly_hash(uhash_ctx_t hc, UINT32 దత్తాంశం_లోపల[])
{
    పూర్ణాంకం i;
    UINT64 *దత్తాంశం=(UINT64*)దత్తాంశం_లోపల;

    కొరకు (i = 0; i < STREAMS; i++) {
        ఒకవేళ ((UINT32)(దత్తాంశం[i] >> 32) == 0xfffffffful) {
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_కీలకం_8[i], p64 - 1);
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_కీలకం_8[i], (దత్తాంశం[i] - 59));
        } లేకపోతే {
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_కీలకం_8[i], దత్తాంశం[i]);
        }
    }
}


/* ---------------------------------------------------------------------- */


/* The final step in UHASH is an inner-product hash. The poly hash
 * produces a result not necessarily WORD_LEN bytes long. The inner-
 * product hash breaks the polyhash output into 16-bit chunks and
 * multiplies each with a 36 bit key.
 */

స్థిర UINT64 ip_aux(UINT64 t, UINT64 *ipkp, UINT64 దత్తాంశం)
{
    t = t + ipkp[0] * (UINT64)(UINT16)(దత్తాంశం >> 48);
    t = t + ipkp[1] * (UINT64)(UINT16)(దత్తాంశం >> 32);
    t = t + ipkp[2] * (UINT64)(UINT16)(దత్తాంశం >> 16);
    t = t + ipkp[3] * (UINT64)(UINT16)(దత్తాంశం);

    తిరిగి t;
}

స్థిర UINT32 ip_reduce_p36(UINT64 t)
{
/* Divisionless modular reduction */
    UINT64 ret;

    ret = (t & m36) + 5 * (t >> 36);
    ఒకవేళ (ret >= p36)
        ret -= p36;

    /* return least significant 32 bits */
    తిరిగి (UINT32)(ret);
}


/* If the data being hashed by UHASH is no longer than L1_KEY_LEN, then
 * the polyhash stage is skipped and ip_short is applied directly to the
 * NH output.
 */
స్థిర శూన్య ip_short(uhash_ctx_t ahc, UINT8 *nh_res, u_char *res)
{
    UINT64 t;
    UINT64 *nhp = (UINT64 *)nh_res;

    t  = ip_aux(0,ahc->ip_కీలకాలు, nhp[0]);
    STORE_UINT32_BIG((UINT32 *)res+0, ip_reduce_p36(t) ^ ahc->ip_trans[0]);
#ఒకవేళ (UMAC_OUTPUT_LEN >= 8)
    t  = ip_aux(0,ahc->ip_కీలకాలు+4, nhp[1]);
    STORE_UINT32_BIG((UINT32 *)res+1, ip_reduce_p36(t) ^ ahc->ip_trans[1]);
#అయితే_ముగింపు
#ఒకవేళ (UMAC_OUTPUT_LEN >= 12)
    t  = ip_aux(0,ahc->ip_కీలకాలు+8, nhp[2]);
    STORE_UINT32_BIG((UINT32 *)res+2, ip_reduce_p36(t) ^ ahc->ip_trans[2]);
#అయితే_ముగింపు
#ఒకవేళ (UMAC_OUTPUT_LEN == 16)
    t  = ip_aux(0,ahc->ip_కీలకాలు+12, nhp[3]);
    STORE_UINT32_BIG((UINT32 *)res+3, ip_reduce_p36(t) ^ ahc->ip_trans[3]);
#అయితే_ముగింపు
}

/* If the data being hashed by UHASH is longer than L1_KEY_LEN, then
 * the polyhash stage is not skipped and ip_long is applied to the
 * polyhash output.
 */
స్థిర శూన్య ip_long(uhash_ctx_t ahc, u_char *res)
{
    పూర్ణాంకం i;
    UINT64 t;

    కొరకు (i = 0; i < STREAMS; i++) {
        /* fix polyhash output not in Z_p64 */
        ఒకవేళ (ahc->poly_accum[i] >= p64)
            ahc->poly_accum[i] -= p64;
        t  = ip_aux(0,ahc->ip_కీలకాలు+(i*4), ahc->poly_accum[i]);
        STORE_UINT32_BIG((UINT32 *)res+i,
                         ip_reduce_p36(t) ^ ahc->ip_trans[i]);
    }
}


/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */

/* Reset uhash context for next hash session */
స్థిర పూర్ణాంకం uhash_reset(uhash_ctx_t pc)
{
    nh_reset(&pc->hash);
    pc->సందేశం_len = 0;
    pc->poly_accum[0] = 1;
#ఒకవేళ (UMAC_OUTPUT_LEN >= 8)
    pc->poly_accum[1] = 1;
#అయితే_ముగింపు
#ఒకవేళ (UMAC_OUTPUT_LEN >= 12)
    pc->poly_accum[2] = 1;
#అయితే_ముగింపు
#ఒకవేళ (UMAC_OUTPUT_LEN == 16)
    pc->poly_accum[3] = 1;
#అయితే_ముగింపు
    తిరిగి 1;
}

/* ---------------------------------------------------------------------- */

/* Given a pointer to the internal key needed by kdf() and a uhash context,
 * initialize the NH context and generate keys needed for poly and inner-
 * product hashing. All keys are endian adjusted in memory so that native
 * loads cause correct keys to be in registers during calculation.
 */
స్థిర శూన్య uhash_init(uhash_ctx_t ahc, aes_int_కీలకం prf_కీలకం)
{
    పూర్ణాంకం i;
    UINT8 buf[(8*STREAMS+4)*పరిమాణం(UINT64)];

    /* Zero the entire uhash context */
    memset(ahc, 0, పరిమాణం(uhash_ctx));

    /* Initialize the L1 hash */
    nh_init(&ahc->hash, prf_కీలకం);

    /* Setup L2 hash variables */
    kdf(buf, prf_కీలకం, 2, పరిమాణం(buf));    /* Fill buffer with index 1 key */
    కొరకు (i = 0; i < STREAMS; i++) {
        /* Fill keys from the buffer, skipping bytes in the buffer not
         * used by this implementation. Endian reverse the keys if on a
         * little-endian computer.
         */
        జ్ఞాపకం_నకలు(ahc->poly_కీలకం_8+i, buf+24*i, 8);
        endian_convert_if_le(ahc->poly_కీలకం_8+i, 8, 8);
        /* Mask the 64-bit keys to their special domain */
        ahc->poly_కీలకం_8[i] &= ((UINT64)0x01ffffffu << 32) + 0x01ffffffu;
        ahc->poly_accum[i] = 1;  /* Our polyhash prepends a non-zero word */
    }

    /* Setup L3-1 hash variables */
    kdf(buf, prf_కీలకం, 3, పరిమాణం(buf)); /* Fill buffer with index 2 key */
    కొరకు (i = 0; i < STREAMS; i++)
          జ్ఞాపకం_నకలు(ahc->ip_కీలకాలు+4*i, buf+(8*i+4)*పరిమాణం(UINT64),
                                                 4*పరిమాణం(UINT64));
    endian_convert_if_le(ahc->ip_కీలకాలు, పరిమాణం(UINT64),
                                                  పరిమాణం(ahc->ip_కీలకాలు));
    కొరకు (i = 0; i < STREAMS*4; i++)
        ahc->ip_కీలకాలు[i] %= p36;  /* Bring into Z_p36 */

    /* Setup L3-2 hash variables    */
    /* Fill buffer with index 4 key */
    kdf(ahc->ip_trans, prf_కీలకం, 4, STREAMS * పరిమాణం(UINT32));
    endian_convert_if_le(ahc->ip_trans, పరిమాణం(UINT32),
                         STREAMS * పరిమాణం(UINT32));
    explicit_bzero(buf, పరిమాణం(buf));
}

/* ---------------------------------------------------------------------- */

#ఒకవేళ 0
స్థిర uhash_ctx_t uhash_alloc(u_char కీలకం[])
{
/* Allocate memory and force to a 16-byte boundary. */
    uhash_ctx_t ctx;
    u_char బైట్లు_గమ్యం_కూడు;
    aes_int_కీలకం prf_కీలకం;

    ctx = (uhash_ctx_t)జ్ఞాపకం_ఇవ్వు(పరిమాణం(uhash_ctx)+ALLOC_BOUNDARY);
    ఒకవేళ (ctx) {
        ఒకవేళ (ALLOC_BOUNDARY) {
            బైట్లు_గమ్యం_కూడు = ALLOC_BOUNDARY -
                              ((ptrdiff_t)ctx & (ALLOC_BOUNDARY -1));
            ctx = (uhash_ctx_t)((u_char *)ctx + బైట్లు_గమ్యం_కూడు);
            *((u_char *)ctx - 1) = బైట్లు_గమ్యం_కూడు;
        }
        aes_కీలకం_అమరిక(కీలకం,prf_కీలకం);
        uhash_init(ctx, prf_కీలకం);
    }
    తిరిగి (ctx);
}
#అయితే_ముగింపు

/* ---------------------------------------------------------------------- */

#ఒకవేళ 0
స్థిర పూర్ణాంకం uhash_free(uhash_ctx_t ctx)
{
/* Free memory allocated by uhash_alloc */
    u_char బైట్లు_గమ్యం_sub;

    ఒకవేళ (ctx) {
        ఒకవేళ (ALLOC_BOUNDARY) {
            బైట్లు_గమ్యం_sub = *((u_char *)ctx - 1);
            ctx = (uhash_ctx_t)((u_char *)ctx - బైట్లు_గమ్యం_sub);
        }
        విడుదల(ctx);
    }
    తిరిగి (1);
}
#అయితే_ముగింపు
/* ---------------------------------------------------------------------- */

స్థిర పూర్ణాంకం uhash_update(uhash_ctx_t ctx, స్థిరరాశి u_char *ఆదానం, దీర్ఘ len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and
 * hash each one with NH, calling the polyhash on each NH output.
 */
{
    UWORD బైట్లు_hashed, బైట్లు_మిగిలిన;
    UINT64 ఫలితం_buf[STREAMS];
    UINT8 *nh_ఫలితం = (UINT8 *)&ఫలితం_buf;

    ఒకవేళ (ctx->సందేశం_len + len <= L1_కీలకం_LEN) {
        nh_update(&ctx->hash, (స్థిరరాశి UINT8 *)ఆదానం, len);
        ctx->సందేశం_len += len;
    } లేకపోతే {

         బైట్లు_hashed = ctx->సందేశం_len % L1_కీలకం_LEN;
         ఒకవేళ (ctx->సందేశం_len == L1_కీలకం_LEN)
             బైట్లు_hashed = L1_కీలకం_LEN;

         ఒకవేళ (బైట్లు_hashed + len >= L1_కీలకం_LEN) {

             /* If some bytes have been passed to the hash function      */
             /* then we want to pass at most (L1_KEY_LEN - bytes_hashed) */
             /* bytes to complete the current nh_block.                  */
             ఒకవేళ (బైట్లు_hashed) {
                 బైట్లు_మిగిలిన = (L1_కీలకం_LEN - బైట్లు_hashed);
                 nh_update(&ctx->hash, (స్థిరరాశి UINT8 *)ఆదానం, బైట్లు_మిగిలిన);
                 nh_final(&ctx->hash, nh_ఫలితం);
                 ctx->సందేశం_len += బైట్లు_మిగిలిన;
                 poly_hash(ctx,(UINT32 *)nh_ఫలితం);
                 len -= బైట్లు_మిగిలిన;
                 ఆదానం += బైట్లు_మిగిలిన;
             }

             /* Hash directly from input stream if enough bytes */
             అయితే (len >= L1_కీలకం_LEN) {
                 nh(&ctx->hash, (స్థిరరాశి UINT8 *)ఆదానం, L1_కీలకం_LEN,
                                   L1_కీలకం_LEN, nh_ఫలితం);
                 ctx->సందేశం_len += L1_కీలకం_LEN;
                 len -= L1_కీలకం_LEN;
                 ఆదానం += L1_కీలకం_LEN;
                 poly_hash(ctx,(UINT32 *)nh_ఫలితం);
             }
         }

         /* pass remaining < L1_KEY_LEN bytes of input data to NH */
         ఒకవేళ (len > 0 && (గుర్తులేని దీర్ఘ)len <= UINT32_MAX) {
             nh_update(&ctx->hash, (స్థిరరాశి UINT8 *)ఆదానం, len);
             ctx->సందేశం_len += len;
         }
     }

    తిరిగి (1);
}

/* ---------------------------------------------------------------------- */

స్థిర పూర్ణాంకం uhash_final(uhash_ctx_t ctx, u_char *res)
/* Incorporate any pending data, pad, and generate tag */
{
    UINT64 ఫలితం_buf[STREAMS];
    UINT8 *nh_ఫలితం = (UINT8 *)&ఫలితం_buf;

    ఒకవేళ (ctx->సందేశం_len > L1_కీలకం_LEN) {
        ఒకవేళ (ctx->సందేశం_len % L1_కీలకం_LEN) {
            nh_final(&ctx->hash, nh_ఫలితం);
            poly_hash(ctx,(UINT32 *)nh_ఫలితం);
        }
        ip_long(ctx, res);
    } లేకపోతే {
        nh_final(&ctx->hash, nh_ఫలితం);
        ip_short(ctx,nh_ఫలితం, res);
    }
    uhash_reset(ctx);
    తిరిగి (1);
}

/* ---------------------------------------------------------------------- */

#ఒకవేళ 0
స్థిర పూర్ణాంకం uhash(uhash_ctx_t ahc, u_char *సందేశం, దీర్ఘ len, u_char *res)
/* assumes that msg is in a writable buffer of length divisible by */
/* L1_PAD_BOUNDARY. Bytes beyond msg[len] may be zeroed.           */
{
    UINT8 nh_ఫలితం[STREAMS*పరిమాణం(UINT64)];
    UINT32 nh_len;
    పూర్ణాంకం extra_zeroes_needed;

    /* If the message to be hashed is no longer than L1_HASH_LEN, we skip
     * the polyhash.
     */
    ఒకవేళ (len <= L1_కీలకం_LEN) {
	ఒకవేళ (len == 0)                  /* If zero length messages will not */
		nh_len = L1_PAD_BOUNDARY;  /* be seen, comment out this case   */
	లేకపోతే
		nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
        extra_zeroes_needed = nh_len - len;
        zero_pad((UINT8 *)సందేశం + len, extra_zeroes_needed);
        nh(&ahc->hash, (UINT8 *)సందేశం, nh_len, len, nh_ఫలితం);
        ip_short(ahc,nh_ఫలితం, res);
    } లేకపోతే {
        /* Otherwise, we hash each L1_KEY_LEN chunk with NH, passing the NH
         * output to poly_hash().
         */
        చేయి {
            nh(&ahc->hash, (UINT8 *)సందేశం, L1_కీలకం_LEN, L1_కీలకం_LEN, nh_ఫలితం);
            poly_hash(ahc,(UINT32 *)nh_ఫలితం);
            len -= L1_కీలకం_LEN;
            సందేశం += L1_కీలకం_LEN;
        } అయితే (len >= L1_కీలకం_LEN);
        ఒకవేళ (len) {
            nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
            extra_zeroes_needed = nh_len - len;
            zero_pad((UINT8 *)సందేశం + len, extra_zeroes_needed);
            nh(&ahc->hash, (UINT8 *)సందేశం, nh_len, len, nh_ఫలితం);
            poly_hash(ahc,(UINT32 *)nh_ఫలితం);
        }

        ip_long(ahc, res);
    }

    uhash_reset(ahc);
    తిరిగి 1;
}
#అయితే_ముగింపు

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
నిర్మాణం umac_ctx {
    uhash_ctx hash;          /* Hash function for message compression    */
    pdf_ctx pdf;             /* PDF for hashed output                    */
    శూన్య *free_ptr;          /* Address to free this struct via          */
} umac_ctx;

/* ---------------------------------------------------------------------- */

#ఒకవేళ 0
పూర్ణాంకం umac_reset(నిర్మాణం umac_ctx *ctx)
/* Reset the hash function to begin a new authentication.        */
{
    uhash_reset(&ctx->hash);
    తిరిగి (1);
}
#అయితే_ముగింపు

/* ---------------------------------------------------------------------- */

పూర్ణాంకం umac_delete(నిర్మాణం umac_ctx *ctx)
/* Deallocate the ctx structure */
{
    ఒకవేళ (ctx) {
        ఒకవేళ (ALLOC_BOUNDARY)
            ctx = (నిర్మాణం umac_ctx *)ctx->free_ptr;
        freezero(ctx, పరిమాణం(*ctx) + ALLOC_BOUNDARY);
    }
    తిరిగి (1);
}

/* ---------------------------------------------------------------------- */

నిర్మాణం umac_ctx *umac_new(స్థిరరాశి u_char కీలకం[])
/* Dynamically allocate a umac_ctx struct, initialize variables,
 * generate subkeys from key. Align to 16-byte boundary.
 */
{
    నిర్మాణం umac_ctx *ctx, *octx;
    కొలత_t బైట్లు_గమ్యం_కూడు;
    aes_int_కీలకం prf_కీలకం;

    octx = ctx = xcalloc(1, పరిమాణం(*ctx) + ALLOC_BOUNDARY);
    ఒకవేళ (ctx) {
        ఒకవేళ (ALLOC_BOUNDARY) {
            బైట్లు_గమ్యం_కూడు = ALLOC_BOUNDARY -
                              ((ptrdiff_t)ctx & (ALLOC_BOUNDARY - 1));
            ctx = (నిర్మాణం umac_ctx *)((u_char *)ctx + బైట్లు_గమ్యం_కూడు);
        }
        ctx->free_ptr = octx;
        aes_కీలకం_అమరిక(కీలకం, prf_కీలకం);
        pdf_init(&ctx->pdf, prf_కీలకం);
        uhash_init(&ctx->hash, prf_కీలకం);
        explicit_bzero(prf_కీలకం, పరిమాణం(prf_కీలకం));
    }

    తిరిగి (ctx);
}

/* ---------------------------------------------------------------------- */

పూర్ణాంకం umac_final(నిర్మాణం umac_ctx *ctx, u_char ట్యాగ్[], స్థిరరాశి u_char nonce[8])
/* Incorporate any pending data, pad, and generate tag */
{
    uhash_final(&ctx->hash, (u_char *)ట్యాగ్);
    pdf_gen_xor(&ctx->pdf, (స్థిరరాశి UINT8 *)nonce, (UINT8 *)ట్యాగ్);

    తిరిగి (1);
}

/* ---------------------------------------------------------------------- */

పూర్ణాంకం umac_update(నిర్మాణం umac_ctx *ctx, స్థిరరాశి u_char *ఆదానం, దీర్ఘ len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and   */
/* hash each one, calling the PDF on the hashed output whenever the hash- */
/* output buffer is full.                                                 */
{
    uhash_update(&ctx->hash, ఆదానం, len);
    తిరిగి (1);
}

/* ---------------------------------------------------------------------- */

#ఒకవేళ 0
పూర్ణాంకం umac(నిర్మాణం umac_ctx *ctx, u_char *ఆదానం,
         దీర్ఘ len, u_char ట్యాగ్[],
         u_char nonce[8])
/* All-in-one version simply calls umac_update() and umac_final().        */
{
    uhash(&ctx->hash, ఆదానం, len, (u_char *)ట్యాగ్);
    pdf_gen_xor(&ctx->pdf, (UINT8 *)nonce, (UINT8 *)ట్యాగ్);

    తిరిగి (1);
}
#అయితే_ముగింపు

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- End UMAC Section ----------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
