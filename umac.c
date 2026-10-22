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

#यदि UMAC_OUTPUT_LEN != 4 && UMAC_OUTPUT_LEN != 8 && \
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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <endian.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stddef.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "umac.h"
#अन्तर्भाव "misc.h"

/* ---------------------------------------------------------------------- */
/* --- Primitive Data Types ---                                           */
/* ---------------------------------------------------------------------- */

/* The following assumptions may need change on your system */
प्रकारनिर्देश uint8_t	UINT8;  /* 1 byte   */
प्रकारनिर्देश uint16_t	UINT16; /* 2 byte   */
प्रकारनिर्देश uint32_t	UINT32; /* 4 byte   */
प्रकारनिर्देश uint64_t	UINT64; /* 8 bytes  */
प्रकारनिर्देश unsigned पूर्णाङ्क	UWORD;  /* Register */

/* ---------------------------------------------------------------------- */
/* --- Constants -------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#define UMAC_किल्ली_LEN           16  /* UMAC takes 16 bytes of external key */

/* Message "words" are read from memory in an endian-specific manner.     */
/* For this implementation to behave correctly, __LITTLE_ENDIAN__ must    */
/* be set true if the host computer is little-endian.                     */

#यदि BYTE_ORDER == LITTLE_ENDIAN
#define __LITTLE_ENDIAN__ 1
#अन्यथा
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

#यदि (__LITTLE_ENDIAN__)
#define LOAD_UINT32_REVERSED(p)		get_u32(p)
#define STORE_UINT32_REVERSED(p,v)	put_u32(p,v)
#अन्यथा
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
#अन्तर्भाव "openbsd-compat/openssl-compat.h"
#ifndef USE_BUILTIN_RIJNDAEL
# include <openssl/aes.h>
#endif
प्रकारनिर्देश AES_किल्ली aes_int_किल्ली[1];
#define aes_encryption(in,out,int_किल्ली)                  \
  AES_encrypt((u_char *)(in),(u_char *)(out),(AES_किल्ली *)int_किल्ली)
#define aes_किल्ली_setup(किल्ली,int_किल्ली)                      \
  AES_set_encrypt_किल्ली((ध्रुव u_char *)(किल्ली),UMAC_किल्ली_LEN*8,int_किल्ली)
#अन्यथा
#अन्तर्भाव "rijndael.h"
#define AES_ROUNDS ((UMAC_किल्ली_LEN / 4) + 6)
प्रकारनिर्देश UINT8 aes_int_किल्ली[AES_ROUNDS+1][4][4];	/* AES internal */
#define aes_encryption(in,out,int_किल्ली) \
  rijndaelEncrypt((u32 *)(int_किल्ली), AES_ROUNDS, (u8 *)(in), (u8 *)(out))
#define aes_किल्ली_setup(किल्ली,int_किल्ली) \
  rijndael_किल्ली_Setup_Enc((u32 *)(int_किल्ली), (ध्रुव unsigned वर्ण *)(किल्ली), \
  UMAC_किल्ली_LEN*8)
#endif

/* The user-supplied UMAC key is stretched using AES in a counter
 * mode to supply all random bits needed by UMAC. The kdf function takes
 * an AES internal key representation 'key' and writes a stream of
 * 'nbytes' bytes to the memory pointed at by 'bufp'. Each distinct
 * 'ndx' causes a distinct byte stream.
 */
स्थिर शून्य kdf(शून्य *bufp, aes_int_किल्ली किल्ली, UINT8 ndx, पूर्णाङ्क nbytes)
{
    UINT8 in_buf[AES_BLOCK_LEN] = {0};
    UINT8 out_buf[AES_BLOCK_LEN];
    UINT8 *dst_buf = (UINT8 *)bufp;
    पूर्णाङ्क i;

    /* Setup the initial value */
    in_buf[AES_BLOCK_LEN-9] = ndx;
    in_buf[AES_BLOCK_LEN-1] = i = 1;

    यावत् (nbytes >= AES_BLOCK_LEN) {
        aes_encryption(in_buf, out_buf, किल्ली);
        memcpy(dst_buf,out_buf,AES_BLOCK_LEN);
        in_buf[AES_BLOCK_LEN-1] = ++i;
        nbytes -= AES_BLOCK_LEN;
        dst_buf += AES_BLOCK_LEN;
    }
    यदि (nbytes) {
        aes_encryption(in_buf, out_buf, किल्ली);
        memcpy(dst_buf,out_buf,nbytes);
    }
    explicit_bzero(in_buf, परिमाण(in_buf));
    explicit_bzero(out_buf, परिमाण(out_buf));
}

/* The final UHASH result is XOR'd with the output of a pseudorandom
 * function. Here, we use AES to generate random output and
 * xor the appropriate bytes depending on the last bits of nonce.
 * This scheme is optimized for sequential, increasing big-endian nonces.
 */

प्रकारनिर्देश संरचना {
    UINT8 cache[AES_BLOCK_LEN];  /* Previous AES output is saved      */
    UINT8 nonce[AES_BLOCK_LEN];  /* The AES input making above cache  */
    aes_int_किल्ली prf_किल्ली;         /* Expanded AES key for PDF          */
} pdf_ctx;

स्थिर शून्य pdf_init(pdf_ctx *pc, aes_int_किल्ली prf_किल्ली)
{
    UINT8 buf[UMAC_किल्ली_LEN];

    kdf(buf, prf_किल्ली, 0, UMAC_किल्ली_LEN);
    aes_किल्ली_setup(buf, pc->prf_किल्ली);

    /* Initialize pdf and cache */
    memset(pc->nonce, 0, परिमाण(pc->nonce));
    aes_encryption(pc->nonce, pc->cache, pc->prf_किल्ली);
    explicit_bzero(buf, परिमाण(buf));
}

स्थिर शून्य pdf_gen_xor(pdf_ctx *pc, ध्रुव UINT8 nonce[8],
    UINT8 buf[UMAC_OUTPUT_LEN])
{
    /* 'ndx' indicates that we'll be using the 0th or 1st eight bytes
     * of the AES output. If last time around we returned the ndx-1st
     * element, then we may have the result in the cache already.
     */

#यदि (UMAC_OUTPUT_LEN == 4)
#define खालचा_BIT_MASK 3
#नोचेद्यदि (UMAC_OUTPUT_LEN == 8)
#define खालचा_BIT_MASK 1
#नोचेद्यदि (UMAC_OUTPUT_LEN > 8)
#define खालचा_BIT_MASK 0
#endif
    सङ्घ {
        UINT8 tmp_nonce_lo[4];
        UINT32 align;
    } t;
#यदि खालचा_BIT_MASK != 0
    पूर्णाङ्क ndx = nonce[7] & खालचा_BIT_MASK;
#endif
    *(UINT32 *)t.tmp_nonce_lo = ((ध्रुव UINT32 *)nonce)[1];
    t.tmp_nonce_lo[3] &= ~खालचा_BIT_MASK; /* zero last bit */

    यदि ( (((UINT32 *)t.tmp_nonce_lo)[0] != ((UINT32 *)pc->nonce)[1]) ||
         (((ध्रुव UINT32 *)nonce)[0] != ((UINT32 *)pc->nonce)[0]) )
    {
        ((UINT32 *)pc->nonce)[0] = ((ध्रुव UINT32 *)nonce)[0];
        ((UINT32 *)pc->nonce)[1] = ((UINT32 *)t.tmp_nonce_lo)[0];
        aes_encryption(pc->nonce, pc->cache, pc->prf_किल्ली);
    }

#यदि (UMAC_OUTPUT_LEN == 4)
    *((UINT32 *)buf) ^= ((UINT32 *)pc->cache)[ndx];
#नोचेद्यदि (UMAC_OUTPUT_LEN == 8)
    *((UINT64 *)buf) ^= ((UINT64 *)pc->cache)[ndx];
#नोचेद्यदि (UMAC_OUTPUT_LEN == 12)
    ((UINT64 *)buf)[0] ^= ((UINT64 *)pc->cache)[0];
    ((UINT32 *)buf)[2] ^= ((UINT32 *)pc->cache)[2];
#नोचेद्यदि (UMAC_OUTPUT_LEN == 16)
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
#define L1_किल्ली_LEN         1024     /* Internal key bytes                 */
#define L1_किल्ली_SHIFT         16     /* Toeplitz key shift between streams */
#define L1_PAD_BOUNDARY      32     /* pad message to boundary multiple   */
#define ALLOC_BOUNDARY       16     /* Keep buffers aligned to this       */
#define HASH_BUF_BYTES       64     /* nh_aux_hb buffer multiple          */

प्रकारनिर्देश संरचना {
    UINT8  nh_किल्ली [L1_किल्ली_LEN + L1_किल्ली_SHIFT * (STREAMS - 1)]; /* NH Key */
    UINT8  data   [HASH_BUF_BYTES];    /* Incoming data buffer           */
    पूर्णाङ्क next_data_empty;    /* Bookkeeping variable for data buffer.     */
    पूर्णाङ्क bytes_hashed;       /* Bytes (out of L1_KEY_LEN) incorporated.   */
    UINT64 state[STREAMS];               /* on-line state     */
} nh_ctx;


#यदि (UMAC_OUTPUT_LEN == 4)

स्थिर शून्य nh_aux(शून्य *kp, ध्रुव शून्य *dp, शून्य *hp, UINT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and
* then stored via hp pointer. The length of the data pointed at by "dp",
* "dlen", is guaranteed to be divisible by L1_PAD_BOUNDARY (32).  Key
* is expected to be endian compensated in memory at key setup.
*/
{
    UINT64 h;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    ध्रुव UINT32 *d = (ध्रुव UINT32 *)dp;
    UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
    UINT32 k0,k1,k2,k3,k4,k5,k6,k7;

    h = *((UINT64 *)hp);
    कुरु {
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
    } यावत् (--c);
  *((UINT64 *)hp) = h;
}

#नोचेद्यदि (UMAC_OUTPUT_LEN == 8)

स्थिर शून्य nh_aux(शून्य *kp, ध्रुव शून्य *dp, शून्य *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 16 bytes of hash-state per call.
 */
{
  UINT64 h1,h2;
  UWORD c = dlen / 32;
  UINT32 *k = (UINT32 *)kp;
  ध्रुव UINT32 *d = (ध्रुव UINT32 *)dp;
  UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
  UINT32 k0,k1,k2,k3,k4,k5,k6,k7,
        k8,k9,k10,k11;

  h1 = *((UINT64 *)hp);
  h2 = *((UINT64 *)hp + 1);
  k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
  कुरु {
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
  } यावत् (--c);
  ((UINT64 *)hp)[0] = h1;
  ((UINT64 *)hp)[1] = h2;
}

#नोचेद्यदि (UMAC_OUTPUT_LEN == 12)

स्थिर शून्य nh_aux(शून्य *kp, ध्रुव शून्य *dp, शून्य *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 24 bytes of hash-state per call.
*/
{
    UINT64 h1,h2,h3;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    ध्रुव UINT32 *d = (ध्रुव UINT32 *)dp;
    UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
    UINT32 k0,k1,k2,k3,k4,k5,k6,k7,
        k8,k9,k10,k11,k12,k13,k14,k15;

    h1 = *((UINT64 *)hp);
    h2 = *((UINT64 *)hp + 1);
    h3 = *((UINT64 *)hp + 2);
    k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
    k4 = *(k+4); k5 = *(k+5); k6 = *(k+6); k7 = *(k+7);
    कुरु {
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
    } यावत् (--c);
    ((UINT64 *)hp)[0] = h1;
    ((UINT64 *)hp)[1] = h2;
    ((UINT64 *)hp)[2] = h3;
}

#नोचेद्यदि (UMAC_OUTPUT_LEN == 16)

स्थिर शून्य nh_aux(शून्य *kp, ध्रुव शून्य *dp, शून्य *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 24 bytes of hash-state per call.
*/
{
    UINT64 h1,h2,h3,h4;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    ध्रुव UINT32 *d = (ध्रुव UINT32 *)dp;
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
    कुरु {
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
    } यावत् (--c);
    ((UINT64 *)hp)[0] = h1;
    ((UINT64 *)hp)[1] = h2;
    ((UINT64 *)hp)[2] = h3;
    ((UINT64 *)hp)[3] = h4;
}

/* ---------------------------------------------------------------------- */
#endif  /* UMAC_OUTPUT_LENGTH */
/* ---------------------------------------------------------------------- */


/* ---------------------------------------------------------------------- */

स्थिर शून्य nh_transform(nh_ctx *hc, ध्रुव UINT8 *buf, UINT32 nbytes)
/* This function is a wrapper for the primitive NH hash functions. It takes
 * as argument "hc" the current hash context and a buffer which must be a
 * multiple of L1_PAD_BOUNDARY. The key passed to nh_aux is offset
 * appropriately according to how much message has been hashed already.
 */
{
    UINT8 *किल्ली;

    किल्ली = hc->nh_किल्ली + hc->bytes_hashed;
    nh_aux(किल्ली, buf, hc->state, nbytes);
}

/* ---------------------------------------------------------------------- */

#यदि (__LITTLE_ENDIAN__)
स्थिर शून्य endian_convert(शून्य *buf, UWORD bpw, UINT32 अंक_bytes)
/* We endian convert the keys on little-endian computers to               */
/* compensate for the lack of big-endian memory reads during hashing.     */
{
    UWORD iters = अंक_bytes / bpw;
    यदि (bpw == 4) {
        UINT32 *p = (UINT32 *)buf;
        कुरु {
            *p = LOAD_UINT32_REVERSED(p);
            p++;
        } यावत् (--iters);
    } अन्यथा यदि (bpw == 8) {
        UINT32 *p = (UINT32 *)buf;
        UINT32 t;
        कुरु {
            t = LOAD_UINT32_REVERSED(p+1);
            p[1] = LOAD_UINT32_REVERSED(p);
            p[0] = t;
            p += 2;
        } यावत् (--iters);
    }
}
#define endian_convert_if_le(x,y,z) endian_convert((x),(y),(z))
#अन्यथा
#define endian_convert_if_le(x,y,z) कुरु{}यावत्(0)  /* Do nothing */
#endif

/* ---------------------------------------------------------------------- */

स्थिर शून्य nh_reset(nh_ctx *hc)
/* Reset nh_ctx to ready for hashing of new data */
{
    hc->bytes_hashed = 0;
    hc->next_data_empty = 0;
    hc->state[0] = 0;
#यदि (UMAC_OUTPUT_LEN >= 8)
    hc->state[1] = 0;
#endif
#यदि (UMAC_OUTPUT_LEN >= 12)
    hc->state[2] = 0;
#endif
#यदि (UMAC_OUTPUT_LEN == 16)
    hc->state[3] = 0;
#endif

}

/* ---------------------------------------------------------------------- */

स्थिर शून्य nh_init(nh_ctx *hc, aes_int_किल्ली prf_किल्ली)
/* Generate nh_key, endian convert and reset to be ready for hashing.   */
{
    kdf(hc->nh_किल्ली, prf_किल्ली, 1, परिमाण(hc->nh_किल्ली));
    endian_convert_if_le(hc->nh_किल्ली, 4, परिमाण(hc->nh_किल्ली));
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

स्थिर शून्य nh_update(nh_ctx *hc, ध्रुव UINT8 *buf, UINT32 nbytes)
/* Incorporate nbytes of data into a nh_ctx, buffer whatever is not an    */
/* even multiple of HASH_BUF_BYTES.                                       */
{
    UINT32 i,j;

    j = hc->next_data_empty;
    यदि ((j + nbytes) >= HASH_BUF_BYTES) {
        यदि (j) {
            i = HASH_BUF_BYTES - j;
            memcpy(hc->data+j, buf, i);
            nh_transform(hc,hc->data,HASH_BUF_BYTES);
            nbytes -= i;
            buf += i;
            hc->bytes_hashed += HASH_BUF_BYTES;
        }
        यदि (nbytes >= HASH_BUF_BYTES) {
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

स्थिर शून्य zero_pad(UINT8 *p, पूर्णाङ्क nbytes)
{
/* Write "nbytes" of zeroes, beginning at "p" */
    यदि (nbytes >= (पूर्णाङ्क)परिमाण(UWORD)) {
        यावत् ((ptrdiff_t)p % परिमाण(UWORD)) {
            *p = 0;
            nbytes--;
            p++;
        }
        यावत् (nbytes >= (पूर्णाङ्क)परिमाण(UWORD)) {
            *(UWORD *)p = 0;
            nbytes -= परिमाण(UWORD);
            p += परिमाण(UWORD);
        }
    }
    यावत् (nbytes) {
        *p = 0;
        nbytes--;
        p++;
    }
}

/* ---------------------------------------------------------------------- */

स्थिर शून्य nh_final(nh_ctx *hc, UINT8 *result)
/* After passing some number of data buffers to nh_update() for integration
 * into an NH context, nh_final is called to produce a hash result. If any
 * bytes are in the buffer hc->data, incorporate them into the
 * NH context. Finally, add into the NH accumulation "state" the total number
 * of bits hashed. The resulting numbers are written to the buffer "result".
 * If nh_update was never called, L1_PAD_BOUNDARY zeroes are incorporated.
 */
{
    पूर्णाङ्क nh_len, nbits;

    यदि (hc->next_data_empty != 0) {
        nh_len = ((hc->next_data_empty + (L1_PAD_BOUNDARY - 1)) &
                                                ~(L1_PAD_BOUNDARY - 1));
        zero_pad(hc->data + hc->next_data_empty,
                                          nh_len - hc->next_data_empty);
        nh_transform(hc, hc->data, nh_len);
        hc->bytes_hashed += hc->next_data_empty;
    } अन्यथा यदि (hc->bytes_hashed == 0) {
	nh_len = L1_PAD_BOUNDARY;
        zero_pad(hc->data, L1_PAD_BOUNDARY);
        nh_transform(hc, hc->data, nh_len);
    }

    nbits = (hc->bytes_hashed << 3);
    ((UINT64 *)result)[0] = ((UINT64 *)hc->state)[0] + nbits;
#यदि (UMAC_OUTPUT_LEN >= 8)
    ((UINT64 *)result)[1] = ((UINT64 *)hc->state)[1] + nbits;
#endif
#यदि (UMAC_OUTPUT_LEN >= 12)
    ((UINT64 *)result)[2] = ((UINT64 *)hc->state)[2] + nbits;
#endif
#यदि (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)result)[3] = ((UINT64 *)hc->state)[3] + nbits;
#endif
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

स्थिर शून्य nh(nh_ctx *hc, ध्रुव UINT8 *buf, UINT32 padded_len,
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
#यदि (UMAC_OUTPUT_LEN >= 8)
    ((UINT64 *)result)[1] = nbits;
#endif
#यदि (UMAC_OUTPUT_LEN >= 12)
    ((UINT64 *)result)[2] = nbits;
#endif
#यदि (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)result)[3] = nbits;
#endif

    nh_aux(hc->nh_किल्ली, buf, result, padded_len);
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

प्रकारनिर्देश संरचना uhash_ctx {
    nh_ctx hash;                          /* Hash context for L1 NH hash  */
    UINT64 poly_किल्ली_8[STREAMS];           /* p64 poly keys                */
    UINT64 poly_accum[STREAMS];           /* poly hash result             */
    UINT64 ip_किल्ल्या[STREAMS*4];            /* Inner-product keys           */
    UINT32 ip_trans[STREAMS];             /* Inner-product translation    */
    UINT32 संदेश_len;                       /* Total length of data passed  */
                                          /* to uhash */
} uhash_ctx;
प्रकारनिर्देश संरचना uhash_ctx *uhash_ctx_t;

/* ---------------------------------------------------------------------- */


/* The polynomial hashes use Horner's rule to evaluate a polynomial one
 * word at a time. As described in the specification, poly32 and poly64
 * require keys from special domains. The following implementations exploit
 * the special domains to avoid overflow. The results are not guaranteed to
 * be within Z_p32 and Z_p64, but the Inner-Product hash implementation
 * patches any errant values.
 */

स्थिर UINT64 poly64(UINT64 cur, UINT64 किल्ली, UINT64 data)
{
    UINT32 किल्ली_hi = (UINT32)(किल्ली >> 32),
           किल्ली_lo = (UINT32)किल्ली,
           cur_hi = (UINT32)(cur >> 32),
           cur_lo = (UINT32)cur,
           x_lo,
           x_hi;
    UINT64 X,T,res;

    X =  MUL64(किल्ली_hi, cur_lo) + MUL64(cur_hi, किल्ली_lo);
    x_lo = (UINT32)X;
    x_hi = (UINT32)(X >> 32);

    res = (MUL64(किल्ली_hi, cur_hi) + x_hi) * 59 + MUL64(किल्ली_lo, cur_lo);

    T = ((UINT64)x_lo << 32);
    res += T;
    यदि (res < T)
        res += 59;

    res += data;
    यदि (res < data)
        res += 59;

    प्रत्यागम res;
}


/* Although UMAC is specified to use a ramped polynomial hash scheme, this
 * implementation does not handle all ramp levels. Because we don't handle
 * the ramp up to p128 modulus in this implementation, we are limited to
 * 2^14 poly_hash() invocations per stream (for a total capacity of 2^24
 * bytes input to UMAC per tag, ie. 16MB).
 */
स्थिर शून्य poly_hash(uhash_ctx_t hc, UINT32 data_in[])
{
    पूर्णाङ्क i;
    UINT64 *data=(UINT64*)data_in;

    प्रति (i = 0; i < STREAMS; i++) {
        यदि ((UINT32)(data[i] >> 32) == 0xfffffffful) {
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_किल्ली_8[i], p64 - 1);
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_किल्ली_8[i], (data[i] - 59));
        } अन्यथा {
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_किल्ली_8[i], data[i]);
        }
    }
}


/* ---------------------------------------------------------------------- */


/* The final step in UHASH is an inner-product hash. The poly hash
 * produces a result not necessarily WORD_LEN bytes long. The inner-
 * product hash breaks the polyhash output into 16-bit chunks and
 * multiplies each with a 36 bit key.
 */

स्थिर UINT64 ip_aux(UINT64 t, UINT64 *ipkp, UINT64 data)
{
    t = t + ipkp[0] * (UINT64)(UINT16)(data >> 48);
    t = t + ipkp[1] * (UINT64)(UINT16)(data >> 32);
    t = t + ipkp[2] * (UINT64)(UINT16)(data >> 16);
    t = t + ipkp[3] * (UINT64)(UINT16)(data);

    प्रत्यागम t;
}

स्थिर UINT32 ip_reduce_p36(UINT64 t)
{
/* Divisionless modular reduction */
    UINT64 ret;

    ret = (t & m36) + 5 * (t >> 36);
    यदि (ret >= p36)
        ret -= p36;

    /* return least significant 32 bits */
    प्रत्यागम (UINT32)(ret);
}


/* If the data being hashed by UHASH is no longer than L1_KEY_LEN, then
 * the polyhash stage is skipped and ip_short is applied directly to the
 * NH output.
 */
स्थिर शून्य ip_short(uhash_ctx_t ahc, UINT8 *nh_res, u_char *res)
{
    UINT64 t;
    UINT64 *nhp = (UINT64 *)nh_res;

    t  = ip_aux(0,ahc->ip_किल्ल्या, nhp[0]);
    STORE_UINT32_BIG((UINT32 *)res+0, ip_reduce_p36(t) ^ ahc->ip_trans[0]);
#यदि (UMAC_OUTPUT_LEN >= 8)
    t  = ip_aux(0,ahc->ip_किल्ल्या+4, nhp[1]);
    STORE_UINT32_BIG((UINT32 *)res+1, ip_reduce_p36(t) ^ ahc->ip_trans[1]);
#endif
#यदि (UMAC_OUTPUT_LEN >= 12)
    t  = ip_aux(0,ahc->ip_किल्ल्या+8, nhp[2]);
    STORE_UINT32_BIG((UINT32 *)res+2, ip_reduce_p36(t) ^ ahc->ip_trans[2]);
#endif
#यदि (UMAC_OUTPUT_LEN == 16)
    t  = ip_aux(0,ahc->ip_किल्ल्या+12, nhp[3]);
    STORE_UINT32_BIG((UINT32 *)res+3, ip_reduce_p36(t) ^ ahc->ip_trans[3]);
#endif
}

/* If the data being hashed by UHASH is longer than L1_KEY_LEN, then
 * the polyhash stage is not skipped and ip_long is applied to the
 * polyhash output.
 */
स्थिर शून्य ip_long(uhash_ctx_t ahc, u_char *res)
{
    पूर्णाङ्क i;
    UINT64 t;

    प्रति (i = 0; i < STREAMS; i++) {
        /* fix polyhash output not in Z_p64 */
        यदि (ahc->poly_accum[i] >= p64)
            ahc->poly_accum[i] -= p64;
        t  = ip_aux(0,ahc->ip_किल्ल्या+(i*4), ahc->poly_accum[i]);
        STORE_UINT32_BIG((UINT32 *)res+i,
                         ip_reduce_p36(t) ^ ahc->ip_trans[i]);
    }
}


/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */

/* Reset uhash context for next hash session */
स्थिर पूर्णाङ्क uhash_reset(uhash_ctx_t pc)
{
    nh_reset(&pc->hash);
    pc->संदेश_len = 0;
    pc->poly_accum[0] = 1;
#यदि (UMAC_OUTPUT_LEN >= 8)
    pc->poly_accum[1] = 1;
#endif
#यदि (UMAC_OUTPUT_LEN >= 12)
    pc->poly_accum[2] = 1;
#endif
#यदि (UMAC_OUTPUT_LEN == 16)
    pc->poly_accum[3] = 1;
#endif
    प्रत्यागम 1;
}

/* ---------------------------------------------------------------------- */

/* Given a pointer to the internal key needed by kdf() and a uhash context,
 * initialize the NH context and generate keys needed for poly and inner-
 * product hashing. All keys are endian adjusted in memory so that native
 * loads cause correct keys to be in registers during calculation.
 */
स्थिर शून्य uhash_init(uhash_ctx_t ahc, aes_int_किल्ली prf_किल्ली)
{
    पूर्णाङ्क i;
    UINT8 buf[(8*STREAMS+4)*परिमाण(UINT64)];

    /* Zero the entire uhash context */
    memset(ahc, 0, परिमाण(uhash_ctx));

    /* Initialize the L1 hash */
    nh_init(&ahc->hash, prf_किल्ली);

    /* Setup L2 hash variables */
    kdf(buf, prf_किल्ली, 2, परिमाण(buf));    /* Fill buffer with index 1 key */
    प्रति (i = 0; i < STREAMS; i++) {
        /* Fill keys from the buffer, skipping bytes in the buffer not
         * used by this implementation. Endian reverse the keys if on a
         * little-endian computer.
         */
        memcpy(ahc->poly_किल्ली_8+i, buf+24*i, 8);
        endian_convert_if_le(ahc->poly_किल्ली_8+i, 8, 8);
        /* Mask the 64-bit keys to their special domain */
        ahc->poly_किल्ली_8[i] &= ((UINT64)0x01ffffffu << 32) + 0x01ffffffu;
        ahc->poly_accum[i] = 1;  /* Our polyhash prepends a non-zero word */
    }

    /* Setup L3-1 hash variables */
    kdf(buf, prf_किल्ली, 3, परिमाण(buf)); /* Fill buffer with index 2 key */
    प्रति (i = 0; i < STREAMS; i++)
          memcpy(ahc->ip_किल्ल्या+4*i, buf+(8*i+4)*परिमाण(UINT64),
                                                 4*परिमाण(UINT64));
    endian_convert_if_le(ahc->ip_किल्ल्या, परिमाण(UINT64),
                                                  परिमाण(ahc->ip_किल्ल्या));
    प्रति (i = 0; i < STREAMS*4; i++)
        ahc->ip_किल्ल्या[i] %= p36;  /* Bring into Z_p36 */

    /* Setup L3-2 hash variables    */
    /* Fill buffer with index 4 key */
    kdf(ahc->ip_trans, prf_किल्ली, 4, STREAMS * परिमाण(UINT32));
    endian_convert_if_le(ahc->ip_trans, परिमाण(UINT32),
                         STREAMS * परिमाण(UINT32));
    explicit_bzero(buf, परिमाण(buf));
}

/* ---------------------------------------------------------------------- */

#यदि 0
स्थिर uhash_ctx_t uhash_alloc(u_char किल्ली[])
{
/* Allocate memory and force to a 16-byte boundary. */
    uhash_ctx_t ctx;
    u_char bytes_to_add;
    aes_int_किल्ली prf_किल्ली;

    ctx = (uhash_ctx_t)malloc(परिमाण(uhash_ctx)+ALLOC_BOUNDARY);
    यदि (ctx) {
        यदि (ALLOC_BOUNDARY) {
            bytes_to_add = ALLOC_BOUNDARY -
                              ((ptrdiff_t)ctx & (ALLOC_BOUNDARY -1));
            ctx = (uhash_ctx_t)((u_char *)ctx + bytes_to_add);
            *((u_char *)ctx - 1) = bytes_to_add;
        }
        aes_किल्ली_setup(किल्ली,prf_किल्ली);
        uhash_init(ctx, prf_किल्ली);
    }
    प्रत्यागम (ctx);
}
#endif

/* ---------------------------------------------------------------------- */

#यदि 0
स्थिर पूर्णाङ्क uhash_free(uhash_ctx_t ctx)
{
/* Free memory allocated by uhash_alloc */
    u_char bytes_to_sub;

    यदि (ctx) {
        यदि (ALLOC_BOUNDARY) {
            bytes_to_sub = *((u_char *)ctx - 1);
            ctx = (uhash_ctx_t)((u_char *)ctx - bytes_to_sub);
        }
        मुक्त(ctx);
    }
    प्रत्यागम (1);
}
#endif
/* ---------------------------------------------------------------------- */

स्थिर पूर्णाङ्क uhash_update(uhash_ctx_t ctx, ध्रुव u_char *आदान, long len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and
 * hash each one with NH, calling the polyhash on each NH output.
 */
{
    UWORD bytes_hashed, bytes_remaining;
    UINT64 result_buf[STREAMS];
    UINT8 *nh_result = (UINT8 *)&result_buf;

    यदि (ctx->संदेश_len + len <= L1_किल्ली_LEN) {
        nh_update(&ctx->hash, (ध्रुव UINT8 *)आदान, len);
        ctx->संदेश_len += len;
    } अन्यथा {

         bytes_hashed = ctx->संदेश_len % L1_किल्ली_LEN;
         यदि (ctx->संदेश_len == L1_किल्ली_LEN)
             bytes_hashed = L1_किल्ली_LEN;

         यदि (bytes_hashed + len >= L1_किल्ली_LEN) {

             /* If some bytes have been passed to the hash function      */
             /* then we want to pass at most (L1_KEY_LEN - bytes_hashed) */
             /* bytes to complete the current nh_block.                  */
             यदि (bytes_hashed) {
                 bytes_remaining = (L1_किल्ली_LEN - bytes_hashed);
                 nh_update(&ctx->hash, (ध्रुव UINT8 *)आदान, bytes_remaining);
                 nh_final(&ctx->hash, nh_result);
                 ctx->संदेश_len += bytes_remaining;
                 poly_hash(ctx,(UINT32 *)nh_result);
                 len -= bytes_remaining;
                 आदान += bytes_remaining;
             }

             /* Hash directly from input stream if enough bytes */
             यावत् (len >= L1_किल्ली_LEN) {
                 nh(&ctx->hash, (ध्रुव UINT8 *)आदान, L1_किल्ली_LEN,
                                   L1_किल्ली_LEN, nh_result);
                 ctx->संदेश_len += L1_किल्ली_LEN;
                 len -= L1_किल्ली_LEN;
                 आदान += L1_किल्ली_LEN;
                 poly_hash(ctx,(UINT32 *)nh_result);
             }
         }

         /* pass remaining < L1_KEY_LEN bytes of input data to NH */
         यदि (len > 0 && (unsigned long)len <= UINT32_MAX) {
             nh_update(&ctx->hash, (ध्रुव UINT8 *)आदान, len);
             ctx->संदेश_len += len;
         }
     }

    प्रत्यागम (1);
}

/* ---------------------------------------------------------------------- */

स्थिर पूर्णाङ्क uhash_final(uhash_ctx_t ctx, u_char *res)
/* Incorporate any pending data, pad, and generate tag */
{
    UINT64 result_buf[STREAMS];
    UINT8 *nh_result = (UINT8 *)&result_buf;

    यदि (ctx->संदेश_len > L1_किल्ली_LEN) {
        यदि (ctx->संदेश_len % L1_किल्ली_LEN) {
            nh_final(&ctx->hash, nh_result);
            poly_hash(ctx,(UINT32 *)nh_result);
        }
        ip_long(ctx, res);
    } अन्यथा {
        nh_final(&ctx->hash, nh_result);
        ip_short(ctx,nh_result, res);
    }
    uhash_reset(ctx);
    प्रत्यागम (1);
}

/* ---------------------------------------------------------------------- */

#यदि 0
स्थिर पूर्णाङ्क uhash(uhash_ctx_t ahc, u_char *संदेश, long len, u_char *res)
/* assumes that msg is in a writable buffer of length divisible by */
/* L1_PAD_BOUNDARY. Bytes beyond msg[len] may be zeroed.           */
{
    UINT8 nh_result[STREAMS*परिमाण(UINT64)];
    UINT32 nh_len;
    पूर्णाङ्क extra_zeroes_needed;

    /* If the message to be hashed is no longer than L1_HASH_LEN, we skip
     * the polyhash.
     */
    यदि (len <= L1_किल्ली_LEN) {
	यदि (len == 0)                  /* If zero length messages will not */
		nh_len = L1_PAD_BOUNDARY;  /* be seen, comment out this case   */
	अन्यथा
		nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
        extra_zeroes_needed = nh_len - len;
        zero_pad((UINT8 *)संदेश + len, extra_zeroes_needed);
        nh(&ahc->hash, (UINT8 *)संदेश, nh_len, len, nh_result);
        ip_short(ahc,nh_result, res);
    } अन्यथा {
        /* Otherwise, we hash each L1_KEY_LEN chunk with NH, passing the NH
         * output to poly_hash().
         */
        कुरु {
            nh(&ahc->hash, (UINT8 *)संदेश, L1_किल्ली_LEN, L1_किल्ली_LEN, nh_result);
            poly_hash(ahc,(UINT32 *)nh_result);
            len -= L1_किल्ली_LEN;
            संदेश += L1_किल्ली_LEN;
        } यावत् (len >= L1_किल्ली_LEN);
        यदि (len) {
            nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
            extra_zeroes_needed = nh_len - len;
            zero_pad((UINT8 *)संदेश + len, extra_zeroes_needed);
            nh(&ahc->hash, (UINT8 *)संदेश, nh_len, len, nh_result);
            poly_hash(ahc,(UINT32 *)nh_result);
        }

        ip_long(ahc, res);
    }

    uhash_reset(ahc);
    प्रत्यागम 1;
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
संरचना umac_ctx {
    uhash_ctx hash;          /* Hash function for message compression    */
    pdf_ctx pdf;             /* PDF for hashed output                    */
    शून्य *free_ptr;          /* Address to free this struct via          */
} umac_ctx;

/* ---------------------------------------------------------------------- */

#यदि 0
पूर्णाङ्क umac_reset(संरचना umac_ctx *ctx)
/* Reset the hash function to begin a new authentication.        */
{
    uhash_reset(&ctx->hash);
    प्रत्यागम (1);
}
#endif

/* ---------------------------------------------------------------------- */

पूर्णाङ्क umac_delete(संरचना umac_ctx *ctx)
/* Deallocate the ctx structure */
{
    यदि (ctx) {
        यदि (ALLOC_BOUNDARY)
            ctx = (संरचना umac_ctx *)ctx->free_ptr;
        freezero(ctx, परिमाण(*ctx) + ALLOC_BOUNDARY);
    }
    प्रत्यागम (1);
}

/* ---------------------------------------------------------------------- */

संरचना umac_ctx *umac_new(ध्रुव u_char किल्ली[])
/* Dynamically allocate a umac_ctx struct, initialize variables,
 * generate subkeys from key. Align to 16-byte boundary.
 */
{
    संरचना umac_ctx *ctx, *octx;
    size_t bytes_to_add;
    aes_int_किल्ली prf_किल्ली;

    octx = ctx = xcalloc(1, परिमाण(*ctx) + ALLOC_BOUNDARY);
    यदि (ctx) {
        यदि (ALLOC_BOUNDARY) {
            bytes_to_add = ALLOC_BOUNDARY -
                              ((ptrdiff_t)ctx & (ALLOC_BOUNDARY - 1));
            ctx = (संरचना umac_ctx *)((u_char *)ctx + bytes_to_add);
        }
        ctx->free_ptr = octx;
        aes_किल्ली_setup(किल्ली, prf_किल्ली);
        pdf_init(&ctx->pdf, prf_किल्ली);
        uhash_init(&ctx->hash, prf_किल्ली);
        explicit_bzero(prf_किल्ली, परिमाण(prf_किल्ली));
    }

    प्रत्यागम (ctx);
}

/* ---------------------------------------------------------------------- */

पूर्णाङ्क umac_final(संरचना umac_ctx *ctx, u_char tag[], ध्रुव u_char nonce[8])
/* Incorporate any pending data, pad, and generate tag */
{
    uhash_final(&ctx->hash, (u_char *)tag);
    pdf_gen_xor(&ctx->pdf, (ध्रुव UINT8 *)nonce, (UINT8 *)tag);

    प्रत्यागम (1);
}

/* ---------------------------------------------------------------------- */

पूर्णाङ्क umac_update(संरचना umac_ctx *ctx, ध्रुव u_char *आदान, long len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and   */
/* hash each one, calling the PDF on the hashed output whenever the hash- */
/* output buffer is full.                                                 */
{
    uhash_update(&ctx->hash, आदान, len);
    प्रत्यागम (1);
}

/* ---------------------------------------------------------------------- */

#यदि 0
पूर्णाङ्क umac(संरचना umac_ctx *ctx, u_char *आदान,
         long len, u_char tag[],
         u_char nonce[8])
/* All-in-one version simply calls umac_update() and umac_final().        */
{
    uhash(&ctx->hash, आदान, len, (u_char *)tag);
    pdf_gen_xor(&ctx->pdf, (UINT8 *)nonce, (UINT8 *)tag);

    प्रत्यागम (1);
}
#endif

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- End UMAC Section ----------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
