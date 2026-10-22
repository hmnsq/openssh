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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ UMAC_OUTPUT_LEN
#ವ್ಯಾಖ್ಯಾನಿಸು UMAC_OUTPUT_LEN     8  /* Allowable: 4, 8, 12, 16                  */
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ UMAC_OUTPUT_LEN != 4 && UMAC_OUTPUT_LEN != 8 && \
    UMAC_OUTPUT_LEN != 12 && UMAC_OUTPUT_LEN != 16
# error UMAC_OUTPUT_LEN must be defined ಗಮ್ಯ 4, 8, 12 or 16
#ಆದರೆ_ಅಂತ್ಯ

/* #define FORCE_C_ONLY        1  ANSI C and 64-bit integers req'd        */
/* #define AES_IMPLEMENTAION   1  1 = OpenSSL, 2 = Barreto, 3 = Gladman   */
/* #define SSE2                0  Is SSE2 is available?                   */
/* #define RUN_TESTS           0  Run basic correctness/speed tests       */
/* #define UMAC_AE_SUPPORT     0  Enable authenticated encryption         */

/* ---------------------------------------------------------------------- */
/* -- Global Includes --------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <endian.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "umac.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

/* ---------------------------------------------------------------------- */
/* --- Primitive Data Types ---                                           */
/* ---------------------------------------------------------------------- */

/* The following assumptions may need change on your system */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint8_t	UINT8;  /* 1 byte   */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint16_t	UINT16; /* 2 byte   */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint32_t	UINT32; /* 4 byte   */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ uint64_t	UINT64; /* 8 bytes  */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ	UWORD;  /*ರಿಜಿಸ್ಟರ್*/

/* ---------------------------------------------------------------------- */
/* --- Constants -------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#ವ್ಯಾಖ್ಯಾನಿಸು UMAC_ಕೀಲಿ_LEN           16  /* UMAC takes 16 bytes of external key */

/* Message "words" are read from memory in an endian-specific manner.     */
/* For this implementation to behave correctly, __LITTLE_ENDIAN__ must    */
/* be set true if the host computer is little-endian.                     */

#ಆದರೆ BYTE_ORDER == LITTLE_ENDIAN
#ವ್ಯಾಖ್ಯಾನಿಸು __LITTLE_ENDIAN__ 1
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿಸು __LITTLE_ENDIAN__ 0
#ಆದರೆ_ಅಂತ್ಯ

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

#ವ್ಯಾಖ್ಯಾನಿಸು MUL64(a,b) ((UINT64)((UINT64)(UINT32)(a) * (UINT64)(UINT32)(b)))

/* ---------------------------------------------------------------------- */
/* --- Endian Conversion --- Forcing assembly on some platforms           */
/* ---------------------------------------------------------------------- */

#ಆದರೆ (__LITTLE_ENDIAN__)
#ವ್ಯಾಖ್ಯಾನಿಸು ತುಂಬು_UINT32_REVERSED(p)		get_u32(p)
#ವ್ಯಾಖ್ಯಾನಿಸು STORE_UINT32_REVERSED(p,v)	put_u32(p,v)
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿಸು ತುಂಬು_UINT32_REVERSED(p)		get_u32_le(p)
#ವ್ಯಾಖ್ಯಾನಿಸು STORE_UINT32_REVERSED(p,v)	put_u32_le(p,v)
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು ತುಂಬು_UINT32_LITTLE(p)		(get_u32_le(p))
#ವ್ಯಾಖ್ಯಾನಿಸು STORE_UINT32_BIG(p,v)		put_u32(p, v)

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin KDF & PDF Section ---------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* UMAC uses AES with 16 byte block and key lengths */
#ವ್ಯಾಖ್ಯಾನಿಸು AES_ಖಂಡ_LEN  16

/* OpenSSL's AES */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ USE_BUILTIN_RIJNDAEL
# include <openssl/aes.h>
#ಆದರೆ_ಅಂತ್ಯ
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ AES_ಕೀಲಿ aes_int_ಕೀಲಿ[1];
#ವ್ಯಾಖ್ಯಾನಿಸು aes_encryption(ಒಳ,ಹೊರಹೋಗು,int_ಕೀಲಿ)                  \
  AES_encrypt((u_char *)(ಒಳ),(u_char *)(ಹೊರಹೋಗು),(AES_ಕೀಲಿ *)int_ಕೀಲಿ)
#ವ್ಯಾಖ್ಯಾನಿಸು aes_ಕೀಲಿ_ಸಿದ್ಧತೆ(ಕೀಲಿ,int_ಕೀಲಿ)                      \
  AES_ಗಣ_encrypt_ಕೀಲಿ((ಸ್ಥಿರಾಂಕ u_char *)(ಕೀಲಿ),UMAC_ಕೀಲಿ_LEN*8,int_ಕೀಲಿ)
#ಇಲ್ಲದಿದ್ದರೆ
#ಅನ್ತರ್ಭಾವ "rijndael.h"
#ವ್ಯಾಖ್ಯಾನಿಸು AES_ಸುತ್ತುಗಳು ((UMAC_ಕೀಲಿ_LEN / 4) + 6)
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ UINT8 aes_int_ಕೀಲಿ[AES_ಸುತ್ತುಗಳು+1][4][4];	/* AES internal */
#ವ್ಯಾಖ್ಯಾನಿಸು aes_encryption(ಒಳ,ಹೊರಹೋಗು,int_ಕೀಲಿ) \
  rijndaelEncrypt((u32 *)(int_ಕೀಲಿ), AES_ಸುತ್ತುಗಳು, (u8 *)(ಒಳ), (u8 *)(ಹೊರಹೋಗು))
#ವ್ಯಾಖ್ಯಾನಿಸು aes_ಕೀಲಿ_ಸಿದ್ಧತೆ(ಕೀಲಿ,int_ಕೀಲಿ) \
  rijndael_ಕೀಲಿ_ಸಿದ್ಧತೆ_Enc((u32 *)(int_ಕೀಲಿ), (ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *)(ಕೀಲಿ), \
  UMAC_ಕೀಲಿ_LEN*8)
#ಆದರೆ_ಅಂತ್ಯ

/* The user-supplied UMAC key is stretched using AES in a counter
 * mode to supply all random bits needed by UMAC. The kdf function takes
 * an AES internal key representation 'key' and writes a stream of
 * 'nbytes' bytes to the memory pointed at by 'bufp'. Each distinct
 * 'ndx' causes a distinct byte stream.
 */
ಸ್ಥಿರ ಶೂನ್ಯ kdf(ಶೂನ್ಯ *bufp, aes_int_ಕೀಲಿ ಕೀಲಿ, UINT8 ndx, ಪೂರ್ಣಾಂಕ nbytes)
{
    UINT8 ಒಳ_buf[AES_ಖಂಡ_LEN] = {0};
    UINT8 ಹೊರಹೋಗು_buf[AES_ಖಂಡ_LEN];
    UINT8 *dst_buf = (UINT8 *)bufp;
    ಪೂರ್ಣಾಂಕ i;

    /* Setup the initial value */
    ಒಳ_buf[AES_ಖಂಡ_LEN-9] = ndx;
    ಒಳ_buf[AES_ಖಂಡ_LEN-1] = i = 1;

    ಆಗ (nbytes >= AES_ಖಂಡ_LEN) {
        aes_encryption(ಒಳ_buf, ಹೊರಹೋಗು_buf, ಕೀಲಿ);
        ಸ್ಮರಣೆ_ನಕಲು(dst_buf,ಹೊರಹೋಗು_buf,AES_ಖಂಡ_LEN);
        ಒಳ_buf[AES_ಖಂಡ_LEN-1] = ++i;
        nbytes -= AES_ಖಂಡ_LEN;
        dst_buf += AES_ಖಂಡ_LEN;
    }
    ಆದರೆ (nbytes) {
        aes_encryption(ಒಳ_buf, ಹೊರಹೋಗು_buf, ಕೀಲಿ);
        ಸ್ಮರಣೆ_ನಕಲು(dst_buf,ಹೊರಹೋಗು_buf,nbytes);
    }
    explicit_bzero(ಒಳ_buf, ಗಾತ್ರ(ಒಳ_buf));
    explicit_bzero(ಹೊರಹೋಗು_buf, ಗಾತ್ರ(ಹೊರಹೋಗು_buf));
}

/* The final UHASH result is XOR'd with the output of a pseudorandom
 * function. Here, we use AES to generate random output and
 * xor the appropriate bytes depending on the last bits of nonce.
 * This scheme is optimized for sequential, increasing big-endian nonces.
 */

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ {
    UINT8 cache[AES_ಖಂಡ_LEN];  /* Previous AES output is saved      */
    UINT8 nonce[AES_ಖಂಡ_LEN];  /* The AES input making above cache  */
    aes_int_ಕೀಲಿ prf_ಕೀಲಿ;         /* Expanded AES key for PDF          */
} pdf_ctx;

ಸ್ಥಿರ ಶೂನ್ಯ pdf_init(pdf_ctx *pc, aes_int_ಕೀಲಿ prf_ಕೀಲಿ)
{
    UINT8 buf[UMAC_ಕೀಲಿ_LEN];

    kdf(buf, prf_ಕೀಲಿ, 0, UMAC_ಕೀಲಿ_LEN);
    aes_ಕೀಲಿ_ಸಿದ್ಧತೆ(buf, pc->prf_ಕೀಲಿ);

    /* Initialize pdf and cache */
    memset(pc->nonce, 0, ಗಾತ್ರ(pc->nonce));
    aes_encryption(pc->nonce, pc->cache, pc->prf_ಕೀಲಿ);
    explicit_bzero(buf, ಗಾತ್ರ(buf));
}

ಸ್ಥಿರ ಶೂನ್ಯ pdf_gen_xor(pdf_ctx *pc, ಸ್ಥಿರಾಂಕ UINT8 nonce[8],
    UINT8 buf[UMAC_OUTPUT_LEN])
{
    /* 'ndx' indicates that we'll be using the 0th or 1st eight bytes
     * of the AES output. If last time around we returned the ndx-1st
     * element, then we may have the result in the cache already.
     */

#ಆದರೆ (UMAC_OUTPUT_LEN == 4)
#ವ್ಯಾಖ್ಯಾನಿಸು ಕೆಳಗಿನ_ಬಿಟ್_ಮುಖವಾಡ 3
#ಅಥವಾಆದರೆ (UMAC_OUTPUT_LEN == 8)
#ವ್ಯಾಖ್ಯಾನಿಸು ಕೆಳಗಿನ_ಬಿಟ್_ಮುಖವಾಡ 1
#ಅಥವಾಆದರೆ (UMAC_OUTPUT_LEN > 8)
#ವ್ಯಾಖ್ಯಾನಿಸು ಕೆಳಗಿನ_ಬಿಟ್_ಮುಖವಾಡ 0
#ಆದರೆ_ಅಂತ್ಯ
    ಒಕ್ಕೂಟ {
        UINT8 tmp_nonce_lo[4];
        UINT32 align;
    } t;
#ಆದರೆ ಕೆಳಗಿನ_ಬಿಟ್_ಮುಖವಾಡ != 0
    ಪೂರ್ಣಾಂಕ ndx = nonce[7] & ಕೆಳಗಿನ_ಬಿಟ್_ಮುಖವಾಡ;
#ಆದರೆ_ಅಂತ್ಯ
    *(UINT32 *)t.tmp_nonce_lo = ((ಸ್ಥಿರಾಂಕ UINT32 *)nonce)[1];
    t.tmp_nonce_lo[3] &= ~ಕೆಳಗಿನ_ಬಿಟ್_ಮುಖವಾಡ; /* zero last bit */

    ಆದರೆ ( (((UINT32 *)t.tmp_nonce_lo)[0] != ((UINT32 *)pc->nonce)[1]) ||
         (((ಸ್ಥಿರಾಂಕ UINT32 *)nonce)[0] != ((UINT32 *)pc->nonce)[0]) )
    {
        ((UINT32 *)pc->nonce)[0] = ((ಸ್ಥಿರಾಂಕ UINT32 *)nonce)[0];
        ((UINT32 *)pc->nonce)[1] = ((UINT32 *)t.tmp_nonce_lo)[0];
        aes_encryption(pc->nonce, pc->cache, pc->prf_ಕೀಲಿ);
    }

#ಆದರೆ (UMAC_OUTPUT_LEN == 4)
    *((UINT32 *)buf) ^= ((UINT32 *)pc->cache)[ndx];
#ಅಥವಾಆದರೆ (UMAC_OUTPUT_LEN == 8)
    *((UINT64 *)buf) ^= ((UINT64 *)pc->cache)[ndx];
#ಅಥವಾಆದರೆ (UMAC_OUTPUT_LEN == 12)
    ((UINT64 *)buf)[0] ^= ((UINT64 *)pc->cache)[0];
    ((UINT32 *)buf)[2] ^= ((UINT32 *)pc->cache)[2];
#ಅಥವಾಆದರೆ (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)buf)[0] ^= ((UINT64 *)pc->cache)[0];
    ((UINT64 *)buf)[1] ^= ((UINT64 *)pc->cache)[1];
#ಆದರೆ_ಅಂತ್ಯ
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

#ವ್ಯಾಖ್ಯಾನಿಸು STREAMS (UMAC_OUTPUT_LEN / 4) /* Number of times hash is applied  */
#ವ್ಯಾಖ್ಯಾನಿಸು L1_ಕೀಲಿ_LEN         1024     /* Internal key bytes                 */
#ವ್ಯಾಖ್ಯಾನಿಸು L1_ಕೀಲಿ_ಸರಿಸು         16     /* Toeplitz key shift between streams */
#ವ್ಯಾಖ್ಯಾನಿಸು L1_PAD_BOUNDARY      32     /* pad message to boundary multiple   */
#ವ್ಯಾಖ್ಯಾನಿಸು ALLOC_BOUNDARY       16     /* Keep buffers aligned to this       */
#ವ್ಯಾಖ್ಯಾನಿಸು HASH_BUF_ಬೈಟುಗಳು       64     /* nh_aux_hb buffer multiple          */

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ {
    UINT8  nh_ಕೀಲಿ [L1_ಕೀಲಿ_LEN + L1_ಕೀಲಿ_ಸರಿಸು * (STREAMS - 1)]; /* NH Key */
    UINT8  ದತ್ತಾಂಶ   [HASH_BUF_ಬೈಟುಗಳು];    /* Incoming data buffer           */
    ಪೂರ್ಣಾಂಕ ಮುಂದಿನ_ದತ್ತಾಂಶ_ಖಾಲಿಗಳು;    /* Bookkeeping variable for data buffer.     */
    ಪೂರ್ಣಾಂಕ ಬೈಟುಗಳು_hashed;       /* Bytes (out of L1_KEY_LEN) incorporated.   */
    UINT64 state[STREAMS];               /* on-line state     */
} nh_ctx;


#ಆದರೆ (UMAC_OUTPUT_LEN == 4)

ಸ್ಥಿರ ಶೂನ್ಯ nh_aux(ಶೂನ್ಯ *kp, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *dp, ಶೂನ್ಯ *hp, UINT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and
* then stored via hp pointer. The length of the data pointed at by "dp",
* "dlen", is guaranteed to be divisible by L1_PAD_BOUNDARY (32).  Key
* is expected to be endian compensated in memory at key setup.
*/
{
    UINT64 h;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    ಸ್ಥಿರಾಂಕ UINT32 *d = (ಸ್ಥಿರಾಂಕ UINT32 *)dp;
    UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
    UINT32 k0,k1,k2,k3,k4,k5,k6,k7;

    h = *((UINT64 *)hp);
    ಮಾಡು {
        d0 = ತುಂಬು_UINT32_LITTLE(d+0); d1 = ತುಂಬು_UINT32_LITTLE(d+1);
        d2 = ತುಂಬು_UINT32_LITTLE(d+2); d3 = ತುಂಬು_UINT32_LITTLE(d+3);
        d4 = ತುಂಬು_UINT32_LITTLE(d+4); d5 = ತುಂಬು_UINT32_LITTLE(d+5);
        d6 = ತುಂಬು_UINT32_LITTLE(d+6); d7 = ತುಂಬು_UINT32_LITTLE(d+7);
        k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
        k4 = *(k+4); k5 = *(k+5); k6 = *(k+6); k7 = *(k+7);
        h += MUL64((k0 + d0), (k4 + d4));
        h += MUL64((k1 + d1), (k5 + d5));
        h += MUL64((k2 + d2), (k6 + d6));
        h += MUL64((k3 + d3), (k7 + d7));

        d += 8;
        k += 8;
    } ಆಗ (--c);
  *((UINT64 *)hp) = h;
}

#ಅಥವಾಆದರೆ (UMAC_OUTPUT_LEN == 8)

ಸ್ಥಿರ ಶೂನ್ಯ nh_aux(ಶೂನ್ಯ *kp, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *dp, ಶೂನ್ಯ *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 16 bytes of hash-state per call.
 */
{
  UINT64 h1,h2;
  UWORD c = dlen / 32;
  UINT32 *k = (UINT32 *)kp;
  ಸ್ಥಿರಾಂಕ UINT32 *d = (ಸ್ಥಿರಾಂಕ UINT32 *)dp;
  UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
  UINT32 k0,k1,k2,k3,k4,k5,k6,k7,
        k8,k9,k10,k11;

  h1 = *((UINT64 *)hp);
  h2 = *((UINT64 *)hp + 1);
  k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
  ಮಾಡು {
    d0 = ತುಂಬು_UINT32_LITTLE(d+0); d1 = ತುಂಬು_UINT32_LITTLE(d+1);
    d2 = ತುಂಬು_UINT32_LITTLE(d+2); d3 = ತುಂಬು_UINT32_LITTLE(d+3);
    d4 = ತುಂಬು_UINT32_LITTLE(d+4); d5 = ತುಂಬು_UINT32_LITTLE(d+5);
    d6 = ತುಂಬು_UINT32_LITTLE(d+6); d7 = ತುಂಬು_UINT32_LITTLE(d+7);
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
  } ಆಗ (--c);
  ((UINT64 *)hp)[0] = h1;
  ((UINT64 *)hp)[1] = h2;
}

#ಅಥವಾಆದರೆ (UMAC_OUTPUT_LEN == 12)

ಸ್ಥಿರ ಶೂನ್ಯ nh_aux(ಶೂನ್ಯ *kp, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *dp, ಶೂನ್ಯ *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 24 bytes of hash-state per call.
*/
{
    UINT64 h1,h2,h3;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    ಸ್ಥಿರಾಂಕ UINT32 *d = (ಸ್ಥಿರಾಂಕ UINT32 *)dp;
    UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
    UINT32 k0,k1,k2,k3,k4,k5,k6,k7,
        k8,k9,k10,k11,k12,k13,k14,k15;

    h1 = *((UINT64 *)hp);
    h2 = *((UINT64 *)hp + 1);
    h3 = *((UINT64 *)hp + 2);
    k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
    k4 = *(k+4); k5 = *(k+5); k6 = *(k+6); k7 = *(k+7);
    ಮಾಡು {
        d0 = ತುಂಬು_UINT32_LITTLE(d+0); d1 = ತುಂಬು_UINT32_LITTLE(d+1);
        d2 = ತುಂಬು_UINT32_LITTLE(d+2); d3 = ತುಂಬು_UINT32_LITTLE(d+3);
        d4 = ತುಂಬು_UINT32_LITTLE(d+4); d5 = ತುಂಬು_UINT32_LITTLE(d+5);
        d6 = ತುಂಬು_UINT32_LITTLE(d+6); d7 = ತುಂಬು_UINT32_LITTLE(d+7);
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
    } ಆಗ (--c);
    ((UINT64 *)hp)[0] = h1;
    ((UINT64 *)hp)[1] = h2;
    ((UINT64 *)hp)[2] = h3;
}

#ಅಥವಾಆದರೆ (UMAC_OUTPUT_LEN == 16)

ಸ್ಥಿರ ಶೂನ್ಯ nh_aux(ಶೂನ್ಯ *kp, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *dp, ಶೂನ್ಯ *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 24 bytes of hash-state per call.
*/
{
    UINT64 h1,h2,h3,h4;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    ಸ್ಥಿರಾಂಕ UINT32 *d = (ಸ್ಥಿರಾಂಕ UINT32 *)dp;
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
    ಮಾಡು {
        d0 = ತುಂಬು_UINT32_LITTLE(d+0); d1 = ತುಂಬು_UINT32_LITTLE(d+1);
        d2 = ತುಂಬು_UINT32_LITTLE(d+2); d3 = ತುಂಬು_UINT32_LITTLE(d+3);
        d4 = ತುಂಬು_UINT32_LITTLE(d+4); d5 = ತುಂಬು_UINT32_LITTLE(d+5);
        d6 = ತುಂಬು_UINT32_LITTLE(d+6); d7 = ತುಂಬು_UINT32_LITTLE(d+7);
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
    } ಆಗ (--c);
    ((UINT64 *)hp)[0] = h1;
    ((UINT64 *)hp)[1] = h2;
    ((UINT64 *)hp)[2] = h3;
    ((UINT64 *)hp)[3] = h4;
}

/* ---------------------------------------------------------------------- */
#ಆದರೆ_ಅಂತ್ಯ  /* UMAC_OUTPUT_LENGTH */
/* ---------------------------------------------------------------------- */


/* ---------------------------------------------------------------------- */

ಸ್ಥಿರ ಶೂನ್ಯ nh_transform(nh_ctx *hc, ಸ್ಥಿರಾಂಕ UINT8 *buf, UINT32 nbytes)
/* This function is a wrapper for the primitive NH hash functions. It takes
 * as argument "hc" the current hash context and a buffer which must be a
 * multiple of L1_PAD_BOUNDARY. The key passed to nh_aux is offset
 * appropriately according to how much message has been hashed already.
 */
{
    UINT8 *ಕೀಲಿ;

    ಕೀಲಿ = hc->nh_ಕೀಲಿ + hc->ಬೈಟುಗಳು_hashed;
    nh_aux(ಕೀಲಿ, buf, hc->state, nbytes);
}

/* ---------------------------------------------------------------------- */

#ಆದರೆ (__LITTLE_ENDIAN__)
ಸ್ಥಿರ ಶೂನ್ಯ endian_convert(ಶೂನ್ಯ *buf, UWORD bpw, UINT32 ಅಂಕೆ_ಬೈಟುಗಳು)
/* We endian convert the keys on little-endian computers to               */
/* compensate for the lack of big-endian memory reads during hashing.     */
{
    UWORD iters = ಅಂಕೆ_ಬೈಟುಗಳು / bpw;
    ಆದರೆ (bpw == 4) {
        UINT32 *p = (UINT32 *)buf;
        ಮಾಡು {
            *p = ತುಂಬು_UINT32_REVERSED(p);
            p++;
        } ಆಗ (--iters);
    } ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (bpw == 8) {
        UINT32 *p = (UINT32 *)buf;
        UINT32 t;
        ಮಾಡು {
            t = ತುಂಬು_UINT32_REVERSED(p+1);
            p[1] = ತುಂಬು_UINT32_REVERSED(p);
            p[0] = t;
            p += 2;
        } ಆಗ (--iters);
    }
}
#ವ್ಯಾಖ್ಯಾನಿಸು endian_convert_if_le(x,y,z) endian_convert((x),(y),(z))
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿಸು endian_convert_if_le(x,y,z) ಮಾಡು{}ಆಗ(0)  /* Do nothing */
#ಆದರೆ_ಅಂತ್ಯ

/* ---------------------------------------------------------------------- */

ಸ್ಥಿರ ಶೂನ್ಯ nh_reset(nh_ctx *hc)
/* Reset nh_ctx to ready for hashing of new data */
{
    hc->ಬೈಟುಗಳು_hashed = 0;
    hc->ಮುಂದಿನ_ದತ್ತಾಂಶ_ಖಾಲಿಗಳು = 0;
    hc->state[0] = 0;
#ಆದರೆ (UMAC_OUTPUT_LEN >= 8)
    hc->state[1] = 0;
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ (UMAC_OUTPUT_LEN >= 12)
    hc->state[2] = 0;
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ (UMAC_OUTPUT_LEN == 16)
    hc->state[3] = 0;
#ಆದರೆ_ಅಂತ್ಯ

}

/* ---------------------------------------------------------------------- */

ಸ್ಥಿರ ಶೂನ್ಯ nh_init(nh_ctx *hc, aes_int_ಕೀಲಿ prf_ಕೀಲಿ)
/* Generate nh_key, endian convert and reset to be ready for hashing.   */
{
    kdf(hc->nh_ಕೀಲಿ, prf_ಕೀಲಿ, 1, ಗಾತ್ರ(hc->nh_ಕೀಲಿ));
    endian_convert_if_le(hc->nh_ಕೀಲಿ, 4, ಗಾತ್ರ(hc->nh_ಕೀಲಿ));
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

ಸ್ಥಿರ ಶೂನ್ಯ nh_update(nh_ctx *hc, ಸ್ಥಿರಾಂಕ UINT8 *buf, UINT32 nbytes)
/* Incorporate nbytes of data into a nh_ctx, buffer whatever is not an    */
/* even multiple of HASH_BUF_BYTES.                                       */
{
    UINT32 i,j;

    j = hc->ಮುಂದಿನ_ದತ್ತಾಂಶ_ಖಾಲಿಗಳು;
    ಆದರೆ ((j + nbytes) >= HASH_BUF_ಬೈಟುಗಳು) {
        ಆದರೆ (j) {
            i = HASH_BUF_ಬೈಟುಗಳು - j;
            ಸ್ಮರಣೆ_ನಕಲು(hc->ದತ್ತಾಂಶ+j, buf, i);
            nh_transform(hc,hc->ದತ್ತಾಂಶ,HASH_BUF_ಬೈಟುಗಳು);
            nbytes -= i;
            buf += i;
            hc->ಬೈಟುಗಳು_hashed += HASH_BUF_ಬೈಟುಗಳು;
        }
        ಆದರೆ (nbytes >= HASH_BUF_ಬೈಟುಗಳು) {
            i = nbytes & ~(HASH_BUF_ಬೈಟುಗಳು - 1);
            nh_transform(hc, buf, i);
            nbytes -= i;
            buf += i;
            hc->ಬೈಟುಗಳು_hashed += i;
        }
        j = 0;
    }
    ಸ್ಮರಣೆ_ನಕಲು(hc->ದತ್ತಾಂಶ + j, buf, nbytes);
    hc->ಮುಂದಿನ_ದತ್ತಾಂಶ_ಖಾಲಿಗಳು = j + nbytes;
}

/* ---------------------------------------------------------------------- */

ಸ್ಥಿರ ಶೂನ್ಯ zero_pad(UINT8 *p, ಪೂರ್ಣಾಂಕ nbytes)
{
/* Write "nbytes" of zeroes, beginning at "p" */
    ಆದರೆ (nbytes >= (ಪೂರ್ಣಾಂಕ)ಗಾತ್ರ(UWORD)) {
        ಆಗ ((ptrdiff_t)p % ಗಾತ್ರ(UWORD)) {
            *p = 0;
            nbytes--;
            p++;
        }
        ಆಗ (nbytes >= (ಪೂರ್ಣಾಂಕ)ಗಾತ್ರ(UWORD)) {
            *(UWORD *)p = 0;
            nbytes -= ಗಾತ್ರ(UWORD);
            p += ಗಾತ್ರ(UWORD);
        }
    }
    ಆಗ (nbytes) {
        *p = 0;
        nbytes--;
        p++;
    }
}

/* ---------------------------------------------------------------------- */

ಸ್ಥಿರ ಶೂನ್ಯ nh_final(nh_ctx *hc, UINT8 *ಫಲಿತಾಂಶ)
/* After passing some number of data buffers to nh_update() for integration
 * into an NH context, nh_final is called to produce a hash result. If any
 * bytes are in the buffer hc->data, incorporate them into the
 * NH context. Finally, add into the NH accumulation "state" the total number
 * of bits hashed. The resulting numbers are written to the buffer "result".
 * If nh_update was never called, L1_PAD_BOUNDARY zeroes are incorporated.
 */
{
    ಪೂರ್ಣಾಂಕ nh_len, nbits;

    ಆದರೆ (hc->ಮುಂದಿನ_ದತ್ತಾಂಶ_ಖಾಲಿಗಳು != 0) {
        nh_len = ((hc->ಮುಂದಿನ_ದತ್ತಾಂಶ_ಖಾಲಿಗಳು + (L1_PAD_BOUNDARY - 1)) &
                                                ~(L1_PAD_BOUNDARY - 1));
        zero_pad(hc->ದತ್ತಾಂಶ + hc->ಮುಂದಿನ_ದತ್ತಾಂಶ_ಖಾಲಿಗಳು,
                                          nh_len - hc->ಮುಂದಿನ_ದತ್ತಾಂಶ_ಖಾಲಿಗಳು);
        nh_transform(hc, hc->ದತ್ತಾಂಶ, nh_len);
        hc->ಬೈಟುಗಳು_hashed += hc->ಮುಂದಿನ_ದತ್ತಾಂಶ_ಖಾಲಿಗಳು;
    } ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (hc->ಬೈಟುಗಳು_hashed == 0) {
	nh_len = L1_PAD_BOUNDARY;
        zero_pad(hc->ದತ್ತಾಂಶ, L1_PAD_BOUNDARY);
        nh_transform(hc, hc->ದತ್ತಾಂಶ, nh_len);
    }

    nbits = (hc->ಬೈಟುಗಳು_hashed << 3);
    ((UINT64 *)ಫಲಿತಾಂಶ)[0] = ((UINT64 *)hc->state)[0] + nbits;
#ಆದರೆ (UMAC_OUTPUT_LEN >= 8)
    ((UINT64 *)ಫಲಿತಾಂಶ)[1] = ((UINT64 *)hc->state)[1] + nbits;
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ (UMAC_OUTPUT_LEN >= 12)
    ((UINT64 *)ಫಲಿತಾಂಶ)[2] = ((UINT64 *)hc->state)[2] + nbits;
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)ಫಲಿತಾಂಶ)[3] = ((UINT64 *)hc->state)[3] + nbits;
#ಆದರೆ_ಅಂತ್ಯ
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

ಸ್ಥಿರ ಶೂನ್ಯ nh(nh_ctx *hc, ಸ್ಥಿರಾಂಕ UINT8 *buf, UINT32 padded_len,
               UINT32 unpadded_len, UINT8 *ಫಲಿತಾಂಶ)
/* All-in-one nh_update() and nh_final() equivalent.
 * Assumes that padded_len is divisible by L1_PAD_BOUNDARY and result is
 * well aligned
 */
{
    UINT32 nbits;

    /* Initialize the hash state */
    nbits = (unpadded_len << 3);

    ((UINT64 *)ಫಲಿತಾಂಶ)[0] = nbits;
#ಆದರೆ (UMAC_OUTPUT_LEN >= 8)
    ((UINT64 *)ಫಲಿತಾಂಶ)[1] = nbits;
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ (UMAC_OUTPUT_LEN >= 12)
    ((UINT64 *)ಫಲಿತಾಂಶ)[2] = nbits;
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)ಫಲಿತಾಂಶ)[3] = nbits;
#ಆದರೆ_ಅಂತ್ಯ

    nh_aux(hc->nh_ಕೀಲಿ, buf, ಫಲಿತಾಂಶ, padded_len);
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
#ವ್ಯಾಖ್ಯಾನಿಸು p36    ((UINT64)0x0000000FFFFFFFFBull)              /* 2^36 -  5 */
#ವ್ಯಾಖ್ಯಾನಿಸು p64    ((UINT64)0xFFFFFFFFFFFFFFC5ull)              /* 2^64 - 59 */
#ವ್ಯಾಖ್ಯಾನಿಸು m36    ((UINT64)0x0000000FFFFFFFFFull)  /* The low 36 of 64 bits */


/* ---------------------------------------------------------------------- */

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ uhash_ctx {
    nh_ctx hash;                          /* Hash context for L1 NH hash  */
    UINT64 poly_ಕೀಲಿ_8[STREAMS];           /* p64 poly keys                */
    UINT64 poly_accum[STREAMS];           /* poly hash result             */
    UINT64 ip_ಕೀಲಿಗಳು[STREAMS*4];            /* Inner-product keys           */
    UINT32 ip_trans[STREAMS];             /* Inner-product translation    */
    UINT32 ಸಂದೇಶ_len;                       /* Total length of data passed  */
                                          /* to uhash */
} uhash_ctx;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ uhash_ctx *uhash_ctx_t;

/* ---------------------------------------------------------------------- */


/* The polynomial hashes use Horner's rule to evaluate a polynomial one
 * word at a time. As described in the specification, poly32 and poly64
 * require keys from special domains. The following implementations exploit
 * the special domains to avoid overflow. The results are not guaranteed to
 * be within Z_p32 and Z_p64, but the Inner-Product hash implementation
 * patches any errant values.
 */

ಸ್ಥಿರ UINT64 poly64(UINT64 cur, UINT64 ಕೀಲಿ, UINT64 ದತ್ತಾಂಶ)
{
    UINT32 ಕೀಲಿ_hi = (UINT32)(ಕೀಲಿ >> 32),
           ಕೀಲಿ_lo = (UINT32)ಕೀಲಿ,
           cur_hi = (UINT32)(cur >> 32),
           cur_lo = (UINT32)cur,
           x_lo,
           x_hi;
    UINT64 X,T,res;

    X =  MUL64(ಕೀಲಿ_hi, cur_lo) + MUL64(cur_hi, ಕೀಲಿ_lo);
    x_lo = (UINT32)X;
    x_hi = (UINT32)(X >> 32);

    res = (MUL64(ಕೀಲಿ_hi, cur_hi) + x_hi) * 59 + MUL64(ಕೀಲಿ_lo, cur_lo);

    T = ((UINT64)x_lo << 32);
    res += T;
    ಆದರೆ (res < T)
        res += 59;

    res += ದತ್ತಾಂಶ;
    ಆದರೆ (res < ದತ್ತಾಂಶ)
        res += 59;

    ಹಿಂತಿರುಗಿ res;
}


/* Although UMAC is specified to use a ramped polynomial hash scheme, this
 * implementation does not handle all ramp levels. Because we don't handle
 * the ramp up to p128 modulus in this implementation, we are limited to
 * 2^14 poly_hash() invocations per stream (for a total capacity of 2^24
 * bytes input to UMAC per tag, ie. 16MB).
 */
ಸ್ಥಿರ ಶೂನ್ಯ poly_hash(uhash_ctx_t hc, UINT32 ದತ್ತಾಂಶ_ಒಳ[])
{
    ಪೂರ್ಣಾಂಕ i;
    UINT64 *ದತ್ತಾಂಶ=(UINT64*)ದತ್ತಾಂಶ_ಒಳ;

    ಗಾಗಿ (i = 0; i < STREAMS; i++) {
        ಆದರೆ ((UINT32)(ದತ್ತಾಂಶ[i] >> 32) == 0xfffffffful) {
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_ಕೀಲಿ_8[i], p64 - 1);
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_ಕೀಲಿ_8[i], (ದತ್ತಾಂಶ[i] - 59));
        } ಇಲ್ಲದಿದ್ದರೆ {
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_ಕೀಲಿ_8[i], ದತ್ತಾಂಶ[i]);
        }
    }
}


/* ---------------------------------------------------------------------- */


/* The final step in UHASH is an inner-product hash. The poly hash
 * produces a result not necessarily WORD_LEN bytes long. The inner-
 * product hash breaks the polyhash output into 16-bit chunks and
 * multiplies each with a 36 bit key.
 */

ಸ್ಥಿರ UINT64 ip_aux(UINT64 t, UINT64 *ipkp, UINT64 ದತ್ತಾಂಶ)
{
    t = t + ipkp[0] * (UINT64)(UINT16)(ದತ್ತಾಂಶ >> 48);
    t = t + ipkp[1] * (UINT64)(UINT16)(ದತ್ತಾಂಶ >> 32);
    t = t + ipkp[2] * (UINT64)(UINT16)(ದತ್ತಾಂಶ >> 16);
    t = t + ipkp[3] * (UINT64)(UINT16)(ದತ್ತಾಂಶ);

    ಹಿಂತಿರುಗಿ t;
}

ಸ್ಥಿರ UINT32 ip_reduce_p36(UINT64 t)
{
/* Divisionless modular reduction */
    UINT64 ret;

    ret = (t & m36) + 5 * (t >> 36);
    ಆದರೆ (ret >= p36)
        ret -= p36;

    /* return least significant 32 bits */
    ಹಿಂತಿರುಗಿ (UINT32)(ret);
}


/* If the data being hashed by UHASH is no longer than L1_KEY_LEN, then
 * the polyhash stage is skipped and ip_short is applied directly to the
 * NH output.
 */
ಸ್ಥಿರ ಶೂನ್ಯ ip_short(uhash_ctx_t ahc, UINT8 *nh_res, u_char *res)
{
    UINT64 t;
    UINT64 *nhp = (UINT64 *)nh_res;

    t  = ip_aux(0,ahc->ip_ಕೀಲಿಗಳು, nhp[0]);
    STORE_UINT32_BIG((UINT32 *)res+0, ip_reduce_p36(t) ^ ahc->ip_trans[0]);
#ಆದರೆ (UMAC_OUTPUT_LEN >= 8)
    t  = ip_aux(0,ahc->ip_ಕೀಲಿಗಳು+4, nhp[1]);
    STORE_UINT32_BIG((UINT32 *)res+1, ip_reduce_p36(t) ^ ahc->ip_trans[1]);
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ (UMAC_OUTPUT_LEN >= 12)
    t  = ip_aux(0,ahc->ip_ಕೀಲಿಗಳು+8, nhp[2]);
    STORE_UINT32_BIG((UINT32 *)res+2, ip_reduce_p36(t) ^ ahc->ip_trans[2]);
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ (UMAC_OUTPUT_LEN == 16)
    t  = ip_aux(0,ahc->ip_ಕೀಲಿಗಳು+12, nhp[3]);
    STORE_UINT32_BIG((UINT32 *)res+3, ip_reduce_p36(t) ^ ahc->ip_trans[3]);
#ಆದರೆ_ಅಂತ್ಯ
}

/* If the data being hashed by UHASH is longer than L1_KEY_LEN, then
 * the polyhash stage is not skipped and ip_long is applied to the
 * polyhash output.
 */
ಸ್ಥಿರ ಶೂನ್ಯ ip_long(uhash_ctx_t ahc, u_char *res)
{
    ಪೂರ್ಣಾಂಕ i;
    UINT64 t;

    ಗಾಗಿ (i = 0; i < STREAMS; i++) {
        /* fix polyhash output not in Z_p64 */
        ಆದರೆ (ahc->poly_accum[i] >= p64)
            ahc->poly_accum[i] -= p64;
        t  = ip_aux(0,ahc->ip_ಕೀಲಿಗಳು+(i*4), ahc->poly_accum[i]);
        STORE_UINT32_BIG((UINT32 *)res+i,
                         ip_reduce_p36(t) ^ ahc->ip_trans[i]);
    }
}


/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */

/* Reset uhash context for next hash session */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ uhash_reset(uhash_ctx_t pc)
{
    nh_reset(&pc->hash);
    pc->ಸಂದೇಶ_len = 0;
    pc->poly_accum[0] = 1;
#ಆದರೆ (UMAC_OUTPUT_LEN >= 8)
    pc->poly_accum[1] = 1;
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ (UMAC_OUTPUT_LEN >= 12)
    pc->poly_accum[2] = 1;
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ (UMAC_OUTPUT_LEN == 16)
    pc->poly_accum[3] = 1;
#ಆದರೆ_ಅಂತ್ಯ
    ಹಿಂತಿರುಗಿ 1;
}

/* ---------------------------------------------------------------------- */

/* Given a pointer to the internal key needed by kdf() and a uhash context,
 * initialize the NH context and generate keys needed for poly and inner-
 * product hashing. All keys are endian adjusted in memory so that native
 * loads cause correct keys to be in registers during calculation.
 */
ಸ್ಥಿರ ಶೂನ್ಯ uhash_init(uhash_ctx_t ahc, aes_int_ಕೀಲಿ prf_ಕೀಲಿ)
{
    ಪೂರ್ಣಾಂಕ i;
    UINT8 buf[(8*STREAMS+4)*ಗಾತ್ರ(UINT64)];

    /* Zero the entire uhash context */
    memset(ahc, 0, ಗಾತ್ರ(uhash_ctx));

    /* Initialize the L1 hash */
    nh_init(&ahc->hash, prf_ಕೀಲಿ);

    /* Setup L2 hash variables */
    kdf(buf, prf_ಕೀಲಿ, 2, ಗಾತ್ರ(buf));    /* Fill buffer with index 1 key */
    ಗಾಗಿ (i = 0; i < STREAMS; i++) {
        /* Fill keys from the buffer, skipping bytes in the buffer not
         * used by this implementation. Endian reverse the keys if on a
         * little-endian computer.
         */
        ಸ್ಮರಣೆ_ನಕಲು(ahc->poly_ಕೀಲಿ_8+i, buf+24*i, 8);
        endian_convert_if_le(ahc->poly_ಕೀಲಿ_8+i, 8, 8);
        /* Mask the 64-bit keys to their special domain */
        ahc->poly_ಕೀಲಿ_8[i] &= ((UINT64)0x01ffffffu << 32) + 0x01ffffffu;
        ahc->poly_accum[i] = 1;  /* Our polyhash prepends a non-zero word */
    }

    /* Setup L3-1 hash variables */
    kdf(buf, prf_ಕೀಲಿ, 3, ಗಾತ್ರ(buf)); /* Fill buffer with index 2 key */
    ಗಾಗಿ (i = 0; i < STREAMS; i++)
          ಸ್ಮರಣೆ_ನಕಲು(ahc->ip_ಕೀಲಿಗಳು+4*i, buf+(8*i+4)*ಗಾತ್ರ(UINT64),
                                                 4*ಗಾತ್ರ(UINT64));
    endian_convert_if_le(ahc->ip_ಕೀಲಿಗಳು, ಗಾತ್ರ(UINT64),
                                                  ಗಾತ್ರ(ahc->ip_ಕೀಲಿಗಳು));
    ಗಾಗಿ (i = 0; i < STREAMS*4; i++)
        ahc->ip_ಕೀಲಿಗಳು[i] %= p36;  /* Bring into Z_p36 */

    /* Setup L3-2 hash variables    */
    /* Fill buffer with index 4 key */
    kdf(ahc->ip_trans, prf_ಕೀಲಿ, 4, STREAMS * ಗಾತ್ರ(UINT32));
    endian_convert_if_le(ahc->ip_trans, ಗಾತ್ರ(UINT32),
                         STREAMS * ಗಾತ್ರ(UINT32));
    explicit_bzero(buf, ಗಾತ್ರ(buf));
}

/* ---------------------------------------------------------------------- */

#ಆದರೆ 0
ಸ್ಥಿರ uhash_ctx_t uhash_alloc(u_char ಕೀಲಿ[])
{
/* Allocate memory and force to a 16-byte boundary. */
    uhash_ctx_t ctx;
    u_char ಬೈಟುಗಳು_ಗಮ್ಯ_ಕೂಡಿಸು;
    aes_int_ಕೀಲಿ prf_ಕೀಲಿ;

    ctx = (uhash_ctx_t)ಸ್ಮರಣೆ_ಕೊಡು(ಗಾತ್ರ(uhash_ctx)+ALLOC_BOUNDARY);
    ಆದರೆ (ctx) {
        ಆದರೆ (ALLOC_BOUNDARY) {
            ಬೈಟುಗಳು_ಗಮ್ಯ_ಕೂಡಿಸು = ALLOC_BOUNDARY -
                              ((ptrdiff_t)ctx & (ALLOC_BOUNDARY -1));
            ctx = (uhash_ctx_t)((u_char *)ctx + ಬೈಟುಗಳು_ಗಮ್ಯ_ಕೂಡಿಸು);
            *((u_char *)ctx - 1) = ಬೈಟುಗಳು_ಗಮ್ಯ_ಕೂಡಿಸು;
        }
        aes_ಕೀಲಿ_ಸಿದ್ಧತೆ(ಕೀಲಿ,prf_ಕೀಲಿ);
        uhash_init(ctx, prf_ಕೀಲಿ);
    }
    ಹಿಂತಿರುಗಿ (ctx);
}
#ಆದರೆ_ಅಂತ್ಯ

/* ---------------------------------------------------------------------- */

#ಆದರೆ 0
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ uhash_free(uhash_ctx_t ctx)
{
/* Free memory allocated by uhash_alloc */
    u_char ಬೈಟುಗಳು_ಗಮ್ಯ_sub;

    ಆದರೆ (ctx) {
        ಆದರೆ (ALLOC_BOUNDARY) {
            ಬೈಟುಗಳು_ಗಮ್ಯ_sub = *((u_char *)ctx - 1);
            ctx = (uhash_ctx_t)((u_char *)ctx - ಬೈಟುಗಳು_ಗಮ್ಯ_sub);
        }
        ಬಿಡುಗಡೆ(ctx);
    }
    ಹಿಂತಿರುಗಿ (1);
}
#ಆದರೆ_ಅಂತ್ಯ
/* ---------------------------------------------------------------------- */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ uhash_update(uhash_ctx_t ctx, ಸ್ಥಿರಾಂಕ u_char *ಒಳಹರಿವು, ದೀರ್ಘ len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and
 * hash each one with NH, calling the polyhash on each NH output.
 */
{
    UWORD ಬೈಟುಗಳು_hashed, ಬೈಟುಗಳು_ಉಳಿದ;
    UINT64 ಫಲಿತಾಂಶ_buf[STREAMS];
    UINT8 *nh_ಫಲಿತಾಂಶ = (UINT8 *)&ಫಲಿತಾಂಶ_buf;

    ಆದರೆ (ctx->ಸಂದೇಶ_len + len <= L1_ಕೀಲಿ_LEN) {
        nh_update(&ctx->hash, (ಸ್ಥಿರಾಂಕ UINT8 *)ಒಳಹರಿವು, len);
        ctx->ಸಂದೇಶ_len += len;
    } ಇಲ್ಲದಿದ್ದರೆ {

         ಬೈಟುಗಳು_hashed = ctx->ಸಂದೇಶ_len % L1_ಕೀಲಿ_LEN;
         ಆದರೆ (ctx->ಸಂದೇಶ_len == L1_ಕೀಲಿ_LEN)
             ಬೈಟುಗಳು_hashed = L1_ಕೀಲಿ_LEN;

         ಆದರೆ (ಬೈಟುಗಳು_hashed + len >= L1_ಕೀಲಿ_LEN) {

             /* If some bytes have been passed to the hash function      */
             /* then we want to pass at most (L1_KEY_LEN - bytes_hashed) */
             /* bytes to complete the current nh_block.                  */
             ಆದರೆ (ಬೈಟುಗಳು_hashed) {
                 ಬೈಟುಗಳು_ಉಳಿದ = (L1_ಕೀಲಿ_LEN - ಬೈಟುಗಳು_hashed);
                 nh_update(&ctx->hash, (ಸ್ಥಿರಾಂಕ UINT8 *)ಒಳಹರಿವು, ಬೈಟುಗಳು_ಉಳಿದ);
                 nh_final(&ctx->hash, nh_ಫಲಿತಾಂಶ);
                 ctx->ಸಂದೇಶ_len += ಬೈಟುಗಳು_ಉಳಿದ;
                 poly_hash(ctx,(UINT32 *)nh_ಫಲಿತಾಂಶ);
                 len -= ಬೈಟುಗಳು_ಉಳಿದ;
                 ಒಳಹರಿವು += ಬೈಟುಗಳು_ಉಳಿದ;
             }

             /* Hash directly from input stream if enough bytes */
             ಆಗ (len >= L1_ಕೀಲಿ_LEN) {
                 nh(&ctx->hash, (ಸ್ಥಿರಾಂಕ UINT8 *)ಒಳಹರಿವು, L1_ಕೀಲಿ_LEN,
                                   L1_ಕೀಲಿ_LEN, nh_ಫಲಿತಾಂಶ);
                 ctx->ಸಂದೇಶ_len += L1_ಕೀಲಿ_LEN;
                 len -= L1_ಕೀಲಿ_LEN;
                 ಒಳಹರಿವು += L1_ಕೀಲಿ_LEN;
                 poly_hash(ctx,(UINT32 *)nh_ಫಲಿತಾಂಶ);
             }
         }

         /* pass remaining < L1_KEY_LEN bytes of input data to NH */
         ಆದರೆ (len > 0 && (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ)len <= UINT32_MAX) {
             nh_update(&ctx->hash, (ಸ್ಥಿರಾಂಕ UINT8 *)ಒಳಹರಿವು, len);
             ctx->ಸಂದೇಶ_len += len;
         }
     }

    ಹಿಂತಿರುಗಿ (1);
}

/* ---------------------------------------------------------------------- */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ uhash_final(uhash_ctx_t ctx, u_char *res)
/* Incorporate any pending data, pad, and generate tag */
{
    UINT64 ಫಲಿತಾಂಶ_buf[STREAMS];
    UINT8 *nh_ಫಲಿತಾಂಶ = (UINT8 *)&ಫಲಿತಾಂಶ_buf;

    ಆದರೆ (ctx->ಸಂದೇಶ_len > L1_ಕೀಲಿ_LEN) {
        ಆದರೆ (ctx->ಸಂದೇಶ_len % L1_ಕೀಲಿ_LEN) {
            nh_final(&ctx->hash, nh_ಫಲಿತಾಂಶ);
            poly_hash(ctx,(UINT32 *)nh_ಫಲಿತಾಂಶ);
        }
        ip_long(ctx, res);
    } ಇಲ್ಲದಿದ್ದರೆ {
        nh_final(&ctx->hash, nh_ಫಲಿತಾಂಶ);
        ip_short(ctx,nh_ಫಲಿತಾಂಶ, res);
    }
    uhash_reset(ctx);
    ಹಿಂತಿರುಗಿ (1);
}

/* ---------------------------------------------------------------------- */

#ಆದರೆ 0
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ uhash(uhash_ctx_t ahc, u_char *ಸಂದೇಶ, ದೀರ್ಘ len, u_char *res)
/* assumes that msg is in a writable buffer of length divisible by */
/* L1_PAD_BOUNDARY. Bytes beyond msg[len] may be zeroed.           */
{
    UINT8 nh_ಫಲಿತಾಂಶ[STREAMS*ಗಾತ್ರ(UINT64)];
    UINT32 nh_len;
    ಪೂರ್ಣಾಂಕ extra_zeroes_needed;

    /* If the message to be hashed is no longer than L1_HASH_LEN, we skip
     * the polyhash.
     */
    ಆದರೆ (len <= L1_ಕೀಲಿ_LEN) {
	ಆದರೆ (len == 0)                  /* If zero length messages will not */
		nh_len = L1_PAD_BOUNDARY;  /* be seen, comment out this case   */
	ಇಲ್ಲದಿದ್ದರೆ
		nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
        extra_zeroes_needed = nh_len - len;
        zero_pad((UINT8 *)ಸಂದೇಶ + len, extra_zeroes_needed);
        nh(&ahc->hash, (UINT8 *)ಸಂದೇಶ, nh_len, len, nh_ಫಲಿತಾಂಶ);
        ip_short(ahc,nh_ಫಲಿತಾಂಶ, res);
    } ಇಲ್ಲದಿದ್ದರೆ {
        /* Otherwise, we hash each L1_KEY_LEN chunk with NH, passing the NH
         * output to poly_hash().
         */
        ಮಾಡು {
            nh(&ahc->hash, (UINT8 *)ಸಂದೇಶ, L1_ಕೀಲಿ_LEN, L1_ಕೀಲಿ_LEN, nh_ಫಲಿತಾಂಶ);
            poly_hash(ahc,(UINT32 *)nh_ಫಲಿತಾಂಶ);
            len -= L1_ಕೀಲಿ_LEN;
            ಸಂದೇಶ += L1_ಕೀಲಿ_LEN;
        } ಆಗ (len >= L1_ಕೀಲಿ_LEN);
        ಆದರೆ (len) {
            nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
            extra_zeroes_needed = nh_len - len;
            zero_pad((UINT8 *)ಸಂದೇಶ + len, extra_zeroes_needed);
            nh(&ahc->hash, (UINT8 *)ಸಂದೇಶ, nh_len, len, nh_ಫಲಿತಾಂಶ);
            poly_hash(ahc,(UINT32 *)nh_ಫಲಿತಾಂಶ);
        }

        ip_long(ahc, res);
    }

    uhash_reset(ahc);
    ಹಿಂತಿರುಗಿ 1;
}
#ಆದರೆ_ಅಂತ್ಯ

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
ರಚನೆ umac_ctx {
    uhash_ctx hash;          /* Hash function for message compression    */
    pdf_ctx pdf;             /* PDF for hashed output                    */
    ಶೂನ್ಯ *free_ptr;          /* Address to free this struct via          */
} umac_ctx;

/* ---------------------------------------------------------------------- */

#ಆದರೆ 0
ಪೂರ್ಣಾಂಕ umac_reset(ರಚನೆ umac_ctx *ctx)
/* Reset the hash function to begin a new authentication.        */
{
    uhash_reset(&ctx->hash);
    ಹಿಂತಿರುಗಿ (1);
}
#ಆದರೆ_ಅಂತ್ಯ

/* ---------------------------------------------------------------------- */

ಪೂರ್ಣಾಂಕ umac_delete(ರಚನೆ umac_ctx *ctx)
/* Deallocate the ctx structure */
{
    ಆದರೆ (ctx) {
        ಆದರೆ (ALLOC_BOUNDARY)
            ctx = (ರಚನೆ umac_ctx *)ctx->free_ptr;
        freezero(ctx, ಗಾತ್ರ(*ctx) + ALLOC_BOUNDARY);
    }
    ಹಿಂತಿರುಗಿ (1);
}

/* ---------------------------------------------------------------------- */

ರಚನೆ umac_ctx *umac_new(ಸ್ಥಿರಾಂಕ u_char ಕೀಲಿ[])
/* Dynamically allocate a umac_ctx struct, initialize variables,
 * generate subkeys from key. Align to 16-byte boundary.
 */
{
    ರಚನೆ umac_ctx *ctx, *octx;
    ಗಾತ್ರ_t ಬೈಟುಗಳು_ಗಮ್ಯ_ಕೂಡಿಸು;
    aes_int_ಕೀಲಿ prf_ಕೀಲಿ;

    octx = ctx = xcalloc(1, ಗಾತ್ರ(*ctx) + ALLOC_BOUNDARY);
    ಆದರೆ (ctx) {
        ಆದರೆ (ALLOC_BOUNDARY) {
            ಬೈಟುಗಳು_ಗಮ್ಯ_ಕೂಡಿಸು = ALLOC_BOUNDARY -
                              ((ptrdiff_t)ctx & (ALLOC_BOUNDARY - 1));
            ctx = (ರಚನೆ umac_ctx *)((u_char *)ctx + ಬೈಟುಗಳು_ಗಮ್ಯ_ಕೂಡಿಸು);
        }
        ctx->free_ptr = octx;
        aes_ಕೀಲಿ_ಸಿದ್ಧತೆ(ಕೀಲಿ, prf_ಕೀಲಿ);
        pdf_init(&ctx->pdf, prf_ಕೀಲಿ);
        uhash_init(&ctx->hash, prf_ಕೀಲಿ);
        explicit_bzero(prf_ಕೀಲಿ, ಗಾತ್ರ(prf_ಕೀಲಿ));
    }

    ಹಿಂತಿರುಗಿ (ctx);
}

/* ---------------------------------------------------------------------- */

ಪೂರ್ಣಾಂಕ umac_final(ರಚನೆ umac_ctx *ctx, u_char ಟ್ಯಾಗ್[], ಸ್ಥಿರಾಂಕ u_char nonce[8])
/* Incorporate any pending data, pad, and generate tag */
{
    uhash_final(&ctx->hash, (u_char *)ಟ್ಯಾಗ್);
    pdf_gen_xor(&ctx->pdf, (ಸ್ಥಿರಾಂಕ UINT8 *)nonce, (UINT8 *)ಟ್ಯಾಗ್);

    ಹಿಂತಿರುಗಿ (1);
}

/* ---------------------------------------------------------------------- */

ಪೂರ್ಣಾಂಕ umac_update(ರಚನೆ umac_ctx *ctx, ಸ್ಥಿರಾಂಕ u_char *ಒಳಹರಿವು, ದೀರ್ಘ len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and   */
/* hash each one, calling the PDF on the hashed output whenever the hash- */
/* output buffer is full.                                                 */
{
    uhash_update(&ctx->hash, ಒಳಹರಿವು, len);
    ಹಿಂತಿರುಗಿ (1);
}

/* ---------------------------------------------------------------------- */

#ಆದರೆ 0
ಪೂರ್ಣಾಂಕ umac(ರಚನೆ umac_ctx *ctx, u_char *ಒಳಹರಿವು,
         ದೀರ್ಘ len, u_char ಟ್ಯಾಗ್[],
         u_char nonce[8])
/* All-in-one version simply calls umac_update() and umac_final().        */
{
    uhash(&ctx->hash, ಒಳಹರಿವು, len, (u_char *)ಟ್ಯಾಗ್);
    pdf_gen_xor(&ctx->pdf, (UINT8 *)nonce, (UINT8 *)ಟ್ಯಾಗ್);

    ಹಿಂತಿರುಗಿ (1);
}
#ಆದರೆ_ಅಂತ್ಯ

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- End UMAC Section ----------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
