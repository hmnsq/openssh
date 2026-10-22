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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ UMAC_OUTPUT_LEN
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ UMAC_OUTPUT_LEN     8  /* Allowable: 4, 8, 12, 16                  */
#ਜੇ_ਅੰਤ

#ਜੇ UMAC_OUTPUT_LEN != 4 && UMAC_OUTPUT_LEN != 8 && \
    UMAC_OUTPUT_LEN != 12 && UMAC_OUTPUT_LEN != 16
# error UMAC_OUTPUT_LEN must be defined ਮੰਜ਼ਿਲ 4, 8, 12 or 16
#ਜੇ_ਅੰਤ

/* #define FORCE_C_ONLY        1  ANSI C and 64-bit integers req'd        */
/* #define AES_IMPLEMENTAION   1  1 = OpenSSL, 2 = Barreto, 3 = Gladman   */
/* #define SSE2                0  Is SSE2 is available?                   */
/* #define RUN_TESTS           0  Run basic correctness/speed tests       */
/* #define UMAC_AE_SUPPORT     0  Enable authenticated encryption         */

/* ---------------------------------------------------------------------- */
/* -- Global Includes --------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <endian.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "umac.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

/* ---------------------------------------------------------------------- */
/* --- Primitive Data Types ---                                           */
/* ---------------------------------------------------------------------- */

/* The following assumptions may need change on your system */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ uint8_t	UINT8;  /* 1 byte   */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ uint16_t	UINT16; /* 2 byte   */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ uint32_t	UINT32; /* 4 byte   */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ uint64_t	UINT64; /* 8 bytes  */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ	UWORD;  /*ਰਜਿਸਟਰ*/

/* ---------------------------------------------------------------------- */
/* --- Constants -------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ UMAC_ਕੁੰਜੀ_LEN           16  /* UMAC takes 16 bytes of external key */

/* Message "words" are read from memory in an endian-specific manner.     */
/* For this implementation to behave correctly, __LITTLE_ENDIAN__ must    */
/* be set true if the host computer is little-endian.                     */

#ਜੇ BYTE_ORDER == LITTLE_ENDIAN
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ __LITTLE_ENDIAN__ 1
#ਨਹੀਂਤਾਂ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ __LITTLE_ENDIAN__ 0
#ਜੇ_ਅੰਤ

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

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUL64(a,b) ((UINT64)((UINT64)(UINT32)(a) * (UINT64)(UINT32)(b)))

/* ---------------------------------------------------------------------- */
/* --- Endian Conversion --- Forcing assembly on some platforms           */
/* ---------------------------------------------------------------------- */

#ਜੇ (__LITTLE_ENDIAN__)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਲੱਦੋ_UINT32_REVERSED(p)		get_u32(p)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ STORE_UINT32_REVERSED(p,v)	put_u32(p,v)
#ਨਹੀਂਤਾਂ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਲੱਦੋ_UINT32_REVERSED(p)		get_u32_le(p)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ STORE_UINT32_REVERSED(p,v)	put_u32_le(p,v)
#ਜੇ_ਅੰਤ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਲੱਦੋ_UINT32_LITTLE(p)		(get_u32_le(p))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ STORE_UINT32_BIG(p,v)		put_u32(p, v)

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin KDF & PDF Section ---------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* UMAC uses AES with 16 byte block and key lengths */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AES_ਖੰਡ_LEN  16

/* OpenSSL's AES */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ USE_BUILTIN_RIJNDAEL
# include <openssl/aes.h>
#ਜੇ_ਅੰਤ
ਕਿਸਮਪਰਿਭਾਸ਼ਾ AES_ਕੁੰਜੀ aes_int_ਕੁੰਜੀ[1];
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ aes_encryption(ਵਿੱਚ,ਬਾਹਰਲਾ,int_ਕੁੰਜੀ)                  \
  AES_encrypt((u_char *)(ਵਿੱਚ),(u_char *)(ਬਾਹਰਲਾ),(AES_ਕੁੰਜੀ *)int_ਕੁੰਜੀ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ aes_ਕੁੰਜੀ_ਤਿਆਰੀ(ਕੁੰਜੀ,int_ਕੁੰਜੀ)                      \
  AES_ਸੈੱਟ_encrypt_ਕੁੰਜੀ((ਅਚਲ u_char *)(ਕੁੰਜੀ),UMAC_ਕੁੰਜੀ_LEN*8,int_ਕੁੰਜੀ)
#ਨਹੀਂਤਾਂ
#ਅਨ੍ਤਰ੍ਭਾਵ "rijndael.h"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AES_ਗੇੜ ((UMAC_ਕੁੰਜੀ_LEN / 4) + 6)
ਕਿਸਮਪਰਿਭਾਸ਼ਾ UINT8 aes_int_ਕੁੰਜੀ[AES_ਗੇੜ+1][4][4];	/* AES internal */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ aes_encryption(ਵਿੱਚ,ਬਾਹਰਲਾ,int_ਕੁੰਜੀ) \
  rijndaelEncrypt((u32 *)(int_ਕੁੰਜੀ), AES_ਗੇੜ, (u8 *)(ਵਿੱਚ), (u8 *)(ਬਾਹਰਲਾ))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ aes_ਕੁੰਜੀ_ਤਿਆਰੀ(ਕੁੰਜੀ,int_ਕੁੰਜੀ) \
  rijndael_ਕੁੰਜੀ_ਤਿਆਰੀ_Enc((u32 *)(int_ਕੁੰਜੀ), (ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *)(ਕੁੰਜੀ), \
  UMAC_ਕੁੰਜੀ_LEN*8)
#ਜੇ_ਅੰਤ

/* The user-supplied UMAC key is stretched using AES in a counter
 * mode to supply all random bits needed by UMAC. The kdf function takes
 * an AES internal key representation 'key' and writes a stream of
 * 'nbytes' bytes to the memory pointed at by 'bufp'. Each distinct
 * 'ndx' causes a distinct byte stream.
 */
ਸਥਿਰ ਖਾਲੀ kdf(ਖਾਲੀ *bufp, aes_int_ਕੁੰਜੀ ਕੁੰਜੀ, UINT8 ndx, ਪੂਰਨ nbytes)
{
    UINT8 ਵਿੱਚ_buf[AES_ਖੰਡ_LEN] = {0};
    UINT8 ਬਾਹਰਲਾ_buf[AES_ਖੰਡ_LEN];
    UINT8 *dst_buf = (UINT8 *)bufp;
    ਪੂਰਨ i;

    /* Setup the initial value */
    ਵਿੱਚ_buf[AES_ਖੰਡ_LEN-9] = ndx;
    ਵਿੱਚ_buf[AES_ਖੰਡ_LEN-1] = i = 1;

    ਜਦੋਂ (nbytes >= AES_ਖੰਡ_LEN) {
        aes_encryption(ਵਿੱਚ_buf, ਬਾਹਰਲਾ_buf, ਕੁੰਜੀ);
        ਸਮ੍ਰਿਤੀ_ਨਕਲ(dst_buf,ਬਾਹਰਲਾ_buf,AES_ਖੰਡ_LEN);
        ਵਿੱਚ_buf[AES_ਖੰਡ_LEN-1] = ++i;
        nbytes -= AES_ਖੰਡ_LEN;
        dst_buf += AES_ਖੰਡ_LEN;
    }
    ਜੇ (nbytes) {
        aes_encryption(ਵਿੱਚ_buf, ਬਾਹਰਲਾ_buf, ਕੁੰਜੀ);
        ਸਮ੍ਰਿਤੀ_ਨਕਲ(dst_buf,ਬਾਹਰਲਾ_buf,nbytes);
    }
    explicit_bzero(ਵਿੱਚ_buf, ਆਕਾਰ(ਵਿੱਚ_buf));
    explicit_bzero(ਬਾਹਰਲਾ_buf, ਆਕਾਰ(ਬਾਹਰਲਾ_buf));
}

/* The final UHASH result is XOR'd with the output of a pseudorandom
 * function. Here, we use AES to generate random output and
 * xor the appropriate bytes depending on the last bits of nonce.
 * This scheme is optimized for sequential, increasing big-endian nonces.
 */

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ {
    UINT8 cache[AES_ਖੰਡ_LEN];  /* Previous AES output is saved      */
    UINT8 nonce[AES_ਖੰਡ_LEN];  /* The AES input making above cache  */
    aes_int_ਕੁੰਜੀ prf_ਕੁੰਜੀ;         /* Expanded AES key for PDF          */
} pdf_ctx;

ਸਥਿਰ ਖਾਲੀ pdf_init(pdf_ctx *pc, aes_int_ਕੁੰਜੀ prf_ਕੁੰਜੀ)
{
    UINT8 buf[UMAC_ਕੁੰਜੀ_LEN];

    kdf(buf, prf_ਕੁੰਜੀ, 0, UMAC_ਕੁੰਜੀ_LEN);
    aes_ਕੁੰਜੀ_ਤਿਆਰੀ(buf, pc->prf_ਕੁੰਜੀ);

    /* Initialize pdf and cache */
    memset(pc->nonce, 0, ਆਕਾਰ(pc->nonce));
    aes_encryption(pc->nonce, pc->cache, pc->prf_ਕੁੰਜੀ);
    explicit_bzero(buf, ਆਕਾਰ(buf));
}

ਸਥਿਰ ਖਾਲੀ pdf_gen_xor(pdf_ctx *pc, ਅਚਲ UINT8 nonce[8],
    UINT8 buf[UMAC_OUTPUT_LEN])
{
    /* 'ndx' indicates that we'll be using the 0th or 1st eight bytes
     * of the AES output. If last time around we returned the ndx-1st
     * element, then we may have the result in the cache already.
     */

#ਜੇ (UMAC_OUTPUT_LEN == 4)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਨੀਵਾਂ_ਦੋਆਧਾਰੀ_ਅੰਕ_ਨਕਾਬ 3
#ਜਾਂਜੇ (UMAC_OUTPUT_LEN == 8)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਨੀਵਾਂ_ਦੋਆਧਾਰੀ_ਅੰਕ_ਨਕਾਬ 1
#ਜਾਂਜੇ (UMAC_OUTPUT_LEN > 8)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਨੀਵਾਂ_ਦੋਆਧਾਰੀ_ਅੰਕ_ਨਕਾਬ 0
#ਜੇ_ਅੰਤ
    ਸੰਘ {
        UINT8 tmp_nonce_lo[4];
        UINT32 align;
    } t;
#ਜੇ ਨੀਵਾਂ_ਦੋਆਧਾਰੀ_ਅੰਕ_ਨਕਾਬ != 0
    ਪੂਰਨ ndx = nonce[7] & ਨੀਵਾਂ_ਦੋਆਧਾਰੀ_ਅੰਕ_ਨਕਾਬ;
#ਜੇ_ਅੰਤ
    *(UINT32 *)t.tmp_nonce_lo = ((ਅਚਲ UINT32 *)nonce)[1];
    t.tmp_nonce_lo[3] &= ~ਨੀਵਾਂ_ਦੋਆਧਾਰੀ_ਅੰਕ_ਨਕਾਬ; /* zero last bit */

    ਜੇ ( (((UINT32 *)t.tmp_nonce_lo)[0] != ((UINT32 *)pc->nonce)[1]) ||
         (((ਅਚਲ UINT32 *)nonce)[0] != ((UINT32 *)pc->nonce)[0]) )
    {
        ((UINT32 *)pc->nonce)[0] = ((ਅਚਲ UINT32 *)nonce)[0];
        ((UINT32 *)pc->nonce)[1] = ((UINT32 *)t.tmp_nonce_lo)[0];
        aes_encryption(pc->nonce, pc->cache, pc->prf_ਕੁੰਜੀ);
    }

#ਜੇ (UMAC_OUTPUT_LEN == 4)
    *((UINT32 *)buf) ^= ((UINT32 *)pc->cache)[ndx];
#ਜਾਂਜੇ (UMAC_OUTPUT_LEN == 8)
    *((UINT64 *)buf) ^= ((UINT64 *)pc->cache)[ndx];
#ਜਾਂਜੇ (UMAC_OUTPUT_LEN == 12)
    ((UINT64 *)buf)[0] ^= ((UINT64 *)pc->cache)[0];
    ((UINT32 *)buf)[2] ^= ((UINT32 *)pc->cache)[2];
#ਜਾਂਜੇ (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)buf)[0] ^= ((UINT64 *)pc->cache)[0];
    ((UINT64 *)buf)[1] ^= ((UINT64 *)pc->cache)[1];
#ਜੇ_ਅੰਤ
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

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ STREAMS (UMAC_OUTPUT_LEN / 4) /* Number of times hash is applied  */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ L1_ਕੁੰਜੀ_LEN         1024     /* Internal key bytes                 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ L1_ਕੁੰਜੀ_ਖਿਸਕਾਓ         16     /* Toeplitz key shift between streams */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ L1_PAD_BOUNDARY      32     /* pad message to boundary multiple   */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ALLOC_BOUNDARY       16     /* Keep buffers aligned to this       */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HASH_BUF_ਬਾਈਟਾਂ       64     /* nh_aux_hb buffer multiple          */

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ {
    UINT8  nh_ਕੁੰਜੀ [L1_ਕੁੰਜੀ_LEN + L1_ਕੁੰਜੀ_ਖਿਸਕਾਓ * (STREAMS - 1)]; /* NH Key */
    UINT8  ਅੰਕੜੇ   [HASH_BUF_ਬਾਈਟਾਂ];    /* Incoming data buffer           */
    ਪੂਰਨ ਅਗਲਾ_ਅੰਕੜੇ_ਖਾਲੀ_ਥਾਵਾਂ;    /* Bookkeeping variable for data buffer.     */
    ਪੂਰਨ ਬਾਈਟਾਂ_hashed;       /* Bytes (out of L1_KEY_LEN) incorporated.   */
    UINT64 state[STREAMS];               /* on-line state     */
} nh_ctx;


#ਜੇ (UMAC_OUTPUT_LEN == 4)

ਸਥਿਰ ਖਾਲੀ nh_aux(ਖਾਲੀ *kp, ਅਚਲ ਖਾਲੀ *dp, ਖਾਲੀ *hp, UINT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and
* then stored via hp pointer. The length of the data pointed at by "dp",
* "dlen", is guaranteed to be divisible by L1_PAD_BOUNDARY (32).  Key
* is expected to be endian compensated in memory at key setup.
*/
{
    UINT64 h;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    ਅਚਲ UINT32 *d = (ਅਚਲ UINT32 *)dp;
    UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
    UINT32 k0,k1,k2,k3,k4,k5,k6,k7;

    h = *((UINT64 *)hp);
    ਕਰੋ {
        d0 = ਲੱਦੋ_UINT32_LITTLE(d+0); d1 = ਲੱਦੋ_UINT32_LITTLE(d+1);
        d2 = ਲੱਦੋ_UINT32_LITTLE(d+2); d3 = ਲੱਦੋ_UINT32_LITTLE(d+3);
        d4 = ਲੱਦੋ_UINT32_LITTLE(d+4); d5 = ਲੱਦੋ_UINT32_LITTLE(d+5);
        d6 = ਲੱਦੋ_UINT32_LITTLE(d+6); d7 = ਲੱਦੋ_UINT32_LITTLE(d+7);
        k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
        k4 = *(k+4); k5 = *(k+5); k6 = *(k+6); k7 = *(k+7);
        h += MUL64((k0 + d0), (k4 + d4));
        h += MUL64((k1 + d1), (k5 + d5));
        h += MUL64((k2 + d2), (k6 + d6));
        h += MUL64((k3 + d3), (k7 + d7));

        d += 8;
        k += 8;
    } ਜਦੋਂ (--c);
  *((UINT64 *)hp) = h;
}

#ਜਾਂਜੇ (UMAC_OUTPUT_LEN == 8)

ਸਥਿਰ ਖਾਲੀ nh_aux(ਖਾਲੀ *kp, ਅਚਲ ਖਾਲੀ *dp, ਖਾਲੀ *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 16 bytes of hash-state per call.
 */
{
  UINT64 h1,h2;
  UWORD c = dlen / 32;
  UINT32 *k = (UINT32 *)kp;
  ਅਚਲ UINT32 *d = (ਅਚਲ UINT32 *)dp;
  UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
  UINT32 k0,k1,k2,k3,k4,k5,k6,k7,
        k8,k9,k10,k11;

  h1 = *((UINT64 *)hp);
  h2 = *((UINT64 *)hp + 1);
  k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
  ਕਰੋ {
    d0 = ਲੱਦੋ_UINT32_LITTLE(d+0); d1 = ਲੱਦੋ_UINT32_LITTLE(d+1);
    d2 = ਲੱਦੋ_UINT32_LITTLE(d+2); d3 = ਲੱਦੋ_UINT32_LITTLE(d+3);
    d4 = ਲੱਦੋ_UINT32_LITTLE(d+4); d5 = ਲੱਦੋ_UINT32_LITTLE(d+5);
    d6 = ਲੱਦੋ_UINT32_LITTLE(d+6); d7 = ਲੱਦੋ_UINT32_LITTLE(d+7);
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
  } ਜਦੋਂ (--c);
  ((UINT64 *)hp)[0] = h1;
  ((UINT64 *)hp)[1] = h2;
}

#ਜਾਂਜੇ (UMAC_OUTPUT_LEN == 12)

ਸਥਿਰ ਖਾਲੀ nh_aux(ਖਾਲੀ *kp, ਅਚਲ ਖਾਲੀ *dp, ਖਾਲੀ *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 24 bytes of hash-state per call.
*/
{
    UINT64 h1,h2,h3;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    ਅਚਲ UINT32 *d = (ਅਚਲ UINT32 *)dp;
    UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
    UINT32 k0,k1,k2,k3,k4,k5,k6,k7,
        k8,k9,k10,k11,k12,k13,k14,k15;

    h1 = *((UINT64 *)hp);
    h2 = *((UINT64 *)hp + 1);
    h3 = *((UINT64 *)hp + 2);
    k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
    k4 = *(k+4); k5 = *(k+5); k6 = *(k+6); k7 = *(k+7);
    ਕਰੋ {
        d0 = ਲੱਦੋ_UINT32_LITTLE(d+0); d1 = ਲੱਦੋ_UINT32_LITTLE(d+1);
        d2 = ਲੱਦੋ_UINT32_LITTLE(d+2); d3 = ਲੱਦੋ_UINT32_LITTLE(d+3);
        d4 = ਲੱਦੋ_UINT32_LITTLE(d+4); d5 = ਲੱਦੋ_UINT32_LITTLE(d+5);
        d6 = ਲੱਦੋ_UINT32_LITTLE(d+6); d7 = ਲੱਦੋ_UINT32_LITTLE(d+7);
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
    } ਜਦੋਂ (--c);
    ((UINT64 *)hp)[0] = h1;
    ((UINT64 *)hp)[1] = h2;
    ((UINT64 *)hp)[2] = h3;
}

#ਜਾਂਜੇ (UMAC_OUTPUT_LEN == 16)

ਸਥਿਰ ਖਾਲੀ nh_aux(ਖਾਲੀ *kp, ਅਚਲ ਖਾਲੀ *dp, ਖਾਲੀ *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 24 bytes of hash-state per call.
*/
{
    UINT64 h1,h2,h3,h4;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    ਅਚਲ UINT32 *d = (ਅਚਲ UINT32 *)dp;
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
    ਕਰੋ {
        d0 = ਲੱਦੋ_UINT32_LITTLE(d+0); d1 = ਲੱਦੋ_UINT32_LITTLE(d+1);
        d2 = ਲੱਦੋ_UINT32_LITTLE(d+2); d3 = ਲੱਦੋ_UINT32_LITTLE(d+3);
        d4 = ਲੱਦੋ_UINT32_LITTLE(d+4); d5 = ਲੱਦੋ_UINT32_LITTLE(d+5);
        d6 = ਲੱਦੋ_UINT32_LITTLE(d+6); d7 = ਲੱਦੋ_UINT32_LITTLE(d+7);
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
    } ਜਦੋਂ (--c);
    ((UINT64 *)hp)[0] = h1;
    ((UINT64 *)hp)[1] = h2;
    ((UINT64 *)hp)[2] = h3;
    ((UINT64 *)hp)[3] = h4;
}

/* ---------------------------------------------------------------------- */
#ਜੇ_ਅੰਤ  /* UMAC_OUTPUT_LENGTH */
/* ---------------------------------------------------------------------- */


/* ---------------------------------------------------------------------- */

ਸਥਿਰ ਖਾਲੀ nh_transform(nh_ctx *hc, ਅਚਲ UINT8 *buf, UINT32 nbytes)
/* This function is a wrapper for the primitive NH hash functions. It takes
 * as argument "hc" the current hash context and a buffer which must be a
 * multiple of L1_PAD_BOUNDARY. The key passed to nh_aux is offset
 * appropriately according to how much message has been hashed already.
 */
{
    UINT8 *ਕੁੰਜੀ;

    ਕੁੰਜੀ = hc->nh_ਕੁੰਜੀ + hc->ਬਾਈਟਾਂ_hashed;
    nh_aux(ਕੁੰਜੀ, buf, hc->state, nbytes);
}

/* ---------------------------------------------------------------------- */

#ਜੇ (__LITTLE_ENDIAN__)
ਸਥਿਰ ਖਾਲੀ endian_convert(ਖਾਲੀ *buf, UWORD bpw, UINT32 ਅੰਕ_ਬਾਈਟਾਂ)
/* We endian convert the keys on little-endian computers to               */
/* compensate for the lack of big-endian memory reads during hashing.     */
{
    UWORD iters = ਅੰਕ_ਬਾਈਟਾਂ / bpw;
    ਜੇ (bpw == 4) {
        UINT32 *p = (UINT32 *)buf;
        ਕਰੋ {
            *p = ਲੱਦੋ_UINT32_REVERSED(p);
            p++;
        } ਜਦੋਂ (--iters);
    } ਨਹੀਂਤਾਂ ਜੇ (bpw == 8) {
        UINT32 *p = (UINT32 *)buf;
        UINT32 t;
        ਕਰੋ {
            t = ਲੱਦੋ_UINT32_REVERSED(p+1);
            p[1] = ਲੱਦੋ_UINT32_REVERSED(p);
            p[0] = t;
            p += 2;
        } ਜਦੋਂ (--iters);
    }
}
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ endian_convert_if_le(x,y,z) endian_convert((x),(y),(z))
#ਨਹੀਂਤਾਂ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ endian_convert_if_le(x,y,z) ਕਰੋ{}ਜਦੋਂ(0)  /* Do nothing */
#ਜੇ_ਅੰਤ

/* ---------------------------------------------------------------------- */

ਸਥਿਰ ਖਾਲੀ nh_reset(nh_ctx *hc)
/* Reset nh_ctx to ready for hashing of new data */
{
    hc->ਬਾਈਟਾਂ_hashed = 0;
    hc->ਅਗਲਾ_ਅੰਕੜੇ_ਖਾਲੀ_ਥਾਵਾਂ = 0;
    hc->state[0] = 0;
#ਜੇ (UMAC_OUTPUT_LEN >= 8)
    hc->state[1] = 0;
#ਜੇ_ਅੰਤ
#ਜੇ (UMAC_OUTPUT_LEN >= 12)
    hc->state[2] = 0;
#ਜੇ_ਅੰਤ
#ਜੇ (UMAC_OUTPUT_LEN == 16)
    hc->state[3] = 0;
#ਜੇ_ਅੰਤ

}

/* ---------------------------------------------------------------------- */

ਸਥਿਰ ਖਾਲੀ nh_init(nh_ctx *hc, aes_int_ਕੁੰਜੀ prf_ਕੁੰਜੀ)
/* Generate nh_key, endian convert and reset to be ready for hashing.   */
{
    kdf(hc->nh_ਕੁੰਜੀ, prf_ਕੁੰਜੀ, 1, ਆਕਾਰ(hc->nh_ਕੁੰਜੀ));
    endian_convert_if_le(hc->nh_ਕੁੰਜੀ, 4, ਆਕਾਰ(hc->nh_ਕੁੰਜੀ));
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

ਸਥਿਰ ਖਾਲੀ nh_update(nh_ctx *hc, ਅਚਲ UINT8 *buf, UINT32 nbytes)
/* Incorporate nbytes of data into a nh_ctx, buffer whatever is not an    */
/* even multiple of HASH_BUF_BYTES.                                       */
{
    UINT32 i,j;

    j = hc->ਅਗਲਾ_ਅੰਕੜੇ_ਖਾਲੀ_ਥਾਵਾਂ;
    ਜੇ ((j + nbytes) >= HASH_BUF_ਬਾਈਟਾਂ) {
        ਜੇ (j) {
            i = HASH_BUF_ਬਾਈਟਾਂ - j;
            ਸਮ੍ਰਿਤੀ_ਨਕਲ(hc->ਅੰਕੜੇ+j, buf, i);
            nh_transform(hc,hc->ਅੰਕੜੇ,HASH_BUF_ਬਾਈਟਾਂ);
            nbytes -= i;
            buf += i;
            hc->ਬਾਈਟਾਂ_hashed += HASH_BUF_ਬਾਈਟਾਂ;
        }
        ਜੇ (nbytes >= HASH_BUF_ਬਾਈਟਾਂ) {
            i = nbytes & ~(HASH_BUF_ਬਾਈਟਾਂ - 1);
            nh_transform(hc, buf, i);
            nbytes -= i;
            buf += i;
            hc->ਬਾਈਟਾਂ_hashed += i;
        }
        j = 0;
    }
    ਸਮ੍ਰਿਤੀ_ਨਕਲ(hc->ਅੰਕੜੇ + j, buf, nbytes);
    hc->ਅਗਲਾ_ਅੰਕੜੇ_ਖਾਲੀ_ਥਾਵਾਂ = j + nbytes;
}

/* ---------------------------------------------------------------------- */

ਸਥਿਰ ਖਾਲੀ zero_pad(UINT8 *p, ਪੂਰਨ nbytes)
{
/* Write "nbytes" of zeroes, beginning at "p" */
    ਜੇ (nbytes >= (ਪੂਰਨ)ਆਕਾਰ(UWORD)) {
        ਜਦੋਂ ((ptrdiff_t)p % ਆਕਾਰ(UWORD)) {
            *p = 0;
            nbytes--;
            p++;
        }
        ਜਦੋਂ (nbytes >= (ਪੂਰਨ)ਆਕਾਰ(UWORD)) {
            *(UWORD *)p = 0;
            nbytes -= ਆਕਾਰ(UWORD);
            p += ਆਕਾਰ(UWORD);
        }
    }
    ਜਦੋਂ (nbytes) {
        *p = 0;
        nbytes--;
        p++;
    }
}

/* ---------------------------------------------------------------------- */

ਸਥਿਰ ਖਾਲੀ nh_final(nh_ctx *hc, UINT8 *ਨਤੀਜਾ)
/* After passing some number of data buffers to nh_update() for integration
 * into an NH context, nh_final is called to produce a hash result. If any
 * bytes are in the buffer hc->data, incorporate them into the
 * NH context. Finally, add into the NH accumulation "state" the total number
 * of bits hashed. The resulting numbers are written to the buffer "result".
 * If nh_update was never called, L1_PAD_BOUNDARY zeroes are incorporated.
 */
{
    ਪੂਰਨ nh_len, nbits;

    ਜੇ (hc->ਅਗਲਾ_ਅੰਕੜੇ_ਖਾਲੀ_ਥਾਵਾਂ != 0) {
        nh_len = ((hc->ਅਗਲਾ_ਅੰਕੜੇ_ਖਾਲੀ_ਥਾਵਾਂ + (L1_PAD_BOUNDARY - 1)) &
                                                ~(L1_PAD_BOUNDARY - 1));
        zero_pad(hc->ਅੰਕੜੇ + hc->ਅਗਲਾ_ਅੰਕੜੇ_ਖਾਲੀ_ਥਾਵਾਂ,
                                          nh_len - hc->ਅਗਲਾ_ਅੰਕੜੇ_ਖਾਲੀ_ਥਾਵਾਂ);
        nh_transform(hc, hc->ਅੰਕੜੇ, nh_len);
        hc->ਬਾਈਟਾਂ_hashed += hc->ਅਗਲਾ_ਅੰਕੜੇ_ਖਾਲੀ_ਥਾਵਾਂ;
    } ਨਹੀਂਤਾਂ ਜੇ (hc->ਬਾਈਟਾਂ_hashed == 0) {
	nh_len = L1_PAD_BOUNDARY;
        zero_pad(hc->ਅੰਕੜੇ, L1_PAD_BOUNDARY);
        nh_transform(hc, hc->ਅੰਕੜੇ, nh_len);
    }

    nbits = (hc->ਬਾਈਟਾਂ_hashed << 3);
    ((UINT64 *)ਨਤੀਜਾ)[0] = ((UINT64 *)hc->state)[0] + nbits;
#ਜੇ (UMAC_OUTPUT_LEN >= 8)
    ((UINT64 *)ਨਤੀਜਾ)[1] = ((UINT64 *)hc->state)[1] + nbits;
#ਜੇ_ਅੰਤ
#ਜੇ (UMAC_OUTPUT_LEN >= 12)
    ((UINT64 *)ਨਤੀਜਾ)[2] = ((UINT64 *)hc->state)[2] + nbits;
#ਜੇ_ਅੰਤ
#ਜੇ (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)ਨਤੀਜਾ)[3] = ((UINT64 *)hc->state)[3] + nbits;
#ਜੇ_ਅੰਤ
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

ਸਥਿਰ ਖਾਲੀ nh(nh_ctx *hc, ਅਚਲ UINT8 *buf, UINT32 padded_len,
               UINT32 unpadded_len, UINT8 *ਨਤੀਜਾ)
/* All-in-one nh_update() and nh_final() equivalent.
 * Assumes that padded_len is divisible by L1_PAD_BOUNDARY and result is
 * well aligned
 */
{
    UINT32 nbits;

    /* Initialize the hash state */
    nbits = (unpadded_len << 3);

    ((UINT64 *)ਨਤੀਜਾ)[0] = nbits;
#ਜੇ (UMAC_OUTPUT_LEN >= 8)
    ((UINT64 *)ਨਤੀਜਾ)[1] = nbits;
#ਜੇ_ਅੰਤ
#ਜੇ (UMAC_OUTPUT_LEN >= 12)
    ((UINT64 *)ਨਤੀਜਾ)[2] = nbits;
#ਜੇ_ਅੰਤ
#ਜੇ (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)ਨਤੀਜਾ)[3] = nbits;
#ਜੇ_ਅੰਤ

    nh_aux(hc->nh_ਕੁੰਜੀ, buf, ਨਤੀਜਾ, padded_len);
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
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ p36    ((UINT64)0x0000000FFFFFFFFBull)              /* 2^36 -  5 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ p64    ((UINT64)0xFFFFFFFFFFFFFFC5ull)              /* 2^64 - 59 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ m36    ((UINT64)0x0000000FFFFFFFFFull)  /* The low 36 of 64 bits */


/* ---------------------------------------------------------------------- */

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ uhash_ctx {
    nh_ctx hash;                          /* Hash context for L1 NH hash  */
    UINT64 poly_ਕੁੰਜੀ_8[STREAMS];           /* p64 poly keys                */
    UINT64 poly_accum[STREAMS];           /* poly hash result             */
    UINT64 ip_ਕੁੰਜੀਆਂ[STREAMS*4];            /* Inner-product keys           */
    UINT32 ip_trans[STREAMS];             /* Inner-product translation    */
    UINT32 ਸੁਨੇਹਾ_len;                       /* Total length of data passed  */
                                          /* to uhash */
} uhash_ctx;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ uhash_ctx *uhash_ctx_t;

/* ---------------------------------------------------------------------- */


/* The polynomial hashes use Horner's rule to evaluate a polynomial one
 * word at a time. As described in the specification, poly32 and poly64
 * require keys from special domains. The following implementations exploit
 * the special domains to avoid overflow. The results are not guaranteed to
 * be within Z_p32 and Z_p64, but the Inner-Product hash implementation
 * patches any errant values.
 */

ਸਥਿਰ UINT64 poly64(UINT64 cur, UINT64 ਕੁੰਜੀ, UINT64 ਅੰਕੜੇ)
{
    UINT32 ਕੁੰਜੀ_hi = (UINT32)(ਕੁੰਜੀ >> 32),
           ਕੁੰਜੀ_lo = (UINT32)ਕੁੰਜੀ,
           cur_hi = (UINT32)(cur >> 32),
           cur_lo = (UINT32)cur,
           x_lo,
           x_hi;
    UINT64 X,T,res;

    X =  MUL64(ਕੁੰਜੀ_hi, cur_lo) + MUL64(cur_hi, ਕੁੰਜੀ_lo);
    x_lo = (UINT32)X;
    x_hi = (UINT32)(X >> 32);

    res = (MUL64(ਕੁੰਜੀ_hi, cur_hi) + x_hi) * 59 + MUL64(ਕੁੰਜੀ_lo, cur_lo);

    T = ((UINT64)x_lo << 32);
    res += T;
    ਜੇ (res < T)
        res += 59;

    res += ਅੰਕੜੇ;
    ਜੇ (res < ਅੰਕੜੇ)
        res += 59;

    ਵਾਪਸ res;
}


/* Although UMAC is specified to use a ramped polynomial hash scheme, this
 * implementation does not handle all ramp levels. Because we don't handle
 * the ramp up to p128 modulus in this implementation, we are limited to
 * 2^14 poly_hash() invocations per stream (for a total capacity of 2^24
 * bytes input to UMAC per tag, ie. 16MB).
 */
ਸਥਿਰ ਖਾਲੀ poly_hash(uhash_ctx_t hc, UINT32 ਅੰਕੜੇ_ਵਿੱਚ[])
{
    ਪੂਰਨ i;
    UINT64 *ਅੰਕੜੇ=(UINT64*)ਅੰਕੜੇ_ਵਿੱਚ;

    ਲਈ (i = 0; i < STREAMS; i++) {
        ਜੇ ((UINT32)(ਅੰਕੜੇ[i] >> 32) == 0xfffffffful) {
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_ਕੁੰਜੀ_8[i], p64 - 1);
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_ਕੁੰਜੀ_8[i], (ਅੰਕੜੇ[i] - 59));
        } ਨਹੀਂਤਾਂ {
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_ਕੁੰਜੀ_8[i], ਅੰਕੜੇ[i]);
        }
    }
}


/* ---------------------------------------------------------------------- */


/* The final step in UHASH is an inner-product hash. The poly hash
 * produces a result not necessarily WORD_LEN bytes long. The inner-
 * product hash breaks the polyhash output into 16-bit chunks and
 * multiplies each with a 36 bit key.
 */

ਸਥਿਰ UINT64 ip_aux(UINT64 t, UINT64 *ipkp, UINT64 ਅੰਕੜੇ)
{
    t = t + ipkp[0] * (UINT64)(UINT16)(ਅੰਕੜੇ >> 48);
    t = t + ipkp[1] * (UINT64)(UINT16)(ਅੰਕੜੇ >> 32);
    t = t + ipkp[2] * (UINT64)(UINT16)(ਅੰਕੜੇ >> 16);
    t = t + ipkp[3] * (UINT64)(UINT16)(ਅੰਕੜੇ);

    ਵਾਪਸ t;
}

ਸਥਿਰ UINT32 ip_reduce_p36(UINT64 t)
{
/* Divisionless modular reduction */
    UINT64 ret;

    ret = (t & m36) + 5 * (t >> 36);
    ਜੇ (ret >= p36)
        ret -= p36;

    /* return least significant 32 bits */
    ਵਾਪਸ (UINT32)(ret);
}


/* If the data being hashed by UHASH is no longer than L1_KEY_LEN, then
 * the polyhash stage is skipped and ip_short is applied directly to the
 * NH output.
 */
ਸਥਿਰ ਖਾਲੀ ip_short(uhash_ctx_t ahc, UINT8 *nh_res, u_char *res)
{
    UINT64 t;
    UINT64 *nhp = (UINT64 *)nh_res;

    t  = ip_aux(0,ahc->ip_ਕੁੰਜੀਆਂ, nhp[0]);
    STORE_UINT32_BIG((UINT32 *)res+0, ip_reduce_p36(t) ^ ahc->ip_trans[0]);
#ਜੇ (UMAC_OUTPUT_LEN >= 8)
    t  = ip_aux(0,ahc->ip_ਕੁੰਜੀਆਂ+4, nhp[1]);
    STORE_UINT32_BIG((UINT32 *)res+1, ip_reduce_p36(t) ^ ahc->ip_trans[1]);
#ਜੇ_ਅੰਤ
#ਜੇ (UMAC_OUTPUT_LEN >= 12)
    t  = ip_aux(0,ahc->ip_ਕੁੰਜੀਆਂ+8, nhp[2]);
    STORE_UINT32_BIG((UINT32 *)res+2, ip_reduce_p36(t) ^ ahc->ip_trans[2]);
#ਜੇ_ਅੰਤ
#ਜੇ (UMAC_OUTPUT_LEN == 16)
    t  = ip_aux(0,ahc->ip_ਕੁੰਜੀਆਂ+12, nhp[3]);
    STORE_UINT32_BIG((UINT32 *)res+3, ip_reduce_p36(t) ^ ahc->ip_trans[3]);
#ਜੇ_ਅੰਤ
}

/* If the data being hashed by UHASH is longer than L1_KEY_LEN, then
 * the polyhash stage is not skipped and ip_long is applied to the
 * polyhash output.
 */
ਸਥਿਰ ਖਾਲੀ ip_long(uhash_ctx_t ahc, u_char *res)
{
    ਪੂਰਨ i;
    UINT64 t;

    ਲਈ (i = 0; i < STREAMS; i++) {
        /* fix polyhash output not in Z_p64 */
        ਜੇ (ahc->poly_accum[i] >= p64)
            ahc->poly_accum[i] -= p64;
        t  = ip_aux(0,ahc->ip_ਕੁੰਜੀਆਂ+(i*4), ahc->poly_accum[i]);
        STORE_UINT32_BIG((UINT32 *)res+i,
                         ip_reduce_p36(t) ^ ahc->ip_trans[i]);
    }
}


/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */

/* Reset uhash context for next hash session */
ਸਥਿਰ ਪੂਰਨ uhash_reset(uhash_ctx_t pc)
{
    nh_reset(&pc->hash);
    pc->ਸੁਨੇਹਾ_len = 0;
    pc->poly_accum[0] = 1;
#ਜੇ (UMAC_OUTPUT_LEN >= 8)
    pc->poly_accum[1] = 1;
#ਜੇ_ਅੰਤ
#ਜੇ (UMAC_OUTPUT_LEN >= 12)
    pc->poly_accum[2] = 1;
#ਜੇ_ਅੰਤ
#ਜੇ (UMAC_OUTPUT_LEN == 16)
    pc->poly_accum[3] = 1;
#ਜੇ_ਅੰਤ
    ਵਾਪਸ 1;
}

/* ---------------------------------------------------------------------- */

/* Given a pointer to the internal key needed by kdf() and a uhash context,
 * initialize the NH context and generate keys needed for poly and inner-
 * product hashing. All keys are endian adjusted in memory so that native
 * loads cause correct keys to be in registers during calculation.
 */
ਸਥਿਰ ਖਾਲੀ uhash_init(uhash_ctx_t ahc, aes_int_ਕੁੰਜੀ prf_ਕੁੰਜੀ)
{
    ਪੂਰਨ i;
    UINT8 buf[(8*STREAMS+4)*ਆਕਾਰ(UINT64)];

    /* Zero the entire uhash context */
    memset(ahc, 0, ਆਕਾਰ(uhash_ctx));

    /* Initialize the L1 hash */
    nh_init(&ahc->hash, prf_ਕੁੰਜੀ);

    /* Setup L2 hash variables */
    kdf(buf, prf_ਕੁੰਜੀ, 2, ਆਕਾਰ(buf));    /* Fill buffer with index 1 key */
    ਲਈ (i = 0; i < STREAMS; i++) {
        /* Fill keys from the buffer, skipping bytes in the buffer not
         * used by this implementation. Endian reverse the keys if on a
         * little-endian computer.
         */
        ਸਮ੍ਰਿਤੀ_ਨਕਲ(ahc->poly_ਕੁੰਜੀ_8+i, buf+24*i, 8);
        endian_convert_if_le(ahc->poly_ਕੁੰਜੀ_8+i, 8, 8);
        /* Mask the 64-bit keys to their special domain */
        ahc->poly_ਕੁੰਜੀ_8[i] &= ((UINT64)0x01ffffffu << 32) + 0x01ffffffu;
        ahc->poly_accum[i] = 1;  /* Our polyhash prepends a non-zero word */
    }

    /* Setup L3-1 hash variables */
    kdf(buf, prf_ਕੁੰਜੀ, 3, ਆਕਾਰ(buf)); /* Fill buffer with index 2 key */
    ਲਈ (i = 0; i < STREAMS; i++)
          ਸਮ੍ਰਿਤੀ_ਨਕਲ(ahc->ip_ਕੁੰਜੀਆਂ+4*i, buf+(8*i+4)*ਆਕਾਰ(UINT64),
                                                 4*ਆਕਾਰ(UINT64));
    endian_convert_if_le(ahc->ip_ਕੁੰਜੀਆਂ, ਆਕਾਰ(UINT64),
                                                  ਆਕਾਰ(ahc->ip_ਕੁੰਜੀਆਂ));
    ਲਈ (i = 0; i < STREAMS*4; i++)
        ahc->ip_ਕੁੰਜੀਆਂ[i] %= p36;  /* Bring into Z_p36 */

    /* Setup L3-2 hash variables    */
    /* Fill buffer with index 4 key */
    kdf(ahc->ip_trans, prf_ਕੁੰਜੀ, 4, STREAMS * ਆਕਾਰ(UINT32));
    endian_convert_if_le(ahc->ip_trans, ਆਕਾਰ(UINT32),
                         STREAMS * ਆਕਾਰ(UINT32));
    explicit_bzero(buf, ਆਕਾਰ(buf));
}

/* ---------------------------------------------------------------------- */

#ਜੇ 0
ਸਥਿਰ uhash_ctx_t uhash_alloc(u_char ਕੁੰਜੀ[])
{
/* Allocate memory and force to a 16-byte boundary. */
    uhash_ctx_t ctx;
    u_char ਬਾਈਟਾਂ_ਮੰਜ਼ਿਲ_ਜੋੜੋ;
    aes_int_ਕੁੰਜੀ prf_ਕੁੰਜੀ;

    ctx = (uhash_ctx_t)ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਆਕਾਰ(uhash_ctx)+ALLOC_BOUNDARY);
    ਜੇ (ctx) {
        ਜੇ (ALLOC_BOUNDARY) {
            ਬਾਈਟਾਂ_ਮੰਜ਼ਿਲ_ਜੋੜੋ = ALLOC_BOUNDARY -
                              ((ptrdiff_t)ctx & (ALLOC_BOUNDARY -1));
            ctx = (uhash_ctx_t)((u_char *)ctx + ਬਾਈਟਾਂ_ਮੰਜ਼ਿਲ_ਜੋੜੋ);
            *((u_char *)ctx - 1) = ਬਾਈਟਾਂ_ਮੰਜ਼ਿਲ_ਜੋੜੋ;
        }
        aes_ਕੁੰਜੀ_ਤਿਆਰੀ(ਕੁੰਜੀ,prf_ਕੁੰਜੀ);
        uhash_init(ctx, prf_ਕੁੰਜੀ);
    }
    ਵਾਪਸ (ctx);
}
#ਜੇ_ਅੰਤ

/* ---------------------------------------------------------------------- */

#ਜੇ 0
ਸਥਿਰ ਪੂਰਨ uhash_free(uhash_ctx_t ctx)
{
/* Free memory allocated by uhash_alloc */
    u_char ਬਾਈਟਾਂ_ਮੰਜ਼ਿਲ_sub;

    ਜੇ (ctx) {
        ਜੇ (ALLOC_BOUNDARY) {
            ਬਾਈਟਾਂ_ਮੰਜ਼ਿਲ_sub = *((u_char *)ctx - 1);
            ctx = (uhash_ctx_t)((u_char *)ctx - ਬਾਈਟਾਂ_ਮੰਜ਼ਿਲ_sub);
        }
        ਮੁਕਤ(ctx);
    }
    ਵਾਪਸ (1);
}
#ਜੇ_ਅੰਤ
/* ---------------------------------------------------------------------- */

ਸਥਿਰ ਪੂਰਨ uhash_update(uhash_ctx_t ctx, ਅਚਲ u_char *ਨਿਵੇਸ਼, ਲੰਮਾ len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and
 * hash each one with NH, calling the polyhash on each NH output.
 */
{
    UWORD ਬਾਈਟਾਂ_hashed, ਬਾਈਟਾਂ_ਬਚਿਆ;
    UINT64 ਨਤੀਜਾ_buf[STREAMS];
    UINT8 *nh_ਨਤੀਜਾ = (UINT8 *)&ਨਤੀਜਾ_buf;

    ਜੇ (ctx->ਸੁਨੇਹਾ_len + len <= L1_ਕੁੰਜੀ_LEN) {
        nh_update(&ctx->hash, (ਅਚਲ UINT8 *)ਨਿਵੇਸ਼, len);
        ctx->ਸੁਨੇਹਾ_len += len;
    } ਨਹੀਂਤਾਂ {

         ਬਾਈਟਾਂ_hashed = ctx->ਸੁਨੇਹਾ_len % L1_ਕੁੰਜੀ_LEN;
         ਜੇ (ctx->ਸੁਨੇਹਾ_len == L1_ਕੁੰਜੀ_LEN)
             ਬਾਈਟਾਂ_hashed = L1_ਕੁੰਜੀ_LEN;

         ਜੇ (ਬਾਈਟਾਂ_hashed + len >= L1_ਕੁੰਜੀ_LEN) {

             /* If some bytes have been passed to the hash function      */
             /* then we want to pass at most (L1_KEY_LEN - bytes_hashed) */
             /* bytes to complete the current nh_block.                  */
             ਜੇ (ਬਾਈਟਾਂ_hashed) {
                 ਬਾਈਟਾਂ_ਬਚਿਆ = (L1_ਕੁੰਜੀ_LEN - ਬਾਈਟਾਂ_hashed);
                 nh_update(&ctx->hash, (ਅਚਲ UINT8 *)ਨਿਵੇਸ਼, ਬਾਈਟਾਂ_ਬਚਿਆ);
                 nh_final(&ctx->hash, nh_ਨਤੀਜਾ);
                 ctx->ਸੁਨੇਹਾ_len += ਬਾਈਟਾਂ_ਬਚਿਆ;
                 poly_hash(ctx,(UINT32 *)nh_ਨਤੀਜਾ);
                 len -= ਬਾਈਟਾਂ_ਬਚਿਆ;
                 ਨਿਵੇਸ਼ += ਬਾਈਟਾਂ_ਬਚਿਆ;
             }

             /* Hash directly from input stream if enough bytes */
             ਜਦੋਂ (len >= L1_ਕੁੰਜੀ_LEN) {
                 nh(&ctx->hash, (ਅਚਲ UINT8 *)ਨਿਵੇਸ਼, L1_ਕੁੰਜੀ_LEN,
                                   L1_ਕੁੰਜੀ_LEN, nh_ਨਤੀਜਾ);
                 ctx->ਸੁਨੇਹਾ_len += L1_ਕੁੰਜੀ_LEN;
                 len -= L1_ਕੁੰਜੀ_LEN;
                 ਨਿਵੇਸ਼ += L1_ਕੁੰਜੀ_LEN;
                 poly_hash(ctx,(UINT32 *)nh_ਨਤੀਜਾ);
             }
         }

         /* pass remaining < L1_KEY_LEN bytes of input data to NH */
         ਜੇ (len > 0 && (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ)len <= UINT32_MAX) {
             nh_update(&ctx->hash, (ਅਚਲ UINT8 *)ਨਿਵੇਸ਼, len);
             ctx->ਸੁਨੇਹਾ_len += len;
         }
     }

    ਵਾਪਸ (1);
}

/* ---------------------------------------------------------------------- */

ਸਥਿਰ ਪੂਰਨ uhash_final(uhash_ctx_t ctx, u_char *res)
/* Incorporate any pending data, pad, and generate tag */
{
    UINT64 ਨਤੀਜਾ_buf[STREAMS];
    UINT8 *nh_ਨਤੀਜਾ = (UINT8 *)&ਨਤੀਜਾ_buf;

    ਜੇ (ctx->ਸੁਨੇਹਾ_len > L1_ਕੁੰਜੀ_LEN) {
        ਜੇ (ctx->ਸੁਨੇਹਾ_len % L1_ਕੁੰਜੀ_LEN) {
            nh_final(&ctx->hash, nh_ਨਤੀਜਾ);
            poly_hash(ctx,(UINT32 *)nh_ਨਤੀਜਾ);
        }
        ip_long(ctx, res);
    } ਨਹੀਂਤਾਂ {
        nh_final(&ctx->hash, nh_ਨਤੀਜਾ);
        ip_short(ctx,nh_ਨਤੀਜਾ, res);
    }
    uhash_reset(ctx);
    ਵਾਪਸ (1);
}

/* ---------------------------------------------------------------------- */

#ਜੇ 0
ਸਥਿਰ ਪੂਰਨ uhash(uhash_ctx_t ahc, u_char *ਸੁਨੇਹਾ, ਲੰਮਾ len, u_char *res)
/* assumes that msg is in a writable buffer of length divisible by */
/* L1_PAD_BOUNDARY. Bytes beyond msg[len] may be zeroed.           */
{
    UINT8 nh_ਨਤੀਜਾ[STREAMS*ਆਕਾਰ(UINT64)];
    UINT32 nh_len;
    ਪੂਰਨ extra_zeroes_needed;

    /* If the message to be hashed is no longer than L1_HASH_LEN, we skip
     * the polyhash.
     */
    ਜੇ (len <= L1_ਕੁੰਜੀ_LEN) {
	ਜੇ (len == 0)                  /* If zero length messages will not */
		nh_len = L1_PAD_BOUNDARY;  /* be seen, comment out this case   */
	ਨਹੀਂਤਾਂ
		nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
        extra_zeroes_needed = nh_len - len;
        zero_pad((UINT8 *)ਸੁਨੇਹਾ + len, extra_zeroes_needed);
        nh(&ahc->hash, (UINT8 *)ਸੁਨੇਹਾ, nh_len, len, nh_ਨਤੀਜਾ);
        ip_short(ahc,nh_ਨਤੀਜਾ, res);
    } ਨਹੀਂਤਾਂ {
        /* Otherwise, we hash each L1_KEY_LEN chunk with NH, passing the NH
         * output to poly_hash().
         */
        ਕਰੋ {
            nh(&ahc->hash, (UINT8 *)ਸੁਨੇਹਾ, L1_ਕੁੰਜੀ_LEN, L1_ਕੁੰਜੀ_LEN, nh_ਨਤੀਜਾ);
            poly_hash(ahc,(UINT32 *)nh_ਨਤੀਜਾ);
            len -= L1_ਕੁੰਜੀ_LEN;
            ਸੁਨੇਹਾ += L1_ਕੁੰਜੀ_LEN;
        } ਜਦੋਂ (len >= L1_ਕੁੰਜੀ_LEN);
        ਜੇ (len) {
            nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
            extra_zeroes_needed = nh_len - len;
            zero_pad((UINT8 *)ਸੁਨੇਹਾ + len, extra_zeroes_needed);
            nh(&ahc->hash, (UINT8 *)ਸੁਨੇਹਾ, nh_len, len, nh_ਨਤੀਜਾ);
            poly_hash(ahc,(UINT32 *)nh_ਨਤੀਜਾ);
        }

        ip_long(ahc, res);
    }

    uhash_reset(ahc);
    ਵਾਪਸ 1;
}
#ਜੇ_ਅੰਤ

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
ਬਣਤਰ umac_ctx {
    uhash_ctx hash;          /* Hash function for message compression    */
    pdf_ctx pdf;             /* PDF for hashed output                    */
    ਖਾਲੀ *free_ptr;          /* Address to free this struct via          */
} umac_ctx;

/* ---------------------------------------------------------------------- */

#ਜੇ 0
ਪੂਰਨ umac_reset(ਬਣਤਰ umac_ctx *ctx)
/* Reset the hash function to begin a new authentication.        */
{
    uhash_reset(&ctx->hash);
    ਵਾਪਸ (1);
}
#ਜੇ_ਅੰਤ

/* ---------------------------------------------------------------------- */

ਪੂਰਨ umac_delete(ਬਣਤਰ umac_ctx *ctx)
/* Deallocate the ctx structure */
{
    ਜੇ (ctx) {
        ਜੇ (ALLOC_BOUNDARY)
            ctx = (ਬਣਤਰ umac_ctx *)ctx->free_ptr;
        freezero(ctx, ਆਕਾਰ(*ctx) + ALLOC_BOUNDARY);
    }
    ਵਾਪਸ (1);
}

/* ---------------------------------------------------------------------- */

ਬਣਤਰ umac_ctx *umac_new(ਅਚਲ u_char ਕੁੰਜੀ[])
/* Dynamically allocate a umac_ctx struct, initialize variables,
 * generate subkeys from key. Align to 16-byte boundary.
 */
{
    ਬਣਤਰ umac_ctx *ctx, *octx;
    ਮਾਪ_t ਬਾਈਟਾਂ_ਮੰਜ਼ਿਲ_ਜੋੜੋ;
    aes_int_ਕੁੰਜੀ prf_ਕੁੰਜੀ;

    octx = ctx = xcalloc(1, ਆਕਾਰ(*ctx) + ALLOC_BOUNDARY);
    ਜੇ (ctx) {
        ਜੇ (ALLOC_BOUNDARY) {
            ਬਾਈਟਾਂ_ਮੰਜ਼ਿਲ_ਜੋੜੋ = ALLOC_BOUNDARY -
                              ((ptrdiff_t)ctx & (ALLOC_BOUNDARY - 1));
            ctx = (ਬਣਤਰ umac_ctx *)((u_char *)ctx + ਬਾਈਟਾਂ_ਮੰਜ਼ਿਲ_ਜੋੜੋ);
        }
        ctx->free_ptr = octx;
        aes_ਕੁੰਜੀ_ਤਿਆਰੀ(ਕੁੰਜੀ, prf_ਕੁੰਜੀ);
        pdf_init(&ctx->pdf, prf_ਕੁੰਜੀ);
        uhash_init(&ctx->hash, prf_ਕੁੰਜੀ);
        explicit_bzero(prf_ਕੁੰਜੀ, ਆਕਾਰ(prf_ਕੁੰਜੀ));
    }

    ਵਾਪਸ (ctx);
}

/* ---------------------------------------------------------------------- */

ਪੂਰਨ umac_final(ਬਣਤਰ umac_ctx *ctx, u_char ਟੈਗ[], ਅਚਲ u_char nonce[8])
/* Incorporate any pending data, pad, and generate tag */
{
    uhash_final(&ctx->hash, (u_char *)ਟੈਗ);
    pdf_gen_xor(&ctx->pdf, (ਅਚਲ UINT8 *)nonce, (UINT8 *)ਟੈਗ);

    ਵਾਪਸ (1);
}

/* ---------------------------------------------------------------------- */

ਪੂਰਨ umac_update(ਬਣਤਰ umac_ctx *ctx, ਅਚਲ u_char *ਨਿਵੇਸ਼, ਲੰਮਾ len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and   */
/* hash each one, calling the PDF on the hashed output whenever the hash- */
/* output buffer is full.                                                 */
{
    uhash_update(&ctx->hash, ਨਿਵੇਸ਼, len);
    ਵਾਪਸ (1);
}

/* ---------------------------------------------------------------------- */

#ਜੇ 0
ਪੂਰਨ umac(ਬਣਤਰ umac_ctx *ctx, u_char *ਨਿਵੇਸ਼,
         ਲੰਮਾ len, u_char ਟੈਗ[],
         u_char nonce[8])
/* All-in-one version simply calls umac_update() and umac_final().        */
{
    uhash(&ctx->hash, ਨਿਵੇਸ਼, len, (u_char *)ਟੈਗ);
    pdf_gen_xor(&ctx->pdf, (UINT8 *)nonce, (UINT8 *)ਟੈਗ);

    ਵਾਪਸ (1);
}
#ਜੇ_ਅੰਤ

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- End UMAC Section ----------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
