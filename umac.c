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

#اگر_تعریف_نشده UMAC_OUTPUT_LEN
#تعریف_کن UMAC_OUTPUT_LEN     8  /* Allowable: 4, 8, 12, 16                  */
#پایان_اگر

#إذا UMAC_OUTPUT_LEN != 4 && UMAC_OUTPUT_LEN != 8 && \
    UMAC_OUTPUT_LEN != 12 && UMAC_OUTPUT_LEN != 16
# error UMAC_OUTPUT_LEN must be defined مقصد 4, 8, 12 or 16
#پایان_اگر

/* #define FORCE_C_ONLY        1  ANSI C and 64-bit integers req'd        */
/* #define AES_IMPLEMENTAION   1  1 = OpenSSL, 2 = Barreto, 3 = Gladman   */
/* #define SSE2                0  Is SSE2 is available?                   */
/* #define RUN_TESTS           0  Run basic correctness/speed tests       */
/* #define UMAC_AE_SUPPORT     0  Enable authenticated encryption         */

/* ---------------------------------------------------------------------- */
/* -- Global Includes --------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <endian.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <stddef.h>

#ضمن "xmalloc.h"
#ضمن "umac.h"
#ضمن "misc.h"

/* ---------------------------------------------------------------------- */
/* --- Primitive Data Types ---                                           */
/* ---------------------------------------------------------------------- */

/* The following assumptions may need change on your system */
تعريفنوع uint8_t	UINT8;  /* 1 byte   */
تعريفنوع uint16_t	UINT16; /* 2 byte   */
تعريفنوع uint32_t	UINT32; /* 4 byte   */
تعريفنوع uint64_t	UINT64; /* 8 bytes  */
تعريفنوع بیعلامت صحيح	UWORD;  /*ثبات*/

/* ---------------------------------------------------------------------- */
/* --- Constants -------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#تعریف_کن UMAC_کلید_LEN           16  /* UMAC takes 16 bytes of external key */

/* Message "words" are read from memory in an endian-specific manner.     */
/* For this implementation to behave correctly, __LITTLE_ENDIAN__ must    */
/* be set true if the host computer is little-endian.                     */

#إذا BYTE_ORDER == LITTLE_ENDIAN
#تعریف_کن __LITTLE_ENDIAN__ 1
#وإلا
#تعریف_کن __LITTLE_ENDIAN__ 0
#پایان_اگر

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

#تعریف_کن MUL64(a,b) ((UINT64)((UINT64)(UINT32)(a) * (UINT64)(UINT32)(b)))

/* ---------------------------------------------------------------------- */
/* --- Endian Conversion --- Forcing assembly on some platforms           */
/* ---------------------------------------------------------------------- */

#إذا (__LITTLE_ENDIAN__)
#تعریف_کن بارگیری_UINT32_REVERSED(p)		get_u32(p)
#تعریف_کن STORE_UINT32_REVERSED(p,v)	put_u32(p,v)
#وإلا
#تعریف_کن بارگیری_UINT32_REVERSED(p)		get_u32_le(p)
#تعریف_کن STORE_UINT32_REVERSED(p,v)	put_u32_le(p,v)
#پایان_اگر

#تعریف_کن بارگیری_UINT32_LITTLE(p)		(get_u32_le(p))
#تعریف_کن STORE_UINT32_BIG(p,v)		put_u32(p, v)

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin KDF & PDF Section ---------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* UMAC uses AES with 16 byte block and key lengths */
#تعریف_کن AES_بلوک_LEN  16

/* OpenSSL's AES */
#اگر_تعریف_شده WITH_OPENSSL
#ضمن "openbsd-compat/openssl-compat.h"
#اگر_تعریف_نشده USE_BUILTIN_RIJNDAEL
# include <openssl/aes.h>
#پایان_اگر
تعريفنوع AES_کلید aes_int_کلید[1];
#تعریف_کن aes_encryption(درون,بیرون,int_کلید)                  \
  AES_encrypt((u_char *)(درون),(u_char *)(بیرون),(AES_کلید *)int_کلید)
#تعریف_کن aes_کلید_راهاندازی(کلید,int_کلید)                      \
  AES_مجموعه_encrypt_کلید((ثابت u_char *)(کلید),UMAC_کلید_LEN*8,int_کلید)
#وإلا
#ضمن "rijndael.h"
#تعریف_کن AES_دورها ((UMAC_کلید_LEN / 4) + 6)
تعريفنوع UINT8 aes_int_کلید[AES_دورها+1][4][4];	/* AES internal */
#تعریف_کن aes_encryption(درون,بیرون,int_کلید) \
  rijndaelEncrypt((u32 *)(int_کلید), AES_دورها, (u8 *)(درون), (u8 *)(بیرون))
#تعریف_کن aes_کلید_راهاندازی(کلید,int_کلید) \
  rijndael_کلید_راهاندازی_Enc((u32 *)(int_کلید), (ثابت بیعلامت حرف *)(کلید), \
  UMAC_کلید_LEN*8)
#پایان_اگر

/* The user-supplied UMAC key is stretched using AES in a counter
 * mode to supply all random bits needed by UMAC. The kdf function takes
 * an AES internal key representation 'key' and writes a stream of
 * 'nbytes' bytes to the memory pointed at by 'bufp'. Each distinct
 * 'ndx' causes a distinct byte stream.
 */
ساكن فراغ kdf(فراغ *bufp, aes_int_کلید کلید, UINT8 ndx, صحيح nbytes)
{
    UINT8 درون_buf[AES_بلوک_LEN] = {0};
    UINT8 بیرون_buf[AES_بلوک_LEN];
    UINT8 *dst_buf = (UINT8 *)bufp;
    صحيح i;

    /* Setup the initial value */
    درون_buf[AES_بلوک_LEN-9] = ndx;
    درون_buf[AES_بلوک_LEN-1] = i = 1;

    طالما (nbytes >= AES_بلوک_LEN) {
        aes_encryption(درون_buf, بیرون_buf, کلید);
        کپی_حافظه(dst_buf,بیرون_buf,AES_بلوک_LEN);
        درون_buf[AES_بلوک_LEN-1] = ++i;
        nbytes -= AES_بلوک_LEN;
        dst_buf += AES_بلوک_LEN;
    }
    إذا (nbytes) {
        aes_encryption(درون_buf, بیرون_buf, کلید);
        کپی_حافظه(dst_buf,بیرون_buf,nbytes);
    }
    explicit_bzero(درون_buf, حجم(درون_buf));
    explicit_bzero(بیرون_buf, حجم(بیرون_buf));
}

/* The final UHASH result is XOR'd with the output of a pseudorandom
 * function. Here, we use AES to generate random output and
 * xor the appropriate bytes depending on the last bits of nonce.
 * This scheme is optimized for sequential, increasing big-endian nonces.
 */

تعريفنوع بنية {
    UINT8 cache[AES_بلوک_LEN];  /* Previous AES output is saved      */
    UINT8 nonce[AES_بلوک_LEN];  /* The AES input making above cache  */
    aes_int_کلید prf_کلید;         /* Expanded AES key for PDF          */
} pdf_ctx;

ساكن فراغ pdf_init(pdf_ctx *pc, aes_int_کلید prf_کلید)
{
    UINT8 buf[UMAC_کلید_LEN];

    kdf(buf, prf_کلید, 0, UMAC_کلید_LEN);
    aes_کلید_راهاندازی(buf, pc->prf_کلید);

    /* Initialize pdf and cache */
    memset(pc->nonce, 0, حجم(pc->nonce));
    aes_encryption(pc->nonce, pc->cache, pc->prf_کلید);
    explicit_bzero(buf, حجم(buf));
}

ساكن فراغ pdf_gen_xor(pdf_ctx *pc, ثابت UINT8 nonce[8],
    UINT8 buf[UMAC_OUTPUT_LEN])
{
    /* 'ndx' indicates that we'll be using the 0th or 1st eight bytes
     * of the AES output. If last time around we returned the ndx-1st
     * element, then we may have the result in the cache already.
     */

#إذا (UMAC_OUTPUT_LEN == 4)
#تعریف_کن کم_بیت_ماسک 3
#وإلاإذا (UMAC_OUTPUT_LEN == 8)
#تعریف_کن کم_بیت_ماسک 1
#وإلاإذا (UMAC_OUTPUT_LEN > 8)
#تعریف_کن کم_بیت_ماسک 0
#پایان_اگر
    اتحاد {
        UINT8 tmp_nonce_lo[4];
        UINT32 align;
    } t;
#إذا کم_بیت_ماسک != 0
    صحيح ndx = nonce[7] & کم_بیت_ماسک;
#پایان_اگر
    *(UINT32 *)t.tmp_nonce_lo = ((ثابت UINT32 *)nonce)[1];
    t.tmp_nonce_lo[3] &= ~کم_بیت_ماسک; /* zero last bit */

    إذا ( (((UINT32 *)t.tmp_nonce_lo)[0] != ((UINT32 *)pc->nonce)[1]) ||
         (((ثابت UINT32 *)nonce)[0] != ((UINT32 *)pc->nonce)[0]) )
    {
        ((UINT32 *)pc->nonce)[0] = ((ثابت UINT32 *)nonce)[0];
        ((UINT32 *)pc->nonce)[1] = ((UINT32 *)t.tmp_nonce_lo)[0];
        aes_encryption(pc->nonce, pc->cache, pc->prf_کلید);
    }

#إذا (UMAC_OUTPUT_LEN == 4)
    *((UINT32 *)buf) ^= ((UINT32 *)pc->cache)[ndx];
#وإلاإذا (UMAC_OUTPUT_LEN == 8)
    *((UINT64 *)buf) ^= ((UINT64 *)pc->cache)[ndx];
#وإلاإذا (UMAC_OUTPUT_LEN == 12)
    ((UINT64 *)buf)[0] ^= ((UINT64 *)pc->cache)[0];
    ((UINT32 *)buf)[2] ^= ((UINT32 *)pc->cache)[2];
#وإلاإذا (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)buf)[0] ^= ((UINT64 *)pc->cache)[0];
    ((UINT64 *)buf)[1] ^= ((UINT64 *)pc->cache)[1];
#پایان_اگر
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

#تعریف_کن STREAMS (UMAC_OUTPUT_LEN / 4) /* Number of times hash is applied  */
#تعریف_کن L1_کلید_LEN         1024     /* Internal key bytes                 */
#تعریف_کن L1_کلید_لغزش         16     /* Toeplitz key shift between streams */
#تعریف_کن L1_PAD_BOUNDARY      32     /* pad message to boundary multiple   */
#تعریف_کن ALLOC_BOUNDARY       16     /* Keep buffers aligned to this       */
#تعریف_کن HASH_BUF_بایتها       64     /* nh_aux_hb buffer multiple          */

تعريفنوع بنية {
    UINT8  nh_کلید [L1_کلید_LEN + L1_کلید_لغزش * (STREAMS - 1)]; /* NH Key */
    UINT8  داده   [HASH_BUF_بایتها];    /* Incoming data buffer           */
    صحيح بعدی_داده_خالی;    /* Bookkeeping variable for data buffer.     */
    صحيح بایتها_hashed;       /* Bytes (out of L1_KEY_LEN) incorporated.   */
    UINT64 state[STREAMS];               /* on-line state     */
} nh_ctx;


#إذا (UMAC_OUTPUT_LEN == 4)

ساكن فراغ nh_aux(فراغ *kp, ثابت فراغ *dp, فراغ *hp, UINT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and
* then stored via hp pointer. The length of the data pointed at by "dp",
* "dlen", is guaranteed to be divisible by L1_PAD_BOUNDARY (32).  Key
* is expected to be endian compensated in memory at key setup.
*/
{
    UINT64 h;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    ثابت UINT32 *d = (ثابت UINT32 *)dp;
    UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
    UINT32 k0,k1,k2,k3,k4,k5,k6,k7;

    h = *((UINT64 *)hp);
    افعل {
        d0 = بارگیری_UINT32_LITTLE(d+0); d1 = بارگیری_UINT32_LITTLE(d+1);
        d2 = بارگیری_UINT32_LITTLE(d+2); d3 = بارگیری_UINT32_LITTLE(d+3);
        d4 = بارگیری_UINT32_LITTLE(d+4); d5 = بارگیری_UINT32_LITTLE(d+5);
        d6 = بارگیری_UINT32_LITTLE(d+6); d7 = بارگیری_UINT32_LITTLE(d+7);
        k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
        k4 = *(k+4); k5 = *(k+5); k6 = *(k+6); k7 = *(k+7);
        h += MUL64((k0 + d0), (k4 + d4));
        h += MUL64((k1 + d1), (k5 + d5));
        h += MUL64((k2 + d2), (k6 + d6));
        h += MUL64((k3 + d3), (k7 + d7));

        d += 8;
        k += 8;
    } طالما (--c);
  *((UINT64 *)hp) = h;
}

#وإلاإذا (UMAC_OUTPUT_LEN == 8)

ساكن فراغ nh_aux(فراغ *kp, ثابت فراغ *dp, فراغ *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 16 bytes of hash-state per call.
 */
{
  UINT64 h1,h2;
  UWORD c = dlen / 32;
  UINT32 *k = (UINT32 *)kp;
  ثابت UINT32 *d = (ثابت UINT32 *)dp;
  UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
  UINT32 k0,k1,k2,k3,k4,k5,k6,k7,
        k8,k9,k10,k11;

  h1 = *((UINT64 *)hp);
  h2 = *((UINT64 *)hp + 1);
  k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
  افعل {
    d0 = بارگیری_UINT32_LITTLE(d+0); d1 = بارگیری_UINT32_LITTLE(d+1);
    d2 = بارگیری_UINT32_LITTLE(d+2); d3 = بارگیری_UINT32_LITTLE(d+3);
    d4 = بارگیری_UINT32_LITTLE(d+4); d5 = بارگیری_UINT32_LITTLE(d+5);
    d6 = بارگیری_UINT32_LITTLE(d+6); d7 = بارگیری_UINT32_LITTLE(d+7);
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
  } طالما (--c);
  ((UINT64 *)hp)[0] = h1;
  ((UINT64 *)hp)[1] = h2;
}

#وإلاإذا (UMAC_OUTPUT_LEN == 12)

ساكن فراغ nh_aux(فراغ *kp, ثابت فراغ *dp, فراغ *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 24 bytes of hash-state per call.
*/
{
    UINT64 h1,h2,h3;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    ثابت UINT32 *d = (ثابت UINT32 *)dp;
    UINT32 d0,d1,d2,d3,d4,d5,d6,d7;
    UINT32 k0,k1,k2,k3,k4,k5,k6,k7,
        k8,k9,k10,k11,k12,k13,k14,k15;

    h1 = *((UINT64 *)hp);
    h2 = *((UINT64 *)hp + 1);
    h3 = *((UINT64 *)hp + 2);
    k0 = *(k+0); k1 = *(k+1); k2 = *(k+2); k3 = *(k+3);
    k4 = *(k+4); k5 = *(k+5); k6 = *(k+6); k7 = *(k+7);
    افعل {
        d0 = بارگیری_UINT32_LITTLE(d+0); d1 = بارگیری_UINT32_LITTLE(d+1);
        d2 = بارگیری_UINT32_LITTLE(d+2); d3 = بارگیری_UINT32_LITTLE(d+3);
        d4 = بارگیری_UINT32_LITTLE(d+4); d5 = بارگیری_UINT32_LITTLE(d+5);
        d6 = بارگیری_UINT32_LITTLE(d+6); d7 = بارگیری_UINT32_LITTLE(d+7);
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
    } طالما (--c);
    ((UINT64 *)hp)[0] = h1;
    ((UINT64 *)hp)[1] = h2;
    ((UINT64 *)hp)[2] = h3;
}

#وإلاإذا (UMAC_OUTPUT_LEN == 16)

ساكن فراغ nh_aux(فراغ *kp, ثابت فراغ *dp, فراغ *hp, UINT32 dlen)
/* Same as previous nh_aux, but two streams are handled in one pass,
 * reading and writing 24 bytes of hash-state per call.
*/
{
    UINT64 h1,h2,h3,h4;
    UWORD c = dlen / 32;
    UINT32 *k = (UINT32 *)kp;
    ثابت UINT32 *d = (ثابت UINT32 *)dp;
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
    افعل {
        d0 = بارگیری_UINT32_LITTLE(d+0); d1 = بارگیری_UINT32_LITTLE(d+1);
        d2 = بارگیری_UINT32_LITTLE(d+2); d3 = بارگیری_UINT32_LITTLE(d+3);
        d4 = بارگیری_UINT32_LITTLE(d+4); d5 = بارگیری_UINT32_LITTLE(d+5);
        d6 = بارگیری_UINT32_LITTLE(d+6); d7 = بارگیری_UINT32_LITTLE(d+7);
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
    } طالما (--c);
    ((UINT64 *)hp)[0] = h1;
    ((UINT64 *)hp)[1] = h2;
    ((UINT64 *)hp)[2] = h3;
    ((UINT64 *)hp)[3] = h4;
}

/* ---------------------------------------------------------------------- */
#پایان_اگر  /* UMAC_OUTPUT_LENGTH */
/* ---------------------------------------------------------------------- */


/* ---------------------------------------------------------------------- */

ساكن فراغ nh_transform(nh_ctx *hc, ثابت UINT8 *buf, UINT32 nbytes)
/* This function is a wrapper for the primitive NH hash functions. It takes
 * as argument "hc" the current hash context and a buffer which must be a
 * multiple of L1_PAD_BOUNDARY. The key passed to nh_aux is offset
 * appropriately according to how much message has been hashed already.
 */
{
    UINT8 *کلید;

    کلید = hc->nh_کلید + hc->بایتها_hashed;
    nh_aux(کلید, buf, hc->state, nbytes);
}

/* ---------------------------------------------------------------------- */

#إذا (__LITTLE_ENDIAN__)
ساكن فراغ endian_convert(فراغ *buf, UWORD bpw, UINT32 رقم_بایتها)
/* We endian convert the keys on little-endian computers to               */
/* compensate for the lack of big-endian memory reads during hashing.     */
{
    UWORD iters = رقم_بایتها / bpw;
    إذا (bpw == 4) {
        UINT32 *p = (UINT32 *)buf;
        افعل {
            *p = بارگیری_UINT32_REVERSED(p);
            p++;
        } طالما (--iters);
    } وإلا إذا (bpw == 8) {
        UINT32 *p = (UINT32 *)buf;
        UINT32 t;
        افعل {
            t = بارگیری_UINT32_REVERSED(p+1);
            p[1] = بارگیری_UINT32_REVERSED(p);
            p[0] = t;
            p += 2;
        } طالما (--iters);
    }
}
#تعریف_کن endian_convert_if_le(x,y,z) endian_convert((x),(y),(z))
#وإلا
#تعریف_کن endian_convert_if_le(x,y,z) افعل{}طالما(0)  /* Do nothing */
#پایان_اگر

/* ---------------------------------------------------------------------- */

ساكن فراغ nh_reset(nh_ctx *hc)
/* Reset nh_ctx to ready for hashing of new data */
{
    hc->بایتها_hashed = 0;
    hc->بعدی_داده_خالی = 0;
    hc->state[0] = 0;
#إذا (UMAC_OUTPUT_LEN >= 8)
    hc->state[1] = 0;
#پایان_اگر
#إذا (UMAC_OUTPUT_LEN >= 12)
    hc->state[2] = 0;
#پایان_اگر
#إذا (UMAC_OUTPUT_LEN == 16)
    hc->state[3] = 0;
#پایان_اگر

}

/* ---------------------------------------------------------------------- */

ساكن فراغ nh_init(nh_ctx *hc, aes_int_کلید prf_کلید)
/* Generate nh_key, endian convert and reset to be ready for hashing.   */
{
    kdf(hc->nh_کلید, prf_کلید, 1, حجم(hc->nh_کلید));
    endian_convert_if_le(hc->nh_کلید, 4, حجم(hc->nh_کلید));
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

ساكن فراغ nh_update(nh_ctx *hc, ثابت UINT8 *buf, UINT32 nbytes)
/* Incorporate nbytes of data into a nh_ctx, buffer whatever is not an    */
/* even multiple of HASH_BUF_BYTES.                                       */
{
    UINT32 i,j;

    j = hc->بعدی_داده_خالی;
    إذا ((j + nbytes) >= HASH_BUF_بایتها) {
        إذا (j) {
            i = HASH_BUF_بایتها - j;
            کپی_حافظه(hc->داده+j, buf, i);
            nh_transform(hc,hc->داده,HASH_BUF_بایتها);
            nbytes -= i;
            buf += i;
            hc->بایتها_hashed += HASH_BUF_بایتها;
        }
        إذا (nbytes >= HASH_BUF_بایتها) {
            i = nbytes & ~(HASH_BUF_بایتها - 1);
            nh_transform(hc, buf, i);
            nbytes -= i;
            buf += i;
            hc->بایتها_hashed += i;
        }
        j = 0;
    }
    کپی_حافظه(hc->داده + j, buf, nbytes);
    hc->بعدی_داده_خالی = j + nbytes;
}

/* ---------------------------------------------------------------------- */

ساكن فراغ zero_pad(UINT8 *p, صحيح nbytes)
{
/* Write "nbytes" of zeroes, beginning at "p" */
    إذا (nbytes >= (صحيح)حجم(UWORD)) {
        طالما ((ptrdiff_t)p % حجم(UWORD)) {
            *p = 0;
            nbytes--;
            p++;
        }
        طالما (nbytes >= (صحيح)حجم(UWORD)) {
            *(UWORD *)p = 0;
            nbytes -= حجم(UWORD);
            p += حجم(UWORD);
        }
    }
    طالما (nbytes) {
        *p = 0;
        nbytes--;
        p++;
    }
}

/* ---------------------------------------------------------------------- */

ساكن فراغ nh_final(nh_ctx *hc, UINT8 *نتیجه)
/* After passing some number of data buffers to nh_update() for integration
 * into an NH context, nh_final is called to produce a hash result. If any
 * bytes are in the buffer hc->data, incorporate them into the
 * NH context. Finally, add into the NH accumulation "state" the total number
 * of bits hashed. The resulting numbers are written to the buffer "result".
 * If nh_update was never called, L1_PAD_BOUNDARY zeroes are incorporated.
 */
{
    صحيح nh_len, nbits;

    إذا (hc->بعدی_داده_خالی != 0) {
        nh_len = ((hc->بعدی_داده_خالی + (L1_PAD_BOUNDARY - 1)) &
                                                ~(L1_PAD_BOUNDARY - 1));
        zero_pad(hc->داده + hc->بعدی_داده_خالی,
                                          nh_len - hc->بعدی_داده_خالی);
        nh_transform(hc, hc->داده, nh_len);
        hc->بایتها_hashed += hc->بعدی_داده_خالی;
    } وإلا إذا (hc->بایتها_hashed == 0) {
	nh_len = L1_PAD_BOUNDARY;
        zero_pad(hc->داده, L1_PAD_BOUNDARY);
        nh_transform(hc, hc->داده, nh_len);
    }

    nbits = (hc->بایتها_hashed << 3);
    ((UINT64 *)نتیجه)[0] = ((UINT64 *)hc->state)[0] + nbits;
#إذا (UMAC_OUTPUT_LEN >= 8)
    ((UINT64 *)نتیجه)[1] = ((UINT64 *)hc->state)[1] + nbits;
#پایان_اگر
#إذا (UMAC_OUTPUT_LEN >= 12)
    ((UINT64 *)نتیجه)[2] = ((UINT64 *)hc->state)[2] + nbits;
#پایان_اگر
#إذا (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)نتیجه)[3] = ((UINT64 *)hc->state)[3] + nbits;
#پایان_اگر
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

ساكن فراغ nh(nh_ctx *hc, ثابت UINT8 *buf, UINT32 padded_len,
               UINT32 unpadded_len, UINT8 *نتیجه)
/* All-in-one nh_update() and nh_final() equivalent.
 * Assumes that padded_len is divisible by L1_PAD_BOUNDARY and result is
 * well aligned
 */
{
    UINT32 nbits;

    /* Initialize the hash state */
    nbits = (unpadded_len << 3);

    ((UINT64 *)نتیجه)[0] = nbits;
#إذا (UMAC_OUTPUT_LEN >= 8)
    ((UINT64 *)نتیجه)[1] = nbits;
#پایان_اگر
#إذا (UMAC_OUTPUT_LEN >= 12)
    ((UINT64 *)نتیجه)[2] = nbits;
#پایان_اگر
#إذا (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)نتیجه)[3] = nbits;
#پایان_اگر

    nh_aux(hc->nh_کلید, buf, نتیجه, padded_len);
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
#تعریف_کن p36    ((UINT64)0x0000000FFFFFFFFBull)              /* 2^36 -  5 */
#تعریف_کن p64    ((UINT64)0xFFFFFFFFFFFFFFC5ull)              /* 2^64 - 59 */
#تعریف_کن m36    ((UINT64)0x0000000FFFFFFFFFull)  /* The low 36 of 64 bits */


/* ---------------------------------------------------------------------- */

تعريفنوع بنية uhash_ctx {
    nh_ctx hash;                          /* Hash context for L1 NH hash  */
    UINT64 poly_کلید_8[STREAMS];           /* p64 poly keys                */
    UINT64 poly_accum[STREAMS];           /* poly hash result             */
    UINT64 ip_کلیدها[STREAMS*4];            /* Inner-product keys           */
    UINT32 ip_trans[STREAMS];             /* Inner-product translation    */
    UINT32 پیام_len;                       /* Total length of data passed  */
                                          /* to uhash */
} uhash_ctx;
تعريفنوع بنية uhash_ctx *uhash_ctx_t;

/* ---------------------------------------------------------------------- */


/* The polynomial hashes use Horner's rule to evaluate a polynomial one
 * word at a time. As described in the specification, poly32 and poly64
 * require keys from special domains. The following implementations exploit
 * the special domains to avoid overflow. The results are not guaranteed to
 * be within Z_p32 and Z_p64, but the Inner-Product hash implementation
 * patches any errant values.
 */

ساكن UINT64 poly64(UINT64 cur, UINT64 کلید, UINT64 داده)
{
    UINT32 کلید_hi = (UINT32)(کلید >> 32),
           کلید_lo = (UINT32)کلید,
           cur_hi = (UINT32)(cur >> 32),
           cur_lo = (UINT32)cur,
           x_lo,
           x_hi;
    UINT64 X,T,res;

    X =  MUL64(کلید_hi, cur_lo) + MUL64(cur_hi, کلید_lo);
    x_lo = (UINT32)X;
    x_hi = (UINT32)(X >> 32);

    res = (MUL64(کلید_hi, cur_hi) + x_hi) * 59 + MUL64(کلید_lo, cur_lo);

    T = ((UINT64)x_lo << 32);
    res += T;
    إذا (res < T)
        res += 59;

    res += داده;
    إذا (res < داده)
        res += 59;

    أرجع res;
}


/* Although UMAC is specified to use a ramped polynomial hash scheme, this
 * implementation does not handle all ramp levels. Because we don't handle
 * the ramp up to p128 modulus in this implementation, we are limited to
 * 2^14 poly_hash() invocations per stream (for a total capacity of 2^24
 * bytes input to UMAC per tag, ie. 16MB).
 */
ساكن فراغ poly_hash(uhash_ctx_t hc, UINT32 داده_درون[])
{
    صحيح i;
    UINT64 *داده=(UINT64*)داده_درون;

    لكل (i = 0; i < STREAMS; i++) {
        إذا ((UINT32)(داده[i] >> 32) == 0xfffffffful) {
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_کلید_8[i], p64 - 1);
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_کلید_8[i], (داده[i] - 59));
        } وإلا {
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_کلید_8[i], داده[i]);
        }
    }
}


/* ---------------------------------------------------------------------- */


/* The final step in UHASH is an inner-product hash. The poly hash
 * produces a result not necessarily WORD_LEN bytes long. The inner-
 * product hash breaks the polyhash output into 16-bit chunks and
 * multiplies each with a 36 bit key.
 */

ساكن UINT64 ip_aux(UINT64 t, UINT64 *ipkp, UINT64 داده)
{
    t = t + ipkp[0] * (UINT64)(UINT16)(داده >> 48);
    t = t + ipkp[1] * (UINT64)(UINT16)(داده >> 32);
    t = t + ipkp[2] * (UINT64)(UINT16)(داده >> 16);
    t = t + ipkp[3] * (UINT64)(UINT16)(داده);

    أرجع t;
}

ساكن UINT32 ip_reduce_p36(UINT64 t)
{
/* Divisionless modular reduction */
    UINT64 ret;

    ret = (t & m36) + 5 * (t >> 36);
    إذا (ret >= p36)
        ret -= p36;

    /* return least significant 32 bits */
    أرجع (UINT32)(ret);
}


/* If the data being hashed by UHASH is no longer than L1_KEY_LEN, then
 * the polyhash stage is skipped and ip_short is applied directly to the
 * NH output.
 */
ساكن فراغ ip_short(uhash_ctx_t ahc, UINT8 *nh_res, u_char *res)
{
    UINT64 t;
    UINT64 *nhp = (UINT64 *)nh_res;

    t  = ip_aux(0,ahc->ip_کلیدها, nhp[0]);
    STORE_UINT32_BIG((UINT32 *)res+0, ip_reduce_p36(t) ^ ahc->ip_trans[0]);
#إذا (UMAC_OUTPUT_LEN >= 8)
    t  = ip_aux(0,ahc->ip_کلیدها+4, nhp[1]);
    STORE_UINT32_BIG((UINT32 *)res+1, ip_reduce_p36(t) ^ ahc->ip_trans[1]);
#پایان_اگر
#إذا (UMAC_OUTPUT_LEN >= 12)
    t  = ip_aux(0,ahc->ip_کلیدها+8, nhp[2]);
    STORE_UINT32_BIG((UINT32 *)res+2, ip_reduce_p36(t) ^ ahc->ip_trans[2]);
#پایان_اگر
#إذا (UMAC_OUTPUT_LEN == 16)
    t  = ip_aux(0,ahc->ip_کلیدها+12, nhp[3]);
    STORE_UINT32_BIG((UINT32 *)res+3, ip_reduce_p36(t) ^ ahc->ip_trans[3]);
#پایان_اگر
}

/* If the data being hashed by UHASH is longer than L1_KEY_LEN, then
 * the polyhash stage is not skipped and ip_long is applied to the
 * polyhash output.
 */
ساكن فراغ ip_long(uhash_ctx_t ahc, u_char *res)
{
    صحيح i;
    UINT64 t;

    لكل (i = 0; i < STREAMS; i++) {
        /* fix polyhash output not in Z_p64 */
        إذا (ahc->poly_accum[i] >= p64)
            ahc->poly_accum[i] -= p64;
        t  = ip_aux(0,ahc->ip_کلیدها+(i*4), ahc->poly_accum[i]);
        STORE_UINT32_BIG((UINT32 *)res+i,
                         ip_reduce_p36(t) ^ ahc->ip_trans[i]);
    }
}


/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */

/* Reset uhash context for next hash session */
ساكن صحيح uhash_reset(uhash_ctx_t pc)
{
    nh_reset(&pc->hash);
    pc->پیام_len = 0;
    pc->poly_accum[0] = 1;
#إذا (UMAC_OUTPUT_LEN >= 8)
    pc->poly_accum[1] = 1;
#پایان_اگر
#إذا (UMAC_OUTPUT_LEN >= 12)
    pc->poly_accum[2] = 1;
#پایان_اگر
#إذا (UMAC_OUTPUT_LEN == 16)
    pc->poly_accum[3] = 1;
#پایان_اگر
    أرجع 1;
}

/* ---------------------------------------------------------------------- */

/* Given a pointer to the internal key needed by kdf() and a uhash context,
 * initialize the NH context and generate keys needed for poly and inner-
 * product hashing. All keys are endian adjusted in memory so that native
 * loads cause correct keys to be in registers during calculation.
 */
ساكن فراغ uhash_init(uhash_ctx_t ahc, aes_int_کلید prf_کلید)
{
    صحيح i;
    UINT8 buf[(8*STREAMS+4)*حجم(UINT64)];

    /* Zero the entire uhash context */
    memset(ahc, 0, حجم(uhash_ctx));

    /* Initialize the L1 hash */
    nh_init(&ahc->hash, prf_کلید);

    /* Setup L2 hash variables */
    kdf(buf, prf_کلید, 2, حجم(buf));    /* Fill buffer with index 1 key */
    لكل (i = 0; i < STREAMS; i++) {
        /* Fill keys from the buffer, skipping bytes in the buffer not
         * used by this implementation. Endian reverse the keys if on a
         * little-endian computer.
         */
        کپی_حافظه(ahc->poly_کلید_8+i, buf+24*i, 8);
        endian_convert_if_le(ahc->poly_کلید_8+i, 8, 8);
        /* Mask the 64-bit keys to their special domain */
        ahc->poly_کلید_8[i] &= ((UINT64)0x01ffffffu << 32) + 0x01ffffffu;
        ahc->poly_accum[i] = 1;  /* Our polyhash prepends a non-zero word */
    }

    /* Setup L3-1 hash variables */
    kdf(buf, prf_کلید, 3, حجم(buf)); /* Fill buffer with index 2 key */
    لكل (i = 0; i < STREAMS; i++)
          کپی_حافظه(ahc->ip_کلیدها+4*i, buf+(8*i+4)*حجم(UINT64),
                                                 4*حجم(UINT64));
    endian_convert_if_le(ahc->ip_کلیدها, حجم(UINT64),
                                                  حجم(ahc->ip_کلیدها));
    لكل (i = 0; i < STREAMS*4; i++)
        ahc->ip_کلیدها[i] %= p36;  /* Bring into Z_p36 */

    /* Setup L3-2 hash variables    */
    /* Fill buffer with index 4 key */
    kdf(ahc->ip_trans, prf_کلید, 4, STREAMS * حجم(UINT32));
    endian_convert_if_le(ahc->ip_trans, حجم(UINT32),
                         STREAMS * حجم(UINT32));
    explicit_bzero(buf, حجم(buf));
}

/* ---------------------------------------------------------------------- */

#إذا 0
ساكن uhash_ctx_t uhash_alloc(u_char کلید[])
{
/* Allocate memory and force to a 16-byte boundary. */
    uhash_ctx_t ctx;
    u_char بایتها_مقصد_جمع_کن;
    aes_int_کلید prf_کلید;

    ctx = (uhash_ctx_t)حافظه_بده(حجم(uhash_ctx)+ALLOC_BOUNDARY);
    إذا (ctx) {
        إذا (ALLOC_BOUNDARY) {
            بایتها_مقصد_جمع_کن = ALLOC_BOUNDARY -
                              ((ptrdiff_t)ctx & (ALLOC_BOUNDARY -1));
            ctx = (uhash_ctx_t)((u_char *)ctx + بایتها_مقصد_جمع_کن);
            *((u_char *)ctx - 1) = بایتها_مقصد_جمع_کن;
        }
        aes_کلید_راهاندازی(کلید,prf_کلید);
        uhash_init(ctx, prf_کلید);
    }
    أرجع (ctx);
}
#پایان_اگر

/* ---------------------------------------------------------------------- */

#إذا 0
ساكن صحيح uhash_free(uhash_ctx_t ctx)
{
/* Free memory allocated by uhash_alloc */
    u_char بایتها_مقصد_sub;

    إذا (ctx) {
        إذا (ALLOC_BOUNDARY) {
            بایتها_مقصد_sub = *((u_char *)ctx - 1);
            ctx = (uhash_ctx_t)((u_char *)ctx - بایتها_مقصد_sub);
        }
        حرر(ctx);
    }
    أرجع (1);
}
#پایان_اگر
/* ---------------------------------------------------------------------- */

ساكن صحيح uhash_update(uhash_ctx_t ctx, ثابت u_char *درون_داد, دراز len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and
 * hash each one with NH, calling the polyhash on each NH output.
 */
{
    UWORD بایتها_hashed, بایتها_مانده;
    UINT64 نتیجه_buf[STREAMS];
    UINT8 *nh_نتیجه = (UINT8 *)&نتیجه_buf;

    إذا (ctx->پیام_len + len <= L1_کلید_LEN) {
        nh_update(&ctx->hash, (ثابت UINT8 *)درون_داد, len);
        ctx->پیام_len += len;
    } وإلا {

         بایتها_hashed = ctx->پیام_len % L1_کلید_LEN;
         إذا (ctx->پیام_len == L1_کلید_LEN)
             بایتها_hashed = L1_کلید_LEN;

         إذا (بایتها_hashed + len >= L1_کلید_LEN) {

             /* If some bytes have been passed to the hash function      */
             /* then we want to pass at most (L1_KEY_LEN - bytes_hashed) */
             /* bytes to complete the current nh_block.                  */
             إذا (بایتها_hashed) {
                 بایتها_مانده = (L1_کلید_LEN - بایتها_hashed);
                 nh_update(&ctx->hash, (ثابت UINT8 *)درون_داد, بایتها_مانده);
                 nh_final(&ctx->hash, nh_نتیجه);
                 ctx->پیام_len += بایتها_مانده;
                 poly_hash(ctx,(UINT32 *)nh_نتیجه);
                 len -= بایتها_مانده;
                 درون_داد += بایتها_مانده;
             }

             /* Hash directly from input stream if enough bytes */
             طالما (len >= L1_کلید_LEN) {
                 nh(&ctx->hash, (ثابت UINT8 *)درون_داد, L1_کلید_LEN,
                                   L1_کلید_LEN, nh_نتیجه);
                 ctx->پیام_len += L1_کلید_LEN;
                 len -= L1_کلید_LEN;
                 درون_داد += L1_کلید_LEN;
                 poly_hash(ctx,(UINT32 *)nh_نتیجه);
             }
         }

         /* pass remaining < L1_KEY_LEN bytes of input data to NH */
         إذا (len > 0 && (بیعلامت دراز)len <= UINT32_MAX) {
             nh_update(&ctx->hash, (ثابت UINT8 *)درون_داد, len);
             ctx->پیام_len += len;
         }
     }

    أرجع (1);
}

/* ---------------------------------------------------------------------- */

ساكن صحيح uhash_final(uhash_ctx_t ctx, u_char *res)
/* Incorporate any pending data, pad, and generate tag */
{
    UINT64 نتیجه_buf[STREAMS];
    UINT8 *nh_نتیجه = (UINT8 *)&نتیجه_buf;

    إذا (ctx->پیام_len > L1_کلید_LEN) {
        إذا (ctx->پیام_len % L1_کلید_LEN) {
            nh_final(&ctx->hash, nh_نتیجه);
            poly_hash(ctx,(UINT32 *)nh_نتیجه);
        }
        ip_long(ctx, res);
    } وإلا {
        nh_final(&ctx->hash, nh_نتیجه);
        ip_short(ctx,nh_نتیجه, res);
    }
    uhash_reset(ctx);
    أرجع (1);
}

/* ---------------------------------------------------------------------- */

#إذا 0
ساكن صحيح uhash(uhash_ctx_t ahc, u_char *پیام, دراز len, u_char *res)
/* assumes that msg is in a writable buffer of length divisible by */
/* L1_PAD_BOUNDARY. Bytes beyond msg[len] may be zeroed.           */
{
    UINT8 nh_نتیجه[STREAMS*حجم(UINT64)];
    UINT32 nh_len;
    صحيح extra_zeroes_needed;

    /* If the message to be hashed is no longer than L1_HASH_LEN, we skip
     * the polyhash.
     */
    إذا (len <= L1_کلید_LEN) {
	إذا (len == 0)                  /* If zero length messages will not */
		nh_len = L1_PAD_BOUNDARY;  /* be seen, comment out this case   */
	وإلا
		nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
        extra_zeroes_needed = nh_len - len;
        zero_pad((UINT8 *)پیام + len, extra_zeroes_needed);
        nh(&ahc->hash, (UINT8 *)پیام, nh_len, len, nh_نتیجه);
        ip_short(ahc,nh_نتیجه, res);
    } وإلا {
        /* Otherwise, we hash each L1_KEY_LEN chunk with NH, passing the NH
         * output to poly_hash().
         */
        افعل {
            nh(&ahc->hash, (UINT8 *)پیام, L1_کلید_LEN, L1_کلید_LEN, nh_نتیجه);
            poly_hash(ahc,(UINT32 *)nh_نتیجه);
            len -= L1_کلید_LEN;
            پیام += L1_کلید_LEN;
        } طالما (len >= L1_کلید_LEN);
        إذا (len) {
            nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
            extra_zeroes_needed = nh_len - len;
            zero_pad((UINT8 *)پیام + len, extra_zeroes_needed);
            nh(&ahc->hash, (UINT8 *)پیام, nh_len, len, nh_نتیجه);
            poly_hash(ahc,(UINT32 *)nh_نتیجه);
        }

        ip_long(ahc, res);
    }

    uhash_reset(ahc);
    أرجع 1;
}
#پایان_اگر

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
بنية umac_ctx {
    uhash_ctx hash;          /* Hash function for message compression    */
    pdf_ctx pdf;             /* PDF for hashed output                    */
    فراغ *free_ptr;          /* Address to free this struct via          */
} umac_ctx;

/* ---------------------------------------------------------------------- */

#إذا 0
صحيح umac_reset(بنية umac_ctx *ctx)
/* Reset the hash function to begin a new authentication.        */
{
    uhash_reset(&ctx->hash);
    أرجع (1);
}
#پایان_اگر

/* ---------------------------------------------------------------------- */

صحيح umac_delete(بنية umac_ctx *ctx)
/* Deallocate the ctx structure */
{
    إذا (ctx) {
        إذا (ALLOC_BOUNDARY)
            ctx = (بنية umac_ctx *)ctx->free_ptr;
        freezero(ctx, حجم(*ctx) + ALLOC_BOUNDARY);
    }
    أرجع (1);
}

/* ---------------------------------------------------------------------- */

بنية umac_ctx *umac_new(ثابت u_char کلید[])
/* Dynamically allocate a umac_ctx struct, initialize variables,
 * generate subkeys from key. Align to 16-byte boundary.
 */
{
    بنية umac_ctx *ctx, *octx;
    اندازه_t بایتها_مقصد_جمع_کن;
    aes_int_کلید prf_کلید;

    octx = ctx = xcalloc(1, حجم(*ctx) + ALLOC_BOUNDARY);
    إذا (ctx) {
        إذا (ALLOC_BOUNDARY) {
            بایتها_مقصد_جمع_کن = ALLOC_BOUNDARY -
                              ((ptrdiff_t)ctx & (ALLOC_BOUNDARY - 1));
            ctx = (بنية umac_ctx *)((u_char *)ctx + بایتها_مقصد_جمع_کن);
        }
        ctx->free_ptr = octx;
        aes_کلید_راهاندازی(کلید, prf_کلید);
        pdf_init(&ctx->pdf, prf_کلید);
        uhash_init(&ctx->hash, prf_کلید);
        explicit_bzero(prf_کلید, حجم(prf_کلید));
    }

    أرجع (ctx);
}

/* ---------------------------------------------------------------------- */

صحيح umac_final(بنية umac_ctx *ctx, u_char برچسب[], ثابت u_char nonce[8])
/* Incorporate any pending data, pad, and generate tag */
{
    uhash_final(&ctx->hash, (u_char *)برچسب);
    pdf_gen_xor(&ctx->pdf, (ثابت UINT8 *)nonce, (UINT8 *)برچسب);

    أرجع (1);
}

/* ---------------------------------------------------------------------- */

صحيح umac_update(بنية umac_ctx *ctx, ثابت u_char *درون_داد, دراز len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and   */
/* hash each one, calling the PDF on the hashed output whenever the hash- */
/* output buffer is full.                                                 */
{
    uhash_update(&ctx->hash, درون_داد, len);
    أرجع (1);
}

/* ---------------------------------------------------------------------- */

#إذا 0
صحيح umac(بنية umac_ctx *ctx, u_char *درون_داد,
         دراز len, u_char برچسب[],
         u_char nonce[8])
/* All-in-one version simply calls umac_update() and umac_final().        */
{
    uhash(&ctx->hash, درون_داد, len, (u_char *)برچسب);
    pdf_gen_xor(&ctx->pdf, (UINT8 *)nonce, (UINT8 *)برچسب);

    أرجع (1);
}
#پایان_اگر

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- End UMAC Section ----------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
