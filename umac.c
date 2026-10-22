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

#جيڪڏهن_وصف_نه_ٿيل UMAC_OUTPUT_LEN
#وصف_ڪريو UMAC_OUTPUT_LEN     8  /* Allowable: 4, 8, 12, 16                  */
#جيڪڏهن_پورو

#إذا UMAC_OUTPUT_LEN != 4 && UMAC_OUTPUT_LEN != 8 && \
    UMAC_OUTPUT_LEN != 12 && UMAC_OUTPUT_LEN != 16
# error UMAC_OUTPUT_LEN must be defined منزل 4, 8, 12 or 16
#جيڪڏهن_پورو

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
تعريفنوع بنانشان صحيح	UWORD;  /*رجسٽر*/

/* ---------------------------------------------------------------------- */
/* --- Constants -------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#وصف_ڪريو UMAC_ڪنجي_LEN           16  /* UMAC takes 16 bytes of external key */

/* Message "words" are read from memory in an endian-specific manner.     */
/* For this implementation to behave correctly, __LITTLE_ENDIAN__ must    */
/* be set true if the host computer is little-endian.                     */

#إذا BYTE_ORDER == LITTLE_ENDIAN
#وصف_ڪريو __LITTLE_ENDIAN__ 1
#وإلا
#وصف_ڪريو __LITTLE_ENDIAN__ 0
#جيڪڏهن_پورو

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

#وصف_ڪريو MUL64(a,b) ((UINT64)((UINT64)(UINT32)(a) * (UINT64)(UINT32)(b)))

/* ---------------------------------------------------------------------- */
/* --- Endian Conversion --- Forcing assembly on some platforms           */
/* ---------------------------------------------------------------------- */

#إذا (__LITTLE_ENDIAN__)
#وصف_ڪريو ڀريو_UINT32_REVERSED(p)		get_u32(p)
#وصف_ڪريو STORE_UINT32_REVERSED(p,v)	put_u32(p,v)
#وإلا
#وصف_ڪريو ڀريو_UINT32_REVERSED(p)		get_u32_le(p)
#وصف_ڪريو STORE_UINT32_REVERSED(p,v)	put_u32_le(p,v)
#جيڪڏهن_پورو

#وصف_ڪريو ڀريو_UINT32_LITTLE(p)		(get_u32_le(p))
#وصف_ڪريو STORE_UINT32_BIG(p,v)		put_u32(p, v)

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin KDF & PDF Section ---------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* UMAC uses AES with 16 byte block and key lengths */
#وصف_ڪريو AES_بلاڪ_LEN  16

/* OpenSSL's AES */
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن "openbsd-compat/openssl-compat.h"
#جيڪڏهن_وصف_نه_ٿيل USE_BUILTIN_RIJNDAEL
# include <openssl/aes.h>
#جيڪڏهن_پورو
تعريفنوع AES_ڪنجي aes_int_ڪنجي[1];
#وصف_ڪريو aes_encryption(اندريون,ٻاهريون,int_ڪنجي)                  \
  AES_encrypt((u_char *)(اندريون),(u_char *)(ٻاهريون),(AES_ڪنجي *)int_ڪنجي)
#وصف_ڪريو aes_ڪنجي_تياري(ڪنجي,int_ڪنجي)                      \
  AES_سيٽ_encrypt_ڪنجي((ثابت u_char *)(ڪنجي),UMAC_ڪنجي_LEN*8,int_ڪنجي)
#وإلا
#ضمن "rijndael.h"
#وصف_ڪريو AES_ڦيرا ((UMAC_ڪنجي_LEN / 4) + 6)
تعريفنوع UINT8 aes_int_ڪنجي[AES_ڦيرا+1][4][4];	/* AES internal */
#وصف_ڪريو aes_encryption(اندريون,ٻاهريون,int_ڪنجي) \
  rijndaelEncrypt((u32 *)(int_ڪنجي), AES_ڦيرا, (u8 *)(اندريون), (u8 *)(ٻاهريون))
#وصف_ڪريو aes_ڪنجي_تياري(ڪنجي,int_ڪنجي) \
  rijndael_ڪنجي_تياري_Enc((u32 *)(int_ڪنجي), (ثابت بنانشان حرف *)(ڪنجي), \
  UMAC_ڪنجي_LEN*8)
#جيڪڏهن_پورو

/* The user-supplied UMAC key is stretched using AES in a counter
 * mode to supply all random bits needed by UMAC. The kdf function takes
 * an AES internal key representation 'key' and writes a stream of
 * 'nbytes' bytes to the memory pointed at by 'bufp'. Each distinct
 * 'ndx' causes a distinct byte stream.
 */
ساكن فراغ kdf(فراغ *bufp, aes_int_ڪنجي ڪنجي, UINT8 ndx, صحيح nbytes)
{
    UINT8 اندريون_buf[AES_بلاڪ_LEN] = {0};
    UINT8 ٻاهريون_buf[AES_بلاڪ_LEN];
    UINT8 *dst_buf = (UINT8 *)bufp;
    صحيح i;

    /* Setup the initial value */
    اندريون_buf[AES_بلاڪ_LEN-9] = ndx;
    اندريون_buf[AES_بلاڪ_LEN-1] = i = 1;

    طالما (nbytes >= AES_بلاڪ_LEN) {
        aes_encryption(اندريون_buf, ٻاهريون_buf, ڪنجي);
        يادگيري_نقل(dst_buf,ٻاهريون_buf,AES_بلاڪ_LEN);
        اندريون_buf[AES_بلاڪ_LEN-1] = ++i;
        nbytes -= AES_بلاڪ_LEN;
        dst_buf += AES_بلاڪ_LEN;
    }
    إذا (nbytes) {
        aes_encryption(اندريون_buf, ٻاهريون_buf, ڪنجي);
        يادگيري_نقل(dst_buf,ٻاهريون_buf,nbytes);
    }
    explicit_bzero(اندريون_buf, حجم(اندريون_buf));
    explicit_bzero(ٻاهريون_buf, حجم(ٻاهريون_buf));
}

/* The final UHASH result is XOR'd with the output of a pseudorandom
 * function. Here, we use AES to generate random output and
 * xor the appropriate bytes depending on the last bits of nonce.
 * This scheme is optimized for sequential, increasing big-endian nonces.
 */

تعريفنوع بنية {
    UINT8 cache[AES_بلاڪ_LEN];  /* Previous AES output is saved      */
    UINT8 nonce[AES_بلاڪ_LEN];  /* The AES input making above cache  */
    aes_int_ڪنجي prf_ڪنجي;         /* Expanded AES key for PDF          */
} pdf_ctx;

ساكن فراغ pdf_init(pdf_ctx *pc, aes_int_ڪنجي prf_ڪنجي)
{
    UINT8 buf[UMAC_ڪنجي_LEN];

    kdf(buf, prf_ڪنجي, 0, UMAC_ڪنجي_LEN);
    aes_ڪنجي_تياري(buf, pc->prf_ڪنجي);

    /* Initialize pdf and cache */
    memset(pc->nonce, 0, حجم(pc->nonce));
    aes_encryption(pc->nonce, pc->cache, pc->prf_ڪنجي);
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
#وصف_ڪريو هيٺيون_ٻٽو_انگ_نقاب 3
#وإلاإذا (UMAC_OUTPUT_LEN == 8)
#وصف_ڪريو هيٺيون_ٻٽو_انگ_نقاب 1
#وإلاإذا (UMAC_OUTPUT_LEN > 8)
#وصف_ڪريو هيٺيون_ٻٽو_انگ_نقاب 0
#جيڪڏهن_پورو
    اتحاد {
        UINT8 tmp_nonce_lo[4];
        UINT32 align;
    } t;
#إذا هيٺيون_ٻٽو_انگ_نقاب != 0
    صحيح ndx = nonce[7] & هيٺيون_ٻٽو_انگ_نقاب;
#جيڪڏهن_پورو
    *(UINT32 *)t.tmp_nonce_lo = ((ثابت UINT32 *)nonce)[1];
    t.tmp_nonce_lo[3] &= ~هيٺيون_ٻٽو_انگ_نقاب; /* zero last bit */

    إذا ( (((UINT32 *)t.tmp_nonce_lo)[0] != ((UINT32 *)pc->nonce)[1]) ||
         (((ثابت UINT32 *)nonce)[0] != ((UINT32 *)pc->nonce)[0]) )
    {
        ((UINT32 *)pc->nonce)[0] = ((ثابت UINT32 *)nonce)[0];
        ((UINT32 *)pc->nonce)[1] = ((UINT32 *)t.tmp_nonce_lo)[0];
        aes_encryption(pc->nonce, pc->cache, pc->prf_ڪنجي);
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
#جيڪڏهن_پورو
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

#وصف_ڪريو STREAMS (UMAC_OUTPUT_LEN / 4) /* Number of times hash is applied  */
#وصف_ڪريو L1_ڪنجي_LEN         1024     /* Internal key bytes                 */
#وصف_ڪريو L1_ڪنجي_سرڪايو         16     /* Toeplitz key shift between streams */
#وصف_ڪريو L1_PAD_BOUNDARY      32     /* pad message to boundary multiple   */
#وصف_ڪريو ALLOC_BOUNDARY       16     /* Keep buffers aligned to this       */
#وصف_ڪريو HASH_BUF_بائيٽون       64     /* nh_aux_hb buffer multiple          */

تعريفنوع بنية {
    UINT8  nh_ڪنجي [L1_ڪنجي_LEN + L1_ڪنجي_سرڪايو * (STREAMS - 1)]; /* NH Key */
    UINT8  معلومات   [HASH_BUF_بائيٽون];    /* Incoming data buffer           */
    صحيح ايندڙ_معلومات_خالي_جايون;    /* Bookkeeping variable for data buffer.     */
    صحيح بائيٽون_hashed;       /* Bytes (out of L1_KEY_LEN) incorporated.   */
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
        d0 = ڀريو_UINT32_LITTLE(d+0); d1 = ڀريو_UINT32_LITTLE(d+1);
        d2 = ڀريو_UINT32_LITTLE(d+2); d3 = ڀريو_UINT32_LITTLE(d+3);
        d4 = ڀريو_UINT32_LITTLE(d+4); d5 = ڀريو_UINT32_LITTLE(d+5);
        d6 = ڀريو_UINT32_LITTLE(d+6); d7 = ڀريو_UINT32_LITTLE(d+7);
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
    d0 = ڀريو_UINT32_LITTLE(d+0); d1 = ڀريو_UINT32_LITTLE(d+1);
    d2 = ڀريو_UINT32_LITTLE(d+2); d3 = ڀريو_UINT32_LITTLE(d+3);
    d4 = ڀريو_UINT32_LITTLE(d+4); d5 = ڀريو_UINT32_LITTLE(d+5);
    d6 = ڀريو_UINT32_LITTLE(d+6); d7 = ڀريو_UINT32_LITTLE(d+7);
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
        d0 = ڀريو_UINT32_LITTLE(d+0); d1 = ڀريو_UINT32_LITTLE(d+1);
        d2 = ڀريو_UINT32_LITTLE(d+2); d3 = ڀريو_UINT32_LITTLE(d+3);
        d4 = ڀريو_UINT32_LITTLE(d+4); d5 = ڀريو_UINT32_LITTLE(d+5);
        d6 = ڀريو_UINT32_LITTLE(d+6); d7 = ڀريو_UINT32_LITTLE(d+7);
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
        d0 = ڀريو_UINT32_LITTLE(d+0); d1 = ڀريو_UINT32_LITTLE(d+1);
        d2 = ڀريو_UINT32_LITTLE(d+2); d3 = ڀريو_UINT32_LITTLE(d+3);
        d4 = ڀريو_UINT32_LITTLE(d+4); d5 = ڀريو_UINT32_LITTLE(d+5);
        d6 = ڀريو_UINT32_LITTLE(d+6); d7 = ڀريو_UINT32_LITTLE(d+7);
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
#جيڪڏهن_پورو  /* UMAC_OUTPUT_LENGTH */
/* ---------------------------------------------------------------------- */


/* ---------------------------------------------------------------------- */

ساكن فراغ nh_transform(nh_ctx *hc, ثابت UINT8 *buf, UINT32 nbytes)
/* This function is a wrapper for the primitive NH hash functions. It takes
 * as argument "hc" the current hash context and a buffer which must be a
 * multiple of L1_PAD_BOUNDARY. The key passed to nh_aux is offset
 * appropriately according to how much message has been hashed already.
 */
{
    UINT8 *ڪنجي;

    ڪنجي = hc->nh_ڪنجي + hc->بائيٽون_hashed;
    nh_aux(ڪنجي, buf, hc->state, nbytes);
}

/* ---------------------------------------------------------------------- */

#إذا (__LITTLE_ENDIAN__)
ساكن فراغ endian_convert(فراغ *buf, UWORD bpw, UINT32 انگ_بائيٽون)
/* We endian convert the keys on little-endian computers to               */
/* compensate for the lack of big-endian memory reads during hashing.     */
{
    UWORD iters = انگ_بائيٽون / bpw;
    إذا (bpw == 4) {
        UINT32 *p = (UINT32 *)buf;
        افعل {
            *p = ڀريو_UINT32_REVERSED(p);
            p++;
        } طالما (--iters);
    } وإلا إذا (bpw == 8) {
        UINT32 *p = (UINT32 *)buf;
        UINT32 t;
        افعل {
            t = ڀريو_UINT32_REVERSED(p+1);
            p[1] = ڀريو_UINT32_REVERSED(p);
            p[0] = t;
            p += 2;
        } طالما (--iters);
    }
}
#وصف_ڪريو endian_convert_if_le(x,y,z) endian_convert((x),(y),(z))
#وإلا
#وصف_ڪريو endian_convert_if_le(x,y,z) افعل{}طالما(0)  /* Do nothing */
#جيڪڏهن_پورو

/* ---------------------------------------------------------------------- */

ساكن فراغ nh_reset(nh_ctx *hc)
/* Reset nh_ctx to ready for hashing of new data */
{
    hc->بائيٽون_hashed = 0;
    hc->ايندڙ_معلومات_خالي_جايون = 0;
    hc->state[0] = 0;
#إذا (UMAC_OUTPUT_LEN >= 8)
    hc->state[1] = 0;
#جيڪڏهن_پورو
#إذا (UMAC_OUTPUT_LEN >= 12)
    hc->state[2] = 0;
#جيڪڏهن_پورو
#إذا (UMAC_OUTPUT_LEN == 16)
    hc->state[3] = 0;
#جيڪڏهن_پورو

}

/* ---------------------------------------------------------------------- */

ساكن فراغ nh_init(nh_ctx *hc, aes_int_ڪنجي prf_ڪنجي)
/* Generate nh_key, endian convert and reset to be ready for hashing.   */
{
    kdf(hc->nh_ڪنجي, prf_ڪنجي, 1, حجم(hc->nh_ڪنجي));
    endian_convert_if_le(hc->nh_ڪنجي, 4, حجم(hc->nh_ڪنجي));
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

ساكن فراغ nh_update(nh_ctx *hc, ثابت UINT8 *buf, UINT32 nbytes)
/* Incorporate nbytes of data into a nh_ctx, buffer whatever is not an    */
/* even multiple of HASH_BUF_BYTES.                                       */
{
    UINT32 i,j;

    j = hc->ايندڙ_معلومات_خالي_جايون;
    إذا ((j + nbytes) >= HASH_BUF_بائيٽون) {
        إذا (j) {
            i = HASH_BUF_بائيٽون - j;
            يادگيري_نقل(hc->معلومات+j, buf, i);
            nh_transform(hc,hc->معلومات,HASH_BUF_بائيٽون);
            nbytes -= i;
            buf += i;
            hc->بائيٽون_hashed += HASH_BUF_بائيٽون;
        }
        إذا (nbytes >= HASH_BUF_بائيٽون) {
            i = nbytes & ~(HASH_BUF_بائيٽون - 1);
            nh_transform(hc, buf, i);
            nbytes -= i;
            buf += i;
            hc->بائيٽون_hashed += i;
        }
        j = 0;
    }
    يادگيري_نقل(hc->معلومات + j, buf, nbytes);
    hc->ايندڙ_معلومات_خالي_جايون = j + nbytes;
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

ساكن فراغ nh_final(nh_ctx *hc, UINT8 *نتيجو)
/* After passing some number of data buffers to nh_update() for integration
 * into an NH context, nh_final is called to produce a hash result. If any
 * bytes are in the buffer hc->data, incorporate them into the
 * NH context. Finally, add into the NH accumulation "state" the total number
 * of bits hashed. The resulting numbers are written to the buffer "result".
 * If nh_update was never called, L1_PAD_BOUNDARY zeroes are incorporated.
 */
{
    صحيح nh_len, nbits;

    إذا (hc->ايندڙ_معلومات_خالي_جايون != 0) {
        nh_len = ((hc->ايندڙ_معلومات_خالي_جايون + (L1_PAD_BOUNDARY - 1)) &
                                                ~(L1_PAD_BOUNDARY - 1));
        zero_pad(hc->معلومات + hc->ايندڙ_معلومات_خالي_جايون,
                                          nh_len - hc->ايندڙ_معلومات_خالي_جايون);
        nh_transform(hc, hc->معلومات, nh_len);
        hc->بائيٽون_hashed += hc->ايندڙ_معلومات_خالي_جايون;
    } وإلا إذا (hc->بائيٽون_hashed == 0) {
	nh_len = L1_PAD_BOUNDARY;
        zero_pad(hc->معلومات, L1_PAD_BOUNDARY);
        nh_transform(hc, hc->معلومات, nh_len);
    }

    nbits = (hc->بائيٽون_hashed << 3);
    ((UINT64 *)نتيجو)[0] = ((UINT64 *)hc->state)[0] + nbits;
#إذا (UMAC_OUTPUT_LEN >= 8)
    ((UINT64 *)نتيجو)[1] = ((UINT64 *)hc->state)[1] + nbits;
#جيڪڏهن_پورو
#إذا (UMAC_OUTPUT_LEN >= 12)
    ((UINT64 *)نتيجو)[2] = ((UINT64 *)hc->state)[2] + nbits;
#جيڪڏهن_پورو
#إذا (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)نتيجو)[3] = ((UINT64 *)hc->state)[3] + nbits;
#جيڪڏهن_پورو
    nh_reset(hc);
}

/* ---------------------------------------------------------------------- */

ساكن فراغ nh(nh_ctx *hc, ثابت UINT8 *buf, UINT32 padded_len,
               UINT32 unpadded_len, UINT8 *نتيجو)
/* All-in-one nh_update() and nh_final() equivalent.
 * Assumes that padded_len is divisible by L1_PAD_BOUNDARY and result is
 * well aligned
 */
{
    UINT32 nbits;

    /* Initialize the hash state */
    nbits = (unpadded_len << 3);

    ((UINT64 *)نتيجو)[0] = nbits;
#إذا (UMAC_OUTPUT_LEN >= 8)
    ((UINT64 *)نتيجو)[1] = nbits;
#جيڪڏهن_پورو
#إذا (UMAC_OUTPUT_LEN >= 12)
    ((UINT64 *)نتيجو)[2] = nbits;
#جيڪڏهن_پورو
#إذا (UMAC_OUTPUT_LEN == 16)
    ((UINT64 *)نتيجو)[3] = nbits;
#جيڪڏهن_پورو

    nh_aux(hc->nh_ڪنجي, buf, نتيجو, padded_len);
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
#وصف_ڪريو p36    ((UINT64)0x0000000FFFFFFFFBull)              /* 2^36 -  5 */
#وصف_ڪريو p64    ((UINT64)0xFFFFFFFFFFFFFFC5ull)              /* 2^64 - 59 */
#وصف_ڪريو m36    ((UINT64)0x0000000FFFFFFFFFull)  /* The low 36 of 64 bits */


/* ---------------------------------------------------------------------- */

تعريفنوع بنية uhash_ctx {
    nh_ctx hash;                          /* Hash context for L1 NH hash  */
    UINT64 poly_ڪنجي_8[STREAMS];           /* p64 poly keys                */
    UINT64 poly_accum[STREAMS];           /* poly hash result             */
    UINT64 ip_ڪنجيون[STREAMS*4];            /* Inner-product keys           */
    UINT32 ip_trans[STREAMS];             /* Inner-product translation    */
    UINT32 نياپو_len;                       /* Total length of data passed  */
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

ساكن UINT64 poly64(UINT64 cur, UINT64 ڪنجي, UINT64 معلومات)
{
    UINT32 ڪنجي_hi = (UINT32)(ڪنجي >> 32),
           ڪنجي_lo = (UINT32)ڪنجي,
           cur_hi = (UINT32)(cur >> 32),
           cur_lo = (UINT32)cur,
           x_lo,
           x_hi;
    UINT64 X,T,res;

    X =  MUL64(ڪنجي_hi, cur_lo) + MUL64(cur_hi, ڪنجي_lo);
    x_lo = (UINT32)X;
    x_hi = (UINT32)(X >> 32);

    res = (MUL64(ڪنجي_hi, cur_hi) + x_hi) * 59 + MUL64(ڪنجي_lo, cur_lo);

    T = ((UINT64)x_lo << 32);
    res += T;
    إذا (res < T)
        res += 59;

    res += معلومات;
    إذا (res < معلومات)
        res += 59;

    أرجع res;
}


/* Although UMAC is specified to use a ramped polynomial hash scheme, this
 * implementation does not handle all ramp levels. Because we don't handle
 * the ramp up to p128 modulus in this implementation, we are limited to
 * 2^14 poly_hash() invocations per stream (for a total capacity of 2^24
 * bytes input to UMAC per tag, ie. 16MB).
 */
ساكن فراغ poly_hash(uhash_ctx_t hc, UINT32 معلومات_اندريون[])
{
    صحيح i;
    UINT64 *معلومات=(UINT64*)معلومات_اندريون;

    لكل (i = 0; i < STREAMS; i++) {
        إذا ((UINT32)(معلومات[i] >> 32) == 0xfffffffful) {
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_ڪنجي_8[i], p64 - 1);
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_ڪنجي_8[i], (معلومات[i] - 59));
        } وإلا {
            hc->poly_accum[i] = poly64(hc->poly_accum[i],
                                       hc->poly_ڪنجي_8[i], معلومات[i]);
        }
    }
}


/* ---------------------------------------------------------------------- */


/* The final step in UHASH is an inner-product hash. The poly hash
 * produces a result not necessarily WORD_LEN bytes long. The inner-
 * product hash breaks the polyhash output into 16-bit chunks and
 * multiplies each with a 36 bit key.
 */

ساكن UINT64 ip_aux(UINT64 t, UINT64 *ipkp, UINT64 معلومات)
{
    t = t + ipkp[0] * (UINT64)(UINT16)(معلومات >> 48);
    t = t + ipkp[1] * (UINT64)(UINT16)(معلومات >> 32);
    t = t + ipkp[2] * (UINT64)(UINT16)(معلومات >> 16);
    t = t + ipkp[3] * (UINT64)(UINT16)(معلومات);

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

    t  = ip_aux(0,ahc->ip_ڪنجيون, nhp[0]);
    STORE_UINT32_BIG((UINT32 *)res+0, ip_reduce_p36(t) ^ ahc->ip_trans[0]);
#إذا (UMAC_OUTPUT_LEN >= 8)
    t  = ip_aux(0,ahc->ip_ڪنجيون+4, nhp[1]);
    STORE_UINT32_BIG((UINT32 *)res+1, ip_reduce_p36(t) ^ ahc->ip_trans[1]);
#جيڪڏهن_پورو
#إذا (UMAC_OUTPUT_LEN >= 12)
    t  = ip_aux(0,ahc->ip_ڪنجيون+8, nhp[2]);
    STORE_UINT32_BIG((UINT32 *)res+2, ip_reduce_p36(t) ^ ahc->ip_trans[2]);
#جيڪڏهن_پورو
#إذا (UMAC_OUTPUT_LEN == 16)
    t  = ip_aux(0,ahc->ip_ڪنجيون+12, nhp[3]);
    STORE_UINT32_BIG((UINT32 *)res+3, ip_reduce_p36(t) ^ ahc->ip_trans[3]);
#جيڪڏهن_پورو
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
        t  = ip_aux(0,ahc->ip_ڪنجيون+(i*4), ahc->poly_accum[i]);
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
    pc->نياپو_len = 0;
    pc->poly_accum[0] = 1;
#إذا (UMAC_OUTPUT_LEN >= 8)
    pc->poly_accum[1] = 1;
#جيڪڏهن_پورو
#إذا (UMAC_OUTPUT_LEN >= 12)
    pc->poly_accum[2] = 1;
#جيڪڏهن_پورو
#إذا (UMAC_OUTPUT_LEN == 16)
    pc->poly_accum[3] = 1;
#جيڪڏهن_پورو
    أرجع 1;
}

/* ---------------------------------------------------------------------- */

/* Given a pointer to the internal key needed by kdf() and a uhash context,
 * initialize the NH context and generate keys needed for poly and inner-
 * product hashing. All keys are endian adjusted in memory so that native
 * loads cause correct keys to be in registers during calculation.
 */
ساكن فراغ uhash_init(uhash_ctx_t ahc, aes_int_ڪنجي prf_ڪنجي)
{
    صحيح i;
    UINT8 buf[(8*STREAMS+4)*حجم(UINT64)];

    /* Zero the entire uhash context */
    memset(ahc, 0, حجم(uhash_ctx));

    /* Initialize the L1 hash */
    nh_init(&ahc->hash, prf_ڪنجي);

    /* Setup L2 hash variables */
    kdf(buf, prf_ڪنجي, 2, حجم(buf));    /* Fill buffer with index 1 key */
    لكل (i = 0; i < STREAMS; i++) {
        /* Fill keys from the buffer, skipping bytes in the buffer not
         * used by this implementation. Endian reverse the keys if on a
         * little-endian computer.
         */
        يادگيري_نقل(ahc->poly_ڪنجي_8+i, buf+24*i, 8);
        endian_convert_if_le(ahc->poly_ڪنجي_8+i, 8, 8);
        /* Mask the 64-bit keys to their special domain */
        ahc->poly_ڪنجي_8[i] &= ((UINT64)0x01ffffffu << 32) + 0x01ffffffu;
        ahc->poly_accum[i] = 1;  /* Our polyhash prepends a non-zero word */
    }

    /* Setup L3-1 hash variables */
    kdf(buf, prf_ڪنجي, 3, حجم(buf)); /* Fill buffer with index 2 key */
    لكل (i = 0; i < STREAMS; i++)
          يادگيري_نقل(ahc->ip_ڪنجيون+4*i, buf+(8*i+4)*حجم(UINT64),
                                                 4*حجم(UINT64));
    endian_convert_if_le(ahc->ip_ڪنجيون, حجم(UINT64),
                                                  حجم(ahc->ip_ڪنجيون));
    لكل (i = 0; i < STREAMS*4; i++)
        ahc->ip_ڪنجيون[i] %= p36;  /* Bring into Z_p36 */

    /* Setup L3-2 hash variables    */
    /* Fill buffer with index 4 key */
    kdf(ahc->ip_trans, prf_ڪنجي, 4, STREAMS * حجم(UINT32));
    endian_convert_if_le(ahc->ip_trans, حجم(UINT32),
                         STREAMS * حجم(UINT32));
    explicit_bzero(buf, حجم(buf));
}

/* ---------------------------------------------------------------------- */

#إذا 0
ساكن uhash_ctx_t uhash_alloc(u_char ڪنجي[])
{
/* Allocate memory and force to a 16-byte boundary. */
    uhash_ctx_t ctx;
    u_char بائيٽون_منزل_جوڙيو;
    aes_int_ڪنجي prf_ڪنجي;

    ctx = (uhash_ctx_t)يادگيري_ڏيو(حجم(uhash_ctx)+ALLOC_BOUNDARY);
    إذا (ctx) {
        إذا (ALLOC_BOUNDARY) {
            بائيٽون_منزل_جوڙيو = ALLOC_BOUNDARY -
                              ((ptrdiff_t)ctx & (ALLOC_BOUNDARY -1));
            ctx = (uhash_ctx_t)((u_char *)ctx + بائيٽون_منزل_جوڙيو);
            *((u_char *)ctx - 1) = بائيٽون_منزل_جوڙيو;
        }
        aes_ڪنجي_تياري(ڪنجي,prf_ڪنجي);
        uhash_init(ctx, prf_ڪنجي);
    }
    أرجع (ctx);
}
#جيڪڏهن_پورو

/* ---------------------------------------------------------------------- */

#إذا 0
ساكن صحيح uhash_free(uhash_ctx_t ctx)
{
/* Free memory allocated by uhash_alloc */
    u_char بائيٽون_منزل_sub;

    إذا (ctx) {
        إذا (ALLOC_BOUNDARY) {
            بائيٽون_منزل_sub = *((u_char *)ctx - 1);
            ctx = (uhash_ctx_t)((u_char *)ctx - بائيٽون_منزل_sub);
        }
        حرر(ctx);
    }
    أرجع (1);
}
#جيڪڏهن_پورو
/* ---------------------------------------------------------------------- */

ساكن صحيح uhash_update(uhash_ctx_t ctx, ثابت u_char *داخلا_2, ڊگهو len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and
 * hash each one with NH, calling the polyhash on each NH output.
 */
{
    UWORD بائيٽون_hashed, بائيٽون_بچيل;
    UINT64 نتيجو_buf[STREAMS];
    UINT8 *nh_نتيجو = (UINT8 *)&نتيجو_buf;

    إذا (ctx->نياپو_len + len <= L1_ڪنجي_LEN) {
        nh_update(&ctx->hash, (ثابت UINT8 *)داخلا_2, len);
        ctx->نياپو_len += len;
    } وإلا {

         بائيٽون_hashed = ctx->نياپو_len % L1_ڪنجي_LEN;
         إذا (ctx->نياپو_len == L1_ڪنجي_LEN)
             بائيٽون_hashed = L1_ڪنجي_LEN;

         إذا (بائيٽون_hashed + len >= L1_ڪنجي_LEN) {

             /* If some bytes have been passed to the hash function      */
             /* then we want to pass at most (L1_KEY_LEN - bytes_hashed) */
             /* bytes to complete the current nh_block.                  */
             إذا (بائيٽون_hashed) {
                 بائيٽون_بچيل = (L1_ڪنجي_LEN - بائيٽون_hashed);
                 nh_update(&ctx->hash, (ثابت UINT8 *)داخلا_2, بائيٽون_بچيل);
                 nh_final(&ctx->hash, nh_نتيجو);
                 ctx->نياپو_len += بائيٽون_بچيل;
                 poly_hash(ctx,(UINT32 *)nh_نتيجو);
                 len -= بائيٽون_بچيل;
                 داخلا_2 += بائيٽون_بچيل;
             }

             /* Hash directly from input stream if enough bytes */
             طالما (len >= L1_ڪنجي_LEN) {
                 nh(&ctx->hash, (ثابت UINT8 *)داخلا_2, L1_ڪنجي_LEN,
                                   L1_ڪنجي_LEN, nh_نتيجو);
                 ctx->نياپو_len += L1_ڪنجي_LEN;
                 len -= L1_ڪنجي_LEN;
                 داخلا_2 += L1_ڪنجي_LEN;
                 poly_hash(ctx,(UINT32 *)nh_نتيجو);
             }
         }

         /* pass remaining < L1_KEY_LEN bytes of input data to NH */
         إذا (len > 0 && (بنانشان ڊگهو)len <= UINT32_MAX) {
             nh_update(&ctx->hash, (ثابت UINT8 *)داخلا_2, len);
             ctx->نياپو_len += len;
         }
     }

    أرجع (1);
}

/* ---------------------------------------------------------------------- */

ساكن صحيح uhash_final(uhash_ctx_t ctx, u_char *res)
/* Incorporate any pending data, pad, and generate tag */
{
    UINT64 نتيجو_buf[STREAMS];
    UINT8 *nh_نتيجو = (UINT8 *)&نتيجو_buf;

    إذا (ctx->نياپو_len > L1_ڪنجي_LEN) {
        إذا (ctx->نياپو_len % L1_ڪنجي_LEN) {
            nh_final(&ctx->hash, nh_نتيجو);
            poly_hash(ctx,(UINT32 *)nh_نتيجو);
        }
        ip_long(ctx, res);
    } وإلا {
        nh_final(&ctx->hash, nh_نتيجو);
        ip_short(ctx,nh_نتيجو, res);
    }
    uhash_reset(ctx);
    أرجع (1);
}

/* ---------------------------------------------------------------------- */

#إذا 0
ساكن صحيح uhash(uhash_ctx_t ahc, u_char *نياپو, ڊگهو len, u_char *res)
/* assumes that msg is in a writable buffer of length divisible by */
/* L1_PAD_BOUNDARY. Bytes beyond msg[len] may be zeroed.           */
{
    UINT8 nh_نتيجو[STREAMS*حجم(UINT64)];
    UINT32 nh_len;
    صحيح extra_zeroes_needed;

    /* If the message to be hashed is no longer than L1_HASH_LEN, we skip
     * the polyhash.
     */
    إذا (len <= L1_ڪنجي_LEN) {
	إذا (len == 0)                  /* If zero length messages will not */
		nh_len = L1_PAD_BOUNDARY;  /* be seen, comment out this case   */
	وإلا
		nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
        extra_zeroes_needed = nh_len - len;
        zero_pad((UINT8 *)نياپو + len, extra_zeroes_needed);
        nh(&ahc->hash, (UINT8 *)نياپو, nh_len, len, nh_نتيجو);
        ip_short(ahc,nh_نتيجو, res);
    } وإلا {
        /* Otherwise, we hash each L1_KEY_LEN chunk with NH, passing the NH
         * output to poly_hash().
         */
        افعل {
            nh(&ahc->hash, (UINT8 *)نياپو, L1_ڪنجي_LEN, L1_ڪنجي_LEN, nh_نتيجو);
            poly_hash(ahc,(UINT32 *)nh_نتيجو);
            len -= L1_ڪنجي_LEN;
            نياپو += L1_ڪنجي_LEN;
        } طالما (len >= L1_ڪنجي_LEN);
        إذا (len) {
            nh_len = ((len + (L1_PAD_BOUNDARY - 1)) & ~(L1_PAD_BOUNDARY - 1));
            extra_zeroes_needed = nh_len - len;
            zero_pad((UINT8 *)نياپو + len, extra_zeroes_needed);
            nh(&ahc->hash, (UINT8 *)نياپو, nh_len, len, nh_نتيجو);
            poly_hash(ahc,(UINT32 *)nh_نتيجو);
        }

        ip_long(ahc, res);
    }

    uhash_reset(ahc);
    أرجع 1;
}
#جيڪڏهن_پورو

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
#جيڪڏهن_پورو

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

بنية umac_ctx *umac_new(ثابت u_char ڪنجي[])
/* Dynamically allocate a umac_ctx struct, initialize variables,
 * generate subkeys from key. Align to 16-byte boundary.
 */
{
    بنية umac_ctx *ctx, *octx;
    سائيز_t بائيٽون_منزل_جوڙيو;
    aes_int_ڪنجي prf_ڪنجي;

    octx = ctx = xcalloc(1, حجم(*ctx) + ALLOC_BOUNDARY);
    إذا (ctx) {
        إذا (ALLOC_BOUNDARY) {
            بائيٽون_منزل_جوڙيو = ALLOC_BOUNDARY -
                              ((ptrdiff_t)ctx & (ALLOC_BOUNDARY - 1));
            ctx = (بنية umac_ctx *)((u_char *)ctx + بائيٽون_منزل_جوڙيو);
        }
        ctx->free_ptr = octx;
        aes_ڪنجي_تياري(ڪنجي, prf_ڪنجي);
        pdf_init(&ctx->pdf, prf_ڪنجي);
        uhash_init(&ctx->hash, prf_ڪنجي);
        explicit_bzero(prf_ڪنجي, حجم(prf_ڪنجي));
    }

    أرجع (ctx);
}

/* ---------------------------------------------------------------------- */

صحيح umac_final(بنية umac_ctx *ctx, u_char ٽيگ[], ثابت u_char nonce[8])
/* Incorporate any pending data, pad, and generate tag */
{
    uhash_final(&ctx->hash, (u_char *)ٽيگ);
    pdf_gen_xor(&ctx->pdf, (ثابت UINT8 *)nonce, (UINT8 *)ٽيگ);

    أرجع (1);
}

/* ---------------------------------------------------------------------- */

صحيح umac_update(بنية umac_ctx *ctx, ثابت u_char *داخلا_2, ڊگهو len)
/* Given len bytes of data, we parse it into L1_KEY_LEN chunks and   */
/* hash each one, calling the PDF on the hashed output whenever the hash- */
/* output buffer is full.                                                 */
{
    uhash_update(&ctx->hash, داخلا_2, len);
    أرجع (1);
}

/* ---------------------------------------------------------------------- */

#إذا 0
صحيح umac(بنية umac_ctx *ctx, u_char *داخلا_2,
         ڊگهو len, u_char ٽيگ[],
         u_char nonce[8])
/* All-in-one version simply calls umac_update() and umac_final().        */
{
    uhash(&ctx->hash, داخلا_2, len, (u_char *)ٽيگ);
    pdf_gen_xor(&ctx->pdf, (UINT8 *)nonce, (UINT8 *)ٽيگ);

    أرجع (1);
}
#جيڪڏهن_پورو

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- End UMAC Section ----------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
