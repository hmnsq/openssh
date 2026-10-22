/* $OpenBSD: umac.h,v 1.5 2022/01/01 01:55:30 jsg Exp $ */
/* -----------------------------------------------------------------------
 * 
 * umac.h -- C Implementation UMAC Message Authentication
 *
 * Version 0.93a of rfc4418.txt -- 2006 July 14
 *
 * For a full description of UMAC message authentication see the UMAC
 * world-wide-web page at http://www.cs.ucdavis.edu/~rogaway/umac
 * Please report bugs and suggestions to the UMAC webpage.
 *
 * Copyright (c) 1999-2004 Ted Krovetz
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
  * 4) Two free AES implementations are supported by this implementation of
  * UMAC. Paulo Barreto's version is in the public domain and can be found
  * at http://www.esat.kuleuven.ac.be/~rijmen/rijndael/ (search for
  * "Barreto"). The only two files needed are rijndael-alg-fst.c and
  * rijndael-alg-fst.h.
  * Brian Gladman's version is distributed with GNU Public license
  * and can be found at http://fp.gladman.plus.com/AES/index.htm. It
  * includes a fast IA-32 assembly version.
  *
  /////////////////////////////////////////////////////////////////////// */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਸਿਰਲੇਖ_UMAC_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਸਿਰਲੇਖ_UMAC_H


#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __cplusplus
    ਬਾਹਰੀ "C" {
#ਜੇ_ਅੰਤ

ਬਣਤਰ umac_ctx *umac_new(ਅਚਲ u_char ਕੁੰਜੀ[]);
/* Dynamically allocate a umac_ctx struct, initialize variables, 
 * generate subkeys from key.
 */

#ਜੇ 0
ਪੂਰਨ umac_reset(ਬਣਤਰ umac_ctx *ctx);
/* Reset a umac_ctx to begin authenticating a new message */
#ਜੇ_ਅੰਤ

ਪੂਰਨ umac_update(ਬਣਤਰ umac_ctx *ctx, ਅਚਲ u_char *ਨਿਵੇਸ਼, ਲੰਮਾ len);
/* Incorporate len bytes pointed to by input into context ctx */

ਪੂਰਨ umac_final(ਬਣਤਰ umac_ctx *ctx, u_char ਟੈਗ[], ਅਚਲ u_char nonce[8]);
/* Incorporate any pending data and the ctr value, and return tag. 
 * This function returns error code if ctr < 0. 
 */

ਪੂਰਨ umac_delete(ਬਣਤਰ umac_ctx *ctx);
/* Deallocate the context structure */

#ਜੇ 0
ਪੂਰਨ umac(ਬਣਤਰ umac_ctx *ctx, u_char *ਨਿਵੇਸ਼, 
         ਲੰਮਾ len, u_char ਟੈਗ[],
         u_char nonce[8]);
/* All-in-one implementation of the functions Reset, Update and Final */
#ਜੇ_ਅੰਤ

/* uhash.h */


#ਜੇ 0
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ uhash_ctx *uhash_ctx_t;
  /* The uhash_ctx structure is defined by the implementation of the    */
  /* UHASH functions.                                                   */
 
uhash_ctx_t uhash_alloc(u_char ਕੁੰਜੀ[16]);
  /* Dynamically allocate a uhash_ctx struct and generate subkeys using */
  /* the kdf and kdf_key passed in. If kdf_key_len is 0 then RC6 is     */
  /* used to generate key with a fixed key. If kdf_key_len > 0 but kdf  */
  /* is NULL then the first 16 bytes pointed at by kdf_key is used as a */
  /* key for an RC6 based KDF.                                          */
  
ਪੂਰਨ uhash_free(uhash_ctx_t ctx);

ਪੂਰਨ uhash_ਸੈੱਟ_params(uhash_ctx_t ctx,
                   ਖਾਲੀ       *params);

ਪੂਰਨ uhash_reset(uhash_ctx_t ctx);

ਪੂਰਨ uhash_update(uhash_ctx_t ctx,
               u_char       *ਨਿਵੇਸ਼,
               ਲੰਮਾ        len);

ਪੂਰਨ uhash_final(uhash_ctx_t ctx,
              u_char        output[]);

ਪੂਰਨ uhash(uhash_ctx_t ctx,
        u_char       *ਨਿਵੇਸ਼,
        ਲੰਮਾ        len,
        u_char        output[]);

#ਜੇ_ਅੰਤ

/* matching umac-128 API, we reuse umac_ctx, since it's opaque */
ਬਣਤਰ umac_ctx *umac128_new(ਅਚਲ u_char ਕੁੰਜੀ[]);
ਪੂਰਨ umac128_update(ਬਣਤਰ umac_ctx *ctx, ਅਚਲ u_char *ਨਿਵੇਸ਼, ਲੰਮਾ len);
ਪੂਰਨ umac128_final(ਬਣਤਰ umac_ctx *ctx, u_char ਟੈਗ[], ਅਚਲ u_char nonce[8]);
ਪੂਰਨ umac128_delete(ਬਣਤਰ umac_ctx *ctx);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __cplusplus
    }
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ /* HEADER_UMAC_H */
