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
#ifndef HEADER_UMAC_H
#define HEADER_UMAC_H


#ifdef __cplusplus
    خارجي "C" {
#endif

بنية umac_ctx *umac_new(ثابت u_char key[]);
/* Dynamically allocate a umac_ctx struct, initialize variables, 
 * generate subkeys from key.
 */

#𐤀𐤌 0
صحيح umac_reset(بنية umac_ctx *ctx);
/* Reset a umac_ctx to begin authenticating a new message */
#endif

صحيح umac_update(بنية umac_ctx *ctx, ثابت u_char *input, long len);
/* Incorporate len bytes pointed to by input into context ctx */

صحيح umac_final(بنية umac_ctx *ctx, u_char tag[], ثابت u_char nonce[8]);
/* Incorporate any pending data and the ctr value, and return tag. 
 * This function returns error code if ctr < 0. 
 */

صحيح umac_delete(بنية umac_ctx *ctx);
/* Deallocate the context structure */

#𐤀𐤌 0
صحيح umac(بنية umac_ctx *ctx, u_char *input, 
         long len, u_char tag[],
         u_char nonce[8]);
/* All-in-one implementation of the functions Reset, Update and Final */
#endif

/* uhash.h */


#𐤀𐤌 0
تعريفنوع بنية uhash_ctx *uhash_ctx_t;
  /* The uhash_ctx structure is defined by the implementation of the    */
  /* UHASH functions.                                                   */
 
uhash_ctx_t uhash_alloc(u_char key[16]);
  /* Dynamically allocate a uhash_ctx struct and generate subkeys using */
  /* the kdf and kdf_key passed in. If kdf_key_len is 0 then RC6 is     */
  /* used to generate key with a fixed key. If kdf_key_len > 0 but kdf  */
  /* is NULL then the first 16 bytes pointed at by kdf_key is used as a */
  /* key for an RC6 based KDF.                                          */
  
صحيح uhash_free(uhash_ctx_t ctx);

صحيح uhash_set_params(uhash_ctx_t ctx,
                   فراغ       *params);

صحيح uhash_reset(uhash_ctx_t ctx);

صحيح uhash_update(uhash_ctx_t ctx,
               u_char       *input,
               long        len);

صحيح uhash_final(uhash_ctx_t ctx,
              u_char        output[]);

صحيح uhash(uhash_ctx_t ctx,
        u_char       *input,
        long        len,
        u_char        output[]);

#endif

/* matching umac-128 API, we reuse umac_ctx, since it's opaque */
بنية umac_ctx *umac128_new(ثابت u_char key[]);
صحيح umac128_update(بنية umac_ctx *ctx, ثابت u_char *input, long len);
صحيح umac128_final(بنية umac_ctx *ctx, u_char tag[], ثابت u_char nonce[8]);
صحيح umac128_delete(بنية umac_ctx *ctx);

#ifdef __cplusplus
    }
#endif

#endif /* HEADER_UMAC_H */
