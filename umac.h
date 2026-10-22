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
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಶೀರ್ಷಿಕೆ_UMAC_H
#ವ್ಯಾಖ್ಯಾನಿಸು ಶೀರ್ಷಿಕೆ_UMAC_H


#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __cplusplus
    ಬಾಹ್ಯ "C" {
#ಆದರೆ_ಅಂತ್ಯ

ರಚನೆ umac_ctx *umac_new(ಸ್ಥಿರಾಂಕ u_char ಕೀಲಿ[]);
/* Dynamically allocate a umac_ctx struct, initialize variables, 
 * generate subkeys from key.
 */

#ಆದರೆ 0
ಪೂರ್ಣಾಂಕ umac_reset(ರಚನೆ umac_ctx *ctx);
/* Reset a umac_ctx to begin authenticating a new message */
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ umac_update(ರಚನೆ umac_ctx *ctx, ಸ್ಥಿರಾಂಕ u_char *ಒಳಹರಿವು, ದೀರ್ಘ len);
/* Incorporate len bytes pointed to by input into context ctx */

ಪೂರ್ಣಾಂಕ umac_final(ರಚನೆ umac_ctx *ctx, u_char ಟ್ಯಾಗ್[], ಸ್ಥಿರಾಂಕ u_char nonce[8]);
/* Incorporate any pending data and the ctr value, and return tag. 
 * This function returns error code if ctr < 0. 
 */

ಪೂರ್ಣಾಂಕ umac_delete(ರಚನೆ umac_ctx *ctx);
/* Deallocate the context structure */

#ಆದರೆ 0
ಪೂರ್ಣಾಂಕ umac(ರಚನೆ umac_ctx *ctx, u_char *ಒಳಹರಿವು, 
         ದೀರ್ಘ len, u_char ಟ್ಯಾಗ್[],
         u_char nonce[8]);
/* All-in-one implementation of the functions Reset, Update and Final */
#ಆದರೆ_ಅಂತ್ಯ

/* uhash.h */


#ಆದರೆ 0
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ uhash_ctx *uhash_ctx_t;
  /* The uhash_ctx structure is defined by the implementation of the    */
  /* UHASH functions.                                                   */
 
uhash_ctx_t uhash_alloc(u_char ಕೀಲಿ[16]);
  /* Dynamically allocate a uhash_ctx struct and generate subkeys using */
  /* the kdf and kdf_key passed in. If kdf_key_len is 0 then RC6 is     */
  /* used to generate key with a fixed key. If kdf_key_len > 0 but kdf  */
  /* is NULL then the first 16 bytes pointed at by kdf_key is used as a */
  /* key for an RC6 based KDF.                                          */
  
ಪೂರ್ಣಾಂಕ uhash_free(uhash_ctx_t ctx);

ಪೂರ್ಣಾಂಕ uhash_ಗಣ_params(uhash_ctx_t ctx,
                   ಶೂನ್ಯ       *params);

ಪೂರ್ಣಾಂಕ uhash_reset(uhash_ctx_t ctx);

ಪೂರ್ಣಾಂಕ uhash_update(uhash_ctx_t ctx,
               u_char       *ಒಳಹರಿವು,
               ದೀರ್ಘ        len);

ಪೂರ್ಣಾಂಕ uhash_final(uhash_ctx_t ctx,
              u_char        output[]);

ಪೂರ್ಣಾಂಕ uhash(uhash_ctx_t ctx,
        u_char       *ಒಳಹರಿವು,
        ದೀರ್ಘ        len,
        u_char        output[]);

#ಆದರೆ_ಅಂತ್ಯ

/* matching umac-128 API, we reuse umac_ctx, since it's opaque */
ರಚನೆ umac_ctx *umac128_new(ಸ್ಥಿರಾಂಕ u_char ಕೀಲಿ[]);
ಪೂರ್ಣಾಂಕ umac128_update(ರಚನೆ umac_ctx *ctx, ಸ್ಥಿರಾಂಕ u_char *ಒಳಹರಿವು, ದೀರ್ಘ len);
ಪೂರ್ಣಾಂಕ umac128_final(ರಚನೆ umac_ctx *ctx, u_char ಟ್ಯಾಗ್[], ಸ್ಥಿರಾಂಕ u_char nonce[8]);
ಪೂರ್ಣಾಂಕ umac128_delete(ರಚನೆ umac_ctx *ctx);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __cplusplus
    }
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ /* HEADER_UMAC_H */
