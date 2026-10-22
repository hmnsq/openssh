/*
 * Copyright (c) 2003 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

/* compatibility with old or broken OpenSSL versions */
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ifdef USE_BUILTIN_RIJNDAEL
#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <openssl/evp.h>

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "rijndael.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#define RIJNDAEL_BLOCKSIZE 16
ಸಂರಚನಾ ssh_rijndael_ctx
{
	rijndael_ctx	r_ctx;
	u_char		r_iv[RIJNDAEL_BLOCKSIZE];
};

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_rijndael_init(EVP_CIPHER_CTX *ctx, ಧ್ರುವ u_char *ಕೀಲಿ, ಧ್ರುವ u_char *iv,
    ಪೂರ್ಣಾಙ್ಕ enc)
{
	ಸಂರಚನಾ ssh_rijndael_ctx *c;

	ಯದಿ ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == ರಿಕ್ತ) {
		c = xmalloc(ಪರಿಮಾಣ(*c));
		EVP_CIPHER_CTX_set_app_data(ctx, c);
	}
	ಯದಿ (ಕೀಲಿ != ರಿಕ್ತ) {
		ಯದಿ (enc == -1)
			enc = ctx->encrypt;
		rijndael_set_ಕೀಲಿ(&c->r_ctx, (u_char *)ಕೀಲಿ,
		    8*EVP_CIPHER_CTX_ಕೀಲಿ_length(ctx), enc);
	}
	ಯದಿ (iv != ರಿಕ್ತ)
		memcpy(c->r_iv, iv, RIJNDAEL_BLOCKSIZE);
	ಪ್ರತ್ಯಾಗಮ (1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_rijndael_cbc(EVP_CIPHER_CTX *ctx, u_char *dest, ಧ್ರುವ u_char *src,
    size_t len)
{
	ಸಂರಚನಾ ssh_rijndael_ctx *c;
	u_char buf[RIJNDAEL_BLOCKSIZE];
	u_char *cprev, *cnow, *plain, *ivp;
	ಪೂರ್ಣಾಙ್ಕ i, j, blocks = len / RIJNDAEL_BLOCKSIZE;

	ಯದಿ (len == 0)
		ಪ್ರತ್ಯಾಗಮ (1);
	ಯದಿ (len % RIJNDAEL_BLOCKSIZE)
		fatal("ssh_rijndael_cbc: bad len %d", len);
	ಯದಿ ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == ರಿಕ್ತ) {
		error("ssh_rijndael_cbc: no context");
		ಪ್ರತ್ಯಾಗಮ (0);
	}
	ಯದಿ (ctx->encrypt) {
		cnow  = dest;
		plain = (u_char *)src;
		cprev = c->r_iv;
		ಪ್ರತಿ (i = 0; i < blocks; i++, plain+=RIJNDAEL_BLOCKSIZE,
		    cnow+=RIJNDAEL_BLOCKSIZE) {
			ಪ್ರತಿ (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				buf[j] = plain[j] ^ cprev[j];
			rijndael_encrypt(&c->r_ctx, buf, cnow);
			cprev = cnow;
		}
		memcpy(c->r_iv, cprev, RIJNDAEL_BLOCKSIZE);
	} ಅನ್ಯಥಾ {
		cnow  = (u_char *) (src+len-RIJNDAEL_BLOCKSIZE);
		plain = dest+len-RIJNDAEL_BLOCKSIZE;

		memcpy(buf, cnow, RIJNDAEL_BLOCKSIZE);
		ಪ್ರತಿ (i = blocks; i > 0; i--, cnow-=RIJNDAEL_BLOCKSIZE,
		    plain-=RIJNDAEL_BLOCKSIZE) {
			rijndael_decrypt(&c->r_ctx, cnow, plain);
			ivp = (i == 1) ? c->r_iv : cnow-RIJNDAEL_BLOCKSIZE;
			ಪ್ರತಿ (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				plain[j] ^= ivp[j];
		}
		memcpy(c->r_iv, buf, RIJNDAEL_BLOCKSIZE);
	}
	ಪ್ರತ್ಯಾಗಮ (1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_rijndael_cleanup(EVP_CIPHER_CTX *ctx)
{
	ಸಂರಚನಾ ssh_rijndael_ctx *c;

	ಯದಿ ((c = EVP_CIPHER_CTX_get_app_data(ctx)) != ರಿಕ್ತ) {
		memset(c, 0, ಪರಿಮಾಣ(*c));
		ಮುಕ್ತ(c);
		EVP_CIPHER_CTX_set_app_data(ctx, ರಿಕ್ತ);
	}
	ಪ್ರತ್ಯಾಗಮ (1);
}

ಶೂನ್ಯ
ssh_rijndael_iv(EVP_CIPHER_CTX *evp, ಪೂರ್ಣಾಙ್ಕ doset, u_char * iv, u_int len)
{
	ಸಂರಚನಾ ssh_rijndael_ctx *c;

	ಯದಿ ((c = EVP_CIPHER_CTX_get_app_data(evp)) == ರಿಕ್ತ)
		fatal("ssh_rijndael_iv: no context");
	ಯದಿ (doset)
		memcpy(c->r_iv, iv, len);
	ಅನ್ಯಥಾ
		memcpy(iv, c->r_iv, len);
}

ಧ್ರುವ EVP_CIPHER *
evp_rijndael(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ EVP_CIPHER rijndal_cbc;

	memset(&rijndal_cbc, 0, ಪರಿಮಾಣ(EVP_CIPHER));
	rijndal_cbc.nid = NID_undef;
	rijndal_cbc.block_size = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.iv_len = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.ಕೀಲಿ_len = 16;
	rijndal_cbc.init = ssh_rijndael_init;
	rijndal_cbc.cleanup = ssh_rijndael_cleanup;
	rijndal_cbc.do_cipher = ssh_rijndael_cbc;
#ifndef SSH_OLD_EVP
	rijndal_cbc.flags = EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_LENGTH |
	    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV;
#endif
	ಪ್ರತ್ಯಾಗಮ (&rijndal_cbc);
}
#endif /* USE_BUILTIN_RIJNDAEL */
