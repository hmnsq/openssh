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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_BUILTIN_RIJNDAEL
#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <openssl/evp.h>

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "rijndael.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#ವ್ಯಾಖ್ಯಾನಿಸು RIJNDAEL_BLOCKSIZE 16
ರಚನೆ ssh_rijndael_ctx
{
	rijndael_ctx	r_ctx;
	u_char		r_iv[RIJNDAEL_BLOCKSIZE];
};

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_rijndael_init(EVP_CIPHER_CTX *ctx, ಸ್ಥಿರಾಂಕ u_char *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ u_char *iv,
    ಪೂರ್ಣಾಂಕ enc)
{
	ರಚನೆ ssh_rijndael_ctx *c;

	ಆದರೆ ((c = EVP_CIPHER_CTX_get_app_ದತ್ತಾಂಶ(ctx)) == ಖಾಲಿ) {
		c = xmalloc(ಗಾತ್ರ(*c));
		EVP_CIPHER_CTX_ಗಣ_app_ದತ್ತಾಂಶ(ctx, c);
	}
	ಆದರೆ (ಕೀಲಿ != ಖಾಲಿ) {
		ಆದರೆ (enc == -1)
			enc = ctx->encrypt;
		rijndael_ಗಣ_ಕೀಲಿ(&c->r_ctx, (u_char *)ಕೀಲಿ,
		    8*EVP_CIPHER_CTX_ಕೀಲಿ_ಉದ್ದಳತೆ(ctx), enc);
	}
	ಆದರೆ (iv != ಖಾಲಿ)
		ಸ್ಮರಣೆ_ನಕಲು(c->r_iv, iv, RIJNDAEL_BLOCKSIZE);
	ಹಿಂತಿರುಗಿ (1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_rijndael_cbc(EVP_CIPHER_CTX *ctx, u_char *dest, ಸ್ಥಿರಾಂಕ u_char *src,
    ಗಾತ್ರ_t len)
{
	ರಚನೆ ssh_rijndael_ctx *c;
	u_char buf[RIJNDAEL_BLOCKSIZE];
	u_char *cprev, *cnow, *plain, *ivp;
	ಪೂರ್ಣಾಂಕ i, j, ಖಂಡಗಳು = len / RIJNDAEL_BLOCKSIZE;

	ಆದರೆ (len == 0)
		ಹಿಂತಿರುಗಿ (1);
	ಆದರೆ (len % RIJNDAEL_BLOCKSIZE)
		fatal("ssh_rijndael_cbc: bad len %d", len);
	ಆದರೆ ((c = EVP_CIPHER_CTX_get_app_ದತ್ತಾಂಶ(ctx)) == ಖಾಲಿ) {
		error("ssh_rijndael_cbc: no context");
		ಹಿಂತಿರುಗಿ (0);
	}
	ಆದರೆ (ctx->encrypt) {
		cnow  = dest;
		plain = (u_char *)src;
		cprev = c->r_iv;
		ಗಾಗಿ (i = 0; i < ಖಂಡಗಳು; i++, plain+=RIJNDAEL_BLOCKSIZE,
		    cnow+=RIJNDAEL_BLOCKSIZE) {
			ಗಾಗಿ (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				buf[j] = plain[j] ^ cprev[j];
			rijndael_encrypt(&c->r_ctx, buf, cnow);
			cprev = cnow;
		}
		ಸ್ಮರಣೆ_ನಕಲು(c->r_iv, cprev, RIJNDAEL_BLOCKSIZE);
	} ಇಲ್ಲದಿದ್ದರೆ {
		cnow  = (u_char *) (src+len-RIJNDAEL_BLOCKSIZE);
		plain = dest+len-RIJNDAEL_BLOCKSIZE;

		ಸ್ಮರಣೆ_ನಕಲು(buf, cnow, RIJNDAEL_BLOCKSIZE);
		ಗಾಗಿ (i = ಖಂಡಗಳು; i > 0; i--, cnow-=RIJNDAEL_BLOCKSIZE,
		    plain-=RIJNDAEL_BLOCKSIZE) {
			rijndael_decrypt(&c->r_ctx, cnow, plain);
			ivp = (i == 1) ? c->r_iv : cnow-RIJNDAEL_BLOCKSIZE;
			ಗಾಗಿ (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				plain[j] ^= ivp[j];
		}
		ಸ್ಮರಣೆ_ನಕಲು(c->r_iv, buf, RIJNDAEL_BLOCKSIZE);
	}
	ಹಿಂತಿರುಗಿ (1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_rijndael_cleanup(EVP_CIPHER_CTX *ctx)
{
	ರಚನೆ ssh_rijndael_ctx *c;

	ಆದರೆ ((c = EVP_CIPHER_CTX_get_app_ದತ್ತಾಂಶ(ctx)) != ಖಾಲಿ) {
		memset(c, 0, ಗಾತ್ರ(*c));
		ಬಿಡುಗಡೆ(c);
		EVP_CIPHER_CTX_ಗಣ_app_ದತ್ತಾಂಶ(ctx, ಖಾಲಿ);
	}
	ಹಿಂತಿರುಗಿ (1);
}

ಶೂನ್ಯ
ssh_rijndael_iv(EVP_CIPHER_CTX *evp, ಪೂರ್ಣಾಂಕ doset, u_char * iv, u_int len)
{
	ರಚನೆ ssh_rijndael_ctx *c;

	ಆದರೆ ((c = EVP_CIPHER_CTX_get_app_ದತ್ತಾಂಶ(evp)) == ಖಾಲಿ)
		fatal("ssh_rijndael_iv: no context");
	ಆದರೆ (doset)
		ಸ್ಮರಣೆ_ನಕಲು(c->r_iv, iv, len);
	ಇಲ್ಲದಿದ್ದರೆ
		ಸ್ಮರಣೆ_ನಕಲು(iv, c->r_iv, len);
}

ಸ್ಥಿರಾಂಕ EVP_CIPHER *
evp_rijndael(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ EVP_CIPHER rijndal_cbc;

	memset(&rijndal_cbc, 0, ಗಾತ್ರ(EVP_CIPHER));
	rijndal_cbc.nid = NID_undef;
	rijndal_cbc.ಖಂಡ_ಗಾತ್ರ = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.iv_len = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.ಕೀಲಿ_len = 16;
	rijndal_cbc.init = ssh_rijndael_init;
	rijndal_cbc.cleanup = ssh_rijndael_cleanup;
	rijndal_cbc.do_cipher = ssh_rijndael_cbc;
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SSH_OLD_EVP
	rijndal_cbc.flags = EVP_CIPH_CBC_ಬಹುಲಕ | EVP_CIPH_VARIABLE_ಉದ್ದಳತೆ |
	    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV;
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ (&rijndal_cbc);
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_BUILTIN_RIJNDAEL */
