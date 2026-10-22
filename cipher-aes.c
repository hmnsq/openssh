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

#અન્તર્ભાવ "includes.h"

/* compatibility with old or broken OpenSSL versions */
#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

#ifdef USE_BUILTIN_RIJNDAEL
#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <openssl/evp.h>

#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "rijndael.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "log.h"

#define RIJNDAEL_BLOCKSIZE 16
સંરચના ssh_rijndael_ctx
{
	rijndael_ctx	r_ctx;
	u_char		r_iv[RIJNDAEL_BLOCKSIZE];
};

સ્થિર પૂર્ણાંક
ssh_rijndael_init(EVP_CIPHER_CTX *ctx, અચલ u_char *ચાવી, અચલ u_char *iv,
    પૂર્ણાંક enc)
{
	સંરચના ssh_rijndael_ctx *c;

	જો ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == ખાલી) {
		c = xmalloc(કદ(*c));
		EVP_CIPHER_CTX_set_app_data(ctx, c);
	}
	જો (ચાવી != ખાલી) {
		જો (enc == -1)
			enc = ctx->encrypt;
		rijndael_set_ચાવી(&c->r_ctx, (u_char *)ચાવી,
		    8*EVP_CIPHER_CTX_ચાવી_length(ctx), enc);
	}
	જો (iv != ખાલી)
		memcpy(c->r_iv, iv, RIJNDAEL_BLOCKSIZE);
	પાછા (1);
}

સ્થિર પૂર્ણાંક
ssh_rijndael_cbc(EVP_CIPHER_CTX *ctx, u_char *dest, અચલ u_char *src,
    size_t len)
{
	સંરચના ssh_rijndael_ctx *c;
	u_char buf[RIJNDAEL_BLOCKSIZE];
	u_char *cprev, *cnow, *plain, *ivp;
	પૂર્ણાંક i, j, blocks = len / RIJNDAEL_BLOCKSIZE;

	જો (len == 0)
		પાછા (1);
	જો (len % RIJNDAEL_BLOCKSIZE)
		fatal("ssh_rijndael_cbc: bad len %d", len);
	જો ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == ખાલી) {
		error("ssh_rijndael_cbc: no context");
		પાછા (0);
	}
	જો (ctx->encrypt) {
		cnow  = dest;
		plain = (u_char *)src;
		cprev = c->r_iv;
		માટે (i = 0; i < blocks; i++, plain+=RIJNDAEL_BLOCKSIZE,
		    cnow+=RIJNDAEL_BLOCKSIZE) {
			માટે (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				buf[j] = plain[j] ^ cprev[j];
			rijndael_encrypt(&c->r_ctx, buf, cnow);
			cprev = cnow;
		}
		memcpy(c->r_iv, cprev, RIJNDAEL_BLOCKSIZE);
	} નહીંતર {
		cnow  = (u_char *) (src+len-RIJNDAEL_BLOCKSIZE);
		plain = dest+len-RIJNDAEL_BLOCKSIZE;

		memcpy(buf, cnow, RIJNDAEL_BLOCKSIZE);
		માટે (i = blocks; i > 0; i--, cnow-=RIJNDAEL_BLOCKSIZE,
		    plain-=RIJNDAEL_BLOCKSIZE) {
			rijndael_decrypt(&c->r_ctx, cnow, plain);
			ivp = (i == 1) ? c->r_iv : cnow-RIJNDAEL_BLOCKSIZE;
			માટે (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				plain[j] ^= ivp[j];
		}
		memcpy(c->r_iv, buf, RIJNDAEL_BLOCKSIZE);
	}
	પાછા (1);
}

સ્થિર પૂર્ણાંક
ssh_rijndael_cleanup(EVP_CIPHER_CTX *ctx)
{
	સંરચના ssh_rijndael_ctx *c;

	જો ((c = EVP_CIPHER_CTX_get_app_data(ctx)) != ખાલી) {
		memset(c, 0, કદ(*c));
		મુક્ત(c);
		EVP_CIPHER_CTX_set_app_data(ctx, ખાલી);
	}
	પાછા (1);
}

શૂન્ય
ssh_rijndael_iv(EVP_CIPHER_CTX *evp, પૂર્ણાંક doset, u_char * iv, u_int len)
{
	સંરચના ssh_rijndael_ctx *c;

	જો ((c = EVP_CIPHER_CTX_get_app_data(evp)) == ખાલી)
		fatal("ssh_rijndael_iv: no context");
	જો (doset)
		memcpy(c->r_iv, iv, len);
	નહીંતર
		memcpy(iv, c->r_iv, len);
}

અચલ EVP_CIPHER *
evp_rijndael(શૂન્ય)
{
	સ્થિર EVP_CIPHER rijndal_cbc;

	memset(&rijndal_cbc, 0, કદ(EVP_CIPHER));
	rijndal_cbc.nid = NID_undef;
	rijndal_cbc.block_size = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.iv_len = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.ચાવી_len = 16;
	rijndal_cbc.init = ssh_rijndael_init;
	rijndal_cbc.cleanup = ssh_rijndael_cleanup;
	rijndal_cbc.do_cipher = ssh_rijndael_cbc;
#ifndef SSH_OLD_EVP
	rijndal_cbc.flags = EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_LENGTH |
	    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV;
#endif
	પાછા (&rijndal_cbc);
}
#endif /* USE_BUILTIN_RIJNDAEL */
