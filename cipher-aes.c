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

#ଅନ୍ତର୍ଭାଵ "includes.h"

/* compatibility with old or broken OpenSSL versions */
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

#ifdef USE_BUILTIN_RIJNDAEL
#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>

#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "rijndael.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

#define RIJNDAEL_BLOCKSIZE 16
ସଂରଚନା ssh_rijndael_ctx
{
	rijndael_ctx	r_ctx;
	u_char		r_iv[RIJNDAEL_BLOCKSIZE];
};

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rijndael_init(EVP_CIPHER_CTX *ctx, ଅଚଳ u_char *ଚାବି, ଅଚଳ u_char *iv,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା enc)
{
	ସଂରଚନା ssh_rijndael_ctx *c;

	ଯଦି ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == ଖାଲି) {
		c = xmalloc(ଆକାର(*c));
		EVP_CIPHER_CTX_set_app_data(ctx, c);
	}
	ଯଦି (ଚାବି != ଖାଲି) {
		ଯଦି (enc == -1)
			enc = ctx->encrypt;
		rijndael_set_ଚାବି(&c->r_ctx, (u_char *)ଚାବି,
		    8*EVP_CIPHER_CTX_ଚାବି_length(ctx), enc);
	}
	ଯଦି (iv != ଖାଲି)
		memcpy(c->r_iv, iv, RIJNDAEL_BLOCKSIZE);
	ଫେରନ୍ତୁ (1);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rijndael_cbc(EVP_CIPHER_CTX *ctx, u_char *dest, ଅଚଳ u_char *src,
    size_t len)
{
	ସଂରଚନା ssh_rijndael_ctx *c;
	u_char buf[RIJNDAEL_BLOCKSIZE];
	u_char *cprev, *cnow, *plain, *ivp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, j, blocks = len / RIJNDAEL_BLOCKSIZE;

	ଯଦି (len == 0)
		ଫେରନ୍ତୁ (1);
	ଯଦି (len % RIJNDAEL_BLOCKSIZE)
		fatal("ssh_rijndael_cbc: bad len %d", len);
	ଯଦି ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == ଖାଲି) {
		error("ssh_rijndael_cbc: no context");
		ଫେରନ୍ତୁ (0);
	}
	ଯଦି (ctx->encrypt) {
		cnow  = dest;
		plain = (u_char *)src;
		cprev = c->r_iv;
		ପାଇଁ (i = 0; i < blocks; i++, plain+=RIJNDAEL_BLOCKSIZE,
		    cnow+=RIJNDAEL_BLOCKSIZE) {
			ପାଇଁ (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				buf[j] = plain[j] ^ cprev[j];
			rijndael_encrypt(&c->r_ctx, buf, cnow);
			cprev = cnow;
		}
		memcpy(c->r_iv, cprev, RIJNDAEL_BLOCKSIZE);
	} ଅନ୍ୟଥା {
		cnow  = (u_char *) (src+len-RIJNDAEL_BLOCKSIZE);
		plain = dest+len-RIJNDAEL_BLOCKSIZE;

		memcpy(buf, cnow, RIJNDAEL_BLOCKSIZE);
		ପାଇଁ (i = blocks; i > 0; i--, cnow-=RIJNDAEL_BLOCKSIZE,
		    plain-=RIJNDAEL_BLOCKSIZE) {
			rijndael_decrypt(&c->r_ctx, cnow, plain);
			ivp = (i == 1) ? c->r_iv : cnow-RIJNDAEL_BLOCKSIZE;
			ପାଇଁ (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				plain[j] ^= ivp[j];
		}
		memcpy(c->r_iv, buf, RIJNDAEL_BLOCKSIZE);
	}
	ଫେରନ୍ତୁ (1);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_rijndael_cleanup(EVP_CIPHER_CTX *ctx)
{
	ସଂରଚନା ssh_rijndael_ctx *c;

	ଯଦି ((c = EVP_CIPHER_CTX_get_app_data(ctx)) != ଖାଲି) {
		memset(c, 0, ଆକାର(*c));
		ମୁକ୍ତ(c);
		EVP_CIPHER_CTX_set_app_data(ctx, ଖାଲି);
	}
	ଫେରନ୍ତୁ (1);
}

ଶୂନ୍ୟ
ssh_rijndael_iv(EVP_CIPHER_CTX *evp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା doset, u_char * iv, u_int len)
{
	ସଂରଚନା ssh_rijndael_ctx *c;

	ଯଦି ((c = EVP_CIPHER_CTX_get_app_data(evp)) == ଖାଲି)
		fatal("ssh_rijndael_iv: no context");
	ଯଦି (doset)
		memcpy(c->r_iv, iv, len);
	ଅନ୍ୟଥା
		memcpy(iv, c->r_iv, len);
}

ଅଚଳ EVP_CIPHER *
evp_rijndael(ଶୂନ୍ୟ)
{
	ସ୍ଥିର EVP_CIPHER rijndal_cbc;

	memset(&rijndal_cbc, 0, ଆକାର(EVP_CIPHER));
	rijndal_cbc.nid = NID_undef;
	rijndal_cbc.block_size = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.iv_len = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.ଚାବି_len = 16;
	rijndal_cbc.init = ssh_rijndael_init;
	rijndal_cbc.cleanup = ssh_rijndael_cleanup;
	rijndal_cbc.do_cipher = ssh_rijndael_cbc;
#ifndef SSH_OLD_EVP
	rijndal_cbc.flags = EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_LENGTH |
	    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV;
#endif
	ଫେରନ୍ତୁ (&rijndal_cbc);
}
#endif /* USE_BUILTIN_RIJNDAEL */
