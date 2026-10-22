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

#شامل "includes.h"

/* compatibility with old or broken OpenSSL versions */
#شامل "openbsd-compat/openssl-compat.h"

#ifdef USE_BUILTIN_RIJNDAEL
#شامل <sys/types.h>

#شامل <openssl/evp.h>

#شامل <stdarg.h>
#شامل <string.h>

#شامل "rijndael.h"
#شامل "xmalloc.h"
#شامل "log.h"

#define RIJNDAEL_BLOCKSIZE 16
ساختار ssh_rijndael_ctx
{
	rijndael_ctx	r_ctx;
	u_char		r_iv[RIJNDAEL_BLOCKSIZE];
};

ایستا صحیح
ssh_rijndael_init(EVP_CIPHER_CTX *ctx, ثابت u_char *کلید, ثابت u_char *iv,
    صحیح enc)
{
	ساختار ssh_rijndael_ctx *c;

	اگر ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == پوچ) {
		c = xmalloc(اندازه(*c));
		EVP_CIPHER_CTX_set_app_data(ctx, c);
	}
	اگر (کلید != پوچ) {
		اگر (enc == -1)
			enc = ctx->encrypt;
		rijndael_set_کلید(&c->r_ctx, (u_char *)کلید,
		    8*EVP_CIPHER_CTX_کلید_length(ctx), enc);
	}
	اگر (iv != پوچ)
		memcpy(c->r_iv, iv, RIJNDAEL_BLOCKSIZE);
	بازگشت (1);
}

ایستا صحیح
ssh_rijndael_cbc(EVP_CIPHER_CTX *ctx, u_char *dest, ثابت u_char *src,
    size_t len)
{
	ساختار ssh_rijndael_ctx *c;
	u_char buf[RIJNDAEL_BLOCKSIZE];
	u_char *cprev, *cnow, *plain, *ivp;
	صحیح i, j, blocks = len / RIJNDAEL_BLOCKSIZE;

	اگر (len == 0)
		بازگشت (1);
	اگر (len % RIJNDAEL_BLOCKSIZE)
		fatal("ssh_rijndael_cbc: bad len %d", len);
	اگر ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == پوچ) {
		error("ssh_rijndael_cbc: no context");
		بازگشت (0);
	}
	اگر (ctx->encrypt) {
		cnow  = dest;
		plain = (u_char *)src;
		cprev = c->r_iv;
		برای (i = 0; i < blocks; i++, plain+=RIJNDAEL_BLOCKSIZE,
		    cnow+=RIJNDAEL_BLOCKSIZE) {
			برای (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				buf[j] = plain[j] ^ cprev[j];
			rijndael_encrypt(&c->r_ctx, buf, cnow);
			cprev = cnow;
		}
		memcpy(c->r_iv, cprev, RIJNDAEL_BLOCKSIZE);
	} وگرنه {
		cnow  = (u_char *) (src+len-RIJNDAEL_BLOCKSIZE);
		plain = dest+len-RIJNDAEL_BLOCKSIZE;

		memcpy(buf, cnow, RIJNDAEL_BLOCKSIZE);
		برای (i = blocks; i > 0; i--, cnow-=RIJNDAEL_BLOCKSIZE,
		    plain-=RIJNDAEL_BLOCKSIZE) {
			rijndael_decrypt(&c->r_ctx, cnow, plain);
			ivp = (i == 1) ? c->r_iv : cnow-RIJNDAEL_BLOCKSIZE;
			برای (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				plain[j] ^= ivp[j];
		}
		memcpy(c->r_iv, buf, RIJNDAEL_BLOCKSIZE);
	}
	بازگشت (1);
}

ایستا صحیح
ssh_rijndael_cleanup(EVP_CIPHER_CTX *ctx)
{
	ساختار ssh_rijndael_ctx *c;

	اگر ((c = EVP_CIPHER_CTX_get_app_data(ctx)) != پوچ) {
		memset(c, 0, اندازه(*c));
		آزاد(c);
		EVP_CIPHER_CTX_set_app_data(ctx, پوچ);
	}
	بازگشت (1);
}

تهی
ssh_rijndael_iv(EVP_CIPHER_CTX *evp, صحیح doset, u_char * iv, u_int len)
{
	ساختار ssh_rijndael_ctx *c;

	اگر ((c = EVP_CIPHER_CTX_get_app_data(evp)) == پوچ)
		fatal("ssh_rijndael_iv: no context");
	اگر (doset)
		memcpy(c->r_iv, iv, len);
	وگرنه
		memcpy(iv, c->r_iv, len);
}

ثابت EVP_CIPHER *
evp_rijndael(تهی)
{
	ایستا EVP_CIPHER rijndal_cbc;

	memset(&rijndal_cbc, 0, اندازه(EVP_CIPHER));
	rijndal_cbc.nid = NID_undef;
	rijndal_cbc.block_size = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.iv_len = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.کلید_len = 16;
	rijndal_cbc.init = ssh_rijndael_init;
	rijndal_cbc.cleanup = ssh_rijndael_cleanup;
	rijndal_cbc.do_cipher = ssh_rijndael_cbc;
#ifndef SSH_OLD_EVP
	rijndal_cbc.flags = EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_LENGTH |
	    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV;
#endif
	بازگشت (&rijndal_cbc);
}
#endif /* USE_BUILTIN_RIJNDAEL */
