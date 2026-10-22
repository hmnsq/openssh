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

#অন্তর্ভাৱ "includes.h"

/* compatibility with old or broken OpenSSL versions */
#অন্তর্ভাৱ "openbsd-compat/openssl-compat.h"

#ifdef USE_BUILTIN_RIJNDAEL
#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <openssl/evp.h>

#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <string.h>

#অন্তর্ভাৱ "rijndael.h"
#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "log.h"

#define RIJNDAEL_BLOCKSIZE 16
সংরচনা ssh_rijndael_ctx
{
	rijndael_ctx	r_ctx;
	u_char		r_iv[RIJNDAEL_BLOCKSIZE];
};

স্থির পূর্ণাঙ্ক
ssh_rijndael_init(EVP_CIPHER_CTX *ctx, ধ্রুৱ u_char *চাবি, ধ্রুৱ u_char *iv,
    পূর্ণাঙ্ক enc)
{
	সংরচনা ssh_rijndael_ctx *c;

	যদি ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == রিক্ত) {
		c = xmalloc(পরিমাণ(*c));
		EVP_CIPHER_CTX_set_app_data(ctx, c);
	}
	যদি (চাবি != রিক্ত) {
		যদি (enc == -1)
			enc = ctx->encrypt;
		rijndael_set_চাবি(&c->r_ctx, (u_char *)চাবি,
		    8*EVP_CIPHER_CTX_চাবি_length(ctx), enc);
	}
	যদি (iv != রিক্ত)
		memcpy(c->r_iv, iv, RIJNDAEL_BLOCKSIZE);
	ঘূৰাই (1);
}

স্থির পূর্ণাঙ্ক
ssh_rijndael_cbc(EVP_CIPHER_CTX *ctx, u_char *dest, ধ্রুৱ u_char *src,
    size_t len)
{
	সংরচনা ssh_rijndael_ctx *c;
	u_char buf[RIJNDAEL_BLOCKSIZE];
	u_char *cprev, *cnow, *plain, *ivp;
	পূর্ণাঙ্ক i, j, blocks = len / RIJNDAEL_BLOCKSIZE;

	যদি (len == 0)
		ঘূৰাই (1);
	যদি (len % RIJNDAEL_BLOCKSIZE)
		fatal("ssh_rijndael_cbc: bad len %d", len);
	যদি ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == রিক্ত) {
		error("ssh_rijndael_cbc: no context");
		ঘূৰাই (0);
	}
	যদি (ctx->encrypt) {
		cnow  = dest;
		plain = (u_char *)src;
		cprev = c->r_iv;
		বাবে (i = 0; i < blocks; i++, plain+=RIJNDAEL_BLOCKSIZE,
		    cnow+=RIJNDAEL_BLOCKSIZE) {
			বাবে (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				buf[j] = plain[j] ^ cprev[j];
			rijndael_encrypt(&c->r_ctx, buf, cnow);
			cprev = cnow;
		}
		memcpy(c->r_iv, cprev, RIJNDAEL_BLOCKSIZE);
	} অন্যথা {
		cnow  = (u_char *) (src+len-RIJNDAEL_BLOCKSIZE);
		plain = dest+len-RIJNDAEL_BLOCKSIZE;

		memcpy(buf, cnow, RIJNDAEL_BLOCKSIZE);
		বাবে (i = blocks; i > 0; i--, cnow-=RIJNDAEL_BLOCKSIZE,
		    plain-=RIJNDAEL_BLOCKSIZE) {
			rijndael_decrypt(&c->r_ctx, cnow, plain);
			ivp = (i == 1) ? c->r_iv : cnow-RIJNDAEL_BLOCKSIZE;
			বাবে (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				plain[j] ^= ivp[j];
		}
		memcpy(c->r_iv, buf, RIJNDAEL_BLOCKSIZE);
	}
	ঘূৰাই (1);
}

স্থির পূর্ণাঙ্ক
ssh_rijndael_cleanup(EVP_CIPHER_CTX *ctx)
{
	সংরচনা ssh_rijndael_ctx *c;

	যদি ((c = EVP_CIPHER_CTX_get_app_data(ctx)) != রিক্ত) {
		memset(c, 0, পরিমাণ(*c));
		মুক্ত(c);
		EVP_CIPHER_CTX_set_app_data(ctx, রিক্ত);
	}
	ঘূৰাই (1);
}

শূন্য
ssh_rijndael_iv(EVP_CIPHER_CTX *evp, পূর্ণাঙ্ক doset, u_char * iv, u_int len)
{
	সংরচনা ssh_rijndael_ctx *c;

	যদি ((c = EVP_CIPHER_CTX_get_app_data(evp)) == রিক্ত)
		fatal("ssh_rijndael_iv: no context");
	যদি (doset)
		memcpy(c->r_iv, iv, len);
	অন্যথা
		memcpy(iv, c->r_iv, len);
}

ধ্রুৱ EVP_CIPHER *
evp_rijndael(শূন্য)
{
	স্থির EVP_CIPHER rijndal_cbc;

	memset(&rijndal_cbc, 0, পরিমাণ(EVP_CIPHER));
	rijndal_cbc.nid = NID_undef;
	rijndal_cbc.block_size = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.iv_len = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.চাবি_len = 16;
	rijndal_cbc.init = ssh_rijndael_init;
	rijndal_cbc.cleanup = ssh_rijndael_cleanup;
	rijndal_cbc.do_cipher = ssh_rijndael_cbc;
#ifndef SSH_OLD_EVP
	rijndal_cbc.flags = EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_LENGTH |
	    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV;
#endif
	ঘূৰাই (&rijndal_cbc);
}
#endif /* USE_BUILTIN_RIJNDAEL */
