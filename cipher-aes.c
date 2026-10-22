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

#அந்தர்பாவ "includes.h"

/* compatibility with old or broken OpenSSL versions */
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

#ifdef USE_BUILTIN_RIJNDAEL
#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <openssl/evp.h>

#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "rijndael.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "log.h"

#define RIJNDAEL_BLOCKSIZE 16
கட்டமைப்பு ssh_rijndael_ctx
{
	rijndael_ctx	r_ctx;
	u_char		r_iv[RIJNDAEL_BLOCKSIZE];
};

நிலையான முழு
ssh_rijndael_init(EVP_CIPHER_CTX *ctx, மாறிலி u_char *சாவி, மாறிலி u_char *iv,
    முழு enc)
{
	கட்டமைப்பு ssh_rijndael_ctx *c;

	எனில் ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == வெற்று) {
		c = xmalloc(அளவு(*c));
		EVP_CIPHER_CTX_set_app_data(ctx, c);
	}
	எனில் (சாவி != வெற்று) {
		எனில் (enc == -1)
			enc = ctx->encrypt;
		rijndael_set_சாவி(&c->r_ctx, (u_char *)சாவி,
		    8*EVP_CIPHER_CTX_சாவி_length(ctx), enc);
	}
	எனில் (iv != வெற்று)
		memcpy(c->r_iv, iv, RIJNDAEL_BLOCKSIZE);
	திரும்பு (1);
}

நிலையான முழு
ssh_rijndael_cbc(EVP_CIPHER_CTX *ctx, u_char *dest, மாறிலி u_char *src,
    size_t len)
{
	கட்டமைப்பு ssh_rijndael_ctx *c;
	u_char buf[RIJNDAEL_BLOCKSIZE];
	u_char *cprev, *cnow, *plain, *ivp;
	முழு i, j, blocks = len / RIJNDAEL_BLOCKSIZE;

	எனில் (len == 0)
		திரும்பு (1);
	எனில் (len % RIJNDAEL_BLOCKSIZE)
		fatal("ssh_rijndael_cbc: bad len %d", len);
	எனில் ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == வெற்று) {
		error("ssh_rijndael_cbc: no context");
		திரும்பு (0);
	}
	எனில் (ctx->encrypt) {
		cnow  = dest;
		plain = (u_char *)src;
		cprev = c->r_iv;
		க்கு (i = 0; i < blocks; i++, plain+=RIJNDAEL_BLOCKSIZE,
		    cnow+=RIJNDAEL_BLOCKSIZE) {
			க்கு (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				buf[j] = plain[j] ^ cprev[j];
			rijndael_encrypt(&c->r_ctx, buf, cnow);
			cprev = cnow;
		}
		memcpy(c->r_iv, cprev, RIJNDAEL_BLOCKSIZE);
	} இல்லையெனில் {
		cnow  = (u_char *) (src+len-RIJNDAEL_BLOCKSIZE);
		plain = dest+len-RIJNDAEL_BLOCKSIZE;

		memcpy(buf, cnow, RIJNDAEL_BLOCKSIZE);
		க்கு (i = blocks; i > 0; i--, cnow-=RIJNDAEL_BLOCKSIZE,
		    plain-=RIJNDAEL_BLOCKSIZE) {
			rijndael_decrypt(&c->r_ctx, cnow, plain);
			ivp = (i == 1) ? c->r_iv : cnow-RIJNDAEL_BLOCKSIZE;
			க்கு (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				plain[j] ^= ivp[j];
		}
		memcpy(c->r_iv, buf, RIJNDAEL_BLOCKSIZE);
	}
	திரும்பு (1);
}

நிலையான முழு
ssh_rijndael_cleanup(EVP_CIPHER_CTX *ctx)
{
	கட்டமைப்பு ssh_rijndael_ctx *c;

	எனில் ((c = EVP_CIPHER_CTX_get_app_data(ctx)) != வெற்று) {
		memset(c, 0, அளவு(*c));
		விடுவி(c);
		EVP_CIPHER_CTX_set_app_data(ctx, வெற்று);
	}
	திரும்பு (1);
}

வெறுமை
ssh_rijndael_iv(EVP_CIPHER_CTX *evp, முழு doset, u_char * iv, u_int len)
{
	கட்டமைப்பு ssh_rijndael_ctx *c;

	எனில் ((c = EVP_CIPHER_CTX_get_app_data(evp)) == வெற்று)
		fatal("ssh_rijndael_iv: no context");
	எனில் (doset)
		memcpy(c->r_iv, iv, len);
	இல்லையெனில்
		memcpy(iv, c->r_iv, len);
}

மாறிலி EVP_CIPHER *
evp_rijndael(வெறுமை)
{
	நிலையான EVP_CIPHER rijndal_cbc;

	memset(&rijndal_cbc, 0, அளவு(EVP_CIPHER));
	rijndal_cbc.nid = NID_undef;
	rijndal_cbc.block_size = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.iv_len = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.சாவி_len = 16;
	rijndal_cbc.init = ssh_rijndael_init;
	rijndal_cbc.cleanup = ssh_rijndael_cleanup;
	rijndal_cbc.do_cipher = ssh_rijndael_cbc;
#ifndef SSH_OLD_EVP
	rijndal_cbc.flags = EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_LENGTH |
	    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV;
#endif
	திரும்பு (&rijndal_cbc);
}
#endif /* USE_BUILTIN_RIJNDAEL */
