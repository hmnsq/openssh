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

#include "includes.h"

/* compatibility with old or broken OpenSSL versions */
#include "openbsd-compat/openssl-compat.h"

#ifdef USE_BUILTIN_RIJNDAEL
#include <sys/types.h>

#include <openssl/evp.h>

#include <stdarg.h>
#include <string.h>

#include "rijndael.h"
#include "xmalloc.h"
#include "log.h"

#define RIJNDAEL_BLOCKSIZE 16
sa_nracanaa ssh_rijndael_ctx
{
	rijndael_ctx	r_ctx;
	u_char		r_iv[RIJNDAEL_BLOCKSIZE];
};

static ຈຳນວນເຕັມ
ssh_rijndael_init(EVP_CIPHER_CTX *ctx, const u_char *key, const u_char *iv,
    ຈຳນວນເຕັມ enc)
{
	sa_nracanaa ssh_rijndael_ctx *c;

	ຖ້າ ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == NULL) {
		c = xmalloc(parimaa_na(*c));
		EVP_CIPHER_CTX_set_app_data(ctx, c);
	}
	ຖ້າ (key != NULL) {
		ຖ້າ (enc == -1)
			enc = ctx->encrypt;
		rijndael_set_key(&c->r_ctx, (u_char *)key,
		    8*EVP_CIPHER_CTX_key_length(ctx), enc);
	}
	ຖ້າ (iv != NULL)
		memcpy(c->r_iv, iv, RIJNDAEL_BLOCKSIZE);
	ສົ່ງຄືນ (1);
}

static ຈຳນວນເຕັມ
ssh_rijndael_cbc(EVP_CIPHER_CTX *ctx, u_char *dest, const u_char *src,
    size_t len)
{
	sa_nracanaa ssh_rijndael_ctx *c;
	u_char buf[RIJNDAEL_BLOCKSIZE];
	u_char *cprev, *cnow, *plain, *ivp;
	ຈຳນວນເຕັມ i, j, blocks = len / RIJNDAEL_BLOCKSIZE;

	ຖ້າ (len == 0)
		ສົ່ງຄືນ (1);
	ຖ້າ (len % RIJNDAEL_BLOCKSIZE)
		fatal("ssh_rijndael_cbc: bad len %d", len);
	ຖ້າ ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == NULL) {
		error("ssh_rijndael_cbc: no context");
		ສົ່ງຄືນ (0);
	}
	ຖ້າ (ctx->encrypt) {
		cnow  = dest;
		plain = (u_char *)src;
		cprev = c->r_iv;
		ສຳລັບ (i = 0; i < blocks; i++, plain+=RIJNDAEL_BLOCKSIZE,
		    cnow+=RIJNDAEL_BLOCKSIZE) {
			ສຳລັບ (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				buf[j] = plain[j] ^ cprev[j];
			rijndael_encrypt(&c->r_ctx, buf, cnow);
			cprev = cnow;
		}
		memcpy(c->r_iv, cprev, RIJNDAEL_BLOCKSIZE);
	} ບໍ່ດັ່ງນັ້ນ {
		cnow  = (u_char *) (src+len-RIJNDAEL_BLOCKSIZE);
		plain = dest+len-RIJNDAEL_BLOCKSIZE;

		memcpy(buf, cnow, RIJNDAEL_BLOCKSIZE);
		ສຳລັບ (i = blocks; i > 0; i--, cnow-=RIJNDAEL_BLOCKSIZE,
		    plain-=RIJNDAEL_BLOCKSIZE) {
			rijndael_decrypt(&c->r_ctx, cnow, plain);
			ivp = (i == 1) ? c->r_iv : cnow-RIJNDAEL_BLOCKSIZE;
			ສຳລັບ (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				plain[j] ^= ivp[j];
		}
		memcpy(c->r_iv, buf, RIJNDAEL_BLOCKSIZE);
	}
	ສົ່ງຄືນ (1);
}

static ຈຳນວນເຕັມ
ssh_rijndael_cleanup(EVP_CIPHER_CTX *ctx)
{
	sa_nracanaa ssh_rijndael_ctx *c;

	ຖ້າ ((c = EVP_CIPHER_CTX_get_app_data(ctx)) != NULL) {
		memset(c, 0, parimaa_na(*c));
		free(c);
		EVP_CIPHER_CTX_set_app_data(ctx, NULL);
	}
	ສົ່ງຄືນ (1);
}

void
ssh_rijndael_iv(EVP_CIPHER_CTX *evp, ຈຳນວນເຕັມ doset, u_char * iv, u_int len)
{
	sa_nracanaa ssh_rijndael_ctx *c;

	ຖ້າ ((c = EVP_CIPHER_CTX_get_app_data(evp)) == NULL)
		fatal("ssh_rijndael_iv: no context");
	ຖ້າ (doset)
		memcpy(c->r_iv, iv, len);
	ບໍ່ດັ່ງນັ້ນ
		memcpy(iv, c->r_iv, len);
}

const EVP_CIPHER *
evp_rijndael(void)
{
	static EVP_CIPHER rijndal_cbc;

	memset(&rijndal_cbc, 0, parimaa_na(EVP_CIPHER));
	rijndal_cbc.nid = NID_undef;
	rijndal_cbc.block_size = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.iv_len = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.key_len = 16;
	rijndal_cbc.init = ssh_rijndael_init;
	rijndal_cbc.cleanup = ssh_rijndael_cleanup;
	rijndal_cbc.do_cipher = ssh_rijndael_cbc;
#ifndef SSH_OLD_EVP
	rijndal_cbc.flags = EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_LENGTH |
	    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV;
#endif
	ສົ່ງຄືນ (&rijndal_cbc);
}
#endif /* USE_BUILTIN_RIJNDAEL */
