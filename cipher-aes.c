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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

/* compatibility with old or broken OpenSSL versions */
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_BUILTIN_RIJNDAEL
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "rijndael.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RIJNDAEL_BLOCKSIZE 16
ਬਣਤਰ ssh_rijndael_ctx
{
	rijndael_ctx	r_ctx;
	u_char		r_iv[RIJNDAEL_BLOCKSIZE];
};

ਸਥਿਰ ਪੂਰਨ
ssh_rijndael_init(EVP_CIPHER_CTX *ctx, ਅਚਲ u_char *ਕੁੰਜੀ, ਅਚਲ u_char *iv,
    ਪੂਰਨ enc)
{
	ਬਣਤਰ ssh_rijndael_ctx *c;

	ਜੇ ((c = EVP_CIPHER_CTX_get_app_ਅੰਕੜੇ(ctx)) == ਨਿਰਾ) {
		c = xmalloc(ਆਕਾਰ(*c));
		EVP_CIPHER_CTX_ਸੈੱਟ_app_ਅੰਕੜੇ(ctx, c);
	}
	ਜੇ (ਕੁੰਜੀ != ਨਿਰਾ) {
		ਜੇ (enc == -1)
			enc = ctx->encrypt;
		rijndael_ਸੈੱਟ_ਕੁੰਜੀ(&c->r_ctx, (u_char *)ਕੁੰਜੀ,
		    8*EVP_CIPHER_CTX_ਕੁੰਜੀ_ਲੰਮਾਈ(ctx), enc);
	}
	ਜੇ (iv != ਨਿਰਾ)
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(c->r_iv, iv, RIJNDAEL_BLOCKSIZE);
	ਵਾਪਸ (1);
}

ਸਥਿਰ ਪੂਰਨ
ssh_rijndael_cbc(EVP_CIPHER_CTX *ctx, u_char *dest, ਅਚਲ u_char *src,
    ਮਾਪ_t len)
{
	ਬਣਤਰ ssh_rijndael_ctx *c;
	u_char buf[RIJNDAEL_BLOCKSIZE];
	u_char *cprev, *cnow, *plain, *ivp;
	ਪੂਰਨ i, j, ਖੰਡਾਂ = len / RIJNDAEL_BLOCKSIZE;

	ਜੇ (len == 0)
		ਵਾਪਸ (1);
	ਜੇ (len % RIJNDAEL_BLOCKSIZE)
		fatal("ssh_rijndael_cbc: bad len %d", len);
	ਜੇ ((c = EVP_CIPHER_CTX_get_app_ਅੰਕੜੇ(ctx)) == ਨਿਰਾ) {
		error("ssh_rijndael_cbc: no context");
		ਵਾਪਸ (0);
	}
	ਜੇ (ctx->encrypt) {
		cnow  = dest;
		plain = (u_char *)src;
		cprev = c->r_iv;
		ਲਈ (i = 0; i < ਖੰਡਾਂ; i++, plain+=RIJNDAEL_BLOCKSIZE,
		    cnow+=RIJNDAEL_BLOCKSIZE) {
			ਲਈ (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				buf[j] = plain[j] ^ cprev[j];
			rijndael_encrypt(&c->r_ctx, buf, cnow);
			cprev = cnow;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(c->r_iv, cprev, RIJNDAEL_BLOCKSIZE);
	} ਨਹੀਂਤਾਂ {
		cnow  = (u_char *) (src+len-RIJNDAEL_BLOCKSIZE);
		plain = dest+len-RIJNDAEL_BLOCKSIZE;

		ਸਮ੍ਰਿਤੀ_ਨਕਲ(buf, cnow, RIJNDAEL_BLOCKSIZE);
		ਲਈ (i = ਖੰਡਾਂ; i > 0; i--, cnow-=RIJNDAEL_BLOCKSIZE,
		    plain-=RIJNDAEL_BLOCKSIZE) {
			rijndael_decrypt(&c->r_ctx, cnow, plain);
			ivp = (i == 1) ? c->r_iv : cnow-RIJNDAEL_BLOCKSIZE;
			ਲਈ (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				plain[j] ^= ivp[j];
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(c->r_iv, buf, RIJNDAEL_BLOCKSIZE);
	}
	ਵਾਪਸ (1);
}

ਸਥਿਰ ਪੂਰਨ
ssh_rijndael_cleanup(EVP_CIPHER_CTX *ctx)
{
	ਬਣਤਰ ssh_rijndael_ctx *c;

	ਜੇ ((c = EVP_CIPHER_CTX_get_app_ਅੰਕੜੇ(ctx)) != ਨਿਰਾ) {
		memset(c, 0, ਆਕਾਰ(*c));
		ਮੁਕਤ(c);
		EVP_CIPHER_CTX_ਸੈੱਟ_app_ਅੰਕੜੇ(ctx, ਨਿਰਾ);
	}
	ਵਾਪਸ (1);
}

ਖਾਲੀ
ssh_rijndael_iv(EVP_CIPHER_CTX *evp, ਪੂਰਨ doset, u_char * iv, u_int len)
{
	ਬਣਤਰ ssh_rijndael_ctx *c;

	ਜੇ ((c = EVP_CIPHER_CTX_get_app_ਅੰਕੜੇ(evp)) == ਨਿਰਾ)
		fatal("ssh_rijndael_iv: no context");
	ਜੇ (doset)
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(c->r_iv, iv, len);
	ਨਹੀਂਤਾਂ
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(iv, c->r_iv, len);
}

ਅਚਲ EVP_CIPHER *
evp_rijndael(ਖਾਲੀ)
{
	ਸਥਿਰ EVP_CIPHER rijndal_cbc;

	memset(&rijndal_cbc, 0, ਆਕਾਰ(EVP_CIPHER));
	rijndal_cbc.nid = NID_undef;
	rijndal_cbc.ਖੰਡ_ਮਾਪ = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.iv_len = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.ਕੁੰਜੀ_len = 16;
	rijndal_cbc.init = ssh_rijndael_init;
	rijndal_cbc.cleanup = ssh_rijndael_cleanup;
	rijndal_cbc.do_cipher = ssh_rijndael_cbc;
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SSH_OLD_EVP
	rijndal_cbc.flags = EVP_CIPH_CBC_ਬਹੁਲਕ | EVP_CIPH_VARIABLE_ਲੰਮਾਈ |
	    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV;
#ਜੇ_ਅੰਤ
	ਵਾਪਸ (&rijndal_cbc);
}
#ਜੇ_ਅੰਤ /* USE_BUILTIN_RIJNDAEL */
