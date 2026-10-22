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

#ضمن "includes.h"

/* compatibility with old or broken OpenSSL versions */
#ضمن "openbsd-compat/openssl-compat.h"

#جيڪڏهن_وصف_ٿيل USE_BUILTIN_RIJNDAEL
#ضمن <sys/types.h>

#ضمن <openssl/evp.h>

#ضمن <stdarg.h>
#ضمن <string.h>

#ضمن "rijndael.h"
#ضمن "xmalloc.h"
#ضمن "log.h"

#وصف_ڪريو RIJNDAEL_BLOCKSIZE 16
بنية ssh_rijndael_ctx
{
	rijndael_ctx	r_ctx;
	u_char		r_iv[RIJNDAEL_BLOCKSIZE];
};

ساكن صحيح
ssh_rijndael_init(EVP_CIPHER_CTX *ctx, ثابت u_char *ڪنجي, ثابت u_char *iv,
    صحيح enc)
{
	بنية ssh_rijndael_ctx *c;

	إذا ((c = EVP_CIPHER_CTX_get_app_معلومات(ctx)) == عدم) {
		c = xmalloc(حجم(*c));
		EVP_CIPHER_CTX_سيٽ_app_معلومات(ctx, c);
	}
	إذا (ڪنجي != عدم) {
		إذا (enc == -1)
			enc = ctx->encrypt;
		rijndael_سيٽ_ڪنجي(&c->r_ctx, (u_char *)ڪنجي,
		    8*EVP_CIPHER_CTX_ڪنجي_ڊيگهائي(ctx), enc);
	}
	إذا (iv != عدم)
		يادگيري_نقل(c->r_iv, iv, RIJNDAEL_BLOCKSIZE);
	أرجع (1);
}

ساكن صحيح
ssh_rijndael_cbc(EVP_CIPHER_CTX *ctx, u_char *dest, ثابت u_char *src,
    سائيز_t len)
{
	بنية ssh_rijndael_ctx *c;
	u_char buf[RIJNDAEL_BLOCKSIZE];
	u_char *cprev, *cnow, *plain, *ivp;
	صحيح i, j, بلاڪون = len / RIJNDAEL_BLOCKSIZE;

	إذا (len == 0)
		أرجع (1);
	إذا (len % RIJNDAEL_BLOCKSIZE)
		fatal("ssh_rijndael_cbc: bad len %d", len);
	إذا ((c = EVP_CIPHER_CTX_get_app_معلومات(ctx)) == عدم) {
		error("ssh_rijndael_cbc: no context");
		أرجع (0);
	}
	إذا (ctx->encrypt) {
		cnow  = dest;
		plain = (u_char *)src;
		cprev = c->r_iv;
		لكل (i = 0; i < بلاڪون; i++, plain+=RIJNDAEL_BLOCKSIZE,
		    cnow+=RIJNDAEL_BLOCKSIZE) {
			لكل (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				buf[j] = plain[j] ^ cprev[j];
			rijndael_encrypt(&c->r_ctx, buf, cnow);
			cprev = cnow;
		}
		يادگيري_نقل(c->r_iv, cprev, RIJNDAEL_BLOCKSIZE);
	} وإلا {
		cnow  = (u_char *) (src+len-RIJNDAEL_BLOCKSIZE);
		plain = dest+len-RIJNDAEL_BLOCKSIZE;

		يادگيري_نقل(buf, cnow, RIJNDAEL_BLOCKSIZE);
		لكل (i = بلاڪون; i > 0; i--, cnow-=RIJNDAEL_BLOCKSIZE,
		    plain-=RIJNDAEL_BLOCKSIZE) {
			rijndael_decrypt(&c->r_ctx, cnow, plain);
			ivp = (i == 1) ? c->r_iv : cnow-RIJNDAEL_BLOCKSIZE;
			لكل (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				plain[j] ^= ivp[j];
		}
		يادگيري_نقل(c->r_iv, buf, RIJNDAEL_BLOCKSIZE);
	}
	أرجع (1);
}

ساكن صحيح
ssh_rijndael_cleanup(EVP_CIPHER_CTX *ctx)
{
	بنية ssh_rijndael_ctx *c;

	إذا ((c = EVP_CIPHER_CTX_get_app_معلومات(ctx)) != عدم) {
		memset(c, 0, حجم(*c));
		حرر(c);
		EVP_CIPHER_CTX_سيٽ_app_معلومات(ctx, عدم);
	}
	أرجع (1);
}

فراغ
ssh_rijndael_iv(EVP_CIPHER_CTX *evp, صحيح doset, u_char * iv, u_int len)
{
	بنية ssh_rijndael_ctx *c;

	إذا ((c = EVP_CIPHER_CTX_get_app_معلومات(evp)) == عدم)
		fatal("ssh_rijndael_iv: no context");
	إذا (doset)
		يادگيري_نقل(c->r_iv, iv, len);
	وإلا
		يادگيري_نقل(iv, c->r_iv, len);
}

ثابت EVP_CIPHER *
evp_rijndael(فراغ)
{
	ساكن EVP_CIPHER rijndal_cbc;

	memset(&rijndal_cbc, 0, حجم(EVP_CIPHER));
	rijndal_cbc.nid = NID_undef;
	rijndal_cbc.بلاڪ_سائيز = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.iv_len = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.ڪنجي_len = 16;
	rijndal_cbc.init = ssh_rijndael_init;
	rijndal_cbc.cleanup = ssh_rijndael_cleanup;
	rijndal_cbc.do_cipher = ssh_rijndael_cbc;
#جيڪڏهن_وصف_نه_ٿيل SSH_OLD_EVP
	rijndal_cbc.flags = EVP_CIPH_CBC_گهڻائي | EVP_CIPH_VARIABLE_ڊيگهائي |
	    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV;
#جيڪڏهن_پورو
	أرجع (&rijndal_cbc);
}
#جيڪڏهن_پورو /* USE_BUILTIN_RIJNDAEL */
