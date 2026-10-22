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

#اگر_تعریف_شدہ USE_BUILTIN_RIJNDAEL
#شامل <sys/types.h>

#شامل <openssl/evp.h>

#شامل <stdarg.h>
#شامل <string.h>

#شامل "rijndael.h"
#شامل "xmalloc.h"
#شامل "log.h"

#تعریف_کرو RIJNDAEL_BLOCKSIZE 16
ساخت ssh_rijndael_ctx
{
	rijndael_ctx	r_ctx;
	u_char		r_iv[RIJNDAEL_BLOCKSIZE];
};

ساکن صحیح
ssh_rijndael_init(EVP_CIPHER_CTX *ctx, ثابت u_char *کلید, ثابت u_char *iv,
    صحیح enc)
{
	ساخت ssh_rijndael_ctx *c;

	اگر ((c = EVP_CIPHER_CTX_get_app_ڈیٹا(ctx)) == تہی) {
		c = xmalloc(حجم(*c));
		EVP_CIPHER_CTX_سیٹ_app_ڈیٹا(ctx, c);
	}
	اگر (کلید != تہی) {
		اگر (enc == -1)
			enc = ctx->encrypt;
		rijndael_سیٹ_کلید(&c->r_ctx, (u_char *)کلید,
		    8*EVP_CIPHER_CTX_کلید_لمبائی(ctx), enc);
	}
	اگر (iv != تہی)
		حافظہ_نقل(c->r_iv, iv, RIJNDAEL_BLOCKSIZE);
	واپس (1);
}

ساکن صحیح
ssh_rijndael_cbc(EVP_CIPHER_CTX *ctx, u_char *dest, ثابت u_char *src,
    سائز_t len)
{
	ساخت ssh_rijndael_ctx *c;
	u_char buf[RIJNDAEL_BLOCKSIZE];
	u_char *cprev, *cnow, *plain, *ivp;
	صحیح i, j, بلاکیں = len / RIJNDAEL_BLOCKSIZE;

	اگر (len == 0)
		واپس (1);
	اگر (len % RIJNDAEL_BLOCKSIZE)
		fatal("ssh_rijndael_cbc: bad len %d", len);
	اگر ((c = EVP_CIPHER_CTX_get_app_ڈیٹا(ctx)) == تہی) {
		error("ssh_rijndael_cbc: no context");
		واپس (0);
	}
	اگر (ctx->encrypt) {
		cnow  = dest;
		plain = (u_char *)src;
		cprev = c->r_iv;
		برائے (i = 0; i < بلاکیں; i++, plain+=RIJNDAEL_BLOCKSIZE,
		    cnow+=RIJNDAEL_BLOCKSIZE) {
			برائے (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				buf[j] = plain[j] ^ cprev[j];
			rijndael_encrypt(&c->r_ctx, buf, cnow);
			cprev = cnow;
		}
		حافظہ_نقل(c->r_iv, cprev, RIJNDAEL_BLOCKSIZE);
	} ورنہ {
		cnow  = (u_char *) (src+len-RIJNDAEL_BLOCKSIZE);
		plain = dest+len-RIJNDAEL_BLOCKSIZE;

		حافظہ_نقل(buf, cnow, RIJNDAEL_BLOCKSIZE);
		برائے (i = بلاکیں; i > 0; i--, cnow-=RIJNDAEL_BLOCKSIZE,
		    plain-=RIJNDAEL_BLOCKSIZE) {
			rijndael_decrypt(&c->r_ctx, cnow, plain);
			ivp = (i == 1) ? c->r_iv : cnow-RIJNDAEL_BLOCKSIZE;
			برائے (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				plain[j] ^= ivp[j];
		}
		حافظہ_نقل(c->r_iv, buf, RIJNDAEL_BLOCKSIZE);
	}
	واپس (1);
}

ساکن صحیح
ssh_rijndael_cleanup(EVP_CIPHER_CTX *ctx)
{
	ساخت ssh_rijndael_ctx *c;

	اگر ((c = EVP_CIPHER_CTX_get_app_ڈیٹا(ctx)) != تہی) {
		memset(c, 0, حجم(*c));
		آزاد(c);
		EVP_CIPHER_CTX_سیٹ_app_ڈیٹا(ctx, تہی);
	}
	واپس (1);
}

خالی
ssh_rijndael_iv(EVP_CIPHER_CTX *evp, صحیح doset, u_char * iv, u_int len)
{
	ساخت ssh_rijndael_ctx *c;

	اگر ((c = EVP_CIPHER_CTX_get_app_ڈیٹا(evp)) == تہی)
		fatal("ssh_rijndael_iv: no context");
	اگر (doset)
		حافظہ_نقل(c->r_iv, iv, len);
	ورنہ
		حافظہ_نقل(iv, c->r_iv, len);
}

ثابت EVP_CIPHER *
evp_rijndael(خالی)
{
	ساکن EVP_CIPHER rijndal_cbc;

	memset(&rijndal_cbc, 0, حجم(EVP_CIPHER));
	rijndal_cbc.nid = NID_undef;
	rijndal_cbc.بلاک_سائز = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.iv_len = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.کلید_len = 16;
	rijndal_cbc.init = ssh_rijndael_init;
	rijndal_cbc.cleanup = ssh_rijndael_cleanup;
	rijndal_cbc.do_cipher = ssh_rijndael_cbc;
#اگر_غیر_تعریف_شدہ SSH_OLD_EVP
	rijndal_cbc.flags = EVP_CIPH_CBC_منوال | EVP_CIPH_VARIABLE_لمبائی |
	    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV;
#اگر_ختم
	واپس (&rijndal_cbc);
}
#اگر_ختم /* USE_BUILTIN_RIJNDAEL */
