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

#అన్తర్భావ "includes.h"

/* compatibility with old or broken OpenSSL versions */
#అన్తర్భావ "openbsd-compat/openssl-compat.h"

#నిర్వచితమైతే USE_BUILTIN_RIJNDAEL
#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <openssl/evp.h>

#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "rijndael.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "log.h"

#నిర్వచించు RIJNDAEL_BLOCKSIZE 16
నిర్మాణం ssh_rijndael_ctx
{
	rijndael_ctx	r_ctx;
	u_char		r_iv[RIJNDAEL_BLOCKSIZE];
};

స్థిర పూర్ణాంకం
ssh_rijndael_init(EVP_CIPHER_CTX *ctx, స్థిరరాశి u_char *కీలకం, స్థిరరాశి u_char *iv,
    పూర్ణాంకం enc)
{
	నిర్మాణం ssh_rijndael_ctx *c;

	ఒకవేళ ((c = EVP_CIPHER_CTX_get_app_దత్తాంశం(ctx)) == ఖాళీ) {
		c = xmalloc(పరిమాణం(*c));
		EVP_CIPHER_CTX_సమితి_app_దత్తాంశం(ctx, c);
	}
	ఒకవేళ (కీలకం != ఖాళీ) {
		ఒకవేళ (enc == -1)
			enc = ctx->encrypt;
		rijndael_సమితి_కీలకం(&c->r_ctx, (u_char *)కీలకం,
		    8*EVP_CIPHER_CTX_కీలకం_నిడివి(ctx), enc);
	}
	ఒకవేళ (iv != ఖాళీ)
		జ్ఞాపకం_నకలు(c->r_iv, iv, RIJNDAEL_BLOCKSIZE);
	తిరిగి (1);
}

స్థిర పూర్ణాంకం
ssh_rijndael_cbc(EVP_CIPHER_CTX *ctx, u_char *dest, స్థిరరాశి u_char *src,
    కొలత_t len)
{
	నిర్మాణం ssh_rijndael_ctx *c;
	u_char buf[RIJNDAEL_BLOCKSIZE];
	u_char *cprev, *cnow, *plain, *ivp;
	పూర్ణాంకం i, j, ఖండాలు = len / RIJNDAEL_BLOCKSIZE;

	ఒకవేళ (len == 0)
		తిరిగి (1);
	ఒకవేళ (len % RIJNDAEL_BLOCKSIZE)
		fatal("ssh_rijndael_cbc: bad len %d", len);
	ఒకవేళ ((c = EVP_CIPHER_CTX_get_app_దత్తాంశం(ctx)) == ఖాళీ) {
		error("ssh_rijndael_cbc: no context");
		తిరిగి (0);
	}
	ఒకవేళ (ctx->encrypt) {
		cnow  = dest;
		plain = (u_char *)src;
		cprev = c->r_iv;
		కొరకు (i = 0; i < ఖండాలు; i++, plain+=RIJNDAEL_BLOCKSIZE,
		    cnow+=RIJNDAEL_BLOCKSIZE) {
			కొరకు (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				buf[j] = plain[j] ^ cprev[j];
			rijndael_encrypt(&c->r_ctx, buf, cnow);
			cprev = cnow;
		}
		జ్ఞాపకం_నకలు(c->r_iv, cprev, RIJNDAEL_BLOCKSIZE);
	} లేకపోతే {
		cnow  = (u_char *) (src+len-RIJNDAEL_BLOCKSIZE);
		plain = dest+len-RIJNDAEL_BLOCKSIZE;

		జ్ఞాపకం_నకలు(buf, cnow, RIJNDAEL_BLOCKSIZE);
		కొరకు (i = ఖండాలు; i > 0; i--, cnow-=RIJNDAEL_BLOCKSIZE,
		    plain-=RIJNDAEL_BLOCKSIZE) {
			rijndael_decrypt(&c->r_ctx, cnow, plain);
			ivp = (i == 1) ? c->r_iv : cnow-RIJNDAEL_BLOCKSIZE;
			కొరకు (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				plain[j] ^= ivp[j];
		}
		జ్ఞాపకం_నకలు(c->r_iv, buf, RIJNDAEL_BLOCKSIZE);
	}
	తిరిగి (1);
}

స్థిర పూర్ణాంకం
ssh_rijndael_cleanup(EVP_CIPHER_CTX *ctx)
{
	నిర్మాణం ssh_rijndael_ctx *c;

	ఒకవేళ ((c = EVP_CIPHER_CTX_get_app_దత్తాంశం(ctx)) != ఖాళీ) {
		memset(c, 0, పరిమాణం(*c));
		విడుదల(c);
		EVP_CIPHER_CTX_సమితి_app_దత్తాంశం(ctx, ఖాళీ);
	}
	తిరిగి (1);
}

శూన్య
ssh_rijndael_iv(EVP_CIPHER_CTX *evp, పూర్ణాంకం doset, u_char * iv, u_int len)
{
	నిర్మాణం ssh_rijndael_ctx *c;

	ఒకవేళ ((c = EVP_CIPHER_CTX_get_app_దత్తాంశం(evp)) == ఖాళీ)
		fatal("ssh_rijndael_iv: no context");
	ఒకవేళ (doset)
		జ్ఞాపకం_నకలు(c->r_iv, iv, len);
	లేకపోతే
		జ్ఞాపకం_నకలు(iv, c->r_iv, len);
}

స్థిరరాశి EVP_CIPHER *
evp_rijndael(శూన్య)
{
	స్థిర EVP_CIPHER rijndal_cbc;

	memset(&rijndal_cbc, 0, పరిమాణం(EVP_CIPHER));
	rijndal_cbc.nid = NID_undef;
	rijndal_cbc.ఖండం_కొలత = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.iv_len = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.కీలకం_len = 16;
	rijndal_cbc.init = ssh_rijndael_init;
	rijndal_cbc.cleanup = ssh_rijndael_cleanup;
	rijndal_cbc.do_cipher = ssh_rijndael_cbc;
#నిర్వచితం_కాకపోతే SSH_OLD_EVP
	rijndal_cbc.flags = EVP_CIPH_CBC_బహుళకం | EVP_CIPH_VARIABLE_నిడివి |
	    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV;
#అయితే_ముగింపు
	తిరిగి (&rijndal_cbc);
}
#అయితే_ముగింపు /* USE_BUILTIN_RIJNDAEL */
