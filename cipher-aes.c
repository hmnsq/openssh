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

#अन्तर्भाव "includes.h"

/* compatibility with old or broken OpenSSL versions */
#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#ifdef USE_BUILTIN_RIJNDAEL
#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <openssl/evp.h>

#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "rijndael.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "log.h"

#define RIJNDAEL_BLOCKSIZE 16
संरचना ssh_rijndael_ctx
{
	rijndael_ctx	r_ctx;
	u_char		r_iv[RIJNDAEL_BLOCKSIZE];
};

स्थिर पूर्णांक
ssh_rijndael_init(EVP_CIPHER_CTX *ctx, स्थिरांक u_char *किल्ली, स्थिरांक u_char *iv,
    पूर्णांक enc)
{
	संरचना ssh_rijndael_ctx *c;

	जर ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == रिक्त) {
		c = xmalloc(आकार(*c));
		EVP_CIPHER_CTX_set_app_data(ctx, c);
	}
	जर (किल्ली != रिक्त) {
		जर (enc == -1)
			enc = ctx->encrypt;
		rijndael_set_किल्ली(&c->r_ctx, (u_char *)किल्ली,
		    8*EVP_CIPHER_CTX_किल्ली_length(ctx), enc);
	}
	जर (iv != रिक्त)
		स_नकल(c->r_iv, iv, RIJNDAEL_BLOCKSIZE);
	परत (1);
}

स्थिर पूर्णांक
ssh_rijndael_cbc(EVP_CIPHER_CTX *ctx, u_char *dest, स्थिरांक u_char *src,
    माप_प्रकार len)
{
	संरचना ssh_rijndael_ctx *c;
	u_char buf[RIJNDAEL_BLOCKSIZE];
	u_char *cprev, *cnow, *plain, *ivp;
	पूर्णांक i, j, blocks = len / RIJNDAEL_BLOCKSIZE;

	जर (len == 0)
		परत (1);
	जर (len % RIJNDAEL_BLOCKSIZE)
		fatal("ssh_rijndael_cbc: bad len %d", len);
	जर ((c = EVP_CIPHER_CTX_get_app_data(ctx)) == रिक्त) {
		error("ssh_rijndael_cbc: no context");
		परत (0);
	}
	जर (ctx->encrypt) {
		cnow  = dest;
		plain = (u_char *)src;
		cprev = c->r_iv;
		साठी (i = 0; i < blocks; i++, plain+=RIJNDAEL_BLOCKSIZE,
		    cnow+=RIJNDAEL_BLOCKSIZE) {
			साठी (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				buf[j] = plain[j] ^ cprev[j];
			rijndael_encrypt(&c->r_ctx, buf, cnow);
			cprev = cnow;
		}
		स_नकल(c->r_iv, cprev, RIJNDAEL_BLOCKSIZE);
	} अन्यथा {
		cnow  = (u_char *) (src+len-RIJNDAEL_BLOCKSIZE);
		plain = dest+len-RIJNDAEL_BLOCKSIZE;

		स_नकल(buf, cnow, RIJNDAEL_BLOCKSIZE);
		साठी (i = blocks; i > 0; i--, cnow-=RIJNDAEL_BLOCKSIZE,
		    plain-=RIJNDAEL_BLOCKSIZE) {
			rijndael_decrypt(&c->r_ctx, cnow, plain);
			ivp = (i == 1) ? c->r_iv : cnow-RIJNDAEL_BLOCKSIZE;
			साठी (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				plain[j] ^= ivp[j];
		}
		स_नकल(c->r_iv, buf, RIJNDAEL_BLOCKSIZE);
	}
	परत (1);
}

स्थिर पूर्णांक
ssh_rijndael_cleanup(EVP_CIPHER_CTX *ctx)
{
	संरचना ssh_rijndael_ctx *c;

	जर ((c = EVP_CIPHER_CTX_get_app_data(ctx)) != रिक्त) {
		स_रखो(c, 0, आकार(*c));
		मुक्त(c);
		EVP_CIPHER_CTX_set_app_data(ctx, रिक्त);
	}
	परत (1);
}

शून्य
ssh_rijndael_iv(EVP_CIPHER_CTX *evp, पूर्णांक doset, u_char * iv, u_int len)
{
	संरचना ssh_rijndael_ctx *c;

	जर ((c = EVP_CIPHER_CTX_get_app_data(evp)) == रिक्त)
		fatal("ssh_rijndael_iv: no context");
	जर (doset)
		स_नकल(c->r_iv, iv, len);
	अन्यथा
		स_नकल(iv, c->r_iv, len);
}

स्थिरांक EVP_CIPHER *
evp_rijndael(शून्य)
{
	स्थिर EVP_CIPHER rijndal_cbc;

	स_रखो(&rijndal_cbc, 0, आकार(EVP_CIPHER));
	rijndal_cbc.nid = NID_undef;
	rijndal_cbc.block_size = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.iv_len = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.किल्ली_len = 16;
	rijndal_cbc.init = ssh_rijndael_init;
	rijndal_cbc.cleanup = ssh_rijndael_cleanup;
	rijndal_cbc.do_cipher = ssh_rijndael_cbc;
#ifndef SSH_OLD_EVP
	rijndal_cbc.flags = EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_LENGTH |
	    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV;
#endif
	परत (&rijndal_cbc);
}
#endif /* USE_BUILTIN_RIJNDAEL */
