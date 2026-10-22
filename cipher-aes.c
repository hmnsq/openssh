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

#समावेश "includes.h"

/* compatibility with old or broken OpenSSL versions */
#समावेश "openbsd-compat/openssl-compat.h"

#अगर_घोषित USE_BUILTIN_RIJNDAEL
#समावेश <sys/types.h>

#समावेश <openssl/evp.h>

#समावेश <stdarg.h>
#समावेश <string.h>

#समावेश "rijndael.h"
#समावेश "xmalloc.h"
#समावेश "log.h"

#घोषणा RIJNDAEL_BLOCKSIZE 16
काष्ठा ssh_rijndael_ctx
{
	rijndael_ctx	r_ctx;
	u_char		r_iv[RIJNDAEL_BLOCKSIZE];
};

अटल पूर्णांक
ssh_rijndael_init(EVP_CIPHER_CTX *ctx, स्थिर u_char *कुंजी, स्थिर u_char *iv,
    पूर्णांक enc)
{
	काष्ठा ssh_rijndael_ctx *c;

	अगर ((c = EVP_CIPHER_CTX_get_app_तथ्य(ctx)) == शून्य) {
		c = xmalloc(माप(*c));
		EVP_CIPHER_CTX_set_app_तथ्य(ctx, c);
	}
	अगर (कुंजी != शून्य) {
		अगर (enc == -1)
			enc = ctx->encrypt;
		rijndael_set_कुंजी(&c->r_ctx, (u_char *)कुंजी,
		    8*EVP_CIPHER_CTX_कुंजी_लंबाई(ctx), enc);
	}
	अगर (iv != शून्य)
		स_नकल(c->r_iv, iv, RIJNDAEL_BLOCKSIZE);
	वापस (1);
}

अटल पूर्णांक
ssh_rijndael_cbc(EVP_CIPHER_CTX *ctx, u_char *dest, स्थिर u_char *src,
    माप_प्रकार len)
{
	काष्ठा ssh_rijndael_ctx *c;
	u_char buf[RIJNDAEL_BLOCKSIZE];
	u_char *cprev, *cnow, *plain, *ivp;
	पूर्णांक i, j, blocks = len / RIJNDAEL_BLOCKSIZE;

	अगर (len == 0)
		वापस (1);
	अगर (len % RIJNDAEL_BLOCKSIZE)
		fatal("ssh_rijndael_cbc: bad len %d", len);
	अगर ((c = EVP_CIPHER_CTX_get_app_तथ्य(ctx)) == शून्य) {
		error("ssh_rijndael_cbc: no context");
		वापस (0);
	}
	अगर (ctx->encrypt) {
		cnow  = dest;
		plain = (u_char *)src;
		cprev = c->r_iv;
		क्रम (i = 0; i < blocks; i++, plain+=RIJNDAEL_BLOCKSIZE,
		    cnow+=RIJNDAEL_BLOCKSIZE) {
			क्रम (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				buf[j] = plain[j] ^ cprev[j];
			rijndael_encrypt(&c->r_ctx, buf, cnow);
			cprev = cnow;
		}
		स_नकल(c->r_iv, cprev, RIJNDAEL_BLOCKSIZE);
	} अन्यथा {
		cnow  = (u_char *) (src+len-RIJNDAEL_BLOCKSIZE);
		plain = dest+len-RIJNDAEL_BLOCKSIZE;

		स_नकल(buf, cnow, RIJNDAEL_BLOCKSIZE);
		क्रम (i = blocks; i > 0; i--, cnow-=RIJNDAEL_BLOCKSIZE,
		    plain-=RIJNDAEL_BLOCKSIZE) {
			rijndael_decrypt(&c->r_ctx, cnow, plain);
			ivp = (i == 1) ? c->r_iv : cnow-RIJNDAEL_BLOCKSIZE;
			क्रम (j = 0; j < RIJNDAEL_BLOCKSIZE; j++)
				plain[j] ^= ivp[j];
		}
		स_नकल(c->r_iv, buf, RIJNDAEL_BLOCKSIZE);
	}
	वापस (1);
}

अटल पूर्णांक
ssh_rijndael_cleanup(EVP_CIPHER_CTX *ctx)
{
	काष्ठा ssh_rijndael_ctx *c;

	अगर ((c = EVP_CIPHER_CTX_get_app_तथ्य(ctx)) != शून्य) {
		स_रखो(c, 0, माप(*c));
		मुक्त(c);
		EVP_CIPHER_CTX_set_app_तथ्य(ctx, शून्य);
	}
	वापस (1);
}

व्योम
ssh_rijndael_iv(EVP_CIPHER_CTX *evp, पूर्णांक doset, u_char * iv, u_int len)
{
	काष्ठा ssh_rijndael_ctx *c;

	अगर ((c = EVP_CIPHER_CTX_get_app_तथ्य(evp)) == शून्य)
		fatal("ssh_rijndael_iv: no context");
	अगर (doset)
		स_नकल(c->r_iv, iv, len);
	अन्यथा
		स_नकल(iv, c->r_iv, len);
}

स्थिर EVP_CIPHER *
evp_rijndael(व्योम)
{
	अटल EVP_CIPHER rijndal_cbc;

	स_रखो(&rijndal_cbc, 0, माप(EVP_CIPHER));
	rijndal_cbc.nid = NID_undef;
	rijndal_cbc.block_आकार = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.iv_len = RIJNDAEL_BLOCKSIZE;
	rijndal_cbc.कुंजी_len = 16;
	rijndal_cbc.init = ssh_rijndael_init;
	rijndal_cbc.cleanup = ssh_rijndael_cleanup;
	rijndal_cbc.do_cipher = ssh_rijndael_cbc;
#अगर_अघोषित SSH_OLD_EVP
	rijndal_cbc.flags = EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_लंबाई |
	    EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV;
#पूर्ण_अगर
	वापस (&rijndal_cbc);
}
#पूर्ण_अगर /* USE_BUILTIN_RIJNDAEL */
