/* $OpenBSD: cipher.c,v 1.129 2026/06/19 05:26:04 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * Copyright (c) 1999 Niels Provos.  All rights reserved.
 * Copyright (c) 1999, 2000 Markus Friedl.  All rights reserved.
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

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>

#अन्तर्भाव "cipher.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"

#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#यदि_अपरिभाषितम् WITH_OPENSSL
#परिभाषय EVP_CIPHER_CTX शून्य
#यदि_अन्तः

संरचना sshcipher_ctx {
	पूर्णाङ्क	plaintext;
	पूर्णाङ्क	encrypt;
	EVP_CIPHER_CTX *evp;
	संरचना chachapoly_ctx *cp_ctx;
	संरचना aesctr_ctx ac_ctx; /* XXX union with evp? */
	ध्रुव संरचना sshcipher *cipher;
};

संरचना sshcipher {
	वर्ण	*name;
	u_int	खण्डम्_आकार;
	u_int	कुञ्चिका_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#परिभाषय CFLAG_CBC		(1<<0)
#परिभाषय CFLAG_CHACHAPOLY	(1<<1)
#परिभाषय CFLAG_AESCTR		(1<<2)
#परिभाषय CFLAG_NONE		(1<<3)
#परिभाषय CFLAG_आन्तरिकम्		CFLAG_NONE /* Don't use "none" for packets */
#यदि_परिभाषितम् WITH_OPENSSL
	ध्रुव EVP_CIPHER	*(*evptype)(शून्य);
#अन्यथा
	शून्य	*ignored;
#यदि_अन्तः
};

स्थिर ध्रुव संरचना sshcipher ciphers[] = {
#यदि_परिभाषितम् WITH_OPENSSL
#यदि_अपरिभाषितम् OPENSSL_NO_DES
	{ "3des-cbc",		8, 24, 0, 0, CFLAG_CBC, EVP_des_ede3_cbc },
#यदि_अन्तः
	{ "aes128-cbc",		16, 16, 0, 0, CFLAG_CBC, EVP_aes_128_cbc },
	{ "aes192-cbc",		16, 24, 0, 0, CFLAG_CBC, EVP_aes_192_cbc },
	{ "aes256-cbc",		16, 32, 0, 0, CFLAG_CBC, EVP_aes_256_cbc },
	{ "aes128-ctr",		16, 16, 0, 0, 0, EVP_aes_128_ctr },
	{ "aes192-ctr",		16, 24, 0, 0, 0, EVP_aes_192_ctr },
	{ "aes256-ctr",		16, 32, 0, 0, 0, EVP_aes_256_ctr },
	{ "aes128-gcm@openssh.com",
				16, 16, 12, 16, 0, EVP_aes_128_gcm },
	{ "aes256-gcm@openssh.com",
				16, 32, 12, 16, 0, EVP_aes_256_gcm },
#अन्यथा
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, रिक्त },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, रिक्त },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, रिक्त },
#यदि_अन्तः
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, रिक्त },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, रिक्त },

	{ रिक्त,			0, 0, 0, 0, 0, रिक्त }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
वर्ण *
cipher_alg_list(वर्ण sep, पूर्णाङ्क auth_only)
{
	वर्ण *ret = रिक्त;
	ध्रुव संरचना sshcipher *c;
	वर्ण sep_str[2] = {sep, '\0'};

	प्रति (c = ciphers; c->name != रिक्त; c++) {
		यदि ((c->flags & CFLAG_आन्तरिकम्) != 0)
			अनुवर्त;
		यदि (auth_only && c->auth_len == 0)
			अनुवर्त;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	प्रत्यागम ret;
}

ध्रुव वर्ण *
compression_alg_list(पूर्णाङ्क compression)
{
#यदि_परिभाषितम् WITH_ZLIB
	प्रत्यागम compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#अन्यथा
	प्रत्यागम "none";
#यदि_अन्तः
}

u_int
cipher_blocksize(ध्रुव संरचना sshcipher *c)
{
	प्रत्यागम (c->खण्डम्_आकार);
}

u_int
cipher_keylen(ध्रुव संरचना sshcipher *c)
{
	प्रत्यागम (c->कुञ्चिका_len);
}

u_int
cipher_seclen(ध्रुव संरचना sshcipher *c)
{
	यदि (वाक्यं_तुलय("3des-cbc", c->name) == 0)
		प्रत्यागम 14;
	प्रत्यागम cipher_keylen(c);
}

u_int
cipher_authlen(ध्रुव संरचना sshcipher *c)
{
	प्रत्यागम (c->auth_len);
}

u_int
cipher_ivlen(ध्रुव संरचना sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	प्रत्यागम (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->खण्डम्_आकार;
}

u_int
cipher_is_cbc(ध्रुव संरचना sshcipher *c)
{
	प्रत्यागम (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_आन्तरिकम्(ध्रुव संरचना sshcipher *c)
{
	प्रत्यागम (c->flags & CFLAG_आन्तरिकम्) != 0;
}

u_int
cipher_ctx_is_plaintext(संरचना sshcipher_ctx *cc)
{
	प्रत्यागम cc->plaintext;
}

ध्रुव संरचना sshcipher *
cipher_by_name(ध्रुव वर्ण *name)
{
	ध्रुव संरचना sshcipher *c;
	प्रति (c = ciphers; c->name != रिक्त; c++)
		यदि (वाक्यं_तुलय(c->name, name) == 0)
			प्रत्यागम c;
	प्रत्यागम रिक्त;
}

#परिभाषय	CIPHER_SEP	","
पूर्णाङ्क
ciphers_valid(ध्रुव वर्ण *नामानि)
{
	ध्रुव संरचना sshcipher *c;
	वर्ण *cipher_list, *cp;
	वर्ण *p;
	पूर्णाङ्क प्राप्तम् = 0;

	यदि (नामानि == रिक्त || वाक्यं_तुलय(नामानि, "") == 0)
		प्रत्यागम 0;
	यदि ((cipher_list = cp = strdup(नामानि)) == रिक्त)
		प्रत्यागम 0;
	प्रति ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		यदि (c == रिक्त || (c->flags & CFLAG_आन्तरिकम्) != 0) {
			मुक्त(cipher_list);
			प्रत्यागम 0;
		} अन्यथा
			प्राप्तम् = 1;
	}
	मुक्त(cipher_list);
	प्रत्यागम प्राप्तम्;
}

ध्रुव वर्ण *
cipher_warning_सन्देशः(ध्रुव संरचना sshcipher_ctx *cc)
{
	यदि (cc == रिक्त || cc->cipher == रिक्त)
		प्रत्यागम रिक्त;
	/* XXX repurpose for CBC warning */
	प्रत्यागम रिक्त;
}

पूर्णाङ्क
cipher_init(संरचना sshcipher_ctx **ccp, ध्रुव संरचना sshcipher *cipher,
    ध्रुव u_char *कुञ्चिका, u_int keylen, ध्रुव u_char *iv, u_int ivlen,
    पूर्णाङ्क do_encrypt)
{
	संरचना sshcipher_ctx *cc = रिक्त;
	पूर्णाङ्क ret = SSH_ERR_आन्तरिकम्_ERROR;
#यदि_परिभाषितम् WITH_OPENSSL
	ध्रुव EVP_CIPHER *type;
	पूर्णाङ्क klen;
#यदि_अन्तः

	*ccp = रिक्त;
	यदि ((cc = शून्यस्मृतिं_देहि(1, परिमाण(*cc))) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	यदि (keylen < cipher->कुञ्चिका_len ||
	    (iv != रिक्त && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_तर्कः;
		गच्छ बहिर्गमनम्;
	}

	cc->cipher = cipher;
	यदि ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(कुञ्चिका, keylen);
		ret = cc->cp_ctx != रिक्त ? 0 : SSH_ERR_INVALID_तर्कः;
		गच्छ बहिर्गमनम्;
	}
	यदि ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		गच्छ बहिर्गमनम्;
	}
#यदि_अपरिभाषितम् WITH_OPENSSL
	यदि ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, कुञ्चिका, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		गच्छ बहिर्गमनम्;
	}
	ret = SSH_ERR_INVALID_तर्कः;
	गच्छ बहिर्गमनम्;
#अन्यथा /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	यदि ((cc->evp = EVP_CIPHER_CTX_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि (EVP_CipherInit(cc->evp, type, रिक्त, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	यदि (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_समुच्चयः_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	klen = EVP_CIPHER_CTX_कुञ्चिका_दीर्घता(cc->evp);
	यदि (klen > 0 && keylen != (u_int)klen) {
		यदि (EVP_CIPHER_CTX_समुच्चयः_कुञ्चिका_दीर्घता(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ बहिर्गमनम्;
		}
	}
	यदि (EVP_CipherInit(cc->evp, रिक्त, (u_char *)कुञ्चिका, रिक्त, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	ret = 0;
#यदि_अन्तः /* WITH_OPENSSL */
 बहिर्गमनम्:
	यदि (ret == 0) {
		/* success */
		*ccp = cc;
	} अन्यथा {
		यदि (cc != रिक्त) {
#यदि_परिभाषितम् WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#यदि_अन्तः /* WITH_OPENSSL */
			freezero(cc, परिमाण(*cc));
		}
	}
	प्रत्यागम ret;
}

/*
 * cipher_crypt() operates as following:
 * Copy 'aadlen' bytes (without en/decryption) from 'src' to 'dest'.
 * These bytes are treated as additional authenticated data for
 * authenticated encryption modes.
 * En/Decrypt 'len' bytes at offset 'aadlen' from 'src' to 'dest'.
 * Use 'authlen' bytes at offset 'len'+'aadlen' as the authentication tag.
 * This tag is written on encryption and verified on decryption.
 * Both 'aadlen' and 'authlen' can be set to 0.
 */
पूर्णाङ्क
cipher_crypt(संरचना sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   ध्रुव u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	यदि ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		प्रत्यागम chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	यदि ((cc->cipher->flags & CFLAG_NONE) != 0) {
		स्मृतिं_प्रतिलिख(dest, src, aadlen + len);
		प्रत्यागम 0;
	}
#यदि_अपरिभाषितम् WITH_OPENSSL
	यदि ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		यदि (aadlen)
			स्मृतिं_प्रतिलिख(dest, src, aadlen);
		aesctr_encrypt_अष्टकानि(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		प्रत्यागम 0;
	}
	प्रत्यागम SSH_ERR_INVALID_तर्कः;
#अन्यथा
	यदि (authlen) {
		u_char lastiv[1];

		यदि (authlen != cipher_authlen(cc->cipher))
			प्रत्यागम SSH_ERR_INVALID_तर्कः;
		/* increment IV */
		यदि (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		यदि (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_समुच्चयः_चिह्नकम्,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
	}
	यदि (aadlen) {
		यदि (authlen &&
		    EVP_Cipher(cc->evp, रिक्त, (u_char *)src, aadlen) < 0)
			प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
		स्मृतिं_प्रतिलिख(dest, src, aadlen);
	}
	यदि (len % cc->cipher->खण्डम्_आकार)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	यदि (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
	यदि (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		यदि (EVP_Cipher(cc->evp, रिक्त, रिक्त, 0) < 0)
			प्रत्यागम cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		यदि (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_चिह्नकम्,
		    authlen, dest + aadlen + len) <= 0)
			प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
	}
	प्रत्यागम 0;
#यदि_अन्तः
}

/* Extract the packet length, including any decryption necessary beforehand */
पूर्णाङ्क
cipher_get_दीर्घता(संरचना sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    ध्रुव u_char *cp, u_int len)
{
	यदि ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		प्रत्यागम chachapoly_get_दीर्घता(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	यदि (len < 4)
		प्रत्यागम SSH_ERR_सन्देशः_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	प्रत्यागम 0;
}

शून्य
cipher_free(संरचना sshcipher_ctx *cc)
{
	यदि (cc == रिक्त)
		प्रत्यागम;
	यदि ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = रिक्त;
	} अन्यथा यदि ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, परिमाण(cc->ac_ctx));
#यदि_परिभाषितम् WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = रिक्त;
#यदि_अन्तः
	freezero(cc, परिमाण(*cc));
}

पूर्णाङ्क
cipher_get_keyiv(संरचना sshcipher_ctx *cc, u_char *iv, आकार_t len)
{
#यदि_परिभाषितम् WITH_OPENSSL
	ध्रुव संरचना sshcipher *c = cc->cipher;
	पूर्णाङ्क evplen;
#यदि_अन्तः

	यदि ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		यदि (len != 0)
			प्रत्यागम SSH_ERR_INVALID_तर्कः;
		प्रत्यागम 0;
	}
	यदि ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		यदि (len != परिमाण(cc->ac_ctx.ctr))
			प्रत्यागम SSH_ERR_INVALID_तर्कः;
		स्मृतिं_प्रतिलिख(iv, cc->ac_ctx.ctr, len);
		प्रत्यागम 0;
	}
	यदि ((cc->cipher->flags & CFLAG_NONE) != 0)
		प्रत्यागम 0;

#यदि_परिभाषितम् WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_दीर्घता(cc->evp);
	यदि (evplen == 0)
		प्रत्यागम 0;
	अन्यथा यदि (evplen < 0)
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
	यदि ((आकार_t)evplen != len)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	यदि (cipher_authlen(c)) {
		यदि (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
	} अन्यथा यदि (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
#यदि_अन्तः
	प्रत्यागम 0;
}
