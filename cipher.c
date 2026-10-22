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

#ifndef WITH_OPENSSL
#define EVP_CIPHER_CTX शून्य
#endif

संरचना sshcipher_ctx {
	पूर्णाङ्क	plaintext;
	पूर्णाङ्क	encrypt;
	EVP_CIPHER_CTX *evp;
	संरचना chachapoly_ctx *cp_ctx;
	संरचना aesctr_ctx ac_ctx; /* XXX union with evp? */
	अचर संरचना sshcipher *cipher;
};

संरचना sshcipher {
	वर्ण	*name;
	u_int	block_size;
	u_int	साँचो_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#define CFLAG_CBC		(1<<0)
#define CFLAG_CHACHAPOLY	(1<<1)
#define CFLAG_AESCTR		(1<<2)
#define CFLAG_NONE		(1<<3)
#define CFLAG_INTERNAL		CFLAG_NONE /* Don't use "none" for packets */
#ifdef WITH_OPENSSL
	अचर EVP_CIPHER	*(*evptype)(शून्य);
#अन्यथा
	शून्य	*ignored;
#endif
};

स्थिर अचर संरचना sshcipher ciphers[] = {
#ifdef WITH_OPENSSL
#ifndef OPENSSL_NO_DES
	{ "3des-cbc",		8, 24, 0, 0, CFLAG_CBC, EVP_des_ede3_cbc },
#endif
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
#endif
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
	अचर संरचना sshcipher *c;
	वर्ण sep_str[2] = {sep, '\0'};

	लागि (c = ciphers; c->name != रिक्त; c++) {
		यदि ((c->flags & CFLAG_INTERNAL) != 0)
			जारी;
		यदि (auth_only && c->auth_len == 0)
			जारी;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	फर्काऊ ret;
}

अचर वर्ण *
compression_alg_list(पूर्णाङ्क compression)
{
#ifdef WITH_ZLIB
	फर्काऊ compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#अन्यथा
	फर्काऊ "none";
#endif
}

u_int
cipher_blocksize(अचर संरचना sshcipher *c)
{
	फर्काऊ (c->block_size);
}

u_int
cipher_keylen(अचर संरचना sshcipher *c)
{
	फर्काऊ (c->साँचो_len);
}

u_int
cipher_seclen(अचर संरचना sshcipher *c)
{
	यदि (म_भेद("3des-cbc", c->name) == 0)
		फर्काऊ 14;
	फर्काऊ cipher_keylen(c);
}

u_int
cipher_authlen(अचर संरचना sshcipher *c)
{
	फर्काऊ (c->auth_len);
}

u_int
cipher_ivlen(अचर संरचना sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	फर्काऊ (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->block_size;
}

u_int
cipher_is_cbc(अचर संरचना sshcipher *c)
{
	फर्काऊ (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_internal(अचर संरचना sshcipher *c)
{
	फर्काऊ (c->flags & CFLAG_INTERNAL) != 0;
}

u_int
cipher_ctx_is_plaintext(संरचना sshcipher_ctx *cc)
{
	फर्काऊ cc->plaintext;
}

अचर संरचना sshcipher *
cipher_by_name(अचर वर्ण *name)
{
	अचर संरचना sshcipher *c;
	लागि (c = ciphers; c->name != रिक्त; c++)
		यदि (म_भेद(c->name, name) == 0)
			फर्काऊ c;
	फर्काऊ रिक्त;
}

#define	CIPHER_SEP	","
पूर्णाङ्क
ciphers_valid(अचर वर्ण *names)
{
	अचर संरचना sshcipher *c;
	वर्ण *cipher_list, *cp;
	वर्ण *p;
	पूर्णाङ्क found = 0;

	यदि (names == रिक्त || म_भेद(names, "") == 0)
		फर्काऊ 0;
	यदि ((cipher_list = cp = strdup(names)) == रिक्त)
		फर्काऊ 0;
	लागि ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		यदि (c == रिक्त || (c->flags & CFLAG_INTERNAL) != 0) {
			मुक्त(cipher_list);
			फर्काऊ 0;
		} अन्यथा
			found = 1;
	}
	मुक्त(cipher_list);
	फर्काऊ found;
}

अचर वर्ण *
cipher_warning_message(अचर संरचना sshcipher_ctx *cc)
{
	यदि (cc == रिक्त || cc->cipher == रिक्त)
		फर्काऊ रिक्त;
	/* XXX repurpose for CBC warning */
	फर्काऊ रिक्त;
}

पूर्णाङ्क
cipher_init(संरचना sshcipher_ctx **ccp, अचर संरचना sshcipher *cipher,
    अचर u_char *साँचो, u_int keylen, अचर u_char *iv, u_int ivlen,
    पूर्णाङ्क do_encrypt)
{
	संरचना sshcipher_ctx *cc = रिक्त;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_OPENSSL
	अचर EVP_CIPHER *type;
	पूर्णाङ्क klen;
#endif

	*ccp = रिक्त;
	यदि ((cc = सुस्मृति(1, परिमाण(*cc))) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	यदि (keylen < cipher->साँचो_len ||
	    (iv != रिक्त && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}

	cc->cipher = cipher;
	यदि ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(साँचो, keylen);
		ret = cc->cp_ctx != रिक्त ? 0 : SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	यदि ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		गच्छ out;
	}
#ifndef WITH_OPENSSL
	यदि ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, साँचो, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		गच्छ out;
	}
	ret = SSH_ERR_INVALID_ARGUMENT;
	गच्छ out;
#अन्यथा /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	यदि ((cc->evp = EVP_CIPHER_CTX_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (EVP_CipherInit(cc->evp, type, रिक्त, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	यदि (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	klen = EVP_CIPHER_CTX_साँचो_length(cc->evp);
	यदि (klen > 0 && keylen != (u_int)klen) {
		यदि (EVP_CIPHER_CTX_set_साँचो_length(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
	}
	यदि (EVP_CipherInit(cc->evp, रिक्त, (u_char *)साँचो, रिक्त, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	ret = 0;
#endif /* WITH_OPENSSL */
 out:
	यदि (ret == 0) {
		/* success */
		*ccp = cc;
	} अन्यथा {
		यदि (cc != रिक्त) {
#ifdef WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#endif /* WITH_OPENSSL */
			freezero(cc, परिमाण(*cc));
		}
	}
	फर्काऊ ret;
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
   अचर u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	यदि ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		फर्काऊ chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	यदि ((cc->cipher->flags & CFLAG_NONE) != 0) {
		स_नकल(dest, src, aadlen + len);
		फर्काऊ 0;
	}
#ifndef WITH_OPENSSL
	यदि ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		यदि (aadlen)
			स_नकल(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		फर्काऊ 0;
	}
	फर्काऊ SSH_ERR_INVALID_ARGUMENT;
#अन्यथा
	यदि (authlen) {
		u_char lastiv[1];

		यदि (authlen != cipher_authlen(cc->cipher))
			फर्काऊ SSH_ERR_INVALID_ARGUMENT;
		/* increment IV */
		यदि (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		यदि (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_TAG,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;
	}
	यदि (aadlen) {
		यदि (authlen &&
		    EVP_Cipher(cc->evp, रिक्त, (u_char *)src, aadlen) < 0)
			फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;
		स_नकल(dest, src, aadlen);
	}
	यदि (len % cc->cipher->block_size)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;
	यदि (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		यदि (EVP_Cipher(cc->evp, रिक्त, रिक्त, 0) < 0)
			फर्काऊ cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		यदि (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_TAG,
		    authlen, dest + aadlen + len) <= 0)
			फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;
	}
	फर्काऊ 0;
#endif
}

/* Extract the packet length, including any decryption necessary beforehand */
पूर्णाङ्क
cipher_get_length(संरचना sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    अचर u_char *cp, u_int len)
{
	यदि ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		फर्काऊ chachapoly_get_length(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	यदि (len < 4)
		फर्काऊ SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	फर्काऊ 0;
}

शून्य
cipher_free(संरचना sshcipher_ctx *cc)
{
	यदि (cc == रिक्त)
		फर्काऊ;
	यदि ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = रिक्त;
	} अन्यथा यदि ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, परिमाण(cc->ac_ctx));
#ifdef WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = रिक्त;
#endif
	freezero(cc, परिमाण(*cc));
}

पूर्णाङ्क
cipher_get_keyiv(संरचना sshcipher_ctx *cc, u_char *iv, माप_प्रकार len)
{
#ifdef WITH_OPENSSL
	अचर संरचना sshcipher *c = cc->cipher;
	पूर्णाङ्क evplen;
#endif

	यदि ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		यदि (len != 0)
			फर्काऊ SSH_ERR_INVALID_ARGUMENT;
		फर्काऊ 0;
	}
	यदि ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		यदि (len != परिमाण(cc->ac_ctx.ctr))
			फर्काऊ SSH_ERR_INVALID_ARGUMENT;
		स_नकल(iv, cc->ac_ctx.ctr, len);
		फर्काऊ 0;
	}
	यदि ((cc->cipher->flags & CFLAG_NONE) != 0)
		फर्काऊ 0;

#ifdef WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_length(cc->evp);
	यदि (evplen == 0)
		फर्काऊ 0;
	अन्यथा यदि (evplen < 0)
		फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;
	यदि ((माप_प्रकार)evplen != len)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि (cipher_authlen(c)) {
		यदि (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;
	} अन्यथा यदि (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;
#endif
	फर्काऊ 0;
}
