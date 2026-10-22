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
	पूर्णांक	plaintext;
	पूर्णांक	encrypt;
	EVP_CIPHER_CTX *evp;
	संरचना chachapoly_ctx *cp_ctx;
	संरचना aesctr_ctx ac_ctx; /* XXX union with evp? */
	स्थिरांक संरचना sshcipher *cipher;
};

संरचना sshcipher {
	अक्षर	*name;
	u_int	block_size;
	u_int	किल्ली_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#define CFLAG_CBC		(1<<0)
#define CFLAG_CHACHAPOLY	(1<<1)
#define CFLAG_AESCTR		(1<<2)
#define CFLAG_NONE		(1<<3)
#define CFLAG_INTERNAL		CFLAG_NONE /* Don't use "none" for packets */
#ifdef WITH_OPENSSL
	स्थिरांक EVP_CIPHER	*(*evptype)(शून्य);
#अन्यथा
	शून्य	*ignored;
#endif
};

स्थिर स्थिरांक संरचना sshcipher ciphers[] = {
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
अक्षर *
cipher_alg_list(अक्षर sep, पूर्णांक auth_only)
{
	अक्षर *ret = रिक्त;
	स्थिरांक संरचना sshcipher *c;
	अक्षर sep_str[2] = {sep, '\0'};

	साठी (c = ciphers; c->name != रिक्त; c++) {
		जर ((c->flags & CFLAG_INTERNAL) != 0)
			सुरूठेवा;
		जर (auth_only && c->auth_len == 0)
			सुरूठेवा;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	परत ret;
}

स्थिरांक अक्षर *
compression_alg_list(पूर्णांक compression)
{
#ifdef WITH_ZLIB
	परत compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#अन्यथा
	परत "none";
#endif
}

u_int
cipher_blocksize(स्थिरांक संरचना sshcipher *c)
{
	परत (c->block_size);
}

u_int
cipher_keylen(स्थिरांक संरचना sshcipher *c)
{
	परत (c->किल्ली_len);
}

u_int
cipher_seclen(स्थिरांक संरचना sshcipher *c)
{
	जर (म_भेद("3des-cbc", c->name) == 0)
		परत 14;
	परत cipher_keylen(c);
}

u_int
cipher_authlen(स्थिरांक संरचना sshcipher *c)
{
	परत (c->auth_len);
}

u_int
cipher_ivlen(स्थिरांक संरचना sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	परत (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->block_size;
}

u_int
cipher_is_cbc(स्थिरांक संरचना sshcipher *c)
{
	परत (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_internal(स्थिरांक संरचना sshcipher *c)
{
	परत (c->flags & CFLAG_INTERNAL) != 0;
}

u_int
cipher_ctx_is_plaintext(संरचना sshcipher_ctx *cc)
{
	परत cc->plaintext;
}

स्थिरांक संरचना sshcipher *
cipher_by_name(स्थिरांक अक्षर *name)
{
	स्थिरांक संरचना sshcipher *c;
	साठी (c = ciphers; c->name != रिक्त; c++)
		जर (म_भेद(c->name, name) == 0)
			परत c;
	परत रिक्त;
}

#define	CIPHER_SEP	","
पूर्णांक
ciphers_valid(स्थिरांक अक्षर *names)
{
	स्थिरांक संरचना sshcipher *c;
	अक्षर *cipher_list, *cp;
	अक्षर *p;
	पूर्णांक found = 0;

	जर (names == रिक्त || म_भेद(names, "") == 0)
		परत 0;
	जर ((cipher_list = cp = strdup(names)) == रिक्त)
		परत 0;
	साठी ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		जर (c == रिक्त || (c->flags & CFLAG_INTERNAL) != 0) {
			मुक्त(cipher_list);
			परत 0;
		} अन्यथा
			found = 1;
	}
	मुक्त(cipher_list);
	परत found;
}

स्थिरांक अक्षर *
cipher_warning_message(स्थिरांक संरचना sshcipher_ctx *cc)
{
	जर (cc == रिक्त || cc->cipher == रिक्त)
		परत रिक्त;
	/* XXX repurpose for CBC warning */
	परत रिक्त;
}

पूर्णांक
cipher_init(संरचना sshcipher_ctx **ccp, स्थिरांक संरचना sshcipher *cipher,
    स्थिरांक u_char *किल्ली, u_int keylen, स्थिरांक u_char *iv, u_int ivlen,
    पूर्णांक do_encrypt)
{
	संरचना sshcipher_ctx *cc = रिक्त;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_OPENSSL
	स्थिरांक EVP_CIPHER *type;
	पूर्णांक klen;
#endif

	*ccp = रिक्त;
	जर ((cc = सुस्मृति(1, आकार(*cc))) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	जर (keylen < cipher->किल्ली_len ||
	    (iv != रिक्त && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		जा out;
	}

	cc->cipher = cipher;
	जर ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(किल्ली, keylen);
		ret = cc->cp_ctx != रिक्त ? 0 : SSH_ERR_INVALID_ARGUMENT;
		जा out;
	}
	जर ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		जा out;
	}
#ifndef WITH_OPENSSL
	जर ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, किल्ली, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		जा out;
	}
	ret = SSH_ERR_INVALID_ARGUMENT;
	जा out;
#अन्यथा /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	जर ((cc->evp = EVP_CIPHER_CTX_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (EVP_CipherInit(cc->evp, type, रिक्त, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	जर (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	klen = EVP_CIPHER_CTX_किल्ली_length(cc->evp);
	जर (klen > 0 && keylen != (u_int)klen) {
		जर (EVP_CIPHER_CTX_set_किल्ली_length(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			जा out;
		}
	}
	जर (EVP_CipherInit(cc->evp, रिक्त, (u_char *)किल्ली, रिक्त, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	ret = 0;
#endif /* WITH_OPENSSL */
 out:
	जर (ret == 0) {
		/* success */
		*ccp = cc;
	} अन्यथा {
		जर (cc != रिक्त) {
#ifdef WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#endif /* WITH_OPENSSL */
			freezero(cc, आकार(*cc));
		}
	}
	परत ret;
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
पूर्णांक
cipher_crypt(संरचना sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   स्थिरांक u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	जर ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		परत chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	जर ((cc->cipher->flags & CFLAG_NONE) != 0) {
		स_नकल(dest, src, aadlen + len);
		परत 0;
	}
#ifndef WITH_OPENSSL
	जर ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		जर (aadlen)
			स_नकल(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		परत 0;
	}
	परत SSH_ERR_INVALID_ARGUMENT;
#अन्यथा
	जर (authlen) {
		u_char lastiv[1];

		जर (authlen != cipher_authlen(cc->cipher))
			परत SSH_ERR_INVALID_ARGUMENT;
		/* increment IV */
		जर (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			परत SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		जर (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_TAG,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			परत SSH_ERR_LIBCRYPTO_ERROR;
	}
	जर (aadlen) {
		जर (authlen &&
		    EVP_Cipher(cc->evp, रिक्त, (u_char *)src, aadlen) < 0)
			परत SSH_ERR_LIBCRYPTO_ERROR;
		स_नकल(dest, src, aadlen);
	}
	जर (len % cc->cipher->block_size)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		परत SSH_ERR_LIBCRYPTO_ERROR;
	जर (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		जर (EVP_Cipher(cc->evp, रिक्त, रिक्त, 0) < 0)
			परत cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		जर (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_TAG,
		    authlen, dest + aadlen + len) <= 0)
			परत SSH_ERR_LIBCRYPTO_ERROR;
	}
	परत 0;
#endif
}

/* Extract the packet length, including any decryption necessary beforehand */
पूर्णांक
cipher_get_length(संरचना sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    स्थिरांक u_char *cp, u_int len)
{
	जर ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		परत chachapoly_get_length(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	जर (len < 4)
		परत SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	परत 0;
}

शून्य
cipher_free(संरचना sshcipher_ctx *cc)
{
	जर (cc == रिक्त)
		परत;
	जर ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = रिक्त;
	} अन्यथा जर ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, आकार(cc->ac_ctx));
#ifdef WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = रिक्त;
#endif
	freezero(cc, आकार(*cc));
}

पूर्णांक
cipher_get_keyiv(संरचना sshcipher_ctx *cc, u_char *iv, माप_प्रकार len)
{
#ifdef WITH_OPENSSL
	स्थिरांक संरचना sshcipher *c = cc->cipher;
	पूर्णांक evplen;
#endif

	जर ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		जर (len != 0)
			परत SSH_ERR_INVALID_ARGUMENT;
		परत 0;
	}
	जर ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		जर (len != आकार(cc->ac_ctx.ctr))
			परत SSH_ERR_INVALID_ARGUMENT;
		स_नकल(iv, cc->ac_ctx.ctr, len);
		परत 0;
	}
	जर ((cc->cipher->flags & CFLAG_NONE) != 0)
		परत 0;

#ifdef WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_length(cc->evp);
	जर (evplen == 0)
		परत 0;
	अन्यथा जर (evplen < 0)
		परत SSH_ERR_LIBCRYPTO_ERROR;
	जर ((माप_प्रकार)evplen != len)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर (cipher_authlen(c)) {
		जर (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			परत SSH_ERR_LIBCRYPTO_ERROR;
	} अन्यथा जर (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		परत SSH_ERR_LIBCRYPTO_ERROR;
#endif
	परत 0;
}
