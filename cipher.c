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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <string.h>
#شامل <stdarg.h>
#شامل <stdio.h>

#شامل "cipher.h"
#شامل "misc.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"

#شامل "openbsd-compat/openssl-compat.h"

#ifndef WITH_OPENSSL
#define EVP_CIPHER_CTX تهی
#endif

ساختار sshcipher_ctx {
	صحیح	plaintext;
	صحیح	encrypt;
	EVP_CIPHER_CTX *evp;
	ساختار chachapoly_ctx *cp_ctx;
	ساختار aesctr_ctx ac_ctx; /* XXX union with evp? */
	ثابت ساختار sshcipher *cipher;
};

ساختار sshcipher {
	نویسه	*name;
	u_int	block_size;
	u_int	کلید_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#define CFLAG_CBC		(1<<0)
#define CFLAG_CHACHAPOLY	(1<<1)
#define CFLAG_AESCTR		(1<<2)
#define CFLAG_NONE		(1<<3)
#define CFLAG_INTERNAL		CFLAG_NONE /* Don't use "none" for packets */
#ifdef WITH_OPENSSL
	ثابت EVP_CIPHER	*(*evptype)(تهی);
#وگرنه
	تهی	*ignored;
#endif
};

ایستا ثابت ساختار sshcipher ciphers[] = {
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
#وگرنه
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, پوچ },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, پوچ },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, پوچ },
#endif
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, پوچ },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, پوچ },

	{ پوچ,			0, 0, 0, 0, 0, پوچ }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
نویسه *
cipher_alg_list(نویسه sep, صحیح auth_only)
{
	نویسه *ret = پوچ;
	ثابت ساختار sshcipher *c;
	نویسه sep_str[2] = {sep, '\0'};

	برای (c = ciphers; c->name != پوچ; c++) {
		اگر ((c->flags & CFLAG_INTERNAL) != 0)
			ادامه;
		اگر (auth_only && c->auth_len == 0)
			ادامه;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	بازگشت ret;
}

ثابت نویسه *
compression_alg_list(صحیح compression)
{
#ifdef WITH_ZLIB
	بازگشت compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#وگرنه
	بازگشت "none";
#endif
}

u_int
cipher_blocksize(ثابت ساختار sshcipher *c)
{
	بازگشت (c->block_size);
}

u_int
cipher_keylen(ثابت ساختار sshcipher *c)
{
	بازگشت (c->کلید_len);
}

u_int
cipher_seclen(ثابت ساختار sshcipher *c)
{
	اگر (strcmp("3des-cbc", c->name) == 0)
		بازگشت 14;
	بازگشت cipher_keylen(c);
}

u_int
cipher_authlen(ثابت ساختار sshcipher *c)
{
	بازگشت (c->auth_len);
}

u_int
cipher_ivlen(ثابت ساختار sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	بازگشت (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->block_size;
}

u_int
cipher_is_cbc(ثابت ساختار sshcipher *c)
{
	بازگشت (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_internal(ثابت ساختار sshcipher *c)
{
	بازگشت (c->flags & CFLAG_INTERNAL) != 0;
}

u_int
cipher_ctx_is_plaintext(ساختار sshcipher_ctx *cc)
{
	بازگشت cc->plaintext;
}

ثابت ساختار sshcipher *
cipher_by_name(ثابت نویسه *name)
{
	ثابت ساختار sshcipher *c;
	برای (c = ciphers; c->name != پوچ; c++)
		اگر (strcmp(c->name, name) == 0)
			بازگشت c;
	بازگشت پوچ;
}

#define	CIPHER_SEP	","
صحیح
ciphers_valid(ثابت نویسه *names)
{
	ثابت ساختار sshcipher *c;
	نویسه *cipher_list, *cp;
	نویسه *p;
	صحیح found = 0;

	اگر (names == پوچ || strcmp(names, "") == 0)
		بازگشت 0;
	اگر ((cipher_list = cp = strdup(names)) == پوچ)
		بازگشت 0;
	برای ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		اگر (c == پوچ || (c->flags & CFLAG_INTERNAL) != 0) {
			آزاد(cipher_list);
			بازگشت 0;
		} وگرنه
			found = 1;
	}
	آزاد(cipher_list);
	بازگشت found;
}

ثابت نویسه *
cipher_warning_message(ثابت ساختار sshcipher_ctx *cc)
{
	اگر (cc == پوچ || cc->cipher == پوچ)
		بازگشت پوچ;
	/* XXX repurpose for CBC warning */
	بازگشت پوچ;
}

صحیح
cipher_init(ساختار sshcipher_ctx **ccp, ثابت ساختار sshcipher *cipher,
    ثابت u_char *کلید, u_int keylen, ثابت u_char *iv, u_int ivlen,
    صحیح do_encrypt)
{
	ساختار sshcipher_ctx *cc = پوچ;
	صحیح ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_OPENSSL
	ثابت EVP_CIPHER *type;
	صحیح klen;
#endif

	*ccp = پوچ;
	اگر ((cc = calloc(1, اندازه(*cc))) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	اگر (keylen < cipher->کلید_len ||
	    (iv != پوچ && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}

	cc->cipher = cipher;
	اگر ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(کلید, keylen);
		ret = cc->cp_ctx != پوچ ? 0 : SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	اگر ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		برو out;
	}
#ifndef WITH_OPENSSL
	اگر ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, کلید, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		برو out;
	}
	ret = SSH_ERR_INVALID_ARGUMENT;
	برو out;
#وگرنه /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	اگر ((cc->evp = EVP_CIPHER_CTX_new()) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (EVP_CipherInit(cc->evp, type, پوچ, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	اگر (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	klen = EVP_CIPHER_CTX_کلید_length(cc->evp);
	اگر (klen > 0 && keylen != (u_int)klen) {
		اگر (EVP_CIPHER_CTX_set_کلید_length(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			برو out;
		}
	}
	اگر (EVP_CipherInit(cc->evp, پوچ, (u_char *)کلید, پوچ, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	ret = 0;
#endif /* WITH_OPENSSL */
 out:
	اگر (ret == 0) {
		/* success */
		*ccp = cc;
	} وگرنه {
		اگر (cc != پوچ) {
#ifdef WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#endif /* WITH_OPENSSL */
			freezero(cc, اندازه(*cc));
		}
	}
	بازگشت ret;
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
صحیح
cipher_crypt(ساختار sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   ثابت u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	اگر ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		بازگشت chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	اگر ((cc->cipher->flags & CFLAG_NONE) != 0) {
		memcpy(dest, src, aadlen + len);
		بازگشت 0;
	}
#ifndef WITH_OPENSSL
	اگر ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		اگر (aadlen)
			memcpy(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		بازگشت 0;
	}
	بازگشت SSH_ERR_INVALID_ARGUMENT;
#وگرنه
	اگر (authlen) {
		u_char lastiv[1];

		اگر (authlen != cipher_authlen(cc->cipher))
			بازگشت SSH_ERR_INVALID_ARGUMENT;
		/* increment IV */
		اگر (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			بازگشت SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		اگر (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_TAG,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			بازگشت SSH_ERR_LIBCRYPTO_ERROR;
	}
	اگر (aadlen) {
		اگر (authlen &&
		    EVP_Cipher(cc->evp, پوچ, (u_char *)src, aadlen) < 0)
			بازگشت SSH_ERR_LIBCRYPTO_ERROR;
		memcpy(dest, src, aadlen);
	}
	اگر (len % cc->cipher->block_size)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		بازگشت SSH_ERR_LIBCRYPTO_ERROR;
	اگر (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		اگر (EVP_Cipher(cc->evp, پوچ, پوچ, 0) < 0)
			بازگشت cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		اگر (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_TAG,
		    authlen, dest + aadlen + len) <= 0)
			بازگشت SSH_ERR_LIBCRYPTO_ERROR;
	}
	بازگشت 0;
#endif
}

/* Extract the packet length, including any decryption necessary beforehand */
صحیح
cipher_get_length(ساختار sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    ثابت u_char *cp, u_int len)
{
	اگر ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		بازگشت chachapoly_get_length(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	اگر (len < 4)
		بازگشت SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	بازگشت 0;
}

تهی
cipher_free(ساختار sshcipher_ctx *cc)
{
	اگر (cc == پوچ)
		بازگشت;
	اگر ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = پوچ;
	} وگرنه اگر ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, اندازه(cc->ac_ctx));
#ifdef WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = پوچ;
#endif
	freezero(cc, اندازه(*cc));
}

صحیح
cipher_get_keyiv(ساختار sshcipher_ctx *cc, u_char *iv, size_t len)
{
#ifdef WITH_OPENSSL
	ثابت ساختار sshcipher *c = cc->cipher;
	صحیح evplen;
#endif

	اگر ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		اگر (len != 0)
			بازگشت SSH_ERR_INVALID_ARGUMENT;
		بازگشت 0;
	}
	اگر ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		اگر (len != اندازه(cc->ac_ctx.ctr))
			بازگشت SSH_ERR_INVALID_ARGUMENT;
		memcpy(iv, cc->ac_ctx.ctr, len);
		بازگشت 0;
	}
	اگر ((cc->cipher->flags & CFLAG_NONE) != 0)
		بازگشت 0;

#ifdef WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_length(cc->evp);
	اگر (evplen == 0)
		بازگشت 0;
	وگرنه اگر (evplen < 0)
		بازگشت SSH_ERR_LIBCRYPTO_ERROR;
	اگر ((size_t)evplen != len)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (cipher_authlen(c)) {
		اگر (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			بازگشت SSH_ERR_LIBCRYPTO_ERROR;
	} وگرنه اگر (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		بازگشت SSH_ERR_LIBCRYPTO_ERROR;
#endif
	بازگشت 0;
}
