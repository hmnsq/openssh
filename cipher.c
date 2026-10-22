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

#include "includes.h"

#include <sys/types.h>

#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "cipher.h"
#include "misc.h"
#include "sshbuf.h"
#include "ssherr.h"

#include "openbsd-compat/openssl-compat.h"

#ifndef WITH_OPENSSL
#define EVP_CIPHER_CTX void
#endif

sa_nracanaa sshcipher_ctx {
	puur_naa_nka	plaintext;
	puur_naa_nka	encrypt;
	EVP_CIPHER_CTX *evp;
	sa_nracanaa chachapoly_ctx *cp_ctx;
	sa_nracanaa aesctr_ctx ac_ctx; /* XXX union with evp? */
	const sa_nracanaa sshcipher *cipher;
};

sa_nracanaa sshcipher {
	var_na	*name;
	u_int	block_size;
	u_int	key_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#define CFLAG_CBC		(1<<0)
#define CFLAG_CHACHAPOLY	(1<<1)
#define CFLAG_AESCTR		(1<<2)
#define CFLAG_NONE		(1<<3)
#define CFLAG_INTERNAL		CFLAG_NONE /* Don't use "none" for packets */
#ifdef WITH_OPENSSL
	const EVP_CIPHER	*(*evptype)(void);
#ᨀᨘᨁ
	void	*ignored;
#endif
};

static const sa_nracanaa sshcipher ciphers[] = {
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
#ᨀᨘᨁ
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, NULL },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, NULL },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, NULL },
#endif
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, NULL },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, NULL },

	{ NULL,			0, 0, 0, 0, 0, NULL }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
var_na *
cipher_alg_list(var_na sep, puur_naa_nka auth_only)
{
	var_na *ret = NULL;
	const sa_nracanaa sshcipher *c;
	var_na sep_str[2] = {sep, '\0'};

	for (c = ciphers; c->name != NULL; c++) {
		ᨀᨘ ((c->flags & CFLAG_INTERNAL) != 0)
			continue;
		ᨀᨘ (auth_only && c->auth_len == 0)
			continue;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	ᨀᨘᨒ ret;
}

const var_na *
compression_alg_list(puur_naa_nka compression)
{
#ifdef WITH_ZLIB
	ᨀᨘᨒ compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#ᨀᨘᨁ
	ᨀᨘᨒ "none";
#endif
}

u_int
cipher_blocksize(const sa_nracanaa sshcipher *c)
{
	ᨀᨘᨒ (c->block_size);
}

u_int
cipher_keylen(const sa_nracanaa sshcipher *c)
{
	ᨀᨘᨒ (c->key_len);
}

u_int
cipher_seclen(const sa_nracanaa sshcipher *c)
{
	ᨀᨘ (strcmp("3des-cbc", c->name) == 0)
		ᨀᨘᨒ 14;
	ᨀᨘᨒ cipher_keylen(c);
}

u_int
cipher_authlen(const sa_nracanaa sshcipher *c)
{
	ᨀᨘᨒ (c->auth_len);
}

u_int
cipher_ivlen(const sa_nracanaa sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	ᨀᨘᨒ (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->block_size;
}

u_int
cipher_is_cbc(const sa_nracanaa sshcipher *c)
{
	ᨀᨘᨒ (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_internal(const sa_nracanaa sshcipher *c)
{
	ᨀᨘᨒ (c->flags & CFLAG_INTERNAL) != 0;
}

u_int
cipher_ctx_is_plaintext(sa_nracanaa sshcipher_ctx *cc)
{
	ᨀᨘᨒ cc->plaintext;
}

const sa_nracanaa sshcipher *
cipher_by_name(const var_na *name)
{
	const sa_nracanaa sshcipher *c;
	for (c = ciphers; c->name != NULL; c++)
		ᨀᨘ (strcmp(c->name, name) == 0)
			ᨀᨘᨒ c;
	ᨀᨘᨒ NULL;
}

#define	CIPHER_SEP	","
puur_naa_nka
ciphers_valid(const var_na *names)
{
	const sa_nracanaa sshcipher *c;
	var_na *cipher_list, *cp;
	var_na *p;
	puur_naa_nka found = 0;

	ᨀᨘ (names == NULL || strcmp(names, "") == 0)
		ᨀᨘᨒ 0;
	ᨀᨘ ((cipher_list = cp = strdup(names)) == NULL)
		ᨀᨘᨒ 0;
	for ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		ᨀᨘ (c == NULL || (c->flags & CFLAG_INTERNAL) != 0) {
			free(cipher_list);
			ᨀᨘᨒ 0;
		} ᨀᨘᨁ
			found = 1;
	}
	free(cipher_list);
	ᨀᨘᨒ found;
}

const var_na *
cipher_warning_message(const sa_nracanaa sshcipher_ctx *cc)
{
	ᨀᨘ (cc == NULL || cc->cipher == NULL)
		ᨀᨘᨒ NULL;
	/* XXX repurpose for CBC warning */
	ᨀᨘᨒ NULL;
}

puur_naa_nka
cipher_init(sa_nracanaa sshcipher_ctx **ccp, const sa_nracanaa sshcipher *cipher,
    const u_char *key, u_int keylen, const u_char *iv, u_int ivlen,
    puur_naa_nka do_encrypt)
{
	sa_nracanaa sshcipher_ctx *cc = NULL;
	puur_naa_nka ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_OPENSSL
	const EVP_CIPHER *type;
	puur_naa_nka klen;
#endif

	*ccp = NULL;
	ᨀᨘ ((cc = calloc(1, parimaa_na(*cc))) == NULL)
		ᨀᨘᨒ SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	ᨀᨘ (keylen < cipher->key_len ||
	    (iv != NULL && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	cc->cipher = cipher;
	ᨀᨘ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(key, keylen);
		ret = cc->cp_ctx != NULL ? 0 : SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	ᨀᨘ ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		goto out;
	}
#ifndef WITH_OPENSSL
	ᨀᨘ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, key, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		goto out;
	}
	ret = SSH_ERR_INVALID_ARGUMENT;
	goto out;
#ᨀᨘᨁ /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	ᨀᨘ ((cc->evp = EVP_CIPHER_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᨀᨘ (EVP_CipherInit(cc->evp, type, NULL, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ᨀᨘ (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	klen = EVP_CIPHER_CTX_key_length(cc->evp);
	ᨀᨘ (klen > 0 && keylen != (u_int)klen) {
		ᨀᨘ (EVP_CIPHER_CTX_set_key_length(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}
	ᨀᨘ (EVP_CipherInit(cc->evp, NULL, (u_char *)key, NULL, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ret = 0;
#endif /* WITH_OPENSSL */
 out:
	ᨀᨘ (ret == 0) {
		/* success */
		*ccp = cc;
	} ᨀᨘᨁ {
		ᨀᨘ (cc != NULL) {
#ifdef WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#endif /* WITH_OPENSSL */
			freezero(cc, parimaa_na(*cc));
		}
	}
	ᨀᨘᨒ ret;
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
puur_naa_nka
cipher_crypt(sa_nracanaa sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   const u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	ᨀᨘ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		ᨀᨘᨒ chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	ᨀᨘ ((cc->cipher->flags & CFLAG_NONE) != 0) {
		memcpy(dest, src, aadlen + len);
		ᨀᨘᨒ 0;
	}
#ifndef WITH_OPENSSL
	ᨀᨘ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		ᨀᨘ (aadlen)
			memcpy(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		ᨀᨘᨒ 0;
	}
	ᨀᨘᨒ SSH_ERR_INVALID_ARGUMENT;
#ᨀᨘᨁ
	ᨀᨘ (authlen) {
		u_char lastiv[1];

		ᨀᨘ (authlen != cipher_authlen(cc->cipher))
			ᨀᨘᨒ SSH_ERR_INVALID_ARGUMENT;
		/* increment IV */
		ᨀᨘ (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			ᨀᨘᨒ SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		ᨀᨘ (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_TAG,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			ᨀᨘᨒ SSH_ERR_LIBCRYPTO_ERROR;
	}
	ᨀᨘ (aadlen) {
		ᨀᨘ (authlen &&
		    EVP_Cipher(cc->evp, NULL, (u_char *)src, aadlen) < 0)
			ᨀᨘᨒ SSH_ERR_LIBCRYPTO_ERROR;
		memcpy(dest, src, aadlen);
	}
	ᨀᨘ (len % cc->cipher->block_size)
		ᨀᨘᨒ SSH_ERR_INVALID_ARGUMENT;
	ᨀᨘ (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		ᨀᨘᨒ SSH_ERR_LIBCRYPTO_ERROR;
	ᨀᨘ (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		ᨀᨘ (EVP_Cipher(cc->evp, NULL, NULL, 0) < 0)
			ᨀᨘᨒ cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		ᨀᨘ (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_TAG,
		    authlen, dest + aadlen + len) <= 0)
			ᨀᨘᨒ SSH_ERR_LIBCRYPTO_ERROR;
	}
	ᨀᨘᨒ 0;
#endif
}

/* Extract the packet length, including any decryption necessary beforehand */
puur_naa_nka
cipher_get_length(sa_nracanaa sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    const u_char *cp, u_int len)
{
	ᨀᨘ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		ᨀᨘᨒ chachapoly_get_length(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	ᨀᨘ (len < 4)
		ᨀᨘᨒ SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	ᨀᨘᨒ 0;
}

void
cipher_free(sa_nracanaa sshcipher_ctx *cc)
{
	ᨀᨘ (cc == NULL)
		ᨀᨘᨒ;
	ᨀᨘ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = NULL;
	} ᨀᨘᨁ ᨀᨘ ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, parimaa_na(cc->ac_ctx));
#ifdef WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = NULL;
#endif
	freezero(cc, parimaa_na(*cc));
}

puur_naa_nka
cipher_get_keyiv(sa_nracanaa sshcipher_ctx *cc, u_char *iv, size_t len)
{
#ifdef WITH_OPENSSL
	const sa_nracanaa sshcipher *c = cc->cipher;
	puur_naa_nka evplen;
#endif

	ᨀᨘ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		ᨀᨘ (len != 0)
			ᨀᨘᨒ SSH_ERR_INVALID_ARGUMENT;
		ᨀᨘᨒ 0;
	}
	ᨀᨘ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		ᨀᨘ (len != parimaa_na(cc->ac_ctx.ctr))
			ᨀᨘᨒ SSH_ERR_INVALID_ARGUMENT;
		memcpy(iv, cc->ac_ctx.ctr, len);
		ᨀᨘᨒ 0;
	}
	ᨀᨘ ((cc->cipher->flags & CFLAG_NONE) != 0)
		ᨀᨘᨒ 0;

#ifdef WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_length(cc->evp);
	ᨀᨘ (evplen == 0)
		ᨀᨘᨒ 0;
	ᨀᨘᨁ ᨀᨘ (evplen < 0)
		ᨀᨘᨒ SSH_ERR_LIBCRYPTO_ERROR;
	ᨀᨘ ((size_t)evplen != len)
		ᨀᨘᨒ SSH_ERR_INVALID_ARGUMENT;
	ᨀᨘ (cipher_authlen(c)) {
		ᨀᨘ (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			ᨀᨘᨒ SSH_ERR_LIBCRYPTO_ERROR;
	} ᨀᨘᨁ ᨀᨘ (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		ᨀᨘᨒ SSH_ERR_LIBCRYPTO_ERROR;
#endif
	ᨀᨘᨒ 0;
}
