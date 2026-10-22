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

struct sshcipher_ctx {
	整数	plaintext;
	整数	encrypt;
	EVP_CIPHER_CTX *evp;
	struct chachapoly_ctx *cp_ctx;
	struct aesctr_ctx ac_ctx; /* XXX union with evp? */
	const struct sshcipher *cipher;
};

struct sshcipher {
	char	*name;
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
#否则
	void	*ignored;
#endif
};

static const struct sshcipher ciphers[] = {
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
#否则
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
char *
cipher_alg_list(char sep, 整数 auth_only)
{
	char *ret = NULL;
	const struct sshcipher *c;
	char sep_str[2] = {sep, '\0'};

	为 (c = ciphers; c->name != NULL; c++) {
		如果 ((c->flags & CFLAG_INTERNAL) != 0)
			continue;
		如果 (auth_only && c->auth_len == 0)
			continue;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	返回 ret;
}

const char *
compression_alg_list(整数 compression)
{
#ifdef WITH_ZLIB
	返回 compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#否则
	返回 "none";
#endif
}

u_int
cipher_blocksize(const struct sshcipher *c)
{
	返回 (c->block_size);
}

u_int
cipher_keylen(const struct sshcipher *c)
{
	返回 (c->key_len);
}

u_int
cipher_seclen(const struct sshcipher *c)
{
	如果 (strcmp("3des-cbc", c->name) == 0)
		返回 14;
	返回 cipher_keylen(c);
}

u_int
cipher_authlen(const struct sshcipher *c)
{
	返回 (c->auth_len);
}

u_int
cipher_ivlen(const struct sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	返回 (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->block_size;
}

u_int
cipher_is_cbc(const struct sshcipher *c)
{
	返回 (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_internal(const struct sshcipher *c)
{
	返回 (c->flags & CFLAG_INTERNAL) != 0;
}

u_int
cipher_ctx_is_plaintext(struct sshcipher_ctx *cc)
{
	返回 cc->plaintext;
}

const struct sshcipher *
cipher_by_name(const char *name)
{
	const struct sshcipher *c;
	为 (c = ciphers; c->name != NULL; c++)
		如果 (strcmp(c->name, name) == 0)
			返回 c;
	返回 NULL;
}

#define	CIPHER_SEP	","
整数
ciphers_valid(const char *names)
{
	const struct sshcipher *c;
	char *cipher_list, *cp;
	char *p;
	整数 found = 0;

	如果 (names == NULL || strcmp(names, "") == 0)
		返回 0;
	如果 ((cipher_list = cp = strdup(names)) == NULL)
		返回 0;
	为 ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		如果 (c == NULL || (c->flags & CFLAG_INTERNAL) != 0) {
			free(cipher_list);
			返回 0;
		} 否则
			found = 1;
	}
	free(cipher_list);
	返回 found;
}

const char *
cipher_warning_message(const struct sshcipher_ctx *cc)
{
	如果 (cc == NULL || cc->cipher == NULL)
		返回 NULL;
	/* XXX repurpose for CBC warning */
	返回 NULL;
}

整数
cipher_init(struct sshcipher_ctx **ccp, const struct sshcipher *cipher,
    const u_char *key, u_int keylen, const u_char *iv, u_int ivlen,
    整数 do_encrypt)
{
	struct sshcipher_ctx *cc = NULL;
	整数 ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_OPENSSL
	const EVP_CIPHER *type;
	整数 klen;
#endif

	*ccp = NULL;
	如果 ((cc = calloc(1, sizeof(*cc))) == NULL)
		返回 SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	如果 (keylen < cipher->key_len ||
	    (iv != NULL && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	cc->cipher = cipher;
	如果 ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(key, keylen);
		ret = cc->cp_ctx != NULL ? 0 : SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	如果 ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		goto out;
	}
#ifndef WITH_OPENSSL
	如果 ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, key, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		goto out;
	}
	ret = SSH_ERR_INVALID_ARGUMENT;
	goto out;
#否则 /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	如果 ((cc->evp = EVP_CIPHER_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	如果 (EVP_CipherInit(cc->evp, type, NULL, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	如果 (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	klen = EVP_CIPHER_CTX_key_length(cc->evp);
	如果 (klen > 0 && keylen != (u_int)klen) {
		如果 (EVP_CIPHER_CTX_set_key_length(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}
	如果 (EVP_CipherInit(cc->evp, NULL, (u_char *)key, NULL, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ret = 0;
#endif /* WITH_OPENSSL */
 out:
	如果 (ret == 0) {
		/* success */
		*ccp = cc;
	} 否则 {
		如果 (cc != NULL) {
#ifdef WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#endif /* WITH_OPENSSL */
			freezero(cc, sizeof(*cc));
		}
	}
	返回 ret;
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
整数
cipher_crypt(struct sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   const u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	如果 ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		返回 chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	如果 ((cc->cipher->flags & CFLAG_NONE) != 0) {
		memcpy(dest, src, aadlen + len);
		返回 0;
	}
#ifndef WITH_OPENSSL
	如果 ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		如果 (aadlen)
			memcpy(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		返回 0;
	}
	返回 SSH_ERR_INVALID_ARGUMENT;
#否则
	如果 (authlen) {
		u_char lastiv[1];

		如果 (authlen != cipher_authlen(cc->cipher))
			返回 SSH_ERR_INVALID_ARGUMENT;
		/* increment IV */
		如果 (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			返回 SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		如果 (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_TAG,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			返回 SSH_ERR_LIBCRYPTO_ERROR;
	}
	如果 (aadlen) {
		如果 (authlen &&
		    EVP_Cipher(cc->evp, NULL, (u_char *)src, aadlen) < 0)
			返回 SSH_ERR_LIBCRYPTO_ERROR;
		memcpy(dest, src, aadlen);
	}
	如果 (len % cc->cipher->block_size)
		返回 SSH_ERR_INVALID_ARGUMENT;
	如果 (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		返回 SSH_ERR_LIBCRYPTO_ERROR;
	如果 (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		如果 (EVP_Cipher(cc->evp, NULL, NULL, 0) < 0)
			返回 cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		如果 (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_TAG,
		    authlen, dest + aadlen + len) <= 0)
			返回 SSH_ERR_LIBCRYPTO_ERROR;
	}
	返回 0;
#endif
}

/* Extract the packet length, including any decryption necessary beforehand */
整数
cipher_get_length(struct sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    const u_char *cp, u_int len)
{
	如果 ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		返回 chachapoly_get_length(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	如果 (len < 4)
		返回 SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	返回 0;
}

void
cipher_free(struct sshcipher_ctx *cc)
{
	如果 (cc == NULL)
		返回;
	如果 ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = NULL;
	} 否则 如果 ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, sizeof(cc->ac_ctx));
#ifdef WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = NULL;
#endif
	freezero(cc, sizeof(*cc));
}

整数
cipher_get_keyiv(struct sshcipher_ctx *cc, u_char *iv, size_t len)
{
#ifdef WITH_OPENSSL
	const struct sshcipher *c = cc->cipher;
	整数 evplen;
#endif

	如果 ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		如果 (len != 0)
			返回 SSH_ERR_INVALID_ARGUMENT;
		返回 0;
	}
	如果 ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		如果 (len != sizeof(cc->ac_ctx.ctr))
			返回 SSH_ERR_INVALID_ARGUMENT;
		memcpy(iv, cc->ac_ctx.ctr, len);
		返回 0;
	}
	如果 ((cc->cipher->flags & CFLAG_NONE) != 0)
		返回 0;

#ifdef WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_length(cc->evp);
	如果 (evplen == 0)
		返回 0;
	否则 如果 (evplen < 0)
		返回 SSH_ERR_LIBCRYPTO_ERROR;
	如果 ((size_t)evplen != len)
		返回 SSH_ERR_INVALID_ARGUMENT;
	如果 (cipher_authlen(c)) {
		如果 (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			返回 SSH_ERR_LIBCRYPTO_ERROR;
	} 否则 如果 (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		返回 SSH_ERR_LIBCRYPTO_ERROR;
#endif
	返回 0;
}
