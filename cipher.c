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
	ціле	plaintext;
	ціле	encrypt;
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
#інакше
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
#інакше
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
cipher_alg_list(char sep, ціле auth_only)
{
	char *ret = NULL;
	const struct sshcipher *c;
	char sep_str[2] = {sep, '\0'};

	для (c = ciphers; c->name != NULL; c++) {
		якщо ((c->flags & CFLAG_INTERNAL) != 0)
			continue;
		якщо (auth_only && c->auth_len == 0)
			continue;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	повернути ret;
}

const char *
compression_alg_list(ціле compression)
{
#ifdef WITH_ZLIB
	повернути compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#інакше
	повернути "none";
#endif
}

u_int
cipher_blocksize(const struct sshcipher *c)
{
	повернути (c->block_size);
}

u_int
cipher_keylen(const struct sshcipher *c)
{
	повернути (c->key_len);
}

u_int
cipher_seclen(const struct sshcipher *c)
{
	якщо (strcmp("3des-cbc", c->name) == 0)
		повернути 14;
	повернути cipher_keylen(c);
}

u_int
cipher_authlen(const struct sshcipher *c)
{
	повернути (c->auth_len);
}

u_int
cipher_ivlen(const struct sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	повернути (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->block_size;
}

u_int
cipher_is_cbc(const struct sshcipher *c)
{
	повернути (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_internal(const struct sshcipher *c)
{
	повернути (c->flags & CFLAG_INTERNAL) != 0;
}

u_int
cipher_ctx_is_plaintext(struct sshcipher_ctx *cc)
{
	повернути cc->plaintext;
}

const struct sshcipher *
cipher_by_name(const char *name)
{
	const struct sshcipher *c;
	для (c = ciphers; c->name != NULL; c++)
		якщо (strcmp(c->name, name) == 0)
			повернути c;
	повернути NULL;
}

#define	CIPHER_SEP	","
ціле
ciphers_valid(const char *names)
{
	const struct sshcipher *c;
	char *cipher_list, *cp;
	char *p;
	ціле found = 0;

	якщо (names == NULL || strcmp(names, "") == 0)
		повернути 0;
	якщо ((cipher_list = cp = strdup(names)) == NULL)
		повернути 0;
	для ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		якщо (c == NULL || (c->flags & CFLAG_INTERNAL) != 0) {
			free(cipher_list);
			повернути 0;
		} інакше
			found = 1;
	}
	free(cipher_list);
	повернути found;
}

const char *
cipher_warning_message(const struct sshcipher_ctx *cc)
{
	якщо (cc == NULL || cc->cipher == NULL)
		повернути NULL;
	/* XXX repurpose for CBC warning */
	повернути NULL;
}

ціле
cipher_init(struct sshcipher_ctx **ccp, const struct sshcipher *cipher,
    const u_char *key, u_int keylen, const u_char *iv, u_int ivlen,
    ціле do_encrypt)
{
	struct sshcipher_ctx *cc = NULL;
	ціле ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_OPENSSL
	const EVP_CIPHER *type;
	ціле klen;
#endif

	*ccp = NULL;
	якщо ((cc = calloc(1, sizeof(*cc))) == NULL)
		повернути SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	якщо (keylen < cipher->key_len ||
	    (iv != NULL && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	cc->cipher = cipher;
	якщо ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(key, keylen);
		ret = cc->cp_ctx != NULL ? 0 : SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	якщо ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		goto out;
	}
#ifndef WITH_OPENSSL
	якщо ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, key, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		goto out;
	}
	ret = SSH_ERR_INVALID_ARGUMENT;
	goto out;
#інакше /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	якщо ((cc->evp = EVP_CIPHER_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	якщо (EVP_CipherInit(cc->evp, type, NULL, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	якщо (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	klen = EVP_CIPHER_CTX_key_length(cc->evp);
	якщо (klen > 0 && keylen != (u_int)klen) {
		якщо (EVP_CIPHER_CTX_set_key_length(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}
	якщо (EVP_CipherInit(cc->evp, NULL, (u_char *)key, NULL, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ret = 0;
#endif /* WITH_OPENSSL */
 out:
	якщо (ret == 0) {
		/* success */
		*ccp = cc;
	} інакше {
		якщо (cc != NULL) {
#ifdef WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#endif /* WITH_OPENSSL */
			freezero(cc, sizeof(*cc));
		}
	}
	повернути ret;
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
ціле
cipher_crypt(struct sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   const u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	якщо ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		повернути chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	якщо ((cc->cipher->flags & CFLAG_NONE) != 0) {
		memcpy(dest, src, aadlen + len);
		повернути 0;
	}
#ifndef WITH_OPENSSL
	якщо ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		якщо (aadlen)
			memcpy(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		повернути 0;
	}
	повернути SSH_ERR_INVALID_ARGUMENT;
#інакше
	якщо (authlen) {
		u_char lastiv[1];

		якщо (authlen != cipher_authlen(cc->cipher))
			повернути SSH_ERR_INVALID_ARGUMENT;
		/* increment IV */
		якщо (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			повернути SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		якщо (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_TAG,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			повернути SSH_ERR_LIBCRYPTO_ERROR;
	}
	якщо (aadlen) {
		якщо (authlen &&
		    EVP_Cipher(cc->evp, NULL, (u_char *)src, aadlen) < 0)
			повернути SSH_ERR_LIBCRYPTO_ERROR;
		memcpy(dest, src, aadlen);
	}
	якщо (len % cc->cipher->block_size)
		повернути SSH_ERR_INVALID_ARGUMENT;
	якщо (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		повернути SSH_ERR_LIBCRYPTO_ERROR;
	якщо (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		якщо (EVP_Cipher(cc->evp, NULL, NULL, 0) < 0)
			повернути cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		якщо (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_TAG,
		    authlen, dest + aadlen + len) <= 0)
			повернути SSH_ERR_LIBCRYPTO_ERROR;
	}
	повернути 0;
#endif
}

/* Extract the packet length, including any decryption necessary beforehand */
ціле
cipher_get_length(struct sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    const u_char *cp, u_int len)
{
	якщо ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		повернути chachapoly_get_length(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	якщо (len < 4)
		повернути SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	повернути 0;
}

void
cipher_free(struct sshcipher_ctx *cc)
{
	якщо (cc == NULL)
		повернути;
	якщо ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = NULL;
	} інакше якщо ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, sizeof(cc->ac_ctx));
#ifdef WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = NULL;
#endif
	freezero(cc, sizeof(*cc));
}

ціле
cipher_get_keyiv(struct sshcipher_ctx *cc, u_char *iv, size_t len)
{
#ifdef WITH_OPENSSL
	const struct sshcipher *c = cc->cipher;
	ціле evplen;
#endif

	якщо ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		якщо (len != 0)
			повернути SSH_ERR_INVALID_ARGUMENT;
		повернути 0;
	}
	якщо ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		якщо (len != sizeof(cc->ac_ctx.ctr))
			повернути SSH_ERR_INVALID_ARGUMENT;
		memcpy(iv, cc->ac_ctx.ctr, len);
		повернути 0;
	}
	якщо ((cc->cipher->flags & CFLAG_NONE) != 0)
		повернути 0;

#ifdef WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_length(cc->evp);
	якщо (evplen == 0)
		повернути 0;
	інакше якщо (evplen < 0)
		повернути SSH_ERR_LIBCRYPTO_ERROR;
	якщо ((size_t)evplen != len)
		повернути SSH_ERR_INVALID_ARGUMENT;
	якщо (cipher_authlen(c)) {
		якщо (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			повернути SSH_ERR_LIBCRYPTO_ERROR;
	} інакше якщо (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		повернути SSH_ERR_LIBCRYPTO_ERROR;
#endif
	повернути 0;
}
