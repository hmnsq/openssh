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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ifndef WITH_OPENSSL
#define EVP_CIPHER_CTX ಶೂನ್ಯ
#endif

ಸಂರಚನಾ sshcipher_ctx {
	ಪೂರ್ಣಾಙ್ಕ	plaintext;
	ಪೂರ್ಣಾಙ್ಕ	encrypt;
	EVP_CIPHER_CTX *evp;
	ಸಂರಚನಾ chachapoly_ctx *cp_ctx;
	ಸಂರಚನಾ aesctr_ctx ac_ctx; /* XXX union with evp? */
	ಧ್ರುವ ಸಂರಚನಾ sshcipher *cipher;
};

ಸಂರಚನಾ sshcipher {
	ವರ್ಣ	*name;
	u_int	block_size;
	u_int	ಕೀಲಿ_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#define CFLAG_CBC		(1<<0)
#define CFLAG_CHACHAPOLY	(1<<1)
#define CFLAG_AESCTR		(1<<2)
#define CFLAG_NONE		(1<<3)
#define CFLAG_INTERNAL		CFLAG_NONE /* Don't use "none" for packets */
#ifdef WITH_OPENSSL
	ಧ್ರುವ EVP_CIPHER	*(*evptype)(ಶೂನ್ಯ);
#ಅನ್ಯಥಾ
	ಶೂನ್ಯ	*ignored;
#endif
};

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ sshcipher ciphers[] = {
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
#ಅನ್ಯಥಾ
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, ರಿಕ್ತ },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, ರಿಕ್ತ },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, ರಿಕ್ತ },
#endif
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, ರಿಕ್ತ },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, ರಿಕ್ತ },

	{ ರಿಕ್ತ,			0, 0, 0, 0, 0, ರಿಕ್ತ }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
ವರ್ಣ *
cipher_alg_list(ವರ್ಣ sep, ಪೂರ್ಣಾಙ್ಕ auth_only)
{
	ವರ್ಣ *ret = ರಿಕ್ತ;
	ಧ್ರುವ ಸಂರಚನಾ sshcipher *c;
	ವರ್ಣ sep_str[2] = {sep, '\0'};

	ಪ್ರತಿ (c = ciphers; c->name != ರಿಕ್ತ; c++) {
		ಯದಿ ((c->flags & CFLAG_INTERNAL) != 0)
			ಅನುವರ್ತ;
		ಯದಿ (auth_only && c->auth_len == 0)
			ಅನುವರ್ತ;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಧ್ರುವ ವರ್ಣ *
compression_alg_list(ಪೂರ್ಣಾಙ್ಕ compression)
{
#ifdef WITH_ZLIB
	ಪ್ರತ್ಯಾಗಮ compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#ಅನ್ಯಥಾ
	ಪ್ರತ್ಯಾಗಮ "none";
#endif
}

u_int
cipher_blocksize(ಧ್ರುವ ಸಂರಚನಾ sshcipher *c)
{
	ಪ್ರತ್ಯಾಗಮ (c->block_size);
}

u_int
cipher_keylen(ಧ್ರುವ ಸಂರಚನಾ sshcipher *c)
{
	ಪ್ರತ್ಯಾಗಮ (c->ಕೀಲಿ_len);
}

u_int
cipher_seclen(ಧ್ರುವ ಸಂರಚನಾ sshcipher *c)
{
	ಯದಿ (strcmp("3des-cbc", c->name) == 0)
		ಪ್ರತ್ಯಾಗಮ 14;
	ಪ್ರತ್ಯಾಗಮ cipher_keylen(c);
}

u_int
cipher_authlen(ಧ್ರುವ ಸಂರಚನಾ sshcipher *c)
{
	ಪ್ರತ್ಯಾಗಮ (c->auth_len);
}

u_int
cipher_ivlen(ಧ್ರುವ ಸಂರಚನಾ sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	ಪ್ರತ್ಯಾಗಮ (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->block_size;
}

u_int
cipher_is_cbc(ಧ್ರುವ ಸಂರಚನಾ sshcipher *c)
{
	ಪ್ರತ್ಯಾಗಮ (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_internal(ಧ್ರುವ ಸಂರಚನಾ sshcipher *c)
{
	ಪ್ರತ್ಯಾಗಮ (c->flags & CFLAG_INTERNAL) != 0;
}

u_int
cipher_ctx_is_plaintext(ಸಂರಚನಾ sshcipher_ctx *cc)
{
	ಪ್ರತ್ಯಾಗಮ cc->plaintext;
}

ಧ್ರುವ ಸಂರಚನಾ sshcipher *
cipher_by_name(ಧ್ರುವ ವರ್ಣ *name)
{
	ಧ್ರುವ ಸಂರಚನಾ sshcipher *c;
	ಪ್ರತಿ (c = ciphers; c->name != ರಿಕ್ತ; c++)
		ಯದಿ (strcmp(c->name, name) == 0)
			ಪ್ರತ್ಯಾಗಮ c;
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

#define	CIPHER_SEP	","
ಪೂರ್ಣಾಙ್ಕ
ciphers_valid(ಧ್ರುವ ವರ್ಣ *names)
{
	ಧ್ರುವ ಸಂರಚನಾ sshcipher *c;
	ವರ್ಣ *cipher_list, *cp;
	ವರ್ಣ *p;
	ಪೂರ್ಣಾಙ್ಕ found = 0;

	ಯದಿ (names == ರಿಕ್ತ || strcmp(names, "") == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((cipher_list = cp = strdup(names)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತಿ ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		ಯದಿ (c == ರಿಕ್ತ || (c->flags & CFLAG_INTERNAL) != 0) {
			ಮುಕ್ತ(cipher_list);
			ಪ್ರತ್ಯಾಗಮ 0;
		} ಅನ್ಯಥಾ
			found = 1;
	}
	ಮುಕ್ತ(cipher_list);
	ಪ್ರತ್ಯಾಗಮ found;
}

ಧ್ರುವ ವರ್ಣ *
cipher_warning_message(ಧ್ರುವ ಸಂರಚನಾ sshcipher_ctx *cc)
{
	ಯದಿ (cc == ರಿಕ್ತ || cc->cipher == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	/* XXX repurpose for CBC warning */
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಪೂರ್ಣಾಙ್ಕ
cipher_init(ಸಂರಚನಾ sshcipher_ctx **ccp, ಧ್ರುವ ಸಂರಚನಾ sshcipher *cipher,
    ಧ್ರುವ u_char *ಕೀಲಿ, u_int keylen, ಧ್ರುವ u_char *iv, u_int ivlen,
    ಪೂರ್ಣಾಙ್ಕ do_encrypt)
{
	ಸಂರಚನಾ sshcipher_ctx *cc = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_OPENSSL
	ಧ್ರುವ EVP_CIPHER *type;
	ಪೂರ್ಣಾಙ್ಕ klen;
#endif

	*ccp = ರಿಕ್ತ;
	ಯದಿ ((cc = calloc(1, ಪರಿಮಾಣ(*cc))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	ಯದಿ (keylen < cipher->ಕೀಲಿ_len ||
	    (iv != ರಿಕ್ತ && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}

	cc->cipher = cipher;
	ಯದಿ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(ಕೀಲಿ, keylen);
		ret = cc->cp_ctx != ರಿಕ್ತ ? 0 : SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		ಗಚ್ಛ out;
	}
#ifndef WITH_OPENSSL
	ಯದಿ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, ಕೀಲಿ, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		ಗಚ್ಛ out;
	}
	ret = SSH_ERR_INVALID_ARGUMENT;
	ಗಚ್ಛ out;
#ಅನ್ಯಥಾ /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	ಯದಿ ((cc->evp = EVP_CIPHER_CTX_new()) == ರಿಕ್ತ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_CipherInit(cc->evp, type, ರಿಕ್ತ, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	klen = EVP_CIPHER_CTX_ಕೀಲಿ_length(cc->evp);
	ಯದಿ (klen > 0 && keylen != (u_int)klen) {
		ಯದಿ (EVP_CIPHER_CTX_set_ಕೀಲಿ_length(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			ಗಚ್ಛ out;
		}
	}
	ಯದಿ (EVP_CipherInit(cc->evp, ರಿಕ್ತ, (u_char *)ಕೀಲಿ, ರಿಕ್ತ, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ret = 0;
#endif /* WITH_OPENSSL */
 out:
	ಯದಿ (ret == 0) {
		/* success */
		*ccp = cc;
	} ಅನ್ಯಥಾ {
		ಯದಿ (cc != ರಿಕ್ತ) {
#ifdef WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#endif /* WITH_OPENSSL */
			freezero(cc, ಪರಿಮಾಣ(*cc));
		}
	}
	ಪ್ರತ್ಯಾಗಮ ret;
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
ಪೂರ್ಣಾಙ್ಕ
cipher_crypt(ಸಂರಚನಾ sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   ಧ್ರುವ u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	ಯದಿ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		ಪ್ರತ್ಯಾಗಮ chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	ಯದಿ ((cc->cipher->flags & CFLAG_NONE) != 0) {
		memcpy(dest, src, aadlen + len);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
#ifndef WITH_OPENSSL
	ಯದಿ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		ಯದಿ (aadlen)
			memcpy(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
#ಅನ್ಯಥಾ
	ಯದಿ (authlen) {
		u_char lastiv[1];

		ಯದಿ (authlen != cipher_authlen(cc->cipher))
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
		/* increment IV */
		ಯದಿ (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		ಯದಿ (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_TAG,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
	}
	ಯದಿ (aadlen) {
		ಯದಿ (authlen &&
		    EVP_Cipher(cc->evp, ರಿಕ್ತ, (u_char *)src, aadlen) < 0)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
		memcpy(dest, src, aadlen);
	}
	ಯದಿ (len % cc->cipher->block_size)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
	ಯದಿ (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		ಯದಿ (EVP_Cipher(cc->evp, ರಿಕ್ತ, ರಿಕ್ತ, 0) < 0)
			ಪ್ರತ್ಯಾಗಮ cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		ಯದಿ (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_TAG,
		    authlen, dest + aadlen + len) <= 0)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
#endif
}

/* Extract the packet length, including any decryption necessary beforehand */
ಪೂರ್ಣಾಙ್ಕ
cipher_get_length(ಸಂರಚನಾ sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    ಧ್ರುವ u_char *cp, u_int len)
{
	ಯದಿ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		ಪ್ರತ್ಯಾಗಮ chachapoly_get_length(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	ಯದಿ (len < 4)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
cipher_free(ಸಂರಚನಾ sshcipher_ctx *cc)
{
	ಯದಿ (cc == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = ರಿಕ್ತ;
	} ಅನ್ಯಥಾ ಯದಿ ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, ಪರಿಮಾಣ(cc->ac_ctx));
#ifdef WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = ರಿಕ್ತ;
#endif
	freezero(cc, ಪರಿಮಾಣ(*cc));
}

ಪೂರ್ಣಾಙ್ಕ
cipher_get_keyiv(ಸಂರಚನಾ sshcipher_ctx *cc, u_char *iv, size_t len)
{
#ifdef WITH_OPENSSL
	ಧ್ರುವ ಸಂರಚನಾ sshcipher *c = cc->cipher;
	ಪೂರ್ಣಾಙ್ಕ evplen;
#endif

	ಯದಿ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		ಯದಿ (len != 0)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		ಯದಿ (len != ಪರಿಮಾಣ(cc->ac_ctx.ctr))
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
		memcpy(iv, cc->ac_ctx.ctr, len);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ ((cc->cipher->flags & CFLAG_NONE) != 0)
		ಪ್ರತ್ಯಾಗಮ 0;

#ifdef WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_length(cc->evp);
	ಯದಿ (evplen == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಅನ್ಯಥಾ ಯದಿ (evplen < 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
	ಯದಿ ((size_t)evplen != len)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (cipher_authlen(c)) {
		ಯದಿ (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
	} ಅನ್ಯಥಾ ಯದಿ (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
#endif
	ಪ್ರತ್ಯಾಗಮ 0;
}
