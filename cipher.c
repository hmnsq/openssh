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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>

#അന്തര്ഭാവ "cipher.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"

#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

#ifndef WITH_OPENSSL
#define EVP_CIPHER_CTX ശൂന്യം
#endif

ഘടന sshcipher_ctx {
	പൂർണ്ണസംഖ്യ	plaintext;
	പൂർണ്ണസംഖ്യ	encrypt;
	EVP_CIPHER_CTX *evp;
	ഘടന chachapoly_ctx *cp_ctx;
	ഘടന aesctr_ctx ac_ctx; /* XXX union with evp? */
	സ്ഥിരം ഘടന sshcipher *cipher;
};

ഘടന sshcipher {
	അക്ഷരം	*name;
	u_int	block_size;
	u_int	താക്കോൽ_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#define CFLAG_CBC		(1<<0)
#define CFLAG_CHACHAPOLY	(1<<1)
#define CFLAG_AESCTR		(1<<2)
#define CFLAG_NONE		(1<<3)
#define CFLAG_INTERNAL		CFLAG_NONE /* Don't use "none" for packets */
#ifdef WITH_OPENSSL
	സ്ഥിരം EVP_CIPHER	*(*evptype)(ശൂന്യം);
#അല്ലെങ്കിൽ
	ശൂന്യം	*ignored;
#endif
};

സ്ഥിതം സ്ഥിരം ഘടന sshcipher ciphers[] = {
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
#അല്ലെങ്കിൽ
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, ശൂന്യ },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, ശൂന്യ },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, ശൂന്യ },
#endif
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, ശൂന്യ },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, ശൂന്യ },

	{ ശൂന്യ,			0, 0, 0, 0, 0, ശൂന്യ }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
അക്ഷരം *
cipher_alg_list(അക്ഷരം sep, പൂർണ്ണസംഖ്യ auth_only)
{
	അക്ഷരം *ret = ശൂന്യ;
	സ്ഥിരം ഘടന sshcipher *c;
	അക്ഷരം sep_str[2] = {sep, '\0'};

	വേണ്ടി (c = ciphers; c->name != ശൂന്യ; c++) {
		എങ്കിൽ ((c->flags & CFLAG_INTERNAL) != 0)
			തുടരുക;
		എങ്കിൽ (auth_only && c->auth_len == 0)
			തുടരുക;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	തിരികെ ret;
}

സ്ഥിരം അക്ഷരം *
compression_alg_list(പൂർണ്ണസംഖ്യ compression)
{
#ifdef WITH_ZLIB
	തിരികെ compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#അല്ലെങ്കിൽ
	തിരികെ "none";
#endif
}

u_int
cipher_blocksize(സ്ഥിരം ഘടന sshcipher *c)
{
	തിരികെ (c->block_size);
}

u_int
cipher_keylen(സ്ഥിരം ഘടന sshcipher *c)
{
	തിരികെ (c->താക്കോൽ_len);
}

u_int
cipher_seclen(സ്ഥിരം ഘടന sshcipher *c)
{
	എങ്കിൽ (strcmp("3des-cbc", c->name) == 0)
		തിരികെ 14;
	തിരികെ cipher_keylen(c);
}

u_int
cipher_authlen(സ്ഥിരം ഘടന sshcipher *c)
{
	തിരികെ (c->auth_len);
}

u_int
cipher_ivlen(സ്ഥിരം ഘടന sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	തിരികെ (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->block_size;
}

u_int
cipher_is_cbc(സ്ഥിരം ഘടന sshcipher *c)
{
	തിരികെ (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_internal(സ്ഥിരം ഘടന sshcipher *c)
{
	തിരികെ (c->flags & CFLAG_INTERNAL) != 0;
}

u_int
cipher_ctx_is_plaintext(ഘടന sshcipher_ctx *cc)
{
	തിരികെ cc->plaintext;
}

സ്ഥിരം ഘടന sshcipher *
cipher_by_name(സ്ഥിരം അക്ഷരം *name)
{
	സ്ഥിരം ഘടന sshcipher *c;
	വേണ്ടി (c = ciphers; c->name != ശൂന്യ; c++)
		എങ്കിൽ (strcmp(c->name, name) == 0)
			തിരികെ c;
	തിരികെ ശൂന്യ;
}

#define	CIPHER_SEP	","
പൂർണ്ണസംഖ്യ
ciphers_valid(സ്ഥിരം അക്ഷരം *names)
{
	സ്ഥിരം ഘടന sshcipher *c;
	അക്ഷരം *cipher_list, *cp;
	അക്ഷരം *p;
	പൂർണ്ണസംഖ്യ found = 0;

	എങ്കിൽ (names == ശൂന്യ || strcmp(names, "") == 0)
		തിരികെ 0;
	എങ്കിൽ ((cipher_list = cp = strdup(names)) == ശൂന്യ)
		തിരികെ 0;
	വേണ്ടി ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		എങ്കിൽ (c == ശൂന്യ || (c->flags & CFLAG_INTERNAL) != 0) {
			സ്വതന്ത്രം(cipher_list);
			തിരികെ 0;
		} അല്ലെങ്കിൽ
			found = 1;
	}
	സ്വതന്ത്രം(cipher_list);
	തിരികെ found;
}

സ്ഥിരം അക്ഷരം *
cipher_warning_message(സ്ഥിരം ഘടന sshcipher_ctx *cc)
{
	എങ്കിൽ (cc == ശൂന്യ || cc->cipher == ശൂന്യ)
		തിരികെ ശൂന്യ;
	/* XXX repurpose for CBC warning */
	തിരികെ ശൂന്യ;
}

പൂർണ്ണസംഖ്യ
cipher_init(ഘടന sshcipher_ctx **ccp, സ്ഥിരം ഘടന sshcipher *cipher,
    സ്ഥിരം u_char *താക്കോൽ, u_int keylen, സ്ഥിരം u_char *iv, u_int ivlen,
    പൂർണ്ണസംഖ്യ do_encrypt)
{
	ഘടന sshcipher_ctx *cc = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_OPENSSL
	സ്ഥിരം EVP_CIPHER *type;
	പൂർണ്ണസംഖ്യ klen;
#endif

	*ccp = ശൂന്യ;
	എങ്കിൽ ((cc = calloc(1, വലുപ്പം(*cc))) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	എങ്കിൽ (keylen < cipher->താക്കോൽ_len ||
	    (iv != ശൂന്യ && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}

	cc->cipher = cipher;
	എങ്കിൽ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(താക്കോൽ, keylen);
		ret = cc->cp_ctx != ശൂന്യ ? 0 : SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	എങ്കിൽ ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		പോകുക out;
	}
#ifndef WITH_OPENSSL
	എങ്കിൽ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, താക്കോൽ, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		പോകുക out;
	}
	ret = SSH_ERR_INVALID_ARGUMENT;
	പോകുക out;
#അല്ലെങ്കിൽ /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	എങ്കിൽ ((cc->evp = EVP_CIPHER_CTX_new()) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (EVP_CipherInit(cc->evp, type, ശൂന്യ, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	എങ്കിൽ (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	klen = EVP_CIPHER_CTX_താക്കോൽ_length(cc->evp);
	എങ്കിൽ (klen > 0 && keylen != (u_int)klen) {
		എങ്കിൽ (EVP_CIPHER_CTX_set_താക്കോൽ_length(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			പോകുക out;
		}
	}
	എങ്കിൽ (EVP_CipherInit(cc->evp, ശൂന്യ, (u_char *)താക്കോൽ, ശൂന്യ, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	ret = 0;
#endif /* WITH_OPENSSL */
 out:
	എങ്കിൽ (ret == 0) {
		/* success */
		*ccp = cc;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (cc != ശൂന്യ) {
#ifdef WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#endif /* WITH_OPENSSL */
			freezero(cc, വലുപ്പം(*cc));
		}
	}
	തിരികെ ret;
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
പൂർണ്ണസംഖ്യ
cipher_crypt(ഘടന sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   സ്ഥിരം u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	എങ്കിൽ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		തിരികെ chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	എങ്കിൽ ((cc->cipher->flags & CFLAG_NONE) != 0) {
		memcpy(dest, src, aadlen + len);
		തിരികെ 0;
	}
#ifndef WITH_OPENSSL
	എങ്കിൽ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		എങ്കിൽ (aadlen)
			memcpy(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		തിരികെ 0;
	}
	തിരികെ SSH_ERR_INVALID_ARGUMENT;
#അല്ലെങ്കിൽ
	എങ്കിൽ (authlen) {
		u_char lastiv[1];

		എങ്കിൽ (authlen != cipher_authlen(cc->cipher))
			തിരികെ SSH_ERR_INVALID_ARGUMENT;
		/* increment IV */
		എങ്കിൽ (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		എങ്കിൽ (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_TAG,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
	}
	എങ്കിൽ (aadlen) {
		എങ്കിൽ (authlen &&
		    EVP_Cipher(cc->evp, ശൂന്യ, (u_char *)src, aadlen) < 0)
			തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
		memcpy(dest, src, aadlen);
	}
	എങ്കിൽ (len % cc->cipher->block_size)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
	എങ്കിൽ (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		എങ്കിൽ (EVP_Cipher(cc->evp, ശൂന്യ, ശൂന്യ, 0) < 0)
			തിരികെ cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		എങ്കിൽ (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_TAG,
		    authlen, dest + aadlen + len) <= 0)
			തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
	}
	തിരികെ 0;
#endif
}

/* Extract the packet length, including any decryption necessary beforehand */
പൂർണ്ണസംഖ്യ
cipher_get_length(ഘടന sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    സ്ഥിരം u_char *cp, u_int len)
{
	എങ്കിൽ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		തിരികെ chachapoly_get_length(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	എങ്കിൽ (len < 4)
		തിരികെ SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	തിരികെ 0;
}

ശൂന്യം
cipher_free(ഘടന sshcipher_ctx *cc)
{
	എങ്കിൽ (cc == ശൂന്യ)
		തിരികെ;
	എങ്കിൽ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = ശൂന്യ;
	} അല്ലെങ്കിൽ എങ്കിൽ ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, വലുപ്പം(cc->ac_ctx));
#ifdef WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = ശൂന്യ;
#endif
	freezero(cc, വലുപ്പം(*cc));
}

പൂർണ്ണസംഖ്യ
cipher_get_keyiv(ഘടന sshcipher_ctx *cc, u_char *iv, size_t len)
{
#ifdef WITH_OPENSSL
	സ്ഥിരം ഘടന sshcipher *c = cc->cipher;
	പൂർണ്ണസംഖ്യ evplen;
#endif

	എങ്കിൽ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		എങ്കിൽ (len != 0)
			തിരികെ SSH_ERR_INVALID_ARGUMENT;
		തിരികെ 0;
	}
	എങ്കിൽ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		എങ്കിൽ (len != വലുപ്പം(cc->ac_ctx.ctr))
			തിരികെ SSH_ERR_INVALID_ARGUMENT;
		memcpy(iv, cc->ac_ctx.ctr, len);
		തിരികെ 0;
	}
	എങ്കിൽ ((cc->cipher->flags & CFLAG_NONE) != 0)
		തിരികെ 0;

#ifdef WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_length(cc->evp);
	എങ്കിൽ (evplen == 0)
		തിരികെ 0;
	അല്ലെങ്കിൽ എങ്കിൽ (evplen < 0)
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
	എങ്കിൽ ((size_t)evplen != len)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (cipher_authlen(c)) {
		എങ്കിൽ (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
	} അല്ലെങ്കിൽ എങ്കിൽ (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
#endif
	തിരികെ 0;
}
