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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>

#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"

#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

#ifndef WITH_OPENSSL
#define EVP_CIPHER_CTX வெறுமை
#endif

கட்டமைப்பு sshcipher_ctx {
	முழு	plaintext;
	முழு	encrypt;
	EVP_CIPHER_CTX *evp;
	கட்டமைப்பு chachapoly_ctx *cp_ctx;
	கட்டமைப்பு aesctr_ctx ac_ctx; /* XXX union with evp? */
	மாறிலி கட்டமைப்பு sshcipher *cipher;
};

கட்டமைப்பு sshcipher {
	எழுத்து	*name;
	u_int	block_size;
	u_int	சாவி_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#define CFLAG_CBC		(1<<0)
#define CFLAG_CHACHAPOLY	(1<<1)
#define CFLAG_AESCTR		(1<<2)
#define CFLAG_NONE		(1<<3)
#define CFLAG_INTERNAL		CFLAG_NONE /* Don't use "none" for packets */
#ifdef WITH_OPENSSL
	மாறிலி EVP_CIPHER	*(*evptype)(வெறுமை);
#இல்லையெனில்
	வெறுமை	*ignored;
#endif
};

நிலையான மாறிலி கட்டமைப்பு sshcipher ciphers[] = {
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
#இல்லையெனில்
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, வெற்று },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, வெற்று },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, வெற்று },
#endif
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, வெற்று },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, வெற்று },

	{ வெற்று,			0, 0, 0, 0, 0, வெற்று }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
எழுத்து *
cipher_alg_list(எழுத்து sep, முழு auth_only)
{
	எழுத்து *ret = வெற்று;
	மாறிலி கட்டமைப்பு sshcipher *c;
	எழுத்து sep_str[2] = {sep, '\0'};

	க்கு (c = ciphers; c->name != வெற்று; c++) {
		எனில் ((c->flags & CFLAG_INTERNAL) != 0)
			தொடர்;
		எனில் (auth_only && c->auth_len == 0)
			தொடர்;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	திரும்பு ret;
}

மாறிலி எழுத்து *
compression_alg_list(முழு compression)
{
#ifdef WITH_ZLIB
	திரும்பு compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#இல்லையெனில்
	திரும்பு "none";
#endif
}

u_int
cipher_blocksize(மாறிலி கட்டமைப்பு sshcipher *c)
{
	திரும்பு (c->block_size);
}

u_int
cipher_keylen(மாறிலி கட்டமைப்பு sshcipher *c)
{
	திரும்பு (c->சாவி_len);
}

u_int
cipher_seclen(மாறிலி கட்டமைப்பு sshcipher *c)
{
	எனில் (strcmp("3des-cbc", c->name) == 0)
		திரும்பு 14;
	திரும்பு cipher_keylen(c);
}

u_int
cipher_authlen(மாறிலி கட்டமைப்பு sshcipher *c)
{
	திரும்பு (c->auth_len);
}

u_int
cipher_ivlen(மாறிலி கட்டமைப்பு sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	திரும்பு (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->block_size;
}

u_int
cipher_is_cbc(மாறிலி கட்டமைப்பு sshcipher *c)
{
	திரும்பு (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_internal(மாறிலி கட்டமைப்பு sshcipher *c)
{
	திரும்பு (c->flags & CFLAG_INTERNAL) != 0;
}

u_int
cipher_ctx_is_plaintext(கட்டமைப்பு sshcipher_ctx *cc)
{
	திரும்பு cc->plaintext;
}

மாறிலி கட்டமைப்பு sshcipher *
cipher_by_name(மாறிலி எழுத்து *name)
{
	மாறிலி கட்டமைப்பு sshcipher *c;
	க்கு (c = ciphers; c->name != வெற்று; c++)
		எனில் (strcmp(c->name, name) == 0)
			திரும்பு c;
	திரும்பு வெற்று;
}

#define	CIPHER_SEP	","
முழு
ciphers_valid(மாறிலி எழுத்து *names)
{
	மாறிலி கட்டமைப்பு sshcipher *c;
	எழுத்து *cipher_list, *cp;
	எழுத்து *p;
	முழு found = 0;

	எனில் (names == வெற்று || strcmp(names, "") == 0)
		திரும்பு 0;
	எனில் ((cipher_list = cp = strdup(names)) == வெற்று)
		திரும்பு 0;
	க்கு ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		எனில் (c == வெற்று || (c->flags & CFLAG_INTERNAL) != 0) {
			விடுவி(cipher_list);
			திரும்பு 0;
		} இல்லையெனில்
			found = 1;
	}
	விடுவி(cipher_list);
	திரும்பு found;
}

மாறிலி எழுத்து *
cipher_warning_message(மாறிலி கட்டமைப்பு sshcipher_ctx *cc)
{
	எனில் (cc == வெற்று || cc->cipher == வெற்று)
		திரும்பு வெற்று;
	/* XXX repurpose for CBC warning */
	திரும்பு வெற்று;
}

முழு
cipher_init(கட்டமைப்பு sshcipher_ctx **ccp, மாறிலி கட்டமைப்பு sshcipher *cipher,
    மாறிலி u_char *சாவி, u_int keylen, மாறிலி u_char *iv, u_int ivlen,
    முழு do_encrypt)
{
	கட்டமைப்பு sshcipher_ctx *cc = வெற்று;
	முழு ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_OPENSSL
	மாறிலி EVP_CIPHER *type;
	முழு klen;
#endif

	*ccp = வெற்று;
	எனில் ((cc = calloc(1, அளவு(*cc))) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	எனில் (keylen < cipher->சாவி_len ||
	    (iv != வெற்று && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}

	cc->cipher = cipher;
	எனில் ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(சாவி, keylen);
		ret = cc->cp_ctx != வெற்று ? 0 : SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	எனில் ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		செல் out;
	}
#ifndef WITH_OPENSSL
	எனில் ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, சாவி, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		செல் out;
	}
	ret = SSH_ERR_INVALID_ARGUMENT;
	செல் out;
#இல்லையெனில் /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	எனில் ((cc->evp = EVP_CIPHER_CTX_new()) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (EVP_CipherInit(cc->evp, type, வெற்று, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	எனில் (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	klen = EVP_CIPHER_CTX_சாவி_length(cc->evp);
	எனில் (klen > 0 && keylen != (u_int)klen) {
		எனில் (EVP_CIPHER_CTX_set_சாவி_length(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			செல் out;
		}
	}
	எனில் (EVP_CipherInit(cc->evp, வெற்று, (u_char *)சாவி, வெற்று, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	ret = 0;
#endif /* WITH_OPENSSL */
 out:
	எனில் (ret == 0) {
		/* success */
		*ccp = cc;
	} இல்லையெனில் {
		எனில் (cc != வெற்று) {
#ifdef WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#endif /* WITH_OPENSSL */
			freezero(cc, அளவு(*cc));
		}
	}
	திரும்பு ret;
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
முழு
cipher_crypt(கட்டமைப்பு sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   மாறிலி u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	எனில் ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		திரும்பு chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	எனில் ((cc->cipher->flags & CFLAG_NONE) != 0) {
		memcpy(dest, src, aadlen + len);
		திரும்பு 0;
	}
#ifndef WITH_OPENSSL
	எனில் ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		எனில் (aadlen)
			memcpy(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		திரும்பு 0;
	}
	திரும்பு SSH_ERR_INVALID_ARGUMENT;
#இல்லையெனில்
	எனில் (authlen) {
		u_char lastiv[1];

		எனில் (authlen != cipher_authlen(cc->cipher))
			திரும்பு SSH_ERR_INVALID_ARGUMENT;
		/* increment IV */
		எனில் (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		எனில் (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_TAG,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
	}
	எனில் (aadlen) {
		எனில் (authlen &&
		    EVP_Cipher(cc->evp, வெற்று, (u_char *)src, aadlen) < 0)
			திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
		memcpy(dest, src, aadlen);
	}
	எனில் (len % cc->cipher->block_size)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
	எனில் (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		எனில் (EVP_Cipher(cc->evp, வெற்று, வெற்று, 0) < 0)
			திரும்பு cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		எனில் (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_TAG,
		    authlen, dest + aadlen + len) <= 0)
			திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
	}
	திரும்பு 0;
#endif
}

/* Extract the packet length, including any decryption necessary beforehand */
முழு
cipher_get_length(கட்டமைப்பு sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    மாறிலி u_char *cp, u_int len)
{
	எனில் ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		திரும்பு chachapoly_get_length(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	எனில் (len < 4)
		திரும்பு SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	திரும்பு 0;
}

வெறுமை
cipher_free(கட்டமைப்பு sshcipher_ctx *cc)
{
	எனில் (cc == வெற்று)
		திரும்பு;
	எனில் ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = வெற்று;
	} இல்லையெனில் எனில் ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, அளவு(cc->ac_ctx));
#ifdef WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = வெற்று;
#endif
	freezero(cc, அளவு(*cc));
}

முழு
cipher_get_keyiv(கட்டமைப்பு sshcipher_ctx *cc, u_char *iv, size_t len)
{
#ifdef WITH_OPENSSL
	மாறிலி கட்டமைப்பு sshcipher *c = cc->cipher;
	முழு evplen;
#endif

	எனில் ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		எனில் (len != 0)
			திரும்பு SSH_ERR_INVALID_ARGUMENT;
		திரும்பு 0;
	}
	எனில் ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		எனில் (len != அளவு(cc->ac_ctx.ctr))
			திரும்பு SSH_ERR_INVALID_ARGUMENT;
		memcpy(iv, cc->ac_ctx.ctr, len);
		திரும்பு 0;
	}
	எனில் ((cc->cipher->flags & CFLAG_NONE) != 0)
		திரும்பு 0;

#ifdef WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_length(cc->evp);
	எனில் (evplen == 0)
		திரும்பு 0;
	இல்லையெனில் எனில் (evplen < 0)
		திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
	எனில் ((size_t)evplen != len)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (cipher_authlen(c)) {
		எனில் (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
	} இல்லையெனில் எனில் (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
#endif
	திரும்பு 0;
}
