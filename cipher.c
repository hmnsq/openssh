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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EVP_CIPHER_CTX ਖਾਲੀ
#ਜੇ_ਅੰਤ

ਬਣਤਰ sshcipher_ctx {
	ਪੂਰਨ	plaintext;
	ਪੂਰਨ	encrypt;
	EVP_CIPHER_CTX *evp;
	ਬਣਤਰ chachapoly_ctx *cp_ctx;
	ਬਣਤਰ aesctr_ctx ac_ctx; /* XXX union with evp? */
	ਅਚਲ ਬਣਤਰ sshcipher *cipher;
};

ਬਣਤਰ sshcipher {
	ਅੱਖਰ	*name;
	u_int	ਖੰਡ_ਮਾਪ;
	u_int	ਕੁੰਜੀ_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CFLAG_CBC		(1<<0)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CFLAG_CHACHAPOLY	(1<<1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CFLAG_AESCTR		(1<<2)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CFLAG_NONE		(1<<3)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CFLAG_ਅੰਦਰੂਨੀ		CFLAG_NONE /* Don't use "none" for packets */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਅਚਲ EVP_CIPHER	*(*evptype)(ਖਾਲੀ);
#ਨਹੀਂਤਾਂ
	ਖਾਲੀ	*ignored;
#ਜੇ_ਅੰਤ
};

ਸਥਿਰ ਅਚਲ ਬਣਤਰ sshcipher ciphers[] = {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ OPENSSL_NO_DES
	{ "3des-cbc",		8, 24, 0, 0, CFLAG_CBC, EVP_des_ede3_cbc },
#ਜੇ_ਅੰਤ
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
#ਨਹੀਂਤਾਂ
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, ਨਿਰਾ },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, ਨਿਰਾ },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, ਨਿਰਾ },
#ਜੇ_ਅੰਤ
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, ਨਿਰਾ },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, ਨਿਰਾ },

	{ ਨਿਰਾ,			0, 0, 0, 0, 0, ਨਿਰਾ }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
ਅੱਖਰ *
cipher_alg_list(ਅੱਖਰ sep, ਪੂਰਨ auth_only)
{
	ਅੱਖਰ *ret = ਨਿਰਾ;
	ਅਚਲ ਬਣਤਰ sshcipher *c;
	ਅੱਖਰ sep_str[2] = {sep, '\0'};

	ਲਈ (c = ciphers; c->name != ਨਿਰਾ; c++) {
		ਜੇ ((c->flags & CFLAG_ਅੰਦਰੂਨੀ) != 0)
			ਜਾਰੀ;
		ਜੇ (auth_only && c->auth_len == 0)
			ਜਾਰੀ;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	ਵਾਪਸ ret;
}

ਅਚਲ ਅੱਖਰ *
compression_alg_list(ਪੂਰਨ compression)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_ZLIB
	ਵਾਪਸ compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#ਨਹੀਂਤਾਂ
	ਵਾਪਸ "none";
#ਜੇ_ਅੰਤ
}

u_int
cipher_blocksize(ਅਚਲ ਬਣਤਰ sshcipher *c)
{
	ਵਾਪਸ (c->ਖੰਡ_ਮਾਪ);
}

u_int
cipher_keylen(ਅਚਲ ਬਣਤਰ sshcipher *c)
{
	ਵਾਪਸ (c->ਕੁੰਜੀ_len);
}

u_int
cipher_seclen(ਅਚਲ ਬਣਤਰ sshcipher *c)
{
	ਜੇ (strcmp("3des-cbc", c->name) == 0)
		ਵਾਪਸ 14;
	ਵਾਪਸ cipher_keylen(c);
}

u_int
cipher_authlen(ਅਚਲ ਬਣਤਰ sshcipher *c)
{
	ਵਾਪਸ (c->auth_len);
}

u_int
cipher_ivlen(ਅਚਲ ਬਣਤਰ sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	ਵਾਪਸ (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->ਖੰਡ_ਮਾਪ;
}

u_int
cipher_is_cbc(ਅਚਲ ਬਣਤਰ sshcipher *c)
{
	ਵਾਪਸ (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_ਅੰਦਰੂਨੀ(ਅਚਲ ਬਣਤਰ sshcipher *c)
{
	ਵਾਪਸ (c->flags & CFLAG_ਅੰਦਰੂਨੀ) != 0;
}

u_int
cipher_ctx_is_plaintext(ਬਣਤਰ sshcipher_ctx *cc)
{
	ਵਾਪਸ cc->plaintext;
}

ਅਚਲ ਬਣਤਰ sshcipher *
cipher_by_name(ਅਚਲ ਅੱਖਰ *name)
{
	ਅਚਲ ਬਣਤਰ sshcipher *c;
	ਲਈ (c = ciphers; c->name != ਨਿਰਾ; c++)
		ਜੇ (strcmp(c->name, name) == 0)
			ਵਾਪਸ c;
	ਵਾਪਸ ਨਿਰਾ;
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	CIPHER_SEP	","
ਪੂਰਨ
ciphers_valid(ਅਚਲ ਅੱਖਰ *ਨਾਂ)
{
	ਅਚਲ ਬਣਤਰ sshcipher *c;
	ਅੱਖਰ *cipher_list, *cp;
	ਅੱਖਰ *p;
	ਪੂਰਨ ਮਿਲਿਆ = 0;

	ਜੇ (ਨਾਂ == ਨਿਰਾ || strcmp(ਨਾਂ, "") == 0)
		ਵਾਪਸ 0;
	ਜੇ ((cipher_list = cp = strdup(ਨਾਂ)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਲਈ ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		ਜੇ (c == ਨਿਰਾ || (c->flags & CFLAG_ਅੰਦਰੂਨੀ) != 0) {
			ਮੁਕਤ(cipher_list);
			ਵਾਪਸ 0;
		} ਨਹੀਂਤਾਂ
			ਮਿਲਿਆ = 1;
	}
	ਮੁਕਤ(cipher_list);
	ਵਾਪਸ ਮਿਲਿਆ;
}

ਅਚਲ ਅੱਖਰ *
cipher_warning_ਸੁਨੇਹਾ(ਅਚਲ ਬਣਤਰ sshcipher_ctx *cc)
{
	ਜੇ (cc == ਨਿਰਾ || cc->cipher == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	/* XXX repurpose for CBC warning */
	ਵਾਪਸ ਨਿਰਾ;
}

ਪੂਰਨ
cipher_init(ਬਣਤਰ sshcipher_ctx **ccp, ਅਚਲ ਬਣਤਰ sshcipher *cipher,
    ਅਚਲ u_char *ਕੁੰਜੀ, u_int keylen, ਅਚਲ u_char *iv, u_int ivlen,
    ਪੂਰਨ do_encrypt)
{
	ਬਣਤਰ sshcipher_ctx *cc = ਨਿਰਾ;
	ਪੂਰਨ ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਅਚਲ EVP_CIPHER *type;
	ਪੂਰਨ klen;
#ਜੇ_ਅੰਤ

	*ccp = ਨਿਰਾ;
	ਜੇ ((cc = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*cc))) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	ਜੇ (keylen < cipher->ਕੁੰਜੀ_len ||
	    (iv != ਨਿਰਾ && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	cc->cipher = cipher;
	ਜੇ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(ਕੁੰਜੀ, keylen);
		ret = cc->cp_ctx != ਨਿਰਾ ? 0 : SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਜੇ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, ਕੁੰਜੀ, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ret = SSH_ERR_INVALID_ਦਲੀਲ;
	ਜਾਓ ਬਾਹਰਲਾ;
#ਨਹੀਂਤਾਂ /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	ਜੇ ((cc->evp = EVP_CIPHER_CTX_new()) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_CipherInit(cc->evp, type, ਨਿਰਾ, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_ਸੈੱਟ_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	klen = EVP_CIPHER_CTX_ਕੁੰਜੀ_ਲੰਮਾਈ(cc->evp);
	ਜੇ (klen > 0 && keylen != (u_int)klen) {
		ਜੇ (EVP_CIPHER_CTX_ਸੈੱਟ_ਕੁੰਜੀ_ਲੰਮਾਈ(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	ਜੇ (EVP_CipherInit(cc->evp, ਨਿਰਾ, (u_char *)ਕੁੰਜੀ, ਨਿਰਾ, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ret = 0;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
 ਬਾਹਰਲਾ:
	ਜੇ (ret == 0) {
		/* success */
		*ccp = cc;
	} ਨਹੀਂਤਾਂ {
		ਜੇ (cc != ਨਿਰਾ) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
			freezero(cc, ਆਕਾਰ(*cc));
		}
	}
	ਵਾਪਸ ret;
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
ਪੂਰਨ
cipher_crypt(ਬਣਤਰ sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   ਅਚਲ u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	ਜੇ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		ਵਾਪਸ chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	ਜੇ ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(dest, src, aadlen + len);
		ਵਾਪਸ 0;
	}
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਜੇ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		ਜੇ (aadlen)
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(dest, src, aadlen);
		aesctr_encrypt_ਬਾਈਟਾਂ(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		ਵਾਪਸ 0;
	}
	ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
#ਨਹੀਂਤਾਂ
	ਜੇ (authlen) {
		u_char lastiv[1];

		ਜੇ (authlen != cipher_authlen(cc->cipher))
			ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
		/* increment IV */
		ਜੇ (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		ਜੇ (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_ਸੈੱਟ_ਟੈਗ,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
	}
	ਜੇ (aadlen) {
		ਜੇ (authlen &&
		    EVP_Cipher(cc->evp, ਨਿਰਾ, (u_char *)src, aadlen) < 0)
			ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(dest, src, aadlen);
	}
	ਜੇ (len % cc->cipher->ਖੰਡ_ਮਾਪ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
	ਜੇ (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		ਜੇ (EVP_Cipher(cc->evp, ਨਿਰਾ, ਨਿਰਾ, 0) < 0)
			ਵਾਪਸ cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		ਜੇ (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_ਟੈਗ,
		    authlen, dest + aadlen + len) <= 0)
			ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
	}
	ਵਾਪਸ 0;
#ਜੇ_ਅੰਤ
}

/* Extract the packet length, including any decryption necessary beforehand */
ਪੂਰਨ
cipher_get_ਲੰਮਾਈ(ਬਣਤਰ sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    ਅਚਲ u_char *cp, u_int len)
{
	ਜੇ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		ਵਾਪਸ chachapoly_get_ਲੰਮਾਈ(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	ਜੇ (len < 4)
		ਵਾਪਸ SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	ਵਾਪਸ 0;
}

ਖਾਲੀ
cipher_free(ਬਣਤਰ sshcipher_ctx *cc)
{
	ਜੇ (cc == ਨਿਰਾ)
		ਵਾਪਸ;
	ਜੇ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ ਜੇ ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, ਆਕਾਰ(cc->ac_ctx));
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = ਨਿਰਾ;
#ਜੇ_ਅੰਤ
	freezero(cc, ਆਕਾਰ(*cc));
}

ਪੂਰਨ
cipher_get_keyiv(ਬਣਤਰ sshcipher_ctx *cc, u_char *iv, ਮਾਪ_t len)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਅਚਲ ਬਣਤਰ sshcipher *c = cc->cipher;
	ਪੂਰਨ evplen;
#ਜੇ_ਅੰਤ

	ਜੇ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		ਜੇ (len != 0)
			ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
		ਵਾਪਸ 0;
	}
	ਜੇ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		ਜੇ (len != ਆਕਾਰ(cc->ac_ctx.ctr))
			ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(iv, cc->ac_ctx.ctr, len);
		ਵਾਪਸ 0;
	}
	ਜੇ ((cc->cipher->flags & CFLAG_NONE) != 0)
		ਵਾਪਸ 0;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_ਲੰਮਾਈ(cc->evp);
	ਜੇ (evplen == 0)
		ਵਾਪਸ 0;
	ਨਹੀਂਤਾਂ ਜੇ (evplen < 0)
		ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
	ਜੇ ((ਮਾਪ_t)evplen != len)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (cipher_authlen(c)) {
		ਜੇ (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
	} ਨਹੀਂਤਾਂ ਜੇ (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
#ਜੇ_ਅੰਤ
	ਵਾਪਸ 0;
}
