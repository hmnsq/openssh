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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>

#ضمن "cipher.h"
#ضمن "misc.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"

#ضمن "openbsd-compat/openssl-compat.h"

#ifndef WITH_OPENSSL
#define EVP_CIPHER_CTX فراغ
#endif

بنية sshcipher_ctx {
	صحيح	plaintext;
	صحيح	encrypt;
	EVP_CIPHER_CTX *evp;
	بنية chachapoly_ctx *cp_ctx;
	بنية aesctr_ctx ac_ctx; /* XXX union with evp? */
	ثابت بنية sshcipher *cipher;
};

بنية sshcipher {
	حرف	*name;
	u_int	block_size;
	u_int	ئاچقۇچ_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#define CFLAG_CBC		(1<<0)
#define CFLAG_CHACHAPOLY	(1<<1)
#define CFLAG_AESCTR		(1<<2)
#define CFLAG_NONE		(1<<3)
#define CFLAG_INTERNAL		CFLAG_NONE /* Don't use "none" for packets */
#ifdef WITH_OPENSSL
	ثابت EVP_CIPHER	*(*evptype)(فراغ);
#وإلا
	فراغ	*ignored;
#endif
};

ساكن ثابت بنية sshcipher ciphers[] = {
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
#وإلا
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, عدم },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, عدم },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, عدم },
#endif
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, عدم },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, عدم },

	{ عدم,			0, 0, 0, 0, 0, عدم }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
حرف *
cipher_alg_list(حرف sep, صحيح auth_only)
{
	حرف *ret = عدم;
	ثابت بنية sshcipher *c;
	حرف sep_str[2] = {sep, '\0'};

	لكل (c = ciphers; c->name != عدم; c++) {
		إذا ((c->flags & CFLAG_INTERNAL) != 0)
			استمر;
		إذا (auth_only && c->auth_len == 0)
			استمر;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	أرجع ret;
}

ثابت حرف *
compression_alg_list(صحيح compression)
{
#ifdef WITH_ZLIB
	أرجع compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#وإلا
	أرجع "none";
#endif
}

u_int
cipher_blocksize(ثابت بنية sshcipher *c)
{
	أرجع (c->block_size);
}

u_int
cipher_keylen(ثابت بنية sshcipher *c)
{
	أرجع (c->ئاچقۇچ_len);
}

u_int
cipher_seclen(ثابت بنية sshcipher *c)
{
	إذا (strcmp("3des-cbc", c->name) == 0)
		أرجع 14;
	أرجع cipher_keylen(c);
}

u_int
cipher_authlen(ثابت بنية sshcipher *c)
{
	أرجع (c->auth_len);
}

u_int
cipher_ivlen(ثابت بنية sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	أرجع (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->block_size;
}

u_int
cipher_is_cbc(ثابت بنية sshcipher *c)
{
	أرجع (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_internal(ثابت بنية sshcipher *c)
{
	أرجع (c->flags & CFLAG_INTERNAL) != 0;
}

u_int
cipher_ctx_is_plaintext(بنية sshcipher_ctx *cc)
{
	أرجع cc->plaintext;
}

ثابت بنية sshcipher *
cipher_by_name(ثابت حرف *name)
{
	ثابت بنية sshcipher *c;
	لكل (c = ciphers; c->name != عدم; c++)
		إذا (strcmp(c->name, name) == 0)
			أرجع c;
	أرجع عدم;
}

#define	CIPHER_SEP	","
صحيح
ciphers_valid(ثابت حرف *names)
{
	ثابت بنية sshcipher *c;
	حرف *cipher_list, *cp;
	حرف *p;
	صحيح found = 0;

	إذا (names == عدم || strcmp(names, "") == 0)
		أرجع 0;
	إذا ((cipher_list = cp = strdup(names)) == عدم)
		أرجع 0;
	لكل ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		إذا (c == عدم || (c->flags & CFLAG_INTERNAL) != 0) {
			حرر(cipher_list);
			أرجع 0;
		} وإلا
			found = 1;
	}
	حرر(cipher_list);
	أرجع found;
}

ثابت حرف *
cipher_warning_message(ثابت بنية sshcipher_ctx *cc)
{
	إذا (cc == عدم || cc->cipher == عدم)
		أرجع عدم;
	/* XXX repurpose for CBC warning */
	أرجع عدم;
}

صحيح
cipher_init(بنية sshcipher_ctx **ccp, ثابت بنية sshcipher *cipher,
    ثابت u_char *ئاچقۇچ, u_int keylen, ثابت u_char *iv, u_int ivlen,
    صحيح do_encrypt)
{
	بنية sshcipher_ctx *cc = عدم;
	صحيح ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_OPENSSL
	ثابت EVP_CIPHER *type;
	صحيح klen;
#endif

	*ccp = عدم;
	إذا ((cc = calloc(1, حجم(*cc))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	إذا (keylen < cipher->ئاچقۇچ_len ||
	    (iv != عدم && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}

	cc->cipher = cipher;
	إذا ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(ئاچقۇچ, keylen);
		ret = cc->cp_ctx != عدم ? 0 : SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	إذا ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		اذهب out;
	}
#ifndef WITH_OPENSSL
	إذا ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, ئاچقۇچ, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		اذهب out;
	}
	ret = SSH_ERR_INVALID_ARGUMENT;
	اذهب out;
#وإلا /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	إذا ((cc->evp = EVP_CIPHER_CTX_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (EVP_CipherInit(cc->evp, type, عدم, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	إذا (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	klen = EVP_CIPHER_CTX_ئاچقۇچ_length(cc->evp);
	إذا (klen > 0 && keylen != (u_int)klen) {
		إذا (EVP_CIPHER_CTX_set_ئاچقۇچ_length(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
	}
	إذا (EVP_CipherInit(cc->evp, عدم, (u_char *)ئاچقۇچ, عدم, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	ret = 0;
#endif /* WITH_OPENSSL */
 out:
	إذا (ret == 0) {
		/* success */
		*ccp = cc;
	} وإلا {
		إذا (cc != عدم) {
#ifdef WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#endif /* WITH_OPENSSL */
			freezero(cc, حجم(*cc));
		}
	}
	أرجع ret;
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
صحيح
cipher_crypt(بنية sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   ثابت u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	إذا ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		أرجع chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	إذا ((cc->cipher->flags & CFLAG_NONE) != 0) {
		memcpy(dest, src, aadlen + len);
		أرجع 0;
	}
#ifndef WITH_OPENSSL
	إذا ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		إذا (aadlen)
			memcpy(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		أرجع 0;
	}
	أرجع SSH_ERR_INVALID_ARGUMENT;
#وإلا
	إذا (authlen) {
		u_char lastiv[1];

		إذا (authlen != cipher_authlen(cc->cipher))
			أرجع SSH_ERR_INVALID_ARGUMENT;
		/* increment IV */
		إذا (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			أرجع SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		إذا (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_TAG,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			أرجع SSH_ERR_LIBCRYPTO_ERROR;
	}
	إذا (aadlen) {
		إذا (authlen &&
		    EVP_Cipher(cc->evp, عدم, (u_char *)src, aadlen) < 0)
			أرجع SSH_ERR_LIBCRYPTO_ERROR;
		memcpy(dest, src, aadlen);
	}
	إذا (len % cc->cipher->block_size)
		أرجع SSH_ERR_INVALID_ARGUMENT;
	إذا (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		أرجع SSH_ERR_LIBCRYPTO_ERROR;
	إذا (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		إذا (EVP_Cipher(cc->evp, عدم, عدم, 0) < 0)
			أرجع cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		إذا (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_TAG,
		    authlen, dest + aadlen + len) <= 0)
			أرجع SSH_ERR_LIBCRYPTO_ERROR;
	}
	أرجع 0;
#endif
}

/* Extract the packet length, including any decryption necessary beforehand */
صحيح
cipher_get_length(بنية sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    ثابت u_char *cp, u_int len)
{
	إذا ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		أرجع chachapoly_get_length(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	إذا (len < 4)
		أرجع SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	أرجع 0;
}

فراغ
cipher_free(بنية sshcipher_ctx *cc)
{
	إذا (cc == عدم)
		أرجع;
	إذا ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = عدم;
	} وإلا إذا ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, حجم(cc->ac_ctx));
#ifdef WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = عدم;
#endif
	freezero(cc, حجم(*cc));
}

صحيح
cipher_get_keyiv(بنية sshcipher_ctx *cc, u_char *iv, size_t len)
{
#ifdef WITH_OPENSSL
	ثابت بنية sshcipher *c = cc->cipher;
	صحيح evplen;
#endif

	إذا ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		إذا (len != 0)
			أرجع SSH_ERR_INVALID_ARGUMENT;
		أرجع 0;
	}
	إذا ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		إذا (len != حجم(cc->ac_ctx.ctr))
			أرجع SSH_ERR_INVALID_ARGUMENT;
		memcpy(iv, cc->ac_ctx.ctr, len);
		أرجع 0;
	}
	إذا ((cc->cipher->flags & CFLAG_NONE) != 0)
		أرجع 0;

#ifdef WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_length(cc->evp);
	إذا (evplen == 0)
		أرجع 0;
	وإلا إذا (evplen < 0)
		أرجع SSH_ERR_LIBCRYPTO_ERROR;
	إذا ((size_t)evplen != len)
		أرجع SSH_ERR_INVALID_ARGUMENT;
	إذا (cipher_authlen(c)) {
		إذا (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			أرجع SSH_ERR_LIBCRYPTO_ERROR;
	} وإلا إذا (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		أرجع SSH_ERR_LIBCRYPTO_ERROR;
#endif
	أرجع 0;
}
