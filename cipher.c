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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>

#ଅନ୍ତର୍ଭାଵ "cipher.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"

#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

#ifndef WITH_OPENSSL
#define EVP_CIPHER_CTX ଶୂନ୍ୟ
#endif

ସଂରଚନା sshcipher_ctx {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	plaintext;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	encrypt;
	EVP_CIPHER_CTX *evp;
	ସଂରଚନା chachapoly_ctx *cp_ctx;
	ସଂରଚନା aesctr_ctx ac_ctx; /* XXX union with evp? */
	ଅଚଳ ସଂରଚନା sshcipher *cipher;
};

ସଂରଚନା sshcipher {
	ଅକ୍ଷର	*name;
	u_int	block_size;
	u_int	ଚାବି_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#define CFLAG_CBC		(1<<0)
#define CFLAG_CHACHAPOLY	(1<<1)
#define CFLAG_AESCTR		(1<<2)
#define CFLAG_NONE		(1<<3)
#define CFLAG_INTERNAL		CFLAG_NONE /* Don't use "none" for packets */
#ifdef WITH_OPENSSL
	ଅଚଳ EVP_CIPHER	*(*evptype)(ଶୂନ୍ୟ);
#ଅନ୍ୟଥା
	ଶୂନ୍ୟ	*ignored;
#endif
};

ସ୍ଥିର ଅଚଳ ସଂରଚନା sshcipher ciphers[] = {
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
#ଅନ୍ୟଥା
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, ଖାଲି },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, ଖାଲି },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, ଖାଲି },
#endif
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, ଖାଲି },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, ଖାଲି },

	{ ଖାଲି,			0, 0, 0, 0, 0, ଖାଲି }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
ଅକ୍ଷର *
cipher_alg_list(ଅକ୍ଷର sep, ପୂର୍ଣ୍ଣସଂଖ୍ୟା auth_only)
{
	ଅକ୍ଷର *ret = ଖାଲି;
	ଅଚଳ ସଂରଚନା sshcipher *c;
	ଅକ୍ଷର sep_str[2] = {sep, '\0'};

	ପାଇଁ (c = ciphers; c->name != ଖାଲି; c++) {
		ଯଦି ((c->flags & CFLAG_INTERNAL) != 0)
			ଜାରି;
		ଯଦି (auth_only && c->auth_len == 0)
			ଜାରି;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	ଫେରନ୍ତୁ ret;
}

ଅଚଳ ଅକ୍ଷର *
compression_alg_list(ପୂର୍ଣ୍ଣସଂଖ୍ୟା compression)
{
#ifdef WITH_ZLIB
	ଫେରନ୍ତୁ compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#ଅନ୍ୟଥା
	ଫେରନ୍ତୁ "none";
#endif
}

u_int
cipher_blocksize(ଅଚଳ ସଂରଚନା sshcipher *c)
{
	ଫେରନ୍ତୁ (c->block_size);
}

u_int
cipher_keylen(ଅଚଳ ସଂରଚନା sshcipher *c)
{
	ଫେରନ୍ତୁ (c->ଚାବି_len);
}

u_int
cipher_seclen(ଅଚଳ ସଂରଚନା sshcipher *c)
{
	ଯଦି (strcmp("3des-cbc", c->name) == 0)
		ଫେରନ୍ତୁ 14;
	ଫେରନ୍ତୁ cipher_keylen(c);
}

u_int
cipher_authlen(ଅଚଳ ସଂରଚନା sshcipher *c)
{
	ଫେରନ୍ତୁ (c->auth_len);
}

u_int
cipher_ivlen(ଅଚଳ ସଂରଚନା sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	ଫେରନ୍ତୁ (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->block_size;
}

u_int
cipher_is_cbc(ଅଚଳ ସଂରଚନା sshcipher *c)
{
	ଫେରନ୍ତୁ (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_internal(ଅଚଳ ସଂରଚନା sshcipher *c)
{
	ଫେରନ୍ତୁ (c->flags & CFLAG_INTERNAL) != 0;
}

u_int
cipher_ctx_is_plaintext(ସଂରଚନା sshcipher_ctx *cc)
{
	ଫେରନ୍ତୁ cc->plaintext;
}

ଅଚଳ ସଂରଚନା sshcipher *
cipher_by_name(ଅଚଳ ଅକ୍ଷର *name)
{
	ଅଚଳ ସଂରଚନା sshcipher *c;
	ପାଇଁ (c = ciphers; c->name != ଖାଲି; c++)
		ଯଦି (strcmp(c->name, name) == 0)
			ଫେରନ୍ତୁ c;
	ଫେରନ୍ତୁ ଖାଲି;
}

#define	CIPHER_SEP	","
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ciphers_valid(ଅଚଳ ଅକ୍ଷର *names)
{
	ଅଚଳ ସଂରଚନା sshcipher *c;
	ଅକ୍ଷର *cipher_list, *cp;
	ଅକ୍ଷର *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା found = 0;

	ଯଦି (names == ଖାଲି || strcmp(names, "") == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି ((cipher_list = cp = strdup(names)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ପାଇଁ ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		ଯଦି (c == ଖାଲି || (c->flags & CFLAG_INTERNAL) != 0) {
			ମୁକ୍ତ(cipher_list);
			ଫେରନ୍ତୁ 0;
		} ଅନ୍ୟଥା
			found = 1;
	}
	ମୁକ୍ତ(cipher_list);
	ଫେରନ୍ତୁ found;
}

ଅଚଳ ଅକ୍ଷର *
cipher_warning_message(ଅଚଳ ସଂରଚନା sshcipher_ctx *cc)
{
	ଯଦି (cc == ଖାଲି || cc->cipher == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	/* XXX repurpose for CBC warning */
	ଫେରନ୍ତୁ ଖାଲି;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cipher_init(ସଂରଚନା sshcipher_ctx **ccp, ଅଚଳ ସଂରଚନା sshcipher *cipher,
    ଅଚଳ u_char *ଚାବି, u_int keylen, ଅଚଳ u_char *iv, u_int ivlen,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_encrypt)
{
	ସଂରଚନା sshcipher_ctx *cc = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_OPENSSL
	ଅଚଳ EVP_CIPHER *type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା klen;
#endif

	*ccp = ଖାଲି;
	ଯଦି ((cc = calloc(1, ଆକାର(*cc))) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	ଯଦି (keylen < cipher->ଚାବି_len ||
	    (iv != ଖାଲି && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}

	cc->cipher = cipher;
	ଯଦି ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(ଚାବି, keylen);
		ret = cc->cp_ctx != ଖାଲି ? 0 : SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	ଯଦି ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		ଯାଅ out;
	}
#ifndef WITH_OPENSSL
	ଯଦି ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, ଚାବି, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		ଯାଅ out;
	}
	ret = SSH_ERR_INVALID_ARGUMENT;
	ଯାଅ out;
#ଅନ୍ୟଥା /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	ଯଦି ((cc->evp = EVP_CIPHER_CTX_new()) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (EVP_CipherInit(cc->evp, type, ଖାଲି, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ଯଦି (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	klen = EVP_CIPHER_CTX_ଚାବି_length(cc->evp);
	ଯଦି (klen > 0 && keylen != (u_int)klen) {
		ଯଦି (EVP_CIPHER_CTX_set_ଚାବି_length(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			ଯାଅ out;
		}
	}
	ଯଦି (EVP_CipherInit(cc->evp, ଖାଲି, (u_char *)ଚାବି, ଖାଲି, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ret = 0;
#endif /* WITH_OPENSSL */
 out:
	ଯଦି (ret == 0) {
		/* success */
		*ccp = cc;
	} ଅନ୍ୟଥା {
		ଯଦି (cc != ଖାଲି) {
#ifdef WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#endif /* WITH_OPENSSL */
			freezero(cc, ଆକାର(*cc));
		}
	}
	ଫେରନ୍ତୁ ret;
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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cipher_crypt(ସଂରଚନା sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   ଅଚଳ u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	ଯଦି ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		ଫେରନ୍ତୁ chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	ଯଦି ((cc->cipher->flags & CFLAG_NONE) != 0) {
		memcpy(dest, src, aadlen + len);
		ଫେରନ୍ତୁ 0;
	}
#ifndef WITH_OPENSSL
	ଯଦି ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		ଯଦି (aadlen)
			memcpy(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		ଫେରନ୍ତୁ 0;
	}
	ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
#ଅନ୍ୟଥା
	ଯଦି (authlen) {
		u_char lastiv[1];

		ଯଦି (authlen != cipher_authlen(cc->cipher))
			ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
		/* increment IV */
		ଯଦି (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		ଯଦି (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_TAG,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
	}
	ଯଦି (aadlen) {
		ଯଦି (authlen &&
		    EVP_Cipher(cc->evp, ଖାଲି, (u_char *)src, aadlen) < 0)
			ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
		memcpy(dest, src, aadlen);
	}
	ଯଦି (len % cc->cipher->block_size)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
	ଯଦି (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		ଯଦି (EVP_Cipher(cc->evp, ଖାଲି, ଖାଲି, 0) < 0)
			ଫେରନ୍ତୁ cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		ଯଦି (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_TAG,
		    authlen, dest + aadlen + len) <= 0)
			ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
	}
	ଫେରନ୍ତୁ 0;
#endif
}

/* Extract the packet length, including any decryption necessary beforehand */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cipher_get_length(ସଂରଚନା sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    ଅଚଳ u_char *cp, u_int len)
{
	ଯଦି ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		ଫେରନ୍ତୁ chachapoly_get_length(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	ଯଦି (len < 4)
		ଫେରନ୍ତୁ SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
cipher_free(ସଂରଚନା sshcipher_ctx *cc)
{
	ଯଦି (cc == ଖାଲି)
		ଫେରନ୍ତୁ;
	ଯଦି ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = ଖାଲି;
	} ଅନ୍ୟଥା ଯଦି ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, ଆକାର(cc->ac_ctx));
#ifdef WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = ଖାଲି;
#endif
	freezero(cc, ଆକାର(*cc));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cipher_get_keyiv(ସଂରଚନା sshcipher_ctx *cc, u_char *iv, size_t len)
{
#ifdef WITH_OPENSSL
	ଅଚଳ ସଂରଚନା sshcipher *c = cc->cipher;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା evplen;
#endif

	ଯଦି ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		ଯଦି (len != 0)
			ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		ଯଦି (len != ଆକାର(cc->ac_ctx.ctr))
			ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
		memcpy(iv, cc->ac_ctx.ctr, len);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି ((cc->cipher->flags & CFLAG_NONE) != 0)
		ଫେରନ୍ତୁ 0;

#ifdef WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_length(cc->evp);
	ଯଦି (evplen == 0)
		ଫେରନ୍ତୁ 0;
	ଅନ୍ୟଥା ଯଦି (evplen < 0)
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
	ଯଦି ((size_t)evplen != len)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (cipher_authlen(c)) {
		ଯଦି (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
	} ଅନ୍ୟଥା ଯଦି (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
#endif
	ଫେରନ୍ତୁ 0;
}
