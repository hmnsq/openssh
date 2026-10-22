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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>

#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"

#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

#ifndef WITH_OPENSSL
#define EVP_CIPHER_CTX শূন্য
#endif

কাঠামো sshcipher_ctx {
	পূর্ণসংখ্যা	plaintext;
	পূর্ণসংখ্যা	encrypt;
	EVP_CIPHER_CTX *evp;
	কাঠামো chachapoly_ctx *cp_ctx;
	কাঠামো aesctr_ctx ac_ctx; /* XXX union with evp? */
	ধ্রুবক কাঠামো sshcipher *cipher;
};

কাঠামো sshcipher {
	অক্ষর	*name;
	u_int	block_আকার;
	u_int	চাবি_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#define CFLAG_CBC		(1<<0)
#define CFLAG_CHACHAPOLY	(1<<1)
#define CFLAG_AESCTR		(1<<2)
#define CFLAG_NONE		(1<<3)
#define CFLAG_INTERNAL		CFLAG_NONE /* Don't use "none" for packets */
#ifdef WITH_OPENSSL
	ধ্রুবক EVP_CIPHER	*(*evptype)(শূন্য);
#অন্যথা
	শূন্য	*ignored;
#endif
};

স্থির ধ্রুবক কাঠামো sshcipher ciphers[] = {
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
#অন্যথা
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, ফাঁকা },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, ফাঁকা },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, ফাঁকা },
#endif
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, ফাঁকা },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, ফাঁকা },

	{ ফাঁকা,			0, 0, 0, 0, 0, ফাঁকা }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
অক্ষর *
cipher_alg_list(অক্ষর sep, পূর্ণসংখ্যা auth_only)
{
	অক্ষর *ret = ফাঁকা;
	ধ্রুবক কাঠামো sshcipher *c;
	অক্ষর sep_str[2] = {sep, '\0'};

	জন্য (c = ciphers; c->name != ফাঁকা; c++) {
		যদি ((c->flags & CFLAG_INTERNAL) != 0)
			চালু;
		যদি (auth_only && c->auth_len == 0)
			চালু;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	ফেরত ret;
}

ধ্রুবক অক্ষর *
compression_alg_list(পূর্ণসংখ্যা compression)
{
#ifdef WITH_ZLIB
	ফেরত compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#অন্যথা
	ফেরত "none";
#endif
}

u_int
cipher_blocksize(ধ্রুবক কাঠামো sshcipher *c)
{
	ফেরত (c->block_আকার);
}

u_int
cipher_keylen(ধ্রুবক কাঠামো sshcipher *c)
{
	ফেরত (c->চাবি_len);
}

u_int
cipher_seclen(ধ্রুবক কাঠামো sshcipher *c)
{
	যদি (strcmp("3des-cbc", c->name) == 0)
		ফেরত 14;
	ফেরত cipher_keylen(c);
}

u_int
cipher_authlen(ধ্রুবক কাঠামো sshcipher *c)
{
	ফেরত (c->auth_len);
}

u_int
cipher_ivlen(ধ্রুবক কাঠামো sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	ফেরত (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->block_আকার;
}

u_int
cipher_is_cbc(ধ্রুবক কাঠামো sshcipher *c)
{
	ফেরত (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_internal(ধ্রুবক কাঠামো sshcipher *c)
{
	ফেরত (c->flags & CFLAG_INTERNAL) != 0;
}

u_int
cipher_ctx_is_plaintext(কাঠামো sshcipher_ctx *cc)
{
	ফেরত cc->plaintext;
}

ধ্রুবক কাঠামো sshcipher *
cipher_by_name(ধ্রুবক অক্ষর *name)
{
	ধ্রুবক কাঠামো sshcipher *c;
	জন্য (c = ciphers; c->name != ফাঁকা; c++)
		যদি (strcmp(c->name, name) == 0)
			ফেরত c;
	ফেরত ফাঁকা;
}

#define	CIPHER_SEP	","
পূর্ণসংখ্যা
ciphers_valid(ধ্রুবক অক্ষর *names)
{
	ধ্রুবক কাঠামো sshcipher *c;
	অক্ষর *cipher_list, *cp;
	অক্ষর *p;
	পূর্ণসংখ্যা found = 0;

	যদি (names == ফাঁকা || strcmp(names, "") == 0)
		ফেরত 0;
	যদি ((cipher_list = cp = strdup(names)) == ফাঁকা)
		ফেরত 0;
	জন্য ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		যদি (c == ফাঁকা || (c->flags & CFLAG_INTERNAL) != 0) {
			মুক্ত(cipher_list);
			ফেরত 0;
		} অন্যথা
			found = 1;
	}
	মুক্ত(cipher_list);
	ফেরত found;
}

ধ্রুবক অক্ষর *
cipher_warning_message(ধ্রুবক কাঠামো sshcipher_ctx *cc)
{
	যদি (cc == ফাঁকা || cc->cipher == ফাঁকা)
		ফেরত ফাঁকা;
	/* XXX repurpose for CBC warning */
	ফেরত ফাঁকা;
}

পূর্ণসংখ্যা
cipher_init(কাঠামো sshcipher_ctx **ccp, ধ্রুবক কাঠামো sshcipher *cipher,
    ধ্রুবক u_char *চাবি, u_int keylen, ধ্রুবক u_char *iv, u_int ivlen,
    পূর্ণসংখ্যা do_encrypt)
{
	কাঠামো sshcipher_ctx *cc = ফাঁকা;
	পূর্ণসংখ্যা ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_OPENSSL
	ধ্রুবক EVP_CIPHER *type;
	পূর্ণসংখ্যা klen;
#endif

	*ccp = ফাঁকা;
	যদি ((cc = calloc(1, আকার(*cc))) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	যদি (keylen < cipher->চাবি_len ||
	    (iv != ফাঁকা && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}

	cc->cipher = cipher;
	যদি ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(চাবি, keylen);
		ret = cc->cp_ctx != ফাঁকা ? 0 : SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	যদি ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		যাও out;
	}
#ifndef WITH_OPENSSL
	যদি ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, চাবি, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		যাও out;
	}
	ret = SSH_ERR_INVALID_ARGUMENT;
	যাও out;
#অন্যথা /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	যদি ((cc->evp = EVP_CIPHER_CTX_new()) == ফাঁকা) {
		ret = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (EVP_CipherInit(cc->evp, type, ফাঁকা, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	যদি (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	klen = EVP_CIPHER_CTX_চাবি_দৈর্ঘ্য(cc->evp);
	যদি (klen > 0 && keylen != (u_int)klen) {
		যদি (EVP_CIPHER_CTX_set_চাবি_দৈর্ঘ্য(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			যাও out;
		}
	}
	যদি (EVP_CipherInit(cc->evp, ফাঁকা, (u_char *)চাবি, ফাঁকা, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	ret = 0;
#endif /* WITH_OPENSSL */
 out:
	যদি (ret == 0) {
		/* success */
		*ccp = cc;
	} অন্যথা {
		যদি (cc != ফাঁকা) {
#ifdef WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#endif /* WITH_OPENSSL */
			freezero(cc, আকার(*cc));
		}
	}
	ফেরত ret;
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
পূর্ণসংখ্যা
cipher_crypt(কাঠামো sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   ধ্রুবক u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	যদি ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		ফেরত chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	যদি ((cc->cipher->flags & CFLAG_NONE) != 0) {
		memcpy(dest, src, aadlen + len);
		ফেরত 0;
	}
#ifndef WITH_OPENSSL
	যদি ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		যদি (aadlen)
			memcpy(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		ফেরত 0;
	}
	ফেরত SSH_ERR_INVALID_ARGUMENT;
#অন্যথা
	যদি (authlen) {
		u_char lastiv[1];

		যদি (authlen != cipher_authlen(cc->cipher))
			ফেরত SSH_ERR_INVALID_ARGUMENT;
		/* increment IV */
		যদি (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			ফেরত SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		যদি (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_TAG,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			ফেরত SSH_ERR_LIBCRYPTO_ERROR;
	}
	যদি (aadlen) {
		যদি (authlen &&
		    EVP_Cipher(cc->evp, ফাঁকা, (u_char *)src, aadlen) < 0)
			ফেরত SSH_ERR_LIBCRYPTO_ERROR;
		memcpy(dest, src, aadlen);
	}
	যদি (len % cc->cipher->block_আকার)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		ফেরত SSH_ERR_LIBCRYPTO_ERROR;
	যদি (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		যদি (EVP_Cipher(cc->evp, ফাঁকা, ফাঁকা, 0) < 0)
			ফেরত cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		যদি (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_TAG,
		    authlen, dest + aadlen + len) <= 0)
			ফেরত SSH_ERR_LIBCRYPTO_ERROR;
	}
	ফেরত 0;
#endif
}

/* Extract the packet length, including any decryption necessary beforehand */
পূর্ণসংখ্যা
cipher_get_দৈর্ঘ্য(কাঠামো sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    ধ্রুবক u_char *cp, u_int len)
{
	যদি ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		ফেরত chachapoly_get_দৈর্ঘ্য(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	যদি (len < 4)
		ফেরত SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	ফেরত 0;
}

শূন্য
cipher_free(কাঠামো sshcipher_ctx *cc)
{
	যদি (cc == ফাঁকা)
		ফেরত;
	যদি ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = ফাঁকা;
	} অন্যথা যদি ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, আকার(cc->ac_ctx));
#ifdef WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = ফাঁকা;
#endif
	freezero(cc, আকার(*cc));
}

পূর্ণসংখ্যা
cipher_get_keyiv(কাঠামো sshcipher_ctx *cc, u_char *iv, আকার_t len)
{
#ifdef WITH_OPENSSL
	ধ্রুবক কাঠামো sshcipher *c = cc->cipher;
	পূর্ণসংখ্যা evplen;
#endif

	যদি ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		যদি (len != 0)
			ফেরত SSH_ERR_INVALID_ARGUMENT;
		ফেরত 0;
	}
	যদি ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		যদি (len != আকার(cc->ac_ctx.ctr))
			ফেরত SSH_ERR_INVALID_ARGUMENT;
		memcpy(iv, cc->ac_ctx.ctr, len);
		ফেরত 0;
	}
	যদি ((cc->cipher->flags & CFLAG_NONE) != 0)
		ফেরত 0;

#ifdef WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_দৈর্ঘ্য(cc->evp);
	যদি (evplen == 0)
		ফেরত 0;
	অন্যথা যদি (evplen < 0)
		ফেরত SSH_ERR_LIBCRYPTO_ERROR;
	যদি ((আকার_t)evplen != len)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (cipher_authlen(c)) {
		যদি (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			ফেরত SSH_ERR_LIBCRYPTO_ERROR;
	} অন্যথা যদি (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		ফেরত SSH_ERR_LIBCRYPTO_ERROR;
#endif
	ফেরত 0;
}
