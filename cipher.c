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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>

#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"

#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

#ifndef WITH_OPENSSL
#define EVP_CIPHER_CTX શૂન્ય
#endif

સંરચના sshcipher_ctx {
	પૂર્ણાંક	plaintext;
	પૂર્ણાંક	encrypt;
	EVP_CIPHER_CTX *evp;
	સંરચના chachapoly_ctx *cp_ctx;
	સંરચના aesctr_ctx ac_ctx; /* XXX union with evp? */
	અચલ સંરચના sshcipher *cipher;
};

સંરચના sshcipher {
	અક્ષર	*name;
	u_int	block_size;
	u_int	ચાવી_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#define CFLAG_CBC		(1<<0)
#define CFLAG_CHACHAPOLY	(1<<1)
#define CFLAG_AESCTR		(1<<2)
#define CFLAG_NONE		(1<<3)
#define CFLAG_INTERNAL		CFLAG_NONE /* Don't use "none" for packets */
#ifdef WITH_OPENSSL
	અચલ EVP_CIPHER	*(*evptype)(શૂન્ય);
#નહીંતર
	શૂન્ય	*ignored;
#endif
};

સ્થિર અચલ સંરચના sshcipher ciphers[] = {
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
#નહીંતર
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, ખાલી },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, ખાલી },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, ખાલી },
#endif
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, ખાલી },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, ખાલી },

	{ ખાલી,			0, 0, 0, 0, 0, ખાલી }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
અક્ષર *
cipher_alg_list(અક્ષર sep, પૂર્ણાંક auth_only)
{
	અક્ષર *ret = ખાલી;
	અચલ સંરચના sshcipher *c;
	અક્ષર sep_str[2] = {sep, '\0'};

	માટે (c = ciphers; c->name != ખાલી; c++) {
		જો ((c->flags & CFLAG_INTERNAL) != 0)
			ચાલુ;
		જો (auth_only && c->auth_len == 0)
			ચાલુ;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	પાછા ret;
}

અચલ અક્ષર *
compression_alg_list(પૂર્ણાંક compression)
{
#ifdef WITH_ZLIB
	પાછા compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#નહીંતર
	પાછા "none";
#endif
}

u_int
cipher_blocksize(અચલ સંરચના sshcipher *c)
{
	પાછા (c->block_size);
}

u_int
cipher_keylen(અચલ સંરચના sshcipher *c)
{
	પાછા (c->ચાવી_len);
}

u_int
cipher_seclen(અચલ સંરચના sshcipher *c)
{
	જો (strcmp("3des-cbc", c->name) == 0)
		પાછા 14;
	પાછા cipher_keylen(c);
}

u_int
cipher_authlen(અચલ સંરચના sshcipher *c)
{
	પાછા (c->auth_len);
}

u_int
cipher_ivlen(અચલ સંરચના sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	પાછા (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->block_size;
}

u_int
cipher_is_cbc(અચલ સંરચના sshcipher *c)
{
	પાછા (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_internal(અચલ સંરચના sshcipher *c)
{
	પાછા (c->flags & CFLAG_INTERNAL) != 0;
}

u_int
cipher_ctx_is_plaintext(સંરચના sshcipher_ctx *cc)
{
	પાછા cc->plaintext;
}

અચલ સંરચના sshcipher *
cipher_by_name(અચલ અક્ષર *name)
{
	અચલ સંરચના sshcipher *c;
	માટે (c = ciphers; c->name != ખાલી; c++)
		જો (strcmp(c->name, name) == 0)
			પાછા c;
	પાછા ખાલી;
}

#define	CIPHER_SEP	","
પૂર્ણાંક
ciphers_valid(અચલ અક્ષર *names)
{
	અચલ સંરચના sshcipher *c;
	અક્ષર *cipher_list, *cp;
	અક્ષર *p;
	પૂર્ણાંક found = 0;

	જો (names == ખાલી || strcmp(names, "") == 0)
		પાછા 0;
	જો ((cipher_list = cp = strdup(names)) == ખાલી)
		પાછા 0;
	માટે ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		જો (c == ખાલી || (c->flags & CFLAG_INTERNAL) != 0) {
			મુક્ત(cipher_list);
			પાછા 0;
		} નહીંતર
			found = 1;
	}
	મુક્ત(cipher_list);
	પાછા found;
}

અચલ અક્ષર *
cipher_warning_message(અચલ સંરચના sshcipher_ctx *cc)
{
	જો (cc == ખાલી || cc->cipher == ખાલી)
		પાછા ખાલી;
	/* XXX repurpose for CBC warning */
	પાછા ખાલી;
}

પૂર્ણાંક
cipher_init(સંરચના sshcipher_ctx **ccp, અચલ સંરચના sshcipher *cipher,
    અચલ u_char *ચાવી, u_int keylen, અચલ u_char *iv, u_int ivlen,
    પૂર્ણાંક do_encrypt)
{
	સંરચના sshcipher_ctx *cc = ખાલી;
	પૂર્ણાંક ret = SSH_ERR_INTERNAL_ERROR;
#ifdef WITH_OPENSSL
	અચલ EVP_CIPHER *type;
	પૂર્ણાંક klen;
#endif

	*ccp = ખાલી;
	જો ((cc = calloc(1, કદ(*cc))) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	જો (keylen < cipher->ચાવી_len ||
	    (iv != ખાલી && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}

	cc->cipher = cipher;
	જો ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(ચાવી, keylen);
		ret = cc->cp_ctx != ખાલી ? 0 : SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	જો ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		જાઓ out;
	}
#ifndef WITH_OPENSSL
	જો ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, ચાવી, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		જાઓ out;
	}
	ret = SSH_ERR_INVALID_ARGUMENT;
	જાઓ out;
#નહીંતર /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	જો ((cc->evp = EVP_CIPHER_CTX_new()) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (EVP_CipherInit(cc->evp, type, ખાલી, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	જો (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	klen = EVP_CIPHER_CTX_ચાવી_length(cc->evp);
	જો (klen > 0 && keylen != (u_int)klen) {
		જો (EVP_CIPHER_CTX_set_ચાવી_length(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			જાઓ out;
		}
	}
	જો (EVP_CipherInit(cc->evp, ખાલી, (u_char *)ચાવી, ખાલી, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	ret = 0;
#endif /* WITH_OPENSSL */
 out:
	જો (ret == 0) {
		/* success */
		*ccp = cc;
	} નહીંતર {
		જો (cc != ખાલી) {
#ifdef WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#endif /* WITH_OPENSSL */
			freezero(cc, કદ(*cc));
		}
	}
	પાછા ret;
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
પૂર્ણાંક
cipher_crypt(સંરચના sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   અચલ u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	જો ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		પાછા chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	જો ((cc->cipher->flags & CFLAG_NONE) != 0) {
		memcpy(dest, src, aadlen + len);
		પાછા 0;
	}
#ifndef WITH_OPENSSL
	જો ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		જો (aadlen)
			memcpy(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		પાછા 0;
	}
	પાછા SSH_ERR_INVALID_ARGUMENT;
#નહીંતર
	જો (authlen) {
		u_char lastiv[1];

		જો (authlen != cipher_authlen(cc->cipher))
			પાછા SSH_ERR_INVALID_ARGUMENT;
		/* increment IV */
		જો (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			પાછા SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		જો (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_TAG,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			પાછા SSH_ERR_LIBCRYPTO_ERROR;
	}
	જો (aadlen) {
		જો (authlen &&
		    EVP_Cipher(cc->evp, ખાલી, (u_char *)src, aadlen) < 0)
			પાછા SSH_ERR_LIBCRYPTO_ERROR;
		memcpy(dest, src, aadlen);
	}
	જો (len % cc->cipher->block_size)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		પાછા SSH_ERR_LIBCRYPTO_ERROR;
	જો (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		જો (EVP_Cipher(cc->evp, ખાલી, ખાલી, 0) < 0)
			પાછા cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		જો (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_TAG,
		    authlen, dest + aadlen + len) <= 0)
			પાછા SSH_ERR_LIBCRYPTO_ERROR;
	}
	પાછા 0;
#endif
}

/* Extract the packet length, including any decryption necessary beforehand */
પૂર્ણાંક
cipher_get_length(સંરચના sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    અચલ u_char *cp, u_int len)
{
	જો ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		પાછા chachapoly_get_length(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	જો (len < 4)
		પાછા SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	પાછા 0;
}

શૂન્ય
cipher_free(સંરચના sshcipher_ctx *cc)
{
	જો (cc == ખાલી)
		પાછા;
	જો ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = ખાલી;
	} નહીંતર જો ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, કદ(cc->ac_ctx));
#ifdef WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = ખાલી;
#endif
	freezero(cc, કદ(*cc));
}

પૂર્ણાંક
cipher_get_keyiv(સંરચના sshcipher_ctx *cc, u_char *iv, size_t len)
{
#ifdef WITH_OPENSSL
	અચલ સંરચના sshcipher *c = cc->cipher;
	પૂર્ણાંક evplen;
#endif

	જો ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		જો (len != 0)
			પાછા SSH_ERR_INVALID_ARGUMENT;
		પાછા 0;
	}
	જો ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		જો (len != કદ(cc->ac_ctx.ctr))
			પાછા SSH_ERR_INVALID_ARGUMENT;
		memcpy(iv, cc->ac_ctx.ctr, len);
		પાછા 0;
	}
	જો ((cc->cipher->flags & CFLAG_NONE) != 0)
		પાછા 0;

#ifdef WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_length(cc->evp);
	જો (evplen == 0)
		પાછા 0;
	નહીંતર જો (evplen < 0)
		પાછા SSH_ERR_LIBCRYPTO_ERROR;
	જો ((size_t)evplen != len)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (cipher_authlen(c)) {
		જો (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			પાછા SSH_ERR_LIBCRYPTO_ERROR;
	} નહીંતર જો (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		પાછા SSH_ERR_LIBCRYPTO_ERROR;
#endif
	પાછા 0;
}
