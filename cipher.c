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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ WITH_OPENSSL
#ವ್ಯಾಖ್ಯಾನಿಸು EVP_CIPHER_CTX ಶೂನ್ಯ
#ಆದರೆ_ಅಂತ್ಯ

ರಚನೆ sshcipher_ctx {
	ಪೂರ್ಣಾಂಕ	plaintext;
	ಪೂರ್ಣಾಂಕ	encrypt;
	EVP_CIPHER_CTX *evp;
	ರಚನೆ chachapoly_ctx *cp_ctx;
	ರಚನೆ aesctr_ctx ac_ctx; /* XXX union with evp? */
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *cipher;
};

ರಚನೆ sshcipher {
	ಅಕ್ಷರ	*name;
	u_int	ಖಂಡ_ಗಾತ್ರ;
	u_int	ಕೀಲಿ_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#ವ್ಯಾಖ್ಯಾನಿಸು CFLAG_CBC		(1<<0)
#ವ್ಯಾಖ್ಯಾನಿಸು CFLAG_CHACHAPOLY	(1<<1)
#ವ್ಯಾಖ್ಯಾನಿಸು CFLAG_AESCTR		(1<<2)
#ವ್ಯಾಖ್ಯಾನಿಸು CFLAG_NONE		(1<<3)
#ವ್ಯಾಖ್ಯಾನಿಸು CFLAG_ಆಂತರಿಕ		CFLAG_NONE /* Don't use "none" for packets */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿರಾಂಕ EVP_CIPHER	*(*evptype)(ಶೂನ್ಯ);
#ಇಲ್ಲದಿದ್ದರೆ
	ಶೂನ್ಯ	*ignored;
#ಆದರೆ_ಅಂತ್ಯ
};

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher ciphers[] = {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ OPENSSL_NO_DES
	{ "3des-cbc",		8, 24, 0, 0, CFLAG_CBC, EVP_des_ede3_cbc },
#ಆದರೆ_ಅಂತ್ಯ
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
#ಇಲ್ಲದಿದ್ದರೆ
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, ಖಾಲಿ },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, ಖಾಲಿ },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, ಖಾಲಿ },
#ಆದರೆ_ಅಂತ್ಯ
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, ಖಾಲಿ },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, ಖಾಲಿ },

	{ ಖಾಲಿ,			0, 0, 0, 0, 0, ಖಾಲಿ }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
ಅಕ್ಷರ *
cipher_alg_list(ಅಕ್ಷರ sep, ಪೂರ್ಣಾಂಕ auth_only)
{
	ಅಕ್ಷರ *ret = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *c;
	ಅಕ್ಷರ sep_str[2] = {sep, '\0'};

	ಗಾಗಿ (c = ciphers; c->name != ಖಾಲಿ; c++) {
		ಆದರೆ ((c->flags & CFLAG_ಆಂತರಿಕ) != 0)
			ಮುಂದುವರಿ;
		ಆದರೆ (auth_only && c->auth_len == 0)
			ಮುಂದುವರಿ;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
compression_alg_list(ಪೂರ್ಣಾಂಕ compression)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_ZLIB
	ಹಿಂತಿರುಗಿ compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#ಇಲ್ಲದಿದ್ದರೆ
	ಹಿಂತಿರುಗಿ "none";
#ಆದರೆ_ಅಂತ್ಯ
}

u_int
cipher_blocksize(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *c)
{
	ಹಿಂತಿರುಗಿ (c->ಖಂಡ_ಗಾತ್ರ);
}

u_int
cipher_keylen(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *c)
{
	ಹಿಂತಿರುಗಿ (c->ಕೀಲಿ_len);
}

u_int
cipher_seclen(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *c)
{
	ಆದರೆ (strcmp("3des-cbc", c->name) == 0)
		ಹಿಂತಿರುಗಿ 14;
	ಹಿಂತಿರುಗಿ cipher_keylen(c);
}

u_int
cipher_authlen(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *c)
{
	ಹಿಂತಿರುಗಿ (c->auth_len);
}

u_int
cipher_ivlen(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	ಹಿಂತಿರುಗಿ (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->ಖಂಡ_ಗಾತ್ರ;
}

u_int
cipher_is_cbc(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *c)
{
	ಹಿಂತಿರುಗಿ (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_ಆಂತರಿಕ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *c)
{
	ಹಿಂತಿರುಗಿ (c->flags & CFLAG_ಆಂತರಿಕ) != 0;
}

u_int
cipher_ctx_is_plaintext(ರಚನೆ sshcipher_ctx *cc)
{
	ಹಿಂತಿರುಗಿ cc->plaintext;
}

ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *
cipher_by_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *c;
	ಗಾಗಿ (c = ciphers; c->name != ಖಾಲಿ; c++)
		ಆದರೆ (strcmp(c->name, name) == 0)
			ಹಿಂತಿರುಗಿ c;
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

#ವ್ಯಾಖ್ಯಾನಿಸು	CIPHER_SEP	","
ಪೂರ್ಣಾಂಕ
ciphers_valid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಹೆಸರುಗಳು)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *c;
	ಅಕ್ಷರ *cipher_list, *cp;
	ಅಕ್ಷರ *p;
	ಪೂರ್ಣಾಂಕ ಸಿಕ್ಕಿತು = 0;

	ಆದರೆ (ಹೆಸರುಗಳು == ಖಾಲಿ || strcmp(ಹೆಸರುಗಳು, "") == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((cipher_list = cp = strdup(ಹೆಸರುಗಳು)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಗಾಗಿ ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		ಆದರೆ (c == ಖಾಲಿ || (c->flags & CFLAG_ಆಂತರಿಕ) != 0) {
			ಬಿಡುಗಡೆ(cipher_list);
			ಹಿಂತಿರುಗಿ 0;
		} ಇಲ್ಲದಿದ್ದರೆ
			ಸಿಕ್ಕಿತು = 1;
	}
	ಬಿಡುಗಡೆ(cipher_list);
	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು;
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
cipher_warning_ಸಂದೇಶ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher_ctx *cc)
{
	ಆದರೆ (cc == ಖಾಲಿ || cc->cipher == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	/* XXX repurpose for CBC warning */
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಪೂರ್ಣಾಂಕ
cipher_init(ರಚನೆ sshcipher_ctx **ccp, ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *cipher,
    ಸ್ಥಿರಾಂಕ u_char *ಕೀಲಿ, u_int keylen, ಸ್ಥಿರಾಂಕ u_char *iv, u_int ivlen,
    ಪೂರ್ಣಾಂಕ do_encrypt)
{
	ರಚನೆ sshcipher_ctx *cc = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಆಂತರಿಕ_ERROR;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿರಾಂಕ EVP_CIPHER *type;
	ಪೂರ್ಣಾಂಕ klen;
#ಆದರೆ_ಅಂತ್ಯ

	*ccp = ಖಾಲಿ;
	ಆದರೆ ((cc = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*cc))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	ಆದರೆ (keylen < cipher->ಕೀಲಿ_len ||
	    (iv != ಖಾಲಿ && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	cc->cipher = cipher;
	ಆದರೆ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(ಕೀಲಿ, keylen);
		ret = cc->cp_ctx != ಖಾಲಿ ? 0 : SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		ಹೋಗು ಹೊರಹೋಗು;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ WITH_OPENSSL
	ಆದರೆ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, ಕೀಲಿ, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ret = SSH_ERR_INVALID_ವಾದ;
	ಹೋಗು ಹೊರಹೋಗು;
#ಇಲ್ಲದಿದ್ದರೆ /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	ಆದರೆ ((cc->evp = EVP_CIPHER_CTX_new()) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_CipherInit(cc->evp, type, ಖಾಲಿ, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_ಗಣ_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	klen = EVP_CIPHER_CTX_ಕೀಲಿ_ಉದ್ದಳತೆ(cc->evp);
	ಆದರೆ (klen > 0 && keylen != (u_int)klen) {
		ಆದರೆ (EVP_CIPHER_CTX_ಗಣ_ಕೀಲಿ_ಉದ್ದಳತೆ(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	ಆದರೆ (EVP_CipherInit(cc->evp, ಖಾಲಿ, (u_char *)ಕೀಲಿ, ಖಾಲಿ, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ret = 0;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
 ಹೊರಹೋಗು:
	ಆದರೆ (ret == 0) {
		/* success */
		*ccp = cc;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (cc != ಖಾಲಿ) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
			freezero(cc, ಗಾತ್ರ(*cc));
		}
	}
	ಹಿಂತಿರುಗಿ ret;
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
ಪೂರ್ಣಾಂಕ
cipher_crypt(ರಚನೆ sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   ಸ್ಥಿರಾಂಕ u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	ಆದರೆ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		ಹಿಂತಿರುಗಿ chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	ಆದರೆ ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ಸ್ಮರಣೆ_ನಕಲು(dest, src, aadlen + len);
		ಹಿಂತಿರುಗಿ 0;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ WITH_OPENSSL
	ಆದರೆ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		ಆದರೆ (aadlen)
			ಸ್ಮರಣೆ_ನಕಲು(dest, src, aadlen);
		aesctr_encrypt_ಬೈಟುಗಳು(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
#ಇಲ್ಲದಿದ್ದರೆ
	ಆದರೆ (authlen) {
		u_char lastiv[1];

		ಆದರೆ (authlen != cipher_authlen(cc->cipher))
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
		/* increment IV */
		ಆದರೆ (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		ಆದರೆ (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_ಗಣ_ಟ್ಯಾಗ್,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
	}
	ಆದರೆ (aadlen) {
		ಆದರೆ (authlen &&
		    EVP_Cipher(cc->evp, ಖಾಲಿ, (u_char *)src, aadlen) < 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
		ಸ್ಮರಣೆ_ನಕಲು(dest, src, aadlen);
	}
	ಆದರೆ (len % cc->cipher->ಖಂಡ_ಗಾತ್ರ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
	ಆದರೆ (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		ಆದರೆ (EVP_Cipher(cc->evp, ಖಾಲಿ, ಖಾಲಿ, 0) < 0)
			ಹಿಂತಿರುಗಿ cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		ಆದರೆ (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_ಟ್ಯಾಗ್,
		    authlen, dest + aadlen + len) <= 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
	}
	ಹಿಂತಿರುಗಿ 0;
#ಆದರೆ_ಅಂತ್ಯ
}

/* Extract the packet length, including any decryption necessary beforehand */
ಪೂರ್ಣಾಂಕ
cipher_get_ಉದ್ದಳತೆ(ರಚನೆ sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    ಸ್ಥಿರಾಂಕ u_char *cp, u_int len)
{
	ಆದರೆ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		ಹಿಂತಿರುಗಿ chachapoly_get_ಉದ್ದಳತೆ(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	ಆದರೆ (len < 4)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಸಂದೇಶ_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
cipher_free(ರಚನೆ sshcipher_ctx *cc)
{
	ಆದರೆ (cc == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, ಗಾತ್ರ(cc->ac_ctx));
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = ಖಾಲಿ;
#ಆದರೆ_ಅಂತ್ಯ
	freezero(cc, ಗಾತ್ರ(*cc));
}

ಪೂರ್ಣಾಂಕ
cipher_get_keyiv(ರಚನೆ sshcipher_ctx *cc, u_char *iv, ಗಾತ್ರ_t len)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *c = cc->cipher;
	ಪೂರ್ಣಾಂಕ evplen;
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		ಆದರೆ (len != 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		ಆದರೆ (len != ಗಾತ್ರ(cc->ac_ctx.ctr))
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
		ಸ್ಮರಣೆ_ನಕಲು(iv, cc->ac_ctx.ctr, len);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ ((cc->cipher->flags & CFLAG_NONE) != 0)
		ಹಿಂತಿರುಗಿ 0;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_ಉದ್ದಳತೆ(cc->evp);
	ಆದರೆ (evplen == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (evplen < 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
	ಆದರೆ ((ಗಾತ್ರ_t)evplen != len)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (cipher_authlen(c)) {
		ಆದರೆ (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ 0;
}
