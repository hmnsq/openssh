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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <string.h>
#شامل <stdarg.h>
#شامل <stdio.h>

#شامل "cipher.h"
#شامل "misc.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"

#شامل "openbsd-compat/openssl-compat.h"

#اگر_غیر_تعریف_شدہ WITH_OPENSSL
#تعریف_کرو EVP_CIPHER_CTX خالی
#اگر_ختم

ساخت sshcipher_ctx {
	صحیح	plaintext;
	صحیح	encrypt;
	EVP_CIPHER_CTX *evp;
	ساخت chachapoly_ctx *cp_ctx;
	ساخت aesctr_ctx ac_ctx; /* XXX union with evp? */
	ثابت ساخت sshcipher *cipher;
};

ساخت sshcipher {
	حرف	*name;
	u_int	بلاک_سائز;
	u_int	کلید_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#تعریف_کرو CFLAG_CBC		(1<<0)
#تعریف_کرو CFLAG_CHACHAPOLY	(1<<1)
#تعریف_کرو CFLAG_AESCTR		(1<<2)
#تعریف_کرو CFLAG_NONE		(1<<3)
#تعریف_کرو CFLAG_اندرونی		CFLAG_NONE /* Don't use "none" for packets */
#اگر_تعریف_شدہ WITH_OPENSSL
	ثابت EVP_CIPHER	*(*evptype)(خالی);
#ورنہ
	خالی	*ignored;
#اگر_ختم
};

ساکن ثابت ساخت sshcipher ciphers[] = {
#اگر_تعریف_شدہ WITH_OPENSSL
#اگر_غیر_تعریف_شدہ OPENSSL_NO_DES
	{ "3des-cbc",		8, 24, 0, 0, CFLAG_CBC, EVP_des_ede3_cbc },
#اگر_ختم
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
#ورنہ
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, تہی },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, تہی },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, تہی },
#اگر_ختم
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, تہی },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, تہی },

	{ تہی,			0, 0, 0, 0, 0, تہی }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
حرف *
cipher_alg_list(حرف sep, صحیح auth_only)
{
	حرف *ret = تہی;
	ثابت ساخت sshcipher *c;
	حرف sep_str[2] = {sep, '\0'};

	برائے (c = ciphers; c->name != تہی; c++) {
		اگر ((c->flags & CFLAG_اندرونی) != 0)
			جاری;
		اگر (auth_only && c->auth_len == 0)
			جاری;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	واپس ret;
}

ثابت حرف *
compression_alg_list(صحیح compression)
{
#اگر_تعریف_شدہ WITH_ZLIB
	واپس compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#ورنہ
	واپس "none";
#اگر_ختم
}

u_int
cipher_blocksize(ثابت ساخت sshcipher *c)
{
	واپس (c->بلاک_سائز);
}

u_int
cipher_keylen(ثابت ساخت sshcipher *c)
{
	واپس (c->کلید_len);
}

u_int
cipher_seclen(ثابت ساخت sshcipher *c)
{
	اگر (strcmp("3des-cbc", c->name) == 0)
		واپس 14;
	واپس cipher_keylen(c);
}

u_int
cipher_authlen(ثابت ساخت sshcipher *c)
{
	واپس (c->auth_len);
}

u_int
cipher_ivlen(ثابت ساخت sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	واپس (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->بلاک_سائز;
}

u_int
cipher_is_cbc(ثابت ساخت sshcipher *c)
{
	واپس (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_اندرونی(ثابت ساخت sshcipher *c)
{
	واپس (c->flags & CFLAG_اندرونی) != 0;
}

u_int
cipher_ctx_is_plaintext(ساخت sshcipher_ctx *cc)
{
	واپس cc->plaintext;
}

ثابت ساخت sshcipher *
cipher_by_name(ثابت حرف *name)
{
	ثابت ساخت sshcipher *c;
	برائے (c = ciphers; c->name != تہی; c++)
		اگر (strcmp(c->name, name) == 0)
			واپس c;
	واپس تہی;
}

#تعریف_کرو	CIPHER_SEP	","
صحیح
ciphers_valid(ثابت حرف *نام)
{
	ثابت ساخت sshcipher *c;
	حرف *cipher_list, *cp;
	حرف *p;
	صحیح ملا = 0;

	اگر (نام == تہی || strcmp(نام, "") == 0)
		واپس 0;
	اگر ((cipher_list = cp = strdup(نام)) == تہی)
		واپس 0;
	برائے ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		اگر (c == تہی || (c->flags & CFLAG_اندرونی) != 0) {
			آزاد(cipher_list);
			واپس 0;
		} ورنہ
			ملا = 1;
	}
	آزاد(cipher_list);
	واپس ملا;
}

ثابت حرف *
cipher_warning_پیغام(ثابت ساخت sshcipher_ctx *cc)
{
	اگر (cc == تہی || cc->cipher == تہی)
		واپس تہی;
	/* XXX repurpose for CBC warning */
	واپس تہی;
}

صحیح
cipher_init(ساخت sshcipher_ctx **ccp, ثابت ساخت sshcipher *cipher,
    ثابت u_char *کلید, u_int keylen, ثابت u_char *iv, u_int ivlen,
    صحیح do_encrypt)
{
	ساخت sshcipher_ctx *cc = تہی;
	صحیح ret = SSH_ERR_اندرونی_ERROR;
#اگر_تعریف_شدہ WITH_OPENSSL
	ثابت EVP_CIPHER *type;
	صحیح klen;
#اگر_ختم

	*ccp = تہی;
	اگر ((cc = صفر_حافظہ_دو(1, حجم(*cc))) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	اگر (keylen < cipher->کلید_len ||
	    (iv != تہی && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}

	cc->cipher = cipher;
	اگر ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(کلید, keylen);
		ret = cc->cp_ctx != تہی ? 0 : SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	اگر ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		جاؤ برآمد;
	}
#اگر_غیر_تعریف_شدہ WITH_OPENSSL
	اگر ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, کلید, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		جاؤ برآمد;
	}
	ret = SSH_ERR_INVALID_دلیل;
	جاؤ برآمد;
#ورنہ /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	اگر ((cc->evp = EVP_CIPHER_CTX_new()) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (EVP_CipherInit(cc->evp, type, تہی, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	اگر (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_سیٹ_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	klen = EVP_CIPHER_CTX_کلید_لمبائی(cc->evp);
	اگر (klen > 0 && keylen != (u_int)klen) {
		اگر (EVP_CIPHER_CTX_سیٹ_کلید_لمبائی(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			جاؤ برآمد;
		}
	}
	اگر (EVP_CipherInit(cc->evp, تہی, (u_char *)کلید, تہی, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	ret = 0;
#اگر_ختم /* WITH_OPENSSL */
 برآمد:
	اگر (ret == 0) {
		/* success */
		*ccp = cc;
	} ورنہ {
		اگر (cc != تہی) {
#اگر_تعریف_شدہ WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#اگر_ختم /* WITH_OPENSSL */
			freezero(cc, حجم(*cc));
		}
	}
	واپس ret;
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
صحیح
cipher_crypt(ساخت sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   ثابت u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	اگر ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		واپس chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	اگر ((cc->cipher->flags & CFLAG_NONE) != 0) {
		حافظہ_نقل(dest, src, aadlen + len);
		واپس 0;
	}
#اگر_غیر_تعریف_شدہ WITH_OPENSSL
	اگر ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		اگر (aadlen)
			حافظہ_نقل(dest, src, aadlen);
		aesctr_encrypt_بائٹیں(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		واپس 0;
	}
	واپس SSH_ERR_INVALID_دلیل;
#ورنہ
	اگر (authlen) {
		u_char lastiv[1];

		اگر (authlen != cipher_authlen(cc->cipher))
			واپس SSH_ERR_INVALID_دلیل;
		/* increment IV */
		اگر (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			واپس SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		اگر (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_سیٹ_لیبل,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			واپس SSH_ERR_LIBCRYPTO_ERROR;
	}
	اگر (aadlen) {
		اگر (authlen &&
		    EVP_Cipher(cc->evp, تہی, (u_char *)src, aadlen) < 0)
			واپس SSH_ERR_LIBCRYPTO_ERROR;
		حافظہ_نقل(dest, src, aadlen);
	}
	اگر (len % cc->cipher->بلاک_سائز)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		واپس SSH_ERR_LIBCRYPTO_ERROR;
	اگر (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		اگر (EVP_Cipher(cc->evp, تہی, تہی, 0) < 0)
			واپس cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		اگر (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_لیبل,
		    authlen, dest + aadlen + len) <= 0)
			واپس SSH_ERR_LIBCRYPTO_ERROR;
	}
	واپس 0;
#اگر_ختم
}

/* Extract the packet length, including any decryption necessary beforehand */
صحیح
cipher_get_لمبائی(ساخت sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    ثابت u_char *cp, u_int len)
{
	اگر ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		واپس chachapoly_get_لمبائی(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	اگر (len < 4)
		واپس SSH_ERR_پیغام_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	واپس 0;
}

خالی
cipher_free(ساخت sshcipher_ctx *cc)
{
	اگر (cc == تہی)
		واپس;
	اگر ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = تہی;
	} ورنہ اگر ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, حجم(cc->ac_ctx));
#اگر_تعریف_شدہ WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = تہی;
#اگر_ختم
	freezero(cc, حجم(*cc));
}

صحیح
cipher_get_keyiv(ساخت sshcipher_ctx *cc, u_char *iv, سائز_t len)
{
#اگر_تعریف_شدہ WITH_OPENSSL
	ثابت ساخت sshcipher *c = cc->cipher;
	صحیح evplen;
#اگر_ختم

	اگر ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		اگر (len != 0)
			واپس SSH_ERR_INVALID_دلیل;
		واپس 0;
	}
	اگر ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		اگر (len != حجم(cc->ac_ctx.ctr))
			واپس SSH_ERR_INVALID_دلیل;
		حافظہ_نقل(iv, cc->ac_ctx.ctr, len);
		واپس 0;
	}
	اگر ((cc->cipher->flags & CFLAG_NONE) != 0)
		واپس 0;

#اگر_تعریف_شدہ WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_لمبائی(cc->evp);
	اگر (evplen == 0)
		واپس 0;
	ورنہ اگر (evplen < 0)
		واپس SSH_ERR_LIBCRYPTO_ERROR;
	اگر ((سائز_t)evplen != len)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (cipher_authlen(c)) {
		اگر (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			واپس SSH_ERR_LIBCRYPTO_ERROR;
	} ورنہ اگر (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		واپس SSH_ERR_LIBCRYPTO_ERROR;
#اگر_ختم
	واپس 0;
}
