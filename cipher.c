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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>

#అన్తర్భావ "cipher.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"

#అన్తర్భావ "openbsd-compat/openssl-compat.h"

#నిర్వచితం_కాకపోతే WITH_OPENSSL
#నిర్వచించు EVP_CIPHER_CTX శూన్య
#అయితే_ముగింపు

నిర్మాణం sshcipher_ctx {
	పూర్ణాంకం	plaintext;
	పూర్ణాంకం	encrypt;
	EVP_CIPHER_CTX *evp;
	నిర్మాణం chachapoly_ctx *cp_ctx;
	నిర్మాణం aesctr_ctx ac_ctx; /* XXX union with evp? */
	స్థిరరాశి నిర్మాణం sshcipher *cipher;
};

నిర్మాణం sshcipher {
	అక్షరం	*name;
	u_int	ఖండం_కొలత;
	u_int	కీలకం_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#నిర్వచించు CFLAG_CBC		(1<<0)
#నిర్వచించు CFLAG_CHACHAPOLY	(1<<1)
#నిర్వచించు CFLAG_AESCTR		(1<<2)
#నిర్వచించు CFLAG_NONE		(1<<3)
#నిర్వచించు CFLAG_అంతర్గత		CFLAG_NONE /* Don't use "none" for packets */
#నిర్వచితమైతే WITH_OPENSSL
	స్థిరరాశి EVP_CIPHER	*(*evptype)(శూన్య);
#లేకపోతే
	శూన్య	*ignored;
#అయితే_ముగింపు
};

స్థిర స్థిరరాశి నిర్మాణం sshcipher ciphers[] = {
#నిర్వచితమైతే WITH_OPENSSL
#నిర్వచితం_కాకపోతే OPENSSL_NO_DES
	{ "3des-cbc",		8, 24, 0, 0, CFLAG_CBC, EVP_des_ede3_cbc },
#అయితే_ముగింపు
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
#లేకపోతే
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, ఖాళీ },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, ఖాళీ },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, ఖాళీ },
#అయితే_ముగింపు
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, ఖాళీ },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, ఖాళీ },

	{ ఖాళీ,			0, 0, 0, 0, 0, ఖాళీ }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
అక్షరం *
cipher_alg_list(అక్షరం sep, పూర్ణాంకం auth_only)
{
	అక్షరం *ret = ఖాళీ;
	స్థిరరాశి నిర్మాణం sshcipher *c;
	అక్షరం sep_str[2] = {sep, '\0'};

	కొరకు (c = ciphers; c->name != ఖాళీ; c++) {
		ఒకవేళ ((c->flags & CFLAG_అంతర్గత) != 0)
			కొనసాగు;
		ఒకవేళ (auth_only && c->auth_len == 0)
			కొనసాగు;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	తిరిగి ret;
}

స్థిరరాశి అక్షరం *
compression_alg_list(పూర్ణాంకం compression)
{
#నిర్వచితమైతే WITH_ZLIB
	తిరిగి compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#లేకపోతే
	తిరిగి "none";
#అయితే_ముగింపు
}

u_int
cipher_blocksize(స్థిరరాశి నిర్మాణం sshcipher *c)
{
	తిరిగి (c->ఖండం_కొలత);
}

u_int
cipher_keylen(స్థిరరాశి నిర్మాణం sshcipher *c)
{
	తిరిగి (c->కీలకం_len);
}

u_int
cipher_seclen(స్థిరరాశి నిర్మాణం sshcipher *c)
{
	ఒకవేళ (strcmp("3des-cbc", c->name) == 0)
		తిరిగి 14;
	తిరిగి cipher_keylen(c);
}

u_int
cipher_authlen(స్థిరరాశి నిర్మాణం sshcipher *c)
{
	తిరిగి (c->auth_len);
}

u_int
cipher_ivlen(స్థిరరాశి నిర్మాణం sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	తిరిగి (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->ఖండం_కొలత;
}

u_int
cipher_is_cbc(స్థిరరాశి నిర్మాణం sshcipher *c)
{
	తిరిగి (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_అంతర్గత(స్థిరరాశి నిర్మాణం sshcipher *c)
{
	తిరిగి (c->flags & CFLAG_అంతర్గత) != 0;
}

u_int
cipher_ctx_is_plaintext(నిర్మాణం sshcipher_ctx *cc)
{
	తిరిగి cc->plaintext;
}

స్థిరరాశి నిర్మాణం sshcipher *
cipher_by_name(స్థిరరాశి అక్షరం *name)
{
	స్థిరరాశి నిర్మాణం sshcipher *c;
	కొరకు (c = ciphers; c->name != ఖాళీ; c++)
		ఒకవేళ (strcmp(c->name, name) == 0)
			తిరిగి c;
	తిరిగి ఖాళీ;
}

#నిర్వచించు	CIPHER_SEP	","
పూర్ణాంకం
ciphers_valid(స్థిరరాశి అక్షరం *పేర్లు)
{
	స్థిరరాశి నిర్మాణం sshcipher *c;
	అక్షరం *cipher_list, *cp;
	అక్షరం *p;
	పూర్ణాంకం దొరికింది = 0;

	ఒకవేళ (పేర్లు == ఖాళీ || strcmp(పేర్లు, "") == 0)
		తిరిగి 0;
	ఒకవేళ ((cipher_list = cp = strdup(పేర్లు)) == ఖాళీ)
		తిరిగి 0;
	కొరకు ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		ఒకవేళ (c == ఖాళీ || (c->flags & CFLAG_అంతర్గత) != 0) {
			విడుదల(cipher_list);
			తిరిగి 0;
		} లేకపోతే
			దొరికింది = 1;
	}
	విడుదల(cipher_list);
	తిరిగి దొరికింది;
}

స్థిరరాశి అక్షరం *
cipher_warning_సందేశం(స్థిరరాశి నిర్మాణం sshcipher_ctx *cc)
{
	ఒకవేళ (cc == ఖాళీ || cc->cipher == ఖాళీ)
		తిరిగి ఖాళీ;
	/* XXX repurpose for CBC warning */
	తిరిగి ఖాళీ;
}

పూర్ణాంకం
cipher_init(నిర్మాణం sshcipher_ctx **ccp, స్థిరరాశి నిర్మాణం sshcipher *cipher,
    స్థిరరాశి u_char *కీలకం, u_int keylen, స్థిరరాశి u_char *iv, u_int ivlen,
    పూర్ణాంకం do_encrypt)
{
	నిర్మాణం sshcipher_ctx *cc = ఖాళీ;
	పూర్ణాంకం ret = SSH_ERR_అంతర్గత_ERROR;
#నిర్వచితమైతే WITH_OPENSSL
	స్థిరరాశి EVP_CIPHER *type;
	పూర్ణాంకం klen;
#అయితే_ముగింపు

	*ccp = ఖాళీ;
	ఒకవేళ ((cc = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*cc))) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	ఒకవేళ (keylen < cipher->కీలకం_len ||
	    (iv != ఖాళీ && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}

	cc->cipher = cipher;
	ఒకవేళ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(కీలకం, keylen);
		ret = cc->cp_ctx != ఖాళీ ? 0 : SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		వెళ్ళు బహిర్గతం;
	}
#నిర్వచితం_కాకపోతే WITH_OPENSSL
	ఒకవేళ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, కీలకం, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		వెళ్ళు బహిర్గతం;
	}
	ret = SSH_ERR_INVALID_వాదం;
	వెళ్ళు బహిర్గతం;
#లేకపోతే /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	ఒకవేళ ((cc->evp = EVP_CIPHER_CTX_new()) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_CipherInit(cc->evp, type, ఖాళీ, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_సమితి_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	klen = EVP_CIPHER_CTX_కీలకం_నిడివి(cc->evp);
	ఒకవేళ (klen > 0 && keylen != (u_int)klen) {
		ఒకవేళ (EVP_CIPHER_CTX_సమితి_కీలకం_నిడివి(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			వెళ్ళు బహిర్గతం;
		}
	}
	ఒకవేళ (EVP_CipherInit(cc->evp, ఖాళీ, (u_char *)కీలకం, ఖాళీ, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ret = 0;
#అయితే_ముగింపు /* WITH_OPENSSL */
 బహిర్గతం:
	ఒకవేళ (ret == 0) {
		/* success */
		*ccp = cc;
	} లేకపోతే {
		ఒకవేళ (cc != ఖాళీ) {
#నిర్వచితమైతే WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#అయితే_ముగింపు /* WITH_OPENSSL */
			freezero(cc, పరిమాణం(*cc));
		}
	}
	తిరిగి ret;
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
పూర్ణాంకం
cipher_crypt(నిర్మాణం sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   స్థిరరాశి u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	ఒకవేళ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		తిరిగి chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	ఒకవేళ ((cc->cipher->flags & CFLAG_NONE) != 0) {
		జ్ఞాపకం_నకలు(dest, src, aadlen + len);
		తిరిగి 0;
	}
#నిర్వచితం_కాకపోతే WITH_OPENSSL
	ఒకవేళ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		ఒకవేళ (aadlen)
			జ్ఞాపకం_నకలు(dest, src, aadlen);
		aesctr_encrypt_బైట్లు(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		తిరిగి 0;
	}
	తిరిగి SSH_ERR_INVALID_వాదం;
#లేకపోతే
	ఒకవేళ (authlen) {
		u_char lastiv[1];

		ఒకవేళ (authlen != cipher_authlen(cc->cipher))
			తిరిగి SSH_ERR_INVALID_వాదం;
		/* increment IV */
		ఒకవేళ (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		ఒకవేళ (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_సమితి_ట్యాగ్,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
	}
	ఒకవేళ (aadlen) {
		ఒకవేళ (authlen &&
		    EVP_Cipher(cc->evp, ఖాళీ, (u_char *)src, aadlen) < 0)
			తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
		జ్ఞాపకం_నకలు(dest, src, aadlen);
	}
	ఒకవేళ (len % cc->cipher->ఖండం_కొలత)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
	ఒకవేళ (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		ఒకవేళ (EVP_Cipher(cc->evp, ఖాళీ, ఖాళీ, 0) < 0)
			తిరిగి cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		ఒకవేళ (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_ట్యాగ్,
		    authlen, dest + aadlen + len) <= 0)
			తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
	}
	తిరిగి 0;
#అయితే_ముగింపు
}

/* Extract the packet length, including any decryption necessary beforehand */
పూర్ణాంకం
cipher_get_నిడివి(నిర్మాణం sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    స్థిరరాశి u_char *cp, u_int len)
{
	ఒకవేళ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		తిరిగి chachapoly_get_నిడివి(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	ఒకవేళ (len < 4)
		తిరిగి SSH_ERR_సందేశం_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	తిరిగి 0;
}

శూన్య
cipher_free(నిర్మాణం sshcipher_ctx *cc)
{
	ఒకవేళ (cc == ఖాళీ)
		తిరిగి;
	ఒకవేళ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = ఖాళీ;
	} లేకపోతే ఒకవేళ ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, పరిమాణం(cc->ac_ctx));
#నిర్వచితమైతే WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = ఖాళీ;
#అయితే_ముగింపు
	freezero(cc, పరిమాణం(*cc));
}

పూర్ణాంకం
cipher_get_keyiv(నిర్మాణం sshcipher_ctx *cc, u_char *iv, కొలత_t len)
{
#నిర్వచితమైతే WITH_OPENSSL
	స్థిరరాశి నిర్మాణం sshcipher *c = cc->cipher;
	పూర్ణాంకం evplen;
#అయితే_ముగింపు

	ఒకవేళ ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		ఒకవేళ (len != 0)
			తిరిగి SSH_ERR_INVALID_వాదం;
		తిరిగి 0;
	}
	ఒకవేళ ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		ఒకవేళ (len != పరిమాణం(cc->ac_ctx.ctr))
			తిరిగి SSH_ERR_INVALID_వాదం;
		జ్ఞాపకం_నకలు(iv, cc->ac_ctx.ctr, len);
		తిరిగి 0;
	}
	ఒకవేళ ((cc->cipher->flags & CFLAG_NONE) != 0)
		తిరిగి 0;

#నిర్వచితమైతే WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_నిడివి(cc->evp);
	ఒకవేళ (evplen == 0)
		తిరిగి 0;
	లేకపోతే ఒకవేళ (evplen < 0)
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
	ఒకవేళ ((కొలత_t)evplen != len)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (cipher_authlen(c)) {
		ఒకవేళ (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
	} లేకపోతే ఒకవేళ (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
#అయితే_ముగింపు
	తిరిగి 0;
}
