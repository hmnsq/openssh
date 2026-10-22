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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <string.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>

#समावेश "cipher.h"
#समावेश "misc.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"

#समावेश "openbsd-compat/openssl-compat.h"

#अगर_अघोषित WITH_OPENSSL
#घोषणा EVP_CIPHER_CTX व्योम
#पूर्ण_अगर

काष्ठा sshcipher_ctx {
	पूर्णांक	plaintext;
	पूर्णांक	encrypt;
	EVP_CIPHER_CTX *evp;
	काष्ठा chachapoly_ctx *cp_ctx;
	काष्ठा aesctr_ctx ac_ctx; /* XXX union with evp? */
	स्थिर काष्ठा sshcipher *cipher;
};

काष्ठा sshcipher {
	अक्षर	*name;
	u_int	block_आकार;
	u_int	कुंजी_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#घोषणा CFLAG_CBC		(1<<0)
#घोषणा CFLAG_CHACHAPOLY	(1<<1)
#घोषणा CFLAG_AESCTR		(1<<2)
#घोषणा CFLAG_NONE		(1<<3)
#घोषणा CFLAG_INTERNAL		CFLAG_NONE /* Don't use "none" for packets */
#अगर_घोषित WITH_OPENSSL
	स्थिर EVP_CIPHER	*(*evptype)(व्योम);
#अन्यथा
	व्योम	*ignored;
#पूर्ण_अगर
};

अटल स्थिर काष्ठा sshcipher ciphers[] = {
#अगर_घोषित WITH_OPENSSL
#अगर_अघोषित OPENSSL_NO_DES
	{ "3des-cbc",		8, 24, 0, 0, CFLAG_CBC, EVP_des_ede3_cbc },
#पूर्ण_अगर
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
#अन्यथा
	{ "aes128-ctr",		16, 16, 0, 0, CFLAG_AESCTR, शून्य },
	{ "aes192-ctr",		16, 24, 0, 0, CFLAG_AESCTR, शून्य },
	{ "aes256-ctr",		16, 32, 0, 0, CFLAG_AESCTR, शून्य },
#पूर्ण_अगर
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CFLAG_CHACHAPOLY, शून्य },
	{ "none",		8, 0, 0, 0, CFLAG_NONE, शून्य },

	{ शून्य,			0, 0, 0, 0, 0, शून्य }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
अक्षर *
cipher_alg_list(अक्षर sep, पूर्णांक auth_only)
{
	अक्षर *ret = शून्य;
	स्थिर काष्ठा sshcipher *c;
	अक्षर sep_str[2] = {sep, '\0'};

	क्रम (c = ciphers; c->name != शून्य; c++) {
		अगर ((c->flags & CFLAG_INTERNAL) != 0)
			जारी;
		अगर (auth_only && c->auth_len == 0)
			जारी;
		xextendf(&ret, sep_str, "%s", c->name);
	}
	वापस ret;
}

स्थिर अक्षर *
compression_alg_list(पूर्णांक compression)
{
#अगर_घोषित WITH_ZLIB
	वापस compression ? "zlib@openssh.com,none" :
	    "none,zlib@openssh.com";
#अन्यथा
	वापस "none";
#पूर्ण_अगर
}

u_int
cipher_blocksize(स्थिर काष्ठा sshcipher *c)
{
	वापस (c->block_आकार);
}

u_int
cipher_keylen(स्थिर काष्ठा sshcipher *c)
{
	वापस (c->कुंजी_len);
}

u_int
cipher_seclen(स्थिर काष्ठा sshcipher *c)
{
	अगर (म_भेद("3des-cbc", c->name) == 0)
		वापस 14;
	वापस cipher_keylen(c);
}

u_int
cipher_authlen(स्थिर काष्ठा sshcipher *c)
{
	वापस (c->auth_len);
}

u_int
cipher_ivlen(स्थिर काष्ठा sshcipher *c)
{
	/*
	 * Default is cipher block size, except for chacha20+poly1305 that
	 * needs no IV. XXX make iv_len == -1 default?
	 */
	वापस (c->iv_len != 0 || (c->flags & CFLAG_CHACHAPOLY) != 0) ?
	    c->iv_len : c->block_आकार;
}

u_int
cipher_is_cbc(स्थिर काष्ठा sshcipher *c)
{
	वापस (c->flags & CFLAG_CBC) != 0;
}

u_int
cipher_is_internal(स्थिर काष्ठा sshcipher *c)
{
	वापस (c->flags & CFLAG_INTERNAL) != 0;
}

u_int
cipher_ctx_is_plaintext(काष्ठा sshcipher_ctx *cc)
{
	वापस cc->plaintext;
}

स्थिर काष्ठा sshcipher *
cipher_by_name(स्थिर अक्षर *name)
{
	स्थिर काष्ठा sshcipher *c;
	क्रम (c = ciphers; c->name != शून्य; c++)
		अगर (म_भेद(c->name, name) == 0)
			वापस c;
	वापस शून्य;
}

#घोषणा	CIPHER_SEP	","
पूर्णांक
ciphers_valid(स्थिर अक्षर *names)
{
	स्थिर काष्ठा sshcipher *c;
	अक्षर *cipher_list, *cp;
	अक्षर *p;
	पूर्णांक found = 0;

	अगर (names == शून्य || म_भेद(names, "") == 0)
		वापस 0;
	अगर ((cipher_list = cp = strdup(names)) == शून्य)
		वापस 0;
	क्रम ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		अगर (c == शून्य || (c->flags & CFLAG_INTERNAL) != 0) {
			मुक्त(cipher_list);
			वापस 0;
		} अन्यथा
			found = 1;
	}
	मुक्त(cipher_list);
	वापस found;
}

स्थिर अक्षर *
cipher_warning_message(स्थिर काष्ठा sshcipher_ctx *cc)
{
	अगर (cc == शून्य || cc->cipher == शून्य)
		वापस शून्य;
	/* XXX repurpose for CBC warning */
	वापस शून्य;
}

पूर्णांक
cipher_init(काष्ठा sshcipher_ctx **ccp, स्थिर काष्ठा sshcipher *cipher,
    स्थिर u_char *कुंजी, u_int keylen, स्थिर u_char *iv, u_int ivlen,
    पूर्णांक do_encrypt)
{
	काष्ठा sshcipher_ctx *cc = शून्य;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;
#अगर_घोषित WITH_OPENSSL
	स्थिर EVP_CIPHER *type;
	पूर्णांक klen;
#पूर्ण_अगर

	*ccp = शून्य;
	अगर ((cc = सुस्मृति(1, माप(*cc))) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;

	cc->plaintext = (cipher->flags & CFLAG_NONE) != 0;
	cc->encrypt = do_encrypt;

	अगर (keylen < cipher->कुंजी_len ||
	    (iv != शून्य && ivlen < cipher_ivlen(cipher))) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}

	cc->cipher = cipher;
	अगर ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		cc->cp_ctx = chachapoly_new(कुंजी, keylen);
		ret = cc->cp_ctx != शून्य ? 0 : SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	अगर ((cc->cipher->flags & CFLAG_NONE) != 0) {
		ret = 0;
		जाओ out;
	}
#अगर_अघोषित WITH_OPENSSL
	अगर ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		aesctr_keysetup(&cc->ac_ctx, कुंजी, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		ret = 0;
		जाओ out;
	}
	ret = SSH_ERR_INVALID_ARGUMENT;
	जाओ out;
#अन्यथा /* WITH_OPENSSL */
	type = (*cipher->evptype)();
	अगर ((cc->evp = EVP_CIPHER_CTX_new()) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (EVP_CipherInit(cc->evp, type, शून्य, (u_char *)iv,
	    (do_encrypt == CIPHER_ENCRYPT)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	अगर (cipher_authlen(cipher) &&
	    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_IV_FIXED,
	    -1, (u_char *)iv) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	klen = EVP_CIPHER_CTX_कुंजी_लंबाई(cc->evp);
	अगर (klen > 0 && keylen != (u_int)klen) {
		अगर (EVP_CIPHER_CTX_set_कुंजी_लंबाई(cc->evp, keylen) == 0) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			जाओ out;
		}
	}
	अगर (EVP_CipherInit(cc->evp, शून्य, (u_char *)कुंजी, शून्य, -1) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	ret = 0;
#पूर्ण_अगर /* WITH_OPENSSL */
 out:
	अगर (ret == 0) {
		/* success */
		*ccp = cc;
	} अन्यथा {
		अगर (cc != शून्य) {
#अगर_घोषित WITH_OPENSSL
			EVP_CIPHER_CTX_free(cc->evp);
#पूर्ण_अगर /* WITH_OPENSSL */
			freezero(cc, माप(*cc));
		}
	}
	वापस ret;
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
पूर्णांक
cipher_crypt(काष्ठा sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   स्थिर u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	अगर ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		वापस chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
	}
	अगर ((cc->cipher->flags & CFLAG_NONE) != 0) {
		स_नकल(dest, src, aadlen + len);
		वापस 0;
	}
#अगर_अघोषित WITH_OPENSSL
	अगर ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		अगर (aadlen)
			स_नकल(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		वापस 0;
	}
	वापस SSH_ERR_INVALID_ARGUMENT;
#अन्यथा
	अगर (authlen) {
		u_char lastiv[1];

		अगर (authlen != cipher_authlen(cc->cipher))
			वापस SSH_ERR_INVALID_ARGUMENT;
		/* increment IV */
		अगर (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN,
		    1, lastiv) <= 0)
			वापस SSH_ERR_LIBCRYPTO_ERROR;
		/* set tag on decryption */
		अगर (!cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_SET_TAG,
		    authlen, (u_char *)src + aadlen + len) <= 0)
			वापस SSH_ERR_LIBCRYPTO_ERROR;
	}
	अगर (aadlen) {
		अगर (authlen &&
		    EVP_Cipher(cc->evp, शून्य, (u_char *)src, aadlen) < 0)
			वापस SSH_ERR_LIBCRYPTO_ERROR;
		स_नकल(dest, src, aadlen);
	}
	अगर (len % cc->cipher->block_आकार)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (EVP_Cipher(cc->evp, dest + aadlen, (u_char *)src + aadlen,
	    len) < 0)
		वापस SSH_ERR_LIBCRYPTO_ERROR;
	अगर (authlen) {
		/* compute tag (on encrypt) or verify tag (on decrypt) */
		अगर (EVP_Cipher(cc->evp, शून्य, शून्य, 0) < 0)
			वापस cc->encrypt ?
			    SSH_ERR_LIBCRYPTO_ERROR : SSH_ERR_MAC_INVALID;
		अगर (cc->encrypt &&
		    EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_GET_TAG,
		    authlen, dest + aadlen + len) <= 0)
			वापस SSH_ERR_LIBCRYPTO_ERROR;
	}
	वापस 0;
#पूर्ण_अगर
}

/* Extract the packet length, including any decryption necessary beforehand */
पूर्णांक
cipher_get_लंबाई(काष्ठा sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    स्थिर u_char *cp, u_int len)
{
	अगर ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0)
		वापस chachapoly_get_लंबाई(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	अगर (len < 4)
		वापस SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	वापस 0;
}

व्योम
cipher_free(काष्ठा sshcipher_ctx *cc)
{
	अगर (cc == शून्य)
		वापस;
	अगर ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = शून्य;
	} अन्यथा अगर ((cc->cipher->flags & CFLAG_AESCTR) != 0)
		explicit_bzero(&cc->ac_ctx, माप(cc->ac_ctx));
#अगर_घोषित WITH_OPENSSL
	EVP_CIPHER_CTX_free(cc->evp);
	cc->evp = शून्य;
#पूर्ण_अगर
	freezero(cc, माप(*cc));
}

पूर्णांक
cipher_get_keyiv(काष्ठा sshcipher_ctx *cc, u_char *iv, माप_प्रकार len)
{
#अगर_घोषित WITH_OPENSSL
	स्थिर काष्ठा sshcipher *c = cc->cipher;
	पूर्णांक evplen;
#पूर्ण_अगर

	अगर ((cc->cipher->flags & CFLAG_CHACHAPOLY) != 0) {
		अगर (len != 0)
			वापस SSH_ERR_INVALID_ARGUMENT;
		वापस 0;
	}
	अगर ((cc->cipher->flags & CFLAG_AESCTR) != 0) {
		अगर (len != माप(cc->ac_ctx.ctr))
			वापस SSH_ERR_INVALID_ARGUMENT;
		स_नकल(iv, cc->ac_ctx.ctr, len);
		वापस 0;
	}
	अगर ((cc->cipher->flags & CFLAG_NONE) != 0)
		वापस 0;

#अगर_घोषित WITH_OPENSSL
	evplen = EVP_CIPHER_CTX_iv_लंबाई(cc->evp);
	अगर (evplen == 0)
		वापस 0;
	अन्यथा अगर (evplen < 0)
		वापस SSH_ERR_LIBCRYPTO_ERROR;
	अगर ((माप_प्रकार)evplen != len)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (cipher_authlen(c)) {
		अगर (EVP_CIPHER_CTX_ctrl(cc->evp, EVP_CTRL_GCM_IV_GEN, len,
		    iv) <= 0)
			वापस SSH_ERR_LIBCRYPTO_ERROR;
	} अन्यथा अगर (EVP_CIPHER_CTX_get_iv(cc->evp, iv, len) <= 0)
		वापस SSH_ERR_LIBCRYPTO_ERROR;
#पूर्ण_अगर
	वापस 0;
}
