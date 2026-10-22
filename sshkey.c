/* $OpenBSD: sshkey.c,v 1.165 2026/10/01 07:07:49 djm Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Alexander von Gernler.  All rights reserved.
 * Copyright (c) 2010,2011 Damien Miller.  All rights reserved.
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
#समावेश <sys/mman.h>
#समावेश <netinet/in.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/bn.h>
#समावेश <openssl/evp.h>
#समावेश <openssl/err.h>
#समावेश <openssl/pem.h>
#पूर्ण_अगर

#समावेश "crypto_api.h"

#समावेश <errno.h>
#समावेश <limits.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <resolv.h>
#समावेश <time.h>
#समावेश <util.h>

#समावेश "ssh2.h"
#समावेश "ssherr.h"
#समावेश "misc.h"
#समावेश "sshbuf.h"
#समावेश "cipher.h"
#समावेश "digest.h"
#घोषणा SSHKEY_INTERNAL
#समावेश "sshkey.h"
#समावेश "match.h"
#समावेश "ssh-sk.h"
#समावेश "ssh-pkcs11.h"

#समावेश "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#घोषणा MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#घोषणा MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#घोषणा MARK_BEGIN_LEN		(माप(MARK_BEGIN) - 1)
#घोषणा MARK_END_LEN		(माप(MARK_END) - 1)
#घोषणा KDFNAME			"bcrypt"
#घोषणा AUTH_MAGIC		"openssh-key-v1"
#घोषणा SALT_LEN		16
#घोषणा DEFAULT_CIPHERNAME	"aes256-ctr"
#घोषणा	DEFAULT_ROUNDS		32
#घोषणा	MAX_KDF_ROUNDS		(1<<20)

/*
 * Constants relating to "shielding" support; protection of keys expected
 * to remain in memory for long durations
 */
#घोषणा SSHKEY_SHIELD_PREKEY_LEN	(16 * 1024)
#घोषणा SSHKEY_SHIELD_CIPHER		"aes256-ctr" /* XXX want AES-EME* */
#घोषणा SSHKEY_SHIELD_PREKEY_HASH	SSH_DIGEST_SHA512

अटल पूर्णांक sshkey_from_blob_internal(काष्ठा sshbuf *buf,
    काष्ठा sshkey **keyp, पूर्णांक allow_cert,
    स्थिर अक्षर *alg_allowlist, स्थिर अक्षर *ca_sigalg_allowlist);

/* Supported key types */
बाह्य स्थिर काष्ठा sshkey_impl sshkey_ed25519_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_ed25519_cert_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_ed25519_sk_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
बाह्य स्थिर काष्ठा sshkey_impl sshkey_mldsa44_ed25519_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#अगर_घोषित WITH_OPENSSL
# ifdef ENABLE_SK
बाह्य स्थिर काष्ठा sshkey_impl sshkey_ecdsa_sk_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_ecdsa_sk_cert_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
बाह्य स्थिर काष्ठा sshkey_impl sshkey_ecdsa_nistp256_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_ecdsa_nistp384_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_ecdsa_nistp521_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_rsa_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_rsa_cert_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_rsa_sha256_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_rsa_sha256_cert_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_rsa_sha512_impl;
बाह्य स्थिर काष्ठा sshkey_impl sshkey_rsa_sha512_cert_impl;
#पूर्ण_अगर /* WITH_OPENSSL */

स्थिर काष्ठा sshkey_impl * स्थिर keyimpls[] = {
	&sshkey_ed25519_impl,
	&sshkey_ed25519_cert_impl,
#अगर_घोषित ENABLE_SK
	&sshkey_ed25519_sk_impl,
	&sshkey_ed25519_sk_cert_impl,
#पूर्ण_अगर
#अगर_घोषित USE_MLDSA
	&sshkey_mldsa44_ed25519_impl,
	&sshkey_mldsa44_ed25519_cert_impl,
#पूर्ण_अगर /* USE_MLDSA */
#अगर_घोषित WITH_OPENSSL
	&sshkey_ecdsa_nistp256_impl,
	&sshkey_ecdsa_nistp256_cert_impl,
	&sshkey_ecdsa_nistp384_impl,
	&sshkey_ecdsa_nistp384_cert_impl,
	&sshkey_ecdsa_nistp521_impl,
	&sshkey_ecdsa_nistp521_cert_impl,
# ifdef ENABLE_SK
	&sshkey_ecdsa_sk_impl,
	&sshkey_ecdsa_sk_cert_impl,
	&sshkey_ecdsa_sk_webauthn_impl,
	&sshkey_ecdsa_sk_webauthn_cert_impl,
# endif /* ENABLE_SK */
	&sshkey_rsa_impl,
	&sshkey_rsa_cert_impl,
	&sshkey_rsa_sha256_impl,
	&sshkey_rsa_sha256_cert_impl,
	&sshkey_rsa_sha512_impl,
	&sshkey_rsa_sha512_cert_impl,
#पूर्ण_अगर /* WITH_OPENSSL */
	शून्य
};

अटल स्थिर काष्ठा sshkey_impl *
sshkey_impl_from_type(पूर्णांक type)
{
	पूर्णांक i;

	क्रम (i = 0; keyimpls[i] != शून्य; i++) {
		अगर (keyimpls[i]->type == type)
			वापस keyimpls[i];
	}
	वापस शून्य;
}

अटल स्थिर काष्ठा sshkey_impl *
sshkey_impl_from_type_nid(पूर्णांक type, पूर्णांक nid)
{
	पूर्णांक i;

	क्रम (i = 0; keyimpls[i] != शून्य; i++) {
		अगर (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			वापस keyimpls[i];
	}
	वापस शून्य;
}

अटल स्थिर काष्ठा sshkey_impl *
sshkey_impl_from_कुंजी(स्थिर काष्ठा sshkey *k)
{
	अगर (k == शून्य)
		वापस शून्य;
	वापस sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

स्थिर अक्षर *
sshkey_type(स्थिर काष्ठा sshkey *k)
{
	स्थिर काष्ठा sshkey_impl *impl;

	अगर ((impl = sshkey_impl_from_कुंजी(k)) == शून्य)
		वापस "unknown";
	वापस impl->shortname;
}

अटल स्थिर अक्षर *
sshkey_ssh_name_from_type_nid(पूर्णांक type, पूर्णांक nid)
{
	स्थिर काष्ठा sshkey_impl *impl;

	अगर ((impl = sshkey_impl_from_type_nid(type, nid)) == शून्य)
		वापस "ssh-unknown";
	वापस impl->name;
}

पूर्णांक
sshkey_type_is_cert(पूर्णांक type)
{
	स्थिर काष्ठा sshkey_impl *impl;

	अगर ((impl = sshkey_impl_from_type(type)) == शून्य)
		वापस 0;
	वापस impl->cert;
}

स्थिर अक्षर *
sshkey_ssh_name(स्थिर काष्ठा sshkey *k)
{
	वापस sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

स्थिर अक्षर *
sshkey_ssh_name_plain(स्थिर काष्ठा sshkey *k)
{
	वापस sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

अटल पूर्णांक
type_from_name(स्थिर अक्षर *name, पूर्णांक allow_short)
{
	पूर्णांक i;
	स्थिर काष्ठा sshkey_impl *impl;

	क्रम (i = 0; keyimpls[i] != शून्य; i++) {
		impl = keyimpls[i];
		अगर (impl->name != शून्य && म_भेद(name, impl->name) == 0)
			वापस impl->type;
		/* Only allow shortname matches for plain key types */
		अगर (allow_short && !impl->cert && impl->shortname != शून्य &&
		    strcasecmp(impl->shortname, name) == 0)
			वापस impl->type;
	}
	वापस कुंजी_UNSPEC;
}

पूर्णांक
sshkey_type_from_name(स्थिर अक्षर *name)
{
	वापस type_from_name(name, 0);
}

पूर्णांक
sshkey_type_from_shortname(स्थिर अक्षर *name)
{
	वापस type_from_name(name, 1);
}

अटल पूर्णांक
कुंजी_type_is_ecdsa_variant(पूर्णांक type)
{
	चयन (type) {
	हाल कुंजी_ECDSA:
	हाल कुंजी_ECDSA_CERT:
	हाल कुंजी_ECDSA_SK:
	हाल कुंजी_ECDSA_SK_CERT:
		वापस 1;
	}
	वापस 0;
}

पूर्णांक
sshkey_ecdsa_nid_from_name(स्थिर अक्षर *name)
{
	पूर्णांक i;

	क्रम (i = 0; keyimpls[i] != शून्य; i++) {
		अगर (!कुंजी_type_is_ecdsa_variant(keyimpls[i]->type))
			जारी;
		अगर (keyimpls[i]->name != शून्य &&
		    म_भेद(name, keyimpls[i]->name) == 0)
			वापस keyimpls[i]->nid;
	}
	वापस -1;
}

पूर्णांक
sshkey_match_keyname_to_sigalgs(स्थिर अक्षर *keyname, स्थिर अक्षर *sigalgs)
{
	पूर्णांक ktype;

	अगर (sigalgs == शून्य || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == कुंजी_UNSPEC)
		वापस 0;
	अन्यथा अगर (ktype == कुंजी_RSA) {
		वापस match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} अन्यथा अगर (ktype == कुंजी_RSA_CERT) {
		वापस match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} अन्यथा अगर (ktype == कुंजी_ECDSA_SK) {
		वापस match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} अन्यथा अगर (ktype == कुंजी_ECDSA_SK_CERT) {
		वापस match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} अन्यथा
		वापस match_pattern_list(keyname, sigalgs, 0) == 1;
}

अक्षर *
sshkey_alg_list(पूर्णांक certs_only, पूर्णांक plain_only, पूर्णांक include_sigonly, अक्षर sep)
{
	अक्षर *ret = शून्य;
	माप_प्रकार i;
	स्थिर काष्ठा sshkey_impl *impl;
	अक्षर sep_str[2] = {sep, '\0'};

	क्रम (i = 0; keyimpls[i] != शून्य; i++) {
		impl = keyimpls[i];
		अगर (impl->name == शून्य)
			जारी;
		अगर (!include_sigonly && impl->sigonly)
			जारी;
		अगर ((certs_only && !impl->cert) || (plain_only && impl->cert))
			जारी;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	वापस ret;
}

पूर्णांक
sshkey_names_valid2(स्थिर अक्षर *names, पूर्णांक allow_wildcard, पूर्णांक plain_only)
{
	अक्षर *s, *cp, *p;
	स्थिर काष्ठा sshkey_impl *impl;
	पूर्णांक i, type;

	अगर (names == शून्य || म_भेद(names, "") == 0)
		वापस 0;
	अगर ((s = cp = strdup(names)) == शून्य)
		वापस 0;
	क्रम ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		अगर (type == कुंजी_UNSPEC) {
			अगर (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = शून्य;
				क्रम (i = 0; keyimpls[i] != शून्य; i++) {
					अगर (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						अवरोध;
					}
				}
				अगर (impl != शून्य)
					जारी;
			}
			मुक्त(s);
			वापस 0;
		} अन्यथा अगर (plain_only && sshkey_type_is_cert(type)) {
			मुक्त(s);
			वापस 0;
		}
	}
	मुक्त(s);
	वापस 1;
}

u_int
sshkey_आकार(स्थिर काष्ठा sshkey *k)
{
	स्थिर काष्ठा sshkey_impl *impl;

	अगर ((impl = sshkey_impl_from_कुंजी(k)) == शून्य)
		वापस 0;
	अगर (impl->funcs->आकार != शून्य)
		वापस impl->funcs->आकार(k);
	वापस impl->keybits;
}

अटल पूर्णांक
sshkey_type_is_valid_ca(पूर्णांक type)
{
	स्थिर काष्ठा sshkey_impl *impl;

	अगर ((impl = sshkey_impl_from_type(type)) == शून्य)
		वापस 0;
	/* All non-certificate types may act as CAs */
	वापस !impl->cert;
}

पूर्णांक
sshkey_is_cert(स्थिर काष्ठा sshkey *k)
{
	अगर (k == शून्य)
		वापस 0;
	वापस sshkey_type_is_cert(k->type);
}

पूर्णांक
sshkey_is_sk(स्थिर काष्ठा sshkey *k)
{
	अगर (k == शून्य)
		वापस 0;
	चयन (sshkey_type_plain(k->type)) {
	हाल कुंजी_ECDSA_SK:
	हाल कुंजी_ED25519_SK:
		वापस 1;
	शेष:
		वापस 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
पूर्णांक
sshkey_type_plain(पूर्णांक type)
{
	चयन (type) {
	हाल कुंजी_RSA_CERT:
		वापस कुंजी_RSA;
	हाल कुंजी_ECDSA_CERT:
		वापस कुंजी_ECDSA;
	हाल कुंजी_ECDSA_SK_CERT:
		वापस कुंजी_ECDSA_SK;
	हाल कुंजी_ED25519_CERT:
		वापस कुंजी_ED25519;
	हाल कुंजी_MLDSA44_ED25519_CERT:
		वापस कुंजी_MLDSA44_ED25519;
	हाल कुंजी_ED25519_SK_CERT:
		वापस कुंजी_ED25519_SK;
	शेष:
		वापस type;
	}
}

/* Return the cert equivalent to a plain key type */
अटल पूर्णांक
sshkey_type_certified(पूर्णांक type)
{
	चयन (type) {
	हाल कुंजी_RSA:
		वापस कुंजी_RSA_CERT;
	हाल कुंजी_ECDSA:
		वापस कुंजी_ECDSA_CERT;
	हाल कुंजी_ECDSA_SK:
		वापस कुंजी_ECDSA_SK_CERT;
	हाल कुंजी_ED25519:
		वापस कुंजी_ED25519_CERT;
	हाल कुंजी_MLDSA44_ED25519:
		वापस कुंजी_MLDSA44_ED25519_CERT;
	हाल कुंजी_ED25519_SK:
		वापस कुंजी_ED25519_SK_CERT;
	शेष:
		वापस -1;
	}
}

#अगर_घोषित WITH_OPENSSL
अटल स्थिर EVP_MD *
ssh_digest_to_md(पूर्णांक hash_alg)
{
	चयन (hash_alg) {
	हाल SSH_DIGEST_SHA1:
		वापस EVP_sha1();
	हाल SSH_DIGEST_SHA256:
		वापस EVP_sha256();
	हाल SSH_DIGEST_SHA384:
		वापस EVP_sha384();
	हाल SSH_DIGEST_SHA512:
		वापस EVP_sha512();
	}
	वापस शून्य;
}

पूर्णांक
sshkey_pkey_digest_sign(EVP_PKEY *pkey, पूर्णांक hash_alg, u_char **sigp,
    माप_प्रकार *lenp, स्थिर u_char *तथ्य, माप_प्रकार datalen)
{
	EVP_MD_CTX *ctx = शून्य;
	u_char *sig = शून्य;
	पूर्णांक ret;
	माप_प्रकार slen;
	स्थिर EVP_MD *evpmd;

	*sigp = शून्य;
	*lenp = 0;

	slen = EVP_PKEY_आकार(pkey);
	अगर (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;

	अगर ((sig = दो_स्मृति(slen)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;

	अगर ((ctx = EVP_MD_CTX_new()) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (EVP_DigestSignInit(ctx, शून्य, evpmd, शून्य, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, तथ्य, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = शून्य;
	ret = 0;

 out:
	EVP_MD_CTX_free(ctx);
	मुक्त(sig);
	वापस ret;
}

पूर्णांक
sshkey_pkey_digest_verify(EVP_PKEY *pkey, पूर्णांक hash_alg, स्थिर u_char *तथ्य,
    माप_प्रकार datalen, u_char *sigbuf, माप_प्रकार siglen)
{
	EVP_MD_CTX *ctx = शून्य;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;
	स्थिर EVP_MD *evpmd;

	अगर ((evpmd = ssh_digest_to_md(hash_alg)) == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((ctx = EVP_MD_CTX_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर (EVP_DigestVerifyInit(ctx, शून्य, evpmd, शून्य, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	चयन (EVP_DigestVerify(ctx, sigbuf, siglen, तथ्य, datalen)) {
	हाल 1:
		ret = 0;
		अवरोध;
	हाल 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		अवरोध;
	शेष:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		अवरोध;
	}

 out:
	EVP_MD_CTX_free(ctx);
	वापस ret;
}

/* XXX: these are really begging for a table-driven approach */
पूर्णांक
sshkey_curve_name_to_nid(स्थिर अक्षर *name)
{
	अगर (म_भेद(name, "nistp256") == 0)
		वापस NID_X9_62_prime256v1;
	अन्यथा अगर (म_भेद(name, "nistp384") == 0)
		वापस NID_secp384r1;
	अन्यथा अगर (म_भेद(name, "nistp521") == 0)
		वापस NID_secp521r1;
	अन्यथा
		वापस -1;
}

u_int
sshkey_curve_nid_to_bits(पूर्णांक nid)
{
	चयन (nid) {
	हाल NID_X9_62_prime256v1:
		वापस 256;
	हाल NID_secp384r1:
		वापस 384;
	हाल NID_secp521r1:
		वापस 521;
	शेष:
		वापस 0;
	}
}

पूर्णांक
sshkey_ecdsa_bits_to_nid(पूर्णांक bits)
{
	चयन (bits) {
	हाल 256:
		वापस NID_X9_62_prime256v1;
	हाल 384:
		वापस NID_secp384r1;
	हाल 521:
		वापस NID_secp521r1;
	शेष:
		वापस -1;
	}
}

स्थिर अक्षर *
sshkey_curve_nid_to_name(पूर्णांक nid)
{
	चयन (nid) {
	हाल NID_X9_62_prime256v1:
		वापस "nistp256";
	हाल NID_secp384r1:
		वापस "nistp384";
	हाल NID_secp521r1:
		वापस "nistp521";
	शेष:
		वापस शून्य;
	}
}

पूर्णांक
sshkey_ec_nid_to_hash_alg(पूर्णांक nid)
{
	पूर्णांक kbits = sshkey_curve_nid_to_bits(nid);

	अगर (kbits <= 0)
		वापस -1;

	/* RFC5656 section 6.2.1 */
	अगर (kbits <= 256)
		वापस SSH_DIGEST_SHA256;
	अन्यथा अगर (kbits <= 384)
		वापस SSH_DIGEST_SHA384;
	अन्यथा
		वापस SSH_DIGEST_SHA512;
}
#पूर्ण_अगर /* WITH_OPENSSL */

अटल व्योम
cert_free(काष्ठा sshkey_cert *cert)
{
	u_int i;

	अगर (cert == शून्य)
		वापस;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	मुक्त(cert->कुंजी_id);
	क्रम (i = 0; i < cert->nprincipals; i++)
		मुक्त(cert->principals[i]);
	मुक्त(cert->principals);
	sshkey_free(cert->signature_कुंजी);
	मुक्त(cert->signature_type);
	freezero(cert, माप(*cert));
}

अटल काष्ठा sshkey_cert *
cert_new(व्योम)
{
	काष्ठा sshkey_cert *cert;

	अगर ((cert = सुस्मृति(1, माप(*cert))) == शून्य)
		वापस शून्य;
	अगर ((cert->certblob = sshbuf_new()) == शून्य ||
	    (cert->critical = sshbuf_new()) == शून्य ||
	    (cert->extensions = sshbuf_new()) == शून्य) {
		cert_free(cert);
		वापस शून्य;
	}
	cert->कुंजी_id = शून्य;
	cert->principals = शून्य;
	cert->signature_कुंजी = शून्य;
	cert->signature_type = शून्य;
	वापस cert;
}

काष्ठा sshkey *
sshkey_new(पूर्णांक type)
{
	काष्ठा sshkey *k;
	स्थिर काष्ठा sshkey_impl *impl = शून्य;

	अगर (type != कुंजी_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == शून्य)
		वापस शून्य;

	/* All non-certificate types may act as CAs */
	अगर ((k = सुस्मृति(1, माप(*k))) == शून्य)
		वापस शून्य;
	k->type = type;
	k->ecdsa_nid = -1;
	अगर (impl != शून्य && impl->funcs->alloc != शून्य) {
		अगर (impl->funcs->alloc(k) != 0) {
			मुक्त(k);
			वापस शून्य;
		}
	}
	अगर (sshkey_is_cert(k)) {
		अगर ((k->cert = cert_new()) == शून्य) {
			sshkey_free(k);
			वापस शून्य;
		}
	}

	वापस k;
}

/* Frees common FIDO fields */
व्योम
sshkey_sk_cleanup(काष्ठा sshkey *k)
{
	मुक्त(k->sk_application);
	sshbuf_free(k->sk_कुंजी_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = शून्य;
	k->sk_कुंजी_handle = k->sk_reserved = शून्य;
}

#अगर defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#या_अगर defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#अन्यथा
# define PREKEY_MMAP_FLAG	0
#पूर्ण_अगर

अटल पूर्णांक
sshkey_prekey_alloc(u_char **prekeyp, माप_प्रकार len)
{
#अगर defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = शून्य;
	अगर ((prekey = mmap(शून्य, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		वापस SSH_ERR_SYSTEM_ERROR;
#अगर defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(व्योम)madvise(prekey, len, MADV_DONTDUMP);
#पूर्ण_अगर
	*prekeyp = prekey;
#अन्यथा
	*prekeyp = सुस्मृति(1, len);
#पूर्ण_अगर /* HAVE_MMAP et al */
	वापस 0;
}

अटल व्योम
sshkey_prekey_free(व्योम *prekey, माप_प्रकार len)
{
#अगर defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	अगर (prekey == शून्य)
		वापस;
	munmap(prekey, len);
#अन्यथा
	मुक्त(prekey);
#पूर्ण_अगर /* HAVE_MMAP et al */
}

अटल व्योम
sshkey_free_contents(काष्ठा sshkey *k)
{
	स्थिर काष्ठा sshkey_impl *impl;

	अगर (k == शून्य)
		वापस;
	अगर ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_कुंजी_free(k);
	अगर ((impl = sshkey_impl_from_type(k->type)) != शून्य &&
	    impl->funcs->cleanup != शून्य)
		impl->funcs->cleanup(k);
	अगर (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_private, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

व्योम
sshkey_free(काष्ठा sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, माप(*k));
}

अटल पूर्णांक
cert_compare(काष्ठा sshkey_cert *a, काष्ठा sshkey_cert *b)
{
	अगर (a == शून्य && b == शून्य)
		वापस 1;
	अगर (a == शून्य || b == शून्य)
		वापस 0;
	अगर (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		वापस 0;
	अगर (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		वापस 0;
	वापस 1;
}

/* Compares FIDO-specific pubkey fields only */
पूर्णांक
sshkey_sk_fields_equal(स्थिर काष्ठा sshkey *a, स्थिर काष्ठा sshkey *b)
{
	अगर (a->sk_application == शून्य || b->sk_application == शून्य)
		वापस 0;
	अगर (म_भेद(a->sk_application, b->sk_application) != 0)
		वापस 0;
	वापस 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
पूर्णांक
sshkey_equal_public(स्थिर काष्ठा sshkey *a, स्थिर काष्ठा sshkey *b)
{
	स्थिर काष्ठा sshkey_impl *impl;

	अगर (a == शून्य || b == शून्य ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		वापस 0;
	अगर ((impl = sshkey_impl_from_type(a->type)) == शून्य)
		वापस 0;
	वापस impl->funcs->equal(a, b);
}

पूर्णांक
sshkey_equal(स्थिर काष्ठा sshkey *a, स्थिर काष्ठा sshkey *b)
{
	अगर (a == शून्य || b == शून्य || a->type != b->type)
		वापस 0;
	अगर (sshkey_is_cert(a)) {
		अगर (!cert_compare(a->cert, b->cert))
			वापस 0;
	}
	वापस sshkey_equal_public(a, b);
}


/* Serialise common FIDO key parts */
पूर्णांक
sshkey_serialize_sk(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b)
{
	पूर्णांक r;

	अगर ((r = sshbuf_put_cstring(b, कुंजी->sk_application)) != 0)
		वापस r;

	वापस 0;
}

अटल पूर्णांक
to_blob_buf(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b, पूर्णांक force_plain,
  क्रमागत sshkey_serialize_rep opts)
{
	पूर्णांक type, ret = SSH_ERR_INTERNAL_ERROR;
	स्थिर अक्षर *typename;
	स्थिर काष्ठा sshkey_impl *impl;

	अगर (कुंजी == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(कुंजी->type) : कुंजी->type;

	अगर (sshkey_type_is_cert(type)) {
		अगर (कुंजी->cert == शून्य)
			वापस SSH_ERR_EXPECTED_CERT;
		अगर (sshbuf_len(कुंजी->cert->certblob) == 0)
			वापस SSH_ERR_कुंजी_LACKS_CERTBLOB;
		/* Use the existing blob */
		अगर ((ret = sshbuf_putb(b, कुंजी->cert->certblob)) != 0)
			वापस ret;
		वापस 0;
	}
	अगर ((impl = sshkey_impl_from_type(type)) == शून्य)
		वापस SSH_ERR_कुंजी_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, कुंजी->ecdsa_nid);
	अगर ((ret = sshbuf_put_cstring(b, typename)) != 0)
		वापस ret;
	वापस impl->funcs->serialize_public(कुंजी, b, opts);
}

पूर्णांक
sshkey_putb(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b)
{
	वापस to_blob_buf(कुंजी, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

अटल पूर्णांक
sshkey_puts_opts_internal(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b,
    क्रमागत sshkey_serialize_rep opts, पूर्णांक force_plain)
{
	काष्ठा sshbuf *tmp;
	पूर्णांक r;

	अगर ((tmp = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(कुंजी, tmp, force_plain, opts);
	अगर (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	वापस r;
}

पूर्णांक
sshkey_puts(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b)
{
	वापस sshkey_puts_opts_internal(कुंजी, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

पूर्णांक
sshkey_putb_plain(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b)
{
	वापस to_blob_buf(कुंजी, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

पूर्णांक
sshkey_puts_plain(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b)
{
	वापस sshkey_puts_opts_internal(कुंजी, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

अटल पूर्णांक
to_blob(स्थिर काष्ठा sshkey *कुंजी, u_char **blobp, माप_प्रकार *lenp, पूर्णांक force_plain,
    क्रमागत sshkey_serialize_rep opts)
{
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;
	माप_प्रकार len;
	काष्ठा sshbuf *b = शून्य;

	अगर (lenp != शून्य)
		*lenp = 0;
	अगर (blobp != शून्य)
		*blobp = शून्य;
	अगर ((b = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((ret = to_blob_buf(कुंजी, b, force_plain, opts)) != 0)
		जाओ out;
	len = sshbuf_len(b);
	अगर (lenp != शून्य)
		*lenp = len;
	अगर (blobp != शून्य) {
		अगर ((*blobp = दो_स्मृति(len)) == शून्य) {
			ret = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		स_नकल(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	वापस ret;
}

पूर्णांक
sshkey_to_blob(स्थिर काष्ठा sshkey *कुंजी, u_char **blobp, माप_प्रकार *lenp)
{
	वापस to_blob(कुंजी, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

पूर्णांक
sshkey_plain_to_blob(स्थिर काष्ठा sshkey *कुंजी, u_char **blobp, माप_प्रकार *lenp)
{
	वापस to_blob(कुंजी, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

पूर्णांक
sshkey_fingerprint_raw(स्थिर काष्ठा sshkey *k, पूर्णांक dgst_alg,
    u_char **retp, माप_प्रकार *lenp)
{
	u_char *blob = शून्य, *ret = शून्य;
	माप_प्रकार blob_len = 0;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर (retp != शून्य)
		*retp = शून्य;
	अगर (lenp != शून्य)
		*lenp = 0;
	अगर (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	अगर ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		जाओ out;
	अगर ((ret = सुस्मृति(1, SSH_DIGEST_MAX_लंबाई)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_लंबाई)) != 0)
		जाओ out;
	/* success */
	अगर (retp != शून्य) {
		*retp = ret;
		ret = शून्य;
	}
	अगर (lenp != शून्य)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	मुक्त(ret);
	अगर (blob != शून्य)
		freezero(blob, blob_len);
	वापस r;
}

अटल अक्षर *
fingerprint_b64(स्थिर अक्षर *alg, u_char *dgst_raw, माप_प्रकार dgst_raw_len)
{
	अक्षर *ret;
	माप_प्रकार plen = म_माप(alg) + 1;
	माप_प्रकार rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	अगर (dgst_raw_len > 65536 || (ret = सुस्मृति(1, rlen)) == शून्य)
		वापस शून्य;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	अगर (dgst_raw_len == 0)
		वापस ret;
	अगर (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		वापस शून्य;
	}
	/* Trim padding characters from end */
	ret[म_खोज(ret, "=")] = '\0';
	वापस ret;
}

अटल अक्षर *
fingerprint_hex(स्थिर अक्षर *alg, u_char *dgst_raw, माप_प्रकार dgst_raw_len)
{
	अक्षर *retval, hex[5];
	माप_प्रकार i, rlen = dgst_raw_len * 3 + म_माप(alg) + 2;

	अगर (dgst_raw_len > 65536 || (retval = सुस्मृति(1, rlen)) == शून्य)
		वापस शून्य;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	क्रम (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, माप(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	वापस retval;
}

अटल अक्षर *
fingerprint_bubblebabble(u_char *dgst_raw, माप_प्रकार dgst_raw_len)
{
	अक्षर vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	अक्षर consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	अक्षर *retval;

	rounds = (dgst_raw_len / 2) + 1;
	अगर ((retval = सुस्मृति(rounds, 6)) == शून्य)
		वापस शून्य;
	retval[j++] = 'x';
	क्रम (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		अगर ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			अगर ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} अन्यथा {
			idx0 = seed % 6;
			idx1 = 16;
			idx2 = seed / 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
		}
	}
	retval[j++] = 'x';
	retval[j++] = '\0';
	वापस retval;
}

/*
 * Draw an ASCII-Art representing the fingerprint so human brain can
 * profit from its built-in pattern recognition ability.
 * This technique is called "random art" and can be found in some
 * scientific publications like this original paper:
 *
 * "Hash Visualization: a New Technique to improve Real-World Security",
 * Perrig A. and Song D., 1999, International Workshop on Cryptographic
 * Techniques and E-Commerce (CrypTEC '99)
 * sparrow.ece.cmu.edu/~adrian/projects/validation/validation.pdf
 *
 * The subject came up in a talk by Dan Kaminsky, too.
 *
 * If you see the picture is different, the key is different.
 * If the picture looks the same, you still know nothing.
 *
 * The algorithm used here is a worm crawling over a discrete plane,
 * leaving a trace (augmenting the field) everywhere it goes.
 * Movement is taken from dgst_raw 2bit-wise.  Bumping into walls
 * makes the respective movement vector be ignored for this turn.
 * Graphs are not unambiguous, because circles in graphs can be
 * walked in either direction.
 */

/*
 * Field sizes for the random art.  Have to be odd, so the starting point
 * can be in the exact middle of the picture, and FLDBASE should be >=8 .
 * Else pictures would be too dense, and drawing the frame would
 * fail, too, because the key type would not fit in anymore.
 */
#घोषणा	FLDBASE		8
#घोषणा	FLDSIZE_Y	(FLDBASE + 1)
#घोषणा	FLDSIZE_X	(FLDBASE * 2 + 1)
अटल अक्षर *
fingerprint_randomart(स्थिर अक्षर *alg, u_char *dgst_raw, माप_प्रकार dgst_raw_len,
    स्थिर काष्ठा sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	अक्षर	*augmentation_string = " .o+=*BOX@%&#/^SE";
	अक्षर	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	माप_प्रकार	 i, tlen, hlen;
	u_int	 b;
	पूर्णांक	 x, y, r;
	माप_प्रकार	 len = म_माप(augmentation_string) - 1;

	अगर ((retval = सुस्मृति((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == शून्य)
		वापस शून्य;

	/* initialize field */
	स_रखो(field, 0, FLDSIZE_X * FLDSIZE_Y * माप(अक्षर));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	क्रम (i = 0; i < dgst_raw_len; i++) {
		पूर्णांक निवेश;
		/* each byte conveys four 2-bit move commands */
		निवेश = dgst_raw[i];
		क्रम (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (निवेश & 0x1) ? 1 : -1;
			y += (निवेश & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			अगर (field[x][y] < len - 2)
				field[x][y]++;
			निवेश = निवेश >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, माप(title), "[%s %u]",
		sshkey_type(k), sshkey_आकार(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	अगर (r < 0 || r > (पूर्णांक)माप(title))
		r = snprintf(title, माप(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : म_माप(title);

	/* assemble hash ID. */
	r = snprintf(hash, माप(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : म_माप(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	क्रम (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	स_नकल(p, title, tlen);
	p += tlen;
	क्रम (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	क्रम (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		क्रम (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	क्रम (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	स_नकल(p, hash, hlen);
	p += hlen;
	क्रम (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	वापस retval;
}

अक्षर *
sshkey_fingerprint(स्थिर काष्ठा sshkey *k, पूर्णांक dgst_alg,
    क्रमागत sshkey_fp_rep dgst_rep)
{
	अक्षर *retval = शून्य;
	u_char *dgst_raw;
	माप_प्रकार dgst_raw_len;

	अगर (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		वापस शून्य;
	चयन (dgst_rep) {
	हाल SSH_FP_DEFAULT:
		अगर (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} अन्यथा {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		अवरोध;
	हाल SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		अवरोध;
	हाल SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		अवरोध;
	हाल SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		अवरोध;
	हाल SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		अवरोध;
	शेष:
		freezero(dgst_raw, dgst_raw_len);
		वापस शून्य;
	}
	freezero(dgst_raw, dgst_raw_len);
	वापस retval;
}

अटल पूर्णांक
peek_type_nid(स्थिर अक्षर *s, माप_प्रकार l, पूर्णांक *nid)
{
	स्थिर काष्ठा sshkey_impl *impl;
	पूर्णांक i;

	क्रम (i = 0; keyimpls[i] != शून्य; i++) {
		impl = keyimpls[i];
		अगर (impl->name == शून्य || म_माप(impl->name) != l)
			जारी;
		अगर (स_भेद(s, impl->name, l) == 0) {
			*nid = -1;
			अगर (कुंजी_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			वापस impl->type;
		}
	}
	वापस कुंजी_UNSPEC;
}

/* XXX this can now be made const char * */
पूर्णांक
sshkey_read(काष्ठा sshkey *ret, अक्षर **cpp)
{
	काष्ठा sshkey *k;
	अक्षर *cp, *blobcopy;
	माप_प्रकार space;
	पूर्णांक r, type, curve_nid = -1;
	काष्ठा sshbuf *blob;

	अगर (ret == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (ret->type != कुंजी_UNSPEC && sshkey_impl_from_type(ret->type) == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
	space = म_खोज(cp, " \t");
	अगर (space == म_माप(cp))
		वापस SSH_ERR_INVALID_FORMAT;
	अगर ((type = peek_type_nid(cp, space, &curve_nid)) == कुंजी_UNSPEC)
		वापस SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	क्रम (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	अगर (*cp == '\0')
		वापस SSH_ERR_INVALID_FORMAT;
	अगर (ret->type != कुंजी_UNSPEC && ret->type != type)
		वापस SSH_ERR_कुंजी_TYPE_MISMATCH;
	अगर ((blob = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = म_खोज(cp, " \t");
	अगर ((blobcopy = strndup(cp, space)) == शून्य) {
		sshbuf_free(blob);
		वापस SSH_ERR_ALLOC_FAIL;
	}
	अगर ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		मुक्त(blobcopy);
		sshbuf_free(blob);
		वापस r;
	}
	मुक्त(blobcopy);
	अगर ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		वापस r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	क्रम (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	अगर (k->type != type) {
		sshkey_free(k);
		वापस SSH_ERR_कुंजी_TYPE_MISMATCH;
	}
	अगर (कुंजी_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		वापस SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, माप(*k));

	/* success */
	*cpp = cp;
	वापस 0;
}

पूर्णांक
sshkey_to_base64(स्थिर काष्ठा sshkey *कुंजी, अक्षर **b64p)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	काष्ठा sshbuf *b = शून्य;
	अक्षर *uu = शून्य;

	अगर (b64p != शून्य)
		*b64p = शून्य;
	अगर ((b = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshkey_putb(कुंजी, b)) != 0)
		जाओ out;
	अगर ((uu = sshbuf_dtob64_string(b, 0)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	/* Success */
	अगर (b64p != शून्य) {
		*b64p = uu;
		uu = शून्य;
	}
	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(uu);
	वापस r;
}

पूर्णांक
sshkey_format_text(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	अक्षर *uu = शून्य;

	अगर ((r = sshkey_to_base64(कुंजी, &uu)) != 0)
		जाओ out;
	अगर ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(कुंजी), uu)) != 0)
		जाओ out;
	r = 0;
 out:
	मुक्त(uu);
	वापस r;
}

पूर्णांक
sshkey_write(स्थिर काष्ठा sshkey *कुंजी, खाता *f)
{
	काष्ठा sshbuf *b = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर ((b = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshkey_format_text(कुंजी, b)) != 0)
		जाओ out;
	अगर (ख_डालो(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		अगर (ख_पूर्ण(f))
			त्रुटि_सं = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		जाओ out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	वापस r;
}

स्थिर अक्षर *
sshkey_cert_type(स्थिर काष्ठा sshkey *k)
{
	चयन (k->cert->type) {
	हाल SSH2_CERT_TYPE_USER:
		वापस "user";
	हाल SSH2_CERT_TYPE_HOST:
		वापस "host";
	शेष:
		वापस "unknown";
	}
}

पूर्णांक
sshkey_check_rsa_लंबाई(स्थिर काष्ठा sshkey *k, पूर्णांक min_आकार)
{
#अगर_घोषित WITH_OPENSSL
	पूर्णांक nbits;

	अगर (k == शून्य || k->pkey == शून्य ||
	    (k->type != कुंजी_RSA && k->type != कुंजी_RSA_CERT))
		वापस 0;
	nbits = EVP_PKEY_bits(k->pkey);
	अगर (nbits < SSH_RSA_MINIMUM_MODULUS_आकार ||
	    (min_आकार > 0 && nbits < min_आकार))
		वापस SSH_ERR_कुंजी_लंबाई;
#पूर्ण_अगर /* WITH_OPENSSL */
	वापस 0;
}

#अगर_घोषित WITH_OPENSSL
पूर्णांक
sshkey_ecdsa_कुंजी_to_nid(स्थिर EC_कुंजी *k)
{
	स्थिर EC_GROUP *g;
	पूर्णांक nid;

	अगर (k == शून्य || (g = EC_कुंजी_get0_group(k)) == शून्य)
		वापस -1;
	अगर ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		वापस -1;
	वापस nid;
}

पूर्णांक
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	वापस sshkey_ecdsa_कुंजी_to_nid(EVP_PKEY_get0_EC_कुंजी(pkey));
}
#पूर्ण_अगर /* WITH_OPENSSL */

पूर्णांक
sshkey_generate(पूर्णांक type, u_int bits, काष्ठा sshkey **keyp)
{
	काष्ठा sshkey *k;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;
	स्थिर काष्ठा sshkey_impl *impl;

	अगर (keyp == शून्य || sshkey_type_is_cert(type))
		वापस SSH_ERR_INVALID_ARGUMENT;
	*keyp = शून्य;
	अगर ((impl = sshkey_impl_from_type(type)) == शून्य)
		वापस SSH_ERR_कुंजी_TYPE_UNKNOWN;
	अगर (impl->funcs->generate == शून्य)
		वापस SSH_ERR_FEATURE_UNSUPPORTED;
	अगर ((k = sshkey_new(कुंजी_UNSPEC)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	k->type = type;
	अगर ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		वापस ret;
	}
	/* success */
	*keyp = k;
	वापस 0;
}

पूर्णांक
sshkey_cert_copy(स्थिर काष्ठा sshkey *from_कुंजी, काष्ठा sshkey *to_कुंजी)
{
	u_int i;
	स्थिर काष्ठा sshkey_cert *from;
	काष्ठा sshkey_cert *to;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर (to_कुंजी == शून्य || (from = from_कुंजी->cert) == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;

	अगर ((to = cert_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;

	अगर ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		जाओ out;

	to->serial = from->serial;
	to->type = from->type;
	अगर (from->कुंजी_id == शून्य)
		to->कुंजी_id = शून्य;
	अन्यथा अगर ((to->कुंजी_id = strdup(from->कुंजी_id)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	अगर (from->signature_कुंजी == शून्य)
		to->signature_कुंजी = शून्य;
	अन्यथा अगर ((r = sshkey_from_private(from->signature_कुंजी,
	    &to->signature_कुंजी)) != 0)
		जाओ out;
	अगर (from->signature_type != शून्य &&
	    (to->signature_type = strdup(from->signature_type)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	अगर (from->nprincipals > 0) {
		अगर ((to->principals = सुस्मृति(from->nprincipals,
		    माप(*to->principals))) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		क्रम (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			अगर (to->principals[i] == शून्य) {
				to->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				जाओ out;
			}
		}
	}
	to->nprincipals = from->nprincipals;

	/* success */
	cert_free(to_कुंजी->cert);
	to_कुंजी->cert = to;
	to = शून्य;
	r = 0;
 out:
	cert_free(to);
	वापस r;
}

पूर्णांक
sshkey_copy_public_sk(स्थिर काष्ठा sshkey *from, काष्ठा sshkey *to)
{
	/* Append security-key application string */
	अगर ((to->sk_application = strdup(from->sk_application)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	वापस 0;
}

पूर्णांक
sshkey_from_private(स्थिर काष्ठा sshkey *k, काष्ठा sshkey **pkp)
{
	काष्ठा sshkey *n = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	स्थिर काष्ठा sshkey_impl *impl;

	*pkp = शून्य;
	अगर ((impl = sshkey_impl_from_कुंजी(k)) == शून्य)
		वापस SSH_ERR_कुंजी_TYPE_UNKNOWN;
	अगर ((n = sshkey_new(k->type)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = impl->funcs->copy_public(k, n)) != 0)
		जाओ out;
	अगर (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		जाओ out;
	/* success */
	*pkp = n;
	n = शून्य;
	r = 0;
 out:
	sshkey_free(n);
	वापस r;
}

पूर्णांक
sshkey_is_shielded(काष्ठा sshkey *k)
{
	वापस k != शून्य && k->shielded_private != शून्य;
}

पूर्णांक
sshkey_shield_private(काष्ठा sshkey *k)
{
	काष्ठा sshbuf *prvbuf = शून्य;
	u_char *prekey = शून्य, *enc = शून्य, keyiv[SSH_DIGEST_MAX_लंबाई];
	काष्ठा sshcipher_ctx *cctx = शून्य;
	स्थिर काष्ठा sshcipher *cipher;
	माप_प्रकार i, enclen = 0;
	काष्ठा sshkey *kswap = शून्य, tmp;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

#अगर_घोषित DEBUG_PK
	ख_लिखो(मानक_त्रुटि, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#पूर्ण_अगर
	अगर ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == शून्य) {
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	अगर (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		जाओ out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	अगर ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		जाओ out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	अगर ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_लंबाई)) != 0)
		जाओ out;
#अगर_घोषित DEBUG_PK
	ख_लिखो(मानक_त्रुटि, "%s: key+iv\n", __func__);
	sshbuf_dump_तथ्य(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    मानक_त्रुटि);
#पूर्ण_अगर
	अगर ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		जाओ out;

	/* Serialise and encrypt the private key using the ephemeral key */
	अगर ((prvbuf = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		जाओ out;
	अगर ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		जाओ out;
	/* pad to cipher blocksize */
	i = 0;
	जबतक (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		अगर ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			जाओ out;
	}
#अगर_घोषित DEBUG_PK
	ख_लिखो(मानक_त्रुटि, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, मानक_त्रुटि);
#पूर्ण_अगर
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	अगर ((enc = दो_स्मृति(enclen)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		जाओ out;
#अगर_घोषित DEBUG_PK
	ख_लिखो(मानक_त्रुटि, "%s: encrypted\n", __func__);
	sshbuf_dump_तथ्य(enc, enclen, मानक_त्रुटि);
#पूर्ण_अगर

	/* Make a scrubbed, public-only copy of our private key argument */
	अगर ((r = sshkey_from_private(k, &kswap)) != 0)
		जाओ out;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_private = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = शून्य; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 out:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, माप(keyiv));
	explicit_bzero(&tmp, माप(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	वापस r;
}

/* Check deterministic padding after private key */
अटल पूर्णांक
private2_check_padding(काष्ठा sshbuf *decrypted)
{
	u_char pad;
	माप_प्रकार i;
	पूर्णांक r;

	i = 0;
	जबतक (sshbuf_len(decrypted)) {
		अगर ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			जाओ out;
		अगर (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, माप(pad));
	explicit_bzero(&i, माप(i));
	वापस r;
}

पूर्णांक
sshkey_unshield_private(काष्ठा sshkey *k)
{
	काष्ठा sshbuf *prvbuf = शून्य;
	u_char *cp, keyiv[SSH_DIGEST_MAX_लंबाई];
	काष्ठा sshcipher_ctx *cctx = शून्य;
	स्थिर काष्ठा sshcipher *cipher;
	काष्ठा sshkey *kswap = शून्य, tmp;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

#अगर_घोषित DEBUG_PK
	ख_लिखो(मानक_त्रुटि, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#पूर्ण_अगर
	अगर (!sshkey_is_shielded(k))
		वापस 0; /* nothing to do */

	अगर ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == शून्य) {
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	अगर (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		जाओ out;
	}
	/* check size of shielded key blob */
	अगर (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}

	/* Calculate the ephemeral key from the prekey */
	अगर ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_लंबाई)) != 0)
		जाओ out;
	अगर ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		जाओ out;
#अगर_घोषित DEBUG_PK
	ख_लिखो(मानक_त्रुटि, "%s: key+iv\n", __func__);
	sshbuf_dump_तथ्य(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    मानक_त्रुटि);
#पूर्ण_अगर

	/* Decrypt and parse the shielded private key using the ephemeral key */
	अगर ((prvbuf = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		जाओ out;
	/* decrypt */
#अगर_घोषित DEBUG_PK
	ख_लिखो(मानक_त्रुटि, "%s: encrypted\n", __func__);
	sshbuf_dump_तथ्य(k->shielded_private, k->shielded_len, मानक_त्रुटि);
#पूर्ण_अगर
	अगर ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		जाओ out;
#अगर_घोषित DEBUG_PK
	ख_लिखो(मानक_त्रुटि, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, मानक_त्रुटि);
#पूर्ण_अगर
	/* Parse private key */
	अगर ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		जाओ out;

	अगर ((r = private2_check_padding(prvbuf)) != 0)
		जाओ out;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 out:
	cipher_free(cctx);
	explicit_bzero(keyiv, माप(keyiv));
	explicit_bzero(&tmp, माप(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	वापस r;
}

अटल पूर्णांक
cert_parse(काष्ठा sshbuf *b, काष्ठा sshkey *कुंजी, काष्ठा sshbuf *certbuf,
    स्थिर अक्षर *ca_sigalg_allowlist)
{
	काष्ठा sshbuf *principals = शून्य, *crit = शून्य;
	काष्ठा sshbuf *exts = शून्य, *ca = शून्य;
	u_char *sig = शून्य;
	अक्षर *sigtype = शून्य;
	माप_प्रकार signed_len = 0, slen = 0, kidlen = 0;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	अगर ((ret = sshbuf_putb(कुंजी->cert->certblob, certbuf)) != 0)
		वापस ret;

	/* Parse body of certificate up to signature */
	अगर ((ret = sshbuf_get_u64(b, &कुंजी->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &कुंजी->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &कुंजी->cert->कुंजी_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &कुंजी->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &कुंजी->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, शून्य, शून्य)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(कुंजी->cert->certblob) - sshbuf_len(b);

	अगर ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}

	/* Is this a signature we're prepared to accept? */
	अगर ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (ca_sigalg_allowlist != शून्य &&
	    match_pattern_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		जाओ out;
	}

	/* Parse CA key and check whether we might accept it */
	अगर (sshkey_from_blob_internal(ca, &कुंजी->cert->signature_कुंजी, 0,
	    ca_sigalg_allowlist, शून्य) != 0) {
		ret = SSH_ERR_कुंजी_CERT_INVALID_SIGN_कुंजी;
		जाओ out;
	}
	अगर (!sshkey_type_is_valid_ca(कुंजी->cert->signature_कुंजी->type)) {
		ret = SSH_ERR_कुंजी_CERT_INVALID_SIGN_कुंजी;
		जाओ out;
	}

	अगर (कुंजी->cert->type != SSH2_CERT_TYPE_USER &&
	    कुंजी->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_कुंजी_CERT_UNKNOWN_TYPE;
		जाओ out;
	}

	/* Parse principals section */
	जबतक (sshbuf_len(principals) > 0) {
		अक्षर *principal = शून्य;
		अक्षर **oprincipals = शून्य;

		अगर (कुंजी->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		अगर ((ret = sshbuf_get_cstring(principals, &principal,
		    शून्य)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		oprincipals = कुंजी->cert->principals;
		कुंजी->cert->principals = recallocarray(कुंजी->cert->principals,
		    कुंजी->cert->nprincipals, कुंजी->cert->nprincipals + 1,
		    माप(*कुंजी->cert->principals));
		अगर (कुंजी->cert->principals == शून्य) {
			मुक्त(principal);
			कुंजी->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		कुंजी->cert->principals[कुंजी->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	अगर ((ret = sshbuf_putb(कुंजी->cert->critical, crit)) != 0 ||
	    (exts != शून्य &&
	    (ret = sshbuf_putb(कुंजी->cert->extensions, exts)) != 0))
		जाओ out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	जबतक (sshbuf_len(crit) != 0) {
		अगर ((ret = sshbuf_get_string_direct(crit, शून्य, शून्य)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, शून्य, शून्य)) != 0) {
			sshbuf_reset(कुंजी->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
	}
	जबतक (exts != शून्य && sshbuf_len(exts) != 0) {
		अगर ((ret = sshbuf_get_string_direct(exts, शून्य, शून्य)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, शून्य, शून्य)) != 0) {
			sshbuf_reset(कुंजी->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
	}

	/* Finally, validate signature */
	अगर ((ret = sshkey_verify(कुंजी->cert->signature_कुंजी, sig, slen,
	    sshbuf_ptr(कुंजी->cert->certblob), signed_len, शून्य, 0, शून्य)) != 0)
		जाओ out;

	/* Success */
	ret = 0;
	कुंजी->cert->signature_type = sigtype;
	sigtype = शून्य;
 out:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	मुक्त(sig);
	मुक्त(sigtype);
	वापस ret;
}

पूर्णांक
sshkey_deserialize_sk(काष्ठा sshbuf *b, काष्ठा sshkey *कुंजी)
{
	/* Parse additional security-key application string */
	अगर (sshbuf_get_cstring(b, &कुंजी->sk_application, शून्य) != 0)
		वापस SSH_ERR_INVALID_FORMAT;
	वापस 0;
}

अटल पूर्णांक
sshkey_from_blob_internal(काष्ठा sshbuf *b, काष्ठा sshkey **keyp,
    पूर्णांक allow_cert, स्थिर अक्षर *alg_allowlist, स्थिर अक्षर *ca_sigalg_allowlist)
{
	पूर्णांक type, ret = SSH_ERR_INTERNAL_ERROR;
	अक्षर *ktype = शून्य;
	काष्ठा sshkey *कुंजी = शून्य;
	काष्ठा sshbuf *copy;
	स्थिर काष्ठा sshkey_impl *impl;

#अगर_घोषित DEBUG_PK /* XXX */
	sshbuf_dump(b, मानक_त्रुटि);
#पूर्ण_अगर
	अगर (keyp != शून्य)
		*keyp = शून्य;
	अगर ((copy = sshbuf_fromb(b)) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (sshbuf_get_cstring(b, &ktype, शून्य) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}

	type = sshkey_type_from_name(ktype);
	अगर (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_कुंजी_CERT_INVALID_SIGN_कुंजी;
		जाओ out;
	}

	अगर (alg_allowlist != शून्य &&
	    !sshkey_match_keyname_to_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_कुंजी_ALG_UNSUPPORTED;
		जाओ out;
	}

	अगर ((impl = sshkey_impl_from_type(type)) == शून्य) {
		ret = SSH_ERR_कुंजी_TYPE_UNKNOWN;
		जाओ out;
	}
	अगर ((कुंजी = sshkey_new(type)) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		अगर (sshbuf_get_string_direct(b, शून्य, शून्य) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
	}
	अगर ((ret = impl->funcs->deserialize_public(ktype, b, कुंजी)) != 0)
		जाओ out;

	/* Parse certificate potion */
	अगर (sshkey_is_cert(कुंजी) &&
	    (ret = cert_parse(b, कुंजी, copy, ca_sigalg_allowlist)) != 0)
		जाओ out;

	अगर (कुंजी != शून्य && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	ret = 0;
	अगर (keyp != शून्य) {
		*keyp = कुंजी;
		कुंजी = शून्य;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(कुंजी);
	मुक्त(ktype);
	वापस ret;
}

पूर्णांक
sshkey_from_blob(स्थिर u_char *blob, माप_प्रकार blen, काष्ठा sshkey **keyp)
{
	काष्ठा sshbuf *b;
	पूर्णांक r;

	अगर ((b = sshbuf_from(blob, blen)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1, शून्य, शून्य);
	sshbuf_free(b);
	वापस r;
}

पूर्णांक
sshkey_fromb(काष्ठा sshbuf *b, काष्ठा sshkey **keyp)
{
	वापस sshkey_from_blob_internal(b, keyp, 1, शून्य, शून्य);
}

पूर्णांक
sshkey_fromb_allowlist(काष्ठा sshbuf *b, काष्ठा sshkey **keyp,
    स्थिर अक्षर *alg_allowlist, स्थिर अक्षर *ca_sigalg_allowlist)
{
	वापस sshkey_from_blob_internal(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

पूर्णांक
sshkey_froms(काष्ठा sshbuf *buf, काष्ठा sshkey **keyp)
{
	काष्ठा sshbuf *b;
	पूर्णांक r;

	अगर ((r = sshbuf_froms(buf, &b)) != 0)
		वापस r;
	r = sshkey_from_blob_internal(b, keyp, 1, शून्य, शून्य);
	sshbuf_free(b);
	वापस r;
}

पूर्णांक
sshkey_get_sigtype(स्थिर u_char *sig, माप_प्रकार siglen, अक्षर **sigtypep)
{
	पूर्णांक r;
	काष्ठा sshbuf *b = शून्य;
	अक्षर *sigtype = शून्य;

	अगर (sigtypep != शून्य)
		*sigtypep = शून्य;
	अगर ((b = sshbuf_from(sig, siglen)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_get_cstring(b, &sigtype, शून्य)) != 0)
		जाओ out;
	/* success */
	अगर (sigtypep != शून्य) {
		*sigtypep = sigtype;
		sigtype = शून्य;
	}
	r = 0;
 out:
	मुक्त(sigtype);
	sshbuf_free(b);
	वापस r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
पूर्णांक
sshkey_check_cert_sigtype(स्थिर काष्ठा sshkey *कुंजी, स्थिर अक्षर *allowed)
{
	अगर (कुंजी == शून्य || allowed == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (!sshkey_type_is_cert(कुंजी->type))
		वापस 0;
	अगर (कुंजी->cert == शून्य || कुंजी->cert->signature_type == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (match_pattern_list(कुंजी->cert->signature_type, allowed, 0) != 1)
		वापस SSH_ERR_SIGN_ALG_UNSUPPORTED;
	वापस 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
स्थिर अक्षर *
sshkey_sigalg_by_name(स्थिर अक्षर *name)
{
	स्थिर काष्ठा sshkey_impl *impl;
	पूर्णांक i;

	क्रम (i = 0; keyimpls[i] != शून्य; i++) {
		impl = keyimpls[i];
		अगर (म_भेद(impl->name, name) != 0)
			जारी;
		अगर (impl->sigalg != शून्य)
			वापस impl->sigalg;
		अगर (!impl->cert)
			वापस impl->name;
		वापस sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	वापस शून्य;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
पूर्णांक
sshkey_check_sigtype(स्थिर u_char *sig, माप_प्रकार siglen,
    स्थिर अक्षर *requested_alg)
{
	स्थिर अक्षर *expected_alg;
	अक्षर *sigtype = शून्य;
	पूर्णांक r;

	अगर (requested_alg == शून्य)
		वापस 0;
	अगर ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		वापस r;
	r = म_भेद(expected_alg, sigtype) == 0;
	मुक्त(sigtype);
	वापस r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

पूर्णांक
sshkey_sign(काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *alg, स्थिर अक्षर *sk_provider, स्थिर अक्षर *sk_pin, u_int compat)
{
	पूर्णांक was_shielded = sshkey_is_shielded(कुंजी);
	पूर्णांक r2, r = SSH_ERR_INTERNAL_ERROR;
	स्थिर काष्ठा sshkey_impl *impl;

	अगर (sigp != शून्य)
		*sigp = शून्य;
	अगर (lenp != शून्य)
		*lenp = 0;
	अगर (datalen > SSH_कुंजी_MAX_SIGN_तथ्य_आकार)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((impl = sshkey_impl_from_कुंजी(कुंजी)) == शून्य)
		वापस SSH_ERR_कुंजी_TYPE_UNKNOWN;
	अगर ((r = sshkey_unshield_private(कुंजी)) != 0)
		वापस r;
	अगर (sshkey_is_sk(कुंजी)) {
		r = sshsk_sign(sk_provider, कुंजी, sigp, lenp, तथ्य,
		    datalen, compat, sk_pin);
	} अन्यथा अगर ((कुंजी->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(कुंजी, sigp, lenp, तथ्य, datalen,
		    alg, sk_provider, sk_pin, compat);
	} अन्यथा {
		अगर (impl->funcs->sign == शून्य)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		अन्यथा {
			r = impl->funcs->sign(कुंजी, sigp, lenp, तथ्य, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	अगर (was_shielded && (r2 = sshkey_shield_private(कुंजी)) != 0)
		वापस r2;
	वापस r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
पूर्णांक
sshkey_verify(स्थिर काष्ठा sshkey *कुंजी,
    स्थिर u_char *sig, माप_प्रकार siglen,
    स्थिर u_char *तथ्य, माप_प्रकार dlen, स्थिर अक्षर *alg, u_int compat,
    काष्ठा sshkey_sig_details **detailsp)
{
	स्थिर काष्ठा sshkey_impl *impl;

	अगर (detailsp != शून्य)
		*detailsp = शून्य;
	अगर (siglen == 0 || dlen > SSH_कुंजी_MAX_SIGN_तथ्य_आकार)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((impl = sshkey_impl_from_कुंजी(कुंजी)) == शून्य)
		वापस SSH_ERR_कुंजी_TYPE_UNKNOWN;
	वापस impl->funcs->verify(कुंजी, sig, siglen, तथ्य, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
पूर्णांक
sshkey_to_certified(काष्ठा sshkey *k)
{
	पूर्णांक newtype;

	अगर ((newtype = sshkey_type_certified(k->type)) == -1)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((k->cert = cert_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	वापस 0;
}

/* Convert a certificate to its raw key equivalent */
पूर्णांक
sshkey_drop_cert(काष्ठा sshkey *k)
{
	अगर (!sshkey_type_is_cert(k->type))
		वापस SSH_ERR_कुंजी_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = शून्य;
	k->type = sshkey_type_plain(k->type);
	वापस 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
पूर्णांक
sshkey_certify_custom(काष्ठा sshkey *k, काष्ठा sshkey *ca, स्थिर अक्षर *alg,
    स्थिर अक्षर *sk_provider, स्थिर अक्षर *sk_pin,
    sshkey_certify_signer *signer, व्योम *signer_ctx)
{
	स्थिर काष्ठा sshkey_impl *impl;
	काष्ठा sshbuf *principals = शून्य;
	u_char *ca_blob = शून्य, *sig_blob = शून्य, nonce[32];
	माप_प्रकार i, ca_len, sig_len;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;
	काष्ठा sshbuf *cert = शून्य;
	अक्षर *sigtype = शून्य;

	अगर (k == शून्य || k->cert == शून्य ||
	    k->cert->certblob == शून्य || ca == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (!sshkey_is_cert(k))
		वापस SSH_ERR_कुंजी_TYPE_UNKNOWN;
	अगर (!sshkey_type_is_valid_ca(ca->type))
		वापस SSH_ERR_कुंजी_CERT_INVALID_SIGN_कुंजी;
	अगर ((impl = sshkey_impl_from_कुंजी(k)) == शून्य)
		वापस SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	अगर (alg == शून्य)
		alg = k->cert->signature_type;
	अन्यथा अगर (k->cert->signature_type != शून्य &&
	    म_भेद(alg, k->cert->signature_type) != 0)
		वापस SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	अगर (alg == शून्य && ca->type == कुंजी_RSA)
		alg = "rsa-sha2-512";

	अगर ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		वापस SSH_ERR_कुंजी_CERT_INVALID_SIGN_कुंजी;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	अगर ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		जाओ out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, माप(nonce));
	अगर ((ret = sshbuf_put_string(cert, nonce, माप(nonce))) != 0)
		जाओ out;

	/* Public key next */
	अगर ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		जाओ out;

	/* Then remaining cert fields */
	अगर ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->कुंजी_id)) != 0)
		जाओ out;

	अगर ((principals = sshbuf_new()) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	क्रम (i = 0; i < k->cert->nprincipals; i++) {
		अगर ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			जाओ out;
	}
	अगर ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, शून्य, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		जाओ out;

	/* Sign the whole mess */
	अगर ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		जाओ out;
	/* Check and update signature_type against what was actually used */
	अगर ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		जाओ out;
	अगर (alg != शून्य && म_भेद(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		जाओ out;
	}
	अगर (k->cert->signature_type == शून्य) {
		k->cert->signature_type = sigtype;
		sigtype = शून्य;
	}
	/* Append signature and we are done */
	अगर ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		जाओ out;
	ret = 0;
 out:
	अगर (ret != 0)
		sshbuf_reset(cert);
	मुक्त(sig_blob);
	मुक्त(ca_blob);
	मुक्त(sigtype);
	sshbuf_free(principals);
	वापस ret;
}

अटल पूर्णांक
default_कुंजी_sign(काष्ठा sshkey *कुंजी, u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *alg, स्थिर अक्षर *sk_provider, स्थिर अक्षर *sk_pin,
    u_int compat, व्योम *ctx)
{
	अगर (ctx != शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	वापस sshkey_sign(कुंजी, sigp, lenp, तथ्य, datalen, alg,
	    sk_provider, sk_pin, compat);
}

पूर्णांक
sshkey_certify(काष्ठा sshkey *k, काष्ठा sshkey *ca, स्थिर अक्षर *alg,
    स्थिर अक्षर *sk_provider, स्थिर अक्षर *sk_pin)
{
	वापस sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_कुंजी_sign, शून्य);
}

पूर्णांक
sshkey_cert_check_authority(स्थिर काष्ठा sshkey *k,
    पूर्णांक want_host, पूर्णांक wildcard_pattern, uint64_t verify_time,
    स्थिर अक्षर *name, स्थिर अक्षर **reason)
{
	u_int i, principal_matches;

	अगर (reason == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		वापस SSH_ERR_कुंजी_CERT_INVALID;
	}
	अगर (want_host) {
		अगर (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			वापस SSH_ERR_कुंजी_CERT_INVALID;
		}
	} अन्यथा {
		अगर (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			वापस SSH_ERR_कुंजी_CERT_INVALID;
		}
	}
	अगर (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		वापस SSH_ERR_कुंजी_CERT_INVALID;
	}
	अगर (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		वापस SSH_ERR_कुंजी_CERT_INVALID;
	}
	अगर (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		वापस SSH_ERR_कुंजी_CERT_INVALID;
	}
	अगर (name == शून्य)
		वापस 0; /* principal matching not requested */

	principal_matches = 0;
	क्रम (i = 0; i < k->cert->nprincipals; i++) {
		अगर (wildcard_pattern) {
			अगर (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				अवरोध;
			}
		} अन्यथा अगर (म_भेद(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			अवरोध;
		}
	}
	अगर (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		वापस SSH_ERR_कुंजी_CERT_INVALID;
	}
	वापस 0;
}

पूर्णांक
sshkey_cert_check_authority_now(स्थिर काष्ठा sshkey *k,
    पूर्णांक want_host, पूर्णांक wildcard_pattern, स्थिर अक्षर *name,
    स्थिर अक्षर **reason)
{
	समय_प्रकार now;

	अगर ((now = समय(शून्य)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		वापस SSH_ERR_कुंजी_CERT_INVALID;
	}
	वापस sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

पूर्णांक
sshkey_cert_check_host(स्थिर काष्ठा sshkey *कुंजी, स्थिर अक्षर *host,
    स्थिर अक्षर *ca_sign_algorithms, स्थिर अक्षर **reason)
{
	पूर्णांक r;

	अगर ((r = sshkey_cert_check_authority_now(कुंजी, 1, 1, host, reason)) != 0)
		वापस r;
	अगर (sshbuf_len(कुंजी->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		वापस SSH_ERR_कुंजी_CERT_INVALID;
	}
	अगर (ca_sign_algorithms != शून्य &&
	    (r = sshkey_check_cert_sigtype(कुंजी, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		वापस SSH_ERR_कुंजी_CERT_INVALID;
	}
	वापस 0;
}

माप_प्रकार
sshkey_format_cert_validity(स्थिर काष्ठा sshkey_cert *cert, अक्षर *s, माप_प्रकार l)
{
	अक्षर from[32], to[32], ret[128];

	*from = *to = '\0';
	अगर (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		वापस strlcpy(s, "forever", l);

	अगर (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, माप(from));
	अगर (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, माप(to));

	अगर (cert->valid_after == 0)
		snprintf(ret, माप(ret), "before %s", to);
	अन्यथा अगर (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, माप(ret), "after %s", from);
	अन्यथा
		snprintf(ret, माप(ret), "from %s to %s", from, to);

	वापस strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
पूर्णांक
sshkey_serialize_private_sk(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b)
{
	पूर्णांक r;

	अगर ((r = sshbuf_put_cstring(b, कुंजी->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, कुंजी->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, कुंजी->sk_कुंजी_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, कुंजी->sk_reserved)) != 0)
		वापस r;

	वापस 0;
}

अटल पूर्णांक
sshkey_private_serialize_opt(काष्ठा sshkey *कुंजी, काष्ठा sshbuf *buf,
    क्रमागत sshkey_serialize_rep opts)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	पूर्णांक was_shielded = sshkey_is_shielded(कुंजी);
	काष्ठा sshbuf *b = शून्य;
	स्थिर काष्ठा sshkey_impl *impl;

	अगर ((impl = sshkey_impl_from_कुंजी(कुंजी)) == शून्य)
		वापस SSH_ERR_INTERNAL_ERROR;
	अगर ((r = sshkey_unshield_private(कुंजी)) != 0)
		वापस r;
	अगर ((b = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put_cstring(b, sshkey_ssh_name(कुंजी))) != 0)
		जाओ out;
	अगर (sshkey_is_cert(कुंजी)) {
		अगर (कुंजी->cert == शून्य ||
		    sshbuf_len(कुंजी->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			जाओ out;
		}
		अगर ((r = sshbuf_put_stringb(b, कुंजी->cert->certblob)) != 0)
			जाओ out;
	}
	अगर ((r = impl->funcs->serialize_private(कुंजी, b, opts)) != 0)
		जाओ out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	अगर (was_shielded)
		r = sshkey_shield_private(कुंजी);
	अगर (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	वापस r;
}

पूर्णांक
sshkey_private_serialize(काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b)
{
	वापस sshkey_private_serialize_opt(कुंजी, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
पूर्णांक
sshkey_private_deserialize_sk(काष्ठा sshbuf *buf, काष्ठा sshkey *k)
{
	पूर्णांक r;

	अगर ((k->sk_कुंजी_handle = sshbuf_new()) == शून्य ||
	    (k->sk_reserved = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_get_cstring(buf, &k->sk_application, शून्य)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_कुंजी_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		वापस r;

	वापस 0;
}

पूर्णांक
sshkey_private_deserialize(काष्ठा sshbuf *buf, काष्ठा sshkey **kp)
{
	स्थिर काष्ठा sshkey_impl *impl;
	अक्षर *tname = शून्य;
	अक्षर *expect_sk_application = शून्य;
	u_char *expect_ed25519_pk = शून्य;
	काष्ठा sshkey *k = शून्य;
	पूर्णांक type, r = SSH_ERR_INTERNAL_ERROR;

	अगर (kp != शून्य)
		*kp = शून्य;
	अगर ((r = sshbuf_get_cstring(buf, &tname, शून्य)) != 0)
		जाओ out;
	type = sshkey_type_from_name(tname);
	अगर (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		अगर ((r = sshkey_froms(buf, &k)) != 0)
			जाओ out;
		अगर (k->type != type) {
			r = SSH_ERR_कुंजी_CERT_MISMATCH;
			जाओ out;
		}
		/* For ECDSA keys, the group must match too */
		अगर (k->type == कुंजी_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_कुंजी_CERT_MISMATCH;
			जाओ out;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = शून्य;
		k->ed25519_pk = शून्य;
	} अन्यथा {
		अगर ((k = sshkey_new(type)) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
	}
	अगर ((impl = sshkey_impl_from_type(type)) == शून्य) {
		r = SSH_ERR_INTERNAL_ERROR;
		जाओ out;
	}
	अगर ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		जाओ out;

	अगर ((expect_sk_application != शून्य && (k->sk_application == शून्य ||
	    म_भेद(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != शून्य && (k->ed25519_pk == शून्य ||
	    स_भेद(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_कुंजी_CERT_MISMATCH;
		जाओ out;
	}
	/* success */
	r = 0;
	अगर (kp != शून्य) {
		*kp = k;
		k = शून्य;
	}
 out:
	मुक्त(tname);
	sshkey_free(k);
	मुक्त(expect_sk_application);
	मुक्त(expect_ed25519_pk);
	वापस r;
}

#अगर_घोषित WITH_OPENSSL
पूर्णांक
sshkey_ec_validate_public(स्थिर EC_GROUP *group, स्थिर EC_POINT *खुला)
{
	EC_POINT *nq = शून्य;
	BIGNUM *order = शून्य, *cofactor = शून्य;
	पूर्णांक ret = SSH_ERR_कुंजी_INVALID_EC_मूल्य;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	अगर (EC_POINT_is_at_infinity(group, खुला))
		जाओ out;

	अगर ((cofactor = BN_new()) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (EC_GROUP_get_cofactor(group, cofactor, शून्य) != 1)
		जाओ out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	अगर (!BN_is_one(cofactor)) {
		अगर ((order = BN_new()) == शून्य) {
			ret = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		अगर (EC_GROUP_get_order(group, order, शून्य) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			जाओ out;
		}
		अगर ((nq = EC_POINT_new(group)) == शून्य) {
			ret = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		अगर (EC_POINT_mul(group, nq, शून्य, खुला, order, शून्य) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			जाओ out;
		}
		अगर (EC_POINT_is_at_infinity(group, nq) != 1)
			जाओ out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	वापस ret;
}

पूर्णांक
sshkey_ec_validate_private(स्थिर EC_कुंजी *कुंजी)
{
	BIGNUM *order = शून्य, *tmp = शून्य;
	पूर्णांक ret = SSH_ERR_कुंजी_INVALID_EC_मूल्य;

	अगर ((order = BN_new()) == शून्य || (tmp = BN_new()) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}

	/* log2(private) > log2(order)/2 */
	अगर (EC_GROUP_get_order(EC_कुंजी_get0_group(कुंजी), order, शून्य) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	अगर (BN_अंक_bits(EC_कुंजी_get0_private_कुंजी(कुंजी)) <=
	    BN_अंक_bits(order) / 2)
		जाओ out;

	/* private < order - 1 */
	अगर (!BN_sub(tmp, order, BN_मूल्य_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	अगर (BN_cmp(EC_कुंजी_get0_private_कुंजी(कुंजी), tmp) >= 0)
		जाओ out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	वापस ret;
}

व्योम
sshkey_dump_ec_point(स्थिर EC_GROUP *group, स्थिर EC_POINT *point)
{
	BIGNUM *x = शून्य, *y = शून्य;

	अगर (point == शून्य) {
		ख_माला_दो("point=(NULL)\n", मानक_त्रुटि);
		वापस;
	}
	अगर ((x = BN_new()) == शून्य || (y = BN_new()) == शून्य) {
		ख_लिखो(मानक_त्रुटि, "%s: BN_new failed\n", __func__);
		जाओ out;
	}
	अगर (EC_POINT_get_affine_coordinates(group, point, x, y, शून्य) != 1) {
		ख_लिखो(मानक_त्रुटि, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		जाओ out;
	}
	ख_माला_दो("x=", मानक_त्रुटि);
	BN_print_fp(मानक_त्रुटि, x);
	ख_माला_दो("\ny=", मानक_त्रुटि);
	BN_print_fp(मानक_त्रुटि, y);
	ख_माला_दो("\n", मानक_त्रुटि);
 out:
	BN_clear_free(x);
	BN_clear_free(y);
}

व्योम
sshkey_dump_ec_कुंजी(स्थिर EC_कुंजी *कुंजी)
{
	स्थिर BIGNUM *exponent;

	sshkey_dump_ec_point(EC_कुंजी_get0_group(कुंजी),
	    EC_कुंजी_get0_public_कुंजी(कुंजी));
	ख_माला_दो("exponent=", मानक_त्रुटि);
	अगर ((exponent = EC_कुंजी_get0_private_कुंजी(कुंजी)) == शून्य)
		ख_माला_दो("(NULL)", मानक_त्रुटि);
	अन्यथा
		BN_print_fp(मानक_त्रुटि, EC_कुंजी_get0_private_कुंजी(कुंजी));
	ख_माला_दो("\n", मानक_त्रुटि);
}
#पूर्ण_अगर /* WITH_OPENSSL */

अटल पूर्णांक
sshkey_private_to_blob2(काष्ठा sshkey *prv, काष्ठा sshbuf *blob,
    स्थिर अक्षर *passphrase, स्थिर अक्षर *comment, स्थिर अक्षर *ciphername,
    पूर्णांक rounds)
{
	u_char *cp, *कुंजी = शून्य, *pubkeyblob = शून्य;
	u_char salt[SALT_LEN];
	माप_प्रकार i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	काष्ठा sshcipher_ctx *ciphercontext = शून्य;
	स्थिर काष्ठा sshcipher *cipher;
	स्थिर अक्षर *kdfname = KDFNAME;
	काष्ठा sshbuf *encoded = शून्य, *encrypted = शून्य, *kdf = शून्य;

	अगर (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	अगर (rounds > MAX_KDF_ROUNDS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	अगर (passphrase == शून्य || !म_माप(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} अन्यथा अगर (ciphername == शून्य)
		ciphername = DEFAULT_CIPHERNAME;
	अगर ((cipher = cipher_by_name(ciphername)) == शून्य) {
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}

	अगर ((kdf = sshbuf_new()) == शून्य ||
	    (encoded = sshbuf_new()) == शून्य ||
	    (encrypted = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	अगर ((कुंजी = सुस्मृति(1, keylen + ivlen)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (म_भेद(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		अगर (bcrypt_pbkdf(passphrase, म_माप(passphrase),
		    salt, SALT_LEN, कुंजी, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			जाओ out;
		}
		अगर ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			जाओ out;
	} अन्यथा अगर (म_भेद(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_कुंजी_UNKNOWN_CIPHER;
		जाओ out;
	}
	अगर ((r = cipher_init(&ciphercontext, cipher, कुंजी, keylen,
	    कुंजी + keylen, ivlen, 1)) != 0)
		जाओ out;

	अगर ((r = sshbuf_put(encoded, AUTH_MAGIC, माप(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_to_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		जाओ out;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	अगर ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		जाओ out;

	/* append private key and comment*/
	अगर ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		जाओ out;

	/* padding */
	i = 0;
	जबतक (sshbuf_len(encrypted) % blocksize) {
		अगर ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			जाओ out;
	}

	/* length in destination buffer */
	अगर ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		जाओ out;

	/* encrypt */
	अगर ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		जाओ out;
	अगर ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		जाओ out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	अगर ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_END, MARK_END_LEN)) != 0)
		जाओ out;

	/* success */
	r = 0;

 out:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, माप(salt));
	अगर (कुंजी != शून्य)
		freezero(कुंजी, keylen + ivlen);
	अगर (pubkeyblob != शून्य)
		freezero(pubkeyblob, pubkeylen);
	वापस r;
}

अटल पूर्णांक
private2_uudecode(काष्ठा sshbuf *blob, काष्ठा sshbuf **decodedp)
{
	स्थिर u_char *cp;
	माप_प्रकार encoded_len;
	पूर्णांक r;
	u_char last;
	काष्ठा sshbuf *encoded = शून्य, *decoded = शून्य;

	अगर (blob == शून्य || decodedp == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;

	*decodedp = शून्य;

	अगर ((encoded = sshbuf_new()) == शून्य ||
	    (decoded = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	अगर (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    स_भेद(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	जबतक (encoded_len > 0) {
		अगर (*cp != '\n' && *cp != '\r') {
			अगर ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				जाओ out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		अगर (last == '\n') {
			अगर (encoded_len >= MARK_END_LEN &&
			    स_भेद(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				अगर ((r = sshbuf_put_u8(encoded, 0)) != 0)
					जाओ out;
				अवरोध;
			}
		}
	}
	अगर (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}

	/* decode base64 */
	अगर ((r = sshbuf_b64tod(decoded, (अक्षर *)sshbuf_ptr(encoded))) != 0)
		जाओ out;

	/* check magic */
	अगर (sshbuf_len(decoded) < माप(AUTH_MAGIC) ||
	    स_भेद(sshbuf_ptr(decoded), AUTH_MAGIC, माप(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	/* success */
	*decodedp = decoded;
	decoded = शून्य;
	r = 0;
 out:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	वापस r;
}

अटल पूर्णांक
private2_decrypt(काष्ठा sshbuf *decoded, स्थिर अक्षर *passphrase,
    काष्ठा sshbuf **decryptedp, काष्ठा sshkey **pubkeyp)
{
	अक्षर *ciphername = शून्य, *kdfname = शून्य;
	स्थिर काष्ठा sshcipher *cipher = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	माप_प्रकार keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	काष्ठा sshbuf *kdf = शून्य, *decrypted = शून्य;
	काष्ठा sshcipher_ctx *ciphercontext = शून्य;
	काष्ठा sshkey *pubkey = शून्य;
	u_char *कुंजी = शून्य, *salt = शून्य, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	अगर (decoded == शून्य || decryptedp == शून्य || pubkeyp == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = शून्य;
	*pubkeyp = शून्य;

	अगर ((decrypted = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}

	/* parse public portion of key */
	अगर ((r = sshbuf_consume(decoded, माप(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, शून्य)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		जाओ out;

	अगर (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}

	अगर ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		जाओ out;

	अगर ((cipher = cipher_by_name(ciphername)) == शून्य) {
		r = SSH_ERR_कुंजी_UNKNOWN_CIPHER;
		जाओ out;
	}
	अगर (म_भेद(kdfname, "none") != 0 && म_भेद(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_कुंजी_UNKNOWN_CIPHER;
		जाओ out;
	}
	अगर (म_भेद(kdfname, "none") == 0 && म_भेद(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर ((passphrase == शून्य || म_माप(passphrase) == 0) &&
	    म_भेद(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_कुंजी_WRONG_PASSPHRASE;
		जाओ out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	अगर (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	अगर ((कुंजी = सुस्मृति(1, keylen + ivlen)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (म_भेद(kdfname, "bcrypt") == 0) {
		अगर ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			जाओ out;
		अगर (rounds > MAX_KDF_ROUNDS) {
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		अगर (bcrypt_pbkdf(passphrase, म_माप(passphrase), salt, slen,
		    कुंजी, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	अगर (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}

	/* decrypt private portion of key */
	अगर ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, कुंजी, keylen,
	    कुंजी + keylen, ivlen, 0)) != 0)
		जाओ out;
	अगर ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		अगर (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_कुंजी_WRONG_PASSPHRASE;
		जाओ out;
	}
	अगर ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		जाओ out;
	/* there should be no trailing data */
	अगर (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}

	/* check check bytes */
	अगर ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		जाओ out;
	अगर (check1 != check2) {
		r = SSH_ERR_कुंजी_WRONG_PASSPHRASE;
		जाओ out;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = शून्य;
	*pubkeyp = pubkey;
	pubkey = शून्य;
	r = 0;
 out:
	cipher_free(ciphercontext);
	मुक्त(ciphername);
	मुक्त(kdfname);
	sshkey_free(pubkey);
	अगर (salt != शून्य) {
		explicit_bzero(salt, slen);
		मुक्त(salt);
	}
	अगर (कुंजी != शून्य) {
		explicit_bzero(कुंजी, keylen + ivlen);
		मुक्त(कुंजी);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	वापस r;
}

अटल पूर्णांक
sshkey_parse_private2(काष्ठा sshbuf *blob, पूर्णांक type, स्थिर अक्षर *passphrase,
    काष्ठा sshkey **keyp, अक्षर **commentp)
{
	अक्षर *comment = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	काष्ठा sshbuf *decoded = शून्य, *decrypted = शून्य;
	काष्ठा sshkey *k = शून्य, *pubkey = शून्य;

	अगर (keyp != शून्य)
		*keyp = शून्य;
	अगर (commentp != शून्य)
		*commentp = शून्य;

	/* Undo base64 encoding and decrypt the private section */
	अगर ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		जाओ out;

	अगर (type != कुंजी_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_कुंजी_TYPE_MISMATCH;
		जाओ out;
	}

	/* Load the private key and comment */
	अगर ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, शून्य)) != 0)
		जाओ out;

	/* Check deterministic padding after private section */
	अगर ((r = private2_check_padding(decrypted)) != 0)
		जाओ out;

	/* Check that the public key in the envelope matches the private key */
	अगर (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}

	/* success */
	r = 0;
	अगर (keyp != शून्य) {
		*keyp = k;
		k = शून्य;
	}
	अगर (commentp != शून्य) {
		*commentp = comment;
		comment = शून्य;
	}
 out:
	मुक्त(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	वापस r;
}

अटल पूर्णांक
sshkey_parse_private2_pubkey(काष्ठा sshbuf *blob, पूर्णांक type,
    काष्ठा sshkey **keyp)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	काष्ठा sshbuf *decoded = शून्य;
	काष्ठा sshkey *pubkey = शून्य;
	u_int nkeys = 0;

	अगर (keyp != शून्य)
		*keyp = शून्य;

	अगर ((r = private2_uudecode(blob, &decoded)) != 0)
		जाओ out;
	/* parse public key from unencrypted envelope */
	अगर ((r = sshbuf_consume(decoded, माप(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		जाओ out;

	अगर (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}

	/* Parse the public key */
	अगर ((r = sshkey_froms(decoded, &pubkey)) != 0)
		जाओ out;

	अगर (type != कुंजी_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_कुंजी_TYPE_MISMATCH;
		जाओ out;
	}

	/* success */
	r = 0;
	अगर (keyp != शून्य) {
		*keyp = pubkey;
		pubkey = शून्य;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	वापस r;
}

#अगर_घोषित WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
अटल पूर्णांक
sshkey_private_to_blob_pem_pkcs8(काष्ठा sshkey *कुंजी, काष्ठा sshbuf *buf,
    पूर्णांक format, स्थिर अक्षर *_passphrase, स्थिर अक्षर *comment)
{
	पूर्णांक was_shielded = sshkey_is_shielded(कुंजी);
	पूर्णांक success, r;
	पूर्णांक blen, len = म_माप(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : शून्य;
	स्थिर EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : शून्य;
	अक्षर *bptr;
	BIO *bio = शून्य;
	काष्ठा sshbuf *blob;
	EVP_PKEY *pkey = शून्य;

	अगर (len > 0 && len <= 4)
		वापस SSH_ERR_PASSPHRASE_TOO_SHORT;
	अगर ((blob = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((bio = BIO_new(BIO_s_mem())) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshkey_unshield_private(कुंजी)) != 0)
		जाओ out;

	चयन (कुंजी->type) {
	हाल कुंजी_ECDSA:
		अगर (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivate_कुंजी(bio,
			    EVP_PKEY_get0_EC_कुंजी(कुंजी->pkey),
			    cipher, passphrase, len, शून्य, शून्य);
		} अन्यथा {
			pkey = कुंजी->pkey;
			EVP_PKEY_up_ref(कुंजी->pkey);
			success = 1;
		}
		अवरोध;
	हाल कुंजी_RSA:
		अगर (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivate_कुंजी(bio,
			    EVP_PKEY_get0_RSA(कुंजी->pkey),
			    cipher, passphrase, len, शून्य, शून्य);
		} अन्यथा {
			pkey = कुंजी->pkey;
			EVP_PKEY_up_ref(कुंजी->pkey);
			success = 1;
		}
		अवरोध;
#अगर_घोषित OPENSSL_HAS_ED25519
	हाल कुंजी_ED25519:
		अगर (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		} अन्यथा {
			pkey = EVP_PKEY_new_raw_private_कुंजी(EVP_PKEY_ED25519,
			    शून्य, कुंजी->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != शून्य;
		}
		अवरोध;
#पूर्ण_अगर
	शेष:
		success = 0;
		अवरोध;
	}
	अगर (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	अगर (format == SSHKEY_PRIVATE_PKCS8) {
		अगर ((success = PEM_write_bio_Private_कुंजी(bio, pkey, cipher,
		    passphrase, len, शून्य, शून्य)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जाओ out;
		}
	}
	अगर ((blen = BIO_get_mem_तथ्य(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		जाओ out;
	}
	अगर ((r = sshbuf_put(blob, bptr, blen)) != 0)
		जाओ out;
	r = 0;
 out:
	अगर (was_shielded)
		r = sshkey_shield_private(कुंजी);
	अगर (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	वापस r;
}
#पूर्ण_अगर /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
पूर्णांक
sshkey_private_to_fileblob(काष्ठा sshkey *कुंजी, काष्ठा sshbuf *blob,
    स्थिर अक्षर *passphrase, स्थिर अक्षर *comment,
    पूर्णांक format, स्थिर अक्षर *openssh_format_cipher, पूर्णांक openssh_format_rounds)
{
	चयन (कुंजी->type) {
#अगर_घोषित WITH_OPENSSL
	हाल कुंजी_ECDSA:
	हाल कुंजी_RSA:
	हाल कुंजी_ED25519:
		अवरोध; /* see below */
#अन्यथा /* WITH_OPENSSL */
	हाल कुंजी_ED25519:
#पूर्ण_अगर /* WITH_OPENSSL */
	हाल कुंजी_ED25519_SK:
#अगर_घोषित WITH_OPENSSL
	हाल कुंजी_ECDSA_SK:
#पूर्ण_अगर /* WITH_OPENSSL */
	हाल कुंजी_MLDSA44_ED25519:
		वापस sshkey_private_to_blob2(कुंजी, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	शेष:
		वापस SSH_ERR_कुंजी_TYPE_UNKNOWN;
	}

#अगर_घोषित WITH_OPENSSL
	चयन (format) {
	हाल SSHKEY_PRIVATE_OPENSSH:
		वापस sshkey_private_to_blob2(कुंजी, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	हाल SSHKEY_PRIVATE_PEM:
	हाल SSHKEY_PRIVATE_PKCS8:
		वापस sshkey_private_to_blob_pem_pkcs8(कुंजी, blob,
		    format, passphrase, comment);
	शेष:
		वापस SSH_ERR_INVALID_ARGUMENT;
	}
#पूर्ण_अगर /* WITH_OPENSSL */
}

#अगर_घोषित WITH_OPENSSL
अटल पूर्णांक
translate_libcrypto_error(अचिन्हित दीर्घ pem_err)
{
	पूर्णांक pem_reason = ERR_GET_REASON(pem_err);

	चयन (ERR_GET_LIB(pem_err)) {
	हाल ERR_LIB_PEM:
		चयन (pem_reason) {
		हाल PEM_R_BAD_PASSWORD_READ:
#अगर_घोषित PEM_R_PROBLEMS_GETTING_PASSWORD
		हाल PEM_R_PROBLEMS_GETTING_PASSWORD:
#पूर्ण_अगर
#अगर_घोषित PEM_R_BAD_DECRYPT
		हाल PEM_R_BAD_DECRYPT:
#पूर्ण_अगर
			वापस SSH_ERR_कुंजी_WRONG_PASSPHRASE;
		शेष:
			वापस SSH_ERR_INVALID_FORMAT;
		}
	हाल ERR_LIB_EVP:
		चयन (pem_reason) {
#अगर_घोषित EVP_R_BAD_DECRYPT
		हाल EVP_R_BAD_DECRYPT:
			वापस SSH_ERR_कुंजी_WRONG_PASSPHRASE;
#पूर्ण_अगर
#अगर_घोषित EVP_R_BN_DECODE_ERROR
		हाल EVP_R_BN_DECODE_ERROR:
#पूर्ण_अगर
		हाल EVP_R_DECODE_ERROR:
#अगर_घोषित EVP_R_PRIVATE_कुंजी_DECODE_ERROR
		हाल EVP_R_PRIVATE_कुंजी_DECODE_ERROR:
#पूर्ण_अगर
			वापस SSH_ERR_INVALID_FORMAT;
		शेष:
			वापस SSH_ERR_LIBCRYPTO_ERROR;
		}
	हाल ERR_LIB_ASN1:
#अगर_घोषित ERR_LIB_OSSL_DECODER
	हाल ERR_LIB_OSSL_DECODER:
#पूर्ण_अगर
		वापस SSH_ERR_INVALID_FORMAT;
	}
	वापस SSH_ERR_LIBCRYPTO_ERROR;
}

अटल व्योम
clear_libcrypto_errors(व्योम)
{
	जबतक (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
अटल पूर्णांक
convert_libcrypto_error(व्योम)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	अगर (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_कुंजी_WRONG_PASSPHRASE)
		वापस SSH_ERR_कुंजी_WRONG_PASSPHRASE;
	वापस translate_libcrypto_error(ERR_peek_last_error());
}

अटल पूर्णांक
pem_passphrase_cb(अक्षर *buf, पूर्णांक आकार, पूर्णांक rwflag, व्योम *u)
{
	अक्षर *p = (अक्षर *)u;
	माप_प्रकार len;

	अगर (p == शून्य || (len = म_माप(p)) == 0)
		वापस -1;
	अगर (आकार < 0 || len > (माप_प्रकार)आकार)
		वापस -1;
	स_नकल(buf, p, len);
	वापस (पूर्णांक)len;
}

अटल पूर्णांक
sshkey_parse_private_pem_fileblob(काष्ठा sshbuf *blob, पूर्णांक type,
    स्थिर अक्षर *passphrase, काष्ठा sshkey **keyp)
{
	EVP_PKEY *pk = शून्य;
	काष्ठा sshkey *prv = शून्य;
	BIO *bio = शून्य;
	पूर्णांक r;
	RSA *rsa = शून्य;
	EC_कुंजी *ecdsa = शून्य;

	अगर (keyp != शून्य)
		*keyp = शून्य;

	अगर ((bio = BIO_new(BIO_s_mem())) == शून्य || sshbuf_len(blob) > पूर्णांक_उच्च)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (पूर्णांक)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}

	clear_libcrypto_errors();
	अगर ((pk = PEM_read_bio_Private_कुंजी(bio, शून्य, pem_passphrase_cb,
	    (अक्षर *)passphrase)) == शून्य) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		अगर (passphrase != शून्य && *passphrase != '\0')
			r = SSH_ERR_कुंजी_WRONG_PASSPHRASE;
		अन्यथा
			r = convert_libcrypto_error();
		जाओ out;
	}
	अगर (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == कुंजी_UNSPEC || type == कुंजी_RSA)) {
		अगर ((prv = sshkey_new(कुंजी_UNSPEC)) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		अगर ((rsa = EVP_PKEY_get1_RSA(pk)) == शून्य) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जाओ out;
		}
		prv->type = कुंजी_RSA;
#अगर_घोषित DEBUG_PK
		RSA_print_fp(मानक_त्रुटि, rsa, 8);
#पूर्ण_अगर
		अगर (RSA_blinding_on(rsa, शून्य) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जाओ out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		अगर ((r = sshkey_check_rsa_लंबाई(prv, 0)) != 0)
			जाओ out;
	} अन्यथा अगर (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == कुंजी_UNSPEC || type == कुंजी_ECDSA)) {
		अगर ((prv = sshkey_new(कुंजी_UNSPEC)) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		अगर ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_कुंजी(pk)) == शून्य) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जाओ out;
		}
		prv->type = कुंजी_ECDSA;
		अगर (sshkey_curve_nid_to_name(prv->ecdsa_nid) == शून्य ||
		    sshkey_ec_validate_public(EC_कुंजी_get0_group(ecdsa),
		    EC_कुंजी_get0_public_कुंजी(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#अगर_घोषित DEBUG_PK
		अगर (prv != शून्य && prv->pkey != शून्य)
			sshkey_dump_ec_कुंजी(EVP_PKEY_get0_EC_कुंजी(prv->pkey));
#पूर्ण_अगर
#अगर_घोषित OPENSSL_HAS_ED25519
	} अन्यथा अगर (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == कुंजी_UNSPEC || type == कुंजी_ED25519)) {
		माप_प्रकार len;

		अगर ((prv = sshkey_new(कुंजी_UNSPEC)) == शून्य ||
		    (prv->ed25519_sk = सुस्मृति(1, ED25519_SK_SZ)) == शून्य ||
		    (prv->ed25519_pk = सुस्मृति(1, ED25519_PK_SZ)) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		prv->type = कुंजी_ED25519;
		len = ED25519_PK_SZ;
		अगर (!EVP_PKEY_get_raw_public_कुंजी(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जाओ out;
		}
		अगर (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		अगर (!EVP_PKEY_get_raw_private_कुंजी(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जाओ out;
		}
		अगर (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		/* Append the public key to our private key */
		स_नकल(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#अगर_घोषित DEBUG_PK
		sshbuf_dump_तथ्य(prv->ed25519_sk, ED25519_SK_SZ, मानक_त्रुटि);
#पूर्ण_अगर
#पूर्ण_अगर /* OPENSSL_HAS_ED25519 */
	} अन्यथा {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	r = 0;
	अगर (keyp != शून्य) {
		*keyp = prv;
		prv = शून्य;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_कुंजी_free(ecdsa);
	sshkey_free(prv);
	वापस r;
}
#पूर्ण_अगर /* WITH_OPENSSL */

पूर्णांक
sshkey_parse_private_fileblob_type(काष्ठा sshbuf *blob, पूर्णांक type,
    स्थिर अक्षर *passphrase, काष्ठा sshkey **keyp, अक्षर **commentp)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर (keyp != शून्य)
		*keyp = शून्य;
	अगर (commentp != शून्य)
		*commentp = शून्य;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	अगर (r != SSH_ERR_INVALID_FORMAT)
		वापस r;
#अगर_घोषित WITH_OPENSSL
	वापस sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#अन्यथा
	वापस SSH_ERR_INVALID_FORMAT;
#पूर्ण_अगर /* WITH_OPENSSL */
}

पूर्णांक
sshkey_parse_private_fileblob(काष्ठा sshbuf *बफर, स्थिर अक्षर *passphrase,
    काष्ठा sshkey **keyp, अक्षर **commentp)
{
	अगर (keyp != शून्य)
		*keyp = शून्य;
	अगर (commentp != शून्य)
		*commentp = शून्य;

	वापस sshkey_parse_private_fileblob_type(बफर, कुंजी_UNSPEC,
	    passphrase, keyp, commentp);
}

व्योम
sshkey_sig_details_free(काष्ठा sshkey_sig_details *details)
{
	freezero(details, माप(*details));
}

पूर्णांक
sshkey_parse_pubkey_from_private_fileblob_type(काष्ठा sshbuf *blob, पूर्णांक type,
    काष्ठा sshkey **pubkeyp)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर (pubkeyp != शून्य)
		*pubkeyp = शून्य;
	/* only new-format private keys bundle a public key inside */
	अगर ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		वापस r;
	वापस 0;
}
