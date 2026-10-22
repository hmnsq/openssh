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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/mman.h>
#अन्तर्भाव <netinet/in.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव <openssl/err.h>
#अन्तर्भाव <openssl/pem.h>
#endif

#अन्तर्भाव "crypto_api.h"

#अन्तर्भाव <errno.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <resolv.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <util.h>

#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "digest.h"
#define SSHKEY_INTERNAL
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "ssh-sk.h"
#अन्तर्भाव "ssh-pkcs11.h"

#अन्तर्भाव "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#define MARK_BEGIN_LEN		(परिमाण(MARK_BEGIN) - 1)
#define MARK_END_LEN		(परिमाण(MARK_END) - 1)
#define KDFNAME			"bcrypt"
#define AUTH_MAGIC		"openssh-key-v1"
#define SALT_LEN		16
#define DEFAULT_CIPHERNAME	"aes256-ctr"
#define	DEFAULT_ROUNDS		32
#define	MAX_KDF_ROUNDS		(1<<20)

/*
 * Constants relating to "shielding" support; protection of keys expected
 * to remain in memory for long durations
 */
#define SSHKEY_SHIELD_PREKEY_LEN	(16 * 1024)
#define SSHKEY_SHIELD_CIPHER		"aes256-ctr" /* XXX want AES-EME* */
#define SSHKEY_SHIELD_PREKEY_HASH	SSH_DIGEST_SHA512

स्थिर पूर्णाङ्क sshkey_from_blob_internal(संरचना sshbuf *buf,
    संरचना sshkey **keyp, पूर्णाङ्क allow_cert,
    ध्रुव वर्ण *alg_allowlist, ध्रुव वर्ण *ca_sigalg_allowlist);

/* Supported key types */
बाह्य ध्रुव संरचना sshkey_impl sshkey_ed25519_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_ed25519_cert_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_ed25519_sk_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
बाह्य ध्रुव संरचना sshkey_impl sshkey_mldsa44_ed25519_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#ifdef WITH_OPENSSL
# ifdef ENABLE_SK
बाह्य ध्रुव संरचना sshkey_impl sshkey_ecdsa_sk_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_ecdsa_sk_cert_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
बाह्य ध्रुव संरचना sshkey_impl sshkey_ecdsa_nistp256_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_ecdsa_nistp384_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_ecdsa_nistp521_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_rsa_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_rsa_cert_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_rsa_sha256_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_rsa_sha256_cert_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_rsa_sha512_impl;
बाह्य ध्रुव संरचना sshkey_impl sshkey_rsa_sha512_cert_impl;
#endif /* WITH_OPENSSL */

ध्रुव संरचना sshkey_impl * ध्रुव keyimpls[] = {
	&sshkey_ed25519_impl,
	&sshkey_ed25519_cert_impl,
#ifdef ENABLE_SK
	&sshkey_ed25519_sk_impl,
	&sshkey_ed25519_sk_cert_impl,
#endif
#ifdef USE_MLDSA
	&sshkey_mldsa44_ed25519_impl,
	&sshkey_mldsa44_ed25519_cert_impl,
#endif /* USE_MLDSA */
#ifdef WITH_OPENSSL
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
#endif /* WITH_OPENSSL */
	रिक्त
};

स्थिर ध्रुव संरचना sshkey_impl *
sshkey_impl_from_type(पूर्णाङ्क type)
{
	पूर्णाङ्क i;

	प्रति (i = 0; keyimpls[i] != रिक्त; i++) {
		यदि (keyimpls[i]->type == type)
			प्रत्यागम keyimpls[i];
	}
	प्रत्यागम रिक्त;
}

स्थिर ध्रुव संरचना sshkey_impl *
sshkey_impl_from_type_nid(पूर्णाङ्क type, पूर्णाङ्क nid)
{
	पूर्णाङ्क i;

	प्रति (i = 0; keyimpls[i] != रिक्त; i++) {
		यदि (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			प्रत्यागम keyimpls[i];
	}
	प्रत्यागम रिक्त;
}

स्थिर ध्रुव संरचना sshkey_impl *
sshkey_impl_from_किल्ली(ध्रुव संरचना sshkey *k)
{
	यदि (k == रिक्त)
		प्रत्यागम रिक्त;
	प्रत्यागम sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

ध्रुव वर्ण *
sshkey_type(ध्रुव संरचना sshkey *k)
{
	ध्रुव संरचना sshkey_impl *impl;

	यदि ((impl = sshkey_impl_from_किल्ली(k)) == रिक्त)
		प्रत्यागम "unknown";
	प्रत्यागम impl->shortname;
}

स्थिर ध्रुव वर्ण *
sshkey_ssh_name_from_type_nid(पूर्णाङ्क type, पूर्णाङ्क nid)
{
	ध्रुव संरचना sshkey_impl *impl;

	यदि ((impl = sshkey_impl_from_type_nid(type, nid)) == रिक्त)
		प्रत्यागम "ssh-unknown";
	प्रत्यागम impl->name;
}

पूर्णाङ्क
sshkey_type_is_cert(पूर्णाङ्क type)
{
	ध्रुव संरचना sshkey_impl *impl;

	यदि ((impl = sshkey_impl_from_type(type)) == रिक्त)
		प्रत्यागम 0;
	प्रत्यागम impl->cert;
}

ध्रुव वर्ण *
sshkey_ssh_name(ध्रुव संरचना sshkey *k)
{
	प्रत्यागम sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

ध्रुव वर्ण *
sshkey_ssh_name_plain(ध्रुव संरचना sshkey *k)
{
	प्रत्यागम sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

स्थिर पूर्णाङ्क
type_from_name(ध्रुव वर्ण *name, पूर्णाङ्क allow_short)
{
	पूर्णाङ्क i;
	ध्रुव संरचना sshkey_impl *impl;

	प्रति (i = 0; keyimpls[i] != रिक्त; i++) {
		impl = keyimpls[i];
		यदि (impl->name != रिक्त && strcmp(name, impl->name) == 0)
			प्रत्यागम impl->type;
		/* Only allow shortname matches for plain key types */
		यदि (allow_short && !impl->cert && impl->shortname != रिक्त &&
		    strcasecmp(impl->shortname, name) == 0)
			प्रत्यागम impl->type;
	}
	प्रत्यागम किल्ली_UNSPEC;
}

पूर्णाङ्क
sshkey_type_from_name(ध्रुव वर्ण *name)
{
	प्रत्यागम type_from_name(name, 0);
}

पूर्णाङ्क
sshkey_type_from_shortname(ध्रुव वर्ण *name)
{
	प्रत्यागम type_from_name(name, 1);
}

स्थिर पूर्णाङ्क
किल्ली_type_is_ecdsa_variant(पूर्णाङ्क type)
{
	विकल्प (type) {
	पक्ष किल्ली_ECDSA:
	पक्ष किल्ली_ECDSA_CERT:
	पक्ष किल्ली_ECDSA_SK:
	पक्ष किल्ली_ECDSA_SK_CERT:
		प्रत्यागम 1;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
sshkey_ecdsa_nid_from_name(ध्रुव वर्ण *name)
{
	पूर्णाङ्क i;

	प्रति (i = 0; keyimpls[i] != रिक्त; i++) {
		यदि (!किल्ली_type_is_ecdsa_variant(keyimpls[i]->type))
			अनुवर्त;
		यदि (keyimpls[i]->name != रिक्त &&
		    strcmp(name, keyimpls[i]->name) == 0)
			प्रत्यागम keyimpls[i]->nid;
	}
	प्रत्यागम -1;
}

पूर्णाङ्क
sshkey_match_keyname_to_sigalgs(ध्रुव वर्ण *keyname, ध्रुव वर्ण *sigalgs)
{
	पूर्णाङ्क ktype;

	यदि (sigalgs == रिक्त || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == किल्ली_UNSPEC)
		प्रत्यागम 0;
	अन्यथा यदि (ktype == किल्ली_RSA) {
		प्रत्यागम match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} अन्यथा यदि (ktype == किल्ली_RSA_CERT) {
		प्रत्यागम match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} अन्यथा यदि (ktype == किल्ली_ECDSA_SK) {
		प्रत्यागम match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} अन्यथा यदि (ktype == किल्ली_ECDSA_SK_CERT) {
		प्रत्यागम match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} अन्यथा
		प्रत्यागम match_pattern_list(keyname, sigalgs, 0) == 1;
}

वर्ण *
sshkey_alg_list(पूर्णाङ्क certs_only, पूर्णाङ्क plain_only, पूर्णाङ्क include_sigonly, वर्ण sep)
{
	वर्ण *ret = रिक्त;
	size_t i;
	ध्रुव संरचना sshkey_impl *impl;
	वर्ण sep_str[2] = {sep, '\0'};

	प्रति (i = 0; keyimpls[i] != रिक्त; i++) {
		impl = keyimpls[i];
		यदि (impl->name == रिक्त)
			अनुवर्त;
		यदि (!include_sigonly && impl->sigonly)
			अनुवर्त;
		यदि ((certs_only && !impl->cert) || (plain_only && impl->cert))
			अनुवर्त;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	प्रत्यागम ret;
}

पूर्णाङ्क
sshkey_names_valid2(ध्रुव वर्ण *names, पूर्णाङ्क allow_wildcard, पूर्णाङ्क plain_only)
{
	वर्ण *s, *cp, *p;
	ध्रुव संरचना sshkey_impl *impl;
	पूर्णाङ्क i, type;

	यदि (names == रिक्त || strcmp(names, "") == 0)
		प्रत्यागम 0;
	यदि ((s = cp = strdup(names)) == रिक्त)
		प्रत्यागम 0;
	प्रति ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		यदि (type == किल्ली_UNSPEC) {
			यदि (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = रिक्त;
				प्रति (i = 0; keyimpls[i] != रिक्त; i++) {
					यदि (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						भङ्ग;
					}
				}
				यदि (impl != रिक्त)
					अनुवर्त;
			}
			मुक्त(s);
			प्रत्यागम 0;
		} अन्यथा यदि (plain_only && sshkey_type_is_cert(type)) {
			मुक्त(s);
			प्रत्यागम 0;
		}
	}
	मुक्त(s);
	प्रत्यागम 1;
}

u_int
sshkey_size(ध्रुव संरचना sshkey *k)
{
	ध्रुव संरचना sshkey_impl *impl;

	यदि ((impl = sshkey_impl_from_किल्ली(k)) == रिक्त)
		प्रत्यागम 0;
	यदि (impl->funcs->size != रिक्त)
		प्रत्यागम impl->funcs->size(k);
	प्रत्यागम impl->keybits;
}

स्थिर पूर्णाङ्क
sshkey_type_is_valid_ca(पूर्णाङ्क type)
{
	ध्रुव संरचना sshkey_impl *impl;

	यदि ((impl = sshkey_impl_from_type(type)) == रिक्त)
		प्रत्यागम 0;
	/* All non-certificate types may act as CAs */
	प्रत्यागम !impl->cert;
}

पूर्णाङ्क
sshkey_is_cert(ध्रुव संरचना sshkey *k)
{
	यदि (k == रिक्त)
		प्रत्यागम 0;
	प्रत्यागम sshkey_type_is_cert(k->type);
}

पूर्णाङ्क
sshkey_is_sk(ध्रुव संरचना sshkey *k)
{
	यदि (k == रिक्त)
		प्रत्यागम 0;
	विकल्प (sshkey_type_plain(k->type)) {
	पक्ष किल्ली_ECDSA_SK:
	पक्ष किल्ली_ED25519_SK:
		प्रत्यागम 1;
	स्वभाव:
		प्रत्यागम 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
पूर्णाङ्क
sshkey_type_plain(पूर्णाङ्क type)
{
	विकल्प (type) {
	पक्ष किल्ली_RSA_CERT:
		प्रत्यागम किल्ली_RSA;
	पक्ष किल्ली_ECDSA_CERT:
		प्रत्यागम किल्ली_ECDSA;
	पक्ष किल्ली_ECDSA_SK_CERT:
		प्रत्यागम किल्ली_ECDSA_SK;
	पक्ष किल्ली_ED25519_CERT:
		प्रत्यागम किल्ली_ED25519;
	पक्ष किल्ली_MLDSA44_ED25519_CERT:
		प्रत्यागम किल्ली_MLDSA44_ED25519;
	पक्ष किल्ली_ED25519_SK_CERT:
		प्रत्यागम किल्ली_ED25519_SK;
	स्वभाव:
		प्रत्यागम type;
	}
}

/* Return the cert equivalent to a plain key type */
स्थिर पूर्णाङ्क
sshkey_type_certified(पूर्णाङ्क type)
{
	विकल्प (type) {
	पक्ष किल्ली_RSA:
		प्रत्यागम किल्ली_RSA_CERT;
	पक्ष किल्ली_ECDSA:
		प्रत्यागम किल्ली_ECDSA_CERT;
	पक्ष किल्ली_ECDSA_SK:
		प्रत्यागम किल्ली_ECDSA_SK_CERT;
	पक्ष किल्ली_ED25519:
		प्रत्यागम किल्ली_ED25519_CERT;
	पक्ष किल्ली_MLDSA44_ED25519:
		प्रत्यागम किल्ली_MLDSA44_ED25519_CERT;
	पक्ष किल्ली_ED25519_SK:
		प्रत्यागम किल्ली_ED25519_SK_CERT;
	स्वभाव:
		प्रत्यागम -1;
	}
}

#ifdef WITH_OPENSSL
स्थिर ध्रुव EVP_MD *
ssh_digest_to_md(पूर्णाङ्क hash_alg)
{
	विकल्प (hash_alg) {
	पक्ष SSH_DIGEST_SHA1:
		प्रत्यागम EVP_sha1();
	पक्ष SSH_DIGEST_SHA256:
		प्रत्यागम EVP_sha256();
	पक्ष SSH_DIGEST_SHA384:
		प्रत्यागम EVP_sha384();
	पक्ष SSH_DIGEST_SHA512:
		प्रत्यागम EVP_sha512();
	}
	प्रत्यागम रिक्त;
}

पूर्णाङ्क
sshkey_pkey_digest_sign(EVP_PKEY *pkey, पूर्णाङ्क hash_alg, u_char **sigp,
    size_t *lenp, ध्रुव u_char *data, size_t datalen)
{
	EVP_MD_CTX *ctx = रिक्त;
	u_char *sig = रिक्त;
	पूर्णाङ्क ret;
	size_t slen;
	ध्रुव EVP_MD *evpmd;

	*sigp = रिक्त;
	*lenp = 0;

	slen = EVP_PKEY_size(pkey);
	यदि (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;

	यदि ((sig = malloc(slen)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;

	यदि ((ctx = EVP_MD_CTX_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (EVP_DigestSignInit(ctx, रिक्त, evpmd, रिक्त, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, data, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = रिक्त;
	ret = 0;

 out:
	EVP_MD_CTX_free(ctx);
	मुक्त(sig);
	प्रत्यागम ret;
}

पूर्णाङ्क
sshkey_pkey_digest_verify(EVP_PKEY *pkey, पूर्णाङ्क hash_alg, ध्रुव u_char *data,
    size_t datalen, u_char *sigbuf, size_t siglen)
{
	EVP_MD_CTX *ctx = रिक्त;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;
	ध्रुव EVP_MD *evpmd;

	यदि ((evpmd = ssh_digest_to_md(hash_alg)) == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि ((ctx = EVP_MD_CTX_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि (EVP_DigestVerifyInit(ctx, रिक्त, evpmd, रिक्त, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	विकल्प (EVP_DigestVerify(ctx, sigbuf, siglen, data, datalen)) {
	पक्ष 1:
		ret = 0;
		भङ्ग;
	पक्ष 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		भङ्ग;
	स्वभाव:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		भङ्ग;
	}

 out:
	EVP_MD_CTX_free(ctx);
	प्रत्यागम ret;
}

/* XXX: these are really begging for a table-driven approach */
पूर्णाङ्क
sshkey_curve_name_to_nid(ध्रुव वर्ण *name)
{
	यदि (strcmp(name, "nistp256") == 0)
		प्रत्यागम NID_X9_62_prime256v1;
	अन्यथा यदि (strcmp(name, "nistp384") == 0)
		प्रत्यागम NID_secp384r1;
	अन्यथा यदि (strcmp(name, "nistp521") == 0)
		प्रत्यागम NID_secp521r1;
	अन्यथा
		प्रत्यागम -1;
}

u_int
sshkey_curve_nid_to_bits(पूर्णाङ्क nid)
{
	विकल्प (nid) {
	पक्ष NID_X9_62_prime256v1:
		प्रत्यागम 256;
	पक्ष NID_secp384r1:
		प्रत्यागम 384;
	पक्ष NID_secp521r1:
		प्रत्यागम 521;
	स्वभाव:
		प्रत्यागम 0;
	}
}

पूर्णाङ्क
sshkey_ecdsa_bits_to_nid(पूर्णाङ्क bits)
{
	विकल्प (bits) {
	पक्ष 256:
		प्रत्यागम NID_X9_62_prime256v1;
	पक्ष 384:
		प्रत्यागम NID_secp384r1;
	पक्ष 521:
		प्रत्यागम NID_secp521r1;
	स्वभाव:
		प्रत्यागम -1;
	}
}

ध्रुव वर्ण *
sshkey_curve_nid_to_name(पूर्णाङ्क nid)
{
	विकल्प (nid) {
	पक्ष NID_X9_62_prime256v1:
		प्रत्यागम "nistp256";
	पक्ष NID_secp384r1:
		प्रत्यागम "nistp384";
	पक्ष NID_secp521r1:
		प्रत्यागम "nistp521";
	स्वभाव:
		प्रत्यागम रिक्त;
	}
}

पूर्णाङ्क
sshkey_ec_nid_to_hash_alg(पूर्णाङ्क nid)
{
	पूर्णाङ्क kbits = sshkey_curve_nid_to_bits(nid);

	यदि (kbits <= 0)
		प्रत्यागम -1;

	/* RFC5656 section 6.2.1 */
	यदि (kbits <= 256)
		प्रत्यागम SSH_DIGEST_SHA256;
	अन्यथा यदि (kbits <= 384)
		प्रत्यागम SSH_DIGEST_SHA384;
	अन्यथा
		प्रत्यागम SSH_DIGEST_SHA512;
}
#endif /* WITH_OPENSSL */

स्थिर शून्य
cert_free(संरचना sshkey_cert *cert)
{
	u_int i;

	यदि (cert == रिक्त)
		प्रत्यागम;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	मुक्त(cert->किल्ली_id);
	प्रति (i = 0; i < cert->nprincipals; i++)
		मुक्त(cert->principals[i]);
	मुक्त(cert->principals);
	sshkey_free(cert->signature_किल्ली);
	मुक्त(cert->signature_type);
	freezero(cert, परिमाण(*cert));
}

स्थिर संरचना sshkey_cert *
cert_new(शून्य)
{
	संरचना sshkey_cert *cert;

	यदि ((cert = calloc(1, परिमाण(*cert))) == रिक्त)
		प्रत्यागम रिक्त;
	यदि ((cert->certblob = sshbuf_new()) == रिक्त ||
	    (cert->critical = sshbuf_new()) == रिक्त ||
	    (cert->extensions = sshbuf_new()) == रिक्त) {
		cert_free(cert);
		प्रत्यागम रिक्त;
	}
	cert->किल्ली_id = रिक्त;
	cert->principals = रिक्त;
	cert->signature_किल्ली = रिक्त;
	cert->signature_type = रिक्त;
	प्रत्यागम cert;
}

संरचना sshkey *
sshkey_new(पूर्णाङ्क type)
{
	संरचना sshkey *k;
	ध्रुव संरचना sshkey_impl *impl = रिक्त;

	यदि (type != किल्ली_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == रिक्त)
		प्रत्यागम रिक्त;

	/* All non-certificate types may act as CAs */
	यदि ((k = calloc(1, परिमाण(*k))) == रिक्त)
		प्रत्यागम रिक्त;
	k->type = type;
	k->ecdsa_nid = -1;
	यदि (impl != रिक्त && impl->funcs->alloc != रिक्त) {
		यदि (impl->funcs->alloc(k) != 0) {
			मुक्त(k);
			प्रत्यागम रिक्त;
		}
	}
	यदि (sshkey_is_cert(k)) {
		यदि ((k->cert = cert_new()) == रिक्त) {
			sshkey_free(k);
			प्रत्यागम रिक्त;
		}
	}

	प्रत्यागम k;
}

/* Frees common FIDO fields */
शून्य
sshkey_sk_cleanup(संरचना sshkey *k)
{
	मुक्त(k->sk_application);
	sshbuf_free(k->sk_किल्ली_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = रिक्त;
	k->sk_किल्ली_handle = k->sk_reserved = रिक्त;
}

#यदि defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#नोचेद्यदि defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#अन्यथा
# define PREKEY_MMAP_FLAG	0
#endif

स्थिर पूर्णाङ्क
sshkey_prekey_alloc(u_char **prekeyp, size_t len)
{
#यदि defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = रिक्त;
	यदि ((prekey = mmap(रिक्त, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
#यदि defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(शून्य)madvise(prekey, len, MADV_DONTDUMP);
#endif
	*prekeyp = prekey;
#अन्यथा
	*prekeyp = calloc(1, len);
#endif /* HAVE_MMAP et al */
	प्रत्यागम 0;
}

स्थिर शून्य
sshkey_prekey_free(शून्य *prekey, size_t len)
{
#यदि defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	यदि (prekey == रिक्त)
		प्रत्यागम;
	munmap(prekey, len);
#अन्यथा
	मुक्त(prekey);
#endif /* HAVE_MMAP et al */
}

स्थिर शून्य
sshkey_free_contents(संरचना sshkey *k)
{
	ध्रुव संरचना sshkey_impl *impl;

	यदि (k == रिक्त)
		प्रत्यागम;
	यदि ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_किल्ली_free(k);
	यदि ((impl = sshkey_impl_from_type(k->type)) != रिक्त &&
	    impl->funcs->cleanup != रिक्त)
		impl->funcs->cleanup(k);
	यदि (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_private, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

शून्य
sshkey_free(संरचना sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, परिमाण(*k));
}

स्थिर पूर्णाङ्क
cert_compare(संरचना sshkey_cert *a, संरचना sshkey_cert *b)
{
	यदि (a == रिक्त && b == रिक्त)
		प्रत्यागम 1;
	यदि (a == रिक्त || b == रिक्त)
		प्रत्यागम 0;
	यदि (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		प्रत्यागम 0;
	यदि (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		प्रत्यागम 0;
	प्रत्यागम 1;
}

/* Compares FIDO-specific pubkey fields only */
पूर्णाङ्क
sshkey_sk_fields_equal(ध्रुव संरचना sshkey *a, ध्रुव संरचना sshkey *b)
{
	यदि (a->sk_application == रिक्त || b->sk_application == रिक्त)
		प्रत्यागम 0;
	यदि (strcmp(a->sk_application, b->sk_application) != 0)
		प्रत्यागम 0;
	प्रत्यागम 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
पूर्णाङ्क
sshkey_equal_public(ध्रुव संरचना sshkey *a, ध्रुव संरचना sshkey *b)
{
	ध्रुव संरचना sshkey_impl *impl;

	यदि (a == रिक्त || b == रिक्त ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		प्रत्यागम 0;
	यदि ((impl = sshkey_impl_from_type(a->type)) == रिक्त)
		प्रत्यागम 0;
	प्रत्यागम impl->funcs->equal(a, b);
}

पूर्णाङ्क
sshkey_equal(ध्रुव संरचना sshkey *a, ध्रुव संरचना sshkey *b)
{
	यदि (a == रिक्त || b == रिक्त || a->type != b->type)
		प्रत्यागम 0;
	यदि (sshkey_is_cert(a)) {
		यदि (!cert_compare(a->cert, b->cert))
			प्रत्यागम 0;
	}
	प्रत्यागम sshkey_equal_public(a, b);
}


/* Serialise common FIDO key parts */
पूर्णाङ्क
sshkey_serialize_sk(ध्रुव संरचना sshkey *किल्ली, संरचना sshbuf *b)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_cstring(b, किल्ली->sk_application)) != 0)
		प्रत्यागम r;

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
to_blob_buf(ध्रुव संरचना sshkey *किल्ली, संरचना sshbuf *b, पूर्णाङ्क force_plain,
  गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क type, ret = SSH_ERR_INTERNAL_ERROR;
	ध्रुव वर्ण *typename;
	ध्रुव संरचना sshkey_impl *impl;

	यदि (किल्ली == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(किल्ली->type) : किल्ली->type;

	यदि (sshkey_type_is_cert(type)) {
		यदि (किल्ली->cert == रिक्त)
			प्रत्यागम SSH_ERR_EXPECTED_CERT;
		यदि (sshbuf_len(किल्ली->cert->certblob) == 0)
			प्रत्यागम SSH_ERR_किल्ली_LACKS_CERTBLOB;
		/* Use the existing blob */
		यदि ((ret = sshbuf_putb(b, किल्ली->cert->certblob)) != 0)
			प्रत्यागम ret;
		प्रत्यागम 0;
	}
	यदि ((impl = sshkey_impl_from_type(type)) == रिक्त)
		प्रत्यागम SSH_ERR_किल्ली_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, किल्ली->ecdsa_nid);
	यदि ((ret = sshbuf_put_cstring(b, typename)) != 0)
		प्रत्यागम ret;
	प्रत्यागम impl->funcs->serialize_public(किल्ली, b, opts);
}

पूर्णाङ्क
sshkey_putb(ध्रुव संरचना sshkey *किल्ली, संरचना sshbuf *b)
{
	प्रत्यागम to_blob_buf(किल्ली, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

स्थिर पूर्णाङ्क
sshkey_puts_opts_internal(ध्रुव संरचना sshkey *किल्ली, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts, पूर्णाङ्क force_plain)
{
	संरचना sshbuf *tmp;
	पूर्णाङ्क r;

	यदि ((tmp = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(किल्ली, tmp, force_plain, opts);
	यदि (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	प्रत्यागम r;
}

पूर्णाङ्क
sshkey_puts(ध्रुव संरचना sshkey *किल्ली, संरचना sshbuf *b)
{
	प्रत्यागम sshkey_puts_opts_internal(किल्ली, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

पूर्णाङ्क
sshkey_putb_plain(ध्रुव संरचना sshkey *किल्ली, संरचना sshbuf *b)
{
	प्रत्यागम to_blob_buf(किल्ली, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

पूर्णाङ्क
sshkey_puts_plain(ध्रुव संरचना sshkey *किल्ली, संरचना sshbuf *b)
{
	प्रत्यागम sshkey_puts_opts_internal(किल्ली, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

स्थिर पूर्णाङ्क
to_blob(ध्रुव संरचना sshkey *किल्ली, u_char **blobp, size_t *lenp, पूर्णाङ्क force_plain,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	संरचना sshbuf *b = रिक्त;

	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (blobp != रिक्त)
		*blobp = रिक्त;
	यदि ((b = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((ret = to_blob_buf(किल्ली, b, force_plain, opts)) != 0)
		गच्छ out;
	len = sshbuf_len(b);
	यदि (lenp != रिक्त)
		*lenp = len;
	यदि (blobp != रिक्त) {
		यदि ((*blobp = malloc(len)) == रिक्त) {
			ret = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	प्रत्यागम ret;
}

पूर्णाङ्क
sshkey_to_blob(ध्रुव संरचना sshkey *किल्ली, u_char **blobp, size_t *lenp)
{
	प्रत्यागम to_blob(किल्ली, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

पूर्णाङ्क
sshkey_plain_to_blob(ध्रुव संरचना sshkey *किल्ली, u_char **blobp, size_t *lenp)
{
	प्रत्यागम to_blob(किल्ली, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

पूर्णाङ्क
sshkey_fingerprint_raw(ध्रुव संरचना sshkey *k, पूर्णाङ्क dgst_alg,
    u_char **retp, size_t *lenp)
{
	u_char *blob = रिक्त, *ret = रिक्त;
	size_t blob_len = 0;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	यदि (retp != रिक्त)
		*retp = रिक्त;
	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	यदि ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		गच्छ out;
	यदि ((ret = calloc(1, SSH_DIGEST_MAX_LENGTH)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_LENGTH)) != 0)
		गच्छ out;
	/* success */
	यदि (retp != रिक्त) {
		*retp = ret;
		ret = रिक्त;
	}
	यदि (lenp != रिक्त)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	मुक्त(ret);
	यदि (blob != रिक्त)
		freezero(blob, blob_len);
	प्रत्यागम r;
}

स्थिर वर्ण *
fingerprint_b64(ध्रुव वर्ण *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	वर्ण *ret;
	size_t plen = strlen(alg) + 1;
	size_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	यदि (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == रिक्त)
		प्रत्यागम रिक्त;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	यदि (dgst_raw_len == 0)
		प्रत्यागम ret;
	यदि (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		प्रत्यागम रिक्त;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	प्रत्यागम ret;
}

स्थिर वर्ण *
fingerprint_hex(ध्रुव वर्ण *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	वर्ण *retval, hex[5];
	size_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	यदि (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == रिक्त)
		प्रत्यागम रिक्त;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	प्रति (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, परिमाण(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	प्रत्यागम retval;
}

स्थिर वर्ण *
fingerprint_bubblebabble(u_char *dgst_raw, size_t dgst_raw_len)
{
	वर्ण vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	वर्ण consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	वर्ण *retval;

	rounds = (dgst_raw_len / 2) + 1;
	यदि ((retval = calloc(rounds, 6)) == रिक्त)
		प्रत्यागम रिक्त;
	retval[j++] = 'x';
	प्रति (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		यदि ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			यदि ((i + 1) < rounds) {
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
	प्रत्यागम retval;
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
#define	FLDBASE		8
#define	FLDSIZE_Y	(FLDBASE + 1)
#define	FLDSIZE_X	(FLDBASE * 2 + 1)
स्थिर वर्ण *
fingerprint_randomart(ध्रुव वर्ण *alg, u_char *dgst_raw, size_t dgst_raw_len,
    ध्रुव संरचना sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	वर्ण	*augmentation_string = " .o+=*BOX@%&#/^SE";
	वर्ण	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	size_t	 i, tlen, hlen;
	u_int	 b;
	पूर्णाङ्क	 x, y, r;
	size_t	 len = strlen(augmentation_string) - 1;

	यदि ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == रिक्त)
		प्रत्यागम रिक्त;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * परिमाण(वर्ण));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	प्रति (i = 0; i < dgst_raw_len; i++) {
		पूर्णाङ्क आदान;
		/* each byte conveys four 2-bit move commands */
		आदान = dgst_raw[i];
		प्रति (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (आदान & 0x1) ? 1 : -1;
			y += (आदान & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			यदि (field[x][y] < len - 2)
				field[x][y]++;
			आदान = आदान >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, परिमाण(title), "[%s %u]",
		sshkey_type(k), sshkey_size(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	यदि (r < 0 || r > (पूर्णाङ्क)परिमाण(title))
		r = snprintf(title, परिमाण(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, परिमाण(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	प्रति (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	memcpy(p, title, tlen);
	p += tlen;
	प्रति (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	प्रति (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		प्रति (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	प्रति (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	memcpy(p, hash, hlen);
	p += hlen;
	प्रति (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	प्रत्यागम retval;
}

वर्ण *
sshkey_fingerprint(ध्रुव संरचना sshkey *k, पूर्णाङ्क dgst_alg,
    गणना sshkey_fp_rep dgst_rep)
{
	वर्ण *retval = रिक्त;
	u_char *dgst_raw;
	size_t dgst_raw_len;

	यदि (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		प्रत्यागम रिक्त;
	विकल्प (dgst_rep) {
	पक्ष SSH_FP_DEFAULT:
		यदि (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} अन्यथा {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		भङ्ग;
	पक्ष SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		भङ्ग;
	पक्ष SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		भङ्ग;
	पक्ष SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		भङ्ग;
	पक्ष SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		भङ्ग;
	स्वभाव:
		freezero(dgst_raw, dgst_raw_len);
		प्रत्यागम रिक्त;
	}
	freezero(dgst_raw, dgst_raw_len);
	प्रत्यागम retval;
}

स्थिर पूर्णाङ्क
peek_type_nid(ध्रुव वर्ण *s, size_t l, पूर्णाङ्क *nid)
{
	ध्रुव संरचना sshkey_impl *impl;
	पूर्णाङ्क i;

	प्रति (i = 0; keyimpls[i] != रिक्त; i++) {
		impl = keyimpls[i];
		यदि (impl->name == रिक्त || strlen(impl->name) != l)
			अनुवर्त;
		यदि (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			यदि (किल्ली_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			प्रत्यागम impl->type;
		}
	}
	प्रत्यागम किल्ली_UNSPEC;
}

/* XXX this can now be made const char * */
पूर्णाङ्क
sshkey_read(संरचना sshkey *ret, वर्ण **cpp)
{
	संरचना sshkey *k;
	वर्ण *cp, *blobcopy;
	size_t space;
	पूर्णाङ्क r, type, curve_nid = -1;
	संरचना sshbuf *blob;

	यदि (ret == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि (ret->type != किल्ली_UNSPEC && sshkey_impl_from_type(ret->type) == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	यदि (space == strlen(cp))
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	यदि ((type = peek_type_nid(cp, space, &curve_nid)) == किल्ली_UNSPEC)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	प्रति (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	यदि (*cp == '\0')
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	यदि (ret->type != किल्ली_UNSPEC && ret->type != type)
		प्रत्यागम SSH_ERR_किल्ली_TYPE_MISMATCH;
	यदि ((blob = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	यदि ((blobcopy = strndup(cp, space)) == रिक्त) {
		sshbuf_free(blob);
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	}
	यदि ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		मुक्त(blobcopy);
		sshbuf_free(blob);
		प्रत्यागम r;
	}
	मुक्त(blobcopy);
	यदि ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		प्रत्यागम r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	प्रति (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	यदि (k->type != type) {
		sshkey_free(k);
		प्रत्यागम SSH_ERR_किल्ली_TYPE_MISMATCH;
	}
	यदि (किल्ली_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		प्रत्यागम SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, परिमाण(*k));

	/* success */
	*cpp = cp;
	प्रत्यागम 0;
}

पूर्णाङ्क
sshkey_to_base64(ध्रुव संरचना sshkey *किल्ली, वर्ण **b64p)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *b = रिक्त;
	वर्ण *uu = रिक्त;

	यदि (b64p != रिक्त)
		*b64p = रिक्त;
	यदि ((b = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshkey_putb(किल्ली, b)) != 0)
		गच्छ out;
	यदि ((uu = sshbuf_dtob64_string(b, 0)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	/* Success */
	यदि (b64p != रिक्त) {
		*b64p = uu;
		uu = रिक्त;
	}
	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(uu);
	प्रत्यागम r;
}

पूर्णाङ्क
sshkey_format_text(ध्रुव संरचना sshkey *किल्ली, संरचना sshbuf *b)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	वर्ण *uu = रिक्त;

	यदि ((r = sshkey_to_base64(किल्ली, &uu)) != 0)
		गच्छ out;
	यदि ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(किल्ली), uu)) != 0)
		गच्छ out;
	r = 0;
 out:
	मुक्त(uu);
	प्रत्यागम r;
}

पूर्णाङ्क
sshkey_write(ध्रुव संरचना sshkey *किल्ली, FILE *f)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	यदि ((b = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshkey_format_text(किल्ली, b)) != 0)
		गच्छ out;
	यदि (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		यदि (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		गच्छ out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	प्रत्यागम r;
}

ध्रुव वर्ण *
sshkey_cert_type(ध्रुव संरचना sshkey *k)
{
	विकल्प (k->cert->type) {
	पक्ष SSH2_CERT_TYPE_USER:
		प्रत्यागम "user";
	पक्ष SSH2_CERT_TYPE_HOST:
		प्रत्यागम "host";
	स्वभाव:
		प्रत्यागम "unknown";
	}
}

पूर्णाङ्क
sshkey_check_rsa_length(ध्रुव संरचना sshkey *k, पूर्णाङ्क min_size)
{
#ifdef WITH_OPENSSL
	पूर्णाङ्क nbits;

	यदि (k == रिक्त || k->pkey == रिक्त ||
	    (k->type != किल्ली_RSA && k->type != किल्ली_RSA_CERT))
		प्रत्यागम 0;
	nbits = EVP_PKEY_bits(k->pkey);
	यदि (nbits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    (min_size > 0 && nbits < min_size))
		प्रत्यागम SSH_ERR_किल्ली_LENGTH;
#endif /* WITH_OPENSSL */
	प्रत्यागम 0;
}

#ifdef WITH_OPENSSL
पूर्णाङ्क
sshkey_ecdsa_किल्ली_to_nid(ध्रुव EC_किल्ली *k)
{
	ध्रुव EC_GROUP *g;
	पूर्णाङ्क nid;

	यदि (k == रिक्त || (g = EC_किल्ली_get0_group(k)) == रिक्त)
		प्रत्यागम -1;
	यदि ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		प्रत्यागम -1;
	प्रत्यागम nid;
}

पूर्णाङ्क
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	प्रत्यागम sshkey_ecdsa_किल्ली_to_nid(EVP_PKEY_get0_EC_किल्ली(pkey));
}
#endif /* WITH_OPENSSL */

पूर्णाङ्क
sshkey_generate(पूर्णाङ्क type, u_int bits, संरचना sshkey **keyp)
{
	संरचना sshkey *k;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;
	ध्रुव संरचना sshkey_impl *impl;

	यदि (keyp == रिक्त || sshkey_type_is_cert(type))
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	*keyp = रिक्त;
	यदि ((impl = sshkey_impl_from_type(type)) == रिक्त)
		प्रत्यागम SSH_ERR_किल्ली_TYPE_UNKNOWN;
	यदि (impl->funcs->generate == रिक्त)
		प्रत्यागम SSH_ERR_FEATURE_UNSUPPORTED;
	यदि ((k = sshkey_new(किल्ली_UNSPEC)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	k->type = type;
	यदि ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		प्रत्यागम ret;
	}
	/* success */
	*keyp = k;
	प्रत्यागम 0;
}

पूर्णाङ्क
sshkey_cert_copy(ध्रुव संरचना sshkey *from_किल्ली, संरचना sshkey *to_किल्ली)
{
	u_int i;
	ध्रुव संरचना sshkey_cert *from;
	संरचना sshkey_cert *to;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	यदि (to_किल्ली == रिक्त || (from = from_किल्ली->cert) == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;

	यदि ((to = cert_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;

	यदि ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		गच्छ out;

	to->serial = from->serial;
	to->type = from->type;
	यदि (from->किल्ली_id == रिक्त)
		to->किल्ली_id = रिक्त;
	अन्यथा यदि ((to->किल्ली_id = strdup(from->किल्ली_id)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	यदि (from->signature_किल्ली == रिक्त)
		to->signature_किल्ली = रिक्त;
	अन्यथा यदि ((r = sshkey_from_private(from->signature_किल्ली,
	    &to->signature_किल्ली)) != 0)
		गच्छ out;
	यदि (from->signature_type != रिक्त &&
	    (to->signature_type = strdup(from->signature_type)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	यदि (from->nprincipals > 0) {
		यदि ((to->principals = calloc(from->nprincipals,
		    परिमाण(*to->principals))) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		प्रति (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			यदि (to->principals[i] == रिक्त) {
				to->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				गच्छ out;
			}
		}
	}
	to->nprincipals = from->nprincipals;

	/* success */
	cert_free(to_किल्ली->cert);
	to_किल्ली->cert = to;
	to = रिक्त;
	r = 0;
 out:
	cert_free(to);
	प्रत्यागम r;
}

पूर्णाङ्क
sshkey_copy_public_sk(ध्रुव संरचना sshkey *from, संरचना sshkey *to)
{
	/* Append security-key application string */
	यदि ((to->sk_application = strdup(from->sk_application)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	प्रत्यागम 0;
}

पूर्णाङ्क
sshkey_from_private(ध्रुव संरचना sshkey *k, संरचना sshkey **pkp)
{
	संरचना sshkey *n = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	ध्रुव संरचना sshkey_impl *impl;

	*pkp = रिक्त;
	यदि ((impl = sshkey_impl_from_किल्ली(k)) == रिक्त)
		प्रत्यागम SSH_ERR_किल्ली_TYPE_UNKNOWN;
	यदि ((n = sshkey_new(k->type)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = impl->funcs->copy_public(k, n)) != 0)
		गच्छ out;
	यदि (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		गच्छ out;
	/* success */
	*pkp = n;
	n = रिक्त;
	r = 0;
 out:
	sshkey_free(n);
	प्रत्यागम r;
}

पूर्णाङ्क
sshkey_is_shielded(संरचना sshkey *k)
{
	प्रत्यागम k != रिक्त && k->shielded_private != रिक्त;
}

पूर्णाङ्क
sshkey_shield_private(संरचना sshkey *k)
{
	संरचना sshbuf *prvbuf = रिक्त;
	u_char *prekey = रिक्त, *enc = रिक्त, keyiv[SSH_DIGEST_MAX_LENGTH];
	संरचना sshcipher_ctx *cctx = रिक्त;
	ध्रुव संरचना sshcipher *cipher;
	size_t i, enclen = 0;
	संरचना sshkey *kswap = रिक्त, tmp;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	यदि ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == रिक्त) {
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	यदि (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		गच्छ out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	यदि ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		गच्छ out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	यदि ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		गच्छ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	यदि ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		गच्छ out;

	/* Serialise and encrypt the private key using the ephemeral key */
	यदि ((prvbuf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		गच्छ out;
	यदि ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		गच्छ out;
	/* pad to cipher blocksize */
	i = 0;
	यावत् (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		यदि ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			गच्छ out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	यदि ((enc = malloc(enclen)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		गच्छ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	यदि ((r = sshkey_from_private(k, &kswap)) != 0)
		गच्छ out;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_private = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = रिक्त; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 out:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, परिमाण(keyiv));
	explicit_bzero(&tmp, परिमाण(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	प्रत्यागम r;
}

/* Check deterministic padding after private key */
स्थिर पूर्णाङ्क
private2_check_padding(संरचना sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	पूर्णाङ्क r;

	i = 0;
	यावत् (sshbuf_len(decrypted)) {
		यदि ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			गच्छ out;
		यदि (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, परिमाण(pad));
	explicit_bzero(&i, परिमाण(i));
	प्रत्यागम r;
}

पूर्णाङ्क
sshkey_unshield_private(संरचना sshkey *k)
{
	संरचना sshbuf *prvbuf = रिक्त;
	u_char *cp, keyiv[SSH_DIGEST_MAX_LENGTH];
	संरचना sshcipher_ctx *cctx = रिक्त;
	ध्रुव संरचना sshcipher *cipher;
	संरचना sshkey *kswap = रिक्त, tmp;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	यदि (!sshkey_is_shielded(k))
		प्रत्यागम 0; /* nothing to do */

	यदि ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == रिक्त) {
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	यदि (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		गच्छ out;
	}
	/* check size of shielded key blob */
	यदि (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}

	/* Calculate the ephemeral key from the prekey */
	यदि ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		गच्छ out;
	यदि ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		गच्छ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	यदि ((prvbuf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		गच्छ out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(k->shielded_private, k->shielded_len, stderr);
#endif
	यदि ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		गच्छ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	यदि ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		गच्छ out;

	यदि ((r = private2_check_padding(prvbuf)) != 0)
		गच्छ out;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 out:
	cipher_free(cctx);
	explicit_bzero(keyiv, परिमाण(keyiv));
	explicit_bzero(&tmp, परिमाण(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
cert_parse(संरचना sshbuf *b, संरचना sshkey *किल्ली, संरचना sshbuf *certbuf,
    ध्रुव वर्ण *ca_sigalg_allowlist)
{
	संरचना sshbuf *principals = रिक्त, *crit = रिक्त;
	संरचना sshbuf *exts = रिक्त, *ca = रिक्त;
	u_char *sig = रिक्त;
	वर्ण *sigtype = रिक्त;
	size_t signed_len = 0, slen = 0, kidlen = 0;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	यदि ((ret = sshbuf_putb(किल्ली->cert->certblob, certbuf)) != 0)
		प्रत्यागम ret;

	/* Parse body of certificate up to signature */
	यदि ((ret = sshbuf_get_u64(b, &किल्ली->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &किल्ली->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &किल्ली->cert->किल्ली_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &किल्ली->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &किल्ली->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, रिक्त, रिक्त)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(किल्ली->cert->certblob) - sshbuf_len(b);

	यदि ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}

	/* Is this a signature we're prepared to accept? */
	यदि ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि (ca_sigalg_allowlist != रिक्त &&
	    match_pattern_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		गच्छ out;
	}

	/* Parse CA key and check whether we might accept it */
	यदि (sshkey_from_blob_internal(ca, &किल्ली->cert->signature_किल्ली, 0,
	    ca_sigalg_allowlist, रिक्त) != 0) {
		ret = SSH_ERR_किल्ली_CERT_INVALID_SIGN_किल्ली;
		गच्छ out;
	}
	यदि (!sshkey_type_is_valid_ca(किल्ली->cert->signature_किल्ली->type)) {
		ret = SSH_ERR_किल्ली_CERT_INVALID_SIGN_किल्ली;
		गच्छ out;
	}

	यदि (किल्ली->cert->type != SSH2_CERT_TYPE_USER &&
	    किल्ली->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_किल्ली_CERT_UNKNOWN_TYPE;
		गच्छ out;
	}

	/* Parse principals section */
	यावत् (sshbuf_len(principals) > 0) {
		वर्ण *principal = रिक्त;
		वर्ण **oprincipals = रिक्त;

		यदि (किल्ली->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		यदि ((ret = sshbuf_get_cstring(principals, &principal,
		    रिक्त)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		oprincipals = किल्ली->cert->principals;
		किल्ली->cert->principals = recallocarray(किल्ली->cert->principals,
		    किल्ली->cert->nprincipals, किल्ली->cert->nprincipals + 1,
		    परिमाण(*किल्ली->cert->principals));
		यदि (किल्ली->cert->principals == रिक्त) {
			मुक्त(principal);
			किल्ली->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		किल्ली->cert->principals[किल्ली->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	यदि ((ret = sshbuf_putb(किल्ली->cert->critical, crit)) != 0 ||
	    (exts != रिक्त &&
	    (ret = sshbuf_putb(किल्ली->cert->extensions, exts)) != 0))
		गच्छ out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	यावत् (sshbuf_len(crit) != 0) {
		यदि ((ret = sshbuf_get_string_direct(crit, रिक्त, रिक्त)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, रिक्त, रिक्त)) != 0) {
			sshbuf_reset(किल्ली->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
	}
	यावत् (exts != रिक्त && sshbuf_len(exts) != 0) {
		यदि ((ret = sshbuf_get_string_direct(exts, रिक्त, रिक्त)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, रिक्त, रिक्त)) != 0) {
			sshbuf_reset(किल्ली->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
	}

	/* Finally, validate signature */
	यदि ((ret = sshkey_verify(किल्ली->cert->signature_किल्ली, sig, slen,
	    sshbuf_ptr(किल्ली->cert->certblob), signed_len, रिक्त, 0, रिक्त)) != 0)
		गच्छ out;

	/* Success */
	ret = 0;
	किल्ली->cert->signature_type = sigtype;
	sigtype = रिक्त;
 out:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	मुक्त(sig);
	मुक्त(sigtype);
	प्रत्यागम ret;
}

पूर्णाङ्क
sshkey_deserialize_sk(संरचना sshbuf *b, संरचना sshkey *किल्ली)
{
	/* Parse additional security-key application string */
	यदि (sshbuf_get_cstring(b, &किल्ली->sk_application, रिक्त) != 0)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
sshkey_from_blob_internal(संरचना sshbuf *b, संरचना sshkey **keyp,
    पूर्णाङ्क allow_cert, ध्रुव वर्ण *alg_allowlist, ध्रुव वर्ण *ca_sigalg_allowlist)
{
	पूर्णाङ्क type, ret = SSH_ERR_INTERNAL_ERROR;
	वर्ण *ktype = रिक्त;
	संरचना sshkey *किल्ली = रिक्त;
	संरचना sshbuf *copy;
	ध्रुव संरचना sshkey_impl *impl;

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	यदि (keyp != रिक्त)
		*keyp = रिक्त;
	यदि ((copy = sshbuf_fromb(b)) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (sshbuf_get_cstring(b, &ktype, रिक्त) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}

	type = sshkey_type_from_name(ktype);
	यदि (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_किल्ली_CERT_INVALID_SIGN_किल्ली;
		गच्छ out;
	}

	यदि (alg_allowlist != रिक्त &&
	    !sshkey_match_keyname_to_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_किल्ली_ALG_UNSUPPORTED;
		गच्छ out;
	}

	यदि ((impl = sshkey_impl_from_type(type)) == रिक्त) {
		ret = SSH_ERR_किल्ली_TYPE_UNKNOWN;
		गच्छ out;
	}
	यदि ((किल्ली = sshkey_new(type)) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		यदि (sshbuf_get_string_direct(b, रिक्त, रिक्त) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
	}
	यदि ((ret = impl->funcs->deserialize_public(ktype, b, किल्ली)) != 0)
		गच्छ out;

	/* Parse certificate potion */
	यदि (sshkey_is_cert(किल्ली) &&
	    (ret = cert_parse(b, किल्ली, copy, ca_sigalg_allowlist)) != 0)
		गच्छ out;

	यदि (किल्ली != रिक्त && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	ret = 0;
	यदि (keyp != रिक्त) {
		*keyp = किल्ली;
		किल्ली = रिक्त;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(किल्ली);
	मुक्त(ktype);
	प्रत्यागम ret;
}

पूर्णाङ्क
sshkey_from_blob(ध्रुव u_char *blob, size_t blen, संरचना sshkey **keyp)
{
	संरचना sshbuf *b;
	पूर्णाङ्क r;

	यदि ((b = sshbuf_from(blob, blen)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1, रिक्त, रिक्त);
	sshbuf_free(b);
	प्रत्यागम r;
}

पूर्णाङ्क
sshkey_fromb(संरचना sshbuf *b, संरचना sshkey **keyp)
{
	प्रत्यागम sshkey_from_blob_internal(b, keyp, 1, रिक्त, रिक्त);
}

पूर्णाङ्क
sshkey_fromb_allowlist(संरचना sshbuf *b, संरचना sshkey **keyp,
    ध्रुव वर्ण *alg_allowlist, ध्रुव वर्ण *ca_sigalg_allowlist)
{
	प्रत्यागम sshkey_from_blob_internal(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

पूर्णाङ्क
sshkey_froms(संरचना sshbuf *buf, संरचना sshkey **keyp)
{
	संरचना sshbuf *b;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_froms(buf, &b)) != 0)
		प्रत्यागम r;
	r = sshkey_from_blob_internal(b, keyp, 1, रिक्त, रिक्त);
	sshbuf_free(b);
	प्रत्यागम r;
}

पूर्णाङ्क
sshkey_get_sigtype(ध्रुव u_char *sig, size_t siglen, वर्ण **sigtypep)
{
	पूर्णाङ्क r;
	संरचना sshbuf *b = रिक्त;
	वर्ण *sigtype = रिक्त;

	यदि (sigtypep != रिक्त)
		*sigtypep = रिक्त;
	यदि ((b = sshbuf_from(sig, siglen)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_get_cstring(b, &sigtype, रिक्त)) != 0)
		गच्छ out;
	/* success */
	यदि (sigtypep != रिक्त) {
		*sigtypep = sigtype;
		sigtype = रिक्त;
	}
	r = 0;
 out:
	मुक्त(sigtype);
	sshbuf_free(b);
	प्रत्यागम r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
पूर्णाङ्क
sshkey_check_cert_sigtype(ध्रुव संरचना sshkey *किल्ली, ध्रुव वर्ण *allowed)
{
	यदि (किल्ली == रिक्त || allowed == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि (!sshkey_type_is_cert(किल्ली->type))
		प्रत्यागम 0;
	यदि (किल्ली->cert == रिक्त || किल्ली->cert->signature_type == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि (match_pattern_list(किल्ली->cert->signature_type, allowed, 0) != 1)
		प्रत्यागम SSH_ERR_SIGN_ALG_UNSUPPORTED;
	प्रत्यागम 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
ध्रुव वर्ण *
sshkey_sigalg_by_name(ध्रुव वर्ण *name)
{
	ध्रुव संरचना sshkey_impl *impl;
	पूर्णाङ्क i;

	प्रति (i = 0; keyimpls[i] != रिक्त; i++) {
		impl = keyimpls[i];
		यदि (strcmp(impl->name, name) != 0)
			अनुवर्त;
		यदि (impl->sigalg != रिक्त)
			प्रत्यागम impl->sigalg;
		यदि (!impl->cert)
			प्रत्यागम impl->name;
		प्रत्यागम sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	प्रत्यागम रिक्त;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
पूर्णाङ्क
sshkey_check_sigtype(ध्रुव u_char *sig, size_t siglen,
    ध्रुव वर्ण *requested_alg)
{
	ध्रुव वर्ण *expected_alg;
	वर्ण *sigtype = रिक्त;
	पूर्णाङ्क r;

	यदि (requested_alg == रिक्त)
		प्रत्यागम 0;
	यदि ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		प्रत्यागम r;
	r = strcmp(expected_alg, sigtype) == 0;
	मुक्त(sigtype);
	प्रत्यागम r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

पूर्णाङ्क
sshkey_sign(संरचना sshkey *किल्ली,
    u_char **sigp, size_t *lenp,
    ध्रुव u_char *data, size_t datalen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin, u_int compat)
{
	पूर्णाङ्क was_shielded = sshkey_is_shielded(किल्ली);
	पूर्णाङ्क r2, r = SSH_ERR_INTERNAL_ERROR;
	ध्रुव संरचना sshkey_impl *impl;

	यदि (sigp != रिक्त)
		*sigp = रिक्त;
	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (datalen > SSH_किल्ली_MAX_SIGN_DATA_SIZE)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि ((impl = sshkey_impl_from_किल्ली(किल्ली)) == रिक्त)
		प्रत्यागम SSH_ERR_किल्ली_TYPE_UNKNOWN;
	यदि ((r = sshkey_unshield_private(किल्ली)) != 0)
		प्रत्यागम r;
	यदि (sshkey_is_sk(किल्ली)) {
		r = sshsk_sign(sk_provider, किल्ली, sigp, lenp, data,
		    datalen, compat, sk_pin);
	} अन्यथा यदि ((किल्ली->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(किल्ली, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	} अन्यथा {
		यदि (impl->funcs->sign == रिक्त)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		अन्यथा {
			r = impl->funcs->sign(किल्ली, sigp, lenp, data, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	यदि (was_shielded && (r2 = sshkey_shield_private(किल्ली)) != 0)
		प्रत्यागम r2;
	प्रत्यागम r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
पूर्णाङ्क
sshkey_verify(ध्रुव संरचना sshkey *किल्ली,
    ध्रुव u_char *sig, size_t siglen,
    ध्रुव u_char *data, size_t dlen, ध्रुव वर्ण *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	ध्रुव संरचना sshkey_impl *impl;

	यदि (detailsp != रिक्त)
		*detailsp = रिक्त;
	यदि (siglen == 0 || dlen > SSH_किल्ली_MAX_SIGN_DATA_SIZE)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि ((impl = sshkey_impl_from_किल्ली(किल्ली)) == रिक्त)
		प्रत्यागम SSH_ERR_किल्ली_TYPE_UNKNOWN;
	प्रत्यागम impl->funcs->verify(किल्ली, sig, siglen, data, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
पूर्णाङ्क
sshkey_to_certified(संरचना sshkey *k)
{
	पूर्णाङ्क newtype;

	यदि ((newtype = sshkey_type_certified(k->type)) == -1)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि ((k->cert = cert_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	प्रत्यागम 0;
}

/* Convert a certificate to its raw key equivalent */
पूर्णाङ्क
sshkey_drop_cert(संरचना sshkey *k)
{
	यदि (!sshkey_type_is_cert(k->type))
		प्रत्यागम SSH_ERR_किल्ली_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = रिक्त;
	k->type = sshkey_type_plain(k->type);
	प्रत्यागम 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
पूर्णाङ्क
sshkey_certify_custom(संरचना sshkey *k, संरचना sshkey *ca, ध्रुव वर्ण *alg,
    ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin,
    sshkey_certify_signer *signer, शून्य *signer_ctx)
{
	ध्रुव संरचना sshkey_impl *impl;
	संरचना sshbuf *principals = रिक्त;
	u_char *ca_blob = रिक्त, *sig_blob = रिक्त, nonce[32];
	size_t i, ca_len, sig_len;
	पूर्णाङ्क ret = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *cert = रिक्त;
	वर्ण *sigtype = रिक्त;

	यदि (k == रिक्त || k->cert == रिक्त ||
	    k->cert->certblob == रिक्त || ca == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि (!sshkey_is_cert(k))
		प्रत्यागम SSH_ERR_किल्ली_TYPE_UNKNOWN;
	यदि (!sshkey_type_is_valid_ca(ca->type))
		प्रत्यागम SSH_ERR_किल्ली_CERT_INVALID_SIGN_किल्ली;
	यदि ((impl = sshkey_impl_from_किल्ली(k)) == रिक्त)
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	यदि (alg == रिक्त)
		alg = k->cert->signature_type;
	अन्यथा यदि (k->cert->signature_type != रिक्त &&
	    strcmp(alg, k->cert->signature_type) != 0)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	यदि (alg == रिक्त && ca->type == किल्ली_RSA)
		alg = "rsa-sha2-512";

	यदि ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		प्रत्यागम SSH_ERR_किल्ली_CERT_INVALID_SIGN_किल्ली;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	यदि ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		गच्छ out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, परिमाण(nonce));
	यदि ((ret = sshbuf_put_string(cert, nonce, परिमाण(nonce))) != 0)
		गच्छ out;

	/* Public key next */
	यदि ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		गच्छ out;

	/* Then remaining cert fields */
	यदि ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->किल्ली_id)) != 0)
		गच्छ out;

	यदि ((principals = sshbuf_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	प्रति (i = 0; i < k->cert->nprincipals; i++) {
		यदि ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			गच्छ out;
	}
	यदि ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, रिक्त, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		गच्छ out;

	/* Sign the whole mess */
	यदि ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		गच्छ out;
	/* Check and update signature_type against what was actually used */
	यदि ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		गच्छ out;
	यदि (alg != रिक्त && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		गच्छ out;
	}
	यदि (k->cert->signature_type == रिक्त) {
		k->cert->signature_type = sigtype;
		sigtype = रिक्त;
	}
	/* Append signature and we are done */
	यदि ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		गच्छ out;
	ret = 0;
 out:
	यदि (ret != 0)
		sshbuf_reset(cert);
	मुक्त(sig_blob);
	मुक्त(ca_blob);
	मुक्त(sigtype);
	sshbuf_free(principals);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
default_किल्ली_sign(संरचना sshkey *किल्ली, u_char **sigp, size_t *lenp,
    ध्रुव u_char *data, size_t datalen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin,
    u_int compat, शून्य *ctx)
{
	यदि (ctx != रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	प्रत्यागम sshkey_sign(किल्ली, sigp, lenp, data, datalen, alg,
	    sk_provider, sk_pin, compat);
}

पूर्णाङ्क
sshkey_certify(संरचना sshkey *k, संरचना sshkey *ca, ध्रुव वर्ण *alg,
    ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin)
{
	प्रत्यागम sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_किल्ली_sign, रिक्त);
}

पूर्णाङ्क
sshkey_cert_check_authority(ध्रुव संरचना sshkey *k,
    पूर्णाङ्क want_host, पूर्णाङ्क wildcard_pattern, uint64_t verify_time,
    ध्रुव वर्ण *name, ध्रुव वर्ण **reason)
{
	u_int i, principal_matches;

	यदि (reason == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		प्रत्यागम SSH_ERR_किल्ली_CERT_INVALID;
	}
	यदि (want_host) {
		यदि (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			प्रत्यागम SSH_ERR_किल्ली_CERT_INVALID;
		}
	} अन्यथा {
		यदि (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			प्रत्यागम SSH_ERR_किल्ली_CERT_INVALID;
		}
	}
	यदि (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		प्रत्यागम SSH_ERR_किल्ली_CERT_INVALID;
	}
	यदि (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		प्रत्यागम SSH_ERR_किल्ली_CERT_INVALID;
	}
	यदि (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		प्रत्यागम SSH_ERR_किल्ली_CERT_INVALID;
	}
	यदि (name == रिक्त)
		प्रत्यागम 0; /* principal matching not requested */

	principal_matches = 0;
	प्रति (i = 0; i < k->cert->nprincipals; i++) {
		यदि (wildcard_pattern) {
			यदि (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				भङ्ग;
			}
		} अन्यथा यदि (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			भङ्ग;
		}
	}
	यदि (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		प्रत्यागम SSH_ERR_किल्ली_CERT_INVALID;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
sshkey_cert_check_authority_now(ध्रुव संरचना sshkey *k,
    पूर्णाङ्क want_host, पूर्णाङ्क wildcard_pattern, ध्रुव वर्ण *name,
    ध्रुव वर्ण **reason)
{
	time_t now;

	यदि ((now = time(रिक्त)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		प्रत्यागम SSH_ERR_किल्ली_CERT_INVALID;
	}
	प्रत्यागम sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

पूर्णाङ्क
sshkey_cert_check_host(ध्रुव संरचना sshkey *किल्ली, ध्रुव वर्ण *host,
    ध्रुव वर्ण *ca_sign_algorithms, ध्रुव वर्ण **reason)
{
	पूर्णाङ्क r;

	यदि ((r = sshkey_cert_check_authority_now(किल्ली, 1, 1, host, reason)) != 0)
		प्रत्यागम r;
	यदि (sshbuf_len(किल्ली->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		प्रत्यागम SSH_ERR_किल्ली_CERT_INVALID;
	}
	यदि (ca_sign_algorithms != रिक्त &&
	    (r = sshkey_check_cert_sigtype(किल्ली, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		प्रत्यागम SSH_ERR_किल्ली_CERT_INVALID;
	}
	प्रत्यागम 0;
}

size_t
sshkey_format_cert_validity(ध्रुव संरचना sshkey_cert *cert, वर्ण *s, size_t l)
{
	वर्ण from[32], to[32], ret[128];

	*from = *to = '\0';
	यदि (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		प्रत्यागम strlcpy(s, "forever", l);

	यदि (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, परिमाण(from));
	यदि (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, परिमाण(to));

	यदि (cert->valid_after == 0)
		snprintf(ret, परिमाण(ret), "before %s", to);
	अन्यथा यदि (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, परिमाण(ret), "after %s", from);
	अन्यथा
		snprintf(ret, परिमाण(ret), "from %s to %s", from, to);

	प्रत्यागम strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
पूर्णाङ्क
sshkey_serialize_private_sk(ध्रुव संरचना sshkey *किल्ली, संरचना sshbuf *b)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_cstring(b, किल्ली->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, किल्ली->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, किल्ली->sk_किल्ली_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, किल्ली->sk_reserved)) != 0)
		प्रत्यागम r;

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
sshkey_private_serialize_opt(संरचना sshkey *किल्ली, संरचना sshbuf *buf,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	पूर्णाङ्क was_shielded = sshkey_is_shielded(किल्ली);
	संरचना sshbuf *b = रिक्त;
	ध्रुव संरचना sshkey_impl *impl;

	यदि ((impl = sshkey_impl_from_किल्ली(किल्ली)) == रिक्त)
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	यदि ((r = sshkey_unshield_private(किल्ली)) != 0)
		प्रत्यागम r;
	यदि ((b = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_put_cstring(b, sshkey_ssh_name(किल्ली))) != 0)
		गच्छ out;
	यदि (sshkey_is_cert(किल्ली)) {
		यदि (किल्ली->cert == रिक्त ||
		    sshbuf_len(किल्ली->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			गच्छ out;
		}
		यदि ((r = sshbuf_put_stringb(b, किल्ली->cert->certblob)) != 0)
			गच्छ out;
	}
	यदि ((r = impl->funcs->serialize_private(किल्ली, b, opts)) != 0)
		गच्छ out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	यदि (was_shielded)
		r = sshkey_shield_private(किल्ली);
	यदि (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	प्रत्यागम r;
}

पूर्णाङ्क
sshkey_private_serialize(संरचना sshkey *किल्ली, संरचना sshbuf *b)
{
	प्रत्यागम sshkey_private_serialize_opt(किल्ली, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
पूर्णाङ्क
sshkey_private_deserialize_sk(संरचना sshbuf *buf, संरचना sshkey *k)
{
	पूर्णाङ्क r;

	यदि ((k->sk_किल्ली_handle = sshbuf_new()) == रिक्त ||
	    (k->sk_reserved = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_get_cstring(buf, &k->sk_application, रिक्त)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_किल्ली_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		प्रत्यागम r;

	प्रत्यागम 0;
}

पूर्णाङ्क
sshkey_private_deserialize(संरचना sshbuf *buf, संरचना sshkey **kp)
{
	ध्रुव संरचना sshkey_impl *impl;
	वर्ण *tname = रिक्त;
	वर्ण *expect_sk_application = रिक्त;
	u_char *expect_ed25519_pk = रिक्त;
	संरचना sshkey *k = रिक्त;
	पूर्णाङ्क type, r = SSH_ERR_INTERNAL_ERROR;

	यदि (kp != रिक्त)
		*kp = रिक्त;
	यदि ((r = sshbuf_get_cstring(buf, &tname, रिक्त)) != 0)
		गच्छ out;
	type = sshkey_type_from_name(tname);
	यदि (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		यदि ((r = sshkey_froms(buf, &k)) != 0)
			गच्छ out;
		यदि (k->type != type) {
			r = SSH_ERR_किल्ली_CERT_MISMATCH;
			गच्छ out;
		}
		/* For ECDSA keys, the group must match too */
		यदि (k->type == किल्ली_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_किल्ली_CERT_MISMATCH;
			गच्छ out;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = रिक्त;
		k->ed25519_pk = रिक्त;
	} अन्यथा {
		यदि ((k = sshkey_new(type)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
	}
	यदि ((impl = sshkey_impl_from_type(type)) == रिक्त) {
		r = SSH_ERR_INTERNAL_ERROR;
		गच्छ out;
	}
	यदि ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		गच्छ out;

	यदि ((expect_sk_application != रिक्त && (k->sk_application == रिक्त ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != रिक्त && (k->ed25519_pk == रिक्त ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_किल्ली_CERT_MISMATCH;
		गच्छ out;
	}
	/* success */
	r = 0;
	यदि (kp != रिक्त) {
		*kp = k;
		k = रिक्त;
	}
 out:
	मुक्त(tname);
	sshkey_free(k);
	मुक्त(expect_sk_application);
	मुक्त(expect_ed25519_pk);
	प्रत्यागम r;
}

#ifdef WITH_OPENSSL
पूर्णाङ्क
sshkey_ec_validate_public(ध्रुव EC_GROUP *group, ध्रुव EC_POINT *सार्वजनिक)
{
	EC_POINT *nq = रिक्त;
	BIGNUM *order = रिक्त, *cofactor = रिक्त;
	पूर्णाङ्क ret = SSH_ERR_किल्ली_INVALID_EC_मूल्य;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	यदि (EC_POINT_is_at_infinity(group, सार्वजनिक))
		गच्छ out;

	यदि ((cofactor = BN_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (EC_GROUP_get_cofactor(group, cofactor, रिक्त) != 1)
		गच्छ out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	यदि (!BN_is_one(cofactor)) {
		यदि ((order = BN_new()) == रिक्त) {
			ret = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		यदि (EC_GROUP_get_order(group, order, रिक्त) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
		यदि ((nq = EC_POINT_new(group)) == रिक्त) {
			ret = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		यदि (EC_POINT_mul(group, nq, रिक्त, सार्वजनिक, order, रिक्त) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
		यदि (EC_POINT_is_at_infinity(group, nq) != 1)
			गच्छ out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	प्रत्यागम ret;
}

पूर्णाङ्क
sshkey_ec_validate_private(ध्रुव EC_किल्ली *किल्ली)
{
	BIGNUM *order = रिक्त, *tmp = रिक्त;
	पूर्णाङ्क ret = SSH_ERR_किल्ली_INVALID_EC_मूल्य;

	यदि ((order = BN_new()) == रिक्त || (tmp = BN_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	/* log2(private) > log2(order)/2 */
	यदि (EC_GROUP_get_order(EC_किल्ली_get0_group(किल्ली), order, रिक्त) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	यदि (BN_अंक_bits(EC_किल्ली_get0_private_किल्ली(किल्ली)) <=
	    BN_अंक_bits(order) / 2)
		गच्छ out;

	/* private < order - 1 */
	यदि (!BN_sub(tmp, order, BN_मूल्य_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	यदि (BN_cmp(EC_किल्ली_get0_private_किल्ली(किल्ली), tmp) >= 0)
		गच्छ out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	प्रत्यागम ret;
}

शून्य
sshkey_dump_ec_point(ध्रुव EC_GROUP *group, ध्रुव EC_POINT *point)
{
	BIGNUM *x = रिक्त, *y = रिक्त;

	यदि (point == रिक्त) {
		fputs("point=(NULL)\n", stderr);
		प्रत्यागम;
	}
	यदि ((x = BN_new()) == रिक्त || (y = BN_new()) == रिक्त) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		गच्छ out;
	}
	यदि (EC_POINT_get_affine_coordinates(group, point, x, y, रिक्त) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		गच्छ out;
	}
	fputs("x=", stderr);
	BN_print_fp(stderr, x);
	fputs("\ny=", stderr);
	BN_print_fp(stderr, y);
	fputs("\n", stderr);
 out:
	BN_clear_free(x);
	BN_clear_free(y);
}

शून्य
sshkey_dump_ec_किल्ली(ध्रुव EC_किल्ली *किल्ली)
{
	ध्रुव BIGNUM *exponent;

	sshkey_dump_ec_point(EC_किल्ली_get0_group(किल्ली),
	    EC_किल्ली_get0_public_किल्ली(किल्ली));
	fputs("exponent=", stderr);
	यदि ((exponent = EC_किल्ली_get0_private_किल्ली(किल्ली)) == रिक्त)
		fputs("(NULL)", stderr);
	अन्यथा
		BN_print_fp(stderr, EC_किल्ली_get0_private_किल्ली(किल्ली));
	fputs("\n", stderr);
}
#endif /* WITH_OPENSSL */

स्थिर पूर्णाङ्क
sshkey_private_to_blob2(संरचना sshkey *prv, संरचना sshbuf *blob,
    ध्रुव वर्ण *passphrase, ध्रुव वर्ण *comment, ध्रुव वर्ण *ciphername,
    पूर्णाङ्क rounds)
{
	u_char *cp, *किल्ली = रिक्त, *pubkeyblob = रिक्त;
	u_char salt[SALT_LEN];
	size_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshcipher_ctx *ciphercontext = रिक्त;
	ध्रुव संरचना sshcipher *cipher;
	ध्रुव वर्ण *kdfname = KDFNAME;
	संरचना sshbuf *encoded = रिक्त, *encrypted = रिक्त, *kdf = रिक्त;

	यदि (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	यदि (rounds > MAX_KDF_ROUNDS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	यदि (passphrase == रिक्त || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} अन्यथा यदि (ciphername == रिक्त)
		ciphername = DEFAULT_CIPHERNAME;
	यदि ((cipher = cipher_by_name(ciphername)) == रिक्त) {
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}

	यदि ((kdf = sshbuf_new()) == रिक्त ||
	    (encoded = sshbuf_new()) == रिक्त ||
	    (encrypted = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	यदि ((किल्ली = calloc(1, keylen + ivlen)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		यदि (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, किल्ली, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			गच्छ out;
		}
		यदि ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			गच्छ out;
	} अन्यथा यदि (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_किल्ली_UNKNOWN_CIPHER;
		गच्छ out;
	}
	यदि ((r = cipher_init(&ciphercontext, cipher, किल्ली, keylen,
	    किल्ली + keylen, ivlen, 1)) != 0)
		गच्छ out;

	यदि ((r = sshbuf_put(encoded, AUTH_MAGIC, परिमाण(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_to_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		गच्छ out;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	यदि ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		गच्छ out;

	/* append private key and comment*/
	यदि ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		गच्छ out;

	/* padding */
	i = 0;
	यावत् (sshbuf_len(encrypted) % blocksize) {
		यदि ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			गच्छ out;
	}

	/* length in destination buffer */
	यदि ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		गच्छ out;

	/* encrypt */
	यदि ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		गच्छ out;
	यदि ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		गच्छ out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	यदि ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_END, MARK_END_LEN)) != 0)
		गच्छ out;

	/* success */
	r = 0;

 out:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, परिमाण(salt));
	यदि (किल्ली != रिक्त)
		freezero(किल्ली, keylen + ivlen);
	यदि (pubkeyblob != रिक्त)
		freezero(pubkeyblob, pubkeylen);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
private2_uudecode(संरचना sshbuf *blob, संरचना sshbuf **decodedp)
{
	ध्रुव u_char *cp;
	size_t encoded_len;
	पूर्णाङ्क r;
	u_char last;
	संरचना sshbuf *encoded = रिक्त, *decoded = रिक्त;

	यदि (blob == रिक्त || decodedp == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;

	*decodedp = रिक्त;

	यदि ((encoded = sshbuf_new()) == रिक्त ||
	    (decoded = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	यदि (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	यावत् (encoded_len > 0) {
		यदि (*cp != '\n' && *cp != '\r') {
			यदि ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				गच्छ out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		यदि (last == '\n') {
			यदि (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				यदि ((r = sshbuf_put_u8(encoded, 0)) != 0)
					गच्छ out;
				भङ्ग;
			}
		}
	}
	यदि (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}

	/* decode base64 */
	यदि ((r = sshbuf_b64tod(decoded, (वर्ण *)sshbuf_ptr(encoded))) != 0)
		गच्छ out;

	/* check magic */
	यदि (sshbuf_len(decoded) < परिमाण(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, परिमाण(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	/* success */
	*decodedp = decoded;
	decoded = रिक्त;
	r = 0;
 out:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
private2_decrypt(संरचना sshbuf *decoded, ध्रुव वर्ण *passphrase,
    संरचना sshbuf **decryptedp, संरचना sshkey **pubkeyp)
{
	वर्ण *ciphername = रिक्त, *kdfname = रिक्त;
	ध्रुव संरचना sshcipher *cipher = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	संरचना sshbuf *kdf = रिक्त, *decrypted = रिक्त;
	संरचना sshcipher_ctx *ciphercontext = रिक्त;
	संरचना sshkey *pubkey = रिक्त;
	u_char *किल्ली = रिक्त, *salt = रिक्त, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	यदि (decoded == रिक्त || decryptedp == रिक्त || pubkeyp == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = रिक्त;
	*pubkeyp = रिक्त;

	यदि ((decrypted = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	/* parse public portion of key */
	यदि ((r = sshbuf_consume(decoded, परिमाण(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, रिक्त)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		गच्छ out;

	यदि (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}

	यदि ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		गच्छ out;

	यदि ((cipher = cipher_by_name(ciphername)) == रिक्त) {
		r = SSH_ERR_किल्ली_UNKNOWN_CIPHER;
		गच्छ out;
	}
	यदि (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_किल्ली_UNKNOWN_CIPHER;
		गच्छ out;
	}
	यदि (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि ((passphrase == रिक्त || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_किल्ली_WRONG_PASSPHRASE;
		गच्छ out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	यदि (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	यदि ((किल्ली = calloc(1, keylen + ivlen)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (strcmp(kdfname, "bcrypt") == 0) {
		यदि ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			गच्छ out;
		यदि (rounds > MAX_KDF_ROUNDS) {
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		यदि (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    किल्ली, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	यदि (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}

	/* decrypt private portion of key */
	यदि ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, किल्ली, keylen,
	    किल्ली + keylen, ivlen, 0)) != 0)
		गच्छ out;
	यदि ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		यदि (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_किल्ली_WRONG_PASSPHRASE;
		गच्छ out;
	}
	यदि ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		गच्छ out;
	/* there should be no trailing data */
	यदि (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}

	/* check check bytes */
	यदि ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		गच्छ out;
	यदि (check1 != check2) {
		r = SSH_ERR_किल्ली_WRONG_PASSPHRASE;
		गच्छ out;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = रिक्त;
	*pubkeyp = pubkey;
	pubkey = रिक्त;
	r = 0;
 out:
	cipher_free(ciphercontext);
	मुक्त(ciphername);
	मुक्त(kdfname);
	sshkey_free(pubkey);
	यदि (salt != रिक्त) {
		explicit_bzero(salt, slen);
		मुक्त(salt);
	}
	यदि (किल्ली != रिक्त) {
		explicit_bzero(किल्ली, keylen + ivlen);
		मुक्त(किल्ली);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
sshkey_parse_private2(संरचना sshbuf *blob, पूर्णाङ्क type, ध्रुव वर्ण *passphrase,
    संरचना sshkey **keyp, वर्ण **commentp)
{
	वर्ण *comment = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *decoded = रिक्त, *decrypted = रिक्त;
	संरचना sshkey *k = रिक्त, *pubkey = रिक्त;

	यदि (keyp != रिक्त)
		*keyp = रिक्त;
	यदि (commentp != रिक्त)
		*commentp = रिक्त;

	/* Undo base64 encoding and decrypt the private section */
	यदि ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		गच्छ out;

	यदि (type != किल्ली_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_किल्ली_TYPE_MISMATCH;
		गच्छ out;
	}

	/* Load the private key and comment */
	यदि ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, रिक्त)) != 0)
		गच्छ out;

	/* Check deterministic padding after private section */
	यदि ((r = private2_check_padding(decrypted)) != 0)
		गच्छ out;

	/* Check that the public key in the envelope matches the private key */
	यदि (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}

	/* success */
	r = 0;
	यदि (keyp != रिक्त) {
		*keyp = k;
		k = रिक्त;
	}
	यदि (commentp != रिक्त) {
		*commentp = comment;
		comment = रिक्त;
	}
 out:
	मुक्त(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
sshkey_parse_private2_pubkey(संरचना sshbuf *blob, पूर्णाङ्क type,
    संरचना sshkey **keyp)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *decoded = रिक्त;
	संरचना sshkey *pubkey = रिक्त;
	u_int nkeys = 0;

	यदि (keyp != रिक्त)
		*keyp = रिक्त;

	यदि ((r = private2_uudecode(blob, &decoded)) != 0)
		गच्छ out;
	/* parse public key from unencrypted envelope */
	यदि ((r = sshbuf_consume(decoded, परिमाण(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		गच्छ out;

	यदि (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}

	/* Parse the public key */
	यदि ((r = sshkey_froms(decoded, &pubkey)) != 0)
		गच्छ out;

	यदि (type != किल्ली_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_किल्ली_TYPE_MISMATCH;
		गच्छ out;
	}

	/* success */
	r = 0;
	यदि (keyp != रिक्त) {
		*keyp = pubkey;
		pubkey = रिक्त;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	प्रत्यागम r;
}

#ifdef WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
स्थिर पूर्णाङ्क
sshkey_private_to_blob_pem_pkcs8(संरचना sshkey *किल्ली, संरचना sshbuf *buf,
    पूर्णाङ्क format, ध्रुव वर्ण *_passphrase, ध्रुव वर्ण *comment)
{
	पूर्णाङ्क was_shielded = sshkey_is_shielded(किल्ली);
	पूर्णाङ्क success, r;
	पूर्णाङ्क blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : रिक्त;
	ध्रुव EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : रिक्त;
	वर्ण *bptr;
	BIO *bio = रिक्त;
	संरचना sshbuf *blob;
	EVP_PKEY *pkey = रिक्त;

	यदि (len > 0 && len <= 4)
		प्रत्यागम SSH_ERR_PASSPHRASE_TOO_SHORT;
	यदि ((blob = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((bio = BIO_new(BIO_s_mem())) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshkey_unshield_private(किल्ली)) != 0)
		गच्छ out;

	विकल्प (किल्ली->type) {
	पक्ष किल्ली_ECDSA:
		यदि (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivate_किल्ली(bio,
			    EVP_PKEY_get0_EC_किल्ली(किल्ली->pkey),
			    cipher, passphrase, len, रिक्त, रिक्त);
		} अन्यथा {
			pkey = किल्ली->pkey;
			EVP_PKEY_up_ref(किल्ली->pkey);
			success = 1;
		}
		भङ्ग;
	पक्ष किल्ली_RSA:
		यदि (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivate_किल्ली(bio,
			    EVP_PKEY_get0_RSA(किल्ली->pkey),
			    cipher, passphrase, len, रिक्त, रिक्त);
		} अन्यथा {
			pkey = किल्ली->pkey;
			EVP_PKEY_up_ref(किल्ली->pkey);
			success = 1;
		}
		भङ्ग;
#ifdef OPENSSL_HAS_ED25519
	पक्ष किल्ली_ED25519:
		यदि (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		} अन्यथा {
			pkey = EVP_PKEY_new_raw_private_किल्ली(EVP_PKEY_ED25519,
			    रिक्त, किल्ली->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != रिक्त;
		}
		भङ्ग;
#endif
	स्वभाव:
		success = 0;
		भङ्ग;
	}
	यदि (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	यदि (format == SSHKEY_PRIVATE_PKCS8) {
		यदि ((success = PEM_write_bio_Private_किल्ली(bio, pkey, cipher,
		    passphrase, len, रिक्त, रिक्त)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
	}
	यदि ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		गच्छ out;
	}
	यदि ((r = sshbuf_put(blob, bptr, blen)) != 0)
		गच्छ out;
	r = 0;
 out:
	यदि (was_shielded)
		r = sshkey_shield_private(किल्ली);
	यदि (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	प्रत्यागम r;
}
#endif /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
पूर्णाङ्क
sshkey_private_to_fileblob(संरचना sshkey *किल्ली, संरचना sshbuf *blob,
    ध्रुव वर्ण *passphrase, ध्रुव वर्ण *comment,
    पूर्णाङ्क format, ध्रुव वर्ण *openssh_format_cipher, पूर्णाङ्क openssh_format_rounds)
{
	विकल्प (किल्ली->type) {
#ifdef WITH_OPENSSL
	पक्ष किल्ली_ECDSA:
	पक्ष किल्ली_RSA:
	पक्ष किल्ली_ED25519:
		भङ्ग; /* see below */
#अन्यथा /* WITH_OPENSSL */
	पक्ष किल्ली_ED25519:
#endif /* WITH_OPENSSL */
	पक्ष किल्ली_ED25519_SK:
#ifdef WITH_OPENSSL
	पक्ष किल्ली_ECDSA_SK:
#endif /* WITH_OPENSSL */
	पक्ष किल्ली_MLDSA44_ED25519:
		प्रत्यागम sshkey_private_to_blob2(किल्ली, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	स्वभाव:
		प्रत्यागम SSH_ERR_किल्ली_TYPE_UNKNOWN;
	}

#ifdef WITH_OPENSSL
	विकल्प (format) {
	पक्ष SSHKEY_PRIVATE_OPENSSH:
		प्रत्यागम sshkey_private_to_blob2(किल्ली, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	पक्ष SSHKEY_PRIVATE_PEM:
	पक्ष SSHKEY_PRIVATE_PKCS8:
		प्रत्यागम sshkey_private_to_blob_pem_pkcs8(किल्ली, blob,
		    format, passphrase, comment);
	स्वभाव:
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	}
#endif /* WITH_OPENSSL */
}

#ifdef WITH_OPENSSL
स्थिर पूर्णाङ्क
translate_libcrypto_error(unsigned long pem_err)
{
	पूर्णाङ्क pem_reason = ERR_GET_REASON(pem_err);

	विकल्प (ERR_GET_LIB(pem_err)) {
	पक्ष ERR_LIB_PEM:
		विकल्प (pem_reason) {
		पक्ष PEM_R_BAD_PASSWORD_READ:
#ifdef PEM_R_PROBLEMS_GETTING_PASSWORD
		पक्ष PEM_R_PROBLEMS_GETTING_PASSWORD:
#endif
#ifdef PEM_R_BAD_DECRYPT
		पक्ष PEM_R_BAD_DECRYPT:
#endif
			प्रत्यागम SSH_ERR_किल्ली_WRONG_PASSPHRASE;
		स्वभाव:
			प्रत्यागम SSH_ERR_INVALID_FORMAT;
		}
	पक्ष ERR_LIB_EVP:
		विकल्प (pem_reason) {
#ifdef EVP_R_BAD_DECRYPT
		पक्ष EVP_R_BAD_DECRYPT:
			प्रत्यागम SSH_ERR_किल्ली_WRONG_PASSPHRASE;
#endif
#ifdef EVP_R_BN_DECODE_ERROR
		पक्ष EVP_R_BN_DECODE_ERROR:
#endif
		पक्ष EVP_R_DECODE_ERROR:
#ifdef EVP_R_PRIVATE_किल्ली_DECODE_ERROR
		पक्ष EVP_R_PRIVATE_किल्ली_DECODE_ERROR:
#endif
			प्रत्यागम SSH_ERR_INVALID_FORMAT;
		स्वभाव:
			प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
		}
	पक्ष ERR_LIB_ASN1:
#ifdef ERR_LIB_OSSL_DECODER
	पक्ष ERR_LIB_OSSL_DECODER:
#endif
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
}

स्थिर शून्य
clear_libcrypto_errors(शून्य)
{
	यावत् (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
स्थिर पूर्णाङ्क
convert_libcrypto_error(शून्य)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	यदि (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_किल्ली_WRONG_PASSPHRASE)
		प्रत्यागम SSH_ERR_किल्ली_WRONG_PASSPHRASE;
	प्रत्यागम translate_libcrypto_error(ERR_peek_last_error());
}

स्थिर पूर्णाङ्क
pem_passphrase_cb(वर्ण *buf, पूर्णाङ्क size, पूर्णाङ्क rwflag, शून्य *u)
{
	वर्ण *p = (वर्ण *)u;
	size_t len;

	यदि (p == रिक्त || (len = strlen(p)) == 0)
		प्रत्यागम -1;
	यदि (size < 0 || len > (size_t)size)
		प्रत्यागम -1;
	memcpy(buf, p, len);
	प्रत्यागम (पूर्णाङ्क)len;
}

स्थिर पूर्णाङ्क
sshkey_parse_private_pem_fileblob(संरचना sshbuf *blob, पूर्णाङ्क type,
    ध्रुव वर्ण *passphrase, संरचना sshkey **keyp)
{
	EVP_PKEY *pk = रिक्त;
	संरचना sshkey *prv = रिक्त;
	BIO *bio = रिक्त;
	पूर्णाङ्क r;
	RSA *rsa = रिक्त;
	EC_किल्ली *ecdsa = रिक्त;

	यदि (keyp != रिक्त)
		*keyp = रिक्त;

	यदि ((bio = BIO_new(BIO_s_mem())) == रिक्त || sshbuf_len(blob) > INT_MAX)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (पूर्णाङ्क)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	clear_libcrypto_errors();
	यदि ((pk = PEM_read_bio_Private_किल्ली(bio, रिक्त, pem_passphrase_cb,
	    (वर्ण *)passphrase)) == रिक्त) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		यदि (passphrase != रिक्त && *passphrase != '\0')
			r = SSH_ERR_किल्ली_WRONG_PASSPHRASE;
		अन्यथा
			r = convert_libcrypto_error();
		गच्छ out;
	}
	यदि (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == किल्ली_UNSPEC || type == किल्ली_RSA)) {
		यदि ((prv = sshkey_new(किल्ली_UNSPEC)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		यदि ((rsa = EVP_PKEY_get1_RSA(pk)) == रिक्त) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
		prv->type = किल्ली_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#endif
		यदि (RSA_blinding_on(rsa, रिक्त) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		यदि ((r = sshkey_check_rsa_length(prv, 0)) != 0)
			गच्छ out;
	} अन्यथा यदि (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == किल्ली_UNSPEC || type == किल्ली_ECDSA)) {
		यदि ((prv = sshkey_new(किल्ली_UNSPEC)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		यदि ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_किल्ली(pk)) == रिक्त) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
		prv->type = किल्ली_ECDSA;
		यदि (sshkey_curve_nid_to_name(prv->ecdsa_nid) == रिक्त ||
		    sshkey_ec_validate_public(EC_किल्ली_get0_group(ecdsa),
		    EC_किल्ली_get0_public_किल्ली(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#ifdef DEBUG_PK
		यदि (prv != रिक्त && prv->pkey != रिक्त)
			sshkey_dump_ec_किल्ली(EVP_PKEY_get0_EC_किल्ली(prv->pkey));
#endif
#ifdef OPENSSL_HAS_ED25519
	} अन्यथा यदि (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == किल्ली_UNSPEC || type == किल्ली_ED25519)) {
		size_t len;

		यदि ((prv = sshkey_new(किल्ली_UNSPEC)) == रिक्त ||
		    (prv->ed25519_sk = calloc(1, ED25519_SK_SZ)) == रिक्त ||
		    (prv->ed25519_pk = calloc(1, ED25519_PK_SZ)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		prv->type = किल्ली_ED25519;
		len = ED25519_PK_SZ;
		यदि (!EVP_PKEY_get_raw_public_किल्ली(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
		यदि (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		यदि (!EVP_PKEY_get_raw_private_किल्ली(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
		यदि (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		/* Append the public key to our private key */
		memcpy(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#ifdef DEBUG_PK
		sshbuf_dump_data(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#endif
#endif /* OPENSSL_HAS_ED25519 */
	} अन्यथा {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	r = 0;
	यदि (keyp != रिक्त) {
		*keyp = prv;
		prv = रिक्त;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_किल्ली_free(ecdsa);
	sshkey_free(prv);
	प्रत्यागम r;
}
#endif /* WITH_OPENSSL */

पूर्णाङ्क
sshkey_parse_private_fileblob_type(संरचना sshbuf *blob, पूर्णाङ्क type,
    ध्रुव वर्ण *passphrase, संरचना sshkey **keyp, वर्ण **commentp)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	यदि (keyp != रिक्त)
		*keyp = रिक्त;
	यदि (commentp != रिक्त)
		*commentp = रिक्त;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	यदि (r != SSH_ERR_INVALID_FORMAT)
		प्रत्यागम r;
#ifdef WITH_OPENSSL
	प्रत्यागम sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#अन्यथा
	प्रत्यागम SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

पूर्णाङ्क
sshkey_parse_private_fileblob(संरचना sshbuf *buffer, ध्रुव वर्ण *passphrase,
    संरचना sshkey **keyp, वर्ण **commentp)
{
	यदि (keyp != रिक्त)
		*keyp = रिक्त;
	यदि (commentp != रिक्त)
		*commentp = रिक्त;

	प्रत्यागम sshkey_parse_private_fileblob_type(buffer, किल्ली_UNSPEC,
	    passphrase, keyp, commentp);
}

शून्य
sshkey_sig_details_free(संरचना sshkey_sig_details *details)
{
	freezero(details, परिमाण(*details));
}

पूर्णाङ्क
sshkey_parse_pubkey_from_private_fileblob_type(संरचना sshbuf *blob, पूर्णाङ्क type,
    संरचना sshkey **pubkeyp)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	यदि (pubkeyp != रिक्त)
		*pubkeyp = रिक्त;
	/* only new-format private keys bundle a public key inside */
	यदि ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}
