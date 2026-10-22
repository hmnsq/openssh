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

#include "includes.h"

#include <sys/types.h>
#include <sys/mman.h>
#include <netinet/in.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#endif

#include "crypto_api.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <resolv.h>
#include <time.h>
#include <util.h>

#include "ssh2.h"
#include "ssherr.h"
#include "misc.h"
#include "sshbuf.h"
#include "cipher.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "match.h"
#include "ssh-sk.h"
#include "ssh-pkcs11.h"

#include "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#define MARK_BEGIN_LEN		(parimaa_na(MARK_BEGIN) - 1)
#define MARK_END_LEN		(parimaa_na(MARK_END) - 1)
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

static puur_naa_nka sshkey_from_blob_internal(sa_nracanaa sshbuf *buf,
    sa_nracanaa sshkey **keyp, puur_naa_nka allow_cert,
    const var_na *alg_allowlist, const var_na *ca_sigalg_allowlist);

/* Supported key types */
extern const sa_nracanaa sshkey_impl sshkey_ed25519_impl;
extern const sa_nracanaa sshkey_impl sshkey_ed25519_cert_impl;
extern const sa_nracanaa sshkey_impl sshkey_ed25519_sk_impl;
extern const sa_nracanaa sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
extern const sa_nracanaa sshkey_impl sshkey_mldsa44_ed25519_impl;
extern const sa_nracanaa sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#ifdef WITH_OPENSSL
# ifdef ENABLE_SK
extern const sa_nracanaa sshkey_impl sshkey_ecdsa_sk_impl;
extern const sa_nracanaa sshkey_impl sshkey_ecdsa_sk_cert_impl;
extern const sa_nracanaa sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
extern const sa_nracanaa sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
extern const sa_nracanaa sshkey_impl sshkey_ecdsa_nistp256_impl;
extern const sa_nracanaa sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
extern const sa_nracanaa sshkey_impl sshkey_ecdsa_nistp384_impl;
extern const sa_nracanaa sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
extern const sa_nracanaa sshkey_impl sshkey_ecdsa_nistp521_impl;
extern const sa_nracanaa sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
extern const sa_nracanaa sshkey_impl sshkey_rsa_impl;
extern const sa_nracanaa sshkey_impl sshkey_rsa_cert_impl;
extern const sa_nracanaa sshkey_impl sshkey_rsa_sha256_impl;
extern const sa_nracanaa sshkey_impl sshkey_rsa_sha256_cert_impl;
extern const sa_nracanaa sshkey_impl sshkey_rsa_sha512_impl;
extern const sa_nracanaa sshkey_impl sshkey_rsa_sha512_cert_impl;
#endif /* WITH_OPENSSL */

const sa_nracanaa sshkey_impl * const keyimpls[] = {
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
	NULL
};

static const sa_nracanaa sshkey_impl *
sshkey_impl_from_type(puur_naa_nka type)
{
	puur_naa_nka i;

	for (i = 0; keyimpls[i] != NULL; i++) {
		ᬬᬾᬦ᭄ (keyimpls[i]->type == type)
			ᬯᬮᬶ keyimpls[i];
	}
	ᬯᬮᬶ NULL;
}

static const sa_nracanaa sshkey_impl *
sshkey_impl_from_type_nid(puur_naa_nka type, puur_naa_nka nid)
{
	puur_naa_nka i;

	for (i = 0; keyimpls[i] != NULL; i++) {
		ᬬᬾᬦ᭄ (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			ᬯᬮᬶ keyimpls[i];
	}
	ᬯᬮᬶ NULL;
}

static const sa_nracanaa sshkey_impl *
sshkey_impl_from_key(const sa_nracanaa sshkey *k)
{
	ᬬᬾᬦ᭄ (k == NULL)
		ᬯᬮᬶ NULL;
	ᬯᬮᬶ sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

const var_na *
sshkey_type(const sa_nracanaa sshkey *k)
{
	const sa_nracanaa sshkey_impl *impl;

	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_key(k)) == NULL)
		ᬯᬮᬶ "unknown";
	ᬯᬮᬶ impl->shortname;
}

static const var_na *
sshkey_ssh_name_from_type_nid(puur_naa_nka type, puur_naa_nka nid)
{
	const sa_nracanaa sshkey_impl *impl;

	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_type_nid(type, nid)) == NULL)
		ᬯᬮᬶ "ssh-unknown";
	ᬯᬮᬶ impl->name;
}

puur_naa_nka
sshkey_type_is_cert(puur_naa_nka type)
{
	const sa_nracanaa sshkey_impl *impl;

	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_type(type)) == NULL)
		ᬯᬮᬶ 0;
	ᬯᬮᬶ impl->cert;
}

const var_na *
sshkey_ssh_name(const sa_nracanaa sshkey *k)
{
	ᬯᬮᬶ sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

const var_na *
sshkey_ssh_name_plain(const sa_nracanaa sshkey *k)
{
	ᬯᬮᬶ sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

static puur_naa_nka
type_from_name(const var_na *name, puur_naa_nka allow_short)
{
	puur_naa_nka i;
	const sa_nracanaa sshkey_impl *impl;

	for (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		ᬬᬾᬦ᭄ (impl->name != NULL && strcmp(name, impl->name) == 0)
			ᬯᬮᬶ impl->type;
		/* Only allow shortname matches for plain key types */
		ᬬᬾᬦ᭄ (allow_short && !impl->cert && impl->shortname != NULL &&
		    strcasecmp(impl->shortname, name) == 0)
			ᬯᬮᬶ impl->type;
	}
	ᬯᬮᬶ KEY_UNSPEC;
}

puur_naa_nka
sshkey_type_from_name(const var_na *name)
{
	ᬯᬮᬶ type_from_name(name, 0);
}

puur_naa_nka
sshkey_type_from_shortname(const var_na *name)
{
	ᬯᬮᬶ type_from_name(name, 1);
}

static puur_naa_nka
key_type_is_ecdsa_variant(puur_naa_nka type)
{
	switch (type) {
	pak_sa KEY_ECDSA:
	pak_sa KEY_ECDSA_CERT:
	pak_sa KEY_ECDSA_SK:
	pak_sa KEY_ECDSA_SK_CERT:
		ᬯᬮᬶ 1;
	}
	ᬯᬮᬶ 0;
}

puur_naa_nka
sshkey_ecdsa_nid_from_name(const var_na *name)
{
	puur_naa_nka i;

	for (i = 0; keyimpls[i] != NULL; i++) {
		ᬬᬾᬦ᭄ (!key_type_is_ecdsa_variant(keyimpls[i]->type))
			continue;
		ᬬᬾᬦ᭄ (keyimpls[i]->name != NULL &&
		    strcmp(name, keyimpls[i]->name) == 0)
			ᬯᬮᬶ keyimpls[i]->nid;
	}
	ᬯᬮᬶ -1;
}

puur_naa_nka
sshkey_match_keyname_to_sigalgs(const var_na *keyname, const var_na *sigalgs)
{
	puur_naa_nka ktype;

	ᬬᬾᬦ᭄ (sigalgs == NULL || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == KEY_UNSPEC)
		ᬯᬮᬶ 0;
	ᬮᬶᬬ ᬬᬾᬦ᭄ (ktype == KEY_RSA) {
		ᬯᬮᬶ match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} ᬮᬶᬬ ᬬᬾᬦ᭄ (ktype == KEY_RSA_CERT) {
		ᬯᬮᬶ match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} ᬮᬶᬬ ᬬᬾᬦ᭄ (ktype == KEY_ECDSA_SK) {
		ᬯᬮᬶ match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} ᬮᬶᬬ ᬬᬾᬦ᭄ (ktype == KEY_ECDSA_SK_CERT) {
		ᬯᬮᬶ match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} ᬮᬶᬬ
		ᬯᬮᬶ match_pattern_list(keyname, sigalgs, 0) == 1;
}

var_na *
sshkey_alg_list(puur_naa_nka certs_only, puur_naa_nka plain_only, puur_naa_nka include_sigonly, var_na sep)
{
	var_na *ret = NULL;
	size_t i;
	const sa_nracanaa sshkey_impl *impl;
	var_na sep_str[2] = {sep, '\0'};

	for (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		ᬬᬾᬦ᭄ (impl->name == NULL)
			continue;
		ᬬᬾᬦ᭄ (!include_sigonly && impl->sigonly)
			continue;
		ᬬᬾᬦ᭄ ((certs_only && !impl->cert) || (plain_only && impl->cert))
			continue;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	ᬯᬮᬶ ret;
}

puur_naa_nka
sshkey_names_valid2(const var_na *names, puur_naa_nka allow_wildcard, puur_naa_nka plain_only)
{
	var_na *s, *cp, *p;
	const sa_nracanaa sshkey_impl *impl;
	puur_naa_nka i, type;

	ᬬᬾᬦ᭄ (names == NULL || strcmp(names, "") == 0)
		ᬯᬮᬶ 0;
	ᬬᬾᬦ᭄ ((s = cp = strdup(names)) == NULL)
		ᬯᬮᬶ 0;
	for ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		ᬬᬾᬦ᭄ (type == KEY_UNSPEC) {
			ᬬᬾᬦ᭄ (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = NULL;
				for (i = 0; keyimpls[i] != NULL; i++) {
					ᬬᬾᬦ᭄ (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						bha_nga;
					}
				}
				ᬬᬾᬦ᭄ (impl != NULL)
					continue;
			}
			free(s);
			ᬯᬮᬶ 0;
		} ᬮᬶᬬ ᬬᬾᬦ᭄ (plain_only && sshkey_type_is_cert(type)) {
			free(s);
			ᬯᬮᬶ 0;
		}
	}
	free(s);
	ᬯᬮᬶ 1;
}

u_int
sshkey_size(const sa_nracanaa sshkey *k)
{
	const sa_nracanaa sshkey_impl *impl;

	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_key(k)) == NULL)
		ᬯᬮᬶ 0;
	ᬬᬾᬦ᭄ (impl->funcs->size != NULL)
		ᬯᬮᬶ impl->funcs->size(k);
	ᬯᬮᬶ impl->keybits;
}

static puur_naa_nka
sshkey_type_is_valid_ca(puur_naa_nka type)
{
	const sa_nracanaa sshkey_impl *impl;

	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_type(type)) == NULL)
		ᬯᬮᬶ 0;
	/* All non-certificate types may act as CAs */
	ᬯᬮᬶ !impl->cert;
}

puur_naa_nka
sshkey_is_cert(const sa_nracanaa sshkey *k)
{
	ᬬᬾᬦ᭄ (k == NULL)
		ᬯᬮᬶ 0;
	ᬯᬮᬶ sshkey_type_is_cert(k->type);
}

puur_naa_nka
sshkey_is_sk(const sa_nracanaa sshkey *k)
{
	ᬬᬾᬦ᭄ (k == NULL)
		ᬯᬮᬶ 0;
	switch (sshkey_type_plain(k->type)) {
	pak_sa KEY_ECDSA_SK:
	pak_sa KEY_ED25519_SK:
		ᬯᬮᬶ 1;
	default:
		ᬯᬮᬶ 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
puur_naa_nka
sshkey_type_plain(puur_naa_nka type)
{
	switch (type) {
	pak_sa KEY_RSA_CERT:
		ᬯᬮᬶ KEY_RSA;
	pak_sa KEY_ECDSA_CERT:
		ᬯᬮᬶ KEY_ECDSA;
	pak_sa KEY_ECDSA_SK_CERT:
		ᬯᬮᬶ KEY_ECDSA_SK;
	pak_sa KEY_ED25519_CERT:
		ᬯᬮᬶ KEY_ED25519;
	pak_sa KEY_MLDSA44_ED25519_CERT:
		ᬯᬮᬶ KEY_MLDSA44_ED25519;
	pak_sa KEY_ED25519_SK_CERT:
		ᬯᬮᬶ KEY_ED25519_SK;
	default:
		ᬯᬮᬶ type;
	}
}

/* Return the cert equivalent to a plain key type */
static puur_naa_nka
sshkey_type_certified(puur_naa_nka type)
{
	switch (type) {
	pak_sa KEY_RSA:
		ᬯᬮᬶ KEY_RSA_CERT;
	pak_sa KEY_ECDSA:
		ᬯᬮᬶ KEY_ECDSA_CERT;
	pak_sa KEY_ECDSA_SK:
		ᬯᬮᬶ KEY_ECDSA_SK_CERT;
	pak_sa KEY_ED25519:
		ᬯᬮᬶ KEY_ED25519_CERT;
	pak_sa KEY_MLDSA44_ED25519:
		ᬯᬮᬶ KEY_MLDSA44_ED25519_CERT;
	pak_sa KEY_ED25519_SK:
		ᬯᬮᬶ KEY_ED25519_SK_CERT;
	default:
		ᬯᬮᬶ -1;
	}
}

#ifdef WITH_OPENSSL
static const EVP_MD *
ssh_digest_to_md(puur_naa_nka hash_alg)
{
	switch (hash_alg) {
	pak_sa SSH_DIGEST_SHA1:
		ᬯᬮᬶ EVP_sha1();
	pak_sa SSH_DIGEST_SHA256:
		ᬯᬮᬶ EVP_sha256();
	pak_sa SSH_DIGEST_SHA384:
		ᬯᬮᬶ EVP_sha384();
	pak_sa SSH_DIGEST_SHA512:
		ᬯᬮᬶ EVP_sha512();
	}
	ᬯᬮᬶ NULL;
}

puur_naa_nka
sshkey_pkey_digest_sign(EVP_PKEY *pkey, puur_naa_nka hash_alg, u_char **sigp,
    size_t *lenp, const u_char *data, size_t datalen)
{
	EVP_MD_CTX *ctx = NULL;
	u_char *sig = NULL;
	puur_naa_nka ret;
	size_t slen;
	const EVP_MD *evpmd;

	*sigp = NULL;
	*lenp = 0;

	slen = EVP_PKEY_size(pkey);
	ᬬᬾᬦ᭄ (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == NULL)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;

	ᬬᬾᬦ᭄ ((sig = malloc(slen)) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;

	ᬬᬾᬦ᭄ ((ctx = EVP_MD_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᬬᬾᬦ᭄ (EVP_DigestSignInit(ctx, NULL, evpmd, NULL, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, data, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = NULL;
	ret = 0;

 out:
	EVP_MD_CTX_free(ctx);
	free(sig);
	ᬯᬮᬶ ret;
}

puur_naa_nka
sshkey_pkey_digest_verify(EVP_PKEY *pkey, puur_naa_nka hash_alg, const u_char *data,
    size_t datalen, u_char *sigbuf, size_t siglen)
{
	EVP_MD_CTX *ctx = NULL;
	puur_naa_nka ret = SSH_ERR_INTERNAL_ERROR;
	const EVP_MD *evpmd;

	ᬬᬾᬦ᭄ ((evpmd = ssh_digest_to_md(hash_alg)) == NULL)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;
	ᬬᬾᬦ᭄ ((ctx = EVP_MD_CTX_new()) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	ᬬᬾᬦ᭄ (EVP_DigestVerifyInit(ctx, NULL, evpmd, NULL, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	switch (EVP_DigestVerify(ctx, sigbuf, siglen, data, datalen)) {
	pak_sa 1:
		ret = 0;
		bha_nga;
	pak_sa 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		bha_nga;
	default:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		bha_nga;
	}

 out:
	EVP_MD_CTX_free(ctx);
	ᬯᬮᬶ ret;
}

/* XXX: these are really begging for a table-driven approach */
puur_naa_nka
sshkey_curve_name_to_nid(const var_na *name)
{
	ᬬᬾᬦ᭄ (strcmp(name, "nistp256") == 0)
		ᬯᬮᬶ NID_X9_62_prime256v1;
	ᬮᬶᬬ ᬬᬾᬦ᭄ (strcmp(name, "nistp384") == 0)
		ᬯᬮᬶ NID_secp384r1;
	ᬮᬶᬬ ᬬᬾᬦ᭄ (strcmp(name, "nistp521") == 0)
		ᬯᬮᬶ NID_secp521r1;
	ᬮᬶᬬ
		ᬯᬮᬶ -1;
}

u_int
sshkey_curve_nid_to_bits(puur_naa_nka nid)
{
	switch (nid) {
	pak_sa NID_X9_62_prime256v1:
		ᬯᬮᬶ 256;
	pak_sa NID_secp384r1:
		ᬯᬮᬶ 384;
	pak_sa NID_secp521r1:
		ᬯᬮᬶ 521;
	default:
		ᬯᬮᬶ 0;
	}
}

puur_naa_nka
sshkey_ecdsa_bits_to_nid(puur_naa_nka bits)
{
	switch (bits) {
	pak_sa 256:
		ᬯᬮᬶ NID_X9_62_prime256v1;
	pak_sa 384:
		ᬯᬮᬶ NID_secp384r1;
	pak_sa 521:
		ᬯᬮᬶ NID_secp521r1;
	default:
		ᬯᬮᬶ -1;
	}
}

const var_na *
sshkey_curve_nid_to_name(puur_naa_nka nid)
{
	switch (nid) {
	pak_sa NID_X9_62_prime256v1:
		ᬯᬮᬶ "nistp256";
	pak_sa NID_secp384r1:
		ᬯᬮᬶ "nistp384";
	pak_sa NID_secp521r1:
		ᬯᬮᬶ "nistp521";
	default:
		ᬯᬮᬶ NULL;
	}
}

puur_naa_nka
sshkey_ec_nid_to_hash_alg(puur_naa_nka nid)
{
	puur_naa_nka kbits = sshkey_curve_nid_to_bits(nid);

	ᬬᬾᬦ᭄ (kbits <= 0)
		ᬯᬮᬶ -1;

	/* RFC5656 section 6.2.1 */
	ᬬᬾᬦ᭄ (kbits <= 256)
		ᬯᬮᬶ SSH_DIGEST_SHA256;
	ᬮᬶᬬ ᬬᬾᬦ᭄ (kbits <= 384)
		ᬯᬮᬶ SSH_DIGEST_SHA384;
	ᬮᬶᬬ
		ᬯᬮᬶ SSH_DIGEST_SHA512;
}
#endif /* WITH_OPENSSL */

static void
cert_free(sa_nracanaa sshkey_cert *cert)
{
	u_int i;

	ᬬᬾᬦ᭄ (cert == NULL)
		ᬯᬮᬶ;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	free(cert->key_id);
	for (i = 0; i < cert->nprincipals; i++)
		free(cert->principals[i]);
	free(cert->principals);
	sshkey_free(cert->signature_key);
	free(cert->signature_type);
	freezero(cert, parimaa_na(*cert));
}

static sa_nracanaa sshkey_cert *
cert_new(void)
{
	sa_nracanaa sshkey_cert *cert;

	ᬬᬾᬦ᭄ ((cert = calloc(1, parimaa_na(*cert))) == NULL)
		ᬯᬮᬶ NULL;
	ᬬᬾᬦ᭄ ((cert->certblob = sshbuf_new()) == NULL ||
	    (cert->critical = sshbuf_new()) == NULL ||
	    (cert->extensions = sshbuf_new()) == NULL) {
		cert_free(cert);
		ᬯᬮᬶ NULL;
	}
	cert->key_id = NULL;
	cert->principals = NULL;
	cert->signature_key = NULL;
	cert->signature_type = NULL;
	ᬯᬮᬶ cert;
}

sa_nracanaa sshkey *
sshkey_new(puur_naa_nka type)
{
	sa_nracanaa sshkey *k;
	const sa_nracanaa sshkey_impl *impl = NULL;

	ᬬᬾᬦ᭄ (type != KEY_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == NULL)
		ᬯᬮᬶ NULL;

	/* All non-certificate types may act as CAs */
	ᬬᬾᬦ᭄ ((k = calloc(1, parimaa_na(*k))) == NULL)
		ᬯᬮᬶ NULL;
	k->type = type;
	k->ecdsa_nid = -1;
	ᬬᬾᬦ᭄ (impl != NULL && impl->funcs->alloc != NULL) {
		ᬬᬾᬦ᭄ (impl->funcs->alloc(k) != 0) {
			free(k);
			ᬯᬮᬶ NULL;
		}
	}
	ᬬᬾᬦ᭄ (sshkey_is_cert(k)) {
		ᬬᬾᬦ᭄ ((k->cert = cert_new()) == NULL) {
			sshkey_free(k);
			ᬯᬮᬶ NULL;
		}
	}

	ᬯᬮᬶ k;
}

/* Frees common FIDO fields */
void
sshkey_sk_cleanup(sa_nracanaa sshkey *k)
{
	free(k->sk_application);
	sshbuf_free(k->sk_key_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = NULL;
	k->sk_key_handle = k->sk_reserved = NULL;
}

#ᬬᬾᬦ᭄ defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#elif defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#ᬮᬶᬬ
# define PREKEY_MMAP_FLAG	0
#endif

static puur_naa_nka
sshkey_prekey_alloc(u_char **prekeyp, size_t len)
{
#ᬬᬾᬦ᭄ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = NULL;
	ᬬᬾᬦ᭄ ((prekey = mmap(NULL, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		ᬯᬮᬶ SSH_ERR_SYSTEM_ERROR;
#ᬬᬾᬦ᭄ defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(void)madvise(prekey, len, MADV_DONTDUMP);
#endif
	*prekeyp = prekey;
#ᬮᬶᬬ
	*prekeyp = calloc(1, len);
#endif /* HAVE_MMAP et al */
	ᬯᬮᬶ 0;
}

static void
sshkey_prekey_free(void *prekey, size_t len)
{
#ᬬᬾᬦ᭄ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	ᬬᬾᬦ᭄ (prekey == NULL)
		ᬯᬮᬶ;
	munmap(prekey, len);
#ᬮᬶᬬ
	free(prekey);
#endif /* HAVE_MMAP et al */
}

static void
sshkey_free_contents(sa_nracanaa sshkey *k)
{
	const sa_nracanaa sshkey_impl *impl;

	ᬬᬾᬦ᭄ (k == NULL)
		ᬯᬮᬶ;
	ᬬᬾᬦ᭄ ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_key_free(k);
	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_type(k->type)) != NULL &&
	    impl->funcs->cleanup != NULL)
		impl->funcs->cleanup(k);
	ᬬᬾᬦ᭄ (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_private, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

void
sshkey_free(sa_nracanaa sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, parimaa_na(*k));
}

static puur_naa_nka
cert_compare(sa_nracanaa sshkey_cert *a, sa_nracanaa sshkey_cert *b)
{
	ᬬᬾᬦ᭄ (a == NULL && b == NULL)
		ᬯᬮᬶ 1;
	ᬬᬾᬦ᭄ (a == NULL || b == NULL)
		ᬯᬮᬶ 0;
	ᬬᬾᬦ᭄ (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		ᬯᬮᬶ 0;
	ᬬᬾᬦ᭄ (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		ᬯᬮᬶ 0;
	ᬯᬮᬶ 1;
}

/* Compares FIDO-specific pubkey fields only */
puur_naa_nka
sshkey_sk_fields_equal(const sa_nracanaa sshkey *a, const sa_nracanaa sshkey *b)
{
	ᬬᬾᬦ᭄ (a->sk_application == NULL || b->sk_application == NULL)
		ᬯᬮᬶ 0;
	ᬬᬾᬦ᭄ (strcmp(a->sk_application, b->sk_application) != 0)
		ᬯᬮᬶ 0;
	ᬯᬮᬶ 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
puur_naa_nka
sshkey_equal_public(const sa_nracanaa sshkey *a, const sa_nracanaa sshkey *b)
{
	const sa_nracanaa sshkey_impl *impl;

	ᬬᬾᬦ᭄ (a == NULL || b == NULL ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		ᬯᬮᬶ 0;
	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_type(a->type)) == NULL)
		ᬯᬮᬶ 0;
	ᬯᬮᬶ impl->funcs->equal(a, b);
}

puur_naa_nka
sshkey_equal(const sa_nracanaa sshkey *a, const sa_nracanaa sshkey *b)
{
	ᬬᬾᬦ᭄ (a == NULL || b == NULL || a->type != b->type)
		ᬯᬮᬶ 0;
	ᬬᬾᬦ᭄ (sshkey_is_cert(a)) {
		ᬬᬾᬦ᭄ (!cert_compare(a->cert, b->cert))
			ᬯᬮᬶ 0;
	}
	ᬯᬮᬶ sshkey_equal_public(a, b);
}


/* Serialise common FIDO key parts */
puur_naa_nka
sshkey_serialize_sk(const sa_nracanaa sshkey *key, sa_nracanaa sshbuf *b)
{
	puur_naa_nka r;

	ᬬᬾᬦ᭄ ((r = sshbuf_put_cstring(b, key->sk_application)) != 0)
		ᬯᬮᬶ r;

	ᬯᬮᬶ 0;
}

static puur_naa_nka
to_blob_buf(const sa_nracanaa sshkey *key, sa_nracanaa sshbuf *b, puur_naa_nka force_plain,
  ga_nanaa sshkey_serialize_rep opts)
{
	puur_naa_nka type, ret = SSH_ERR_INTERNAL_ERROR;
	const var_na *typename;
	const sa_nracanaa sshkey_impl *impl;

	ᬬᬾᬦ᭄ (key == NULL)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(key->type) : key->type;

	ᬬᬾᬦ᭄ (sshkey_type_is_cert(type)) {
		ᬬᬾᬦ᭄ (key->cert == NULL)
			ᬯᬮᬶ SSH_ERR_EXPECTED_CERT;
		ᬬᬾᬦ᭄ (sshbuf_len(key->cert->certblob) == 0)
			ᬯᬮᬶ SSH_ERR_KEY_LACKS_CERTBLOB;
		/* Use the existing blob */
		ᬬᬾᬦ᭄ ((ret = sshbuf_putb(b, key->cert->certblob)) != 0)
			ᬯᬮᬶ ret;
		ᬯᬮᬶ 0;
	}
	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_type(type)) == NULL)
		ᬯᬮᬶ SSH_ERR_KEY_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, key->ecdsa_nid);
	ᬬᬾᬦ᭄ ((ret = sshbuf_put_cstring(b, typename)) != 0)
		ᬯᬮᬶ ret;
	ᬯᬮᬶ impl->funcs->serialize_public(key, b, opts);
}

puur_naa_nka
sshkey_putb(const sa_nracanaa sshkey *key, sa_nracanaa sshbuf *b)
{
	ᬯᬮᬶ to_blob_buf(key, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

static puur_naa_nka
sshkey_puts_opts_internal(const sa_nracanaa sshkey *key, sa_nracanaa sshbuf *b,
    ga_nanaa sshkey_serialize_rep opts, puur_naa_nka force_plain)
{
	sa_nracanaa sshbuf *tmp;
	puur_naa_nka r;

	ᬬᬾᬦ᭄ ((tmp = sshbuf_new()) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(key, tmp, force_plain, opts);
	ᬬᬾᬦ᭄ (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	ᬯᬮᬶ r;
}

puur_naa_nka
sshkey_puts(const sa_nracanaa sshkey *key, sa_nracanaa sshbuf *b)
{
	ᬯᬮᬶ sshkey_puts_opts_internal(key, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

puur_naa_nka
sshkey_putb_plain(const sa_nracanaa sshkey *key, sa_nracanaa sshbuf *b)
{
	ᬯᬮᬶ to_blob_buf(key, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

puur_naa_nka
sshkey_puts_plain(const sa_nracanaa sshkey *key, sa_nracanaa sshbuf *b)
{
	ᬯᬮᬶ sshkey_puts_opts_internal(key, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

static puur_naa_nka
to_blob(const sa_nracanaa sshkey *key, u_char **blobp, size_t *lenp, puur_naa_nka force_plain,
    ga_nanaa sshkey_serialize_rep opts)
{
	puur_naa_nka ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	sa_nracanaa sshbuf *b = NULL;

	ᬬᬾᬦ᭄ (lenp != NULL)
		*lenp = 0;
	ᬬᬾᬦ᭄ (blobp != NULL)
		*blobp = NULL;
	ᬬᬾᬦ᭄ ((b = sshbuf_new()) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	ᬬᬾᬦ᭄ ((ret = to_blob_buf(key, b, force_plain, opts)) != 0)
		goto out;
	len = sshbuf_len(b);
	ᬬᬾᬦ᭄ (lenp != NULL)
		*lenp = len;
	ᬬᬾᬦ᭄ (blobp != NULL) {
		ᬬᬾᬦ᭄ ((*blobp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	ᬯᬮᬶ ret;
}

puur_naa_nka
sshkey_to_blob(const sa_nracanaa sshkey *key, u_char **blobp, size_t *lenp)
{
	ᬯᬮᬶ to_blob(key, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

puur_naa_nka
sshkey_plain_to_blob(const sa_nracanaa sshkey *key, u_char **blobp, size_t *lenp)
{
	ᬯᬮᬶ to_blob(key, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

puur_naa_nka
sshkey_fingerprint_raw(const sa_nracanaa sshkey *k, puur_naa_nka dgst_alg,
    u_char **retp, size_t *lenp)
{
	u_char *blob = NULL, *ret = NULL;
	size_t blob_len = 0;
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;

	ᬬᬾᬦ᭄ (retp != NULL)
		*retp = NULL;
	ᬬᬾᬦ᭄ (lenp != NULL)
		*lenp = 0;
	ᬬᬾᬦ᭄ (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	ᬬᬾᬦ᭄ ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		goto out;
	ᬬᬾᬦ᭄ ((ret = calloc(1, SSH_DIGEST_MAX_LENGTH)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᬬᬾᬦ᭄ ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_LENGTH)) != 0)
		goto out;
	/* success */
	ᬬᬾᬦ᭄ (retp != NULL) {
		*retp = ret;
		ret = NULL;
	}
	ᬬᬾᬦ᭄ (lenp != NULL)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	free(ret);
	ᬬᬾᬦ᭄ (blob != NULL)
		freezero(blob, blob_len);
	ᬯᬮᬶ r;
}

static var_na *
fingerprint_b64(const var_na *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	var_na *ret;
	size_t plen = strlen(alg) + 1;
	size_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	ᬬᬾᬦ᭄ (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == NULL)
		ᬯᬮᬶ NULL;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	ᬬᬾᬦ᭄ (dgst_raw_len == 0)
		ᬯᬮᬶ ret;
	ᬬᬾᬦ᭄ (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		ᬯᬮᬶ NULL;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	ᬯᬮᬶ ret;
}

static var_na *
fingerprint_hex(const var_na *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	var_na *retval, hex[5];
	size_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	ᬬᬾᬦ᭄ (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == NULL)
		ᬯᬮᬶ NULL;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	for (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, parimaa_na(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	ᬯᬮᬶ retval;
}

static var_na *
fingerprint_bubblebabble(u_char *dgst_raw, size_t dgst_raw_len)
{
	var_na vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	var_na consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	var_na *retval;

	rounds = (dgst_raw_len / 2) + 1;
	ᬬᬾᬦ᭄ ((retval = calloc(rounds, 6)) == NULL)
		ᬯᬮᬶ NULL;
	retval[j++] = 'x';
	for (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		ᬬᬾᬦ᭄ ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			ᬬᬾᬦ᭄ ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} ᬮᬶᬬ {
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
	ᬯᬮᬶ retval;
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
static var_na *
fingerprint_randomart(const var_na *alg, u_char *dgst_raw, size_t dgst_raw_len,
    const sa_nracanaa sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	var_na	*augmentation_string = " .o+=*BOX@%&#/^SE";
	var_na	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	size_t	 i, tlen, hlen;
	u_int	 b;
	puur_naa_nka	 x, y, r;
	size_t	 len = strlen(augmentation_string) - 1;

	ᬬᬾᬦ᭄ ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == NULL)
		ᬯᬮᬶ NULL;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * parimaa_na(var_na));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	for (i = 0; i < dgst_raw_len; i++) {
		puur_naa_nka input;
		/* each byte conveys four 2-bit move commands */
		input = dgst_raw[i];
		for (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (input & 0x1) ? 1 : -1;
			y += (input & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			ᬬᬾᬦ᭄ (field[x][y] < len - 2)
				field[x][y]++;
			input = input >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, parimaa_na(title), "[%s %u]",
		sshkey_type(k), sshkey_size(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	ᬬᬾᬦ᭄ (r < 0 || r > (puur_naa_nka)parimaa_na(title))
		r = snprintf(title, parimaa_na(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, parimaa_na(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	for (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	memcpy(p, title, tlen);
	p += tlen;
	for (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	for (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		for (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	for (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	memcpy(p, hash, hlen);
	p += hlen;
	for (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	ᬯᬮᬶ retval;
}

var_na *
sshkey_fingerprint(const sa_nracanaa sshkey *k, puur_naa_nka dgst_alg,
    ga_nanaa sshkey_fp_rep dgst_rep)
{
	var_na *retval = NULL;
	u_char *dgst_raw;
	size_t dgst_raw_len;

	ᬬᬾᬦ᭄ (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		ᬯᬮᬶ NULL;
	switch (dgst_rep) {
	pak_sa SSH_FP_DEFAULT:
		ᬬᬾᬦ᭄ (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} ᬮᬶᬬ {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		bha_nga;
	pak_sa SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		bha_nga;
	pak_sa SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		bha_nga;
	pak_sa SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		bha_nga;
	pak_sa SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		bha_nga;
	default:
		freezero(dgst_raw, dgst_raw_len);
		ᬯᬮᬶ NULL;
	}
	freezero(dgst_raw, dgst_raw_len);
	ᬯᬮᬶ retval;
}

static puur_naa_nka
peek_type_nid(const var_na *s, size_t l, puur_naa_nka *nid)
{
	const sa_nracanaa sshkey_impl *impl;
	puur_naa_nka i;

	for (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		ᬬᬾᬦ᭄ (impl->name == NULL || strlen(impl->name) != l)
			continue;
		ᬬᬾᬦ᭄ (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			ᬬᬾᬦ᭄ (key_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			ᬯᬮᬶ impl->type;
		}
	}
	ᬯᬮᬶ KEY_UNSPEC;
}

/* XXX this can now be made const char * */
puur_naa_nka
sshkey_read(sa_nracanaa sshkey *ret, var_na **cpp)
{
	sa_nracanaa sshkey *k;
	var_na *cp, *blobcopy;
	size_t space;
	puur_naa_nka r, type, curve_nid = -1;
	sa_nracanaa sshbuf *blob;

	ᬬᬾᬦ᭄ (ret == NULL)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;
	ᬬᬾᬦ᭄ (ret->type != KEY_UNSPEC && sshkey_impl_from_type(ret->type) == NULL)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	ᬬᬾᬦ᭄ (space == strlen(cp))
		ᬯᬮᬶ SSH_ERR_INVALID_FORMAT;
	ᬬᬾᬦ᭄ ((type = peek_type_nid(cp, space, &curve_nid)) == KEY_UNSPEC)
		ᬯᬮᬶ SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	for (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	ᬬᬾᬦ᭄ (*cp == '\0')
		ᬯᬮᬶ SSH_ERR_INVALID_FORMAT;
	ᬬᬾᬦ᭄ (ret->type != KEY_UNSPEC && ret->type != type)
		ᬯᬮᬶ SSH_ERR_KEY_TYPE_MISMATCH;
	ᬬᬾᬦ᭄ ((blob = sshbuf_new()) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	ᬬᬾᬦ᭄ ((blobcopy = strndup(cp, space)) == NULL) {
		sshbuf_free(blob);
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	}
	ᬬᬾᬦ᭄ ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		free(blobcopy);
		sshbuf_free(blob);
		ᬯᬮᬶ r;
	}
	free(blobcopy);
	ᬬᬾᬦ᭄ ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		ᬯᬮᬶ r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	for (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	ᬬᬾᬦ᭄ (k->type != type) {
		sshkey_free(k);
		ᬯᬮᬶ SSH_ERR_KEY_TYPE_MISMATCH;
	}
	ᬬᬾᬦ᭄ (key_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		ᬯᬮᬶ SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, parimaa_na(*k));

	/* success */
	*cpp = cp;
	ᬯᬮᬶ 0;
}

puur_naa_nka
sshkey_to_base64(const sa_nracanaa sshkey *key, var_na **b64p)
{
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa sshbuf *b = NULL;
	var_na *uu = NULL;

	ᬬᬾᬦ᭄ (b64p != NULL)
		*b64p = NULL;
	ᬬᬾᬦ᭄ ((b = sshbuf_new()) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	ᬬᬾᬦ᭄ ((r = sshkey_putb(key, b)) != 0)
		goto out;
	ᬬᬾᬦ᭄ ((uu = sshbuf_dtob64_string(b, 0)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* Success */
	ᬬᬾᬦ᭄ (b64p != NULL) {
		*b64p = uu;
		uu = NULL;
	}
	r = 0;
 out:
	sshbuf_free(b);
	free(uu);
	ᬯᬮᬶ r;
}

puur_naa_nka
sshkey_format_text(const sa_nracanaa sshkey *key, sa_nracanaa sshbuf *b)
{
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;
	var_na *uu = NULL;

	ᬬᬾᬦ᭄ ((r = sshkey_to_base64(key, &uu)) != 0)
		goto out;
	ᬬᬾᬦ᭄ ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(key), uu)) != 0)
		goto out;
	r = 0;
 out:
	free(uu);
	ᬯᬮᬶ r;
}

puur_naa_nka
sshkey_write(const sa_nracanaa sshkey *key, FILE *f)
{
	sa_nracanaa sshbuf *b = NULL;
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;

	ᬬᬾᬦ᭄ ((b = sshbuf_new()) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	ᬬᬾᬦ᭄ ((r = sshkey_format_text(key, b)) != 0)
		goto out;
	ᬬᬾᬦ᭄ (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		ᬬᬾᬦ᭄ (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		goto out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	ᬯᬮᬶ r;
}

const var_na *
sshkey_cert_type(const sa_nracanaa sshkey *k)
{
	switch (k->cert->type) {
	pak_sa SSH2_CERT_TYPE_USER:
		ᬯᬮᬶ "user";
	pak_sa SSH2_CERT_TYPE_HOST:
		ᬯᬮᬶ "host";
	default:
		ᬯᬮᬶ "unknown";
	}
}

puur_naa_nka
sshkey_check_rsa_length(const sa_nracanaa sshkey *k, puur_naa_nka min_size)
{
#ifdef WITH_OPENSSL
	puur_naa_nka nbits;

	ᬬᬾᬦ᭄ (k == NULL || k->pkey == NULL ||
	    (k->type != KEY_RSA && k->type != KEY_RSA_CERT))
		ᬯᬮᬶ 0;
	nbits = EVP_PKEY_bits(k->pkey);
	ᬬᬾᬦ᭄ (nbits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    (min_size > 0 && nbits < min_size))
		ᬯᬮᬶ SSH_ERR_KEY_LENGTH;
#endif /* WITH_OPENSSL */
	ᬯᬮᬶ 0;
}

#ifdef WITH_OPENSSL
puur_naa_nka
sshkey_ecdsa_key_to_nid(const EC_KEY *k)
{
	const EC_GROUP *g;
	puur_naa_nka nid;

	ᬬᬾᬦ᭄ (k == NULL || (g = EC_KEY_get0_group(k)) == NULL)
		ᬯᬮᬶ -1;
	ᬬᬾᬦ᭄ ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		ᬯᬮᬶ -1;
	ᬯᬮᬶ nid;
}

puur_naa_nka
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	ᬯᬮᬶ sshkey_ecdsa_key_to_nid(EVP_PKEY_get0_EC_KEY(pkey));
}
#endif /* WITH_OPENSSL */

puur_naa_nka
sshkey_generate(puur_naa_nka type, u_int bits, sa_nracanaa sshkey **keyp)
{
	sa_nracanaa sshkey *k;
	puur_naa_nka ret = SSH_ERR_INTERNAL_ERROR;
	const sa_nracanaa sshkey_impl *impl;

	ᬬᬾᬦ᭄ (keyp == NULL || sshkey_type_is_cert(type))
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;
	*keyp = NULL;
	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_type(type)) == NULL)
		ᬯᬮᬶ SSH_ERR_KEY_TYPE_UNKNOWN;
	ᬬᬾᬦ᭄ (impl->funcs->generate == NULL)
		ᬯᬮᬶ SSH_ERR_FEATURE_UNSUPPORTED;
	ᬬᬾᬦ᭄ ((k = sshkey_new(KEY_UNSPEC)) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	k->type = type;
	ᬬᬾᬦ᭄ ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		ᬯᬮᬶ ret;
	}
	/* success */
	*keyp = k;
	ᬯᬮᬶ 0;
}

puur_naa_nka
sshkey_cert_copy(const sa_nracanaa sshkey *from_key, sa_nracanaa sshkey *to_key)
{
	u_int i;
	const sa_nracanaa sshkey_cert *from;
	sa_nracanaa sshkey_cert *to;
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;

	ᬬᬾᬦ᭄ (to_key == NULL || (from = from_key->cert) == NULL)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;

	ᬬᬾᬦ᭄ ((to = cert_new()) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;

	ᬬᬾᬦ᭄ ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		goto out;

	to->serial = from->serial;
	to->type = from->type;
	ᬬᬾᬦ᭄ (from->key_id == NULL)
		to->key_id = NULL;
	ᬮᬶᬬ ᬬᬾᬦ᭄ ((to->key_id = strdup(from->key_id)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	ᬬᬾᬦ᭄ (from->signature_key == NULL)
		to->signature_key = NULL;
	ᬮᬶᬬ ᬬᬾᬦ᭄ ((r = sshkey_from_private(from->signature_key,
	    &to->signature_key)) != 0)
		goto out;
	ᬬᬾᬦ᭄ (from->signature_type != NULL &&
	    (to->signature_type = strdup(from->signature_type)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᬬᬾᬦ᭄ (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	ᬬᬾᬦ᭄ (from->nprincipals > 0) {
		ᬬᬾᬦ᭄ ((to->principals = calloc(from->nprincipals,
		    parimaa_na(*to->principals))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		for (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			ᬬᬾᬦ᭄ (to->principals[i] == NULL) {
				to->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				goto out;
			}
		}
	}
	to->nprincipals = from->nprincipals;

	/* success */
	cert_free(to_key->cert);
	to_key->cert = to;
	to = NULL;
	r = 0;
 out:
	cert_free(to);
	ᬯᬮᬶ r;
}

puur_naa_nka
sshkey_copy_public_sk(const sa_nracanaa sshkey *from, sa_nracanaa sshkey *to)
{
	/* Append security-key application string */
	ᬬᬾᬦ᭄ ((to->sk_application = strdup(from->sk_application)) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	ᬯᬮᬶ 0;
}

puur_naa_nka
sshkey_from_private(const sa_nracanaa sshkey *k, sa_nracanaa sshkey **pkp)
{
	sa_nracanaa sshkey *n = NULL;
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;
	const sa_nracanaa sshkey_impl *impl;

	*pkp = NULL;
	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_key(k)) == NULL)
		ᬯᬮᬶ SSH_ERR_KEY_TYPE_UNKNOWN;
	ᬬᬾᬦ᭄ ((n = sshkey_new(k->type)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᬬᬾᬦ᭄ ((r = impl->funcs->copy_public(k, n)) != 0)
		goto out;
	ᬬᬾᬦ᭄ (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		goto out;
	/* success */
	*pkp = n;
	n = NULL;
	r = 0;
 out:
	sshkey_free(n);
	ᬯᬮᬶ r;
}

puur_naa_nka
sshkey_is_shielded(sa_nracanaa sshkey *k)
{
	ᬯᬮᬶ k != NULL && k->shielded_private != NULL;
}

puur_naa_nka
sshkey_shield_private(sa_nracanaa sshkey *k)
{
	sa_nracanaa sshbuf *prvbuf = NULL;
	u_char *prekey = NULL, *enc = NULL, keyiv[SSH_DIGEST_MAX_LENGTH];
	sa_nracanaa sshcipher_ctx *cctx = NULL;
	const sa_nracanaa sshcipher *cipher;
	size_t i, enclen = 0;
	sa_nracanaa sshkey *kswap = NULL, tmp;
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	ᬬᬾᬦ᭄ ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	ᬬᬾᬦ᭄ (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	ᬬᬾᬦ᭄ ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		goto out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	ᬬᬾᬦ᭄ ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	ᬬᬾᬦ᭄ ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		goto out;

	/* Serialise and encrypt the private key using the ephemeral key */
	ᬬᬾᬦ᭄ ((prvbuf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᬬᬾᬦ᭄ (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		goto out;
	ᬬᬾᬦ᭄ ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		goto out;
	/* pad to cipher blocksize */
	i = 0;
	ᬲᭂᬤᭂᬮ (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		ᬬᬾᬦ᭄ ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			goto out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	ᬬᬾᬦ᭄ ((enc = malloc(enclen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᬬᬾᬦ᭄ ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	ᬬᬾᬦ᭄ ((r = sshkey_from_private(k, &kswap)) != 0)
		goto out;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_private = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = NULL; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 out:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, parimaa_na(keyiv));
	explicit_bzero(&tmp, parimaa_na(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	ᬯᬮᬶ r;
}

/* Check deterministic padding after private key */
static puur_naa_nka
private2_check_padding(sa_nracanaa sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	puur_naa_nka r;

	i = 0;
	ᬲᭂᬤᭂᬮ (sshbuf_len(decrypted)) {
		ᬬᬾᬦ᭄ ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			goto out;
		ᬬᬾᬦ᭄ (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, parimaa_na(pad));
	explicit_bzero(&i, parimaa_na(i));
	ᬯᬮᬶ r;
}

puur_naa_nka
sshkey_unshield_private(sa_nracanaa sshkey *k)
{
	sa_nracanaa sshbuf *prvbuf = NULL;
	u_char *cp, keyiv[SSH_DIGEST_MAX_LENGTH];
	sa_nracanaa sshcipher_ctx *cctx = NULL;
	const sa_nracanaa sshcipher *cipher;
	sa_nracanaa sshkey *kswap = NULL, tmp;
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	ᬬᬾᬦ᭄ (!sshkey_is_shielded(k))
		ᬯᬮᬶ 0; /* nothing to do */

	ᬬᬾᬦ᭄ ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	ᬬᬾᬦ᭄ (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	/* check size of shielded key blob */
	ᬬᬾᬦ᭄ (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Calculate the ephemeral key from the prekey */
	ᬬᬾᬦ᭄ ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		goto out;
	ᬬᬾᬦ᭄ ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	ᬬᬾᬦ᭄ ((prvbuf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᬬᬾᬦ᭄ ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		goto out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(k->shielded_private, k->shielded_len, stderr);
#endif
	ᬬᬾᬦ᭄ ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	ᬬᬾᬦ᭄ ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		goto out;

	ᬬᬾᬦ᭄ ((r = private2_check_padding(prvbuf)) != 0)
		goto out;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 out:
	cipher_free(cctx);
	explicit_bzero(keyiv, parimaa_na(keyiv));
	explicit_bzero(&tmp, parimaa_na(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	ᬯᬮᬶ r;
}

static puur_naa_nka
cert_parse(sa_nracanaa sshbuf *b, sa_nracanaa sshkey *key, sa_nracanaa sshbuf *certbuf,
    const var_na *ca_sigalg_allowlist)
{
	sa_nracanaa sshbuf *principals = NULL, *crit = NULL;
	sa_nracanaa sshbuf *exts = NULL, *ca = NULL;
	u_char *sig = NULL;
	var_na *sigtype = NULL;
	size_t signed_len = 0, slen = 0, kidlen = 0;
	puur_naa_nka ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	ᬬᬾᬦ᭄ ((ret = sshbuf_putb(key->cert->certblob, certbuf)) != 0)
		ᬯᬮᬶ ret;

	/* Parse body of certificate up to signature */
	ᬬᬾᬦ᭄ ((ret = sshbuf_get_u64(b, &key->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &key->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &key->cert->key_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &key->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &key->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, NULL, NULL)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(key->cert->certblob) - sshbuf_len(b);

	ᬬᬾᬦ᭄ ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Is this a signature we're prepared to accept? */
	ᬬᬾᬦ᭄ ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ᬬᬾᬦ᭄ (ca_sigalg_allowlist != NULL &&
	    match_pattern_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		goto out;
	}

	/* Parse CA key and check whether we might accept it */
	ᬬᬾᬦ᭄ (sshkey_from_blob_internal(ca, &key->cert->signature_key, 0,
	    ca_sigalg_allowlist, NULL) != 0) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}
	ᬬᬾᬦ᭄ (!sshkey_type_is_valid_ca(key->cert->signature_key->type)) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}

	ᬬᬾᬦ᭄ (key->cert->type != SSH2_CERT_TYPE_USER &&
	    key->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_KEY_CERT_UNKNOWN_TYPE;
		goto out;
	}

	/* Parse principals section */
	ᬲᭂᬤᭂᬮ (sshbuf_len(principals) > 0) {
		var_na *principal = NULL;
		var_na **oprincipals = NULL;

		ᬬᬾᬦ᭄ (key->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		ᬬᬾᬦ᭄ ((ret = sshbuf_get_cstring(principals, &principal,
		    NULL)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		oprincipals = key->cert->principals;
		key->cert->principals = recallocarray(key->cert->principals,
		    key->cert->nprincipals, key->cert->nprincipals + 1,
		    parimaa_na(*key->cert->principals));
		ᬬᬾᬦ᭄ (key->cert->principals == NULL) {
			free(principal);
			key->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		key->cert->principals[key->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	ᬬᬾᬦ᭄ ((ret = sshbuf_putb(key->cert->critical, crit)) != 0 ||
	    (exts != NULL &&
	    (ret = sshbuf_putb(key->cert->extensions, exts)) != 0))
		goto out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	ᬲᭂᬤᭂᬮ (sshbuf_len(crit) != 0) {
		ᬬᬾᬦ᭄ ((ret = sshbuf_get_string_direct(crit, NULL, NULL)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, NULL, NULL)) != 0) {
			sshbuf_reset(key->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	ᬲᭂᬤᭂᬮ (exts != NULL && sshbuf_len(exts) != 0) {
		ᬬᬾᬦ᭄ ((ret = sshbuf_get_string_direct(exts, NULL, NULL)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, NULL, NULL)) != 0) {
			sshbuf_reset(key->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}

	/* Finally, validate signature */
	ᬬᬾᬦ᭄ ((ret = sshkey_verify(key->cert->signature_key, sig, slen,
	    sshbuf_ptr(key->cert->certblob), signed_len, NULL, 0, NULL)) != 0)
		goto out;

	/* Success */
	ret = 0;
	key->cert->signature_type = sigtype;
	sigtype = NULL;
 out:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	free(sig);
	free(sigtype);
	ᬯᬮᬶ ret;
}

puur_naa_nka
sshkey_deserialize_sk(sa_nracanaa sshbuf *b, sa_nracanaa sshkey *key)
{
	/* Parse additional security-key application string */
	ᬬᬾᬦ᭄ (sshbuf_get_cstring(b, &key->sk_application, NULL) != 0)
		ᬯᬮᬶ SSH_ERR_INVALID_FORMAT;
	ᬯᬮᬶ 0;
}

static puur_naa_nka
sshkey_from_blob_internal(sa_nracanaa sshbuf *b, sa_nracanaa sshkey **keyp,
    puur_naa_nka allow_cert, const var_na *alg_allowlist, const var_na *ca_sigalg_allowlist)
{
	puur_naa_nka type, ret = SSH_ERR_INTERNAL_ERROR;
	var_na *ktype = NULL;
	sa_nracanaa sshkey *key = NULL;
	sa_nracanaa sshbuf *copy;
	const sa_nracanaa sshkey_impl *impl;

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	ᬬᬾᬦ᭄ (keyp != NULL)
		*keyp = NULL;
	ᬬᬾᬦ᭄ ((copy = sshbuf_fromb(b)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᬬᬾᬦ᭄ (sshbuf_get_cstring(b, &ktype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	type = sshkey_type_from_name(ktype);
	ᬬᬾᬦ᭄ (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}

	ᬬᬾᬦ᭄ (alg_allowlist != NULL &&
	    !sshkey_match_keyname_to_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_KEY_ALG_UNSUPPORTED;
		goto out;
	}

	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_type(type)) == NULL) {
		ret = SSH_ERR_KEY_TYPE_UNKNOWN;
		goto out;
	}
	ᬬᬾᬦ᭄ ((key = sshkey_new(type)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᬬᬾᬦ᭄ (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		ᬬᬾᬦ᭄ (sshbuf_get_string_direct(b, NULL, NULL) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	ᬬᬾᬦ᭄ ((ret = impl->funcs->deserialize_public(ktype, b, key)) != 0)
		goto out;

	/* Parse certificate potion */
	ᬬᬾᬦ᭄ (sshkey_is_cert(key) &&
	    (ret = cert_parse(b, key, copy, ca_sigalg_allowlist)) != 0)
		goto out;

	ᬬᬾᬦ᭄ (key != NULL && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ret = 0;
	ᬬᬾᬦ᭄ (keyp != NULL) {
		*keyp = key;
		key = NULL;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(key);
	free(ktype);
	ᬯᬮᬶ ret;
}

puur_naa_nka
sshkey_from_blob(const u_char *blob, size_t blen, sa_nracanaa sshkey **keyp)
{
	sa_nracanaa sshbuf *b;
	puur_naa_nka r;

	ᬬᬾᬦ᭄ ((b = sshbuf_from(blob, blen)) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1, NULL, NULL);
	sshbuf_free(b);
	ᬯᬮᬶ r;
}

puur_naa_nka
sshkey_fromb(sa_nracanaa sshbuf *b, sa_nracanaa sshkey **keyp)
{
	ᬯᬮᬶ sshkey_from_blob_internal(b, keyp, 1, NULL, NULL);
}

puur_naa_nka
sshkey_fromb_allowlist(sa_nracanaa sshbuf *b, sa_nracanaa sshkey **keyp,
    const var_na *alg_allowlist, const var_na *ca_sigalg_allowlist)
{
	ᬯᬮᬶ sshkey_from_blob_internal(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

puur_naa_nka
sshkey_froms(sa_nracanaa sshbuf *buf, sa_nracanaa sshkey **keyp)
{
	sa_nracanaa sshbuf *b;
	puur_naa_nka r;

	ᬬᬾᬦ᭄ ((r = sshbuf_froms(buf, &b)) != 0)
		ᬯᬮᬶ r;
	r = sshkey_from_blob_internal(b, keyp, 1, NULL, NULL);
	sshbuf_free(b);
	ᬯᬮᬶ r;
}

puur_naa_nka
sshkey_get_sigtype(const u_char *sig, size_t siglen, var_na **sigtypep)
{
	puur_naa_nka r;
	sa_nracanaa sshbuf *b = NULL;
	var_na *sigtype = NULL;

	ᬬᬾᬦ᭄ (sigtypep != NULL)
		*sigtypep = NULL;
	ᬬᬾᬦ᭄ ((b = sshbuf_from(sig, siglen)) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	ᬬᬾᬦ᭄ ((r = sshbuf_get_cstring(b, &sigtype, NULL)) != 0)
		goto out;
	/* success */
	ᬬᬾᬦ᭄ (sigtypep != NULL) {
		*sigtypep = sigtype;
		sigtype = NULL;
	}
	r = 0;
 out:
	free(sigtype);
	sshbuf_free(b);
	ᬯᬮᬶ r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
puur_naa_nka
sshkey_check_cert_sigtype(const sa_nracanaa sshkey *key, const var_na *allowed)
{
	ᬬᬾᬦ᭄ (key == NULL || allowed == NULL)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;
	ᬬᬾᬦ᭄ (!sshkey_type_is_cert(key->type))
		ᬯᬮᬶ 0;
	ᬬᬾᬦ᭄ (key->cert == NULL || key->cert->signature_type == NULL)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;
	ᬬᬾᬦ᭄ (match_pattern_list(key->cert->signature_type, allowed, 0) != 1)
		ᬯᬮᬶ SSH_ERR_SIGN_ALG_UNSUPPORTED;
	ᬯᬮᬶ 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
const var_na *
sshkey_sigalg_by_name(const var_na *name)
{
	const sa_nracanaa sshkey_impl *impl;
	puur_naa_nka i;

	for (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		ᬬᬾᬦ᭄ (strcmp(impl->name, name) != 0)
			continue;
		ᬬᬾᬦ᭄ (impl->sigalg != NULL)
			ᬯᬮᬶ impl->sigalg;
		ᬬᬾᬦ᭄ (!impl->cert)
			ᬯᬮᬶ impl->name;
		ᬯᬮᬶ sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	ᬯᬮᬶ NULL;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
puur_naa_nka
sshkey_check_sigtype(const u_char *sig, size_t siglen,
    const var_na *requested_alg)
{
	const var_na *expected_alg;
	var_na *sigtype = NULL;
	puur_naa_nka r;

	ᬬᬾᬦ᭄ (requested_alg == NULL)
		ᬯᬮᬶ 0;
	ᬬᬾᬦ᭄ ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == NULL)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;
	ᬬᬾᬦ᭄ ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		ᬯᬮᬶ r;
	r = strcmp(expected_alg, sigtype) == 0;
	free(sigtype);
	ᬯᬮᬶ r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

puur_naa_nka
sshkey_sign(sa_nracanaa sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const var_na *alg, const var_na *sk_provider, const var_na *sk_pin, u_int compat)
{
	puur_naa_nka was_shielded = sshkey_is_shielded(key);
	puur_naa_nka r2, r = SSH_ERR_INTERNAL_ERROR;
	const sa_nracanaa sshkey_impl *impl;

	ᬬᬾᬦ᭄ (sigp != NULL)
		*sigp = NULL;
	ᬬᬾᬦ᭄ (lenp != NULL)
		*lenp = 0;
	ᬬᬾᬦ᭄ (datalen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;
	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_key(key)) == NULL)
		ᬯᬮᬶ SSH_ERR_KEY_TYPE_UNKNOWN;
	ᬬᬾᬦ᭄ ((r = sshkey_unshield_private(key)) != 0)
		ᬯᬮᬶ r;
	ᬬᬾᬦ᭄ (sshkey_is_sk(key)) {
		r = sshsk_sign(sk_provider, key, sigp, lenp, data,
		    datalen, compat, sk_pin);
	} ᬮᬶᬬ ᬬᬾᬦ᭄ ((key->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(key, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	} ᬮᬶᬬ {
		ᬬᬾᬦ᭄ (impl->funcs->sign == NULL)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ᬮᬶᬬ {
			r = impl->funcs->sign(key, sigp, lenp, data, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	ᬬᬾᬦ᭄ (was_shielded && (r2 = sshkey_shield_private(key)) != 0)
		ᬯᬮᬶ r2;
	ᬯᬮᬶ r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
puur_naa_nka
sshkey_verify(const sa_nracanaa sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const var_na *alg, u_int compat,
    sa_nracanaa sshkey_sig_details **detailsp)
{
	const sa_nracanaa sshkey_impl *impl;

	ᬬᬾᬦ᭄ (detailsp != NULL)
		*detailsp = NULL;
	ᬬᬾᬦ᭄ (siglen == 0 || dlen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;
	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_key(key)) == NULL)
		ᬯᬮᬶ SSH_ERR_KEY_TYPE_UNKNOWN;
	ᬯᬮᬶ impl->funcs->verify(key, sig, siglen, data, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
puur_naa_nka
sshkey_to_certified(sa_nracanaa sshkey *k)
{
	puur_naa_nka newtype;

	ᬬᬾᬦ᭄ ((newtype = sshkey_type_certified(k->type)) == -1)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;
	ᬬᬾᬦ᭄ ((k->cert = cert_new()) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	ᬯᬮᬶ 0;
}

/* Convert a certificate to its raw key equivalent */
puur_naa_nka
sshkey_drop_cert(sa_nracanaa sshkey *k)
{
	ᬬᬾᬦ᭄ (!sshkey_type_is_cert(k->type))
		ᬯᬮᬶ SSH_ERR_KEY_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = NULL;
	k->type = sshkey_type_plain(k->type);
	ᬯᬮᬶ 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
puur_naa_nka
sshkey_certify_custom(sa_nracanaa sshkey *k, sa_nracanaa sshkey *ca, const var_na *alg,
    const var_na *sk_provider, const var_na *sk_pin,
    sshkey_certify_signer *signer, void *signer_ctx)
{
	const sa_nracanaa sshkey_impl *impl;
	sa_nracanaa sshbuf *principals = NULL;
	u_char *ca_blob = NULL, *sig_blob = NULL, nonce[32];
	size_t i, ca_len, sig_len;
	puur_naa_nka ret = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa sshbuf *cert = NULL;
	var_na *sigtype = NULL;

	ᬬᬾᬦ᭄ (k == NULL || k->cert == NULL ||
	    k->cert->certblob == NULL || ca == NULL)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;
	ᬬᬾᬦ᭄ (!sshkey_is_cert(k))
		ᬯᬮᬶ SSH_ERR_KEY_TYPE_UNKNOWN;
	ᬬᬾᬦ᭄ (!sshkey_type_is_valid_ca(ca->type))
		ᬯᬮᬶ SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_key(k)) == NULL)
		ᬯᬮᬶ SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	ᬬᬾᬦ᭄ (alg == NULL)
		alg = k->cert->signature_type;
	ᬮᬶᬬ ᬬᬾᬦ᭄ (k->cert->signature_type != NULL &&
	    strcmp(alg, k->cert->signature_type) != 0)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	ᬬᬾᬦ᭄ (alg == NULL && ca->type == KEY_RSA)
		alg = "rsa-sha2-512";

	ᬬᬾᬦ᭄ ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		ᬯᬮᬶ SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	ᬬᬾᬦ᭄ ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		goto out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, parimaa_na(nonce));
	ᬬᬾᬦ᭄ ((ret = sshbuf_put_string(cert, nonce, parimaa_na(nonce))) != 0)
		goto out;

	/* Public key next */
	ᬬᬾᬦ᭄ ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		goto out;

	/* Then remaining cert fields */
	ᬬᬾᬦ᭄ ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->key_id)) != 0)
		goto out;

	ᬬᬾᬦ᭄ ((principals = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	for (i = 0; i < k->cert->nprincipals; i++) {
		ᬬᬾᬦ᭄ ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			goto out;
	}
	ᬬᬾᬦ᭄ ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, NULL, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		goto out;

	/* Sign the whole mess */
	ᬬᬾᬦ᭄ ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		goto out;
	/* Check and update signature_type against what was actually used */
	ᬬᬾᬦ᭄ ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		goto out;
	ᬬᬾᬦ᭄ (alg != NULL && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		goto out;
	}
	ᬬᬾᬦ᭄ (k->cert->signature_type == NULL) {
		k->cert->signature_type = sigtype;
		sigtype = NULL;
	}
	/* Append signature and we are done */
	ᬬᬾᬦ᭄ ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		goto out;
	ret = 0;
 out:
	ᬬᬾᬦ᭄ (ret != 0)
		sshbuf_reset(cert);
	free(sig_blob);
	free(ca_blob);
	free(sigtype);
	sshbuf_free(principals);
	ᬯᬮᬶ ret;
}

static puur_naa_nka
default_key_sign(sa_nracanaa sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const var_na *alg, const var_na *sk_provider, const var_na *sk_pin,
    u_int compat, void *ctx)
{
	ᬬᬾᬦ᭄ (ctx != NULL)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;
	ᬯᬮᬶ sshkey_sign(key, sigp, lenp, data, datalen, alg,
	    sk_provider, sk_pin, compat);
}

puur_naa_nka
sshkey_certify(sa_nracanaa sshkey *k, sa_nracanaa sshkey *ca, const var_na *alg,
    const var_na *sk_provider, const var_na *sk_pin)
{
	ᬯᬮᬶ sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_key_sign, NULL);
}

puur_naa_nka
sshkey_cert_check_authority(const sa_nracanaa sshkey *k,
    puur_naa_nka want_host, puur_naa_nka wildcard_pattern, uint64_t verify_time,
    const var_na *name, const var_na **reason)
{
	u_int i, principal_matches;

	ᬬᬾᬦ᭄ (reason == NULL)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;
	ᬬᬾᬦ᭄ (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		ᬯᬮᬶ SSH_ERR_KEY_CERT_INVALID;
	}
	ᬬᬾᬦ᭄ (want_host) {
		ᬬᬾᬦ᭄ (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			ᬯᬮᬶ SSH_ERR_KEY_CERT_INVALID;
		}
	} ᬮᬶᬬ {
		ᬬᬾᬦ᭄ (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			ᬯᬮᬶ SSH_ERR_KEY_CERT_INVALID;
		}
	}
	ᬬᬾᬦ᭄ (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		ᬯᬮᬶ SSH_ERR_KEY_CERT_INVALID;
	}
	ᬬᬾᬦ᭄ (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		ᬯᬮᬶ SSH_ERR_KEY_CERT_INVALID;
	}
	ᬬᬾᬦ᭄ (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		ᬯᬮᬶ SSH_ERR_KEY_CERT_INVALID;
	}
	ᬬᬾᬦ᭄ (name == NULL)
		ᬯᬮᬶ 0; /* principal matching not requested */

	principal_matches = 0;
	for (i = 0; i < k->cert->nprincipals; i++) {
		ᬬᬾᬦ᭄ (wildcard_pattern) {
			ᬬᬾᬦ᭄ (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				bha_nga;
			}
		} ᬮᬶᬬ ᬬᬾᬦ᭄ (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			bha_nga;
		}
	}
	ᬬᬾᬦ᭄ (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		ᬯᬮᬶ SSH_ERR_KEY_CERT_INVALID;
	}
	ᬯᬮᬶ 0;
}

puur_naa_nka
sshkey_cert_check_authority_now(const sa_nracanaa sshkey *k,
    puur_naa_nka want_host, puur_naa_nka wildcard_pattern, const var_na *name,
    const var_na **reason)
{
	time_t now;

	ᬬᬾᬦ᭄ ((now = time(NULL)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		ᬯᬮᬶ SSH_ERR_KEY_CERT_INVALID;
	}
	ᬯᬮᬶ sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

puur_naa_nka
sshkey_cert_check_host(const sa_nracanaa sshkey *key, const var_na *host,
    const var_na *ca_sign_algorithms, const var_na **reason)
{
	puur_naa_nka r;

	ᬬᬾᬦ᭄ ((r = sshkey_cert_check_authority_now(key, 1, 1, host, reason)) != 0)
		ᬯᬮᬶ r;
	ᬬᬾᬦ᭄ (sshbuf_len(key->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		ᬯᬮᬶ SSH_ERR_KEY_CERT_INVALID;
	}
	ᬬᬾᬦ᭄ (ca_sign_algorithms != NULL &&
	    (r = sshkey_check_cert_sigtype(key, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		ᬯᬮᬶ SSH_ERR_KEY_CERT_INVALID;
	}
	ᬯᬮᬶ 0;
}

size_t
sshkey_format_cert_validity(const sa_nracanaa sshkey_cert *cert, var_na *s, size_t l)
{
	var_na from[32], to[32], ret[128];

	*from = *to = '\0';
	ᬬᬾᬦ᭄ (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		ᬯᬮᬶ strlcpy(s, "forever", l);

	ᬬᬾᬦ᭄ (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, parimaa_na(from));
	ᬬᬾᬦ᭄ (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, parimaa_na(to));

	ᬬᬾᬦ᭄ (cert->valid_after == 0)
		snprintf(ret, parimaa_na(ret), "before %s", to);
	ᬮᬶᬬ ᬬᬾᬦ᭄ (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, parimaa_na(ret), "after %s", from);
	ᬮᬶᬬ
		snprintf(ret, parimaa_na(ret), "from %s to %s", from, to);

	ᬯᬮᬶ strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
puur_naa_nka
sshkey_serialize_private_sk(const sa_nracanaa sshkey *key, sa_nracanaa sshbuf *b)
{
	puur_naa_nka r;

	ᬬᬾᬦ᭄ ((r = sshbuf_put_cstring(b, key->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, key->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, key->sk_key_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, key->sk_reserved)) != 0)
		ᬯᬮᬶ r;

	ᬯᬮᬶ 0;
}

static puur_naa_nka
sshkey_private_serialize_opt(sa_nracanaa sshkey *key, sa_nracanaa sshbuf *buf,
    ga_nanaa sshkey_serialize_rep opts)
{
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;
	puur_naa_nka was_shielded = sshkey_is_shielded(key);
	sa_nracanaa sshbuf *b = NULL;
	const sa_nracanaa sshkey_impl *impl;

	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_key(key)) == NULL)
		ᬯᬮᬶ SSH_ERR_INTERNAL_ERROR;
	ᬬᬾᬦ᭄ ((r = sshkey_unshield_private(key)) != 0)
		ᬯᬮᬶ r;
	ᬬᬾᬦ᭄ ((b = sshbuf_new()) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	ᬬᬾᬦ᭄ ((r = sshbuf_put_cstring(b, sshkey_ssh_name(key))) != 0)
		goto out;
	ᬬᬾᬦ᭄ (sshkey_is_cert(key)) {
		ᬬᬾᬦ᭄ (key->cert == NULL ||
		    sshbuf_len(key->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		ᬬᬾᬦ᭄ ((r = sshbuf_put_stringb(b, key->cert->certblob)) != 0)
			goto out;
	}
	ᬬᬾᬦ᭄ ((r = impl->funcs->serialize_private(key, b, opts)) != 0)
		goto out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	ᬬᬾᬦ᭄ (was_shielded)
		r = sshkey_shield_private(key);
	ᬬᬾᬦ᭄ (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	ᬯᬮᬶ r;
}

puur_naa_nka
sshkey_private_serialize(sa_nracanaa sshkey *key, sa_nracanaa sshbuf *b)
{
	ᬯᬮᬶ sshkey_private_serialize_opt(key, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
puur_naa_nka
sshkey_private_deserialize_sk(sa_nracanaa sshbuf *buf, sa_nracanaa sshkey *k)
{
	puur_naa_nka r;

	ᬬᬾᬦ᭄ ((k->sk_key_handle = sshbuf_new()) == NULL ||
	    (k->sk_reserved = sshbuf_new()) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	ᬬᬾᬦ᭄ ((r = sshbuf_get_cstring(buf, &k->sk_application, NULL)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_key_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		ᬯᬮᬶ r;

	ᬯᬮᬶ 0;
}

puur_naa_nka
sshkey_private_deserialize(sa_nracanaa sshbuf *buf, sa_nracanaa sshkey **kp)
{
	const sa_nracanaa sshkey_impl *impl;
	var_na *tname = NULL;
	var_na *expect_sk_application = NULL;
	u_char *expect_ed25519_pk = NULL;
	sa_nracanaa sshkey *k = NULL;
	puur_naa_nka type, r = SSH_ERR_INTERNAL_ERROR;

	ᬬᬾᬦ᭄ (kp != NULL)
		*kp = NULL;
	ᬬᬾᬦ᭄ ((r = sshbuf_get_cstring(buf, &tname, NULL)) != 0)
		goto out;
	type = sshkey_type_from_name(tname);
	ᬬᬾᬦ᭄ (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		ᬬᬾᬦ᭄ ((r = sshkey_froms(buf, &k)) != 0)
			goto out;
		ᬬᬾᬦ᭄ (k->type != type) {
			r = SSH_ERR_KEY_CERT_MISMATCH;
			goto out;
		}
		/* For ECDSA keys, the group must match too */
		ᬬᬾᬦ᭄ (k->type == KEY_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_KEY_CERT_MISMATCH;
			goto out;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = NULL;
		k->ed25519_pk = NULL;
	} ᬮᬶᬬ {
		ᬬᬾᬦ᭄ ((k = sshkey_new(type)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
	}
	ᬬᬾᬦ᭄ ((impl = sshkey_impl_from_type(type)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	ᬬᬾᬦ᭄ ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		goto out;

	ᬬᬾᬦ᭄ ((expect_sk_application != NULL && (k->sk_application == NULL ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != NULL && (k->ed25519_pk == NULL ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_KEY_CERT_MISMATCH;
		goto out;
	}
	/* success */
	r = 0;
	ᬬᬾᬦ᭄ (kp != NULL) {
		*kp = k;
		k = NULL;
	}
 out:
	free(tname);
	sshkey_free(k);
	free(expect_sk_application);
	free(expect_ed25519_pk);
	ᬯᬮᬶ r;
}

#ifdef WITH_OPENSSL
puur_naa_nka
sshkey_ec_validate_public(const EC_GROUP *group, const EC_POINT *public)
{
	EC_POINT *nq = NULL;
	BIGNUM *order = NULL, *cofactor = NULL;
	puur_naa_nka ret = SSH_ERR_KEY_INVALID_EC_VALUE;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	ᬬᬾᬦ᭄ (EC_POINT_is_at_infinity(group, public))
		goto out;

	ᬬᬾᬦ᭄ ((cofactor = BN_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᬬᬾᬦ᭄ (EC_GROUP_get_cofactor(group, cofactor, NULL) != 1)
		goto out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	ᬬᬾᬦ᭄ (!BN_is_one(cofactor)) {
		ᬬᬾᬦ᭄ ((order = BN_new()) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		ᬬᬾᬦ᭄ (EC_GROUP_get_order(group, order, NULL) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		ᬬᬾᬦ᭄ ((nq = EC_POINT_new(group)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		ᬬᬾᬦ᭄ (EC_POINT_mul(group, nq, NULL, public, order, NULL) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		ᬬᬾᬦ᭄ (EC_POINT_is_at_infinity(group, nq) != 1)
			goto out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	ᬯᬮᬶ ret;
}

puur_naa_nka
sshkey_ec_validate_private(const EC_KEY *key)
{
	BIGNUM *order = NULL, *tmp = NULL;
	puur_naa_nka ret = SSH_ERR_KEY_INVALID_EC_VALUE;

	ᬬᬾᬦ᭄ ((order = BN_new()) == NULL || (tmp = BN_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* log2(private) > log2(order)/2 */
	ᬬᬾᬦ᭄ (EC_GROUP_get_order(EC_KEY_get0_group(key), order, NULL) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ᬬᬾᬦ᭄ (BN_num_bits(EC_KEY_get0_private_key(key)) <=
	    BN_num_bits(order) / 2)
		goto out;

	/* private < order - 1 */
	ᬬᬾᬦ᭄ (!BN_sub(tmp, order, BN_value_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ᬬᬾᬦ᭄ (BN_cmp(EC_KEY_get0_private_key(key), tmp) >= 0)
		goto out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	ᬯᬮᬶ ret;
}

void
sshkey_dump_ec_point(const EC_GROUP *group, const EC_POINT *point)
{
	BIGNUM *x = NULL, *y = NULL;

	ᬬᬾᬦ᭄ (point == NULL) {
		fputs("point=(NULL)\n", stderr);
		ᬯᬮᬶ;
	}
	ᬬᬾᬦ᭄ ((x = BN_new()) == NULL || (y = BN_new()) == NULL) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		goto out;
	}
	ᬬᬾᬦ᭄ (EC_POINT_get_affine_coordinates(group, point, x, y, NULL) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		goto out;
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

void
sshkey_dump_ec_key(const EC_KEY *key)
{
	const BIGNUM *exponent;

	sshkey_dump_ec_point(EC_KEY_get0_group(key),
	    EC_KEY_get0_public_key(key));
	fputs("exponent=", stderr);
	ᬬᬾᬦ᭄ ((exponent = EC_KEY_get0_private_key(key)) == NULL)
		fputs("(NULL)", stderr);
	ᬮᬶᬬ
		BN_print_fp(stderr, EC_KEY_get0_private_key(key));
	fputs("\n", stderr);
}
#endif /* WITH_OPENSSL */

static puur_naa_nka
sshkey_private_to_blob2(sa_nracanaa sshkey *prv, sa_nracanaa sshbuf *blob,
    const var_na *passphrase, const var_na *comment, const var_na *ciphername,
    puur_naa_nka rounds)
{
	u_char *cp, *key = NULL, *pubkeyblob = NULL;
	u_char salt[SALT_LEN];
	size_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa sshcipher_ctx *ciphercontext = NULL;
	const sa_nracanaa sshcipher *cipher;
	const var_na *kdfname = KDFNAME;
	sa_nracanaa sshbuf *encoded = NULL, *encrypted = NULL, *kdf = NULL;

	ᬬᬾᬦ᭄ (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	ᬬᬾᬦ᭄ (rounds > MAX_KDF_ROUNDS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	ᬬᬾᬦ᭄ (passphrase == NULL || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} ᬮᬶᬬ ᬬᬾᬦ᭄ (ciphername == NULL)
		ciphername = DEFAULT_CIPHERNAME;
	ᬬᬾᬦ᭄ ((cipher = cipher_by_name(ciphername)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	ᬬᬾᬦ᭄ ((kdf = sshbuf_new()) == NULL ||
	    (encoded = sshbuf_new()) == NULL ||
	    (encrypted = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	ᬬᬾᬦ᭄ ((key = calloc(1, keylen + ivlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᬬᬾᬦ᭄ (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		ᬬᬾᬦ᭄ (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, key, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		ᬬᬾᬦ᭄ ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			goto out;
	} ᬮᬶᬬ ᬬᬾᬦ᭄ (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	ᬬᬾᬦ᭄ ((r = cipher_init(&ciphercontext, cipher, key, keylen,
	    key + keylen, ivlen, 1)) != 0)
		goto out;

	ᬬᬾᬦ᭄ ((r = sshbuf_put(encoded, AUTH_MAGIC, parimaa_na(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_to_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		goto out;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	ᬬᬾᬦ᭄ ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		goto out;

	/* append private key and comment*/
	ᬬᬾᬦ᭄ ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		goto out;

	/* padding */
	i = 0;
	ᬲᭂᬤᭂᬮ (sshbuf_len(encrypted) % blocksize) {
		ᬬᬾᬦ᭄ ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			goto out;
	}

	/* length in destination buffer */
	ᬬᬾᬦ᭄ ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		goto out;

	/* encrypt */
	ᬬᬾᬦ᭄ ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		goto out;
	ᬬᬾᬦ᭄ ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		goto out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	ᬬᬾᬦ᭄ ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_END, MARK_END_LEN)) != 0)
		goto out;

	/* success */
	r = 0;

 out:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, parimaa_na(salt));
	ᬬᬾᬦ᭄ (key != NULL)
		freezero(key, keylen + ivlen);
	ᬬᬾᬦ᭄ (pubkeyblob != NULL)
		freezero(pubkeyblob, pubkeylen);
	ᬯᬮᬶ r;
}

static puur_naa_nka
private2_uudecode(sa_nracanaa sshbuf *blob, sa_nracanaa sshbuf **decodedp)
{
	const u_char *cp;
	size_t encoded_len;
	puur_naa_nka r;
	u_char last;
	sa_nracanaa sshbuf *encoded = NULL, *decoded = NULL;

	ᬬᬾᬦ᭄ (blob == NULL || decodedp == NULL)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;

	*decodedp = NULL;

	ᬬᬾᬦ᭄ ((encoded = sshbuf_new()) == NULL ||
	    (decoded = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	ᬬᬾᬦ᭄ (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	ᬲᭂᬤᭂᬮ (encoded_len > 0) {
		ᬬᬾᬦ᭄ (*cp != '\n' && *cp != '\r') {
			ᬬᬾᬦ᭄ ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				goto out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		ᬬᬾᬦ᭄ (last == '\n') {
			ᬬᬾᬦ᭄ (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				ᬬᬾᬦ᭄ ((r = sshbuf_put_u8(encoded, 0)) != 0)
					goto out;
				bha_nga;
			}
		}
	}
	ᬬᬾᬦ᭄ (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* decode base64 */
	ᬬᬾᬦ᭄ ((r = sshbuf_b64tod(decoded, (var_na *)sshbuf_ptr(encoded))) != 0)
		goto out;

	/* check magic */
	ᬬᬾᬦ᭄ (sshbuf_len(decoded) < parimaa_na(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, parimaa_na(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* success */
	*decodedp = decoded;
	decoded = NULL;
	r = 0;
 out:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	ᬯᬮᬶ r;
}

static puur_naa_nka
private2_decrypt(sa_nracanaa sshbuf *decoded, const var_na *passphrase,
    sa_nracanaa sshbuf **decryptedp, sa_nracanaa sshkey **pubkeyp)
{
	var_na *ciphername = NULL, *kdfname = NULL;
	const sa_nracanaa sshcipher *cipher = NULL;
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	sa_nracanaa sshbuf *kdf = NULL, *decrypted = NULL;
	sa_nracanaa sshcipher_ctx *ciphercontext = NULL;
	sa_nracanaa sshkey *pubkey = NULL;
	u_char *key = NULL, *salt = NULL, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	ᬬᬾᬦ᭄ (decoded == NULL || decryptedp == NULL || pubkeyp == NULL)
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = NULL;
	*pubkeyp = NULL;

	ᬬᬾᬦ᭄ ((decrypted = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* parse public portion of key */
	ᬬᬾᬦ᭄ ((r = sshbuf_consume(decoded, parimaa_na(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, NULL)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		goto out;

	ᬬᬾᬦ᭄ (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	ᬬᬾᬦ᭄ ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		goto out;

	ᬬᬾᬦ᭄ ((cipher = cipher_by_name(ciphername)) == NULL) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	ᬬᬾᬦ᭄ (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	ᬬᬾᬦ᭄ (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ᬬᬾᬦ᭄ ((passphrase == NULL || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	ᬬᬾᬦ᭄ (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	ᬬᬾᬦ᭄ ((key = calloc(1, keylen + ivlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᬬᬾᬦ᭄ (strcmp(kdfname, "bcrypt") == 0) {
		ᬬᬾᬦ᭄ ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			goto out;
		ᬬᬾᬦ᭄ (rounds > MAX_KDF_ROUNDS) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		ᬬᬾᬦ᭄ (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    key, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	ᬬᬾᬦ᭄ (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* decrypt private portion of key */
	ᬬᬾᬦ᭄ ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, key, keylen,
	    key + keylen, ivlen, 0)) != 0)
		goto out;
	ᬬᬾᬦ᭄ ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		ᬬᬾᬦ᭄ (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}
	ᬬᬾᬦ᭄ ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		goto out;
	/* there should be no trailing data */
	ᬬᬾᬦ᭄ (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* check check bytes */
	ᬬᬾᬦ᭄ ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		goto out;
	ᬬᬾᬦ᭄ (check1 != check2) {
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = NULL;
	*pubkeyp = pubkey;
	pubkey = NULL;
	r = 0;
 out:
	cipher_free(ciphercontext);
	free(ciphername);
	free(kdfname);
	sshkey_free(pubkey);
	ᬬᬾᬦ᭄ (salt != NULL) {
		explicit_bzero(salt, slen);
		free(salt);
	}
	ᬬᬾᬦ᭄ (key != NULL) {
		explicit_bzero(key, keylen + ivlen);
		free(key);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	ᬯᬮᬶ r;
}

static puur_naa_nka
sshkey_parse_private2(sa_nracanaa sshbuf *blob, puur_naa_nka type, const var_na *passphrase,
    sa_nracanaa sshkey **keyp, var_na **commentp)
{
	var_na *comment = NULL;
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa sshbuf *decoded = NULL, *decrypted = NULL;
	sa_nracanaa sshkey *k = NULL, *pubkey = NULL;

	ᬬᬾᬦ᭄ (keyp != NULL)
		*keyp = NULL;
	ᬬᬾᬦ᭄ (commentp != NULL)
		*commentp = NULL;

	/* Undo base64 encoding and decrypt the private section */
	ᬬᬾᬦ᭄ ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		goto out;

	ᬬᬾᬦ᭄ (type != KEY_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}

	/* Load the private key and comment */
	ᬬᬾᬦ᭄ ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, NULL)) != 0)
		goto out;

	/* Check deterministic padding after private section */
	ᬬᬾᬦ᭄ ((r = private2_check_padding(decrypted)) != 0)
		goto out;

	/* Check that the public key in the envelope matches the private key */
	ᬬᬾᬦ᭄ (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* success */
	r = 0;
	ᬬᬾᬦ᭄ (keyp != NULL) {
		*keyp = k;
		k = NULL;
	}
	ᬬᬾᬦ᭄ (commentp != NULL) {
		*commentp = comment;
		comment = NULL;
	}
 out:
	free(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	ᬯᬮᬶ r;
}

static puur_naa_nka
sshkey_parse_private2_pubkey(sa_nracanaa sshbuf *blob, puur_naa_nka type,
    sa_nracanaa sshkey **keyp)
{
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa sshbuf *decoded = NULL;
	sa_nracanaa sshkey *pubkey = NULL;
	u_int nkeys = 0;

	ᬬᬾᬦ᭄ (keyp != NULL)
		*keyp = NULL;

	ᬬᬾᬦ᭄ ((r = private2_uudecode(blob, &decoded)) != 0)
		goto out;
	/* parse public key from unencrypted envelope */
	ᬬᬾᬦ᭄ ((r = sshbuf_consume(decoded, parimaa_na(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		goto out;

	ᬬᬾᬦ᭄ (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Parse the public key */
	ᬬᬾᬦ᭄ ((r = sshkey_froms(decoded, &pubkey)) != 0)
		goto out;

	ᬬᬾᬦ᭄ (type != KEY_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}

	/* success */
	r = 0;
	ᬬᬾᬦ᭄ (keyp != NULL) {
		*keyp = pubkey;
		pubkey = NULL;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	ᬯᬮᬶ r;
}

#ifdef WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
static puur_naa_nka
sshkey_private_to_blob_pem_pkcs8(sa_nracanaa sshkey *key, sa_nracanaa sshbuf *buf,
    puur_naa_nka format, const var_na *_passphrase, const var_na *comment)
{
	puur_naa_nka was_shielded = sshkey_is_shielded(key);
	puur_naa_nka success, r;
	puur_naa_nka blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : NULL;
	const EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : NULL;
	var_na *bptr;
	BIO *bio = NULL;
	sa_nracanaa sshbuf *blob;
	EVP_PKEY *pkey = NULL;

	ᬬᬾᬦ᭄ (len > 0 && len <= 4)
		ᬯᬮᬶ SSH_ERR_PASSPHRASE_TOO_SHORT;
	ᬬᬾᬦ᭄ ((blob = sshbuf_new()) == NULL)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	ᬬᬾᬦ᭄ ((bio = BIO_new(BIO_s_mem())) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᬬᬾᬦ᭄ ((r = sshkey_unshield_private(key)) != 0)
		goto out;

	switch (key->type) {
	pak_sa KEY_ECDSA:
		ᬬᬾᬦ᭄ (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivateKey(bio,
			    EVP_PKEY_get0_EC_KEY(key->pkey),
			    cipher, passphrase, len, NULL, NULL);
		} ᬮᬶᬬ {
			pkey = key->pkey;
			EVP_PKEY_up_ref(key->pkey);
			success = 1;
		}
		bha_nga;
	pak_sa KEY_RSA:
		ᬬᬾᬦ᭄ (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivateKey(bio,
			    EVP_PKEY_get0_RSA(key->pkey),
			    cipher, passphrase, len, NULL, NULL);
		} ᬮᬶᬬ {
			pkey = key->pkey;
			EVP_PKEY_up_ref(key->pkey);
			success = 1;
		}
		bha_nga;
#ifdef OPENSSL_HAS_ED25519
	pak_sa KEY_ED25519:
		ᬬᬾᬦ᭄ (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		} ᬮᬶᬬ {
			pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,
			    NULL, key->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != NULL;
		}
		bha_nga;
#endif
	default:
		success = 0;
		bha_nga;
	}
	ᬬᬾᬦ᭄ (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ᬬᬾᬦ᭄ (format == SSHKEY_PRIVATE_PKCS8) {
		ᬬᬾᬦ᭄ ((success = PEM_write_bio_PrivateKey(bio, pkey, cipher,
		    passphrase, len, NULL, NULL)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}
	ᬬᬾᬦ᭄ ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	ᬬᬾᬦ᭄ ((r = sshbuf_put(blob, bptr, blen)) != 0)
		goto out;
	r = 0;
 out:
	ᬬᬾᬦ᭄ (was_shielded)
		r = sshkey_shield_private(key);
	ᬬᬾᬦ᭄ (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	ᬯᬮᬶ r;
}
#endif /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
puur_naa_nka
sshkey_private_to_fileblob(sa_nracanaa sshkey *key, sa_nracanaa sshbuf *blob,
    const var_na *passphrase, const var_na *comment,
    puur_naa_nka format, const var_na *openssh_format_cipher, puur_naa_nka openssh_format_rounds)
{
	switch (key->type) {
#ifdef WITH_OPENSSL
	pak_sa KEY_ECDSA:
	pak_sa KEY_RSA:
	pak_sa KEY_ED25519:
		bha_nga; /* see below */
#ᬮᬶᬬ /* WITH_OPENSSL */
	pak_sa KEY_ED25519:
#endif /* WITH_OPENSSL */
	pak_sa KEY_ED25519_SK:
#ifdef WITH_OPENSSL
	pak_sa KEY_ECDSA_SK:
#endif /* WITH_OPENSSL */
	pak_sa KEY_MLDSA44_ED25519:
		ᬯᬮᬶ sshkey_private_to_blob2(key, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	default:
		ᬯᬮᬶ SSH_ERR_KEY_TYPE_UNKNOWN;
	}

#ifdef WITH_OPENSSL
	switch (format) {
	pak_sa SSHKEY_PRIVATE_OPENSSH:
		ᬯᬮᬶ sshkey_private_to_blob2(key, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	pak_sa SSHKEY_PRIVATE_PEM:
	pak_sa SSHKEY_PRIVATE_PKCS8:
		ᬯᬮᬶ sshkey_private_to_blob_pem_pkcs8(key, blob,
		    format, passphrase, comment);
	default:
		ᬯᬮᬶ SSH_ERR_INVALID_ARGUMENT;
	}
#endif /* WITH_OPENSSL */
}

#ifdef WITH_OPENSSL
static puur_naa_nka
translate_libcrypto_error(unsigned long pem_err)
{
	puur_naa_nka pem_reason = ERR_GET_REASON(pem_err);

	switch (ERR_GET_LIB(pem_err)) {
	pak_sa ERR_LIB_PEM:
		switch (pem_reason) {
		pak_sa PEM_R_BAD_PASSWORD_READ:
#ifdef PEM_R_PROBLEMS_GETTING_PASSWORD
		pak_sa PEM_R_PROBLEMS_GETTING_PASSWORD:
#endif
#ifdef PEM_R_BAD_DECRYPT
		pak_sa PEM_R_BAD_DECRYPT:
#endif
			ᬯᬮᬶ SSH_ERR_KEY_WRONG_PASSPHRASE;
		default:
			ᬯᬮᬶ SSH_ERR_INVALID_FORMAT;
		}
	pak_sa ERR_LIB_EVP:
		switch (pem_reason) {
#ifdef EVP_R_BAD_DECRYPT
		pak_sa EVP_R_BAD_DECRYPT:
			ᬯᬮᬶ SSH_ERR_KEY_WRONG_PASSPHRASE;
#endif
#ifdef EVP_R_BN_DECODE_ERROR
		pak_sa EVP_R_BN_DECODE_ERROR:
#endif
		pak_sa EVP_R_DECODE_ERROR:
#ifdef EVP_R_PRIVATE_KEY_DECODE_ERROR
		pak_sa EVP_R_PRIVATE_KEY_DECODE_ERROR:
#endif
			ᬯᬮᬶ SSH_ERR_INVALID_FORMAT;
		default:
			ᬯᬮᬶ SSH_ERR_LIBCRYPTO_ERROR;
		}
	pak_sa ERR_LIB_ASN1:
#ifdef ERR_LIB_OSSL_DECODER
	pak_sa ERR_LIB_OSSL_DECODER:
#endif
		ᬯᬮᬶ SSH_ERR_INVALID_FORMAT;
	}
	ᬯᬮᬶ SSH_ERR_LIBCRYPTO_ERROR;
}

static void
clear_libcrypto_errors(void)
{
	ᬲᭂᬤᭂᬮ (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
static puur_naa_nka
convert_libcrypto_error(void)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	ᬬᬾᬦ᭄ (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_KEY_WRONG_PASSPHRASE)
		ᬯᬮᬶ SSH_ERR_KEY_WRONG_PASSPHRASE;
	ᬯᬮᬶ translate_libcrypto_error(ERR_peek_last_error());
}

static puur_naa_nka
pem_passphrase_cb(var_na *buf, puur_naa_nka size, puur_naa_nka rwflag, void *u)
{
	var_na *p = (var_na *)u;
	size_t len;

	ᬬᬾᬦ᭄ (p == NULL || (len = strlen(p)) == 0)
		ᬯᬮᬶ -1;
	ᬬᬾᬦ᭄ (size < 0 || len > (size_t)size)
		ᬯᬮᬶ -1;
	memcpy(buf, p, len);
	ᬯᬮᬶ (puur_naa_nka)len;
}

static puur_naa_nka
sshkey_parse_private_pem_fileblob(sa_nracanaa sshbuf *blob, puur_naa_nka type,
    const var_na *passphrase, sa_nracanaa sshkey **keyp)
{
	EVP_PKEY *pk = NULL;
	sa_nracanaa sshkey *prv = NULL;
	BIO *bio = NULL;
	puur_naa_nka r;
	RSA *rsa = NULL;
	EC_KEY *ecdsa = NULL;

	ᬬᬾᬦ᭄ (keyp != NULL)
		*keyp = NULL;

	ᬬᬾᬦ᭄ ((bio = BIO_new(BIO_s_mem())) == NULL || sshbuf_len(blob) > INT_MAX)
		ᬯᬮᬶ SSH_ERR_ALLOC_FAIL;
	ᬬᬾᬦ᭄ (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (puur_naa_nka)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	clear_libcrypto_errors();
	ᬬᬾᬦ᭄ ((pk = PEM_read_bio_PrivateKey(bio, NULL, pem_passphrase_cb,
	    (var_na *)passphrase)) == NULL) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		ᬬᬾᬦ᭄ (passphrase != NULL && *passphrase != '\0')
			r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		ᬮᬶᬬ
			r = convert_libcrypto_error();
		goto out;
	}
	ᬬᬾᬦ᭄ (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == KEY_UNSPEC || type == KEY_RSA)) {
		ᬬᬾᬦ᭄ ((prv = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		ᬬᬾᬦ᭄ ((rsa = EVP_PKEY_get1_RSA(pk)) == NULL) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		prv->type = KEY_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#endif
		ᬬᬾᬦ᭄ (RSA_blinding_on(rsa, NULL) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		ᬬᬾᬦ᭄ ((r = sshkey_check_rsa_length(prv, 0)) != 0)
			goto out;
	} ᬮᬶᬬ ᬬᬾᬦ᭄ (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == KEY_UNSPEC || type == KEY_ECDSA)) {
		ᬬᬾᬦ᭄ ((prv = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		ᬬᬾᬦ᭄ ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_KEY(pk)) == NULL) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		prv->type = KEY_ECDSA;
		ᬬᬾᬦ᭄ (sshkey_curve_nid_to_name(prv->ecdsa_nid) == NULL ||
		    sshkey_ec_validate_public(EC_KEY_get0_group(ecdsa),
		    EC_KEY_get0_public_key(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#ifdef DEBUG_PK
		ᬬᬾᬦ᭄ (prv != NULL && prv->pkey != NULL)
			sshkey_dump_ec_key(EVP_PKEY_get0_EC_KEY(prv->pkey));
#endif
#ifdef OPENSSL_HAS_ED25519
	} ᬮᬶᬬ ᬬᬾᬦ᭄ (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == KEY_UNSPEC || type == KEY_ED25519)) {
		size_t len;

		ᬬᬾᬦ᭄ ((prv = sshkey_new(KEY_UNSPEC)) == NULL ||
		    (prv->ed25519_sk = calloc(1, ED25519_SK_SZ)) == NULL ||
		    (prv->ed25519_pk = calloc(1, ED25519_PK_SZ)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		prv->type = KEY_ED25519;
		len = ED25519_PK_SZ;
		ᬬᬾᬦ᭄ (!EVP_PKEY_get_raw_public_key(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		ᬬᬾᬦ᭄ (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		ᬬᬾᬦ᭄ (!EVP_PKEY_get_raw_private_key(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		ᬬᬾᬦ᭄ (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		/* Append the public key to our private key */
		memcpy(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#ifdef DEBUG_PK
		sshbuf_dump_data(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#endif
#endif /* OPENSSL_HAS_ED25519 */
	} ᬮᬶᬬ {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	r = 0;
	ᬬᬾᬦ᭄ (keyp != NULL) {
		*keyp = prv;
		prv = NULL;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_KEY_free(ecdsa);
	sshkey_free(prv);
	ᬯᬮᬶ r;
}
#endif /* WITH_OPENSSL */

puur_naa_nka
sshkey_parse_private_fileblob_type(sa_nracanaa sshbuf *blob, puur_naa_nka type,
    const var_na *passphrase, sa_nracanaa sshkey **keyp, var_na **commentp)
{
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;

	ᬬᬾᬦ᭄ (keyp != NULL)
		*keyp = NULL;
	ᬬᬾᬦ᭄ (commentp != NULL)
		*commentp = NULL;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	ᬬᬾᬦ᭄ (r != SSH_ERR_INVALID_FORMAT)
		ᬯᬮᬶ r;
#ifdef WITH_OPENSSL
	ᬯᬮᬶ sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#ᬮᬶᬬ
	ᬯᬮᬶ SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

puur_naa_nka
sshkey_parse_private_fileblob(sa_nracanaa sshbuf *buffer, const var_na *passphrase,
    sa_nracanaa sshkey **keyp, var_na **commentp)
{
	ᬬᬾᬦ᭄ (keyp != NULL)
		*keyp = NULL;
	ᬬᬾᬦ᭄ (commentp != NULL)
		*commentp = NULL;

	ᬯᬮᬶ sshkey_parse_private_fileblob_type(buffer, KEY_UNSPEC,
	    passphrase, keyp, commentp);
}

void
sshkey_sig_details_free(sa_nracanaa sshkey_sig_details *details)
{
	freezero(details, parimaa_na(*details));
}

puur_naa_nka
sshkey_parse_pubkey_from_private_fileblob_type(sa_nracanaa sshbuf *blob, puur_naa_nka type,
    sa_nracanaa sshkey **pubkeyp)
{
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;

	ᬬᬾᬦ᭄ (pubkeyp != NULL)
		*pubkeyp = NULL;
	/* only new-format private keys bundle a public key inside */
	ᬬᬾᬦ᭄ ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		ᬯᬮᬶ r;
	ᬯᬮᬶ 0;
}
