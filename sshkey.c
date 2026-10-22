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
#define MARK_BEGIN_LEN		(sizeof(MARK_BEGIN) - 1)
#define MARK_END_LEN		(sizeof(MARK_END) - 1)
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

static số_nguyên sshkey_from_blob_internal(struct sshbuf *buf,
    struct sshkey **keyp, số_nguyên allow_cert,
    const char *alg_allowlist, const char *ca_sigalg_allowlist);

/* Supported key types */
extern const struct sshkey_impl sshkey_ed25519_impl;
extern const struct sshkey_impl sshkey_ed25519_cert_impl;
extern const struct sshkey_impl sshkey_ed25519_sk_impl;
extern const struct sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
extern const struct sshkey_impl sshkey_mldsa44_ed25519_impl;
extern const struct sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#ifdef WITH_OPENSSL
# ifdef ENABLE_SK
extern const struct sshkey_impl sshkey_ecdsa_sk_impl;
extern const struct sshkey_impl sshkey_ecdsa_sk_cert_impl;
extern const struct sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
extern const struct sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
extern const struct sshkey_impl sshkey_ecdsa_nistp256_impl;
extern const struct sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
extern const struct sshkey_impl sshkey_ecdsa_nistp384_impl;
extern const struct sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
extern const struct sshkey_impl sshkey_ecdsa_nistp521_impl;
extern const struct sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
extern const struct sshkey_impl sshkey_rsa_impl;
extern const struct sshkey_impl sshkey_rsa_cert_impl;
extern const struct sshkey_impl sshkey_rsa_sha256_impl;
extern const struct sshkey_impl sshkey_rsa_sha256_cert_impl;
extern const struct sshkey_impl sshkey_rsa_sha512_impl;
extern const struct sshkey_impl sshkey_rsa_sha512_cert_impl;
#endif /* WITH_OPENSSL */

const struct sshkey_impl * const keyimpls[] = {
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

static const struct sshkey_impl *
sshkey_impl_from_type(số_nguyên type)
{
	số_nguyên i;

	cho (i = 0; keyimpls[i] != NULL; i++) {
		nếu (keyimpls[i]->type == type)
			trả_về keyimpls[i];
	}
	trả_về NULL;
}

static const struct sshkey_impl *
sshkey_impl_from_type_nid(số_nguyên type, số_nguyên nid)
{
	số_nguyên i;

	cho (i = 0; keyimpls[i] != NULL; i++) {
		nếu (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			trả_về keyimpls[i];
	}
	trả_về NULL;
}

static const struct sshkey_impl *
sshkey_impl_from_key(const struct sshkey *k)
{
	nếu (k == NULL)
		trả_về NULL;
	trả_về sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

const char *
sshkey_type(const struct sshkey *k)
{
	const struct sshkey_impl *impl;

	nếu ((impl = sshkey_impl_from_key(k)) == NULL)
		trả_về "unknown";
	trả_về impl->shortname;
}

static const char *
sshkey_ssh_name_from_type_nid(số_nguyên type, số_nguyên nid)
{
	const struct sshkey_impl *impl;

	nếu ((impl = sshkey_impl_from_type_nid(type, nid)) == NULL)
		trả_về "ssh-unknown";
	trả_về impl->name;
}

số_nguyên
sshkey_type_is_cert(số_nguyên type)
{
	const struct sshkey_impl *impl;

	nếu ((impl = sshkey_impl_from_type(type)) == NULL)
		trả_về 0;
	trả_về impl->cert;
}

const char *
sshkey_ssh_name(const struct sshkey *k)
{
	trả_về sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

const char *
sshkey_ssh_name_plain(const struct sshkey *k)
{
	trả_về sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

static số_nguyên
type_from_name(const char *name, số_nguyên allow_short)
{
	số_nguyên i;
	const struct sshkey_impl *impl;

	cho (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		nếu (impl->name != NULL && strcmp(name, impl->name) == 0)
			trả_về impl->type;
		/* Only allow shortname matches for plain key types */
		nếu (allow_short && !impl->cert && impl->shortname != NULL &&
		    strcasecmp(impl->shortname, name) == 0)
			trả_về impl->type;
	}
	trả_về KEY_UNSPEC;
}

số_nguyên
sshkey_type_from_name(const char *name)
{
	trả_về type_from_name(name, 0);
}

số_nguyên
sshkey_type_from_shortname(const char *name)
{
	trả_về type_from_name(name, 1);
}

static số_nguyên
key_type_is_ecdsa_variant(số_nguyên type)
{
	switch (type) {
	case KEY_ECDSA:
	case KEY_ECDSA_CERT:
	case KEY_ECDSA_SK:
	case KEY_ECDSA_SK_CERT:
		trả_về 1;
	}
	trả_về 0;
}

số_nguyên
sshkey_ecdsa_nid_from_name(const char *name)
{
	số_nguyên i;

	cho (i = 0; keyimpls[i] != NULL; i++) {
		nếu (!key_type_is_ecdsa_variant(keyimpls[i]->type))
			continue;
		nếu (keyimpls[i]->name != NULL &&
		    strcmp(name, keyimpls[i]->name) == 0)
			trả_về keyimpls[i]->nid;
	}
	trả_về -1;
}

số_nguyên
sshkey_match_keyname_to_sigalgs(const char *keyname, const char *sigalgs)
{
	số_nguyên ktype;

	nếu (sigalgs == NULL || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == KEY_UNSPEC)
		trả_về 0;
	không_thì nếu (ktype == KEY_RSA) {
		trả_về match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} không_thì nếu (ktype == KEY_RSA_CERT) {
		trả_về match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} không_thì nếu (ktype == KEY_ECDSA_SK) {
		trả_về match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} không_thì nếu (ktype == KEY_ECDSA_SK_CERT) {
		trả_về match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} không_thì
		trả_về match_pattern_list(keyname, sigalgs, 0) == 1;
}

char *
sshkey_alg_list(số_nguyên certs_only, số_nguyên plain_only, số_nguyên include_sigonly, char sep)
{
	char *ret = NULL;
	size_t i;
	const struct sshkey_impl *impl;
	char sep_str[2] = {sep, '\0'};

	cho (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		nếu (impl->name == NULL)
			continue;
		nếu (!include_sigonly && impl->sigonly)
			continue;
		nếu ((certs_only && !impl->cert) || (plain_only && impl->cert))
			continue;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	trả_về ret;
}

số_nguyên
sshkey_names_valid2(const char *names, số_nguyên allow_wildcard, số_nguyên plain_only)
{
	char *s, *cp, *p;
	const struct sshkey_impl *impl;
	số_nguyên i, type;

	nếu (names == NULL || strcmp(names, "") == 0)
		trả_về 0;
	nếu ((s = cp = strdup(names)) == NULL)
		trả_về 0;
	cho ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		nếu (type == KEY_UNSPEC) {
			nếu (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = NULL;
				cho (i = 0; keyimpls[i] != NULL; i++) {
					nếu (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						break;
					}
				}
				nếu (impl != NULL)
					continue;
			}
			free(s);
			trả_về 0;
		} không_thì nếu (plain_only && sshkey_type_is_cert(type)) {
			free(s);
			trả_về 0;
		}
	}
	free(s);
	trả_về 1;
}

u_int
sshkey_size(const struct sshkey *k)
{
	const struct sshkey_impl *impl;

	nếu ((impl = sshkey_impl_from_key(k)) == NULL)
		trả_về 0;
	nếu (impl->funcs->size != NULL)
		trả_về impl->funcs->size(k);
	trả_về impl->keybits;
}

static số_nguyên
sshkey_type_is_valid_ca(số_nguyên type)
{
	const struct sshkey_impl *impl;

	nếu ((impl = sshkey_impl_from_type(type)) == NULL)
		trả_về 0;
	/* All non-certificate types may act as CAs */
	trả_về !impl->cert;
}

số_nguyên
sshkey_is_cert(const struct sshkey *k)
{
	nếu (k == NULL)
		trả_về 0;
	trả_về sshkey_type_is_cert(k->type);
}

số_nguyên
sshkey_is_sk(const struct sshkey *k)
{
	nếu (k == NULL)
		trả_về 0;
	switch (sshkey_type_plain(k->type)) {
	case KEY_ECDSA_SK:
	case KEY_ED25519_SK:
		trả_về 1;
	default:
		trả_về 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
số_nguyên
sshkey_type_plain(số_nguyên type)
{
	switch (type) {
	case KEY_RSA_CERT:
		trả_về KEY_RSA;
	case KEY_ECDSA_CERT:
		trả_về KEY_ECDSA;
	case KEY_ECDSA_SK_CERT:
		trả_về KEY_ECDSA_SK;
	case KEY_ED25519_CERT:
		trả_về KEY_ED25519;
	case KEY_MLDSA44_ED25519_CERT:
		trả_về KEY_MLDSA44_ED25519;
	case KEY_ED25519_SK_CERT:
		trả_về KEY_ED25519_SK;
	default:
		trả_về type;
	}
}

/* Return the cert equivalent to a plain key type */
static số_nguyên
sshkey_type_certified(số_nguyên type)
{
	switch (type) {
	case KEY_RSA:
		trả_về KEY_RSA_CERT;
	case KEY_ECDSA:
		trả_về KEY_ECDSA_CERT;
	case KEY_ECDSA_SK:
		trả_về KEY_ECDSA_SK_CERT;
	case KEY_ED25519:
		trả_về KEY_ED25519_CERT;
	case KEY_MLDSA44_ED25519:
		trả_về KEY_MLDSA44_ED25519_CERT;
	case KEY_ED25519_SK:
		trả_về KEY_ED25519_SK_CERT;
	default:
		trả_về -1;
	}
}

#ifdef WITH_OPENSSL
static const EVP_MD *
ssh_digest_to_md(số_nguyên hash_alg)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		trả_về EVP_sha1();
	case SSH_DIGEST_SHA256:
		trả_về EVP_sha256();
	case SSH_DIGEST_SHA384:
		trả_về EVP_sha384();
	case SSH_DIGEST_SHA512:
		trả_về EVP_sha512();
	}
	trả_về NULL;
}

số_nguyên
sshkey_pkey_digest_sign(EVP_PKEY *pkey, số_nguyên hash_alg, u_char **sigp,
    size_t *lenp, const u_char *data, size_t datalen)
{
	EVP_MD_CTX *ctx = NULL;
	u_char *sig = NULL;
	số_nguyên ret;
	size_t slen;
	const EVP_MD *evpmd;

	*sigp = NULL;
	*lenp = 0;

	slen = EVP_PKEY_size(pkey);
	nếu (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == NULL)
		trả_về SSH_ERR_INVALID_ARGUMENT;

	nếu ((sig = malloc(slen)) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;

	nếu ((ctx = EVP_MD_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	nếu (EVP_DigestSignInit(ctx, NULL, evpmd, NULL, pkey) != 1 ||
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
	trả_về ret;
}

số_nguyên
sshkey_pkey_digest_verify(EVP_PKEY *pkey, số_nguyên hash_alg, const u_char *data,
    size_t datalen, u_char *sigbuf, size_t siglen)
{
	EVP_MD_CTX *ctx = NULL;
	số_nguyên ret = SSH_ERR_INTERNAL_ERROR;
	const EVP_MD *evpmd;

	nếu ((evpmd = ssh_digest_to_md(hash_alg)) == NULL)
		trả_về SSH_ERR_INVALID_ARGUMENT;
	nếu ((ctx = EVP_MD_CTX_new()) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;
	nếu (EVP_DigestVerifyInit(ctx, NULL, evpmd, NULL, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	switch (EVP_DigestVerify(ctx, sigbuf, siglen, data, datalen)) {
	case 1:
		ret = 0;
		break;
	case 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		break;
	default:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		break;
	}

 out:
	EVP_MD_CTX_free(ctx);
	trả_về ret;
}

/* XXX: these are really begging for a table-driven approach */
số_nguyên
sshkey_curve_name_to_nid(const char *name)
{
	nếu (strcmp(name, "nistp256") == 0)
		trả_về NID_X9_62_prime256v1;
	không_thì nếu (strcmp(name, "nistp384") == 0)
		trả_về NID_secp384r1;
	không_thì nếu (strcmp(name, "nistp521") == 0)
		trả_về NID_secp521r1;
	không_thì
		trả_về -1;
}

u_int
sshkey_curve_nid_to_bits(số_nguyên nid)
{
	switch (nid) {
	case NID_X9_62_prime256v1:
		trả_về 256;
	case NID_secp384r1:
		trả_về 384;
	case NID_secp521r1:
		trả_về 521;
	default:
		trả_về 0;
	}
}

số_nguyên
sshkey_ecdsa_bits_to_nid(số_nguyên bits)
{
	switch (bits) {
	case 256:
		trả_về NID_X9_62_prime256v1;
	case 384:
		trả_về NID_secp384r1;
	case 521:
		trả_về NID_secp521r1;
	default:
		trả_về -1;
	}
}

const char *
sshkey_curve_nid_to_name(số_nguyên nid)
{
	switch (nid) {
	case NID_X9_62_prime256v1:
		trả_về "nistp256";
	case NID_secp384r1:
		trả_về "nistp384";
	case NID_secp521r1:
		trả_về "nistp521";
	default:
		trả_về NULL;
	}
}

số_nguyên
sshkey_ec_nid_to_hash_alg(số_nguyên nid)
{
	số_nguyên kbits = sshkey_curve_nid_to_bits(nid);

	nếu (kbits <= 0)
		trả_về -1;

	/* RFC5656 section 6.2.1 */
	nếu (kbits <= 256)
		trả_về SSH_DIGEST_SHA256;
	không_thì nếu (kbits <= 384)
		trả_về SSH_DIGEST_SHA384;
	không_thì
		trả_về SSH_DIGEST_SHA512;
}
#endif /* WITH_OPENSSL */

static void
cert_free(struct sshkey_cert *cert)
{
	u_int i;

	nếu (cert == NULL)
		trả_về;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	free(cert->key_id);
	cho (i = 0; i < cert->nprincipals; i++)
		free(cert->principals[i]);
	free(cert->principals);
	sshkey_free(cert->signature_key);
	free(cert->signature_type);
	freezero(cert, sizeof(*cert));
}

static struct sshkey_cert *
cert_new(void)
{
	struct sshkey_cert *cert;

	nếu ((cert = calloc(1, sizeof(*cert))) == NULL)
		trả_về NULL;
	nếu ((cert->certblob = sshbuf_new()) == NULL ||
	    (cert->critical = sshbuf_new()) == NULL ||
	    (cert->extensions = sshbuf_new()) == NULL) {
		cert_free(cert);
		trả_về NULL;
	}
	cert->key_id = NULL;
	cert->principals = NULL;
	cert->signature_key = NULL;
	cert->signature_type = NULL;
	trả_về cert;
}

struct sshkey *
sshkey_new(số_nguyên type)
{
	struct sshkey *k;
	const struct sshkey_impl *impl = NULL;

	nếu (type != KEY_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == NULL)
		trả_về NULL;

	/* All non-certificate types may act as CAs */
	nếu ((k = calloc(1, sizeof(*k))) == NULL)
		trả_về NULL;
	k->type = type;
	k->ecdsa_nid = -1;
	nếu (impl != NULL && impl->funcs->alloc != NULL) {
		nếu (impl->funcs->alloc(k) != 0) {
			free(k);
			trả_về NULL;
		}
	}
	nếu (sshkey_is_cert(k)) {
		nếu ((k->cert = cert_new()) == NULL) {
			sshkey_free(k);
			trả_về NULL;
		}
	}

	trả_về k;
}

/* Frees common FIDO fields */
void
sshkey_sk_cleanup(struct sshkey *k)
{
	free(k->sk_application);
	sshbuf_free(k->sk_key_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = NULL;
	k->sk_key_handle = k->sk_reserved = NULL;
}

#nếu defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#elif defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#không_thì
# define PREKEY_MMAP_FLAG	0
#endif

static số_nguyên
sshkey_prekey_alloc(u_char **prekeyp, size_t len)
{
#nếu defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = NULL;
	nếu ((prekey = mmap(NULL, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		trả_về SSH_ERR_SYSTEM_ERROR;
#nếu defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(void)madvise(prekey, len, MADV_DONTDUMP);
#endif
	*prekeyp = prekey;
#không_thì
	*prekeyp = calloc(1, len);
#endif /* HAVE_MMAP et al */
	trả_về 0;
}

static void
sshkey_prekey_free(void *prekey, size_t len)
{
#nếu defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	nếu (prekey == NULL)
		trả_về;
	munmap(prekey, len);
#không_thì
	free(prekey);
#endif /* HAVE_MMAP et al */
}

static void
sshkey_free_contents(struct sshkey *k)
{
	const struct sshkey_impl *impl;

	nếu (k == NULL)
		trả_về;
	nếu ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_key_free(k);
	nếu ((impl = sshkey_impl_from_type(k->type)) != NULL &&
	    impl->funcs->cleanup != NULL)
		impl->funcs->cleanup(k);
	nếu (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_private, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

void
sshkey_free(struct sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, sizeof(*k));
}

static số_nguyên
cert_compare(struct sshkey_cert *a, struct sshkey_cert *b)
{
	nếu (a == NULL && b == NULL)
		trả_về 1;
	nếu (a == NULL || b == NULL)
		trả_về 0;
	nếu (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		trả_về 0;
	nếu (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		trả_về 0;
	trả_về 1;
}

/* Compares FIDO-specific pubkey fields only */
số_nguyên
sshkey_sk_fields_equal(const struct sshkey *a, const struct sshkey *b)
{
	nếu (a->sk_application == NULL || b->sk_application == NULL)
		trả_về 0;
	nếu (strcmp(a->sk_application, b->sk_application) != 0)
		trả_về 0;
	trả_về 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
số_nguyên
sshkey_equal_public(const struct sshkey *a, const struct sshkey *b)
{
	const struct sshkey_impl *impl;

	nếu (a == NULL || b == NULL ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		trả_về 0;
	nếu ((impl = sshkey_impl_from_type(a->type)) == NULL)
		trả_về 0;
	trả_về impl->funcs->equal(a, b);
}

số_nguyên
sshkey_equal(const struct sshkey *a, const struct sshkey *b)
{
	nếu (a == NULL || b == NULL || a->type != b->type)
		trả_về 0;
	nếu (sshkey_is_cert(a)) {
		nếu (!cert_compare(a->cert, b->cert))
			trả_về 0;
	}
	trả_về sshkey_equal_public(a, b);
}


/* Serialise common FIDO key parts */
số_nguyên
sshkey_serialize_sk(const struct sshkey *key, struct sshbuf *b)
{
	số_nguyên r;

	nếu ((r = sshbuf_put_cstring(b, key->sk_application)) != 0)
		trả_về r;

	trả_về 0;
}

static số_nguyên
to_blob_buf(const struct sshkey *key, struct sshbuf *b, số_nguyên force_plain,
  enum sshkey_serialize_rep opts)
{
	số_nguyên type, ret = SSH_ERR_INTERNAL_ERROR;
	const char *typename;
	const struct sshkey_impl *impl;

	nếu (key == NULL)
		trả_về SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(key->type) : key->type;

	nếu (sshkey_type_is_cert(type)) {
		nếu (key->cert == NULL)
			trả_về SSH_ERR_EXPECTED_CERT;
		nếu (sshbuf_len(key->cert->certblob) == 0)
			trả_về SSH_ERR_KEY_LACKS_CERTBLOB;
		/* Use the existing blob */
		nếu ((ret = sshbuf_putb(b, key->cert->certblob)) != 0)
			trả_về ret;
		trả_về 0;
	}
	nếu ((impl = sshkey_impl_from_type(type)) == NULL)
		trả_về SSH_ERR_KEY_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, key->ecdsa_nid);
	nếu ((ret = sshbuf_put_cstring(b, typename)) != 0)
		trả_về ret;
	trả_về impl->funcs->serialize_public(key, b, opts);
}

số_nguyên
sshkey_putb(const struct sshkey *key, struct sshbuf *b)
{
	trả_về to_blob_buf(key, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

static số_nguyên
sshkey_puts_opts_internal(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts, số_nguyên force_plain)
{
	struct sshbuf *tmp;
	số_nguyên r;

	nếu ((tmp = sshbuf_new()) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(key, tmp, force_plain, opts);
	nếu (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	trả_về r;
}

số_nguyên
sshkey_puts(const struct sshkey *key, struct sshbuf *b)
{
	trả_về sshkey_puts_opts_internal(key, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

số_nguyên
sshkey_putb_plain(const struct sshkey *key, struct sshbuf *b)
{
	trả_về to_blob_buf(key, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

số_nguyên
sshkey_puts_plain(const struct sshkey *key, struct sshbuf *b)
{
	trả_về sshkey_puts_opts_internal(key, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

static số_nguyên
to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp, số_nguyên force_plain,
    enum sshkey_serialize_rep opts)
{
	số_nguyên ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	struct sshbuf *b = NULL;

	nếu (lenp != NULL)
		*lenp = 0;
	nếu (blobp != NULL)
		*blobp = NULL;
	nếu ((b = sshbuf_new()) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;
	nếu ((ret = to_blob_buf(key, b, force_plain, opts)) != 0)
		goto out;
	len = sshbuf_len(b);
	nếu (lenp != NULL)
		*lenp = len;
	nếu (blobp != NULL) {
		nếu ((*blobp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	trả_về ret;
}

số_nguyên
sshkey_to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp)
{
	trả_về to_blob(key, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

số_nguyên
sshkey_plain_to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp)
{
	trả_về to_blob(key, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

số_nguyên
sshkey_fingerprint_raw(const struct sshkey *k, số_nguyên dgst_alg,
    u_char **retp, size_t *lenp)
{
	u_char *blob = NULL, *ret = NULL;
	size_t blob_len = 0;
	số_nguyên r = SSH_ERR_INTERNAL_ERROR;

	nếu (retp != NULL)
		*retp = NULL;
	nếu (lenp != NULL)
		*lenp = 0;
	nếu (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	nếu ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		goto out;
	nếu ((ret = calloc(1, SSH_DIGEST_MAX_LENGTH)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	nếu ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_LENGTH)) != 0)
		goto out;
	/* success */
	nếu (retp != NULL) {
		*retp = ret;
		ret = NULL;
	}
	nếu (lenp != NULL)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	free(ret);
	nếu (blob != NULL)
		freezero(blob, blob_len);
	trả_về r;
}

static char *
fingerprint_b64(const char *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	char *ret;
	size_t plen = strlen(alg) + 1;
	size_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	nếu (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == NULL)
		trả_về NULL;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	nếu (dgst_raw_len == 0)
		trả_về ret;
	nếu (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		trả_về NULL;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	trả_về ret;
}

static char *
fingerprint_hex(const char *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	char *retval, hex[5];
	size_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	nếu (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == NULL)
		trả_về NULL;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	cho (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, sizeof(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	trả_về retval;
}

static char *
fingerprint_bubblebabble(u_char *dgst_raw, size_t dgst_raw_len)
{
	char vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	char consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	char *retval;

	rounds = (dgst_raw_len / 2) + 1;
	nếu ((retval = calloc(rounds, 6)) == NULL)
		trả_về NULL;
	retval[j++] = 'x';
	cho (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		nếu ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			nếu ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} không_thì {
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
	trả_về retval;
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
static char *
fingerprint_randomart(const char *alg, u_char *dgst_raw, size_t dgst_raw_len,
    const struct sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	char	*augmentation_string = " .o+=*BOX@%&#/^SE";
	char	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	size_t	 i, tlen, hlen;
	u_int	 b;
	số_nguyên	 x, y, r;
	size_t	 len = strlen(augmentation_string) - 1;

	nếu ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == NULL)
		trả_về NULL;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * sizeof(char));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	cho (i = 0; i < dgst_raw_len; i++) {
		số_nguyên input;
		/* each byte conveys four 2-bit move commands */
		input = dgst_raw[i];
		cho (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (input & 0x1) ? 1 : -1;
			y += (input & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			nếu (field[x][y] < len - 2)
				field[x][y]++;
			input = input >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, sizeof(title), "[%s %u]",
		sshkey_type(k), sshkey_size(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	nếu (r < 0 || r > (số_nguyên)sizeof(title))
		r = snprintf(title, sizeof(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, sizeof(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	cho (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	memcpy(p, title, tlen);
	p += tlen;
	cho (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	cho (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		cho (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	cho (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	memcpy(p, hash, hlen);
	p += hlen;
	cho (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	trả_về retval;
}

char *
sshkey_fingerprint(const struct sshkey *k, số_nguyên dgst_alg,
    enum sshkey_fp_rep dgst_rep)
{
	char *retval = NULL;
	u_char *dgst_raw;
	size_t dgst_raw_len;

	nếu (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		trả_về NULL;
	switch (dgst_rep) {
	case SSH_FP_DEFAULT:
		nếu (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} không_thì {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		break;
	case SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		break;
	case SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		break;
	case SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		break;
	case SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		break;
	default:
		freezero(dgst_raw, dgst_raw_len);
		trả_về NULL;
	}
	freezero(dgst_raw, dgst_raw_len);
	trả_về retval;
}

static số_nguyên
peek_type_nid(const char *s, size_t l, số_nguyên *nid)
{
	const struct sshkey_impl *impl;
	số_nguyên i;

	cho (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		nếu (impl->name == NULL || strlen(impl->name) != l)
			continue;
		nếu (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			nếu (key_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			trả_về impl->type;
		}
	}
	trả_về KEY_UNSPEC;
}

/* XXX this can now be made const char * */
số_nguyên
sshkey_read(struct sshkey *ret, char **cpp)
{
	struct sshkey *k;
	char *cp, *blobcopy;
	size_t space;
	số_nguyên r, type, curve_nid = -1;
	struct sshbuf *blob;

	nếu (ret == NULL)
		trả_về SSH_ERR_INVALID_ARGUMENT;
	nếu (ret->type != KEY_UNSPEC && sshkey_impl_from_type(ret->type) == NULL)
		trả_về SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	nếu (space == strlen(cp))
		trả_về SSH_ERR_INVALID_FORMAT;
	nếu ((type = peek_type_nid(cp, space, &curve_nid)) == KEY_UNSPEC)
		trả_về SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	cho (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	nếu (*cp == '\0')
		trả_về SSH_ERR_INVALID_FORMAT;
	nếu (ret->type != KEY_UNSPEC && ret->type != type)
		trả_về SSH_ERR_KEY_TYPE_MISMATCH;
	nếu ((blob = sshbuf_new()) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	nếu ((blobcopy = strndup(cp, space)) == NULL) {
		sshbuf_free(blob);
		trả_về SSH_ERR_ALLOC_FAIL;
	}
	nếu ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		free(blobcopy);
		sshbuf_free(blob);
		trả_về r;
	}
	free(blobcopy);
	nếu ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		trả_về r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	cho (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	nếu (k->type != type) {
		sshkey_free(k);
		trả_về SSH_ERR_KEY_TYPE_MISMATCH;
	}
	nếu (key_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		trả_về SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, sizeof(*k));

	/* success */
	*cpp = cp;
	trả_về 0;
}

số_nguyên
sshkey_to_base64(const struct sshkey *key, char **b64p)
{
	số_nguyên r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;
	char *uu = NULL;

	nếu (b64p != NULL)
		*b64p = NULL;
	nếu ((b = sshbuf_new()) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;
	nếu ((r = sshkey_putb(key, b)) != 0)
		goto out;
	nếu ((uu = sshbuf_dtob64_string(b, 0)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* Success */
	nếu (b64p != NULL) {
		*b64p = uu;
		uu = NULL;
	}
	r = 0;
 out:
	sshbuf_free(b);
	free(uu);
	trả_về r;
}

số_nguyên
sshkey_format_text(const struct sshkey *key, struct sshbuf *b)
{
	số_nguyên r = SSH_ERR_INTERNAL_ERROR;
	char *uu = NULL;

	nếu ((r = sshkey_to_base64(key, &uu)) != 0)
		goto out;
	nếu ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(key), uu)) != 0)
		goto out;
	r = 0;
 out:
	free(uu);
	trả_về r;
}

số_nguyên
sshkey_write(const struct sshkey *key, FILE *f)
{
	struct sshbuf *b = NULL;
	số_nguyên r = SSH_ERR_INTERNAL_ERROR;

	nếu ((b = sshbuf_new()) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;
	nếu ((r = sshkey_format_text(key, b)) != 0)
		goto out;
	nếu (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		nếu (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		goto out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	trả_về r;
}

const char *
sshkey_cert_type(const struct sshkey *k)
{
	switch (k->cert->type) {
	case SSH2_CERT_TYPE_USER:
		trả_về "user";
	case SSH2_CERT_TYPE_HOST:
		trả_về "host";
	default:
		trả_về "unknown";
	}
}

số_nguyên
sshkey_check_rsa_length(const struct sshkey *k, số_nguyên min_size)
{
#ifdef WITH_OPENSSL
	số_nguyên nbits;

	nếu (k == NULL || k->pkey == NULL ||
	    (k->type != KEY_RSA && k->type != KEY_RSA_CERT))
		trả_về 0;
	nbits = EVP_PKEY_bits(k->pkey);
	nếu (nbits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    (min_size > 0 && nbits < min_size))
		trả_về SSH_ERR_KEY_LENGTH;
#endif /* WITH_OPENSSL */
	trả_về 0;
}

#ifdef WITH_OPENSSL
số_nguyên
sshkey_ecdsa_key_to_nid(const EC_KEY *k)
{
	const EC_GROUP *g;
	số_nguyên nid;

	nếu (k == NULL || (g = EC_KEY_get0_group(k)) == NULL)
		trả_về -1;
	nếu ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		trả_về -1;
	trả_về nid;
}

số_nguyên
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	trả_về sshkey_ecdsa_key_to_nid(EVP_PKEY_get0_EC_KEY(pkey));
}
#endif /* WITH_OPENSSL */

số_nguyên
sshkey_generate(số_nguyên type, u_int bits, struct sshkey **keyp)
{
	struct sshkey *k;
	số_nguyên ret = SSH_ERR_INTERNAL_ERROR;
	const struct sshkey_impl *impl;

	nếu (keyp == NULL || sshkey_type_is_cert(type))
		trả_về SSH_ERR_INVALID_ARGUMENT;
	*keyp = NULL;
	nếu ((impl = sshkey_impl_from_type(type)) == NULL)
		trả_về SSH_ERR_KEY_TYPE_UNKNOWN;
	nếu (impl->funcs->generate == NULL)
		trả_về SSH_ERR_FEATURE_UNSUPPORTED;
	nếu ((k = sshkey_new(KEY_UNSPEC)) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;
	k->type = type;
	nếu ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		trả_về ret;
	}
	/* success */
	*keyp = k;
	trả_về 0;
}

số_nguyên
sshkey_cert_copy(const struct sshkey *from_key, struct sshkey *to_key)
{
	u_int i;
	const struct sshkey_cert *from;
	struct sshkey_cert *to;
	số_nguyên r = SSH_ERR_INTERNAL_ERROR;

	nếu (to_key == NULL || (from = from_key->cert) == NULL)
		trả_về SSH_ERR_INVALID_ARGUMENT;

	nếu ((to = cert_new()) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;

	nếu ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		goto out;

	to->serial = from->serial;
	to->type = from->type;
	nếu (from->key_id == NULL)
		to->key_id = NULL;
	không_thì nếu ((to->key_id = strdup(from->key_id)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	nếu (from->signature_key == NULL)
		to->signature_key = NULL;
	không_thì nếu ((r = sshkey_from_private(from->signature_key,
	    &to->signature_key)) != 0)
		goto out;
	nếu (from->signature_type != NULL &&
	    (to->signature_type = strdup(from->signature_type)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	nếu (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	nếu (from->nprincipals > 0) {
		nếu ((to->principals = calloc(from->nprincipals,
		    sizeof(*to->principals))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		cho (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			nếu (to->principals[i] == NULL) {
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
	trả_về r;
}

số_nguyên
sshkey_copy_public_sk(const struct sshkey *from, struct sshkey *to)
{
	/* Append security-key application string */
	nếu ((to->sk_application = strdup(from->sk_application)) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;
	trả_về 0;
}

số_nguyên
sshkey_from_private(const struct sshkey *k, struct sshkey **pkp)
{
	struct sshkey *n = NULL;
	số_nguyên r = SSH_ERR_INTERNAL_ERROR;
	const struct sshkey_impl *impl;

	*pkp = NULL;
	nếu ((impl = sshkey_impl_from_key(k)) == NULL)
		trả_về SSH_ERR_KEY_TYPE_UNKNOWN;
	nếu ((n = sshkey_new(k->type)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	nếu ((r = impl->funcs->copy_public(k, n)) != 0)
		goto out;
	nếu (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		goto out;
	/* success */
	*pkp = n;
	n = NULL;
	r = 0;
 out:
	sshkey_free(n);
	trả_về r;
}

số_nguyên
sshkey_is_shielded(struct sshkey *k)
{
	trả_về k != NULL && k->shielded_private != NULL;
}

số_nguyên
sshkey_shield_private(struct sshkey *k)
{
	struct sshbuf *prvbuf = NULL;
	u_char *prekey = NULL, *enc = NULL, keyiv[SSH_DIGEST_MAX_LENGTH];
	struct sshcipher_ctx *cctx = NULL;
	const struct sshcipher *cipher;
	size_t i, enclen = 0;
	struct sshkey *kswap = NULL, tmp;
	số_nguyên r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	nếu ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	nếu (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	nếu ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		goto out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	nếu ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	nếu ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		goto out;

	/* Serialise and encrypt the private key using the ephemeral key */
	nếu ((prvbuf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	nếu (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		goto out;
	nếu ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		goto out;
	/* pad to cipher blocksize */
	i = 0;
	trong_khi (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		nếu ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			goto out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	nếu ((enc = malloc(enclen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	nếu ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	nếu ((r = sshkey_from_private(k, &kswap)) != 0)
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
	explicit_bzero(keyiv, sizeof(keyiv));
	explicit_bzero(&tmp, sizeof(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	trả_về r;
}

/* Check deterministic padding after private key */
static số_nguyên
private2_check_padding(struct sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	số_nguyên r;

	i = 0;
	trong_khi (sshbuf_len(decrypted)) {
		nếu ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			goto out;
		nếu (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, sizeof(pad));
	explicit_bzero(&i, sizeof(i));
	trả_về r;
}

số_nguyên
sshkey_unshield_private(struct sshkey *k)
{
	struct sshbuf *prvbuf = NULL;
	u_char *cp, keyiv[SSH_DIGEST_MAX_LENGTH];
	struct sshcipher_ctx *cctx = NULL;
	const struct sshcipher *cipher;
	struct sshkey *kswap = NULL, tmp;
	số_nguyên r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	nếu (!sshkey_is_shielded(k))
		trả_về 0; /* nothing to do */

	nếu ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	nếu (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	/* check size of shielded key blob */
	nếu (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Calculate the ephemeral key from the prekey */
	nếu ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		goto out;
	nếu ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	nếu ((prvbuf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	nếu ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		goto out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(k->shielded_private, k->shielded_len, stderr);
#endif
	nếu ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	nếu ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		goto out;

	nếu ((r = private2_check_padding(prvbuf)) != 0)
		goto out;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 out:
	cipher_free(cctx);
	explicit_bzero(keyiv, sizeof(keyiv));
	explicit_bzero(&tmp, sizeof(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	trả_về r;
}

static số_nguyên
cert_parse(struct sshbuf *b, struct sshkey *key, struct sshbuf *certbuf,
    const char *ca_sigalg_allowlist)
{
	struct sshbuf *principals = NULL, *crit = NULL;
	struct sshbuf *exts = NULL, *ca = NULL;
	u_char *sig = NULL;
	char *sigtype = NULL;
	size_t signed_len = 0, slen = 0, kidlen = 0;
	số_nguyên ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	nếu ((ret = sshbuf_putb(key->cert->certblob, certbuf)) != 0)
		trả_về ret;

	/* Parse body of certificate up to signature */
	nếu ((ret = sshbuf_get_u64(b, &key->cert->serial)) != 0 ||
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

	nếu ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Is this a signature we're prepared to accept? */
	nếu ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	nếu (ca_sigalg_allowlist != NULL &&
	    match_pattern_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		goto out;
	}

	/* Parse CA key and check whether we might accept it */
	nếu (sshkey_from_blob_internal(ca, &key->cert->signature_key, 0,
	    ca_sigalg_allowlist, NULL) != 0) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}
	nếu (!sshkey_type_is_valid_ca(key->cert->signature_key->type)) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}

	nếu (key->cert->type != SSH2_CERT_TYPE_USER &&
	    key->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_KEY_CERT_UNKNOWN_TYPE;
		goto out;
	}

	/* Parse principals section */
	trong_khi (sshbuf_len(principals) > 0) {
		char *principal = NULL;
		char **oprincipals = NULL;

		nếu (key->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		nếu ((ret = sshbuf_get_cstring(principals, &principal,
		    NULL)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		oprincipals = key->cert->principals;
		key->cert->principals = recallocarray(key->cert->principals,
		    key->cert->nprincipals, key->cert->nprincipals + 1,
		    sizeof(*key->cert->principals));
		nếu (key->cert->principals == NULL) {
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
	nếu ((ret = sshbuf_putb(key->cert->critical, crit)) != 0 ||
	    (exts != NULL &&
	    (ret = sshbuf_putb(key->cert->extensions, exts)) != 0))
		goto out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	trong_khi (sshbuf_len(crit) != 0) {
		nếu ((ret = sshbuf_get_string_direct(crit, NULL, NULL)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, NULL, NULL)) != 0) {
			sshbuf_reset(key->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	trong_khi (exts != NULL && sshbuf_len(exts) != 0) {
		nếu ((ret = sshbuf_get_string_direct(exts, NULL, NULL)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, NULL, NULL)) != 0) {
			sshbuf_reset(key->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}

	/* Finally, validate signature */
	nếu ((ret = sshkey_verify(key->cert->signature_key, sig, slen,
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
	trả_về ret;
}

số_nguyên
sshkey_deserialize_sk(struct sshbuf *b, struct sshkey *key)
{
	/* Parse additional security-key application string */
	nếu (sshbuf_get_cstring(b, &key->sk_application, NULL) != 0)
		trả_về SSH_ERR_INVALID_FORMAT;
	trả_về 0;
}

static số_nguyên
sshkey_from_blob_internal(struct sshbuf *b, struct sshkey **keyp,
    số_nguyên allow_cert, const char *alg_allowlist, const char *ca_sigalg_allowlist)
{
	số_nguyên type, ret = SSH_ERR_INTERNAL_ERROR;
	char *ktype = NULL;
	struct sshkey *key = NULL;
	struct sshbuf *copy;
	const struct sshkey_impl *impl;

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	nếu (keyp != NULL)
		*keyp = NULL;
	nếu ((copy = sshbuf_fromb(b)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	nếu (sshbuf_get_cstring(b, &ktype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	type = sshkey_type_from_name(ktype);
	nếu (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}

	nếu (alg_allowlist != NULL &&
	    !sshkey_match_keyname_to_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_KEY_ALG_UNSUPPORTED;
		goto out;
	}

	nếu ((impl = sshkey_impl_from_type(type)) == NULL) {
		ret = SSH_ERR_KEY_TYPE_UNKNOWN;
		goto out;
	}
	nếu ((key = sshkey_new(type)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	nếu (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		nếu (sshbuf_get_string_direct(b, NULL, NULL) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	nếu ((ret = impl->funcs->deserialize_public(ktype, b, key)) != 0)
		goto out;

	/* Parse certificate potion */
	nếu (sshkey_is_cert(key) &&
	    (ret = cert_parse(b, key, copy, ca_sigalg_allowlist)) != 0)
		goto out;

	nếu (key != NULL && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ret = 0;
	nếu (keyp != NULL) {
		*keyp = key;
		key = NULL;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(key);
	free(ktype);
	trả_về ret;
}

số_nguyên
sshkey_from_blob(const u_char *blob, size_t blen, struct sshkey **keyp)
{
	struct sshbuf *b;
	số_nguyên r;

	nếu ((b = sshbuf_from(blob, blen)) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1, NULL, NULL);
	sshbuf_free(b);
	trả_về r;
}

số_nguyên
sshkey_fromb(struct sshbuf *b, struct sshkey **keyp)
{
	trả_về sshkey_from_blob_internal(b, keyp, 1, NULL, NULL);
}

số_nguyên
sshkey_fromb_allowlist(struct sshbuf *b, struct sshkey **keyp,
    const char *alg_allowlist, const char *ca_sigalg_allowlist)
{
	trả_về sshkey_from_blob_internal(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

số_nguyên
sshkey_froms(struct sshbuf *buf, struct sshkey **keyp)
{
	struct sshbuf *b;
	số_nguyên r;

	nếu ((r = sshbuf_froms(buf, &b)) != 0)
		trả_về r;
	r = sshkey_from_blob_internal(b, keyp, 1, NULL, NULL);
	sshbuf_free(b);
	trả_về r;
}

số_nguyên
sshkey_get_sigtype(const u_char *sig, size_t siglen, char **sigtypep)
{
	số_nguyên r;
	struct sshbuf *b = NULL;
	char *sigtype = NULL;

	nếu (sigtypep != NULL)
		*sigtypep = NULL;
	nếu ((b = sshbuf_from(sig, siglen)) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;
	nếu ((r = sshbuf_get_cstring(b, &sigtype, NULL)) != 0)
		goto out;
	/* success */
	nếu (sigtypep != NULL) {
		*sigtypep = sigtype;
		sigtype = NULL;
	}
	r = 0;
 out:
	free(sigtype);
	sshbuf_free(b);
	trả_về r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
số_nguyên
sshkey_check_cert_sigtype(const struct sshkey *key, const char *allowed)
{
	nếu (key == NULL || allowed == NULL)
		trả_về SSH_ERR_INVALID_ARGUMENT;
	nếu (!sshkey_type_is_cert(key->type))
		trả_về 0;
	nếu (key->cert == NULL || key->cert->signature_type == NULL)
		trả_về SSH_ERR_INVALID_ARGUMENT;
	nếu (match_pattern_list(key->cert->signature_type, allowed, 0) != 1)
		trả_về SSH_ERR_SIGN_ALG_UNSUPPORTED;
	trả_về 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
const char *
sshkey_sigalg_by_name(const char *name)
{
	const struct sshkey_impl *impl;
	số_nguyên i;

	cho (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		nếu (strcmp(impl->name, name) != 0)
			continue;
		nếu (impl->sigalg != NULL)
			trả_về impl->sigalg;
		nếu (!impl->cert)
			trả_về impl->name;
		trả_về sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	trả_về NULL;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
số_nguyên
sshkey_check_sigtype(const u_char *sig, size_t siglen,
    const char *requested_alg)
{
	const char *expected_alg;
	char *sigtype = NULL;
	số_nguyên r;

	nếu (requested_alg == NULL)
		trả_về 0;
	nếu ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == NULL)
		trả_về SSH_ERR_INVALID_ARGUMENT;
	nếu ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		trả_về r;
	r = strcmp(expected_alg, sigtype) == 0;
	free(sigtype);
	trả_về r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

số_nguyên
sshkey_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	số_nguyên was_shielded = sshkey_is_shielded(key);
	số_nguyên r2, r = SSH_ERR_INTERNAL_ERROR;
	const struct sshkey_impl *impl;

	nếu (sigp != NULL)
		*sigp = NULL;
	nếu (lenp != NULL)
		*lenp = 0;
	nếu (datalen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		trả_về SSH_ERR_INVALID_ARGUMENT;
	nếu ((impl = sshkey_impl_from_key(key)) == NULL)
		trả_về SSH_ERR_KEY_TYPE_UNKNOWN;
	nếu ((r = sshkey_unshield_private(key)) != 0)
		trả_về r;
	nếu (sshkey_is_sk(key)) {
		r = sshsk_sign(sk_provider, key, sigp, lenp, data,
		    datalen, compat, sk_pin);
	} không_thì nếu ((key->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(key, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	} không_thì {
		nếu (impl->funcs->sign == NULL)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		không_thì {
			r = impl->funcs->sign(key, sigp, lenp, data, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	nếu (was_shielded && (r2 = sshkey_shield_private(key)) != 0)
		trả_về r2;
	trả_về r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
số_nguyên
sshkey_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	const struct sshkey_impl *impl;

	nếu (detailsp != NULL)
		*detailsp = NULL;
	nếu (siglen == 0 || dlen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		trả_về SSH_ERR_INVALID_ARGUMENT;
	nếu ((impl = sshkey_impl_from_key(key)) == NULL)
		trả_về SSH_ERR_KEY_TYPE_UNKNOWN;
	trả_về impl->funcs->verify(key, sig, siglen, data, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
số_nguyên
sshkey_to_certified(struct sshkey *k)
{
	số_nguyên newtype;

	nếu ((newtype = sshkey_type_certified(k->type)) == -1)
		trả_về SSH_ERR_INVALID_ARGUMENT;
	nếu ((k->cert = cert_new()) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	trả_về 0;
}

/* Convert a certificate to its raw key equivalent */
số_nguyên
sshkey_drop_cert(struct sshkey *k)
{
	nếu (!sshkey_type_is_cert(k->type))
		trả_về SSH_ERR_KEY_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = NULL;
	k->type = sshkey_type_plain(k->type);
	trả_về 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
số_nguyên
sshkey_certify_custom(struct sshkey *k, struct sshkey *ca, const char *alg,
    const char *sk_provider, const char *sk_pin,
    sshkey_certify_signer *signer, void *signer_ctx)
{
	const struct sshkey_impl *impl;
	struct sshbuf *principals = NULL;
	u_char *ca_blob = NULL, *sig_blob = NULL, nonce[32];
	size_t i, ca_len, sig_len;
	số_nguyên ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *cert = NULL;
	char *sigtype = NULL;

	nếu (k == NULL || k->cert == NULL ||
	    k->cert->certblob == NULL || ca == NULL)
		trả_về SSH_ERR_INVALID_ARGUMENT;
	nếu (!sshkey_is_cert(k))
		trả_về SSH_ERR_KEY_TYPE_UNKNOWN;
	nếu (!sshkey_type_is_valid_ca(ca->type))
		trả_về SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
	nếu ((impl = sshkey_impl_from_key(k)) == NULL)
		trả_về SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	nếu (alg == NULL)
		alg = k->cert->signature_type;
	không_thì nếu (k->cert->signature_type != NULL &&
	    strcmp(alg, k->cert->signature_type) != 0)
		trả_về SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	nếu (alg == NULL && ca->type == KEY_RSA)
		alg = "rsa-sha2-512";

	nếu ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		trả_về SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	nếu ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		goto out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, sizeof(nonce));
	nếu ((ret = sshbuf_put_string(cert, nonce, sizeof(nonce))) != 0)
		goto out;

	/* Public key next */
	nếu ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		goto out;

	/* Then remaining cert fields */
	nếu ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->key_id)) != 0)
		goto out;

	nếu ((principals = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	cho (i = 0; i < k->cert->nprincipals; i++) {
		nếu ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			goto out;
	}
	nếu ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, NULL, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		goto out;

	/* Sign the whole mess */
	nếu ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		goto out;
	/* Check and update signature_type against what was actually used */
	nếu ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		goto out;
	nếu (alg != NULL && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		goto out;
	}
	nếu (k->cert->signature_type == NULL) {
		k->cert->signature_type = sigtype;
		sigtype = NULL;
	}
	/* Append signature and we are done */
	nếu ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		goto out;
	ret = 0;
 out:
	nếu (ret != 0)
		sshbuf_reset(cert);
	free(sig_blob);
	free(ca_blob);
	free(sigtype);
	sshbuf_free(principals);
	trả_về ret;
}

static số_nguyên
default_key_sign(struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin,
    u_int compat, void *ctx)
{
	nếu (ctx != NULL)
		trả_về SSH_ERR_INVALID_ARGUMENT;
	trả_về sshkey_sign(key, sigp, lenp, data, datalen, alg,
	    sk_provider, sk_pin, compat);
}

số_nguyên
sshkey_certify(struct sshkey *k, struct sshkey *ca, const char *alg,
    const char *sk_provider, const char *sk_pin)
{
	trả_về sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_key_sign, NULL);
}

số_nguyên
sshkey_cert_check_authority(const struct sshkey *k,
    số_nguyên want_host, số_nguyên wildcard_pattern, uint64_t verify_time,
    const char *name, const char **reason)
{
	u_int i, principal_matches;

	nếu (reason == NULL)
		trả_về SSH_ERR_INVALID_ARGUMENT;
	nếu (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		trả_về SSH_ERR_KEY_CERT_INVALID;
	}
	nếu (want_host) {
		nếu (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			trả_về SSH_ERR_KEY_CERT_INVALID;
		}
	} không_thì {
		nếu (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			trả_về SSH_ERR_KEY_CERT_INVALID;
		}
	}
	nếu (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		trả_về SSH_ERR_KEY_CERT_INVALID;
	}
	nếu (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		trả_về SSH_ERR_KEY_CERT_INVALID;
	}
	nếu (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		trả_về SSH_ERR_KEY_CERT_INVALID;
	}
	nếu (name == NULL)
		trả_về 0; /* principal matching not requested */

	principal_matches = 0;
	cho (i = 0; i < k->cert->nprincipals; i++) {
		nếu (wildcard_pattern) {
			nếu (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				break;
			}
		} không_thì nếu (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			break;
		}
	}
	nếu (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		trả_về SSH_ERR_KEY_CERT_INVALID;
	}
	trả_về 0;
}

số_nguyên
sshkey_cert_check_authority_now(const struct sshkey *k,
    số_nguyên want_host, số_nguyên wildcard_pattern, const char *name,
    const char **reason)
{
	time_t now;

	nếu ((now = time(NULL)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		trả_về SSH_ERR_KEY_CERT_INVALID;
	}
	trả_về sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

số_nguyên
sshkey_cert_check_host(const struct sshkey *key, const char *host,
    const char *ca_sign_algorithms, const char **reason)
{
	số_nguyên r;

	nếu ((r = sshkey_cert_check_authority_now(key, 1, 1, host, reason)) != 0)
		trả_về r;
	nếu (sshbuf_len(key->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		trả_về SSH_ERR_KEY_CERT_INVALID;
	}
	nếu (ca_sign_algorithms != NULL &&
	    (r = sshkey_check_cert_sigtype(key, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		trả_về SSH_ERR_KEY_CERT_INVALID;
	}
	trả_về 0;
}

size_t
sshkey_format_cert_validity(const struct sshkey_cert *cert, char *s, size_t l)
{
	char from[32], to[32], ret[128];

	*from = *to = '\0';
	nếu (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		trả_về strlcpy(s, "forever", l);

	nếu (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, sizeof(from));
	nếu (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, sizeof(to));

	nếu (cert->valid_after == 0)
		snprintf(ret, sizeof(ret), "before %s", to);
	không_thì nếu (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, sizeof(ret), "after %s", from);
	không_thì
		snprintf(ret, sizeof(ret), "from %s to %s", from, to);

	trả_về strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
số_nguyên
sshkey_serialize_private_sk(const struct sshkey *key, struct sshbuf *b)
{
	số_nguyên r;

	nếu ((r = sshbuf_put_cstring(b, key->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, key->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, key->sk_key_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, key->sk_reserved)) != 0)
		trả_về r;

	trả_về 0;
}

static số_nguyên
sshkey_private_serialize_opt(struct sshkey *key, struct sshbuf *buf,
    enum sshkey_serialize_rep opts)
{
	số_nguyên r = SSH_ERR_INTERNAL_ERROR;
	số_nguyên was_shielded = sshkey_is_shielded(key);
	struct sshbuf *b = NULL;
	const struct sshkey_impl *impl;

	nếu ((impl = sshkey_impl_from_key(key)) == NULL)
		trả_về SSH_ERR_INTERNAL_ERROR;
	nếu ((r = sshkey_unshield_private(key)) != 0)
		trả_về r;
	nếu ((b = sshbuf_new()) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;
	nếu ((r = sshbuf_put_cstring(b, sshkey_ssh_name(key))) != 0)
		goto out;
	nếu (sshkey_is_cert(key)) {
		nếu (key->cert == NULL ||
		    sshbuf_len(key->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		nếu ((r = sshbuf_put_stringb(b, key->cert->certblob)) != 0)
			goto out;
	}
	nếu ((r = impl->funcs->serialize_private(key, b, opts)) != 0)
		goto out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	nếu (was_shielded)
		r = sshkey_shield_private(key);
	nếu (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	trả_về r;
}

số_nguyên
sshkey_private_serialize(struct sshkey *key, struct sshbuf *b)
{
	trả_về sshkey_private_serialize_opt(key, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
số_nguyên
sshkey_private_deserialize_sk(struct sshbuf *buf, struct sshkey *k)
{
	số_nguyên r;

	nếu ((k->sk_key_handle = sshbuf_new()) == NULL ||
	    (k->sk_reserved = sshbuf_new()) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;
	nếu ((r = sshbuf_get_cstring(buf, &k->sk_application, NULL)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_key_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		trả_về r;

	trả_về 0;
}

số_nguyên
sshkey_private_deserialize(struct sshbuf *buf, struct sshkey **kp)
{
	const struct sshkey_impl *impl;
	char *tname = NULL;
	char *expect_sk_application = NULL;
	u_char *expect_ed25519_pk = NULL;
	struct sshkey *k = NULL;
	số_nguyên type, r = SSH_ERR_INTERNAL_ERROR;

	nếu (kp != NULL)
		*kp = NULL;
	nếu ((r = sshbuf_get_cstring(buf, &tname, NULL)) != 0)
		goto out;
	type = sshkey_type_from_name(tname);
	nếu (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		nếu ((r = sshkey_froms(buf, &k)) != 0)
			goto out;
		nếu (k->type != type) {
			r = SSH_ERR_KEY_CERT_MISMATCH;
			goto out;
		}
		/* For ECDSA keys, the group must match too */
		nếu (k->type == KEY_ECDSA &&
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
	} không_thì {
		nếu ((k = sshkey_new(type)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
	}
	nếu ((impl = sshkey_impl_from_type(type)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	nếu ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		goto out;

	nếu ((expect_sk_application != NULL && (k->sk_application == NULL ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != NULL && (k->ed25519_pk == NULL ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_KEY_CERT_MISMATCH;
		goto out;
	}
	/* success */
	r = 0;
	nếu (kp != NULL) {
		*kp = k;
		k = NULL;
	}
 out:
	free(tname);
	sshkey_free(k);
	free(expect_sk_application);
	free(expect_ed25519_pk);
	trả_về r;
}

#ifdef WITH_OPENSSL
số_nguyên
sshkey_ec_validate_public(const EC_GROUP *group, const EC_POINT *public)
{
	EC_POINT *nq = NULL;
	BIGNUM *order = NULL, *cofactor = NULL;
	số_nguyên ret = SSH_ERR_KEY_INVALID_EC_VALUE;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	nếu (EC_POINT_is_at_infinity(group, public))
		goto out;

	nếu ((cofactor = BN_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	nếu (EC_GROUP_get_cofactor(group, cofactor, NULL) != 1)
		goto out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	nếu (!BN_is_one(cofactor)) {
		nếu ((order = BN_new()) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		nếu (EC_GROUP_get_order(group, order, NULL) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		nếu ((nq = EC_POINT_new(group)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		nếu (EC_POINT_mul(group, nq, NULL, public, order, NULL) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		nếu (EC_POINT_is_at_infinity(group, nq) != 1)
			goto out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	trả_về ret;
}

số_nguyên
sshkey_ec_validate_private(const EC_KEY *key)
{
	BIGNUM *order = NULL, *tmp = NULL;
	số_nguyên ret = SSH_ERR_KEY_INVALID_EC_VALUE;

	nếu ((order = BN_new()) == NULL || (tmp = BN_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* log2(private) > log2(order)/2 */
	nếu (EC_GROUP_get_order(EC_KEY_get0_group(key), order, NULL) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	nếu (BN_num_bits(EC_KEY_get0_private_key(key)) <=
	    BN_num_bits(order) / 2)
		goto out;

	/* private < order - 1 */
	nếu (!BN_sub(tmp, order, BN_value_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	nếu (BN_cmp(EC_KEY_get0_private_key(key), tmp) >= 0)
		goto out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	trả_về ret;
}

void
sshkey_dump_ec_point(const EC_GROUP *group, const EC_POINT *point)
{
	BIGNUM *x = NULL, *y = NULL;

	nếu (point == NULL) {
		fputs("point=(NULL)\n", stderr);
		trả_về;
	}
	nếu ((x = BN_new()) == NULL || (y = BN_new()) == NULL) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		goto out;
	}
	nếu (EC_POINT_get_affine_coordinates(group, point, x, y, NULL) != 1) {
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
	nếu ((exponent = EC_KEY_get0_private_key(key)) == NULL)
		fputs("(NULL)", stderr);
	không_thì
		BN_print_fp(stderr, EC_KEY_get0_private_key(key));
	fputs("\n", stderr);
}
#endif /* WITH_OPENSSL */

static số_nguyên
sshkey_private_to_blob2(struct sshkey *prv, struct sshbuf *blob,
    const char *passphrase, const char *comment, const char *ciphername,
    số_nguyên rounds)
{
	u_char *cp, *key = NULL, *pubkeyblob = NULL;
	u_char salt[SALT_LEN];
	size_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	số_nguyên r = SSH_ERR_INTERNAL_ERROR;
	struct sshcipher_ctx *ciphercontext = NULL;
	const struct sshcipher *cipher;
	const char *kdfname = KDFNAME;
	struct sshbuf *encoded = NULL, *encrypted = NULL, *kdf = NULL;

	nếu (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	nếu (rounds > MAX_KDF_ROUNDS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	nếu (passphrase == NULL || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} không_thì nếu (ciphername == NULL)
		ciphername = DEFAULT_CIPHERNAME;
	nếu ((cipher = cipher_by_name(ciphername)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	nếu ((kdf = sshbuf_new()) == NULL ||
	    (encoded = sshbuf_new()) == NULL ||
	    (encrypted = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	nếu ((key = calloc(1, keylen + ivlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	nếu (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		nếu (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, key, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		nếu ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			goto out;
	} không_thì nếu (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	nếu ((r = cipher_init(&ciphercontext, cipher, key, keylen,
	    key + keylen, ivlen, 1)) != 0)
		goto out;

	nếu ((r = sshbuf_put(encoded, AUTH_MAGIC, sizeof(AUTH_MAGIC))) != 0 ||
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
	nếu ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		goto out;

	/* append private key and comment*/
	nếu ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		goto out;

	/* padding */
	i = 0;
	trong_khi (sshbuf_len(encrypted) % blocksize) {
		nếu ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			goto out;
	}

	/* length in destination buffer */
	nếu ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		goto out;

	/* encrypt */
	nếu ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		goto out;
	nếu ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		goto out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	nếu ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
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
	explicit_bzero(salt, sizeof(salt));
	nếu (key != NULL)
		freezero(key, keylen + ivlen);
	nếu (pubkeyblob != NULL)
		freezero(pubkeyblob, pubkeylen);
	trả_về r;
}

static số_nguyên
private2_uudecode(struct sshbuf *blob, struct sshbuf **decodedp)
{
	const u_char *cp;
	size_t encoded_len;
	số_nguyên r;
	u_char last;
	struct sshbuf *encoded = NULL, *decoded = NULL;

	nếu (blob == NULL || decodedp == NULL)
		trả_về SSH_ERR_INVALID_ARGUMENT;

	*decodedp = NULL;

	nếu ((encoded = sshbuf_new()) == NULL ||
	    (decoded = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	nếu (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	trong_khi (encoded_len > 0) {
		nếu (*cp != '\n' && *cp != '\r') {
			nếu ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				goto out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		nếu (last == '\n') {
			nếu (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				nếu ((r = sshbuf_put_u8(encoded, 0)) != 0)
					goto out;
				break;
			}
		}
	}
	nếu (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* decode base64 */
	nếu ((r = sshbuf_b64tod(decoded, (char *)sshbuf_ptr(encoded))) != 0)
		goto out;

	/* check magic */
	nếu (sshbuf_len(decoded) < sizeof(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, sizeof(AUTH_MAGIC))) {
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
	trả_về r;
}

static số_nguyên
private2_decrypt(struct sshbuf *decoded, const char *passphrase,
    struct sshbuf **decryptedp, struct sshkey **pubkeyp)
{
	char *ciphername = NULL, *kdfname = NULL;
	const struct sshcipher *cipher = NULL;
	số_nguyên r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	struct sshbuf *kdf = NULL, *decrypted = NULL;
	struct sshcipher_ctx *ciphercontext = NULL;
	struct sshkey *pubkey = NULL;
	u_char *key = NULL, *salt = NULL, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	nếu (decoded == NULL || decryptedp == NULL || pubkeyp == NULL)
		trả_về SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = NULL;
	*pubkeyp = NULL;

	nếu ((decrypted = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* parse public portion of key */
	nếu ((r = sshbuf_consume(decoded, sizeof(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, NULL)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		goto out;

	nếu (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	nếu ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		goto out;

	nếu ((cipher = cipher_by_name(ciphername)) == NULL) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	nếu (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	nếu (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	nếu ((passphrase == NULL || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	nếu (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	nếu ((key = calloc(1, keylen + ivlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	nếu (strcmp(kdfname, "bcrypt") == 0) {
		nếu ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			goto out;
		nếu (rounds > MAX_KDF_ROUNDS) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		nếu (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    key, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	nếu (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* decrypt private portion of key */
	nếu ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, key, keylen,
	    key + keylen, ivlen, 0)) != 0)
		goto out;
	nếu ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		nếu (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}
	nếu ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		goto out;
	/* there should be no trailing data */
	nếu (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* check check bytes */
	nếu ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		goto out;
	nếu (check1 != check2) {
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
	nếu (salt != NULL) {
		explicit_bzero(salt, slen);
		free(salt);
	}
	nếu (key != NULL) {
		explicit_bzero(key, keylen + ivlen);
		free(key);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	trả_về r;
}

static số_nguyên
sshkey_parse_private2(struct sshbuf *blob, số_nguyên type, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	char *comment = NULL;
	số_nguyên r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *decoded = NULL, *decrypted = NULL;
	struct sshkey *k = NULL, *pubkey = NULL;

	nếu (keyp != NULL)
		*keyp = NULL;
	nếu (commentp != NULL)
		*commentp = NULL;

	/* Undo base64 encoding and decrypt the private section */
	nếu ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		goto out;

	nếu (type != KEY_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}

	/* Load the private key and comment */
	nếu ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, NULL)) != 0)
		goto out;

	/* Check deterministic padding after private section */
	nếu ((r = private2_check_padding(decrypted)) != 0)
		goto out;

	/* Check that the public key in the envelope matches the private key */
	nếu (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* success */
	r = 0;
	nếu (keyp != NULL) {
		*keyp = k;
		k = NULL;
	}
	nếu (commentp != NULL) {
		*commentp = comment;
		comment = NULL;
	}
 out:
	free(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	trả_về r;
}

static số_nguyên
sshkey_parse_private2_pubkey(struct sshbuf *blob, số_nguyên type,
    struct sshkey **keyp)
{
	số_nguyên r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *decoded = NULL;
	struct sshkey *pubkey = NULL;
	u_int nkeys = 0;

	nếu (keyp != NULL)
		*keyp = NULL;

	nếu ((r = private2_uudecode(blob, &decoded)) != 0)
		goto out;
	/* parse public key from unencrypted envelope */
	nếu ((r = sshbuf_consume(decoded, sizeof(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		goto out;

	nếu (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Parse the public key */
	nếu ((r = sshkey_froms(decoded, &pubkey)) != 0)
		goto out;

	nếu (type != KEY_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}

	/* success */
	r = 0;
	nếu (keyp != NULL) {
		*keyp = pubkey;
		pubkey = NULL;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	trả_về r;
}

#ifdef WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
static số_nguyên
sshkey_private_to_blob_pem_pkcs8(struct sshkey *key, struct sshbuf *buf,
    số_nguyên format, const char *_passphrase, const char *comment)
{
	số_nguyên was_shielded = sshkey_is_shielded(key);
	số_nguyên success, r;
	số_nguyên blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : NULL;
	const EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : NULL;
	char *bptr;
	BIO *bio = NULL;
	struct sshbuf *blob;
	EVP_PKEY *pkey = NULL;

	nếu (len > 0 && len <= 4)
		trả_về SSH_ERR_PASSPHRASE_TOO_SHORT;
	nếu ((blob = sshbuf_new()) == NULL)
		trả_về SSH_ERR_ALLOC_FAIL;
	nếu ((bio = BIO_new(BIO_s_mem())) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	nếu ((r = sshkey_unshield_private(key)) != 0)
		goto out;

	switch (key->type) {
	case KEY_ECDSA:
		nếu (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivateKey(bio,
			    EVP_PKEY_get0_EC_KEY(key->pkey),
			    cipher, passphrase, len, NULL, NULL);
		} không_thì {
			pkey = key->pkey;
			EVP_PKEY_up_ref(key->pkey);
			success = 1;
		}
		break;
	case KEY_RSA:
		nếu (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivateKey(bio,
			    EVP_PKEY_get0_RSA(key->pkey),
			    cipher, passphrase, len, NULL, NULL);
		} không_thì {
			pkey = key->pkey;
			EVP_PKEY_up_ref(key->pkey);
			success = 1;
		}
		break;
#ifdef OPENSSL_HAS_ED25519
	case KEY_ED25519:
		nếu (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		} không_thì {
			pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,
			    NULL, key->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != NULL;
		}
		break;
#endif
	default:
		success = 0;
		break;
	}
	nếu (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	nếu (format == SSHKEY_PRIVATE_PKCS8) {
		nếu ((success = PEM_write_bio_PrivateKey(bio, pkey, cipher,
		    passphrase, len, NULL, NULL)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}
	nếu ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	nếu ((r = sshbuf_put(blob, bptr, blen)) != 0)
		goto out;
	r = 0;
 out:
	nếu (was_shielded)
		r = sshkey_shield_private(key);
	nếu (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	trả_về r;
}
#endif /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
số_nguyên
sshkey_private_to_fileblob(struct sshkey *key, struct sshbuf *blob,
    const char *passphrase, const char *comment,
    số_nguyên format, const char *openssh_format_cipher, số_nguyên openssh_format_rounds)
{
	switch (key->type) {
#ifdef WITH_OPENSSL
	case KEY_ECDSA:
	case KEY_RSA:
	case KEY_ED25519:
		break; /* see below */
#không_thì /* WITH_OPENSSL */
	case KEY_ED25519:
#endif /* WITH_OPENSSL */
	case KEY_ED25519_SK:
#ifdef WITH_OPENSSL
	case KEY_ECDSA_SK:
#endif /* WITH_OPENSSL */
	case KEY_MLDSA44_ED25519:
		trả_về sshkey_private_to_blob2(key, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	default:
		trả_về SSH_ERR_KEY_TYPE_UNKNOWN;
	}

#ifdef WITH_OPENSSL
	switch (format) {
	case SSHKEY_PRIVATE_OPENSSH:
		trả_về sshkey_private_to_blob2(key, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	case SSHKEY_PRIVATE_PEM:
	case SSHKEY_PRIVATE_PKCS8:
		trả_về sshkey_private_to_blob_pem_pkcs8(key, blob,
		    format, passphrase, comment);
	default:
		trả_về SSH_ERR_INVALID_ARGUMENT;
	}
#endif /* WITH_OPENSSL */
}

#ifdef WITH_OPENSSL
static số_nguyên
translate_libcrypto_error(unsigned long pem_err)
{
	số_nguyên pem_reason = ERR_GET_REASON(pem_err);

	switch (ERR_GET_LIB(pem_err)) {
	case ERR_LIB_PEM:
		switch (pem_reason) {
		case PEM_R_BAD_PASSWORD_READ:
#ifdef PEM_R_PROBLEMS_GETTING_PASSWORD
		case PEM_R_PROBLEMS_GETTING_PASSWORD:
#endif
#ifdef PEM_R_BAD_DECRYPT
		case PEM_R_BAD_DECRYPT:
#endif
			trả_về SSH_ERR_KEY_WRONG_PASSPHRASE;
		default:
			trả_về SSH_ERR_INVALID_FORMAT;
		}
	case ERR_LIB_EVP:
		switch (pem_reason) {
#ifdef EVP_R_BAD_DECRYPT
		case EVP_R_BAD_DECRYPT:
			trả_về SSH_ERR_KEY_WRONG_PASSPHRASE;
#endif
#ifdef EVP_R_BN_DECODE_ERROR
		case EVP_R_BN_DECODE_ERROR:
#endif
		case EVP_R_DECODE_ERROR:
#ifdef EVP_R_PRIVATE_KEY_DECODE_ERROR
		case EVP_R_PRIVATE_KEY_DECODE_ERROR:
#endif
			trả_về SSH_ERR_INVALID_FORMAT;
		default:
			trả_về SSH_ERR_LIBCRYPTO_ERROR;
		}
	case ERR_LIB_ASN1:
#ifdef ERR_LIB_OSSL_DECODER
	case ERR_LIB_OSSL_DECODER:
#endif
		trả_về SSH_ERR_INVALID_FORMAT;
	}
	trả_về SSH_ERR_LIBCRYPTO_ERROR;
}

static void
clear_libcrypto_errors(void)
{
	trong_khi (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
static số_nguyên
convert_libcrypto_error(void)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	nếu (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_KEY_WRONG_PASSPHRASE)
		trả_về SSH_ERR_KEY_WRONG_PASSPHRASE;
	trả_về translate_libcrypto_error(ERR_peek_last_error());
}

static số_nguyên
pem_passphrase_cb(char *buf, số_nguyên size, số_nguyên rwflag, void *u)
{
	char *p = (char *)u;
	size_t len;

	nếu (p == NULL || (len = strlen(p)) == 0)
		trả_về -1;
	nếu (size < 0 || len > (size_t)size)
		trả_về -1;
	memcpy(buf, p, len);
	trả_về (số_nguyên)len;
}

static số_nguyên
sshkey_parse_private_pem_fileblob(struct sshbuf *blob, số_nguyên type,
    const char *passphrase, struct sshkey **keyp)
{
	EVP_PKEY *pk = NULL;
	struct sshkey *prv = NULL;
	BIO *bio = NULL;
	số_nguyên r;
	RSA *rsa = NULL;
	EC_KEY *ecdsa = NULL;

	nếu (keyp != NULL)
		*keyp = NULL;

	nếu ((bio = BIO_new(BIO_s_mem())) == NULL || sshbuf_len(blob) > INT_MAX)
		trả_về SSH_ERR_ALLOC_FAIL;
	nếu (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (số_nguyên)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	clear_libcrypto_errors();
	nếu ((pk = PEM_read_bio_PrivateKey(bio, NULL, pem_passphrase_cb,
	    (char *)passphrase)) == NULL) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		nếu (passphrase != NULL && *passphrase != '\0')
			r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		không_thì
			r = convert_libcrypto_error();
		goto out;
	}
	nếu (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == KEY_UNSPEC || type == KEY_RSA)) {
		nếu ((prv = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		nếu ((rsa = EVP_PKEY_get1_RSA(pk)) == NULL) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		prv->type = KEY_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#endif
		nếu (RSA_blinding_on(rsa, NULL) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		nếu ((r = sshkey_check_rsa_length(prv, 0)) != 0)
			goto out;
	} không_thì nếu (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == KEY_UNSPEC || type == KEY_ECDSA)) {
		nếu ((prv = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		nếu ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_KEY(pk)) == NULL) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		prv->type = KEY_ECDSA;
		nếu (sshkey_curve_nid_to_name(prv->ecdsa_nid) == NULL ||
		    sshkey_ec_validate_public(EC_KEY_get0_group(ecdsa),
		    EC_KEY_get0_public_key(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#ifdef DEBUG_PK
		nếu (prv != NULL && prv->pkey != NULL)
			sshkey_dump_ec_key(EVP_PKEY_get0_EC_KEY(prv->pkey));
#endif
#ifdef OPENSSL_HAS_ED25519
	} không_thì nếu (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == KEY_UNSPEC || type == KEY_ED25519)) {
		size_t len;

		nếu ((prv = sshkey_new(KEY_UNSPEC)) == NULL ||
		    (prv->ed25519_sk = calloc(1, ED25519_SK_SZ)) == NULL ||
		    (prv->ed25519_pk = calloc(1, ED25519_PK_SZ)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		prv->type = KEY_ED25519;
		len = ED25519_PK_SZ;
		nếu (!EVP_PKEY_get_raw_public_key(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		nếu (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		nếu (!EVP_PKEY_get_raw_private_key(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		nếu (len != ED25519_SK_SZ - ED25519_PK_SZ) {
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
	} không_thì {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	r = 0;
	nếu (keyp != NULL) {
		*keyp = prv;
		prv = NULL;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_KEY_free(ecdsa);
	sshkey_free(prv);
	trả_về r;
}
#endif /* WITH_OPENSSL */

số_nguyên
sshkey_parse_private_fileblob_type(struct sshbuf *blob, số_nguyên type,
    const char *passphrase, struct sshkey **keyp, char **commentp)
{
	số_nguyên r = SSH_ERR_INTERNAL_ERROR;

	nếu (keyp != NULL)
		*keyp = NULL;
	nếu (commentp != NULL)
		*commentp = NULL;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	nếu (r != SSH_ERR_INVALID_FORMAT)
		trả_về r;
#ifdef WITH_OPENSSL
	trả_về sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#không_thì
	trả_về SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

số_nguyên
sshkey_parse_private_fileblob(struct sshbuf *buffer, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	nếu (keyp != NULL)
		*keyp = NULL;
	nếu (commentp != NULL)
		*commentp = NULL;

	trả_về sshkey_parse_private_fileblob_type(buffer, KEY_UNSPEC,
	    passphrase, keyp, commentp);
}

void
sshkey_sig_details_free(struct sshkey_sig_details *details)
{
	freezero(details, sizeof(*details));
}

số_nguyên
sshkey_parse_pubkey_from_private_fileblob_type(struct sshbuf *blob, số_nguyên type,
    struct sshkey **pubkeyp)
{
	số_nguyên r = SSH_ERR_INTERNAL_ERROR;

	nếu (pubkeyp != NULL)
		*pubkeyp = NULL;
	/* only new-format private keys bundle a public key inside */
	nếu ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		trả_về r;
	trả_về 0;
}
