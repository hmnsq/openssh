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

static целое sshkey_from_blob_internal(struct sshbuf *buf,
    struct sshkey **keyp, целое allow_cert,
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
sshkey_impl_from_type(целое type)
{
	целое i;

	для (i = 0; keyimpls[i] != NULL; i++) {
		если (keyimpls[i]->type == type)
			вернуть keyimpls[i];
	}
	вернуть NULL;
}

static const struct sshkey_impl *
sshkey_impl_from_type_nid(целое type, целое nid)
{
	целое i;

	для (i = 0; keyimpls[i] != NULL; i++) {
		если (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			вернуть keyimpls[i];
	}
	вернуть NULL;
}

static const struct sshkey_impl *
sshkey_impl_from_key(const struct sshkey *k)
{
	если (k == NULL)
		вернуть NULL;
	вернуть sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

const char *
sshkey_type(const struct sshkey *k)
{
	const struct sshkey_impl *impl;

	если ((impl = sshkey_impl_from_key(k)) == NULL)
		вернуть "unknown";
	вернуть impl->shortname;
}

static const char *
sshkey_ssh_name_from_type_nid(целое type, целое nid)
{
	const struct sshkey_impl *impl;

	если ((impl = sshkey_impl_from_type_nid(type, nid)) == NULL)
		вернуть "ssh-unknown";
	вернуть impl->name;
}

целое
sshkey_type_is_cert(целое type)
{
	const struct sshkey_impl *impl;

	если ((impl = sshkey_impl_from_type(type)) == NULL)
		вернуть 0;
	вернуть impl->cert;
}

const char *
sshkey_ssh_name(const struct sshkey *k)
{
	вернуть sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

const char *
sshkey_ssh_name_plain(const struct sshkey *k)
{
	вернуть sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

static целое
type_from_name(const char *name, целое allow_short)
{
	целое i;
	const struct sshkey_impl *impl;

	для (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		если (impl->name != NULL && strcmp(name, impl->name) == 0)
			вернуть impl->type;
		/* Only allow shortname matches for plain key types */
		если (allow_short && !impl->cert && impl->shortname != NULL &&
		    strcasecmp(impl->shortname, name) == 0)
			вернуть impl->type;
	}
	вернуть KEY_UNSPEC;
}

целое
sshkey_type_from_name(const char *name)
{
	вернуть type_from_name(name, 0);
}

целое
sshkey_type_from_shortname(const char *name)
{
	вернуть type_from_name(name, 1);
}

static целое
key_type_is_ecdsa_variant(целое type)
{
	switch (type) {
	case KEY_ECDSA:
	case KEY_ECDSA_CERT:
	case KEY_ECDSA_SK:
	case KEY_ECDSA_SK_CERT:
		вернуть 1;
	}
	вернуть 0;
}

целое
sshkey_ecdsa_nid_from_name(const char *name)
{
	целое i;

	для (i = 0; keyimpls[i] != NULL; i++) {
		если (!key_type_is_ecdsa_variant(keyimpls[i]->type))
			continue;
		если (keyimpls[i]->name != NULL &&
		    strcmp(name, keyimpls[i]->name) == 0)
			вернуть keyimpls[i]->nid;
	}
	вернуть -1;
}

целое
sshkey_match_keyname_to_sigalgs(const char *keyname, const char *sigalgs)
{
	целое ktype;

	если (sigalgs == NULL || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == KEY_UNSPEC)
		вернуть 0;
	иначе если (ktype == KEY_RSA) {
		вернуть match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} иначе если (ktype == KEY_RSA_CERT) {
		вернуть match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} иначе если (ktype == KEY_ECDSA_SK) {
		вернуть match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} иначе если (ktype == KEY_ECDSA_SK_CERT) {
		вернуть match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} иначе
		вернуть match_pattern_list(keyname, sigalgs, 0) == 1;
}

char *
sshkey_alg_list(целое certs_only, целое plain_only, целое include_sigonly, char sep)
{
	char *ret = NULL;
	size_t i;
	const struct sshkey_impl *impl;
	char sep_str[2] = {sep, '\0'};

	для (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		если (impl->name == NULL)
			continue;
		если (!include_sigonly && impl->sigonly)
			continue;
		если ((certs_only && !impl->cert) || (plain_only && impl->cert))
			continue;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	вернуть ret;
}

целое
sshkey_names_valid2(const char *names, целое allow_wildcard, целое plain_only)
{
	char *s, *cp, *p;
	const struct sshkey_impl *impl;
	целое i, type;

	если (names == NULL || strcmp(names, "") == 0)
		вернуть 0;
	если ((s = cp = strdup(names)) == NULL)
		вернуть 0;
	для ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		если (type == KEY_UNSPEC) {
			если (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = NULL;
				для (i = 0; keyimpls[i] != NULL; i++) {
					если (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						break;
					}
				}
				если (impl != NULL)
					continue;
			}
			free(s);
			вернуть 0;
		} иначе если (plain_only && sshkey_type_is_cert(type)) {
			free(s);
			вернуть 0;
		}
	}
	free(s);
	вернуть 1;
}

u_int
sshkey_size(const struct sshkey *k)
{
	const struct sshkey_impl *impl;

	если ((impl = sshkey_impl_from_key(k)) == NULL)
		вернуть 0;
	если (impl->funcs->size != NULL)
		вернуть impl->funcs->size(k);
	вернуть impl->keybits;
}

static целое
sshkey_type_is_valid_ca(целое type)
{
	const struct sshkey_impl *impl;

	если ((impl = sshkey_impl_from_type(type)) == NULL)
		вернуть 0;
	/* All non-certificate types may act as CAs */
	вернуть !impl->cert;
}

целое
sshkey_is_cert(const struct sshkey *k)
{
	если (k == NULL)
		вернуть 0;
	вернуть sshkey_type_is_cert(k->type);
}

целое
sshkey_is_sk(const struct sshkey *k)
{
	если (k == NULL)
		вернуть 0;
	switch (sshkey_type_plain(k->type)) {
	case KEY_ECDSA_SK:
	case KEY_ED25519_SK:
		вернуть 1;
	default:
		вернуть 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
целое
sshkey_type_plain(целое type)
{
	switch (type) {
	case KEY_RSA_CERT:
		вернуть KEY_RSA;
	case KEY_ECDSA_CERT:
		вернуть KEY_ECDSA;
	case KEY_ECDSA_SK_CERT:
		вернуть KEY_ECDSA_SK;
	case KEY_ED25519_CERT:
		вернуть KEY_ED25519;
	case KEY_MLDSA44_ED25519_CERT:
		вернуть KEY_MLDSA44_ED25519;
	case KEY_ED25519_SK_CERT:
		вернуть KEY_ED25519_SK;
	default:
		вернуть type;
	}
}

/* Return the cert equivalent to a plain key type */
static целое
sshkey_type_certified(целое type)
{
	switch (type) {
	case KEY_RSA:
		вернуть KEY_RSA_CERT;
	case KEY_ECDSA:
		вернуть KEY_ECDSA_CERT;
	case KEY_ECDSA_SK:
		вернуть KEY_ECDSA_SK_CERT;
	case KEY_ED25519:
		вернуть KEY_ED25519_CERT;
	case KEY_MLDSA44_ED25519:
		вернуть KEY_MLDSA44_ED25519_CERT;
	case KEY_ED25519_SK:
		вернуть KEY_ED25519_SK_CERT;
	default:
		вернуть -1;
	}
}

#ifdef WITH_OPENSSL
static const EVP_MD *
ssh_digest_to_md(целое hash_alg)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		вернуть EVP_sha1();
	case SSH_DIGEST_SHA256:
		вернуть EVP_sha256();
	case SSH_DIGEST_SHA384:
		вернуть EVP_sha384();
	case SSH_DIGEST_SHA512:
		вернуть EVP_sha512();
	}
	вернуть NULL;
}

целое
sshkey_pkey_digest_sign(EVP_PKEY *pkey, целое hash_alg, u_char **sigp,
    size_t *lenp, const u_char *data, size_t datalen)
{
	EVP_MD_CTX *ctx = NULL;
	u_char *sig = NULL;
	целое ret;
	size_t slen;
	const EVP_MD *evpmd;

	*sigp = NULL;
	*lenp = 0;

	slen = EVP_PKEY_size(pkey);
	если (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == NULL)
		вернуть SSH_ERR_INVALID_ARGUMENT;

	если ((sig = malloc(slen)) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;

	если ((ctx = EVP_MD_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	если (EVP_DigestSignInit(ctx, NULL, evpmd, NULL, pkey) != 1 ||
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
	вернуть ret;
}

целое
sshkey_pkey_digest_verify(EVP_PKEY *pkey, целое hash_alg, const u_char *data,
    size_t datalen, u_char *sigbuf, size_t siglen)
{
	EVP_MD_CTX *ctx = NULL;
	целое ret = SSH_ERR_INTERNAL_ERROR;
	const EVP_MD *evpmd;

	если ((evpmd = ssh_digest_to_md(hash_alg)) == NULL)
		вернуть SSH_ERR_INVALID_ARGUMENT;
	если ((ctx = EVP_MD_CTX_new()) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;
	если (EVP_DigestVerifyInit(ctx, NULL, evpmd, NULL, pkey) != 1) {
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
	вернуть ret;
}

/* XXX: these are really begging for a table-driven approach */
целое
sshkey_curve_name_to_nid(const char *name)
{
	если (strcmp(name, "nistp256") == 0)
		вернуть NID_X9_62_prime256v1;
	иначе если (strcmp(name, "nistp384") == 0)
		вернуть NID_secp384r1;
	иначе если (strcmp(name, "nistp521") == 0)
		вернуть NID_secp521r1;
	иначе
		вернуть -1;
}

u_int
sshkey_curve_nid_to_bits(целое nid)
{
	switch (nid) {
	case NID_X9_62_prime256v1:
		вернуть 256;
	case NID_secp384r1:
		вернуть 384;
	case NID_secp521r1:
		вернуть 521;
	default:
		вернуть 0;
	}
}

целое
sshkey_ecdsa_bits_to_nid(целое bits)
{
	switch (bits) {
	case 256:
		вернуть NID_X9_62_prime256v1;
	case 384:
		вернуть NID_secp384r1;
	case 521:
		вернуть NID_secp521r1;
	default:
		вернуть -1;
	}
}

const char *
sshkey_curve_nid_to_name(целое nid)
{
	switch (nid) {
	case NID_X9_62_prime256v1:
		вернуть "nistp256";
	case NID_secp384r1:
		вернуть "nistp384";
	case NID_secp521r1:
		вернуть "nistp521";
	default:
		вернуть NULL;
	}
}

целое
sshkey_ec_nid_to_hash_alg(целое nid)
{
	целое kbits = sshkey_curve_nid_to_bits(nid);

	если (kbits <= 0)
		вернуть -1;

	/* RFC5656 section 6.2.1 */
	если (kbits <= 256)
		вернуть SSH_DIGEST_SHA256;
	иначе если (kbits <= 384)
		вернуть SSH_DIGEST_SHA384;
	иначе
		вернуть SSH_DIGEST_SHA512;
}
#endif /* WITH_OPENSSL */

static void
cert_free(struct sshkey_cert *cert)
{
	u_int i;

	если (cert == NULL)
		вернуть;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	free(cert->key_id);
	для (i = 0; i < cert->nprincipals; i++)
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

	если ((cert = calloc(1, sizeof(*cert))) == NULL)
		вернуть NULL;
	если ((cert->certblob = sshbuf_new()) == NULL ||
	    (cert->critical = sshbuf_new()) == NULL ||
	    (cert->extensions = sshbuf_new()) == NULL) {
		cert_free(cert);
		вернуть NULL;
	}
	cert->key_id = NULL;
	cert->principals = NULL;
	cert->signature_key = NULL;
	cert->signature_type = NULL;
	вернуть cert;
}

struct sshkey *
sshkey_new(целое type)
{
	struct sshkey *k;
	const struct sshkey_impl *impl = NULL;

	если (type != KEY_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == NULL)
		вернуть NULL;

	/* All non-certificate types may act as CAs */
	если ((k = calloc(1, sizeof(*k))) == NULL)
		вернуть NULL;
	k->type = type;
	k->ecdsa_nid = -1;
	если (impl != NULL && impl->funcs->alloc != NULL) {
		если (impl->funcs->alloc(k) != 0) {
			free(k);
			вернуть NULL;
		}
	}
	если (sshkey_is_cert(k)) {
		если ((k->cert = cert_new()) == NULL) {
			sshkey_free(k);
			вернуть NULL;
		}
	}

	вернуть k;
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

#если defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#elif defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#иначе
# define PREKEY_MMAP_FLAG	0
#endif

static целое
sshkey_prekey_alloc(u_char **prekeyp, size_t len)
{
#если defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = NULL;
	если ((prekey = mmap(NULL, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		вернуть SSH_ERR_SYSTEM_ERROR;
#если defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(void)madvise(prekey, len, MADV_DONTDUMP);
#endif
	*prekeyp = prekey;
#иначе
	*prekeyp = calloc(1, len);
#endif /* HAVE_MMAP et al */
	вернуть 0;
}

static void
sshkey_prekey_free(void *prekey, size_t len)
{
#если defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	если (prekey == NULL)
		вернуть;
	munmap(prekey, len);
#иначе
	free(prekey);
#endif /* HAVE_MMAP et al */
}

static void
sshkey_free_contents(struct sshkey *k)
{
	const struct sshkey_impl *impl;

	если (k == NULL)
		вернуть;
	если ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_key_free(k);
	если ((impl = sshkey_impl_from_type(k->type)) != NULL &&
	    impl->funcs->cleanup != NULL)
		impl->funcs->cleanup(k);
	если (sshkey_is_cert(k))
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

static целое
cert_compare(struct sshkey_cert *a, struct sshkey_cert *b)
{
	если (a == NULL && b == NULL)
		вернуть 1;
	если (a == NULL || b == NULL)
		вернуть 0;
	если (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		вернуть 0;
	если (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		вернуть 0;
	вернуть 1;
}

/* Compares FIDO-specific pubkey fields only */
целое
sshkey_sk_fields_equal(const struct sshkey *a, const struct sshkey *b)
{
	если (a->sk_application == NULL || b->sk_application == NULL)
		вернуть 0;
	если (strcmp(a->sk_application, b->sk_application) != 0)
		вернуть 0;
	вернуть 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
целое
sshkey_equal_public(const struct sshkey *a, const struct sshkey *b)
{
	const struct sshkey_impl *impl;

	если (a == NULL || b == NULL ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		вернуть 0;
	если ((impl = sshkey_impl_from_type(a->type)) == NULL)
		вернуть 0;
	вернуть impl->funcs->equal(a, b);
}

целое
sshkey_equal(const struct sshkey *a, const struct sshkey *b)
{
	если (a == NULL || b == NULL || a->type != b->type)
		вернуть 0;
	если (sshkey_is_cert(a)) {
		если (!cert_compare(a->cert, b->cert))
			вернуть 0;
	}
	вернуть sshkey_equal_public(a, b);
}


/* Serialise common FIDO key parts */
целое
sshkey_serialize_sk(const struct sshkey *key, struct sshbuf *b)
{
	целое r;

	если ((r = sshbuf_put_cstring(b, key->sk_application)) != 0)
		вернуть r;

	вернуть 0;
}

static целое
to_blob_buf(const struct sshkey *key, struct sshbuf *b, целое force_plain,
  enum sshkey_serialize_rep opts)
{
	целое type, ret = SSH_ERR_INTERNAL_ERROR;
	const char *typename;
	const struct sshkey_impl *impl;

	если (key == NULL)
		вернуть SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(key->type) : key->type;

	если (sshkey_type_is_cert(type)) {
		если (key->cert == NULL)
			вернуть SSH_ERR_EXPECTED_CERT;
		если (sshbuf_len(key->cert->certblob) == 0)
			вернуть SSH_ERR_KEY_LACKS_CERTBLOB;
		/* Use the existing blob */
		если ((ret = sshbuf_putb(b, key->cert->certblob)) != 0)
			вернуть ret;
		вернуть 0;
	}
	если ((impl = sshkey_impl_from_type(type)) == NULL)
		вернуть SSH_ERR_KEY_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, key->ecdsa_nid);
	если ((ret = sshbuf_put_cstring(b, typename)) != 0)
		вернуть ret;
	вернуть impl->funcs->serialize_public(key, b, opts);
}

целое
sshkey_putb(const struct sshkey *key, struct sshbuf *b)
{
	вернуть to_blob_buf(key, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

static целое
sshkey_puts_opts_internal(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts, целое force_plain)
{
	struct sshbuf *tmp;
	целое r;

	если ((tmp = sshbuf_new()) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(key, tmp, force_plain, opts);
	если (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	вернуть r;
}

целое
sshkey_puts(const struct sshkey *key, struct sshbuf *b)
{
	вернуть sshkey_puts_opts_internal(key, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

целое
sshkey_putb_plain(const struct sshkey *key, struct sshbuf *b)
{
	вернуть to_blob_buf(key, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

целое
sshkey_puts_plain(const struct sshkey *key, struct sshbuf *b)
{
	вернуть sshkey_puts_opts_internal(key, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

static целое
to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp, целое force_plain,
    enum sshkey_serialize_rep opts)
{
	целое ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	struct sshbuf *b = NULL;

	если (lenp != NULL)
		*lenp = 0;
	если (blobp != NULL)
		*blobp = NULL;
	если ((b = sshbuf_new()) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;
	если ((ret = to_blob_buf(key, b, force_plain, opts)) != 0)
		goto out;
	len = sshbuf_len(b);
	если (lenp != NULL)
		*lenp = len;
	если (blobp != NULL) {
		если ((*blobp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	вернуть ret;
}

целое
sshkey_to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp)
{
	вернуть to_blob(key, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

целое
sshkey_plain_to_blob(const struct sshkey *key, u_char **blobp, size_t *lenp)
{
	вернуть to_blob(key, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

целое
sshkey_fingerprint_raw(const struct sshkey *k, целое dgst_alg,
    u_char **retp, size_t *lenp)
{
	u_char *blob = NULL, *ret = NULL;
	size_t blob_len = 0;
	целое r = SSH_ERR_INTERNAL_ERROR;

	если (retp != NULL)
		*retp = NULL;
	если (lenp != NULL)
		*lenp = 0;
	если (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	если ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		goto out;
	если ((ret = calloc(1, SSH_DIGEST_MAX_LENGTH)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	если ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_LENGTH)) != 0)
		goto out;
	/* success */
	если (retp != NULL) {
		*retp = ret;
		ret = NULL;
	}
	если (lenp != NULL)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	free(ret);
	если (blob != NULL)
		freezero(blob, blob_len);
	вернуть r;
}

static char *
fingerprint_b64(const char *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	char *ret;
	size_t plen = strlen(alg) + 1;
	size_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	если (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == NULL)
		вернуть NULL;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	если (dgst_raw_len == 0)
		вернуть ret;
	если (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		вернуть NULL;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	вернуть ret;
}

static char *
fingerprint_hex(const char *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	char *retval, hex[5];
	size_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	если (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == NULL)
		вернуть NULL;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	для (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, sizeof(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	вернуть retval;
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
	если ((retval = calloc(rounds, 6)) == NULL)
		вернуть NULL;
	retval[j++] = 'x';
	для (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		если ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			если ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} иначе {
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
	вернуть retval;
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
	целое	 x, y, r;
	size_t	 len = strlen(augmentation_string) - 1;

	если ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == NULL)
		вернуть NULL;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * sizeof(char));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	для (i = 0; i < dgst_raw_len; i++) {
		целое input;
		/* each byte conveys four 2-bit move commands */
		input = dgst_raw[i];
		для (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (input & 0x1) ? 1 : -1;
			y += (input & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			если (field[x][y] < len - 2)
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
	если (r < 0 || r > (целое)sizeof(title))
		r = snprintf(title, sizeof(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, sizeof(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	для (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	memcpy(p, title, tlen);
	p += tlen;
	для (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	для (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		для (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	для (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	memcpy(p, hash, hlen);
	p += hlen;
	для (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	вернуть retval;
}

char *
sshkey_fingerprint(const struct sshkey *k, целое dgst_alg,
    enum sshkey_fp_rep dgst_rep)
{
	char *retval = NULL;
	u_char *dgst_raw;
	size_t dgst_raw_len;

	если (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		вернуть NULL;
	switch (dgst_rep) {
	case SSH_FP_DEFAULT:
		если (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} иначе {
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
		вернуть NULL;
	}
	freezero(dgst_raw, dgst_raw_len);
	вернуть retval;
}

static целое
peek_type_nid(const char *s, size_t l, целое *nid)
{
	const struct sshkey_impl *impl;
	целое i;

	для (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		если (impl->name == NULL || strlen(impl->name) != l)
			continue;
		если (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			если (key_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			вернуть impl->type;
		}
	}
	вернуть KEY_UNSPEC;
}

/* XXX this can now be made const char * */
целое
sshkey_read(struct sshkey *ret, char **cpp)
{
	struct sshkey *k;
	char *cp, *blobcopy;
	size_t space;
	целое r, type, curve_nid = -1;
	struct sshbuf *blob;

	если (ret == NULL)
		вернуть SSH_ERR_INVALID_ARGUMENT;
	если (ret->type != KEY_UNSPEC && sshkey_impl_from_type(ret->type) == NULL)
		вернуть SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	если (space == strlen(cp))
		вернуть SSH_ERR_INVALID_FORMAT;
	если ((type = peek_type_nid(cp, space, &curve_nid)) == KEY_UNSPEC)
		вернуть SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	для (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	если (*cp == '\0')
		вернуть SSH_ERR_INVALID_FORMAT;
	если (ret->type != KEY_UNSPEC && ret->type != type)
		вернуть SSH_ERR_KEY_TYPE_MISMATCH;
	если ((blob = sshbuf_new()) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	если ((blobcopy = strndup(cp, space)) == NULL) {
		sshbuf_free(blob);
		вернуть SSH_ERR_ALLOC_FAIL;
	}
	если ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		free(blobcopy);
		sshbuf_free(blob);
		вернуть r;
	}
	free(blobcopy);
	если ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		вернуть r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	для (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	если (k->type != type) {
		sshkey_free(k);
		вернуть SSH_ERR_KEY_TYPE_MISMATCH;
	}
	если (key_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		вернуть SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, sizeof(*k));

	/* success */
	*cpp = cp;
	вернуть 0;
}

целое
sshkey_to_base64(const struct sshkey *key, char **b64p)
{
	целое r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;
	char *uu = NULL;

	если (b64p != NULL)
		*b64p = NULL;
	если ((b = sshbuf_new()) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;
	если ((r = sshkey_putb(key, b)) != 0)
		goto out;
	если ((uu = sshbuf_dtob64_string(b, 0)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* Success */
	если (b64p != NULL) {
		*b64p = uu;
		uu = NULL;
	}
	r = 0;
 out:
	sshbuf_free(b);
	free(uu);
	вернуть r;
}

целое
sshkey_format_text(const struct sshkey *key, struct sshbuf *b)
{
	целое r = SSH_ERR_INTERNAL_ERROR;
	char *uu = NULL;

	если ((r = sshkey_to_base64(key, &uu)) != 0)
		goto out;
	если ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(key), uu)) != 0)
		goto out;
	r = 0;
 out:
	free(uu);
	вернуть r;
}

целое
sshkey_write(const struct sshkey *key, FILE *f)
{
	struct sshbuf *b = NULL;
	целое r = SSH_ERR_INTERNAL_ERROR;

	если ((b = sshbuf_new()) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;
	если ((r = sshkey_format_text(key, b)) != 0)
		goto out;
	если (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		если (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		goto out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	вернуть r;
}

const char *
sshkey_cert_type(const struct sshkey *k)
{
	switch (k->cert->type) {
	case SSH2_CERT_TYPE_USER:
		вернуть "user";
	case SSH2_CERT_TYPE_HOST:
		вернуть "host";
	default:
		вернуть "unknown";
	}
}

целое
sshkey_check_rsa_length(const struct sshkey *k, целое min_size)
{
#ifdef WITH_OPENSSL
	целое nbits;

	если (k == NULL || k->pkey == NULL ||
	    (k->type != KEY_RSA && k->type != KEY_RSA_CERT))
		вернуть 0;
	nbits = EVP_PKEY_bits(k->pkey);
	если (nbits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    (min_size > 0 && nbits < min_size))
		вернуть SSH_ERR_KEY_LENGTH;
#endif /* WITH_OPENSSL */
	вернуть 0;
}

#ifdef WITH_OPENSSL
целое
sshkey_ecdsa_key_to_nid(const EC_KEY *k)
{
	const EC_GROUP *g;
	целое nid;

	если (k == NULL || (g = EC_KEY_get0_group(k)) == NULL)
		вернуть -1;
	если ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		вернуть -1;
	вернуть nid;
}

целое
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	вернуть sshkey_ecdsa_key_to_nid(EVP_PKEY_get0_EC_KEY(pkey));
}
#endif /* WITH_OPENSSL */

целое
sshkey_generate(целое type, u_int bits, struct sshkey **keyp)
{
	struct sshkey *k;
	целое ret = SSH_ERR_INTERNAL_ERROR;
	const struct sshkey_impl *impl;

	если (keyp == NULL || sshkey_type_is_cert(type))
		вернуть SSH_ERR_INVALID_ARGUMENT;
	*keyp = NULL;
	если ((impl = sshkey_impl_from_type(type)) == NULL)
		вернуть SSH_ERR_KEY_TYPE_UNKNOWN;
	если (impl->funcs->generate == NULL)
		вернуть SSH_ERR_FEATURE_UNSUPPORTED;
	если ((k = sshkey_new(KEY_UNSPEC)) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;
	k->type = type;
	если ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		вернуть ret;
	}
	/* success */
	*keyp = k;
	вернуть 0;
}

целое
sshkey_cert_copy(const struct sshkey *from_key, struct sshkey *to_key)
{
	u_int i;
	const struct sshkey_cert *from;
	struct sshkey_cert *to;
	целое r = SSH_ERR_INTERNAL_ERROR;

	если (to_key == NULL || (from = from_key->cert) == NULL)
		вернуть SSH_ERR_INVALID_ARGUMENT;

	если ((to = cert_new()) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;

	если ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		goto out;

	to->serial = from->serial;
	to->type = from->type;
	если (from->key_id == NULL)
		to->key_id = NULL;
	иначе если ((to->key_id = strdup(from->key_id)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	если (from->signature_key == NULL)
		to->signature_key = NULL;
	иначе если ((r = sshkey_from_private(from->signature_key,
	    &to->signature_key)) != 0)
		goto out;
	если (from->signature_type != NULL &&
	    (to->signature_type = strdup(from->signature_type)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	если (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	если (from->nprincipals > 0) {
		если ((to->principals = calloc(from->nprincipals,
		    sizeof(*to->principals))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		для (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			если (to->principals[i] == NULL) {
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
	вернуть r;
}

целое
sshkey_copy_public_sk(const struct sshkey *from, struct sshkey *to)
{
	/* Append security-key application string */
	если ((to->sk_application = strdup(from->sk_application)) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;
	вернуть 0;
}

целое
sshkey_from_private(const struct sshkey *k, struct sshkey **pkp)
{
	struct sshkey *n = NULL;
	целое r = SSH_ERR_INTERNAL_ERROR;
	const struct sshkey_impl *impl;

	*pkp = NULL;
	если ((impl = sshkey_impl_from_key(k)) == NULL)
		вернуть SSH_ERR_KEY_TYPE_UNKNOWN;
	если ((n = sshkey_new(k->type)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	если ((r = impl->funcs->copy_public(k, n)) != 0)
		goto out;
	если (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		goto out;
	/* success */
	*pkp = n;
	n = NULL;
	r = 0;
 out:
	sshkey_free(n);
	вернуть r;
}

целое
sshkey_is_shielded(struct sshkey *k)
{
	вернуть k != NULL && k->shielded_private != NULL;
}

целое
sshkey_shield_private(struct sshkey *k)
{
	struct sshbuf *prvbuf = NULL;
	u_char *prekey = NULL, *enc = NULL, keyiv[SSH_DIGEST_MAX_LENGTH];
	struct sshcipher_ctx *cctx = NULL;
	const struct sshcipher *cipher;
	size_t i, enclen = 0;
	struct sshkey *kswap = NULL, tmp;
	целое r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	если ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	если (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	если ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		goto out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	если ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	если ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		goto out;

	/* Serialise and encrypt the private key using the ephemeral key */
	если ((prvbuf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	если (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		goto out;
	если ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		goto out;
	/* pad to cipher blocksize */
	i = 0;
	пока (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		если ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			goto out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	если ((enc = malloc(enclen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	если ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	если ((r = sshkey_from_private(k, &kswap)) != 0)
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
	вернуть r;
}

/* Check deterministic padding after private key */
static целое
private2_check_padding(struct sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	целое r;

	i = 0;
	пока (sshbuf_len(decrypted)) {
		если ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			goto out;
		если (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, sizeof(pad));
	explicit_bzero(&i, sizeof(i));
	вернуть r;
}

целое
sshkey_unshield_private(struct sshkey *k)
{
	struct sshbuf *prvbuf = NULL;
	u_char *cp, keyiv[SSH_DIGEST_MAX_LENGTH];
	struct sshcipher_ctx *cctx = NULL;
	const struct sshcipher *cipher;
	struct sshkey *kswap = NULL, tmp;
	целое r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	если (!sshkey_is_shielded(k))
		вернуть 0; /* nothing to do */

	если ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	если (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	/* check size of shielded key blob */
	если (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Calculate the ephemeral key from the prekey */
	если ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		goto out;
	если ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	если ((prvbuf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	если ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		goto out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(k->shielded_private, k->shielded_len, stderr);
#endif
	если ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	если ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		goto out;

	если ((r = private2_check_padding(prvbuf)) != 0)
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
	вернуть r;
}

static целое
cert_parse(struct sshbuf *b, struct sshkey *key, struct sshbuf *certbuf,
    const char *ca_sigalg_allowlist)
{
	struct sshbuf *principals = NULL, *crit = NULL;
	struct sshbuf *exts = NULL, *ca = NULL;
	u_char *sig = NULL;
	char *sigtype = NULL;
	size_t signed_len = 0, slen = 0, kidlen = 0;
	целое ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	если ((ret = sshbuf_putb(key->cert->certblob, certbuf)) != 0)
		вернуть ret;

	/* Parse body of certificate up to signature */
	если ((ret = sshbuf_get_u64(b, &key->cert->serial)) != 0 ||
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

	если ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Is this a signature we're prepared to accept? */
	если ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	если (ca_sigalg_allowlist != NULL &&
	    match_pattern_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		goto out;
	}

	/* Parse CA key and check whether we might accept it */
	если (sshkey_from_blob_internal(ca, &key->cert->signature_key, 0,
	    ca_sigalg_allowlist, NULL) != 0) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}
	если (!sshkey_type_is_valid_ca(key->cert->signature_key->type)) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}

	если (key->cert->type != SSH2_CERT_TYPE_USER &&
	    key->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_KEY_CERT_UNKNOWN_TYPE;
		goto out;
	}

	/* Parse principals section */
	пока (sshbuf_len(principals) > 0) {
		char *principal = NULL;
		char **oprincipals = NULL;

		если (key->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		если ((ret = sshbuf_get_cstring(principals, &principal,
		    NULL)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		oprincipals = key->cert->principals;
		key->cert->principals = recallocarray(key->cert->principals,
		    key->cert->nprincipals, key->cert->nprincipals + 1,
		    sizeof(*key->cert->principals));
		если (key->cert->principals == NULL) {
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
	если ((ret = sshbuf_putb(key->cert->critical, crit)) != 0 ||
	    (exts != NULL &&
	    (ret = sshbuf_putb(key->cert->extensions, exts)) != 0))
		goto out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	пока (sshbuf_len(crit) != 0) {
		если ((ret = sshbuf_get_string_direct(crit, NULL, NULL)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, NULL, NULL)) != 0) {
			sshbuf_reset(key->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	пока (exts != NULL && sshbuf_len(exts) != 0) {
		если ((ret = sshbuf_get_string_direct(exts, NULL, NULL)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, NULL, NULL)) != 0) {
			sshbuf_reset(key->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}

	/* Finally, validate signature */
	если ((ret = sshkey_verify(key->cert->signature_key, sig, slen,
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
	вернуть ret;
}

целое
sshkey_deserialize_sk(struct sshbuf *b, struct sshkey *key)
{
	/* Parse additional security-key application string */
	если (sshbuf_get_cstring(b, &key->sk_application, NULL) != 0)
		вернуть SSH_ERR_INVALID_FORMAT;
	вернуть 0;
}

static целое
sshkey_from_blob_internal(struct sshbuf *b, struct sshkey **keyp,
    целое allow_cert, const char *alg_allowlist, const char *ca_sigalg_allowlist)
{
	целое type, ret = SSH_ERR_INTERNAL_ERROR;
	char *ktype = NULL;
	struct sshkey *key = NULL;
	struct sshbuf *copy;
	const struct sshkey_impl *impl;

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	если (keyp != NULL)
		*keyp = NULL;
	если ((copy = sshbuf_fromb(b)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	если (sshbuf_get_cstring(b, &ktype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	type = sshkey_type_from_name(ktype);
	если (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
		goto out;
	}

	если (alg_allowlist != NULL &&
	    !sshkey_match_keyname_to_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_KEY_ALG_UNSUPPORTED;
		goto out;
	}

	если ((impl = sshkey_impl_from_type(type)) == NULL) {
		ret = SSH_ERR_KEY_TYPE_UNKNOWN;
		goto out;
	}
	если ((key = sshkey_new(type)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	если (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		если (sshbuf_get_string_direct(b, NULL, NULL) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	если ((ret = impl->funcs->deserialize_public(ktype, b, key)) != 0)
		goto out;

	/* Parse certificate potion */
	если (sshkey_is_cert(key) &&
	    (ret = cert_parse(b, key, copy, ca_sigalg_allowlist)) != 0)
		goto out;

	если (key != NULL && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ret = 0;
	если (keyp != NULL) {
		*keyp = key;
		key = NULL;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(key);
	free(ktype);
	вернуть ret;
}

целое
sshkey_from_blob(const u_char *blob, size_t blen, struct sshkey **keyp)
{
	struct sshbuf *b;
	целое r;

	если ((b = sshbuf_from(blob, blen)) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1, NULL, NULL);
	sshbuf_free(b);
	вернуть r;
}

целое
sshkey_fromb(struct sshbuf *b, struct sshkey **keyp)
{
	вернуть sshkey_from_blob_internal(b, keyp, 1, NULL, NULL);
}

целое
sshkey_fromb_allowlist(struct sshbuf *b, struct sshkey **keyp,
    const char *alg_allowlist, const char *ca_sigalg_allowlist)
{
	вернуть sshkey_from_blob_internal(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

целое
sshkey_froms(struct sshbuf *buf, struct sshkey **keyp)
{
	struct sshbuf *b;
	целое r;

	если ((r = sshbuf_froms(buf, &b)) != 0)
		вернуть r;
	r = sshkey_from_blob_internal(b, keyp, 1, NULL, NULL);
	sshbuf_free(b);
	вернуть r;
}

целое
sshkey_get_sigtype(const u_char *sig, size_t siglen, char **sigtypep)
{
	целое r;
	struct sshbuf *b = NULL;
	char *sigtype = NULL;

	если (sigtypep != NULL)
		*sigtypep = NULL;
	если ((b = sshbuf_from(sig, siglen)) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;
	если ((r = sshbuf_get_cstring(b, &sigtype, NULL)) != 0)
		goto out;
	/* success */
	если (sigtypep != NULL) {
		*sigtypep = sigtype;
		sigtype = NULL;
	}
	r = 0;
 out:
	free(sigtype);
	sshbuf_free(b);
	вернуть r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
целое
sshkey_check_cert_sigtype(const struct sshkey *key, const char *allowed)
{
	если (key == NULL || allowed == NULL)
		вернуть SSH_ERR_INVALID_ARGUMENT;
	если (!sshkey_type_is_cert(key->type))
		вернуть 0;
	если (key->cert == NULL || key->cert->signature_type == NULL)
		вернуть SSH_ERR_INVALID_ARGUMENT;
	если (match_pattern_list(key->cert->signature_type, allowed, 0) != 1)
		вернуть SSH_ERR_SIGN_ALG_UNSUPPORTED;
	вернуть 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
const char *
sshkey_sigalg_by_name(const char *name)
{
	const struct sshkey_impl *impl;
	целое i;

	для (i = 0; keyimpls[i] != NULL; i++) {
		impl = keyimpls[i];
		если (strcmp(impl->name, name) != 0)
			continue;
		если (impl->sigalg != NULL)
			вернуть impl->sigalg;
		если (!impl->cert)
			вернуть impl->name;
		вернуть sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	вернуть NULL;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
целое
sshkey_check_sigtype(const u_char *sig, size_t siglen,
    const char *requested_alg)
{
	const char *expected_alg;
	char *sigtype = NULL;
	целое r;

	если (requested_alg == NULL)
		вернуть 0;
	если ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == NULL)
		вернуть SSH_ERR_INVALID_ARGUMENT;
	если ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		вернуть r;
	r = strcmp(expected_alg, sigtype) == 0;
	free(sigtype);
	вернуть r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

целое
sshkey_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	целое was_shielded = sshkey_is_shielded(key);
	целое r2, r = SSH_ERR_INTERNAL_ERROR;
	const struct sshkey_impl *impl;

	если (sigp != NULL)
		*sigp = NULL;
	если (lenp != NULL)
		*lenp = 0;
	если (datalen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		вернуть SSH_ERR_INVALID_ARGUMENT;
	если ((impl = sshkey_impl_from_key(key)) == NULL)
		вернуть SSH_ERR_KEY_TYPE_UNKNOWN;
	если ((r = sshkey_unshield_private(key)) != 0)
		вернуть r;
	если (sshkey_is_sk(key)) {
		r = sshsk_sign(sk_provider, key, sigp, lenp, data,
		    datalen, compat, sk_pin);
	} иначе если ((key->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(key, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	} иначе {
		если (impl->funcs->sign == NULL)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		иначе {
			r = impl->funcs->sign(key, sigp, lenp, data, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	если (was_shielded && (r2 = sshkey_shield_private(key)) != 0)
		вернуть r2;
	вернуть r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
целое
sshkey_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	const struct sshkey_impl *impl;

	если (detailsp != NULL)
		*detailsp = NULL;
	если (siglen == 0 || dlen > SSH_KEY_MAX_SIGN_DATA_SIZE)
		вернуть SSH_ERR_INVALID_ARGUMENT;
	если ((impl = sshkey_impl_from_key(key)) == NULL)
		вернуть SSH_ERR_KEY_TYPE_UNKNOWN;
	вернуть impl->funcs->verify(key, sig, siglen, data, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
целое
sshkey_to_certified(struct sshkey *k)
{
	целое newtype;

	если ((newtype = sshkey_type_certified(k->type)) == -1)
		вернуть SSH_ERR_INVALID_ARGUMENT;
	если ((k->cert = cert_new()) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	вернуть 0;
}

/* Convert a certificate to its raw key equivalent */
целое
sshkey_drop_cert(struct sshkey *k)
{
	если (!sshkey_type_is_cert(k->type))
		вернуть SSH_ERR_KEY_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = NULL;
	k->type = sshkey_type_plain(k->type);
	вернуть 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
целое
sshkey_certify_custom(struct sshkey *k, struct sshkey *ca, const char *alg,
    const char *sk_provider, const char *sk_pin,
    sshkey_certify_signer *signer, void *signer_ctx)
{
	const struct sshkey_impl *impl;
	struct sshbuf *principals = NULL;
	u_char *ca_blob = NULL, *sig_blob = NULL, nonce[32];
	size_t i, ca_len, sig_len;
	целое ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *cert = NULL;
	char *sigtype = NULL;

	если (k == NULL || k->cert == NULL ||
	    k->cert->certblob == NULL || ca == NULL)
		вернуть SSH_ERR_INVALID_ARGUMENT;
	если (!sshkey_is_cert(k))
		вернуть SSH_ERR_KEY_TYPE_UNKNOWN;
	если (!sshkey_type_is_valid_ca(ca->type))
		вернуть SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;
	если ((impl = sshkey_impl_from_key(k)) == NULL)
		вернуть SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	если (alg == NULL)
		alg = k->cert->signature_type;
	иначе если (k->cert->signature_type != NULL &&
	    strcmp(alg, k->cert->signature_type) != 0)
		вернуть SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	если (alg == NULL && ca->type == KEY_RSA)
		alg = "rsa-sha2-512";

	если ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		вернуть SSH_ERR_KEY_CERT_INVALID_SIGN_KEY;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	если ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		goto out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, sizeof(nonce));
	если ((ret = sshbuf_put_string(cert, nonce, sizeof(nonce))) != 0)
		goto out;

	/* Public key next */
	если ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		goto out;

	/* Then remaining cert fields */
	если ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->key_id)) != 0)
		goto out;

	если ((principals = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	для (i = 0; i < k->cert->nprincipals; i++) {
		если ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			goto out;
	}
	если ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, NULL, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		goto out;

	/* Sign the whole mess */
	если ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		goto out;
	/* Check and update signature_type against what was actually used */
	если ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		goto out;
	если (alg != NULL && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		goto out;
	}
	если (k->cert->signature_type == NULL) {
		k->cert->signature_type = sigtype;
		sigtype = NULL;
	}
	/* Append signature and we are done */
	если ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		goto out;
	ret = 0;
 out:
	если (ret != 0)
		sshbuf_reset(cert);
	free(sig_blob);
	free(ca_blob);
	free(sigtype);
	sshbuf_free(principals);
	вернуть ret;
}

static целое
default_key_sign(struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin,
    u_int compat, void *ctx)
{
	если (ctx != NULL)
		вернуть SSH_ERR_INVALID_ARGUMENT;
	вернуть sshkey_sign(key, sigp, lenp, data, datalen, alg,
	    sk_provider, sk_pin, compat);
}

целое
sshkey_certify(struct sshkey *k, struct sshkey *ca, const char *alg,
    const char *sk_provider, const char *sk_pin)
{
	вернуть sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_key_sign, NULL);
}

целое
sshkey_cert_check_authority(const struct sshkey *k,
    целое want_host, целое wildcard_pattern, uint64_t verify_time,
    const char *name, const char **reason)
{
	u_int i, principal_matches;

	если (reason == NULL)
		вернуть SSH_ERR_INVALID_ARGUMENT;
	если (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		вернуть SSH_ERR_KEY_CERT_INVALID;
	}
	если (want_host) {
		если (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			вернуть SSH_ERR_KEY_CERT_INVALID;
		}
	} иначе {
		если (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			вернуть SSH_ERR_KEY_CERT_INVALID;
		}
	}
	если (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		вернуть SSH_ERR_KEY_CERT_INVALID;
	}
	если (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		вернуть SSH_ERR_KEY_CERT_INVALID;
	}
	если (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		вернуть SSH_ERR_KEY_CERT_INVALID;
	}
	если (name == NULL)
		вернуть 0; /* principal matching not requested */

	principal_matches = 0;
	для (i = 0; i < k->cert->nprincipals; i++) {
		если (wildcard_pattern) {
			если (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				break;
			}
		} иначе если (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			break;
		}
	}
	если (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		вернуть SSH_ERR_KEY_CERT_INVALID;
	}
	вернуть 0;
}

целое
sshkey_cert_check_authority_now(const struct sshkey *k,
    целое want_host, целое wildcard_pattern, const char *name,
    const char **reason)
{
	time_t now;

	если ((now = time(NULL)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		вернуть SSH_ERR_KEY_CERT_INVALID;
	}
	вернуть sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

целое
sshkey_cert_check_host(const struct sshkey *key, const char *host,
    const char *ca_sign_algorithms, const char **reason)
{
	целое r;

	если ((r = sshkey_cert_check_authority_now(key, 1, 1, host, reason)) != 0)
		вернуть r;
	если (sshbuf_len(key->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		вернуть SSH_ERR_KEY_CERT_INVALID;
	}
	если (ca_sign_algorithms != NULL &&
	    (r = sshkey_check_cert_sigtype(key, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		вернуть SSH_ERR_KEY_CERT_INVALID;
	}
	вернуть 0;
}

size_t
sshkey_format_cert_validity(const struct sshkey_cert *cert, char *s, size_t l)
{
	char from[32], to[32], ret[128];

	*from = *to = '\0';
	если (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		вернуть strlcpy(s, "forever", l);

	если (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, sizeof(from));
	если (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, sizeof(to));

	если (cert->valid_after == 0)
		snprintf(ret, sizeof(ret), "before %s", to);
	иначе если (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, sizeof(ret), "after %s", from);
	иначе
		snprintf(ret, sizeof(ret), "from %s to %s", from, to);

	вернуть strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
целое
sshkey_serialize_private_sk(const struct sshkey *key, struct sshbuf *b)
{
	целое r;

	если ((r = sshbuf_put_cstring(b, key->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, key->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, key->sk_key_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, key->sk_reserved)) != 0)
		вернуть r;

	вернуть 0;
}

static целое
sshkey_private_serialize_opt(struct sshkey *key, struct sshbuf *buf,
    enum sshkey_serialize_rep opts)
{
	целое r = SSH_ERR_INTERNAL_ERROR;
	целое was_shielded = sshkey_is_shielded(key);
	struct sshbuf *b = NULL;
	const struct sshkey_impl *impl;

	если ((impl = sshkey_impl_from_key(key)) == NULL)
		вернуть SSH_ERR_INTERNAL_ERROR;
	если ((r = sshkey_unshield_private(key)) != 0)
		вернуть r;
	если ((b = sshbuf_new()) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;
	если ((r = sshbuf_put_cstring(b, sshkey_ssh_name(key))) != 0)
		goto out;
	если (sshkey_is_cert(key)) {
		если (key->cert == NULL ||
		    sshbuf_len(key->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		если ((r = sshbuf_put_stringb(b, key->cert->certblob)) != 0)
			goto out;
	}
	если ((r = impl->funcs->serialize_private(key, b, opts)) != 0)
		goto out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	если (was_shielded)
		r = sshkey_shield_private(key);
	если (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	вернуть r;
}

целое
sshkey_private_serialize(struct sshkey *key, struct sshbuf *b)
{
	вернуть sshkey_private_serialize_opt(key, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
целое
sshkey_private_deserialize_sk(struct sshbuf *buf, struct sshkey *k)
{
	целое r;

	если ((k->sk_key_handle = sshbuf_new()) == NULL ||
	    (k->sk_reserved = sshbuf_new()) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;
	если ((r = sshbuf_get_cstring(buf, &k->sk_application, NULL)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_key_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		вернуть r;

	вернуть 0;
}

целое
sshkey_private_deserialize(struct sshbuf *buf, struct sshkey **kp)
{
	const struct sshkey_impl *impl;
	char *tname = NULL;
	char *expect_sk_application = NULL;
	u_char *expect_ed25519_pk = NULL;
	struct sshkey *k = NULL;
	целое type, r = SSH_ERR_INTERNAL_ERROR;

	если (kp != NULL)
		*kp = NULL;
	если ((r = sshbuf_get_cstring(buf, &tname, NULL)) != 0)
		goto out;
	type = sshkey_type_from_name(tname);
	если (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		если ((r = sshkey_froms(buf, &k)) != 0)
			goto out;
		если (k->type != type) {
			r = SSH_ERR_KEY_CERT_MISMATCH;
			goto out;
		}
		/* For ECDSA keys, the group must match too */
		если (k->type == KEY_ECDSA &&
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
	} иначе {
		если ((k = sshkey_new(type)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
	}
	если ((impl = sshkey_impl_from_type(type)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	если ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		goto out;

	если ((expect_sk_application != NULL && (k->sk_application == NULL ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != NULL && (k->ed25519_pk == NULL ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_KEY_CERT_MISMATCH;
		goto out;
	}
	/* success */
	r = 0;
	если (kp != NULL) {
		*kp = k;
		k = NULL;
	}
 out:
	free(tname);
	sshkey_free(k);
	free(expect_sk_application);
	free(expect_ed25519_pk);
	вернуть r;
}

#ifdef WITH_OPENSSL
целое
sshkey_ec_validate_public(const EC_GROUP *group, const EC_POINT *public)
{
	EC_POINT *nq = NULL;
	BIGNUM *order = NULL, *cofactor = NULL;
	целое ret = SSH_ERR_KEY_INVALID_EC_VALUE;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	если (EC_POINT_is_at_infinity(group, public))
		goto out;

	если ((cofactor = BN_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	если (EC_GROUP_get_cofactor(group, cofactor, NULL) != 1)
		goto out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	если (!BN_is_one(cofactor)) {
		если ((order = BN_new()) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		если (EC_GROUP_get_order(group, order, NULL) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		если ((nq = EC_POINT_new(group)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		если (EC_POINT_mul(group, nq, NULL, public, order, NULL) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		если (EC_POINT_is_at_infinity(group, nq) != 1)
			goto out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	вернуть ret;
}

целое
sshkey_ec_validate_private(const EC_KEY *key)
{
	BIGNUM *order = NULL, *tmp = NULL;
	целое ret = SSH_ERR_KEY_INVALID_EC_VALUE;

	если ((order = BN_new()) == NULL || (tmp = BN_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* log2(private) > log2(order)/2 */
	если (EC_GROUP_get_order(EC_KEY_get0_group(key), order, NULL) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	если (BN_num_bits(EC_KEY_get0_private_key(key)) <=
	    BN_num_bits(order) / 2)
		goto out;

	/* private < order - 1 */
	если (!BN_sub(tmp, order, BN_value_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	если (BN_cmp(EC_KEY_get0_private_key(key), tmp) >= 0)
		goto out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	вернуть ret;
}

void
sshkey_dump_ec_point(const EC_GROUP *group, const EC_POINT *point)
{
	BIGNUM *x = NULL, *y = NULL;

	если (point == NULL) {
		fputs("point=(NULL)\n", stderr);
		вернуть;
	}
	если ((x = BN_new()) == NULL || (y = BN_new()) == NULL) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		goto out;
	}
	если (EC_POINT_get_affine_coordinates(group, point, x, y, NULL) != 1) {
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
	если ((exponent = EC_KEY_get0_private_key(key)) == NULL)
		fputs("(NULL)", stderr);
	иначе
		BN_print_fp(stderr, EC_KEY_get0_private_key(key));
	fputs("\n", stderr);
}
#endif /* WITH_OPENSSL */

static целое
sshkey_private_to_blob2(struct sshkey *prv, struct sshbuf *blob,
    const char *passphrase, const char *comment, const char *ciphername,
    целое rounds)
{
	u_char *cp, *key = NULL, *pubkeyblob = NULL;
	u_char salt[SALT_LEN];
	size_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	целое r = SSH_ERR_INTERNAL_ERROR;
	struct sshcipher_ctx *ciphercontext = NULL;
	const struct sshcipher *cipher;
	const char *kdfname = KDFNAME;
	struct sshbuf *encoded = NULL, *encrypted = NULL, *kdf = NULL;

	если (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	если (rounds > MAX_KDF_ROUNDS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	если (passphrase == NULL || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} иначе если (ciphername == NULL)
		ciphername = DEFAULT_CIPHERNAME;
	если ((cipher = cipher_by_name(ciphername)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	если ((kdf = sshbuf_new()) == NULL ||
	    (encoded = sshbuf_new()) == NULL ||
	    (encrypted = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	если ((key = calloc(1, keylen + ivlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	если (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		если (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, key, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		если ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			goto out;
	} иначе если (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	если ((r = cipher_init(&ciphercontext, cipher, key, keylen,
	    key + keylen, ivlen, 1)) != 0)
		goto out;

	если ((r = sshbuf_put(encoded, AUTH_MAGIC, sizeof(AUTH_MAGIC))) != 0 ||
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
	если ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		goto out;

	/* append private key and comment*/
	если ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		goto out;

	/* padding */
	i = 0;
	пока (sshbuf_len(encrypted) % blocksize) {
		если ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			goto out;
	}

	/* length in destination buffer */
	если ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		goto out;

	/* encrypt */
	если ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		goto out;
	если ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		goto out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	если ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
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
	если (key != NULL)
		freezero(key, keylen + ivlen);
	если (pubkeyblob != NULL)
		freezero(pubkeyblob, pubkeylen);
	вернуть r;
}

static целое
private2_uudecode(struct sshbuf *blob, struct sshbuf **decodedp)
{
	const u_char *cp;
	size_t encoded_len;
	целое r;
	u_char last;
	struct sshbuf *encoded = NULL, *decoded = NULL;

	если (blob == NULL || decodedp == NULL)
		вернуть SSH_ERR_INVALID_ARGUMENT;

	*decodedp = NULL;

	если ((encoded = sshbuf_new()) == NULL ||
	    (decoded = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	если (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	пока (encoded_len > 0) {
		если (*cp != '\n' && *cp != '\r') {
			если ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				goto out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		если (last == '\n') {
			если (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				если ((r = sshbuf_put_u8(encoded, 0)) != 0)
					goto out;
				break;
			}
		}
	}
	если (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* decode base64 */
	если ((r = sshbuf_b64tod(decoded, (char *)sshbuf_ptr(encoded))) != 0)
		goto out;

	/* check magic */
	если (sshbuf_len(decoded) < sizeof(AUTH_MAGIC) ||
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
	вернуть r;
}

static целое
private2_decrypt(struct sshbuf *decoded, const char *passphrase,
    struct sshbuf **decryptedp, struct sshkey **pubkeyp)
{
	char *ciphername = NULL, *kdfname = NULL;
	const struct sshcipher *cipher = NULL;
	целое r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	struct sshbuf *kdf = NULL, *decrypted = NULL;
	struct sshcipher_ctx *ciphercontext = NULL;
	struct sshkey *pubkey = NULL;
	u_char *key = NULL, *salt = NULL, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	если (decoded == NULL || decryptedp == NULL || pubkeyp == NULL)
		вернуть SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = NULL;
	*pubkeyp = NULL;

	если ((decrypted = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* parse public portion of key */
	если ((r = sshbuf_consume(decoded, sizeof(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, NULL)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		goto out;

	если (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	если ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		goto out;

	если ((cipher = cipher_by_name(ciphername)) == NULL) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	если (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_KEY_UNKNOWN_CIPHER;
		goto out;
	}
	если (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	если ((passphrase == NULL || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	если (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	если ((key = calloc(1, keylen + ivlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	если (strcmp(kdfname, "bcrypt") == 0) {
		если ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			goto out;
		если (rounds > MAX_KDF_ROUNDS) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		если (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    key, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	если (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* decrypt private portion of key */
	если ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, key, keylen,
	    key + keylen, ivlen, 0)) != 0)
		goto out;
	если ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		если (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		goto out;
	}
	если ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		goto out;
	/* there should be no trailing data */
	если (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* check check bytes */
	если ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		goto out;
	если (check1 != check2) {
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
	если (salt != NULL) {
		explicit_bzero(salt, slen);
		free(salt);
	}
	если (key != NULL) {
		explicit_bzero(key, keylen + ivlen);
		free(key);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	вернуть r;
}

static целое
sshkey_parse_private2(struct sshbuf *blob, целое type, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	char *comment = NULL;
	целое r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *decoded = NULL, *decrypted = NULL;
	struct sshkey *k = NULL, *pubkey = NULL;

	если (keyp != NULL)
		*keyp = NULL;
	если (commentp != NULL)
		*commentp = NULL;

	/* Undo base64 encoding and decrypt the private section */
	если ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		goto out;

	если (type != KEY_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}

	/* Load the private key and comment */
	если ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, NULL)) != 0)
		goto out;

	/* Check deterministic padding after private section */
	если ((r = private2_check_padding(decrypted)) != 0)
		goto out;

	/* Check that the public key in the envelope matches the private key */
	если (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* success */
	r = 0;
	если (keyp != NULL) {
		*keyp = k;
		k = NULL;
	}
	если (commentp != NULL) {
		*commentp = comment;
		comment = NULL;
	}
 out:
	free(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	вернуть r;
}

static целое
sshkey_parse_private2_pubkey(struct sshbuf *blob, целое type,
    struct sshkey **keyp)
{
	целое r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *decoded = NULL;
	struct sshkey *pubkey = NULL;
	u_int nkeys = 0;

	если (keyp != NULL)
		*keyp = NULL;

	если ((r = private2_uudecode(blob, &decoded)) != 0)
		goto out;
	/* parse public key from unencrypted envelope */
	если ((r = sshbuf_consume(decoded, sizeof(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		goto out;

	если (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* Parse the public key */
	если ((r = sshkey_froms(decoded, &pubkey)) != 0)
		goto out;

	если (type != KEY_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}

	/* success */
	r = 0;
	если (keyp != NULL) {
		*keyp = pubkey;
		pubkey = NULL;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	вернуть r;
}

#ifdef WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
static целое
sshkey_private_to_blob_pem_pkcs8(struct sshkey *key, struct sshbuf *buf,
    целое format, const char *_passphrase, const char *comment)
{
	целое was_shielded = sshkey_is_shielded(key);
	целое success, r;
	целое blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : NULL;
	const EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : NULL;
	char *bptr;
	BIO *bio = NULL;
	struct sshbuf *blob;
	EVP_PKEY *pkey = NULL;

	если (len > 0 && len <= 4)
		вернуть SSH_ERR_PASSPHRASE_TOO_SHORT;
	если ((blob = sshbuf_new()) == NULL)
		вернуть SSH_ERR_ALLOC_FAIL;
	если ((bio = BIO_new(BIO_s_mem())) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	если ((r = sshkey_unshield_private(key)) != 0)
		goto out;

	switch (key->type) {
	case KEY_ECDSA:
		если (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivateKey(bio,
			    EVP_PKEY_get0_EC_KEY(key->pkey),
			    cipher, passphrase, len, NULL, NULL);
		} иначе {
			pkey = key->pkey;
			EVP_PKEY_up_ref(key->pkey);
			success = 1;
		}
		break;
	case KEY_RSA:
		если (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivateKey(bio,
			    EVP_PKEY_get0_RSA(key->pkey),
			    cipher, passphrase, len, NULL, NULL);
		} иначе {
			pkey = key->pkey;
			EVP_PKEY_up_ref(key->pkey);
			success = 1;
		}
		break;
#ifdef OPENSSL_HAS_ED25519
	case KEY_ED25519:
		если (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		} иначе {
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
	если (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	если (format == SSHKEY_PRIVATE_PKCS8) {
		если ((success = PEM_write_bio_PrivateKey(bio, pkey, cipher,
		    passphrase, len, NULL, NULL)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}
	если ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	если ((r = sshbuf_put(blob, bptr, blen)) != 0)
		goto out;
	r = 0;
 out:
	если (was_shielded)
		r = sshkey_shield_private(key);
	если (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	вернуть r;
}
#endif /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
целое
sshkey_private_to_fileblob(struct sshkey *key, struct sshbuf *blob,
    const char *passphrase, const char *comment,
    целое format, const char *openssh_format_cipher, целое openssh_format_rounds)
{
	switch (key->type) {
#ifdef WITH_OPENSSL
	case KEY_ECDSA:
	case KEY_RSA:
	case KEY_ED25519:
		break; /* see below */
#иначе /* WITH_OPENSSL */
	case KEY_ED25519:
#endif /* WITH_OPENSSL */
	case KEY_ED25519_SK:
#ifdef WITH_OPENSSL
	case KEY_ECDSA_SK:
#endif /* WITH_OPENSSL */
	case KEY_MLDSA44_ED25519:
		вернуть sshkey_private_to_blob2(key, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	default:
		вернуть SSH_ERR_KEY_TYPE_UNKNOWN;
	}

#ifdef WITH_OPENSSL
	switch (format) {
	case SSHKEY_PRIVATE_OPENSSH:
		вернуть sshkey_private_to_blob2(key, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	case SSHKEY_PRIVATE_PEM:
	case SSHKEY_PRIVATE_PKCS8:
		вернуть sshkey_private_to_blob_pem_pkcs8(key, blob,
		    format, passphrase, comment);
	default:
		вернуть SSH_ERR_INVALID_ARGUMENT;
	}
#endif /* WITH_OPENSSL */
}

#ifdef WITH_OPENSSL
static целое
translate_libcrypto_error(unsigned long pem_err)
{
	целое pem_reason = ERR_GET_REASON(pem_err);

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
			вернуть SSH_ERR_KEY_WRONG_PASSPHRASE;
		default:
			вернуть SSH_ERR_INVALID_FORMAT;
		}
	case ERR_LIB_EVP:
		switch (pem_reason) {
#ifdef EVP_R_BAD_DECRYPT
		case EVP_R_BAD_DECRYPT:
			вернуть SSH_ERR_KEY_WRONG_PASSPHRASE;
#endif
#ifdef EVP_R_BN_DECODE_ERROR
		case EVP_R_BN_DECODE_ERROR:
#endif
		case EVP_R_DECODE_ERROR:
#ifdef EVP_R_PRIVATE_KEY_DECODE_ERROR
		case EVP_R_PRIVATE_KEY_DECODE_ERROR:
#endif
			вернуть SSH_ERR_INVALID_FORMAT;
		default:
			вернуть SSH_ERR_LIBCRYPTO_ERROR;
		}
	case ERR_LIB_ASN1:
#ifdef ERR_LIB_OSSL_DECODER
	case ERR_LIB_OSSL_DECODER:
#endif
		вернуть SSH_ERR_INVALID_FORMAT;
	}
	вернуть SSH_ERR_LIBCRYPTO_ERROR;
}

static void
clear_libcrypto_errors(void)
{
	пока (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
static целое
convert_libcrypto_error(void)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	если (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_KEY_WRONG_PASSPHRASE)
		вернуть SSH_ERR_KEY_WRONG_PASSPHRASE;
	вернуть translate_libcrypto_error(ERR_peek_last_error());
}

static целое
pem_passphrase_cb(char *buf, целое size, целое rwflag, void *u)
{
	char *p = (char *)u;
	size_t len;

	если (p == NULL || (len = strlen(p)) == 0)
		вернуть -1;
	если (size < 0 || len > (size_t)size)
		вернуть -1;
	memcpy(buf, p, len);
	вернуть (целое)len;
}

static целое
sshkey_parse_private_pem_fileblob(struct sshbuf *blob, целое type,
    const char *passphrase, struct sshkey **keyp)
{
	EVP_PKEY *pk = NULL;
	struct sshkey *prv = NULL;
	BIO *bio = NULL;
	целое r;
	RSA *rsa = NULL;
	EC_KEY *ecdsa = NULL;

	если (keyp != NULL)
		*keyp = NULL;

	если ((bio = BIO_new(BIO_s_mem())) == NULL || sshbuf_len(blob) > INT_MAX)
		вернуть SSH_ERR_ALLOC_FAIL;
	если (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (целое)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	clear_libcrypto_errors();
	если ((pk = PEM_read_bio_PrivateKey(bio, NULL, pem_passphrase_cb,
	    (char *)passphrase)) == NULL) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		если (passphrase != NULL && *passphrase != '\0')
			r = SSH_ERR_KEY_WRONG_PASSPHRASE;
		иначе
			r = convert_libcrypto_error();
		goto out;
	}
	если (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == KEY_UNSPEC || type == KEY_RSA)) {
		если ((prv = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		если ((rsa = EVP_PKEY_get1_RSA(pk)) == NULL) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		prv->type = KEY_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#endif
		если (RSA_blinding_on(rsa, NULL) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		если ((r = sshkey_check_rsa_length(prv, 0)) != 0)
			goto out;
	} иначе если (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == KEY_UNSPEC || type == KEY_ECDSA)) {
		если ((prv = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		если ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_KEY(pk)) == NULL) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		prv->type = KEY_ECDSA;
		если (sshkey_curve_nid_to_name(prv->ecdsa_nid) == NULL ||
		    sshkey_ec_validate_public(EC_KEY_get0_group(ecdsa),
		    EC_KEY_get0_public_key(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#ifdef DEBUG_PK
		если (prv != NULL && prv->pkey != NULL)
			sshkey_dump_ec_key(EVP_PKEY_get0_EC_KEY(prv->pkey));
#endif
#ifdef OPENSSL_HAS_ED25519
	} иначе если (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == KEY_UNSPEC || type == KEY_ED25519)) {
		size_t len;

		если ((prv = sshkey_new(KEY_UNSPEC)) == NULL ||
		    (prv->ed25519_sk = calloc(1, ED25519_SK_SZ)) == NULL ||
		    (prv->ed25519_pk = calloc(1, ED25519_PK_SZ)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		prv->type = KEY_ED25519;
		len = ED25519_PK_SZ;
		если (!EVP_PKEY_get_raw_public_key(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		если (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		если (!EVP_PKEY_get_raw_private_key(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		если (len != ED25519_SK_SZ - ED25519_PK_SZ) {
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
	} иначе {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	r = 0;
	если (keyp != NULL) {
		*keyp = prv;
		prv = NULL;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_KEY_free(ecdsa);
	sshkey_free(prv);
	вернуть r;
}
#endif /* WITH_OPENSSL */

целое
sshkey_parse_private_fileblob_type(struct sshbuf *blob, целое type,
    const char *passphrase, struct sshkey **keyp, char **commentp)
{
	целое r = SSH_ERR_INTERNAL_ERROR;

	если (keyp != NULL)
		*keyp = NULL;
	если (commentp != NULL)
		*commentp = NULL;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	если (r != SSH_ERR_INVALID_FORMAT)
		вернуть r;
#ifdef WITH_OPENSSL
	вернуть sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#иначе
	вернуть SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

целое
sshkey_parse_private_fileblob(struct sshbuf *buffer, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	если (keyp != NULL)
		*keyp = NULL;
	если (commentp != NULL)
		*commentp = NULL;

	вернуть sshkey_parse_private_fileblob_type(buffer, KEY_UNSPEC,
	    passphrase, keyp, commentp);
}

void
sshkey_sig_details_free(struct sshkey_sig_details *details)
{
	freezero(details, sizeof(*details));
}

целое
sshkey_parse_pubkey_from_private_fileblob_type(struct sshbuf *blob, целое type,
    struct sshkey **pubkeyp)
{
	целое r = SSH_ERR_INTERNAL_ERROR;

	если (pubkeyp != NULL)
		*pubkeyp = NULL;
	/* only new-format private keys bundle a public key inside */
	если ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		вернуть r;
	вернуть 0;
}
