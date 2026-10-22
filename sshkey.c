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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/mman.h>
#அந்தர்பாவ <netinet/in.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/evp.h>
#அந்தர்பாவ <openssl/err.h>
#அந்தர்பாவ <openssl/pem.h>
#endif

#அந்தர்பாவ "crypto_api.h"

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <resolv.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <util.h>

#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "digest.h"
#define SSHKEY_INTERNAL
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "ssh-sk.h"
#அந்தர்பாவ "ssh-pkcs11.h"

#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#define MARK_BEGIN_LEN		(அளவு(MARK_BEGIN) - 1)
#define MARK_END_LEN		(அளவு(MARK_END) - 1)
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

நிலையான முழு sshkey_from_blob_internal(கட்டமைப்பு sshbuf *buf,
    கட்டமைப்பு sshkey **keyp, முழு allow_cert,
    மாறிலி எழுத்து *alg_allowlist, மாறிலி எழுத்து *ca_sigalg_allowlist);

/* Supported key types */
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_ed25519_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_ed25519_cert_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_ed25519_sk_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_mldsa44_ed25519_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#ifdef WITH_OPENSSL
# ifdef ENABLE_SK
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_sk_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_sk_cert_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_nistp256_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_nistp384_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_nistp521_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_rsa_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_rsa_cert_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_rsa_sha256_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_rsa_sha256_cert_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_rsa_sha512_impl;
வெளி மாறிலி கட்டமைப்பு sshkey_impl sshkey_rsa_sha512_cert_impl;
#endif /* WITH_OPENSSL */

மாறிலி கட்டமைப்பு sshkey_impl * மாறிலி keyimpls[] = {
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
	வெற்று
};

நிலையான மாறிலி கட்டமைப்பு sshkey_impl *
sshkey_impl_from_type(முழு type)
{
	முழு i;

	க்கு (i = 0; keyimpls[i] != வெற்று; i++) {
		எனில் (keyimpls[i]->type == type)
			திரும்பு keyimpls[i];
	}
	திரும்பு வெற்று;
}

நிலையான மாறிலி கட்டமைப்பு sshkey_impl *
sshkey_impl_from_type_nid(முழு type, முழு nid)
{
	முழு i;

	க்கு (i = 0; keyimpls[i] != வெற்று; i++) {
		எனில் (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			திரும்பு keyimpls[i];
	}
	திரும்பு வெற்று;
}

நிலையான மாறிலி கட்டமைப்பு sshkey_impl *
sshkey_impl_from_சாவி(மாறிலி கட்டமைப்பு sshkey *k)
{
	எனில் (k == வெற்று)
		திரும்பு வெற்று;
	திரும்பு sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

மாறிலி எழுத்து *
sshkey_type(மாறிலி கட்டமைப்பு sshkey *k)
{
	மாறிலி கட்டமைப்பு sshkey_impl *impl;

	எனில் ((impl = sshkey_impl_from_சாவி(k)) == வெற்று)
		திரும்பு "unknown";
	திரும்பு impl->shortname;
}

நிலையான மாறிலி எழுத்து *
sshkey_ssh_name_from_type_nid(முழு type, முழு nid)
{
	மாறிலி கட்டமைப்பு sshkey_impl *impl;

	எனில் ((impl = sshkey_impl_from_type_nid(type, nid)) == வெற்று)
		திரும்பு "ssh-unknown";
	திரும்பு impl->name;
}

முழு
sshkey_type_is_cert(முழு type)
{
	மாறிலி கட்டமைப்பு sshkey_impl *impl;

	எனில் ((impl = sshkey_impl_from_type(type)) == வெற்று)
		திரும்பு 0;
	திரும்பு impl->cert;
}

மாறிலி எழுத்து *
sshkey_ssh_name(மாறிலி கட்டமைப்பு sshkey *k)
{
	திரும்பு sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

மாறிலி எழுத்து *
sshkey_ssh_name_plain(மாறிலி கட்டமைப்பு sshkey *k)
{
	திரும்பு sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

நிலையான முழு
type_from_name(மாறிலி எழுத்து *name, முழு allow_short)
{
	முழு i;
	மாறிலி கட்டமைப்பு sshkey_impl *impl;

	க்கு (i = 0; keyimpls[i] != வெற்று; i++) {
		impl = keyimpls[i];
		எனில் (impl->name != வெற்று && strcmp(name, impl->name) == 0)
			திரும்பு impl->type;
		/* Only allow shortname matches for plain key types */
		எனில் (allow_short && !impl->cert && impl->shortname != வெற்று &&
		    strcasecmp(impl->shortname, name) == 0)
			திரும்பு impl->type;
	}
	திரும்பு சாவி_UNSPEC;
}

முழு
sshkey_type_from_name(மாறிலி எழுத்து *name)
{
	திரும்பு type_from_name(name, 0);
}

முழு
sshkey_type_from_shortname(மாறிலி எழுத்து *name)
{
	திரும்பு type_from_name(name, 1);
}

நிலையான முழு
சாவி_type_is_ecdsa_variant(முழு type)
{
	தேர்வு (type) {
	நிலை சாவி_ECDSA:
	நிலை சாவி_ECDSA_CERT:
	நிலை சாவி_ECDSA_SK:
	நிலை சாவி_ECDSA_SK_CERT:
		திரும்பு 1;
	}
	திரும்பு 0;
}

முழு
sshkey_ecdsa_nid_from_name(மாறிலி எழுத்து *name)
{
	முழு i;

	க்கு (i = 0; keyimpls[i] != வெற்று; i++) {
		எனில் (!சாவி_type_is_ecdsa_variant(keyimpls[i]->type))
			தொடர்;
		எனில் (keyimpls[i]->name != வெற்று &&
		    strcmp(name, keyimpls[i]->name) == 0)
			திரும்பு keyimpls[i]->nid;
	}
	திரும்பு -1;
}

முழு
sshkey_match_keyname_to_sigalgs(மாறிலி எழுத்து *keyname, மாறிலி எழுத்து *sigalgs)
{
	முழு ktype;

	எனில் (sigalgs == வெற்று || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == சாவி_UNSPEC)
		திரும்பு 0;
	இல்லையெனில் எனில் (ktype == சாவி_RSA) {
		திரும்பு match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} இல்லையெனில் எனில் (ktype == சாவி_RSA_CERT) {
		திரும்பு match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} இல்லையெனில் எனில் (ktype == சாவி_ECDSA_SK) {
		திரும்பு match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} இல்லையெனில் எனில் (ktype == சாவி_ECDSA_SK_CERT) {
		திரும்பு match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} இல்லையெனில்
		திரும்பு match_pattern_list(keyname, sigalgs, 0) == 1;
}

எழுத்து *
sshkey_alg_list(முழு certs_only, முழு plain_only, முழு include_sigonly, எழுத்து sep)
{
	எழுத்து *ret = வெற்று;
	size_t i;
	மாறிலி கட்டமைப்பு sshkey_impl *impl;
	எழுத்து sep_str[2] = {sep, '\0'};

	க்கு (i = 0; keyimpls[i] != வெற்று; i++) {
		impl = keyimpls[i];
		எனில் (impl->name == வெற்று)
			தொடர்;
		எனில் (!include_sigonly && impl->sigonly)
			தொடர்;
		எனில் ((certs_only && !impl->cert) || (plain_only && impl->cert))
			தொடர்;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	திரும்பு ret;
}

முழு
sshkey_names_valid2(மாறிலி எழுத்து *names, முழு allow_wildcard, முழு plain_only)
{
	எழுத்து *s, *cp, *p;
	மாறிலி கட்டமைப்பு sshkey_impl *impl;
	முழு i, type;

	எனில் (names == வெற்று || strcmp(names, "") == 0)
		திரும்பு 0;
	எனில் ((s = cp = strdup(names)) == வெற்று)
		திரும்பு 0;
	க்கு ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		எனில் (type == சாவி_UNSPEC) {
			எனில் (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = வெற்று;
				க்கு (i = 0; keyimpls[i] != வெற்று; i++) {
					எனில் (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						நிறுத்து;
					}
				}
				எனில் (impl != வெற்று)
					தொடர்;
			}
			விடுவி(s);
			திரும்பு 0;
		} இல்லையெனில் எனில் (plain_only && sshkey_type_is_cert(type)) {
			விடுவி(s);
			திரும்பு 0;
		}
	}
	விடுவி(s);
	திரும்பு 1;
}

u_int
sshkey_size(மாறிலி கட்டமைப்பு sshkey *k)
{
	மாறிலி கட்டமைப்பு sshkey_impl *impl;

	எனில் ((impl = sshkey_impl_from_சாவி(k)) == வெற்று)
		திரும்பு 0;
	எனில் (impl->funcs->size != வெற்று)
		திரும்பு impl->funcs->size(k);
	திரும்பு impl->keybits;
}

நிலையான முழு
sshkey_type_is_valid_ca(முழு type)
{
	மாறிலி கட்டமைப்பு sshkey_impl *impl;

	எனில் ((impl = sshkey_impl_from_type(type)) == வெற்று)
		திரும்பு 0;
	/* All non-certificate types may act as CAs */
	திரும்பு !impl->cert;
}

முழு
sshkey_is_cert(மாறிலி கட்டமைப்பு sshkey *k)
{
	எனில் (k == வெற்று)
		திரும்பு 0;
	திரும்பு sshkey_type_is_cert(k->type);
}

முழு
sshkey_is_sk(மாறிலி கட்டமைப்பு sshkey *k)
{
	எனில் (k == வெற்று)
		திரும்பு 0;
	தேர்வு (sshkey_type_plain(k->type)) {
	நிலை சாவி_ECDSA_SK:
	நிலை சாவி_ED25519_SK:
		திரும்பு 1;
	இயல்பு:
		திரும்பு 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
முழு
sshkey_type_plain(முழு type)
{
	தேர்வு (type) {
	நிலை சாவி_RSA_CERT:
		திரும்பு சாவி_RSA;
	நிலை சாவி_ECDSA_CERT:
		திரும்பு சாவி_ECDSA;
	நிலை சாவி_ECDSA_SK_CERT:
		திரும்பு சாவி_ECDSA_SK;
	நிலை சாவி_ED25519_CERT:
		திரும்பு சாவி_ED25519;
	நிலை சாவி_MLDSA44_ED25519_CERT:
		திரும்பு சாவி_MLDSA44_ED25519;
	நிலை சாவி_ED25519_SK_CERT:
		திரும்பு சாவி_ED25519_SK;
	இயல்பு:
		திரும்பு type;
	}
}

/* Return the cert equivalent to a plain key type */
நிலையான முழு
sshkey_type_certified(முழு type)
{
	தேர்வு (type) {
	நிலை சாவி_RSA:
		திரும்பு சாவி_RSA_CERT;
	நிலை சாவி_ECDSA:
		திரும்பு சாவி_ECDSA_CERT;
	நிலை சாவி_ECDSA_SK:
		திரும்பு சாவி_ECDSA_SK_CERT;
	நிலை சாவி_ED25519:
		திரும்பு சாவி_ED25519_CERT;
	நிலை சாவி_MLDSA44_ED25519:
		திரும்பு சாவி_MLDSA44_ED25519_CERT;
	நிலை சாவி_ED25519_SK:
		திரும்பு சாவி_ED25519_SK_CERT;
	இயல்பு:
		திரும்பு -1;
	}
}

#ifdef WITH_OPENSSL
நிலையான மாறிலி EVP_MD *
ssh_digest_to_md(முழு hash_alg)
{
	தேர்வு (hash_alg) {
	நிலை SSH_DIGEST_SHA1:
		திரும்பு EVP_sha1();
	நிலை SSH_DIGEST_SHA256:
		திரும்பு EVP_sha256();
	நிலை SSH_DIGEST_SHA384:
		திரும்பு EVP_sha384();
	நிலை SSH_DIGEST_SHA512:
		திரும்பு EVP_sha512();
	}
	திரும்பு வெற்று;
}

முழு
sshkey_pkey_digest_sign(EVP_PKEY *pkey, முழு hash_alg, u_char **sigp,
    size_t *lenp, மாறிலி u_char *data, size_t datalen)
{
	EVP_MD_CTX *ctx = வெற்று;
	u_char *sig = வெற்று;
	முழு ret;
	size_t slen;
	மாறிலி EVP_MD *evpmd;

	*sigp = வெற்று;
	*lenp = 0;

	slen = EVP_PKEY_size(pkey);
	எனில் (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	எனில் ((sig = malloc(slen)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;

	எனில் ((ctx = EVP_MD_CTX_new()) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (EVP_DigestSignInit(ctx, வெற்று, evpmd, வெற்று, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, data, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = வெற்று;
	ret = 0;

 out:
	EVP_MD_CTX_free(ctx);
	விடுவி(sig);
	திரும்பு ret;
}

முழு
sshkey_pkey_digest_verify(EVP_PKEY *pkey, முழு hash_alg, மாறிலி u_char *data,
    size_t datalen, u_char *sigbuf, size_t siglen)
{
	EVP_MD_CTX *ctx = வெற்று;
	முழு ret = SSH_ERR_INTERNAL_ERROR;
	மாறிலி EVP_MD *evpmd;

	எனில் ((evpmd = ssh_digest_to_md(hash_alg)) == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((ctx = EVP_MD_CTX_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் (EVP_DigestVerifyInit(ctx, வெற்று, evpmd, வெற்று, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	தேர்வு (EVP_DigestVerify(ctx, sigbuf, siglen, data, datalen)) {
	நிலை 1:
		ret = 0;
		நிறுத்து;
	நிலை 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		நிறுத்து;
	இயல்பு:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		நிறுத்து;
	}

 out:
	EVP_MD_CTX_free(ctx);
	திரும்பு ret;
}

/* XXX: these are really begging for a table-driven approach */
முழு
sshkey_curve_name_to_nid(மாறிலி எழுத்து *name)
{
	எனில் (strcmp(name, "nistp256") == 0)
		திரும்பு NID_X9_62_prime256v1;
	இல்லையெனில் எனில் (strcmp(name, "nistp384") == 0)
		திரும்பு NID_secp384r1;
	இல்லையெனில் எனில் (strcmp(name, "nistp521") == 0)
		திரும்பு NID_secp521r1;
	இல்லையெனில்
		திரும்பு -1;
}

u_int
sshkey_curve_nid_to_bits(முழு nid)
{
	தேர்வு (nid) {
	நிலை NID_X9_62_prime256v1:
		திரும்பு 256;
	நிலை NID_secp384r1:
		திரும்பு 384;
	நிலை NID_secp521r1:
		திரும்பு 521;
	இயல்பு:
		திரும்பு 0;
	}
}

முழு
sshkey_ecdsa_bits_to_nid(முழு bits)
{
	தேர்வு (bits) {
	நிலை 256:
		திரும்பு NID_X9_62_prime256v1;
	நிலை 384:
		திரும்பு NID_secp384r1;
	நிலை 521:
		திரும்பு NID_secp521r1;
	இயல்பு:
		திரும்பு -1;
	}
}

மாறிலி எழுத்து *
sshkey_curve_nid_to_name(முழு nid)
{
	தேர்வு (nid) {
	நிலை NID_X9_62_prime256v1:
		திரும்பு "nistp256";
	நிலை NID_secp384r1:
		திரும்பு "nistp384";
	நிலை NID_secp521r1:
		திரும்பு "nistp521";
	இயல்பு:
		திரும்பு வெற்று;
	}
}

முழு
sshkey_ec_nid_to_hash_alg(முழு nid)
{
	முழு kbits = sshkey_curve_nid_to_bits(nid);

	எனில் (kbits <= 0)
		திரும்பு -1;

	/* RFC5656 section 6.2.1 */
	எனில் (kbits <= 256)
		திரும்பு SSH_DIGEST_SHA256;
	இல்லையெனில் எனில் (kbits <= 384)
		திரும்பு SSH_DIGEST_SHA384;
	இல்லையெனில்
		திரும்பு SSH_DIGEST_SHA512;
}
#endif /* WITH_OPENSSL */

நிலையான வெறுமை
cert_free(கட்டமைப்பு sshkey_cert *cert)
{
	u_int i;

	எனில் (cert == வெற்று)
		திரும்பு;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	விடுவி(cert->சாவி_id);
	க்கு (i = 0; i < cert->nprincipals; i++)
		விடுவி(cert->principals[i]);
	விடுவி(cert->principals);
	sshkey_free(cert->signature_சாவி);
	விடுவி(cert->signature_type);
	freezero(cert, அளவு(*cert));
}

நிலையான கட்டமைப்பு sshkey_cert *
cert_new(வெறுமை)
{
	கட்டமைப்பு sshkey_cert *cert;

	எனில் ((cert = calloc(1, அளவு(*cert))) == வெற்று)
		திரும்பு வெற்று;
	எனில் ((cert->certblob = sshbuf_new()) == வெற்று ||
	    (cert->critical = sshbuf_new()) == வெற்று ||
	    (cert->extensions = sshbuf_new()) == வெற்று) {
		cert_free(cert);
		திரும்பு வெற்று;
	}
	cert->சாவி_id = வெற்று;
	cert->principals = வெற்று;
	cert->signature_சாவி = வெற்று;
	cert->signature_type = வெற்று;
	திரும்பு cert;
}

கட்டமைப்பு sshkey *
sshkey_new(முழு type)
{
	கட்டமைப்பு sshkey *k;
	மாறிலி கட்டமைப்பு sshkey_impl *impl = வெற்று;

	எனில் (type != சாவி_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == வெற்று)
		திரும்பு வெற்று;

	/* All non-certificate types may act as CAs */
	எனில் ((k = calloc(1, அளவு(*k))) == வெற்று)
		திரும்பு வெற்று;
	k->type = type;
	k->ecdsa_nid = -1;
	எனில் (impl != வெற்று && impl->funcs->alloc != வெற்று) {
		எனில் (impl->funcs->alloc(k) != 0) {
			விடுவி(k);
			திரும்பு வெற்று;
		}
	}
	எனில் (sshkey_is_cert(k)) {
		எனில் ((k->cert = cert_new()) == வெற்று) {
			sshkey_free(k);
			திரும்பு வெற்று;
		}
	}

	திரும்பு k;
}

/* Frees common FIDO fields */
வெறுமை
sshkey_sk_cleanup(கட்டமைப்பு sshkey *k)
{
	விடுவி(k->sk_application);
	sshbuf_free(k->sk_சாவி_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = வெற்று;
	k->sk_சாவி_handle = k->sk_reserved = வெற்று;
}

#எனில் defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#அல்லதெனில் defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#இல்லையெனில்
# define PREKEY_MMAP_FLAG	0
#endif

நிலையான முழு
sshkey_prekey_alloc(u_char **prekeyp, size_t len)
{
#எனில் defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = வெற்று;
	எனில் ((prekey = mmap(வெற்று, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		திரும்பு SSH_ERR_SYSTEM_ERROR;
#எனில் defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(வெறுமை)madvise(prekey, len, MADV_DONTDUMP);
#endif
	*prekeyp = prekey;
#இல்லையெனில்
	*prekeyp = calloc(1, len);
#endif /* HAVE_MMAP et al */
	திரும்பு 0;
}

நிலையான வெறுமை
sshkey_prekey_free(வெறுமை *prekey, size_t len)
{
#எனில் defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	எனில் (prekey == வெற்று)
		திரும்பு;
	munmap(prekey, len);
#இல்லையெனில்
	விடுவி(prekey);
#endif /* HAVE_MMAP et al */
}

நிலையான வெறுமை
sshkey_free_contents(கட்டமைப்பு sshkey *k)
{
	மாறிலி கட்டமைப்பு sshkey_impl *impl;

	எனில் (k == வெற்று)
		திரும்பு;
	எனில் ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_சாவி_free(k);
	எனில் ((impl = sshkey_impl_from_type(k->type)) != வெற்று &&
	    impl->funcs->cleanup != வெற்று)
		impl->funcs->cleanup(k);
	எனில் (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_private, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

வெறுமை
sshkey_free(கட்டமைப்பு sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, அளவு(*k));
}

நிலையான முழு
cert_compare(கட்டமைப்பு sshkey_cert *a, கட்டமைப்பு sshkey_cert *b)
{
	எனில் (a == வெற்று && b == வெற்று)
		திரும்பு 1;
	எனில் (a == வெற்று || b == வெற்று)
		திரும்பு 0;
	எனில் (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		திரும்பு 0;
	எனில் (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		திரும்பு 0;
	திரும்பு 1;
}

/* Compares FIDO-specific pubkey fields only */
முழு
sshkey_sk_fields_equal(மாறிலி கட்டமைப்பு sshkey *a, மாறிலி கட்டமைப்பு sshkey *b)
{
	எனில் (a->sk_application == வெற்று || b->sk_application == வெற்று)
		திரும்பு 0;
	எனில் (strcmp(a->sk_application, b->sk_application) != 0)
		திரும்பு 0;
	திரும்பு 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
முழு
sshkey_equal_public(மாறிலி கட்டமைப்பு sshkey *a, மாறிலி கட்டமைப்பு sshkey *b)
{
	மாறிலி கட்டமைப்பு sshkey_impl *impl;

	எனில் (a == வெற்று || b == வெற்று ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		திரும்பு 0;
	எனில் ((impl = sshkey_impl_from_type(a->type)) == வெற்று)
		திரும்பு 0;
	திரும்பு impl->funcs->equal(a, b);
}

முழு
sshkey_equal(மாறிலி கட்டமைப்பு sshkey *a, மாறிலி கட்டமைப்பு sshkey *b)
{
	எனில் (a == வெற்று || b == வெற்று || a->type != b->type)
		திரும்பு 0;
	எனில் (sshkey_is_cert(a)) {
		எனில் (!cert_compare(a->cert, b->cert))
			திரும்பு 0;
	}
	திரும்பு sshkey_equal_public(a, b);
}


/* Serialise common FIDO key parts */
முழு
sshkey_serialize_sk(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b)
{
	முழு r;

	எனில் ((r = sshbuf_put_cstring(b, சாவி->sk_application)) != 0)
		திரும்பு r;

	திரும்பு 0;
}

நிலையான முழு
to_blob_buf(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b, முழு force_plain,
  எண்ணிக்கை sshkey_serialize_rep opts)
{
	முழு type, ret = SSH_ERR_INTERNAL_ERROR;
	மாறிலி எழுத்து *typename;
	மாறிலி கட்டமைப்பு sshkey_impl *impl;

	எனில் (சாவி == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(சாவி->type) : சாவி->type;

	எனில் (sshkey_type_is_cert(type)) {
		எனில் (சாவி->cert == வெற்று)
			திரும்பு SSH_ERR_EXPECTED_CERT;
		எனில் (sshbuf_len(சாவி->cert->certblob) == 0)
			திரும்பு SSH_ERR_சாவி_LACKS_CERTBLOB;
		/* Use the existing blob */
		எனில் ((ret = sshbuf_putb(b, சாவி->cert->certblob)) != 0)
			திரும்பு ret;
		திரும்பு 0;
	}
	எனில் ((impl = sshkey_impl_from_type(type)) == வெற்று)
		திரும்பு SSH_ERR_சாவி_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, சாவி->ecdsa_nid);
	எனில் ((ret = sshbuf_put_cstring(b, typename)) != 0)
		திரும்பு ret;
	திரும்பு impl->funcs->serialize_public(சாவி, b, opts);
}

முழு
sshkey_putb(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b)
{
	திரும்பு to_blob_buf(சாவி, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

நிலையான முழு
sshkey_puts_opts_internal(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b,
    எண்ணிக்கை sshkey_serialize_rep opts, முழு force_plain)
{
	கட்டமைப்பு sshbuf *tmp;
	முழு r;

	எனில் ((tmp = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(சாவி, tmp, force_plain, opts);
	எனில் (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	திரும்பு r;
}

முழு
sshkey_puts(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b)
{
	திரும்பு sshkey_puts_opts_internal(சாவி, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

முழு
sshkey_putb_plain(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b)
{
	திரும்பு to_blob_buf(சாவி, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

முழு
sshkey_puts_plain(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b)
{
	திரும்பு sshkey_puts_opts_internal(சாவி, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

நிலையான முழு
to_blob(மாறிலி கட்டமைப்பு sshkey *சாவி, u_char **blobp, size_t *lenp, முழு force_plain,
    எண்ணிக்கை sshkey_serialize_rep opts)
{
	முழு ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	கட்டமைப்பு sshbuf *b = வெற்று;

	எனில் (lenp != வெற்று)
		*lenp = 0;
	எனில் (blobp != வெற்று)
		*blobp = வெற்று;
	எனில் ((b = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((ret = to_blob_buf(சாவி, b, force_plain, opts)) != 0)
		செல் out;
	len = sshbuf_len(b);
	எனில் (lenp != வெற்று)
		*lenp = len;
	எனில் (blobp != வெற்று) {
		எனில் ((*blobp = malloc(len)) == வெற்று) {
			ret = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	திரும்பு ret;
}

முழு
sshkey_to_blob(மாறிலி கட்டமைப்பு sshkey *சாவி, u_char **blobp, size_t *lenp)
{
	திரும்பு to_blob(சாவி, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

முழு
sshkey_plain_to_blob(மாறிலி கட்டமைப்பு sshkey *சாவி, u_char **blobp, size_t *lenp)
{
	திரும்பு to_blob(சாவி, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

முழு
sshkey_fingerprint_raw(மாறிலி கட்டமைப்பு sshkey *k, முழு dgst_alg,
    u_char **retp, size_t *lenp)
{
	u_char *blob = வெற்று, *ret = வெற்று;
	size_t blob_len = 0;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் (retp != வெற்று)
		*retp = வெற்று;
	எனில் (lenp != வெற்று)
		*lenp = 0;
	எனில் (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	எனில் ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		செல் out;
	எனில் ((ret = calloc(1, SSH_DIGEST_MAX_LENGTH)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_LENGTH)) != 0)
		செல் out;
	/* success */
	எனில் (retp != வெற்று) {
		*retp = ret;
		ret = வெற்று;
	}
	எனில் (lenp != வெற்று)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	விடுவி(ret);
	எனில் (blob != வெற்று)
		freezero(blob, blob_len);
	திரும்பு r;
}

நிலையான எழுத்து *
fingerprint_b64(மாறிலி எழுத்து *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	எழுத்து *ret;
	size_t plen = strlen(alg) + 1;
	size_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	எனில் (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == வெற்று)
		திரும்பு வெற்று;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	எனில் (dgst_raw_len == 0)
		திரும்பு ret;
	எனில் (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		திரும்பு வெற்று;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	திரும்பு ret;
}

நிலையான எழுத்து *
fingerprint_hex(மாறிலி எழுத்து *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	எழுத்து *retval, hex[5];
	size_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	எனில் (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == வெற்று)
		திரும்பு வெற்று;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	க்கு (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, அளவு(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	திரும்பு retval;
}

நிலையான எழுத்து *
fingerprint_bubblebabble(u_char *dgst_raw, size_t dgst_raw_len)
{
	எழுத்து vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	எழுத்து consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	எழுத்து *retval;

	rounds = (dgst_raw_len / 2) + 1;
	எனில் ((retval = calloc(rounds, 6)) == வெற்று)
		திரும்பு வெற்று;
	retval[j++] = 'x';
	க்கு (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		எனில் ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			எனில் ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} இல்லையெனில் {
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
	திரும்பு retval;
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
நிலையான எழுத்து *
fingerprint_randomart(மாறிலி எழுத்து *alg, u_char *dgst_raw, size_t dgst_raw_len,
    மாறிலி கட்டமைப்பு sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	எழுத்து	*augmentation_string = " .o+=*BOX@%&#/^SE";
	எழுத்து	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	size_t	 i, tlen, hlen;
	u_int	 b;
	முழு	 x, y, r;
	size_t	 len = strlen(augmentation_string) - 1;

	எனில் ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == வெற்று)
		திரும்பு வெற்று;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * அளவு(எழுத்து));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	க்கு (i = 0; i < dgst_raw_len; i++) {
		முழு உள்ளீடு;
		/* each byte conveys four 2-bit move commands */
		உள்ளீடு = dgst_raw[i];
		க்கு (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (உள்ளீடு & 0x1) ? 1 : -1;
			y += (உள்ளீடு & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			எனில் (field[x][y] < len - 2)
				field[x][y]++;
			உள்ளீடு = உள்ளீடு >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, அளவு(title), "[%s %u]",
		sshkey_type(k), sshkey_size(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	எனில் (r < 0 || r > (முழு)அளவு(title))
		r = snprintf(title, அளவு(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, அளவு(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	க்கு (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	memcpy(p, title, tlen);
	p += tlen;
	க்கு (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	க்கு (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		க்கு (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	க்கு (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	memcpy(p, hash, hlen);
	p += hlen;
	க்கு (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	திரும்பு retval;
}

எழுத்து *
sshkey_fingerprint(மாறிலி கட்டமைப்பு sshkey *k, முழு dgst_alg,
    எண்ணிக்கை sshkey_fp_rep dgst_rep)
{
	எழுத்து *retval = வெற்று;
	u_char *dgst_raw;
	size_t dgst_raw_len;

	எனில் (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		திரும்பு வெற்று;
	தேர்வு (dgst_rep) {
	நிலை SSH_FP_DEFAULT:
		எனில் (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} இல்லையெனில் {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		நிறுத்து;
	நிலை SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		நிறுத்து;
	நிலை SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		நிறுத்து;
	நிலை SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		நிறுத்து;
	நிலை SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		நிறுத்து;
	இயல்பு:
		freezero(dgst_raw, dgst_raw_len);
		திரும்பு வெற்று;
	}
	freezero(dgst_raw, dgst_raw_len);
	திரும்பு retval;
}

நிலையான முழு
peek_type_nid(மாறிலி எழுத்து *s, size_t l, முழு *nid)
{
	மாறிலி கட்டமைப்பு sshkey_impl *impl;
	முழு i;

	க்கு (i = 0; keyimpls[i] != வெற்று; i++) {
		impl = keyimpls[i];
		எனில் (impl->name == வெற்று || strlen(impl->name) != l)
			தொடர்;
		எனில் (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			எனில் (சாவி_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			திரும்பு impl->type;
		}
	}
	திரும்பு சாவி_UNSPEC;
}

/* XXX this can now be made const char * */
முழு
sshkey_read(கட்டமைப்பு sshkey *ret, எழுத்து **cpp)
{
	கட்டமைப்பு sshkey *k;
	எழுத்து *cp, *blobcopy;
	size_t space;
	முழு r, type, curve_nid = -1;
	கட்டமைப்பு sshbuf *blob;

	எனில் (ret == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (ret->type != சாவி_UNSPEC && sshkey_impl_from_type(ret->type) == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	எனில் (space == strlen(cp))
		திரும்பு SSH_ERR_INVALID_FORMAT;
	எனில் ((type = peek_type_nid(cp, space, &curve_nid)) == சாவி_UNSPEC)
		திரும்பு SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	க்கு (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	எனில் (*cp == '\0')
		திரும்பு SSH_ERR_INVALID_FORMAT;
	எனில் (ret->type != சாவி_UNSPEC && ret->type != type)
		திரும்பு SSH_ERR_சாவி_TYPE_MISMATCH;
	எனில் ((blob = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	எனில் ((blobcopy = strndup(cp, space)) == வெற்று) {
		sshbuf_free(blob);
		திரும்பு SSH_ERR_ALLOC_FAIL;
	}
	எனில் ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		விடுவி(blobcopy);
		sshbuf_free(blob);
		திரும்பு r;
	}
	விடுவி(blobcopy);
	எனில் ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		திரும்பு r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	க்கு (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	எனில் (k->type != type) {
		sshkey_free(k);
		திரும்பு SSH_ERR_சாவி_TYPE_MISMATCH;
	}
	எனில் (சாவி_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		திரும்பு SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, அளவு(*k));

	/* success */
	*cpp = cp;
	திரும்பு 0;
}

முழு
sshkey_to_base64(மாறிலி கட்டமைப்பு sshkey *சாவி, எழுத்து **b64p)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு sshbuf *b = வெற்று;
	எழுத்து *uu = வெற்று;

	எனில் (b64p != வெற்று)
		*b64p = வெற்று;
	எனில் ((b = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshkey_putb(சாவி, b)) != 0)
		செல் out;
	எனில் ((uu = sshbuf_dtob64_string(b, 0)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	/* Success */
	எனில் (b64p != வெற்று) {
		*b64p = uu;
		uu = வெற்று;
	}
	r = 0;
 out:
	sshbuf_free(b);
	விடுவி(uu);
	திரும்பு r;
}

முழு
sshkey_format_text(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;
	எழுத்து *uu = வெற்று;

	எனில் ((r = sshkey_to_base64(சாவி, &uu)) != 0)
		செல் out;
	எனில் ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(சாவி), uu)) != 0)
		செல் out;
	r = 0;
 out:
	விடுவி(uu);
	திரும்பு r;
}

முழு
sshkey_write(மாறிலி கட்டமைப்பு sshkey *சாவி, FILE *f)
{
	கட்டமைப்பு sshbuf *b = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் ((b = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshkey_format_text(சாவி, b)) != 0)
		செல் out;
	எனில் (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		எனில் (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		செல் out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	திரும்பு r;
}

மாறிலி எழுத்து *
sshkey_cert_type(மாறிலி கட்டமைப்பு sshkey *k)
{
	தேர்வு (k->cert->type) {
	நிலை SSH2_CERT_TYPE_USER:
		திரும்பு "user";
	நிலை SSH2_CERT_TYPE_HOST:
		திரும்பு "host";
	இயல்பு:
		திரும்பு "unknown";
	}
}

முழு
sshkey_check_rsa_length(மாறிலி கட்டமைப்பு sshkey *k, முழு min_size)
{
#ifdef WITH_OPENSSL
	முழு nbits;

	எனில் (k == வெற்று || k->pkey == வெற்று ||
	    (k->type != சாவி_RSA && k->type != சாவி_RSA_CERT))
		திரும்பு 0;
	nbits = EVP_PKEY_bits(k->pkey);
	எனில் (nbits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    (min_size > 0 && nbits < min_size))
		திரும்பு SSH_ERR_சாவி_LENGTH;
#endif /* WITH_OPENSSL */
	திரும்பு 0;
}

#ifdef WITH_OPENSSL
முழு
sshkey_ecdsa_சாவி_to_nid(மாறிலி EC_சாவி *k)
{
	மாறிலி EC_GROUP *g;
	முழு nid;

	எனில் (k == வெற்று || (g = EC_சாவி_get0_group(k)) == வெற்று)
		திரும்பு -1;
	எனில் ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		திரும்பு -1;
	திரும்பு nid;
}

முழு
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	திரும்பு sshkey_ecdsa_சாவி_to_nid(EVP_PKEY_get0_EC_சாவி(pkey));
}
#endif /* WITH_OPENSSL */

முழு
sshkey_generate(முழு type, u_int bits, கட்டமைப்பு sshkey **keyp)
{
	கட்டமைப்பு sshkey *k;
	முழு ret = SSH_ERR_INTERNAL_ERROR;
	மாறிலி கட்டமைப்பு sshkey_impl *impl;

	எனில் (keyp == வெற்று || sshkey_type_is_cert(type))
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	*keyp = வெற்று;
	எனில் ((impl = sshkey_impl_from_type(type)) == வெற்று)
		திரும்பு SSH_ERR_சாவி_TYPE_UNKNOWN;
	எனில் (impl->funcs->generate == வெற்று)
		திரும்பு SSH_ERR_FEATURE_UNSUPPORTED;
	எனில் ((k = sshkey_new(சாவி_UNSPEC)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	k->type = type;
	எனில் ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		திரும்பு ret;
	}
	/* success */
	*keyp = k;
	திரும்பு 0;
}

முழு
sshkey_cert_copy(மாறிலி கட்டமைப்பு sshkey *from_சாவி, கட்டமைப்பு sshkey *to_சாவி)
{
	u_int i;
	மாறிலி கட்டமைப்பு sshkey_cert *from;
	கட்டமைப்பு sshkey_cert *to;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் (to_சாவி == வெற்று || (from = from_சாவி->cert) == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	எனில் ((to = cert_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;

	எனில் ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		செல் out;

	to->serial = from->serial;
	to->type = from->type;
	எனில் (from->சாவி_id == வெற்று)
		to->சாவி_id = வெற்று;
	இல்லையெனில் எனில் ((to->சாவி_id = strdup(from->சாவி_id)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	எனில் (from->signature_சாவி == வெற்று)
		to->signature_சாவி = வெற்று;
	இல்லையெனில் எனில் ((r = sshkey_from_private(from->signature_சாவி,
	    &to->signature_சாவி)) != 0)
		செல் out;
	எனில் (from->signature_type != வெற்று &&
	    (to->signature_type = strdup(from->signature_type)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	எனில் (from->nprincipals > 0) {
		எனில் ((to->principals = calloc(from->nprincipals,
		    அளவு(*to->principals))) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		க்கு (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			எனில் (to->principals[i] == வெற்று) {
				to->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				செல் out;
			}
		}
	}
	to->nprincipals = from->nprincipals;

	/* success */
	cert_free(to_சாவி->cert);
	to_சாவி->cert = to;
	to = வெற்று;
	r = 0;
 out:
	cert_free(to);
	திரும்பு r;
}

முழு
sshkey_copy_public_sk(மாறிலி கட்டமைப்பு sshkey *from, கட்டமைப்பு sshkey *to)
{
	/* Append security-key application string */
	எனில் ((to->sk_application = strdup(from->sk_application)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	திரும்பு 0;
}

முழு
sshkey_from_private(மாறிலி கட்டமைப்பு sshkey *k, கட்டமைப்பு sshkey **pkp)
{
	கட்டமைப்பு sshkey *n = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;
	மாறிலி கட்டமைப்பு sshkey_impl *impl;

	*pkp = வெற்று;
	எனில் ((impl = sshkey_impl_from_சாவி(k)) == வெற்று)
		திரும்பு SSH_ERR_சாவி_TYPE_UNKNOWN;
	எனில் ((n = sshkey_new(k->type)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = impl->funcs->copy_public(k, n)) != 0)
		செல் out;
	எனில் (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		செல் out;
	/* success */
	*pkp = n;
	n = வெற்று;
	r = 0;
 out:
	sshkey_free(n);
	திரும்பு r;
}

முழு
sshkey_is_shielded(கட்டமைப்பு sshkey *k)
{
	திரும்பு k != வெற்று && k->shielded_private != வெற்று;
}

முழு
sshkey_shield_private(கட்டமைப்பு sshkey *k)
{
	கட்டமைப்பு sshbuf *prvbuf = வெற்று;
	u_char *prekey = வெற்று, *enc = வெற்று, keyiv[SSH_DIGEST_MAX_LENGTH];
	கட்டமைப்பு sshcipher_ctx *cctx = வெற்று;
	மாறிலி கட்டமைப்பு sshcipher *cipher;
	size_t i, enclen = 0;
	கட்டமைப்பு sshkey *kswap = வெற்று, tmp;
	முழு r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	எனில் ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == வெற்று) {
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	எனில் (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		செல் out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	எனில் ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		செல் out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	எனில் ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		செல் out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	எனில் ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		செல் out;

	/* Serialise and encrypt the private key using the ephemeral key */
	எனில் ((prvbuf = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		செல் out;
	எனில் ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		செல் out;
	/* pad to cipher blocksize */
	i = 0;
	போது (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		எனில் ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			செல் out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	எனில் ((enc = malloc(enclen)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		செல் out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	எனில் ((r = sshkey_from_private(k, &kswap)) != 0)
		செல் out;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_private = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = வெற்று; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 out:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, அளவு(keyiv));
	explicit_bzero(&tmp, அளவு(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	திரும்பு r;
}

/* Check deterministic padding after private key */
நிலையான முழு
private2_check_padding(கட்டமைப்பு sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	முழு r;

	i = 0;
	போது (sshbuf_len(decrypted)) {
		எனில் ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			செல் out;
		எனில் (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, அளவு(pad));
	explicit_bzero(&i, அளவு(i));
	திரும்பு r;
}

முழு
sshkey_unshield_private(கட்டமைப்பு sshkey *k)
{
	கட்டமைப்பு sshbuf *prvbuf = வெற்று;
	u_char *cp, keyiv[SSH_DIGEST_MAX_LENGTH];
	கட்டமைப்பு sshcipher_ctx *cctx = வெற்று;
	மாறிலி கட்டமைப்பு sshcipher *cipher;
	கட்டமைப்பு sshkey *kswap = வெற்று, tmp;
	முழு r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	எனில் (!sshkey_is_shielded(k))
		திரும்பு 0; /* nothing to do */

	எனில் ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == வெற்று) {
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	எனில் (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		செல் out;
	}
	/* check size of shielded key blob */
	எனில் (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}

	/* Calculate the ephemeral key from the prekey */
	எனில் ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		செல் out;
	எனில் ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		செல் out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	எனில் ((prvbuf = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		செல் out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(k->shielded_private, k->shielded_len, stderr);
#endif
	எனில் ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		செல் out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	எனில் ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		செல் out;

	எனில் ((r = private2_check_padding(prvbuf)) != 0)
		செல் out;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 out:
	cipher_free(cctx);
	explicit_bzero(keyiv, அளவு(keyiv));
	explicit_bzero(&tmp, அளவு(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	திரும்பு r;
}

நிலையான முழு
cert_parse(கட்டமைப்பு sshbuf *b, கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *certbuf,
    மாறிலி எழுத்து *ca_sigalg_allowlist)
{
	கட்டமைப்பு sshbuf *principals = வெற்று, *crit = வெற்று;
	கட்டமைப்பு sshbuf *exts = வெற்று, *ca = வெற்று;
	u_char *sig = வெற்று;
	எழுத்து *sigtype = வெற்று;
	size_t signed_len = 0, slen = 0, kidlen = 0;
	முழு ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	எனில் ((ret = sshbuf_putb(சாவி->cert->certblob, certbuf)) != 0)
		திரும்பு ret;

	/* Parse body of certificate up to signature */
	எனில் ((ret = sshbuf_get_u64(b, &சாவி->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &சாவி->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &சாவி->cert->சாவி_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &சாவி->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &சாவி->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, வெற்று, வெற்று)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(சாவி->cert->certblob) - sshbuf_len(b);

	எனில் ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}

	/* Is this a signature we're prepared to accept? */
	எனில் ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (ca_sigalg_allowlist != வெற்று &&
	    match_pattern_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		செல் out;
	}

	/* Parse CA key and check whether we might accept it */
	எனில் (sshkey_from_blob_internal(ca, &சாவி->cert->signature_சாவி, 0,
	    ca_sigalg_allowlist, வெற்று) != 0) {
		ret = SSH_ERR_சாவி_CERT_INVALID_SIGN_சாவி;
		செல் out;
	}
	எனில் (!sshkey_type_is_valid_ca(சாவி->cert->signature_சாவி->type)) {
		ret = SSH_ERR_சாவி_CERT_INVALID_SIGN_சாவி;
		செல் out;
	}

	எனில் (சாவி->cert->type != SSH2_CERT_TYPE_USER &&
	    சாவி->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_சாவி_CERT_UNKNOWN_TYPE;
		செல் out;
	}

	/* Parse principals section */
	போது (sshbuf_len(principals) > 0) {
		எழுத்து *principal = வெற்று;
		எழுத்து **oprincipals = வெற்று;

		எனில் (சாவி->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		எனில் ((ret = sshbuf_get_cstring(principals, &principal,
		    வெற்று)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		oprincipals = சாவி->cert->principals;
		சாவி->cert->principals = recallocarray(சாவி->cert->principals,
		    சாவி->cert->nprincipals, சாவி->cert->nprincipals + 1,
		    அளவு(*சாவி->cert->principals));
		எனில் (சாவி->cert->principals == வெற்று) {
			விடுவி(principal);
			சாவி->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		சாவி->cert->principals[சாவி->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	எனில் ((ret = sshbuf_putb(சாவி->cert->critical, crit)) != 0 ||
	    (exts != வெற்று &&
	    (ret = sshbuf_putb(சாவி->cert->extensions, exts)) != 0))
		செல் out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	போது (sshbuf_len(crit) != 0) {
		எனில் ((ret = sshbuf_get_string_direct(crit, வெற்று, வெற்று)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, வெற்று, வெற்று)) != 0) {
			sshbuf_reset(சாவி->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
	}
	போது (exts != வெற்று && sshbuf_len(exts) != 0) {
		எனில் ((ret = sshbuf_get_string_direct(exts, வெற்று, வெற்று)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, வெற்று, வெற்று)) != 0) {
			sshbuf_reset(சாவி->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
	}

	/* Finally, validate signature */
	எனில் ((ret = sshkey_verify(சாவி->cert->signature_சாவி, sig, slen,
	    sshbuf_ptr(சாவி->cert->certblob), signed_len, வெற்று, 0, வெற்று)) != 0)
		செல் out;

	/* Success */
	ret = 0;
	சாவி->cert->signature_type = sigtype;
	sigtype = வெற்று;
 out:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	விடுவி(sig);
	விடுவி(sigtype);
	திரும்பு ret;
}

முழு
sshkey_deserialize_sk(கட்டமைப்பு sshbuf *b, கட்டமைப்பு sshkey *சாவி)
{
	/* Parse additional security-key application string */
	எனில் (sshbuf_get_cstring(b, &சாவி->sk_application, வெற்று) != 0)
		திரும்பு SSH_ERR_INVALID_FORMAT;
	திரும்பு 0;
}

நிலையான முழு
sshkey_from_blob_internal(கட்டமைப்பு sshbuf *b, கட்டமைப்பு sshkey **keyp,
    முழு allow_cert, மாறிலி எழுத்து *alg_allowlist, மாறிலி எழுத்து *ca_sigalg_allowlist)
{
	முழு type, ret = SSH_ERR_INTERNAL_ERROR;
	எழுத்து *ktype = வெற்று;
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	கட்டமைப்பு sshbuf *copy;
	மாறிலி கட்டமைப்பு sshkey_impl *impl;

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	எனில் (keyp != வெற்று)
		*keyp = வெற்று;
	எனில் ((copy = sshbuf_fromb(b)) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (sshbuf_get_cstring(b, &ktype, வெற்று) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}

	type = sshkey_type_from_name(ktype);
	எனில் (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_சாவி_CERT_INVALID_SIGN_சாவி;
		செல் out;
	}

	எனில் (alg_allowlist != வெற்று &&
	    !sshkey_match_keyname_to_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_சாவி_ALG_UNSUPPORTED;
		செல் out;
	}

	எனில் ((impl = sshkey_impl_from_type(type)) == வெற்று) {
		ret = SSH_ERR_சாவி_TYPE_UNKNOWN;
		செல் out;
	}
	எனில் ((சாவி = sshkey_new(type)) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		எனில் (sshbuf_get_string_direct(b, வெற்று, வெற்று) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
	}
	எனில் ((ret = impl->funcs->deserialize_public(ktype, b, சாவி)) != 0)
		செல் out;

	/* Parse certificate potion */
	எனில் (sshkey_is_cert(சாவி) &&
	    (ret = cert_parse(b, சாவி, copy, ca_sigalg_allowlist)) != 0)
		செல் out;

	எனில் (சாவி != வெற்று && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	ret = 0;
	எனில் (keyp != வெற்று) {
		*keyp = சாவி;
		சாவி = வெற்று;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(சாவி);
	விடுவி(ktype);
	திரும்பு ret;
}

முழு
sshkey_from_blob(மாறிலி u_char *blob, size_t blen, கட்டமைப்பு sshkey **keyp)
{
	கட்டமைப்பு sshbuf *b;
	முழு r;

	எனில் ((b = sshbuf_from(blob, blen)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1, வெற்று, வெற்று);
	sshbuf_free(b);
	திரும்பு r;
}

முழு
sshkey_fromb(கட்டமைப்பு sshbuf *b, கட்டமைப்பு sshkey **keyp)
{
	திரும்பு sshkey_from_blob_internal(b, keyp, 1, வெற்று, வெற்று);
}

முழு
sshkey_fromb_allowlist(கட்டமைப்பு sshbuf *b, கட்டமைப்பு sshkey **keyp,
    மாறிலி எழுத்து *alg_allowlist, மாறிலி எழுத்து *ca_sigalg_allowlist)
{
	திரும்பு sshkey_from_blob_internal(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

முழு
sshkey_froms(கட்டமைப்பு sshbuf *buf, கட்டமைப்பு sshkey **keyp)
{
	கட்டமைப்பு sshbuf *b;
	முழு r;

	எனில் ((r = sshbuf_froms(buf, &b)) != 0)
		திரும்பு r;
	r = sshkey_from_blob_internal(b, keyp, 1, வெற்று, வெற்று);
	sshbuf_free(b);
	திரும்பு r;
}

முழு
sshkey_get_sigtype(மாறிலி u_char *sig, size_t siglen, எழுத்து **sigtypep)
{
	முழு r;
	கட்டமைப்பு sshbuf *b = வெற்று;
	எழுத்து *sigtype = வெற்று;

	எனில் (sigtypep != வெற்று)
		*sigtypep = வெற்று;
	எனில் ((b = sshbuf_from(sig, siglen)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_get_cstring(b, &sigtype, வெற்று)) != 0)
		செல் out;
	/* success */
	எனில் (sigtypep != வெற்று) {
		*sigtypep = sigtype;
		sigtype = வெற்று;
	}
	r = 0;
 out:
	விடுவி(sigtype);
	sshbuf_free(b);
	திரும்பு r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
முழு
sshkey_check_cert_sigtype(மாறிலி கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *allowed)
{
	எனில் (சாவி == வெற்று || allowed == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (!sshkey_type_is_cert(சாவி->type))
		திரும்பு 0;
	எனில் (சாவி->cert == வெற்று || சாவி->cert->signature_type == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (match_pattern_list(சாவி->cert->signature_type, allowed, 0) != 1)
		திரும்பு SSH_ERR_SIGN_ALG_UNSUPPORTED;
	திரும்பு 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
மாறிலி எழுத்து *
sshkey_sigalg_by_name(மாறிலி எழுத்து *name)
{
	மாறிலி கட்டமைப்பு sshkey_impl *impl;
	முழு i;

	க்கு (i = 0; keyimpls[i] != வெற்று; i++) {
		impl = keyimpls[i];
		எனில் (strcmp(impl->name, name) != 0)
			தொடர்;
		எனில் (impl->sigalg != வெற்று)
			திரும்பு impl->sigalg;
		எனில் (!impl->cert)
			திரும்பு impl->name;
		திரும்பு sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	திரும்பு வெற்று;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
முழு
sshkey_check_sigtype(மாறிலி u_char *sig, size_t siglen,
    மாறிலி எழுத்து *requested_alg)
{
	மாறிலி எழுத்து *expected_alg;
	எழுத்து *sigtype = வெற்று;
	முழு r;

	எனில் (requested_alg == வெற்று)
		திரும்பு 0;
	எனில் ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		திரும்பு r;
	r = strcmp(expected_alg, sigtype) == 0;
	விடுவி(sigtype);
	திரும்பு r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

முழு
sshkey_sign(கட்டமைப்பு sshkey *சாவி,
    u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen,
    மாறிலி எழுத்து *alg, மாறிலி எழுத்து *sk_provider, மாறிலி எழுத்து *sk_pin, u_int compat)
{
	முழு was_shielded = sshkey_is_shielded(சாவி);
	முழு r2, r = SSH_ERR_INTERNAL_ERROR;
	மாறிலி கட்டமைப்பு sshkey_impl *impl;

	எனில் (sigp != வெற்று)
		*sigp = வெற்று;
	எனில் (lenp != வெற்று)
		*lenp = 0;
	எனில் (datalen > SSH_சாவி_MAX_SIGN_DATA_SIZE)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((impl = sshkey_impl_from_சாவி(சாவி)) == வெற்று)
		திரும்பு SSH_ERR_சாவி_TYPE_UNKNOWN;
	எனில் ((r = sshkey_unshield_private(சாவி)) != 0)
		திரும்பு r;
	எனில் (sshkey_is_sk(சாவி)) {
		r = sshsk_sign(sk_provider, சாவி, sigp, lenp, data,
		    datalen, compat, sk_pin);
	} இல்லையெனில் எனில் ((சாவி->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(சாவி, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	} இல்லையெனில் {
		எனில் (impl->funcs->sign == வெற்று)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		இல்லையெனில் {
			r = impl->funcs->sign(சாவி, sigp, lenp, data, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	எனில் (was_shielded && (r2 = sshkey_shield_private(சாவி)) != 0)
		திரும்பு r2;
	திரும்பு r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
முழு
sshkey_verify(மாறிலி கட்டமைப்பு sshkey *சாவி,
    மாறிலி u_char *sig, size_t siglen,
    மாறிலி u_char *data, size_t dlen, மாறிலி எழுத்து *alg, u_int compat,
    கட்டமைப்பு sshkey_sig_details **detailsp)
{
	மாறிலி கட்டமைப்பு sshkey_impl *impl;

	எனில் (detailsp != வெற்று)
		*detailsp = வெற்று;
	எனில் (siglen == 0 || dlen > SSH_சாவி_MAX_SIGN_DATA_SIZE)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((impl = sshkey_impl_from_சாவி(சாவி)) == வெற்று)
		திரும்பு SSH_ERR_சாவி_TYPE_UNKNOWN;
	திரும்பு impl->funcs->verify(சாவி, sig, siglen, data, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
முழு
sshkey_to_certified(கட்டமைப்பு sshkey *k)
{
	முழு newtype;

	எனில் ((newtype = sshkey_type_certified(k->type)) == -1)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((k->cert = cert_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	திரும்பு 0;
}

/* Convert a certificate to its raw key equivalent */
முழு
sshkey_drop_cert(கட்டமைப்பு sshkey *k)
{
	எனில் (!sshkey_type_is_cert(k->type))
		திரும்பு SSH_ERR_சாவி_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = வெற்று;
	k->type = sshkey_type_plain(k->type);
	திரும்பு 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
முழு
sshkey_certify_custom(கட்டமைப்பு sshkey *k, கட்டமைப்பு sshkey *ca, மாறிலி எழுத்து *alg,
    மாறிலி எழுத்து *sk_provider, மாறிலி எழுத்து *sk_pin,
    sshkey_certify_signer *signer, வெறுமை *signer_ctx)
{
	மாறிலி கட்டமைப்பு sshkey_impl *impl;
	கட்டமைப்பு sshbuf *principals = வெற்று;
	u_char *ca_blob = வெற்று, *sig_blob = வெற்று, nonce[32];
	size_t i, ca_len, sig_len;
	முழு ret = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு sshbuf *cert = வெற்று;
	எழுத்து *sigtype = வெற்று;

	எனில் (k == வெற்று || k->cert == வெற்று ||
	    k->cert->certblob == வெற்று || ca == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (!sshkey_is_cert(k))
		திரும்பு SSH_ERR_சாவி_TYPE_UNKNOWN;
	எனில் (!sshkey_type_is_valid_ca(ca->type))
		திரும்பு SSH_ERR_சாவி_CERT_INVALID_SIGN_சாவி;
	எனில் ((impl = sshkey_impl_from_சாவி(k)) == வெற்று)
		திரும்பு SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	எனில் (alg == வெற்று)
		alg = k->cert->signature_type;
	இல்லையெனில் எனில் (k->cert->signature_type != வெற்று &&
	    strcmp(alg, k->cert->signature_type) != 0)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	எனில் (alg == வெற்று && ca->type == சாவி_RSA)
		alg = "rsa-sha2-512";

	எனில் ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		திரும்பு SSH_ERR_சாவி_CERT_INVALID_SIGN_சாவி;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	எனில் ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		செல் out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, அளவு(nonce));
	எனில் ((ret = sshbuf_put_string(cert, nonce, அளவு(nonce))) != 0)
		செல் out;

	/* Public key next */
	எனில் ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		செல் out;

	/* Then remaining cert fields */
	எனில் ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->சாவி_id)) != 0)
		செல் out;

	எனில் ((principals = sshbuf_new()) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	க்கு (i = 0; i < k->cert->nprincipals; i++) {
		எனில் ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			செல் out;
	}
	எனில் ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, வெற்று, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		செல் out;

	/* Sign the whole mess */
	எனில் ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		செல் out;
	/* Check and update signature_type against what was actually used */
	எனில் ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		செல் out;
	எனில் (alg != வெற்று && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		செல் out;
	}
	எனில் (k->cert->signature_type == வெற்று) {
		k->cert->signature_type = sigtype;
		sigtype = வெற்று;
	}
	/* Append signature and we are done */
	எனில் ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		செல் out;
	ret = 0;
 out:
	எனில் (ret != 0)
		sshbuf_reset(cert);
	விடுவி(sig_blob);
	விடுவி(ca_blob);
	விடுவி(sigtype);
	sshbuf_free(principals);
	திரும்பு ret;
}

நிலையான முழு
default_சாவி_sign(கட்டமைப்பு sshkey *சாவி, u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen,
    மாறிலி எழுத்து *alg, மாறிலி எழுத்து *sk_provider, மாறிலி எழுத்து *sk_pin,
    u_int compat, வெறுமை *ctx)
{
	எனில் (ctx != வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	திரும்பு sshkey_sign(சாவி, sigp, lenp, data, datalen, alg,
	    sk_provider, sk_pin, compat);
}

முழு
sshkey_certify(கட்டமைப்பு sshkey *k, கட்டமைப்பு sshkey *ca, மாறிலி எழுத்து *alg,
    மாறிலி எழுத்து *sk_provider, மாறிலி எழுத்து *sk_pin)
{
	திரும்பு sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_சாவி_sign, வெற்று);
}

முழு
sshkey_cert_check_authority(மாறிலி கட்டமைப்பு sshkey *k,
    முழு want_host, முழு wildcard_pattern, uint64_t verify_time,
    மாறிலி எழுத்து *name, மாறிலி எழுத்து **reason)
{
	u_int i, principal_matches;

	எனில் (reason == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		திரும்பு SSH_ERR_சாவி_CERT_INVALID;
	}
	எனில் (want_host) {
		எனில் (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			திரும்பு SSH_ERR_சாவி_CERT_INVALID;
		}
	} இல்லையெனில் {
		எனில் (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			திரும்பு SSH_ERR_சாவி_CERT_INVALID;
		}
	}
	எனில் (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		திரும்பு SSH_ERR_சாவி_CERT_INVALID;
	}
	எனில் (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		திரும்பு SSH_ERR_சாவி_CERT_INVALID;
	}
	எனில் (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		திரும்பு SSH_ERR_சாவி_CERT_INVALID;
	}
	எனில் (name == வெற்று)
		திரும்பு 0; /* principal matching not requested */

	principal_matches = 0;
	க்கு (i = 0; i < k->cert->nprincipals; i++) {
		எனில் (wildcard_pattern) {
			எனில் (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				நிறுத்து;
			}
		} இல்லையெனில் எனில் (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			நிறுத்து;
		}
	}
	எனில் (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		திரும்பு SSH_ERR_சாவி_CERT_INVALID;
	}
	திரும்பு 0;
}

முழு
sshkey_cert_check_authority_now(மாறிலி கட்டமைப்பு sshkey *k,
    முழு want_host, முழு wildcard_pattern, மாறிலி எழுத்து *name,
    மாறிலி எழுத்து **reason)
{
	time_t now;

	எனில் ((now = time(வெற்று)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		திரும்பு SSH_ERR_சாவி_CERT_INVALID;
	}
	திரும்பு sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

முழு
sshkey_cert_check_host(மாறிலி கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *host,
    மாறிலி எழுத்து *ca_sign_algorithms, மாறிலி எழுத்து **reason)
{
	முழு r;

	எனில் ((r = sshkey_cert_check_authority_now(சாவி, 1, 1, host, reason)) != 0)
		திரும்பு r;
	எனில் (sshbuf_len(சாவி->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		திரும்பு SSH_ERR_சாவி_CERT_INVALID;
	}
	எனில் (ca_sign_algorithms != வெற்று &&
	    (r = sshkey_check_cert_sigtype(சாவி, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		திரும்பு SSH_ERR_சாவி_CERT_INVALID;
	}
	திரும்பு 0;
}

size_t
sshkey_format_cert_validity(மாறிலி கட்டமைப்பு sshkey_cert *cert, எழுத்து *s, size_t l)
{
	எழுத்து from[32], to[32], ret[128];

	*from = *to = '\0';
	எனில் (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		திரும்பு strlcpy(s, "forever", l);

	எனில் (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, அளவு(from));
	எனில் (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, அளவு(to));

	எனில் (cert->valid_after == 0)
		snprintf(ret, அளவு(ret), "before %s", to);
	இல்லையெனில் எனில் (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, அளவு(ret), "after %s", from);
	இல்லையெனில்
		snprintf(ret, அளவு(ret), "from %s to %s", from, to);

	திரும்பு strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
முழு
sshkey_serialize_private_sk(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b)
{
	முழு r;

	எனில் ((r = sshbuf_put_cstring(b, சாவி->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, சாவி->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, சாவி->sk_சாவி_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, சாவி->sk_reserved)) != 0)
		திரும்பு r;

	திரும்பு 0;
}

நிலையான முழு
sshkey_private_serialize_opt(கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *buf,
    எண்ணிக்கை sshkey_serialize_rep opts)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;
	முழு was_shielded = sshkey_is_shielded(சாவி);
	கட்டமைப்பு sshbuf *b = வெற்று;
	மாறிலி கட்டமைப்பு sshkey_impl *impl;

	எனில் ((impl = sshkey_impl_from_சாவி(சாவி)) == வெற்று)
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	எனில் ((r = sshkey_unshield_private(சாவி)) != 0)
		திரும்பு r;
	எனில் ((b = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_put_cstring(b, sshkey_ssh_name(சாவி))) != 0)
		செல் out;
	எனில் (sshkey_is_cert(சாவி)) {
		எனில் (சாவி->cert == வெற்று ||
		    sshbuf_len(சாவி->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			செல் out;
		}
		எனில் ((r = sshbuf_put_stringb(b, சாவி->cert->certblob)) != 0)
			செல் out;
	}
	எனில் ((r = impl->funcs->serialize_private(சாவி, b, opts)) != 0)
		செல் out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	எனில் (was_shielded)
		r = sshkey_shield_private(சாவி);
	எனில் (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	திரும்பு r;
}

முழு
sshkey_private_serialize(கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b)
{
	திரும்பு sshkey_private_serialize_opt(சாவி, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
முழு
sshkey_private_deserialize_sk(கட்டமைப்பு sshbuf *buf, கட்டமைப்பு sshkey *k)
{
	முழு r;

	எனில் ((k->sk_சாவி_handle = sshbuf_new()) == வெற்று ||
	    (k->sk_reserved = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_get_cstring(buf, &k->sk_application, வெற்று)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_சாவி_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		திரும்பு r;

	திரும்பு 0;
}

முழு
sshkey_private_deserialize(கட்டமைப்பு sshbuf *buf, கட்டமைப்பு sshkey **kp)
{
	மாறிலி கட்டமைப்பு sshkey_impl *impl;
	எழுத்து *tname = வெற்று;
	எழுத்து *expect_sk_application = வெற்று;
	u_char *expect_ed25519_pk = வெற்று;
	கட்டமைப்பு sshkey *k = வெற்று;
	முழு type, r = SSH_ERR_INTERNAL_ERROR;

	எனில் (kp != வெற்று)
		*kp = வெற்று;
	எனில் ((r = sshbuf_get_cstring(buf, &tname, வெற்று)) != 0)
		செல் out;
	type = sshkey_type_from_name(tname);
	எனில் (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		எனில் ((r = sshkey_froms(buf, &k)) != 0)
			செல் out;
		எனில் (k->type != type) {
			r = SSH_ERR_சாவி_CERT_MISMATCH;
			செல் out;
		}
		/* For ECDSA keys, the group must match too */
		எனில் (k->type == சாவி_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_சாவி_CERT_MISMATCH;
			செல் out;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = வெற்று;
		k->ed25519_pk = வெற்று;
	} இல்லையெனில் {
		எனில் ((k = sshkey_new(type)) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
	}
	எனில் ((impl = sshkey_impl_from_type(type)) == வெற்று) {
		r = SSH_ERR_INTERNAL_ERROR;
		செல் out;
	}
	எனில் ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		செல் out;

	எனில் ((expect_sk_application != வெற்று && (k->sk_application == வெற்று ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != வெற்று && (k->ed25519_pk == வெற்று ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_சாவி_CERT_MISMATCH;
		செல் out;
	}
	/* success */
	r = 0;
	எனில் (kp != வெற்று) {
		*kp = k;
		k = வெற்று;
	}
 out:
	விடுவி(tname);
	sshkey_free(k);
	விடுவி(expect_sk_application);
	விடுவி(expect_ed25519_pk);
	திரும்பு r;
}

#ifdef WITH_OPENSSL
முழு
sshkey_ec_validate_public(மாறிலி EC_GROUP *group, மாறிலி EC_POINT *பொது)
{
	EC_POINT *nq = வெற்று;
	BIGNUM *order = வெற்று, *cofactor = வெற்று;
	முழு ret = SSH_ERR_சாவி_INVALID_EC_மதிப்பு;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	எனில் (EC_POINT_is_at_infinity(group, பொது))
		செல் out;

	எனில் ((cofactor = BN_new()) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (EC_GROUP_get_cofactor(group, cofactor, வெற்று) != 1)
		செல் out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	எனில் (!BN_is_one(cofactor)) {
		எனில் ((order = BN_new()) == வெற்று) {
			ret = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		எனில் (EC_GROUP_get_order(group, order, வெற்று) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			செல் out;
		}
		எனில் ((nq = EC_POINT_new(group)) == வெற்று) {
			ret = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		எனில் (EC_POINT_mul(group, nq, வெற்று, பொது, order, வெற்று) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			செல் out;
		}
		எனில் (EC_POINT_is_at_infinity(group, nq) != 1)
			செல் out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	திரும்பு ret;
}

முழு
sshkey_ec_validate_private(மாறிலி EC_சாவி *சாவி)
{
	BIGNUM *order = வெற்று, *tmp = வெற்று;
	முழு ret = SSH_ERR_சாவி_INVALID_EC_மதிப்பு;

	எனில் ((order = BN_new()) == வெற்று || (tmp = BN_new()) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}

	/* log2(private) > log2(order)/2 */
	எனில் (EC_GROUP_get_order(EC_சாவி_get0_group(சாவி), order, வெற்று) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	எனில் (BN_இலக்கம்_bits(EC_சாவி_get0_private_சாவி(சாவி)) <=
	    BN_இலக்கம்_bits(order) / 2)
		செல் out;

	/* private < order - 1 */
	எனில் (!BN_sub(tmp, order, BN_மதிப்பு_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	எனில் (BN_cmp(EC_சாவி_get0_private_சாவி(சாவி), tmp) >= 0)
		செல் out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	திரும்பு ret;
}

வெறுமை
sshkey_dump_ec_point(மாறிலி EC_GROUP *group, மாறிலி EC_POINT *point)
{
	BIGNUM *x = வெற்று, *y = வெற்று;

	எனில் (point == வெற்று) {
		fputs("point=(NULL)\n", stderr);
		திரும்பு;
	}
	எனில் ((x = BN_new()) == வெற்று || (y = BN_new()) == வெற்று) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		செல் out;
	}
	எனில் (EC_POINT_get_affine_coordinates(group, point, x, y, வெற்று) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		செல் out;
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

வெறுமை
sshkey_dump_ec_சாவி(மாறிலி EC_சாவி *சாவி)
{
	மாறிலி BIGNUM *exponent;

	sshkey_dump_ec_point(EC_சாவி_get0_group(சாவி),
	    EC_சாவி_get0_public_சாவி(சாவி));
	fputs("exponent=", stderr);
	எனில் ((exponent = EC_சாவி_get0_private_சாவி(சாவி)) == வெற்று)
		fputs("(NULL)", stderr);
	இல்லையெனில்
		BN_print_fp(stderr, EC_சாவி_get0_private_சாவி(சாவி));
	fputs("\n", stderr);
}
#endif /* WITH_OPENSSL */

நிலையான முழு
sshkey_private_to_blob2(கட்டமைப்பு sshkey *prv, கட்டமைப்பு sshbuf *blob,
    மாறிலி எழுத்து *passphrase, மாறிலி எழுத்து *comment, மாறிலி எழுத்து *ciphername,
    முழு rounds)
{
	u_char *cp, *சாவி = வெற்று, *pubkeyblob = வெற்று;
	u_char salt[SALT_LEN];
	size_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	முழு r = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு sshcipher_ctx *ciphercontext = வெற்று;
	மாறிலி கட்டமைப்பு sshcipher *cipher;
	மாறிலி எழுத்து *kdfname = KDFNAME;
	கட்டமைப்பு sshbuf *encoded = வெற்று, *encrypted = வெற்று, *kdf = வெற்று;

	எனில் (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	எனில் (rounds > MAX_KDF_ROUNDS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	எனில் (passphrase == வெற்று || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} இல்லையெனில் எனில் (ciphername == வெற்று)
		ciphername = DEFAULT_CIPHERNAME;
	எனில் ((cipher = cipher_by_name(ciphername)) == வெற்று) {
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}

	எனில் ((kdf = sshbuf_new()) == வெற்று ||
	    (encoded = sshbuf_new()) == வெற்று ||
	    (encrypted = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	எனில் ((சாவி = calloc(1, keylen + ivlen)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		எனில் (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, சாவி, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			செல் out;
		}
		எனில் ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			செல் out;
	} இல்லையெனில் எனில் (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_சாவி_UNKNOWN_CIPHER;
		செல் out;
	}
	எனில் ((r = cipher_init(&ciphercontext, cipher, சாவி, keylen,
	    சாவி + keylen, ivlen, 1)) != 0)
		செல் out;

	எனில் ((r = sshbuf_put(encoded, AUTH_MAGIC, அளவு(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_to_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		செல் out;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	எனில் ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		செல் out;

	/* append private key and comment*/
	எனில் ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		செல் out;

	/* padding */
	i = 0;
	போது (sshbuf_len(encrypted) % blocksize) {
		எனில் ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			செல் out;
	}

	/* length in destination buffer */
	எனில் ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		செல் out;

	/* encrypt */
	எனில் ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		செல் out;
	எனில் ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		செல் out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	எனில் ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_END, MARK_END_LEN)) != 0)
		செல் out;

	/* success */
	r = 0;

 out:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, அளவு(salt));
	எனில் (சாவி != வெற்று)
		freezero(சாவி, keylen + ivlen);
	எனில் (pubkeyblob != வெற்று)
		freezero(pubkeyblob, pubkeylen);
	திரும்பு r;
}

நிலையான முழு
private2_uudecode(கட்டமைப்பு sshbuf *blob, கட்டமைப்பு sshbuf **decodedp)
{
	மாறிலி u_char *cp;
	size_t encoded_len;
	முழு r;
	u_char last;
	கட்டமைப்பு sshbuf *encoded = வெற்று, *decoded = வெற்று;

	எனில் (blob == வெற்று || decodedp == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	*decodedp = வெற்று;

	எனில் ((encoded = sshbuf_new()) == வெற்று ||
	    (decoded = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	எனில் (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	போது (encoded_len > 0) {
		எனில் (*cp != '\n' && *cp != '\r') {
			எனில் ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				செல் out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		எனில் (last == '\n') {
			எனில் (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				எனில் ((r = sshbuf_put_u8(encoded, 0)) != 0)
					செல் out;
				நிறுத்து;
			}
		}
	}
	எனில் (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}

	/* decode base64 */
	எனில் ((r = sshbuf_b64tod(decoded, (எழுத்து *)sshbuf_ptr(encoded))) != 0)
		செல் out;

	/* check magic */
	எனில் (sshbuf_len(decoded) < அளவு(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, அளவு(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	/* success */
	*decodedp = decoded;
	decoded = வெற்று;
	r = 0;
 out:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	திரும்பு r;
}

நிலையான முழு
private2_decrypt(கட்டமைப்பு sshbuf *decoded, மாறிலி எழுத்து *passphrase,
    கட்டமைப்பு sshbuf **decryptedp, கட்டமைப்பு sshkey **pubkeyp)
{
	எழுத்து *ciphername = வெற்று, *kdfname = வெற்று;
	மாறிலி கட்டமைப்பு sshcipher *cipher = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	கட்டமைப்பு sshbuf *kdf = வெற்று, *decrypted = வெற்று;
	கட்டமைப்பு sshcipher_ctx *ciphercontext = வெற்று;
	கட்டமைப்பு sshkey *pubkey = வெற்று;
	u_char *சாவி = வெற்று, *salt = வெற்று, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	எனில் (decoded == வெற்று || decryptedp == வெற்று || pubkeyp == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = வெற்று;
	*pubkeyp = வெற்று;

	எனில் ((decrypted = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}

	/* parse public portion of key */
	எனில் ((r = sshbuf_consume(decoded, அளவு(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, வெற்று)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		செல் out;

	எனில் (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}

	எனில் ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		செல் out;

	எனில் ((cipher = cipher_by_name(ciphername)) == வெற்று) {
		r = SSH_ERR_சாவி_UNKNOWN_CIPHER;
		செல் out;
	}
	எனில் (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_சாவி_UNKNOWN_CIPHER;
		செல் out;
	}
	எனில் (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் ((passphrase == வெற்று || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_சாவி_WRONG_PASSPHRASE;
		செல் out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	எனில் (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	எனில் ((சாவி = calloc(1, keylen + ivlen)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (strcmp(kdfname, "bcrypt") == 0) {
		எனில் ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			செல் out;
		எனில் (rounds > MAX_KDF_ROUNDS) {
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		எனில் (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    சாவி, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	எனில் (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}

	/* decrypt private portion of key */
	எனில் ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, சாவி, keylen,
	    சாவி + keylen, ivlen, 0)) != 0)
		செல் out;
	எனில் ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		எனில் (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_சாவி_WRONG_PASSPHRASE;
		செல் out;
	}
	எனில் ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		செல் out;
	/* there should be no trailing data */
	எனில் (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}

	/* check check bytes */
	எனில் ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		செல் out;
	எனில் (check1 != check2) {
		r = SSH_ERR_சாவி_WRONG_PASSPHRASE;
		செல் out;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = வெற்று;
	*pubkeyp = pubkey;
	pubkey = வெற்று;
	r = 0;
 out:
	cipher_free(ciphercontext);
	விடுவி(ciphername);
	விடுவி(kdfname);
	sshkey_free(pubkey);
	எனில் (salt != வெற்று) {
		explicit_bzero(salt, slen);
		விடுவி(salt);
	}
	எனில் (சாவி != வெற்று) {
		explicit_bzero(சாவி, keylen + ivlen);
		விடுவி(சாவி);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	திரும்பு r;
}

நிலையான முழு
sshkey_parse_private2(கட்டமைப்பு sshbuf *blob, முழு type, மாறிலி எழுத்து *passphrase,
    கட்டமைப்பு sshkey **keyp, எழுத்து **commentp)
{
	எழுத்து *comment = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு sshbuf *decoded = வெற்று, *decrypted = வெற்று;
	கட்டமைப்பு sshkey *k = வெற்று, *pubkey = வெற்று;

	எனில் (keyp != வெற்று)
		*keyp = வெற்று;
	எனில் (commentp != வெற்று)
		*commentp = வெற்று;

	/* Undo base64 encoding and decrypt the private section */
	எனில் ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		செல் out;

	எனில் (type != சாவி_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_சாவி_TYPE_MISMATCH;
		செல் out;
	}

	/* Load the private key and comment */
	எனில் ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, வெற்று)) != 0)
		செல் out;

	/* Check deterministic padding after private section */
	எனில் ((r = private2_check_padding(decrypted)) != 0)
		செல் out;

	/* Check that the public key in the envelope matches the private key */
	எனில் (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}

	/* success */
	r = 0;
	எனில் (keyp != வெற்று) {
		*keyp = k;
		k = வெற்று;
	}
	எனில் (commentp != வெற்று) {
		*commentp = comment;
		comment = வெற்று;
	}
 out:
	விடுவி(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	திரும்பு r;
}

நிலையான முழு
sshkey_parse_private2_pubkey(கட்டமைப்பு sshbuf *blob, முழு type,
    கட்டமைப்பு sshkey **keyp)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு sshbuf *decoded = வெற்று;
	கட்டமைப்பு sshkey *pubkey = வெற்று;
	u_int nkeys = 0;

	எனில் (keyp != வெற்று)
		*keyp = வெற்று;

	எனில் ((r = private2_uudecode(blob, &decoded)) != 0)
		செல் out;
	/* parse public key from unencrypted envelope */
	எனில் ((r = sshbuf_consume(decoded, அளவு(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		செல் out;

	எனில் (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}

	/* Parse the public key */
	எனில் ((r = sshkey_froms(decoded, &pubkey)) != 0)
		செல் out;

	எனில் (type != சாவி_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_சாவி_TYPE_MISMATCH;
		செல் out;
	}

	/* success */
	r = 0;
	எனில் (keyp != வெற்று) {
		*keyp = pubkey;
		pubkey = வெற்று;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	திரும்பு r;
}

#ifdef WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
நிலையான முழு
sshkey_private_to_blob_pem_pkcs8(கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *buf,
    முழு format, மாறிலி எழுத்து *_passphrase, மாறிலி எழுத்து *comment)
{
	முழு was_shielded = sshkey_is_shielded(சாவி);
	முழு success, r;
	முழு blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : வெற்று;
	மாறிலி EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : வெற்று;
	எழுத்து *bptr;
	BIO *bio = வெற்று;
	கட்டமைப்பு sshbuf *blob;
	EVP_PKEY *pkey = வெற்று;

	எனில் (len > 0 && len <= 4)
		திரும்பு SSH_ERR_PASSPHRASE_TOO_SHORT;
	எனில் ((blob = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((bio = BIO_new(BIO_s_mem())) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshkey_unshield_private(சாவி)) != 0)
		செல் out;

	தேர்வு (சாவி->type) {
	நிலை சாவி_ECDSA:
		எனில் (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivate_சாவி(bio,
			    EVP_PKEY_get0_EC_சாவி(சாவி->pkey),
			    cipher, passphrase, len, வெற்று, வெற்று);
		} இல்லையெனில் {
			pkey = சாவி->pkey;
			EVP_PKEY_up_ref(சாவி->pkey);
			success = 1;
		}
		நிறுத்து;
	நிலை சாவி_RSA:
		எனில் (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivate_சாவி(bio,
			    EVP_PKEY_get0_RSA(சாவி->pkey),
			    cipher, passphrase, len, வெற்று, வெற்று);
		} இல்லையெனில் {
			pkey = சாவி->pkey;
			EVP_PKEY_up_ref(சாவி->pkey);
			success = 1;
		}
		நிறுத்து;
#ifdef OPENSSL_HAS_ED25519
	நிலை சாவி_ED25519:
		எனில் (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		} இல்லையெனில் {
			pkey = EVP_PKEY_new_raw_private_சாவி(EVP_PKEY_ED25519,
			    வெற்று, சாவி->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != வெற்று;
		}
		நிறுத்து;
#endif
	இயல்பு:
		success = 0;
		நிறுத்து;
	}
	எனில் (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	எனில் (format == SSHKEY_PRIVATE_PKCS8) {
		எனில் ((success = PEM_write_bio_Private_சாவி(bio, pkey, cipher,
		    passphrase, len, வெற்று, வெற்று)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			செல் out;
		}
	}
	எனில் ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		செல் out;
	}
	எனில் ((r = sshbuf_put(blob, bptr, blen)) != 0)
		செல் out;
	r = 0;
 out:
	எனில் (was_shielded)
		r = sshkey_shield_private(சாவி);
	எனில் (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	திரும்பு r;
}
#endif /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
முழு
sshkey_private_to_fileblob(கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *blob,
    மாறிலி எழுத்து *passphrase, மாறிலி எழுத்து *comment,
    முழு format, மாறிலி எழுத்து *openssh_format_cipher, முழு openssh_format_rounds)
{
	தேர்வு (சாவி->type) {
#ifdef WITH_OPENSSL
	நிலை சாவி_ECDSA:
	நிலை சாவி_RSA:
	நிலை சாவி_ED25519:
		நிறுத்து; /* see below */
#இல்லையெனில் /* WITH_OPENSSL */
	நிலை சாவி_ED25519:
#endif /* WITH_OPENSSL */
	நிலை சாவி_ED25519_SK:
#ifdef WITH_OPENSSL
	நிலை சாவி_ECDSA_SK:
#endif /* WITH_OPENSSL */
	நிலை சாவி_MLDSA44_ED25519:
		திரும்பு sshkey_private_to_blob2(சாவி, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	இயல்பு:
		திரும்பு SSH_ERR_சாவி_TYPE_UNKNOWN;
	}

#ifdef WITH_OPENSSL
	தேர்வு (format) {
	நிலை SSHKEY_PRIVATE_OPENSSH:
		திரும்பு sshkey_private_to_blob2(சாவி, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	நிலை SSHKEY_PRIVATE_PEM:
	நிலை SSHKEY_PRIVATE_PKCS8:
		திரும்பு sshkey_private_to_blob_pem_pkcs8(சாவி, blob,
		    format, passphrase, comment);
	இயல்பு:
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	}
#endif /* WITH_OPENSSL */
}

#ifdef WITH_OPENSSL
நிலையான முழு
translate_libcrypto_error(unsigned long pem_err)
{
	முழு pem_reason = ERR_GET_REASON(pem_err);

	தேர்வு (ERR_GET_LIB(pem_err)) {
	நிலை ERR_LIB_PEM:
		தேர்வு (pem_reason) {
		நிலை PEM_R_BAD_PASSWORD_READ:
#ifdef PEM_R_PROBLEMS_GETTING_PASSWORD
		நிலை PEM_R_PROBLEMS_GETTING_PASSWORD:
#endif
#ifdef PEM_R_BAD_DECRYPT
		நிலை PEM_R_BAD_DECRYPT:
#endif
			திரும்பு SSH_ERR_சாவி_WRONG_PASSPHRASE;
		இயல்பு:
			திரும்பு SSH_ERR_INVALID_FORMAT;
		}
	நிலை ERR_LIB_EVP:
		தேர்வு (pem_reason) {
#ifdef EVP_R_BAD_DECRYPT
		நிலை EVP_R_BAD_DECRYPT:
			திரும்பு SSH_ERR_சாவி_WRONG_PASSPHRASE;
#endif
#ifdef EVP_R_BN_DECODE_ERROR
		நிலை EVP_R_BN_DECODE_ERROR:
#endif
		நிலை EVP_R_DECODE_ERROR:
#ifdef EVP_R_PRIVATE_சாவி_DECODE_ERROR
		நிலை EVP_R_PRIVATE_சாவி_DECODE_ERROR:
#endif
			திரும்பு SSH_ERR_INVALID_FORMAT;
		இயல்பு:
			திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
		}
	நிலை ERR_LIB_ASN1:
#ifdef ERR_LIB_OSSL_DECODER
	நிலை ERR_LIB_OSSL_DECODER:
#endif
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
}

நிலையான வெறுமை
clear_libcrypto_errors(வெறுமை)
{
	போது (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
நிலையான முழு
convert_libcrypto_error(வெறுமை)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	எனில் (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_சாவி_WRONG_PASSPHRASE)
		திரும்பு SSH_ERR_சாவி_WRONG_PASSPHRASE;
	திரும்பு translate_libcrypto_error(ERR_peek_last_error());
}

நிலையான முழு
pem_passphrase_cb(எழுத்து *buf, முழு size, முழு rwflag, வெறுமை *u)
{
	எழுத்து *p = (எழுத்து *)u;
	size_t len;

	எனில் (p == வெற்று || (len = strlen(p)) == 0)
		திரும்பு -1;
	எனில் (size < 0 || len > (size_t)size)
		திரும்பு -1;
	memcpy(buf, p, len);
	திரும்பு (முழு)len;
}

நிலையான முழு
sshkey_parse_private_pem_fileblob(கட்டமைப்பு sshbuf *blob, முழு type,
    மாறிலி எழுத்து *passphrase, கட்டமைப்பு sshkey **keyp)
{
	EVP_PKEY *pk = வெற்று;
	கட்டமைப்பு sshkey *prv = வெற்று;
	BIO *bio = வெற்று;
	முழு r;
	RSA *rsa = வெற்று;
	EC_சாவி *ecdsa = வெற்று;

	எனில் (keyp != வெற்று)
		*keyp = வெற்று;

	எனில் ((bio = BIO_new(BIO_s_mem())) == வெற்று || sshbuf_len(blob) > INT_MAX)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (முழு)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}

	clear_libcrypto_errors();
	எனில் ((pk = PEM_read_bio_Private_சாவி(bio, வெற்று, pem_passphrase_cb,
	    (எழுத்து *)passphrase)) == வெற்று) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		எனில் (passphrase != வெற்று && *passphrase != '\0')
			r = SSH_ERR_சாவி_WRONG_PASSPHRASE;
		இல்லையெனில்
			r = convert_libcrypto_error();
		செல் out;
	}
	எனில் (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == சாவி_UNSPEC || type == சாவி_RSA)) {
		எனில் ((prv = sshkey_new(சாவி_UNSPEC)) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		எனில் ((rsa = EVP_PKEY_get1_RSA(pk)) == வெற்று) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			செல் out;
		}
		prv->type = சாவி_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#endif
		எனில் (RSA_blinding_on(rsa, வெற்று) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			செல் out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		எனில் ((r = sshkey_check_rsa_length(prv, 0)) != 0)
			செல் out;
	} இல்லையெனில் எனில் (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == சாவி_UNSPEC || type == சாவி_ECDSA)) {
		எனில் ((prv = sshkey_new(சாவி_UNSPEC)) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		எனில் ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_சாவி(pk)) == வெற்று) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			செல் out;
		}
		prv->type = சாவி_ECDSA;
		எனில் (sshkey_curve_nid_to_name(prv->ecdsa_nid) == வெற்று ||
		    sshkey_ec_validate_public(EC_சாவி_get0_group(ecdsa),
		    EC_சாவி_get0_public_சாவி(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#ifdef DEBUG_PK
		எனில் (prv != வெற்று && prv->pkey != வெற்று)
			sshkey_dump_ec_சாவி(EVP_PKEY_get0_EC_சாவி(prv->pkey));
#endif
#ifdef OPENSSL_HAS_ED25519
	} இல்லையெனில் எனில் (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == சாவி_UNSPEC || type == சாவி_ED25519)) {
		size_t len;

		எனில் ((prv = sshkey_new(சாவி_UNSPEC)) == வெற்று ||
		    (prv->ed25519_sk = calloc(1, ED25519_SK_SZ)) == வெற்று ||
		    (prv->ed25519_pk = calloc(1, ED25519_PK_SZ)) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		prv->type = சாவி_ED25519;
		len = ED25519_PK_SZ;
		எனில் (!EVP_PKEY_get_raw_public_சாவி(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			செல் out;
		}
		எனில் (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		எனில் (!EVP_PKEY_get_raw_private_சாவி(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			செல் out;
		}
		எனில் (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		/* Append the public key to our private key */
		memcpy(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#ifdef DEBUG_PK
		sshbuf_dump_data(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#endif
#endif /* OPENSSL_HAS_ED25519 */
	} இல்லையெனில் {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	r = 0;
	எனில் (keyp != வெற்று) {
		*keyp = prv;
		prv = வெற்று;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_சாவி_free(ecdsa);
	sshkey_free(prv);
	திரும்பு r;
}
#endif /* WITH_OPENSSL */

முழு
sshkey_parse_private_fileblob_type(கட்டமைப்பு sshbuf *blob, முழு type,
    மாறிலி எழுத்து *passphrase, கட்டமைப்பு sshkey **keyp, எழுத்து **commentp)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் (keyp != வெற்று)
		*keyp = வெற்று;
	எனில் (commentp != வெற்று)
		*commentp = வெற்று;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	எனில் (r != SSH_ERR_INVALID_FORMAT)
		திரும்பு r;
#ifdef WITH_OPENSSL
	திரும்பு sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#இல்லையெனில்
	திரும்பு SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

முழு
sshkey_parse_private_fileblob(கட்டமைப்பு sshbuf *buffer, மாறிலி எழுத்து *passphrase,
    கட்டமைப்பு sshkey **keyp, எழுத்து **commentp)
{
	எனில் (keyp != வெற்று)
		*keyp = வெற்று;
	எனில் (commentp != வெற்று)
		*commentp = வெற்று;

	திரும்பு sshkey_parse_private_fileblob_type(buffer, சாவி_UNSPEC,
	    passphrase, keyp, commentp);
}

வெறுமை
sshkey_sig_details_free(கட்டமைப்பு sshkey_sig_details *details)
{
	freezero(details, அளவு(*details));
}

முழு
sshkey_parse_pubkey_from_private_fileblob_type(கட்டமைப்பு sshbuf *blob, முழு type,
    கட்டமைப்பு sshkey **pubkeyp)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் (pubkeyp != வெற்று)
		*pubkeyp = வெற்று;
	/* only new-format private keys bundle a public key inside */
	எனில் ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		திரும்பு r;
	திரும்பு 0;
}
