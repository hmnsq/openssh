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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/mman.h>
#અન્તર્ભાવ <netinet/in.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/evp.h>
#અન્તર્ભાવ <openssl/err.h>
#અન્તર્ભાવ <openssl/pem.h>
#endif

#અન્તર્ભાવ "crypto_api.h"

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <resolv.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <util.h>

#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "digest.h"
#define SSHKEY_INTERNAL
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "ssh-sk.h"
#અન્તર્ભાવ "ssh-pkcs11.h"

#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#define MARK_BEGIN_LEN		(કદ(MARK_BEGIN) - 1)
#define MARK_END_LEN		(કદ(MARK_END) - 1)
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

સ્થિર પૂર્ણાંક sshkey_from_blob_internal(સંરચના sshbuf *buf,
    સંરચના sshkey **keyp, પૂર્ણાંક allow_cert,
    અચલ અક્ષર *alg_allowlist, અચલ અક્ષર *ca_sigalg_allowlist);

/* Supported key types */
બાહ્ય અચલ સંરચના sshkey_impl sshkey_ed25519_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_ed25519_cert_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_ed25519_sk_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
બાહ્ય અચલ સંરચના sshkey_impl sshkey_mldsa44_ed25519_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#ifdef WITH_OPENSSL
# ifdef ENABLE_SK
બાહ્ય અચલ સંરચના sshkey_impl sshkey_ecdsa_sk_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_ecdsa_sk_cert_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
બાહ્ય અચલ સંરચના sshkey_impl sshkey_ecdsa_nistp256_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_ecdsa_nistp384_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_ecdsa_nistp521_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_rsa_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_rsa_cert_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_rsa_sha256_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_rsa_sha256_cert_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_rsa_sha512_impl;
બાહ્ય અચલ સંરચના sshkey_impl sshkey_rsa_sha512_cert_impl;
#endif /* WITH_OPENSSL */

અચલ સંરચના sshkey_impl * અચલ keyimpls[] = {
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
	ખાલી
};

સ્થિર અચલ સંરચના sshkey_impl *
sshkey_impl_from_type(પૂર્ણાંક type)
{
	પૂર્ણાંક i;

	માટે (i = 0; keyimpls[i] != ખાલી; i++) {
		જો (keyimpls[i]->type == type)
			પાછા keyimpls[i];
	}
	પાછા ખાલી;
}

સ્થિર અચલ સંરચના sshkey_impl *
sshkey_impl_from_type_nid(પૂર્ણાંક type, પૂર્ણાંક nid)
{
	પૂર્ણાંક i;

	માટે (i = 0; keyimpls[i] != ખાલી; i++) {
		જો (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			પાછા keyimpls[i];
	}
	પાછા ખાલી;
}

સ્થિર અચલ સંરચના sshkey_impl *
sshkey_impl_from_ચાવી(અચલ સંરચના sshkey *k)
{
	જો (k == ખાલી)
		પાછા ખાલી;
	પાછા sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

અચલ અક્ષર *
sshkey_type(અચલ સંરચના sshkey *k)
{
	અચલ સંરચના sshkey_impl *impl;

	જો ((impl = sshkey_impl_from_ચાવી(k)) == ખાલી)
		પાછા "unknown";
	પાછા impl->shortname;
}

સ્થિર અચલ અક્ષર *
sshkey_ssh_name_from_type_nid(પૂર્ણાંક type, પૂર્ણાંક nid)
{
	અચલ સંરચના sshkey_impl *impl;

	જો ((impl = sshkey_impl_from_type_nid(type, nid)) == ખાલી)
		પાછા "ssh-unknown";
	પાછા impl->name;
}

પૂર્ણાંક
sshkey_type_is_cert(પૂર્ણાંક type)
{
	અચલ સંરચના sshkey_impl *impl;

	જો ((impl = sshkey_impl_from_type(type)) == ખાલી)
		પાછા 0;
	પાછા impl->cert;
}

અચલ અક્ષર *
sshkey_ssh_name(અચલ સંરચના sshkey *k)
{
	પાછા sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

અચલ અક્ષર *
sshkey_ssh_name_plain(અચલ સંરચના sshkey *k)
{
	પાછા sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

સ્થિર પૂર્ણાંક
type_from_name(અચલ અક્ષર *name, પૂર્ણાંક allow_short)
{
	પૂર્ણાંક i;
	અચલ સંરચના sshkey_impl *impl;

	માટે (i = 0; keyimpls[i] != ખાલી; i++) {
		impl = keyimpls[i];
		જો (impl->name != ખાલી && strcmp(name, impl->name) == 0)
			પાછા impl->type;
		/* Only allow shortname matches for plain key types */
		જો (allow_short && !impl->cert && impl->shortname != ખાલી &&
		    strcasecmp(impl->shortname, name) == 0)
			પાછા impl->type;
	}
	પાછા ચાવી_UNSPEC;
}

પૂર્ણાંક
sshkey_type_from_name(અચલ અક્ષર *name)
{
	પાછા type_from_name(name, 0);
}

પૂર્ણાંક
sshkey_type_from_shortname(અચલ અક્ષર *name)
{
	પાછા type_from_name(name, 1);
}

સ્થિર પૂર્ણાંક
ચાવી_type_is_ecdsa_variant(પૂર્ણાંક type)
{
	પસંદગી (type) {
	સ્થિતિ ચાવી_ECDSA:
	સ્થિતિ ચાવી_ECDSA_CERT:
	સ્થિતિ ચાવી_ECDSA_SK:
	સ્થિતિ ચાવી_ECDSA_SK_CERT:
		પાછા 1;
	}
	પાછા 0;
}

પૂર્ણાંક
sshkey_ecdsa_nid_from_name(અચલ અક્ષર *name)
{
	પૂર્ણાંક i;

	માટે (i = 0; keyimpls[i] != ખાલી; i++) {
		જો (!ચાવી_type_is_ecdsa_variant(keyimpls[i]->type))
			ચાલુ;
		જો (keyimpls[i]->name != ખાલી &&
		    strcmp(name, keyimpls[i]->name) == 0)
			પાછા keyimpls[i]->nid;
	}
	પાછા -1;
}

પૂર્ણાંક
sshkey_match_keyname_to_sigalgs(અચલ અક્ષર *keyname, અચલ અક્ષર *sigalgs)
{
	પૂર્ણાંક ktype;

	જો (sigalgs == ખાલી || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == ચાવી_UNSPEC)
		પાછા 0;
	નહીંતર જો (ktype == ચાવી_RSA) {
		પાછા match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} નહીંતર જો (ktype == ચાવી_RSA_CERT) {
		પાછા match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} નહીંતર જો (ktype == ચાવી_ECDSA_SK) {
		પાછા match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} નહીંતર જો (ktype == ચાવી_ECDSA_SK_CERT) {
		પાછા match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} નહીંતર
		પાછા match_pattern_list(keyname, sigalgs, 0) == 1;
}

અક્ષર *
sshkey_alg_list(પૂર્ણાંક certs_only, પૂર્ણાંક plain_only, પૂર્ણાંક include_sigonly, અક્ષર sep)
{
	અક્ષર *ret = ખાલી;
	size_t i;
	અચલ સંરચના sshkey_impl *impl;
	અક્ષર sep_str[2] = {sep, '\0'};

	માટે (i = 0; keyimpls[i] != ખાલી; i++) {
		impl = keyimpls[i];
		જો (impl->name == ખાલી)
			ચાલુ;
		જો (!include_sigonly && impl->sigonly)
			ચાલુ;
		જો ((certs_only && !impl->cert) || (plain_only && impl->cert))
			ચાલુ;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	પાછા ret;
}

પૂર્ણાંક
sshkey_names_valid2(અચલ અક્ષર *names, પૂર્ણાંક allow_wildcard, પૂર્ણાંક plain_only)
{
	અક્ષર *s, *cp, *p;
	અચલ સંરચના sshkey_impl *impl;
	પૂર્ણાંક i, type;

	જો (names == ખાલી || strcmp(names, "") == 0)
		પાછા 0;
	જો ((s = cp = strdup(names)) == ખાલી)
		પાછા 0;
	માટે ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		જો (type == ચાવી_UNSPEC) {
			જો (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = ખાલી;
				માટે (i = 0; keyimpls[i] != ખાલી; i++) {
					જો (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						તોડો;
					}
				}
				જો (impl != ખાલી)
					ચાલુ;
			}
			મુક્ત(s);
			પાછા 0;
		} નહીંતર જો (plain_only && sshkey_type_is_cert(type)) {
			મુક્ત(s);
			પાછા 0;
		}
	}
	મુક્ત(s);
	પાછા 1;
}

u_int
sshkey_size(અચલ સંરચના sshkey *k)
{
	અચલ સંરચના sshkey_impl *impl;

	જો ((impl = sshkey_impl_from_ચાવી(k)) == ખાલી)
		પાછા 0;
	જો (impl->funcs->size != ખાલી)
		પાછા impl->funcs->size(k);
	પાછા impl->keybits;
}

સ્થિર પૂર્ણાંક
sshkey_type_is_valid_ca(પૂર્ણાંક type)
{
	અચલ સંરચના sshkey_impl *impl;

	જો ((impl = sshkey_impl_from_type(type)) == ખાલી)
		પાછા 0;
	/* All non-certificate types may act as CAs */
	પાછા !impl->cert;
}

પૂર્ણાંક
sshkey_is_cert(અચલ સંરચના sshkey *k)
{
	જો (k == ખાલી)
		પાછા 0;
	પાછા sshkey_type_is_cert(k->type);
}

પૂર્ણાંક
sshkey_is_sk(અચલ સંરચના sshkey *k)
{
	જો (k == ખાલી)
		પાછા 0;
	પસંદગી (sshkey_type_plain(k->type)) {
	સ્થિતિ ચાવી_ECDSA_SK:
	સ્થિતિ ચાવી_ED25519_SK:
		પાછા 1;
	મૂળભૂત:
		પાછા 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
પૂર્ણાંક
sshkey_type_plain(પૂર્ણાંક type)
{
	પસંદગી (type) {
	સ્થિતિ ચાવી_RSA_CERT:
		પાછા ચાવી_RSA;
	સ્થિતિ ચાવી_ECDSA_CERT:
		પાછા ચાવી_ECDSA;
	સ્થિતિ ચાવી_ECDSA_SK_CERT:
		પાછા ચાવી_ECDSA_SK;
	સ્થિતિ ચાવી_ED25519_CERT:
		પાછા ચાવી_ED25519;
	સ્થિતિ ચાવી_MLDSA44_ED25519_CERT:
		પાછા ચાવી_MLDSA44_ED25519;
	સ્થિતિ ચાવી_ED25519_SK_CERT:
		પાછા ચાવી_ED25519_SK;
	મૂળભૂત:
		પાછા type;
	}
}

/* Return the cert equivalent to a plain key type */
સ્થિર પૂર્ણાંક
sshkey_type_certified(પૂર્ણાંક type)
{
	પસંદગી (type) {
	સ્થિતિ ચાવી_RSA:
		પાછા ચાવી_RSA_CERT;
	સ્થિતિ ચાવી_ECDSA:
		પાછા ચાવી_ECDSA_CERT;
	સ્થિતિ ચાવી_ECDSA_SK:
		પાછા ચાવી_ECDSA_SK_CERT;
	સ્થિતિ ચાવી_ED25519:
		પાછા ચાવી_ED25519_CERT;
	સ્થિતિ ચાવી_MLDSA44_ED25519:
		પાછા ચાવી_MLDSA44_ED25519_CERT;
	સ્થિતિ ચાવી_ED25519_SK:
		પાછા ચાવી_ED25519_SK_CERT;
	મૂળભૂત:
		પાછા -1;
	}
}

#ifdef WITH_OPENSSL
સ્થિર અચલ EVP_MD *
ssh_digest_to_md(પૂર્ણાંક hash_alg)
{
	પસંદગી (hash_alg) {
	સ્થિતિ SSH_DIGEST_SHA1:
		પાછા EVP_sha1();
	સ્થિતિ SSH_DIGEST_SHA256:
		પાછા EVP_sha256();
	સ્થિતિ SSH_DIGEST_SHA384:
		પાછા EVP_sha384();
	સ્થિતિ SSH_DIGEST_SHA512:
		પાછા EVP_sha512();
	}
	પાછા ખાલી;
}

પૂર્ણાંક
sshkey_pkey_digest_sign(EVP_PKEY *pkey, પૂર્ણાંક hash_alg, u_char **sigp,
    size_t *lenp, અચલ u_char *data, size_t datalen)
{
	EVP_MD_CTX *ctx = ખાલી;
	u_char *sig = ખાલી;
	પૂર્ણાંક ret;
	size_t slen;
	અચલ EVP_MD *evpmd;

	*sigp = ખાલી;
	*lenp = 0;

	slen = EVP_PKEY_size(pkey);
	જો (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	જો ((sig = malloc(slen)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;

	જો ((ctx = EVP_MD_CTX_new()) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (EVP_DigestSignInit(ctx, ખાલી, evpmd, ખાલી, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, data, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = ખાલી;
	ret = 0;

 out:
	EVP_MD_CTX_free(ctx);
	મુક્ત(sig);
	પાછા ret;
}

પૂર્ણાંક
sshkey_pkey_digest_verify(EVP_PKEY *pkey, પૂર્ણાંક hash_alg, અચલ u_char *data,
    size_t datalen, u_char *sigbuf, size_t siglen)
{
	EVP_MD_CTX *ctx = ખાલી;
	પૂર્ણાંક ret = SSH_ERR_INTERNAL_ERROR;
	અચલ EVP_MD *evpmd;

	જો ((evpmd = ssh_digest_to_md(hash_alg)) == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((ctx = EVP_MD_CTX_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો (EVP_DigestVerifyInit(ctx, ખાલી, evpmd, ખાલી, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	પસંદગી (EVP_DigestVerify(ctx, sigbuf, siglen, data, datalen)) {
	સ્થિતિ 1:
		ret = 0;
		તોડો;
	સ્થિતિ 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		તોડો;
	મૂળભૂત:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		તોડો;
	}

 out:
	EVP_MD_CTX_free(ctx);
	પાછા ret;
}

/* XXX: these are really begging for a table-driven approach */
પૂર્ણાંક
sshkey_curve_name_to_nid(અચલ અક્ષર *name)
{
	જો (strcmp(name, "nistp256") == 0)
		પાછા NID_X9_62_prime256v1;
	નહીંતર જો (strcmp(name, "nistp384") == 0)
		પાછા NID_secp384r1;
	નહીંતર જો (strcmp(name, "nistp521") == 0)
		પાછા NID_secp521r1;
	નહીંતર
		પાછા -1;
}

u_int
sshkey_curve_nid_to_bits(પૂર્ણાંક nid)
{
	પસંદગી (nid) {
	સ્થિતિ NID_X9_62_prime256v1:
		પાછા 256;
	સ્થિતિ NID_secp384r1:
		પાછા 384;
	સ્થિતિ NID_secp521r1:
		પાછા 521;
	મૂળભૂત:
		પાછા 0;
	}
}

પૂર્ણાંક
sshkey_ecdsa_bits_to_nid(પૂર્ણાંક bits)
{
	પસંદગી (bits) {
	સ્થિતિ 256:
		પાછા NID_X9_62_prime256v1;
	સ્થિતિ 384:
		પાછા NID_secp384r1;
	સ્થિતિ 521:
		પાછા NID_secp521r1;
	મૂળભૂત:
		પાછા -1;
	}
}

અચલ અક્ષર *
sshkey_curve_nid_to_name(પૂર્ણાંક nid)
{
	પસંદગી (nid) {
	સ્થિતિ NID_X9_62_prime256v1:
		પાછા "nistp256";
	સ્થિતિ NID_secp384r1:
		પાછા "nistp384";
	સ્થિતિ NID_secp521r1:
		પાછા "nistp521";
	મૂળભૂત:
		પાછા ખાલી;
	}
}

પૂર્ણાંક
sshkey_ec_nid_to_hash_alg(પૂર્ણાંક nid)
{
	પૂર્ણાંક kbits = sshkey_curve_nid_to_bits(nid);

	જો (kbits <= 0)
		પાછા -1;

	/* RFC5656 section 6.2.1 */
	જો (kbits <= 256)
		પાછા SSH_DIGEST_SHA256;
	નહીંતર જો (kbits <= 384)
		પાછા SSH_DIGEST_SHA384;
	નહીંતર
		પાછા SSH_DIGEST_SHA512;
}
#endif /* WITH_OPENSSL */

સ્થિર શૂન્ય
cert_free(સંરચના sshkey_cert *cert)
{
	u_int i;

	જો (cert == ખાલી)
		પાછા;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	મુક્ત(cert->ચાવી_id);
	માટે (i = 0; i < cert->nprincipals; i++)
		મુક્ત(cert->principals[i]);
	મુક્ત(cert->principals);
	sshkey_free(cert->signature_ચાવી);
	મુક્ત(cert->signature_type);
	freezero(cert, કદ(*cert));
}

સ્થિર સંરચના sshkey_cert *
cert_new(શૂન્ય)
{
	સંરચના sshkey_cert *cert;

	જો ((cert = calloc(1, કદ(*cert))) == ખાલી)
		પાછા ખાલી;
	જો ((cert->certblob = sshbuf_new()) == ખાલી ||
	    (cert->critical = sshbuf_new()) == ખાલી ||
	    (cert->extensions = sshbuf_new()) == ખાલી) {
		cert_free(cert);
		પાછા ખાલી;
	}
	cert->ચાવી_id = ખાલી;
	cert->principals = ખાલી;
	cert->signature_ચાવી = ખાલી;
	cert->signature_type = ખાલી;
	પાછા cert;
}

સંરચના sshkey *
sshkey_new(પૂર્ણાંક type)
{
	સંરચના sshkey *k;
	અચલ સંરચના sshkey_impl *impl = ખાલી;

	જો (type != ચાવી_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == ખાલી)
		પાછા ખાલી;

	/* All non-certificate types may act as CAs */
	જો ((k = calloc(1, કદ(*k))) == ખાલી)
		પાછા ખાલી;
	k->type = type;
	k->ecdsa_nid = -1;
	જો (impl != ખાલી && impl->funcs->alloc != ખાલી) {
		જો (impl->funcs->alloc(k) != 0) {
			મુક્ત(k);
			પાછા ખાલી;
		}
	}
	જો (sshkey_is_cert(k)) {
		જો ((k->cert = cert_new()) == ખાલી) {
			sshkey_free(k);
			પાછા ખાલી;
		}
	}

	પાછા k;
}

/* Frees common FIDO fields */
શૂન્ય
sshkey_sk_cleanup(સંરચના sshkey *k)
{
	મુક્ત(k->sk_application);
	sshbuf_free(k->sk_ચાવી_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = ખાલી;
	k->sk_ચાવી_handle = k->sk_reserved = ખાલી;
}

#જો defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#અથવાજો defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#નહીંતર
# define PREKEY_MMAP_FLAG	0
#endif

સ્થિર પૂર્ણાંક
sshkey_prekey_alloc(u_char **prekeyp, size_t len)
{
#જો defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = ખાલી;
	જો ((prekey = mmap(ખાલી, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		પાછા SSH_ERR_SYSTEM_ERROR;
#જો defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(શૂન્ય)madvise(prekey, len, MADV_DONTDUMP);
#endif
	*prekeyp = prekey;
#નહીંતર
	*prekeyp = calloc(1, len);
#endif /* HAVE_MMAP et al */
	પાછા 0;
}

સ્થિર શૂન્ય
sshkey_prekey_free(શૂન્ય *prekey, size_t len)
{
#જો defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	જો (prekey == ખાલી)
		પાછા;
	munmap(prekey, len);
#નહીંતર
	મુક્ત(prekey);
#endif /* HAVE_MMAP et al */
}

સ્થિર શૂન્ય
sshkey_free_contents(સંરચના sshkey *k)
{
	અચલ સંરચના sshkey_impl *impl;

	જો (k == ખાલી)
		પાછા;
	જો ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_ચાવી_free(k);
	જો ((impl = sshkey_impl_from_type(k->type)) != ખાલી &&
	    impl->funcs->cleanup != ખાલી)
		impl->funcs->cleanup(k);
	જો (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_private, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

શૂન્ય
sshkey_free(સંરચના sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, કદ(*k));
}

સ્થિર પૂર્ણાંક
cert_compare(સંરચના sshkey_cert *a, સંરચના sshkey_cert *b)
{
	જો (a == ખાલી && b == ખાલી)
		પાછા 1;
	જો (a == ખાલી || b == ખાલી)
		પાછા 0;
	જો (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		પાછા 0;
	જો (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		પાછા 0;
	પાછા 1;
}

/* Compares FIDO-specific pubkey fields only */
પૂર્ણાંક
sshkey_sk_fields_equal(અચલ સંરચના sshkey *a, અચલ સંરચના sshkey *b)
{
	જો (a->sk_application == ખાલી || b->sk_application == ખાલી)
		પાછા 0;
	જો (strcmp(a->sk_application, b->sk_application) != 0)
		પાછા 0;
	પાછા 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
પૂર્ણાંક
sshkey_equal_public(અચલ સંરચના sshkey *a, અચલ સંરચના sshkey *b)
{
	અચલ સંરચના sshkey_impl *impl;

	જો (a == ખાલી || b == ખાલી ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		પાછા 0;
	જો ((impl = sshkey_impl_from_type(a->type)) == ખાલી)
		પાછા 0;
	પાછા impl->funcs->equal(a, b);
}

પૂર્ણાંક
sshkey_equal(અચલ સંરચના sshkey *a, અચલ સંરચના sshkey *b)
{
	જો (a == ખાલી || b == ખાલી || a->type != b->type)
		પાછા 0;
	જો (sshkey_is_cert(a)) {
		જો (!cert_compare(a->cert, b->cert))
			પાછા 0;
	}
	પાછા sshkey_equal_public(a, b);
}


/* Serialise common FIDO key parts */
પૂર્ણાંક
sshkey_serialize_sk(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_put_cstring(b, ચાવી->sk_application)) != 0)
		પાછા r;

	પાછા 0;
}

સ્થિર પૂર્ણાંક
to_blob_buf(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b, પૂર્ણાંક force_plain,
  ગણના sshkey_serialize_rep opts)
{
	પૂર્ણાંક type, ret = SSH_ERR_INTERNAL_ERROR;
	અચલ અક્ષર *typename;
	અચલ સંરચના sshkey_impl *impl;

	જો (ચાવી == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(ચાવી->type) : ચાવી->type;

	જો (sshkey_type_is_cert(type)) {
		જો (ચાવી->cert == ખાલી)
			પાછા SSH_ERR_EXPECTED_CERT;
		જો (sshbuf_len(ચાવી->cert->certblob) == 0)
			પાછા SSH_ERR_ચાવી_LACKS_CERTBLOB;
		/* Use the existing blob */
		જો ((ret = sshbuf_putb(b, ચાવી->cert->certblob)) != 0)
			પાછા ret;
		પાછા 0;
	}
	જો ((impl = sshkey_impl_from_type(type)) == ખાલી)
		પાછા SSH_ERR_ચાવી_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, ચાવી->ecdsa_nid);
	જો ((ret = sshbuf_put_cstring(b, typename)) != 0)
		પાછા ret;
	પાછા impl->funcs->serialize_public(ચાવી, b, opts);
}

પૂર્ણાંક
sshkey_putb(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b)
{
	પાછા to_blob_buf(ચાવી, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

સ્થિર પૂર્ણાંક
sshkey_puts_opts_internal(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b,
    ગણના sshkey_serialize_rep opts, પૂર્ણાંક force_plain)
{
	સંરચના sshbuf *tmp;
	પૂર્ણાંક r;

	જો ((tmp = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(ચાવી, tmp, force_plain, opts);
	જો (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	પાછા r;
}

પૂર્ણાંક
sshkey_puts(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b)
{
	પાછા sshkey_puts_opts_internal(ચાવી, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

પૂર્ણાંક
sshkey_putb_plain(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b)
{
	પાછા to_blob_buf(ચાવી, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

પૂર્ણાંક
sshkey_puts_plain(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b)
{
	પાછા sshkey_puts_opts_internal(ચાવી, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

સ્થિર પૂર્ણાંક
to_blob(અચલ સંરચના sshkey *ચાવી, u_char **blobp, size_t *lenp, પૂર્ણાંક force_plain,
    ગણના sshkey_serialize_rep opts)
{
	પૂર્ણાંક ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	સંરચના sshbuf *b = ખાલી;

	જો (lenp != ખાલી)
		*lenp = 0;
	જો (blobp != ખાલી)
		*blobp = ખાલી;
	જો ((b = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((ret = to_blob_buf(ચાવી, b, force_plain, opts)) != 0)
		જાઓ out;
	len = sshbuf_len(b);
	જો (lenp != ખાલી)
		*lenp = len;
	જો (blobp != ખાલી) {
		જો ((*blobp = malloc(len)) == ખાલી) {
			ret = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	પાછા ret;
}

પૂર્ણાંક
sshkey_to_blob(અચલ સંરચના sshkey *ચાવી, u_char **blobp, size_t *lenp)
{
	પાછા to_blob(ચાવી, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

પૂર્ણાંક
sshkey_plain_to_blob(અચલ સંરચના sshkey *ચાવી, u_char **blobp, size_t *lenp)
{
	પાછા to_blob(ચાવી, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

પૂર્ણાંક
sshkey_fingerprint_raw(અચલ સંરચના sshkey *k, પૂર્ણાંક dgst_alg,
    u_char **retp, size_t *lenp)
{
	u_char *blob = ખાલી, *ret = ખાલી;
	size_t blob_len = 0;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો (retp != ખાલી)
		*retp = ખાલી;
	જો (lenp != ખાલી)
		*lenp = 0;
	જો (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	જો ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		જાઓ out;
	જો ((ret = calloc(1, SSH_DIGEST_MAX_LENGTH)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_LENGTH)) != 0)
		જાઓ out;
	/* success */
	જો (retp != ખાલી) {
		*retp = ret;
		ret = ખાલી;
	}
	જો (lenp != ખાલી)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	મુક્ત(ret);
	જો (blob != ખાલી)
		freezero(blob, blob_len);
	પાછા r;
}

સ્થિર અક્ષર *
fingerprint_b64(અચલ અક્ષર *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	અક્ષર *ret;
	size_t plen = strlen(alg) + 1;
	size_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	જો (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == ખાલી)
		પાછા ખાલી;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	જો (dgst_raw_len == 0)
		પાછા ret;
	જો (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		પાછા ખાલી;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	પાછા ret;
}

સ્થિર અક્ષર *
fingerprint_hex(અચલ અક્ષર *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	અક્ષર *retval, hex[5];
	size_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	જો (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == ખાલી)
		પાછા ખાલી;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	માટે (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, કદ(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	પાછા retval;
}

સ્થિર અક્ષર *
fingerprint_bubblebabble(u_char *dgst_raw, size_t dgst_raw_len)
{
	અક્ષર vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	અક્ષર consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	અક્ષર *retval;

	rounds = (dgst_raw_len / 2) + 1;
	જો ((retval = calloc(rounds, 6)) == ખાલી)
		પાછા ખાલી;
	retval[j++] = 'x';
	માટે (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		જો ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			જો ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} નહીંતર {
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
	પાછા retval;
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
સ્થિર અક્ષર *
fingerprint_randomart(અચલ અક્ષર *alg, u_char *dgst_raw, size_t dgst_raw_len,
    અચલ સંરચના sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	અક્ષર	*augmentation_string = " .o+=*BOX@%&#/^SE";
	અક્ષર	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	size_t	 i, tlen, hlen;
	u_int	 b;
	પૂર્ણાંક	 x, y, r;
	size_t	 len = strlen(augmentation_string) - 1;

	જો ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == ખાલી)
		પાછા ખાલી;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * કદ(અક્ષર));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	માટે (i = 0; i < dgst_raw_len; i++) {
		પૂર્ણાંક આગત;
		/* each byte conveys four 2-bit move commands */
		આગત = dgst_raw[i];
		માટે (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (આગત & 0x1) ? 1 : -1;
			y += (આગત & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			જો (field[x][y] < len - 2)
				field[x][y]++;
			આગત = આગત >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, કદ(title), "[%s %u]",
		sshkey_type(k), sshkey_size(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	જો (r < 0 || r > (પૂર્ણાંક)કદ(title))
		r = snprintf(title, કદ(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, કદ(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	માટે (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	memcpy(p, title, tlen);
	p += tlen;
	માટે (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	માટે (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		માટે (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	માટે (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	memcpy(p, hash, hlen);
	p += hlen;
	માટે (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	પાછા retval;
}

અક્ષર *
sshkey_fingerprint(અચલ સંરચના sshkey *k, પૂર્ણાંક dgst_alg,
    ગણના sshkey_fp_rep dgst_rep)
{
	અક્ષર *retval = ખાલી;
	u_char *dgst_raw;
	size_t dgst_raw_len;

	જો (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		પાછા ખાલી;
	પસંદગી (dgst_rep) {
	સ્થિતિ SSH_FP_DEFAULT:
		જો (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} નહીંતર {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		તોડો;
	સ્થિતિ SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		તોડો;
	સ્થિતિ SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		તોડો;
	સ્થિતિ SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		તોડો;
	સ્થિતિ SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		તોડો;
	મૂળભૂત:
		freezero(dgst_raw, dgst_raw_len);
		પાછા ખાલી;
	}
	freezero(dgst_raw, dgst_raw_len);
	પાછા retval;
}

સ્થિર પૂર્ણાંક
peek_type_nid(અચલ અક્ષર *s, size_t l, પૂર્ણાંક *nid)
{
	અચલ સંરચના sshkey_impl *impl;
	પૂર્ણાંક i;

	માટે (i = 0; keyimpls[i] != ખાલી; i++) {
		impl = keyimpls[i];
		જો (impl->name == ખાલી || strlen(impl->name) != l)
			ચાલુ;
		જો (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			જો (ચાવી_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			પાછા impl->type;
		}
	}
	પાછા ચાવી_UNSPEC;
}

/* XXX this can now be made const char * */
પૂર્ણાંક
sshkey_read(સંરચના sshkey *ret, અક્ષર **cpp)
{
	સંરચના sshkey *k;
	અક્ષર *cp, *blobcopy;
	size_t space;
	પૂર્ણાંક r, type, curve_nid = -1;
	સંરચના sshbuf *blob;

	જો (ret == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (ret->type != ચાવી_UNSPEC && sshkey_impl_from_type(ret->type) == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	જો (space == strlen(cp))
		પાછા SSH_ERR_INVALID_FORMAT;
	જો ((type = peek_type_nid(cp, space, &curve_nid)) == ચાવી_UNSPEC)
		પાછા SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	માટે (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	જો (*cp == '\0')
		પાછા SSH_ERR_INVALID_FORMAT;
	જો (ret->type != ચાવી_UNSPEC && ret->type != type)
		પાછા SSH_ERR_ચાવી_TYPE_MISMATCH;
	જો ((blob = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	જો ((blobcopy = strndup(cp, space)) == ખાલી) {
		sshbuf_free(blob);
		પાછા SSH_ERR_ALLOC_FAIL;
	}
	જો ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		મુક્ત(blobcopy);
		sshbuf_free(blob);
		પાછા r;
	}
	મુક્ત(blobcopy);
	જો ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		પાછા r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	માટે (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	જો (k->type != type) {
		sshkey_free(k);
		પાછા SSH_ERR_ચાવી_TYPE_MISMATCH;
	}
	જો (ચાવી_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		પાછા SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, કદ(*k));

	/* success */
	*cpp = cp;
	પાછા 0;
}

પૂર્ણાંક
sshkey_to_base64(અચલ સંરચના sshkey *ચાવી, અક્ષર **b64p)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	સંરચના sshbuf *b = ખાલી;
	અક્ષર *uu = ખાલી;

	જો (b64p != ખાલી)
		*b64p = ખાલી;
	જો ((b = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshkey_putb(ચાવી, b)) != 0)
		જાઓ out;
	જો ((uu = sshbuf_dtob64_string(b, 0)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	/* Success */
	જો (b64p != ખાલી) {
		*b64p = uu;
		uu = ખાલી;
	}
	r = 0;
 out:
	sshbuf_free(b);
	મુક્ત(uu);
	પાછા r;
}

પૂર્ણાંક
sshkey_format_text(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	અક્ષર *uu = ખાલી;

	જો ((r = sshkey_to_base64(ચાવી, &uu)) != 0)
		જાઓ out;
	જો ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(ચાવી), uu)) != 0)
		જાઓ out;
	r = 0;
 out:
	મુક્ત(uu);
	પાછા r;
}

પૂર્ણાંક
sshkey_write(અચલ સંરચના sshkey *ચાવી, FILE *f)
{
	સંરચના sshbuf *b = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો ((b = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshkey_format_text(ચાવી, b)) != 0)
		જાઓ out;
	જો (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		જો (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		જાઓ out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	પાછા r;
}

અચલ અક્ષર *
sshkey_cert_type(અચલ સંરચના sshkey *k)
{
	પસંદગી (k->cert->type) {
	સ્થિતિ SSH2_CERT_TYPE_USER:
		પાછા "user";
	સ્થિતિ SSH2_CERT_TYPE_HOST:
		પાછા "host";
	મૂળભૂત:
		પાછા "unknown";
	}
}

પૂર્ણાંક
sshkey_check_rsa_length(અચલ સંરચના sshkey *k, પૂર્ણાંક min_size)
{
#ifdef WITH_OPENSSL
	પૂર્ણાંક nbits;

	જો (k == ખાલી || k->pkey == ખાલી ||
	    (k->type != ચાવી_RSA && k->type != ચાવી_RSA_CERT))
		પાછા 0;
	nbits = EVP_PKEY_bits(k->pkey);
	જો (nbits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    (min_size > 0 && nbits < min_size))
		પાછા SSH_ERR_ચાવી_LENGTH;
#endif /* WITH_OPENSSL */
	પાછા 0;
}

#ifdef WITH_OPENSSL
પૂર્ણાંક
sshkey_ecdsa_ચાવી_to_nid(અચલ EC_ચાવી *k)
{
	અચલ EC_GROUP *g;
	પૂર્ણાંક nid;

	જો (k == ખાલી || (g = EC_ચાવી_get0_group(k)) == ખાલી)
		પાછા -1;
	જો ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		પાછા -1;
	પાછા nid;
}

પૂર્ણાંક
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	પાછા sshkey_ecdsa_ચાવી_to_nid(EVP_PKEY_get0_EC_ચાવી(pkey));
}
#endif /* WITH_OPENSSL */

પૂર્ણાંક
sshkey_generate(પૂર્ણાંક type, u_int bits, સંરચના sshkey **keyp)
{
	સંરચના sshkey *k;
	પૂર્ણાંક ret = SSH_ERR_INTERNAL_ERROR;
	અચલ સંરચના sshkey_impl *impl;

	જો (keyp == ખાલી || sshkey_type_is_cert(type))
		પાછા SSH_ERR_INVALID_ARGUMENT;
	*keyp = ખાલી;
	જો ((impl = sshkey_impl_from_type(type)) == ખાલી)
		પાછા SSH_ERR_ચાવી_TYPE_UNKNOWN;
	જો (impl->funcs->generate == ખાલી)
		પાછા SSH_ERR_FEATURE_UNSUPPORTED;
	જો ((k = sshkey_new(ચાવી_UNSPEC)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	k->type = type;
	જો ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		પાછા ret;
	}
	/* success */
	*keyp = k;
	પાછા 0;
}

પૂર્ણાંક
sshkey_cert_copy(અચલ સંરચના sshkey *from_ચાવી, સંરચના sshkey *to_ચાવી)
{
	u_int i;
	અચલ સંરચના sshkey_cert *from;
	સંરચના sshkey_cert *to;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો (to_ચાવી == ખાલી || (from = from_ચાવી->cert) == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	જો ((to = cert_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;

	જો ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		જાઓ out;

	to->serial = from->serial;
	to->type = from->type;
	જો (from->ચાવી_id == ખાલી)
		to->ચાવી_id = ખાલી;
	નહીંતર જો ((to->ચાવી_id = strdup(from->ચાવી_id)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	જો (from->signature_ચાવી == ખાલી)
		to->signature_ચાવી = ખાલી;
	નહીંતર જો ((r = sshkey_from_private(from->signature_ચાવી,
	    &to->signature_ચાવી)) != 0)
		જાઓ out;
	જો (from->signature_type != ખાલી &&
	    (to->signature_type = strdup(from->signature_type)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	જો (from->nprincipals > 0) {
		જો ((to->principals = calloc(from->nprincipals,
		    કદ(*to->principals))) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		માટે (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			જો (to->principals[i] == ખાલી) {
				to->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				જાઓ out;
			}
		}
	}
	to->nprincipals = from->nprincipals;

	/* success */
	cert_free(to_ચાવી->cert);
	to_ચાવી->cert = to;
	to = ખાલી;
	r = 0;
 out:
	cert_free(to);
	પાછા r;
}

પૂર્ણાંક
sshkey_copy_public_sk(અચલ સંરચના sshkey *from, સંરચના sshkey *to)
{
	/* Append security-key application string */
	જો ((to->sk_application = strdup(from->sk_application)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	પાછા 0;
}

પૂર્ણાંક
sshkey_from_private(અચલ સંરચના sshkey *k, સંરચના sshkey **pkp)
{
	સંરચના sshkey *n = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	અચલ સંરચના sshkey_impl *impl;

	*pkp = ખાલી;
	જો ((impl = sshkey_impl_from_ચાવી(k)) == ખાલી)
		પાછા SSH_ERR_ચાવી_TYPE_UNKNOWN;
	જો ((n = sshkey_new(k->type)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = impl->funcs->copy_public(k, n)) != 0)
		જાઓ out;
	જો (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		જાઓ out;
	/* success */
	*pkp = n;
	n = ખાલી;
	r = 0;
 out:
	sshkey_free(n);
	પાછા r;
}

પૂર્ણાંક
sshkey_is_shielded(સંરચના sshkey *k)
{
	પાછા k != ખાલી && k->shielded_private != ખાલી;
}

પૂર્ણાંક
sshkey_shield_private(સંરચના sshkey *k)
{
	સંરચના sshbuf *prvbuf = ખાલી;
	u_char *prekey = ખાલી, *enc = ખાલી, keyiv[SSH_DIGEST_MAX_LENGTH];
	સંરચના sshcipher_ctx *cctx = ખાલી;
	અચલ સંરચના sshcipher *cipher;
	size_t i, enclen = 0;
	સંરચના sshkey *kswap = ખાલી, tmp;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	જો ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ખાલી) {
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	જો (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		જાઓ out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	જો ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		જાઓ out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	જો ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		જાઓ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	જો ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		જાઓ out;

	/* Serialise and encrypt the private key using the ephemeral key */
	જો ((prvbuf = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		જાઓ out;
	જો ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		જાઓ out;
	/* pad to cipher blocksize */
	i = 0;
	જ્યારે (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		જો ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			જાઓ out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	જો ((enc = malloc(enclen)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		જાઓ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	જો ((r = sshkey_from_private(k, &kswap)) != 0)
		જાઓ out;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_private = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = ખાલી; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 out:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, કદ(keyiv));
	explicit_bzero(&tmp, કદ(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	પાછા r;
}

/* Check deterministic padding after private key */
સ્થિર પૂર્ણાંક
private2_check_padding(સંરચના sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	પૂર્ણાંક r;

	i = 0;
	જ્યારે (sshbuf_len(decrypted)) {
		જો ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			જાઓ out;
		જો (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, કદ(pad));
	explicit_bzero(&i, કદ(i));
	પાછા r;
}

પૂર્ણાંક
sshkey_unshield_private(સંરચના sshkey *k)
{
	સંરચના sshbuf *prvbuf = ખાલી;
	u_char *cp, keyiv[SSH_DIGEST_MAX_LENGTH];
	સંરચના sshcipher_ctx *cctx = ખાલી;
	અચલ સંરચના sshcipher *cipher;
	સંરચના sshkey *kswap = ખાલી, tmp;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	જો (!sshkey_is_shielded(k))
		પાછા 0; /* nothing to do */

	જો ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ખાલી) {
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	જો (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		જાઓ out;
	}
	/* check size of shielded key blob */
	જો (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}

	/* Calculate the ephemeral key from the prekey */
	જો ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		જાઓ out;
	જો ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		જાઓ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	જો ((prvbuf = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		જાઓ out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(k->shielded_private, k->shielded_len, stderr);
#endif
	જો ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		જાઓ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	જો ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		જાઓ out;

	જો ((r = private2_check_padding(prvbuf)) != 0)
		જાઓ out;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 out:
	cipher_free(cctx);
	explicit_bzero(keyiv, કદ(keyiv));
	explicit_bzero(&tmp, કદ(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	પાછા r;
}

સ્થિર પૂર્ણાંક
cert_parse(સંરચના sshbuf *b, સંરચના sshkey *ચાવી, સંરચના sshbuf *certbuf,
    અચલ અક્ષર *ca_sigalg_allowlist)
{
	સંરચના sshbuf *principals = ખાલી, *crit = ખાલી;
	સંરચના sshbuf *exts = ખાલી, *ca = ખાલી;
	u_char *sig = ખાલી;
	અક્ષર *sigtype = ખાલી;
	size_t signed_len = 0, slen = 0, kidlen = 0;
	પૂર્ણાંક ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	જો ((ret = sshbuf_putb(ચાવી->cert->certblob, certbuf)) != 0)
		પાછા ret;

	/* Parse body of certificate up to signature */
	જો ((ret = sshbuf_get_u64(b, &ચાવી->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &ચાવી->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &ચાવી->cert->ચાવી_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &ચાવી->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &ચાવી->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, ખાલી, ખાલી)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(ચાવી->cert->certblob) - sshbuf_len(b);

	જો ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}

	/* Is this a signature we're prepared to accept? */
	જો ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (ca_sigalg_allowlist != ખાલી &&
	    match_pattern_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		જાઓ out;
	}

	/* Parse CA key and check whether we might accept it */
	જો (sshkey_from_blob_internal(ca, &ચાવી->cert->signature_ચાવી, 0,
	    ca_sigalg_allowlist, ખાલી) != 0) {
		ret = SSH_ERR_ચાવી_CERT_INVALID_SIGN_ચાવી;
		જાઓ out;
	}
	જો (!sshkey_type_is_valid_ca(ચાવી->cert->signature_ચાવી->type)) {
		ret = SSH_ERR_ચાવી_CERT_INVALID_SIGN_ચાવી;
		જાઓ out;
	}

	જો (ચાવી->cert->type != SSH2_CERT_TYPE_USER &&
	    ચાવી->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_ચાવી_CERT_UNKNOWN_TYPE;
		જાઓ out;
	}

	/* Parse principals section */
	જ્યારે (sshbuf_len(principals) > 0) {
		અક્ષર *principal = ખાલી;
		અક્ષર **oprincipals = ખાલી;

		જો (ચાવી->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		જો ((ret = sshbuf_get_cstring(principals, &principal,
		    ખાલી)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		oprincipals = ચાવી->cert->principals;
		ચાવી->cert->principals = recallocarray(ચાવી->cert->principals,
		    ચાવી->cert->nprincipals, ચાવી->cert->nprincipals + 1,
		    કદ(*ચાવી->cert->principals));
		જો (ચાવી->cert->principals == ખાલી) {
			મુક્ત(principal);
			ચાવી->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		ચાવી->cert->principals[ચાવી->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	જો ((ret = sshbuf_putb(ચાવી->cert->critical, crit)) != 0 ||
	    (exts != ખાલી &&
	    (ret = sshbuf_putb(ચાવી->cert->extensions, exts)) != 0))
		જાઓ out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	જ્યારે (sshbuf_len(crit) != 0) {
		જો ((ret = sshbuf_get_string_direct(crit, ખાલી, ખાલી)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, ખાલી, ખાલી)) != 0) {
			sshbuf_reset(ચાવી->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
	}
	જ્યારે (exts != ખાલી && sshbuf_len(exts) != 0) {
		જો ((ret = sshbuf_get_string_direct(exts, ખાલી, ખાલી)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, ખાલી, ખાલી)) != 0) {
			sshbuf_reset(ચાવી->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
	}

	/* Finally, validate signature */
	જો ((ret = sshkey_verify(ચાવી->cert->signature_ચાવી, sig, slen,
	    sshbuf_ptr(ચાવી->cert->certblob), signed_len, ખાલી, 0, ખાલી)) != 0)
		જાઓ out;

	/* Success */
	ret = 0;
	ચાવી->cert->signature_type = sigtype;
	sigtype = ખાલી;
 out:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	મુક્ત(sig);
	મુક્ત(sigtype);
	પાછા ret;
}

પૂર્ણાંક
sshkey_deserialize_sk(સંરચના sshbuf *b, સંરચના sshkey *ચાવી)
{
	/* Parse additional security-key application string */
	જો (sshbuf_get_cstring(b, &ચાવી->sk_application, ખાલી) != 0)
		પાછા SSH_ERR_INVALID_FORMAT;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
sshkey_from_blob_internal(સંરચના sshbuf *b, સંરચના sshkey **keyp,
    પૂર્ણાંક allow_cert, અચલ અક્ષર *alg_allowlist, અચલ અક્ષર *ca_sigalg_allowlist)
{
	પૂર્ણાંક type, ret = SSH_ERR_INTERNAL_ERROR;
	અક્ષર *ktype = ખાલી;
	સંરચના sshkey *ચાવી = ખાલી;
	સંરચના sshbuf *copy;
	અચલ સંરચના sshkey_impl *impl;

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	જો (keyp != ખાલી)
		*keyp = ખાલી;
	જો ((copy = sshbuf_fromb(b)) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (sshbuf_get_cstring(b, &ktype, ખાલી) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}

	type = sshkey_type_from_name(ktype);
	જો (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_ચાવી_CERT_INVALID_SIGN_ચાવી;
		જાઓ out;
	}

	જો (alg_allowlist != ખાલી &&
	    !sshkey_match_keyname_to_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_ચાવી_ALG_UNSUPPORTED;
		જાઓ out;
	}

	જો ((impl = sshkey_impl_from_type(type)) == ખાલી) {
		ret = SSH_ERR_ચાવી_TYPE_UNKNOWN;
		જાઓ out;
	}
	જો ((ચાવી = sshkey_new(type)) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		જો (sshbuf_get_string_direct(b, ખાલી, ખાલી) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
	}
	જો ((ret = impl->funcs->deserialize_public(ktype, b, ચાવી)) != 0)
		જાઓ out;

	/* Parse certificate potion */
	જો (sshkey_is_cert(ચાવી) &&
	    (ret = cert_parse(b, ચાવી, copy, ca_sigalg_allowlist)) != 0)
		જાઓ out;

	જો (ચાવી != ખાલી && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	ret = 0;
	જો (keyp != ખાલી) {
		*keyp = ચાવી;
		ચાવી = ખાલી;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(ચાવી);
	મુક્ત(ktype);
	પાછા ret;
}

પૂર્ણાંક
sshkey_from_blob(અચલ u_char *blob, size_t blen, સંરચના sshkey **keyp)
{
	સંરચના sshbuf *b;
	પૂર્ણાંક r;

	જો ((b = sshbuf_from(blob, blen)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1, ખાલી, ખાલી);
	sshbuf_free(b);
	પાછા r;
}

પૂર્ણાંક
sshkey_fromb(સંરચના sshbuf *b, સંરચના sshkey **keyp)
{
	પાછા sshkey_from_blob_internal(b, keyp, 1, ખાલી, ખાલી);
}

પૂર્ણાંક
sshkey_fromb_allowlist(સંરચના sshbuf *b, સંરચના sshkey **keyp,
    અચલ અક્ષર *alg_allowlist, અચલ અક્ષર *ca_sigalg_allowlist)
{
	પાછા sshkey_from_blob_internal(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

પૂર્ણાંક
sshkey_froms(સંરચના sshbuf *buf, સંરચના sshkey **keyp)
{
	સંરચના sshbuf *b;
	પૂર્ણાંક r;

	જો ((r = sshbuf_froms(buf, &b)) != 0)
		પાછા r;
	r = sshkey_from_blob_internal(b, keyp, 1, ખાલી, ખાલી);
	sshbuf_free(b);
	પાછા r;
}

પૂર્ણાંક
sshkey_get_sigtype(અચલ u_char *sig, size_t siglen, અક્ષર **sigtypep)
{
	પૂર્ણાંક r;
	સંરચના sshbuf *b = ખાલી;
	અક્ષર *sigtype = ખાલી;

	જો (sigtypep != ખાલી)
		*sigtypep = ખાલી;
	જો ((b = sshbuf_from(sig, siglen)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_get_cstring(b, &sigtype, ખાલી)) != 0)
		જાઓ out;
	/* success */
	જો (sigtypep != ખાલી) {
		*sigtypep = sigtype;
		sigtype = ખાલી;
	}
	r = 0;
 out:
	મુક્ત(sigtype);
	sshbuf_free(b);
	પાછા r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
પૂર્ણાંક
sshkey_check_cert_sigtype(અચલ સંરચના sshkey *ચાવી, અચલ અક્ષર *allowed)
{
	જો (ચાવી == ખાલી || allowed == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (!sshkey_type_is_cert(ચાવી->type))
		પાછા 0;
	જો (ચાવી->cert == ખાલી || ચાવી->cert->signature_type == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (match_pattern_list(ચાવી->cert->signature_type, allowed, 0) != 1)
		પાછા SSH_ERR_SIGN_ALG_UNSUPPORTED;
	પાછા 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
અચલ અક્ષર *
sshkey_sigalg_by_name(અચલ અક્ષર *name)
{
	અચલ સંરચના sshkey_impl *impl;
	પૂર્ણાંક i;

	માટે (i = 0; keyimpls[i] != ખાલી; i++) {
		impl = keyimpls[i];
		જો (strcmp(impl->name, name) != 0)
			ચાલુ;
		જો (impl->sigalg != ખાલી)
			પાછા impl->sigalg;
		જો (!impl->cert)
			પાછા impl->name;
		પાછા sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	પાછા ખાલી;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
પૂર્ણાંક
sshkey_check_sigtype(અચલ u_char *sig, size_t siglen,
    અચલ અક્ષર *requested_alg)
{
	અચલ અક્ષર *expected_alg;
	અક્ષર *sigtype = ખાલી;
	પૂર્ણાંક r;

	જો (requested_alg == ખાલી)
		પાછા 0;
	જો ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		પાછા r;
	r = strcmp(expected_alg, sigtype) == 0;
	મુક્ત(sigtype);
	પાછા r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

પૂર્ણાંક
sshkey_sign(સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen,
    અચલ અક્ષર *alg, અચલ અક્ષર *sk_provider, અચલ અક્ષર *sk_pin, u_int compat)
{
	પૂર્ણાંક was_shielded = sshkey_is_shielded(ચાવી);
	પૂર્ણાંક r2, r = SSH_ERR_INTERNAL_ERROR;
	અચલ સંરચના sshkey_impl *impl;

	જો (sigp != ખાલી)
		*sigp = ખાલી;
	જો (lenp != ખાલી)
		*lenp = 0;
	જો (datalen > SSH_ચાવી_MAX_SIGN_DATA_SIZE)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((impl = sshkey_impl_from_ચાવી(ચાવી)) == ખાલી)
		પાછા SSH_ERR_ચાવી_TYPE_UNKNOWN;
	જો ((r = sshkey_unshield_private(ચાવી)) != 0)
		પાછા r;
	જો (sshkey_is_sk(ચાવી)) {
		r = sshsk_sign(sk_provider, ચાવી, sigp, lenp, data,
		    datalen, compat, sk_pin);
	} નહીંતર જો ((ચાવી->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(ચાવી, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	} નહીંતર {
		જો (impl->funcs->sign == ખાલી)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		નહીંતર {
			r = impl->funcs->sign(ચાવી, sigp, lenp, data, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	જો (was_shielded && (r2 = sshkey_shield_private(ચાવી)) != 0)
		પાછા r2;
	પાછા r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
પૂર્ણાંક
sshkey_verify(અચલ સંરચના sshkey *ચાવી,
    અચલ u_char *sig, size_t siglen,
    અચલ u_char *data, size_t dlen, અચલ અક્ષર *alg, u_int compat,
    સંરચના sshkey_sig_details **detailsp)
{
	અચલ સંરચના sshkey_impl *impl;

	જો (detailsp != ખાલી)
		*detailsp = ખાલી;
	જો (siglen == 0 || dlen > SSH_ચાવી_MAX_SIGN_DATA_SIZE)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((impl = sshkey_impl_from_ચાવી(ચાવી)) == ખાલી)
		પાછા SSH_ERR_ચાવી_TYPE_UNKNOWN;
	પાછા impl->funcs->verify(ચાવી, sig, siglen, data, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
પૂર્ણાંક
sshkey_to_certified(સંરચના sshkey *k)
{
	પૂર્ણાંક newtype;

	જો ((newtype = sshkey_type_certified(k->type)) == -1)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((k->cert = cert_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	પાછા 0;
}

/* Convert a certificate to its raw key equivalent */
પૂર્ણાંક
sshkey_drop_cert(સંરચના sshkey *k)
{
	જો (!sshkey_type_is_cert(k->type))
		પાછા SSH_ERR_ચાવી_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = ખાલી;
	k->type = sshkey_type_plain(k->type);
	પાછા 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
પૂર્ણાંક
sshkey_certify_custom(સંરચના sshkey *k, સંરચના sshkey *ca, અચલ અક્ષર *alg,
    અચલ અક્ષર *sk_provider, અચલ અક્ષર *sk_pin,
    sshkey_certify_signer *signer, શૂન્ય *signer_ctx)
{
	અચલ સંરચના sshkey_impl *impl;
	સંરચના sshbuf *principals = ખાલી;
	u_char *ca_blob = ખાલી, *sig_blob = ખાલી, nonce[32];
	size_t i, ca_len, sig_len;
	પૂર્ણાંક ret = SSH_ERR_INTERNAL_ERROR;
	સંરચના sshbuf *cert = ખાલી;
	અક્ષર *sigtype = ખાલી;

	જો (k == ખાલી || k->cert == ખાલી ||
	    k->cert->certblob == ખાલી || ca == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (!sshkey_is_cert(k))
		પાછા SSH_ERR_ચાવી_TYPE_UNKNOWN;
	જો (!sshkey_type_is_valid_ca(ca->type))
		પાછા SSH_ERR_ચાવી_CERT_INVALID_SIGN_ચાવી;
	જો ((impl = sshkey_impl_from_ચાવી(k)) == ખાલી)
		પાછા SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	જો (alg == ખાલી)
		alg = k->cert->signature_type;
	નહીંતર જો (k->cert->signature_type != ખાલી &&
	    strcmp(alg, k->cert->signature_type) != 0)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	જો (alg == ખાલી && ca->type == ચાવી_RSA)
		alg = "rsa-sha2-512";

	જો ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		પાછા SSH_ERR_ચાવી_CERT_INVALID_SIGN_ચાવી;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	જો ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		જાઓ out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, કદ(nonce));
	જો ((ret = sshbuf_put_string(cert, nonce, કદ(nonce))) != 0)
		જાઓ out;

	/* Public key next */
	જો ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		જાઓ out;

	/* Then remaining cert fields */
	જો ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->ચાવી_id)) != 0)
		જાઓ out;

	જો ((principals = sshbuf_new()) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	માટે (i = 0; i < k->cert->nprincipals; i++) {
		જો ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			જાઓ out;
	}
	જો ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, ખાલી, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		જાઓ out;

	/* Sign the whole mess */
	જો ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		જાઓ out;
	/* Check and update signature_type against what was actually used */
	જો ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		જાઓ out;
	જો (alg != ખાલી && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		જાઓ out;
	}
	જો (k->cert->signature_type == ખાલી) {
		k->cert->signature_type = sigtype;
		sigtype = ખાલી;
	}
	/* Append signature and we are done */
	જો ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		જાઓ out;
	ret = 0;
 out:
	જો (ret != 0)
		sshbuf_reset(cert);
	મુક્ત(sig_blob);
	મુક્ત(ca_blob);
	મુક્ત(sigtype);
	sshbuf_free(principals);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
default_ચાવી_sign(સંરચના sshkey *ચાવી, u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen,
    અચલ અક્ષર *alg, અચલ અક્ષર *sk_provider, અચલ અક્ષર *sk_pin,
    u_int compat, શૂન્ય *ctx)
{
	જો (ctx != ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	પાછા sshkey_sign(ચાવી, sigp, lenp, data, datalen, alg,
	    sk_provider, sk_pin, compat);
}

પૂર્ણાંક
sshkey_certify(સંરચના sshkey *k, સંરચના sshkey *ca, અચલ અક્ષર *alg,
    અચલ અક્ષર *sk_provider, અચલ અક્ષર *sk_pin)
{
	પાછા sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_ચાવી_sign, ખાલી);
}

પૂર્ણાંક
sshkey_cert_check_authority(અચલ સંરચના sshkey *k,
    પૂર્ણાંક want_host, પૂર્ણાંક wildcard_pattern, uint64_t verify_time,
    અચલ અક્ષર *name, અચલ અક્ષર **reason)
{
	u_int i, principal_matches;

	જો (reason == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		પાછા SSH_ERR_ચાવી_CERT_INVALID;
	}
	જો (want_host) {
		જો (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			પાછા SSH_ERR_ચાવી_CERT_INVALID;
		}
	} નહીંતર {
		જો (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			પાછા SSH_ERR_ચાવી_CERT_INVALID;
		}
	}
	જો (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		પાછા SSH_ERR_ચાવી_CERT_INVALID;
	}
	જો (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		પાછા SSH_ERR_ચાવી_CERT_INVALID;
	}
	જો (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		પાછા SSH_ERR_ચાવી_CERT_INVALID;
	}
	જો (name == ખાલી)
		પાછા 0; /* principal matching not requested */

	principal_matches = 0;
	માટે (i = 0; i < k->cert->nprincipals; i++) {
		જો (wildcard_pattern) {
			જો (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				તોડો;
			}
		} નહીંતર જો (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			તોડો;
		}
	}
	જો (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		પાછા SSH_ERR_ચાવી_CERT_INVALID;
	}
	પાછા 0;
}

પૂર્ણાંક
sshkey_cert_check_authority_now(અચલ સંરચના sshkey *k,
    પૂર્ણાંક want_host, પૂર્ણાંક wildcard_pattern, અચલ અક્ષર *name,
    અચલ અક્ષર **reason)
{
	time_t now;

	જો ((now = time(ખાલી)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		પાછા SSH_ERR_ચાવી_CERT_INVALID;
	}
	પાછા sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

પૂર્ણાંક
sshkey_cert_check_host(અચલ સંરચના sshkey *ચાવી, અચલ અક્ષર *host,
    અચલ અક્ષર *ca_sign_algorithms, અચલ અક્ષર **reason)
{
	પૂર્ણાંક r;

	જો ((r = sshkey_cert_check_authority_now(ચાવી, 1, 1, host, reason)) != 0)
		પાછા r;
	જો (sshbuf_len(ચાવી->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		પાછા SSH_ERR_ચાવી_CERT_INVALID;
	}
	જો (ca_sign_algorithms != ખાલી &&
	    (r = sshkey_check_cert_sigtype(ચાવી, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		પાછા SSH_ERR_ચાવી_CERT_INVALID;
	}
	પાછા 0;
}

size_t
sshkey_format_cert_validity(અચલ સંરચના sshkey_cert *cert, અક્ષર *s, size_t l)
{
	અક્ષર from[32], to[32], ret[128];

	*from = *to = '\0';
	જો (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		પાછા strlcpy(s, "forever", l);

	જો (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, કદ(from));
	જો (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, કદ(to));

	જો (cert->valid_after == 0)
		snprintf(ret, કદ(ret), "before %s", to);
	નહીંતર જો (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, કદ(ret), "after %s", from);
	નહીંતર
		snprintf(ret, કદ(ret), "from %s to %s", from, to);

	પાછા strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
પૂર્ણાંક
sshkey_serialize_private_sk(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_put_cstring(b, ચાવી->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, ચાવી->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, ચાવી->sk_ચાવી_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, ચાવી->sk_reserved)) != 0)
		પાછા r;

	પાછા 0;
}

સ્થિર પૂર્ણાંક
sshkey_private_serialize_opt(સંરચના sshkey *ચાવી, સંરચના sshbuf *buf,
    ગણના sshkey_serialize_rep opts)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	પૂર્ણાંક was_shielded = sshkey_is_shielded(ચાવી);
	સંરચના sshbuf *b = ખાલી;
	અચલ સંરચના sshkey_impl *impl;

	જો ((impl = sshkey_impl_from_ચાવી(ચાવી)) == ખાલી)
		પાછા SSH_ERR_INTERNAL_ERROR;
	જો ((r = sshkey_unshield_private(ચાવી)) != 0)
		પાછા r;
	જો ((b = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put_cstring(b, sshkey_ssh_name(ચાવી))) != 0)
		જાઓ out;
	જો (sshkey_is_cert(ચાવી)) {
		જો (ચાવી->cert == ખાલી ||
		    sshbuf_len(ચાવી->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			જાઓ out;
		}
		જો ((r = sshbuf_put_stringb(b, ચાવી->cert->certblob)) != 0)
			જાઓ out;
	}
	જો ((r = impl->funcs->serialize_private(ચાવી, b, opts)) != 0)
		જાઓ out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	જો (was_shielded)
		r = sshkey_shield_private(ચાવી);
	જો (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	પાછા r;
}

પૂર્ણાંક
sshkey_private_serialize(સંરચના sshkey *ચાવી, સંરચના sshbuf *b)
{
	પાછા sshkey_private_serialize_opt(ચાવી, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
પૂર્ણાંક
sshkey_private_deserialize_sk(સંરચના sshbuf *buf, સંરચના sshkey *k)
{
	પૂર્ણાંક r;

	જો ((k->sk_ચાવી_handle = sshbuf_new()) == ખાલી ||
	    (k->sk_reserved = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_get_cstring(buf, &k->sk_application, ખાલી)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_ચાવી_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		પાછા r;

	પાછા 0;
}

પૂર્ણાંક
sshkey_private_deserialize(સંરચના sshbuf *buf, સંરચના sshkey **kp)
{
	અચલ સંરચના sshkey_impl *impl;
	અક્ષર *tname = ખાલી;
	અક્ષર *expect_sk_application = ખાલી;
	u_char *expect_ed25519_pk = ખાલી;
	સંરચના sshkey *k = ખાલી;
	પૂર્ણાંક type, r = SSH_ERR_INTERNAL_ERROR;

	જો (kp != ખાલી)
		*kp = ખાલી;
	જો ((r = sshbuf_get_cstring(buf, &tname, ખાલી)) != 0)
		જાઓ out;
	type = sshkey_type_from_name(tname);
	જો (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		જો ((r = sshkey_froms(buf, &k)) != 0)
			જાઓ out;
		જો (k->type != type) {
			r = SSH_ERR_ચાવી_CERT_MISMATCH;
			જાઓ out;
		}
		/* For ECDSA keys, the group must match too */
		જો (k->type == ચાવી_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_ચાવી_CERT_MISMATCH;
			જાઓ out;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = ખાલી;
		k->ed25519_pk = ખાલી;
	} નહીંતર {
		જો ((k = sshkey_new(type)) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
	}
	જો ((impl = sshkey_impl_from_type(type)) == ખાલી) {
		r = SSH_ERR_INTERNAL_ERROR;
		જાઓ out;
	}
	જો ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		જાઓ out;

	જો ((expect_sk_application != ખાલી && (k->sk_application == ખાલી ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != ખાલી && (k->ed25519_pk == ખાલી ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_ચાવી_CERT_MISMATCH;
		જાઓ out;
	}
	/* success */
	r = 0;
	જો (kp != ખાલી) {
		*kp = k;
		k = ખાલી;
	}
 out:
	મુક્ત(tname);
	sshkey_free(k);
	મુક્ત(expect_sk_application);
	મુક્ત(expect_ed25519_pk);
	પાછા r;
}

#ifdef WITH_OPENSSL
પૂર્ણાંક
sshkey_ec_validate_public(અચલ EC_GROUP *group, અચલ EC_POINT *જાહેર)
{
	EC_POINT *nq = ખાલી;
	BIGNUM *order = ખાલી, *cofactor = ખાલી;
	પૂર્ણાંક ret = SSH_ERR_ચાવી_INVALID_EC_કિંમત;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	જો (EC_POINT_is_at_infinity(group, જાહેર))
		જાઓ out;

	જો ((cofactor = BN_new()) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (EC_GROUP_get_cofactor(group, cofactor, ખાલી) != 1)
		જાઓ out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	જો (!BN_is_one(cofactor)) {
		જો ((order = BN_new()) == ખાલી) {
			ret = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		જો (EC_GROUP_get_order(group, order, ખાલી) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			જાઓ out;
		}
		જો ((nq = EC_POINT_new(group)) == ખાલી) {
			ret = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		જો (EC_POINT_mul(group, nq, ખાલી, જાહેર, order, ખાલી) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			જાઓ out;
		}
		જો (EC_POINT_is_at_infinity(group, nq) != 1)
			જાઓ out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	પાછા ret;
}

પૂર્ણાંક
sshkey_ec_validate_private(અચલ EC_ચાવી *ચાવી)
{
	BIGNUM *order = ખાલી, *tmp = ખાલી;
	પૂર્ણાંક ret = SSH_ERR_ચાવી_INVALID_EC_કિંમત;

	જો ((order = BN_new()) == ખાલી || (tmp = BN_new()) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}

	/* log2(private) > log2(order)/2 */
	જો (EC_GROUP_get_order(EC_ચાવી_get0_group(ચાવી), order, ખાલી) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	જો (BN_અંક_bits(EC_ચાવી_get0_private_ચાવી(ચાવી)) <=
	    BN_અંક_bits(order) / 2)
		જાઓ out;

	/* private < order - 1 */
	જો (!BN_sub(tmp, order, BN_કિંમત_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	જો (BN_cmp(EC_ચાવી_get0_private_ચાવી(ચાવી), tmp) >= 0)
		જાઓ out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	પાછા ret;
}

શૂન્ય
sshkey_dump_ec_point(અચલ EC_GROUP *group, અચલ EC_POINT *point)
{
	BIGNUM *x = ખાલી, *y = ખાલી;

	જો (point == ખાલી) {
		fputs("point=(NULL)\n", stderr);
		પાછા;
	}
	જો ((x = BN_new()) == ખાલી || (y = BN_new()) == ખાલી) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		જાઓ out;
	}
	જો (EC_POINT_get_affine_coordinates(group, point, x, y, ખાલી) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		જાઓ out;
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

શૂન્ય
sshkey_dump_ec_ચાવી(અચલ EC_ચાવી *ચાવી)
{
	અચલ BIGNUM *exponent;

	sshkey_dump_ec_point(EC_ચાવી_get0_group(ચાવી),
	    EC_ચાવી_get0_public_ચાવી(ચાવી));
	fputs("exponent=", stderr);
	જો ((exponent = EC_ચાવી_get0_private_ચાવી(ચાવી)) == ખાલી)
		fputs("(NULL)", stderr);
	નહીંતર
		BN_print_fp(stderr, EC_ચાવી_get0_private_ચાવી(ચાવી));
	fputs("\n", stderr);
}
#endif /* WITH_OPENSSL */

સ્થિર પૂર્ણાંક
sshkey_private_to_blob2(સંરચના sshkey *prv, સંરચના sshbuf *blob,
    અચલ અક્ષર *passphrase, અચલ અક્ષર *comment, અચલ અક્ષર *ciphername,
    પૂર્ણાંક rounds)
{
	u_char *cp, *ચાવી = ખાલી, *pubkeyblob = ખાલી;
	u_char salt[SALT_LEN];
	size_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	સંરચના sshcipher_ctx *ciphercontext = ખાલી;
	અચલ સંરચના sshcipher *cipher;
	અચલ અક્ષર *kdfname = KDFNAME;
	સંરચના sshbuf *encoded = ખાલી, *encrypted = ખાલી, *kdf = ખાલી;

	જો (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	જો (rounds > MAX_KDF_ROUNDS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	જો (passphrase == ખાલી || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} નહીંતર જો (ciphername == ખાલી)
		ciphername = DEFAULT_CIPHERNAME;
	જો ((cipher = cipher_by_name(ciphername)) == ખાલી) {
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}

	જો ((kdf = sshbuf_new()) == ખાલી ||
	    (encoded = sshbuf_new()) == ખાલી ||
	    (encrypted = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	જો ((ચાવી = calloc(1, keylen + ivlen)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		જો (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, ચાવી, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			જાઓ out;
		}
		જો ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			જાઓ out;
	} નહીંતર જો (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_ચાવી_UNKNOWN_CIPHER;
		જાઓ out;
	}
	જો ((r = cipher_init(&ciphercontext, cipher, ચાવી, keylen,
	    ચાવી + keylen, ivlen, 1)) != 0)
		જાઓ out;

	જો ((r = sshbuf_put(encoded, AUTH_MAGIC, કદ(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_to_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		જાઓ out;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	જો ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		જાઓ out;

	/* append private key and comment*/
	જો ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		જાઓ out;

	/* padding */
	i = 0;
	જ્યારે (sshbuf_len(encrypted) % blocksize) {
		જો ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			જાઓ out;
	}

	/* length in destination buffer */
	જો ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		જાઓ out;

	/* encrypt */
	જો ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		જાઓ out;
	જો ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		જાઓ out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	જો ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_END, MARK_END_LEN)) != 0)
		જાઓ out;

	/* success */
	r = 0;

 out:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, કદ(salt));
	જો (ચાવી != ખાલી)
		freezero(ચાવી, keylen + ivlen);
	જો (pubkeyblob != ખાલી)
		freezero(pubkeyblob, pubkeylen);
	પાછા r;
}

સ્થિર પૂર્ણાંક
private2_uudecode(સંરચના sshbuf *blob, સંરચના sshbuf **decodedp)
{
	અચલ u_char *cp;
	size_t encoded_len;
	પૂર્ણાંક r;
	u_char last;
	સંરચના sshbuf *encoded = ખાલી, *decoded = ખાલી;

	જો (blob == ખાલી || decodedp == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	*decodedp = ખાલી;

	જો ((encoded = sshbuf_new()) == ખાલી ||
	    (decoded = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	જો (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	જ્યારે (encoded_len > 0) {
		જો (*cp != '\n' && *cp != '\r') {
			જો ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				જાઓ out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		જો (last == '\n') {
			જો (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				જો ((r = sshbuf_put_u8(encoded, 0)) != 0)
					જાઓ out;
				તોડો;
			}
		}
	}
	જો (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}

	/* decode base64 */
	જો ((r = sshbuf_b64tod(decoded, (અક્ષર *)sshbuf_ptr(encoded))) != 0)
		જાઓ out;

	/* check magic */
	જો (sshbuf_len(decoded) < કદ(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, કદ(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	/* success */
	*decodedp = decoded;
	decoded = ખાલી;
	r = 0;
 out:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	પાછા r;
}

સ્થિર પૂર્ણાંક
private2_decrypt(સંરચના sshbuf *decoded, અચલ અક્ષર *passphrase,
    સંરચના sshbuf **decryptedp, સંરચના sshkey **pubkeyp)
{
	અક્ષર *ciphername = ખાલી, *kdfname = ખાલી;
	અચલ સંરચના sshcipher *cipher = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	સંરચના sshbuf *kdf = ખાલી, *decrypted = ખાલી;
	સંરચના sshcipher_ctx *ciphercontext = ખાલી;
	સંરચના sshkey *pubkey = ખાલી;
	u_char *ચાવી = ખાલી, *salt = ખાલી, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	જો (decoded == ખાલી || decryptedp == ખાલી || pubkeyp == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = ખાલી;
	*pubkeyp = ખાલી;

	જો ((decrypted = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}

	/* parse public portion of key */
	જો ((r = sshbuf_consume(decoded, કદ(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, ખાલી)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		જાઓ out;

	જો (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}

	જો ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		જાઓ out;

	જો ((cipher = cipher_by_name(ciphername)) == ખાલી) {
		r = SSH_ERR_ચાવી_UNKNOWN_CIPHER;
		જાઓ out;
	}
	જો (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_ચાવી_UNKNOWN_CIPHER;
		જાઓ out;
	}
	જો (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો ((passphrase == ખાલી || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_ચાવી_WRONG_PASSPHRASE;
		જાઓ out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	જો (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	જો ((ચાવી = calloc(1, keylen + ivlen)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (strcmp(kdfname, "bcrypt") == 0) {
		જો ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			જાઓ out;
		જો (rounds > MAX_KDF_ROUNDS) {
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		જો (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    ચાવી, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	જો (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}

	/* decrypt private portion of key */
	જો ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, ચાવી, keylen,
	    ચાવી + keylen, ivlen, 0)) != 0)
		જાઓ out;
	જો ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		જો (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_ચાવી_WRONG_PASSPHRASE;
		જાઓ out;
	}
	જો ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		જાઓ out;
	/* there should be no trailing data */
	જો (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}

	/* check check bytes */
	જો ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		જાઓ out;
	જો (check1 != check2) {
		r = SSH_ERR_ચાવી_WRONG_PASSPHRASE;
		જાઓ out;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = ખાલી;
	*pubkeyp = pubkey;
	pubkey = ખાલી;
	r = 0;
 out:
	cipher_free(ciphercontext);
	મુક્ત(ciphername);
	મુક્ત(kdfname);
	sshkey_free(pubkey);
	જો (salt != ખાલી) {
		explicit_bzero(salt, slen);
		મુક્ત(salt);
	}
	જો (ચાવી != ખાલી) {
		explicit_bzero(ચાવી, keylen + ivlen);
		મુક્ત(ચાવી);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	પાછા r;
}

સ્થિર પૂર્ણાંક
sshkey_parse_private2(સંરચના sshbuf *blob, પૂર્ણાંક type, અચલ અક્ષર *passphrase,
    સંરચના sshkey **keyp, અક્ષર **commentp)
{
	અક્ષર *comment = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	સંરચના sshbuf *decoded = ખાલી, *decrypted = ખાલી;
	સંરચના sshkey *k = ખાલી, *pubkey = ખાલી;

	જો (keyp != ખાલી)
		*keyp = ખાલી;
	જો (commentp != ખાલી)
		*commentp = ખાલી;

	/* Undo base64 encoding and decrypt the private section */
	જો ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		જાઓ out;

	જો (type != ચાવી_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_ચાવી_TYPE_MISMATCH;
		જાઓ out;
	}

	/* Load the private key and comment */
	જો ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, ખાલી)) != 0)
		જાઓ out;

	/* Check deterministic padding after private section */
	જો ((r = private2_check_padding(decrypted)) != 0)
		જાઓ out;

	/* Check that the public key in the envelope matches the private key */
	જો (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}

	/* success */
	r = 0;
	જો (keyp != ખાલી) {
		*keyp = k;
		k = ખાલી;
	}
	જો (commentp != ખાલી) {
		*commentp = comment;
		comment = ખાલી;
	}
 out:
	મુક્ત(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	પાછા r;
}

સ્થિર પૂર્ણાંક
sshkey_parse_private2_pubkey(સંરચના sshbuf *blob, પૂર્ણાંક type,
    સંરચના sshkey **keyp)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	સંરચના sshbuf *decoded = ખાલી;
	સંરચના sshkey *pubkey = ખાલી;
	u_int nkeys = 0;

	જો (keyp != ખાલી)
		*keyp = ખાલી;

	જો ((r = private2_uudecode(blob, &decoded)) != 0)
		જાઓ out;
	/* parse public key from unencrypted envelope */
	જો ((r = sshbuf_consume(decoded, કદ(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		જાઓ out;

	જો (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}

	/* Parse the public key */
	જો ((r = sshkey_froms(decoded, &pubkey)) != 0)
		જાઓ out;

	જો (type != ચાવી_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_ચાવી_TYPE_MISMATCH;
		જાઓ out;
	}

	/* success */
	r = 0;
	જો (keyp != ખાલી) {
		*keyp = pubkey;
		pubkey = ખાલી;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	પાછા r;
}

#ifdef WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
સ્થિર પૂર્ણાંક
sshkey_private_to_blob_pem_pkcs8(સંરચના sshkey *ચાવી, સંરચના sshbuf *buf,
    પૂર્ણાંક format, અચલ અક્ષર *_passphrase, અચલ અક્ષર *comment)
{
	પૂર્ણાંક was_shielded = sshkey_is_shielded(ચાવી);
	પૂર્ણાંક success, r;
	પૂર્ણાંક blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : ખાલી;
	અચલ EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : ખાલી;
	અક્ષર *bptr;
	BIO *bio = ખાલી;
	સંરચના sshbuf *blob;
	EVP_PKEY *pkey = ખાલી;

	જો (len > 0 && len <= 4)
		પાછા SSH_ERR_PASSPHRASE_TOO_SHORT;
	જો ((blob = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((bio = BIO_new(BIO_s_mem())) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshkey_unshield_private(ચાવી)) != 0)
		જાઓ out;

	પસંદગી (ચાવી->type) {
	સ્થિતિ ચાવી_ECDSA:
		જો (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivate_ચાવી(bio,
			    EVP_PKEY_get0_EC_ચાવી(ચાવી->pkey),
			    cipher, passphrase, len, ખાલી, ખાલી);
		} નહીંતર {
			pkey = ચાવી->pkey;
			EVP_PKEY_up_ref(ચાવી->pkey);
			success = 1;
		}
		તોડો;
	સ્થિતિ ચાવી_RSA:
		જો (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivate_ચાવી(bio,
			    EVP_PKEY_get0_RSA(ચાવી->pkey),
			    cipher, passphrase, len, ખાલી, ખાલી);
		} નહીંતર {
			pkey = ચાવી->pkey;
			EVP_PKEY_up_ref(ચાવી->pkey);
			success = 1;
		}
		તોડો;
#ifdef OPENSSL_HAS_ED25519
	સ્થિતિ ચાવી_ED25519:
		જો (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		} નહીંતર {
			pkey = EVP_PKEY_new_raw_private_ચાવી(EVP_PKEY_ED25519,
			    ખાલી, ચાવી->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != ખાલી;
		}
		તોડો;
#endif
	મૂળભૂત:
		success = 0;
		તોડો;
	}
	જો (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	જો (format == SSHKEY_PRIVATE_PKCS8) {
		જો ((success = PEM_write_bio_Private_ચાવી(bio, pkey, cipher,
		    passphrase, len, ખાલી, ખાલી)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			જાઓ out;
		}
	}
	જો ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		જાઓ out;
	}
	જો ((r = sshbuf_put(blob, bptr, blen)) != 0)
		જાઓ out;
	r = 0;
 out:
	જો (was_shielded)
		r = sshkey_shield_private(ચાવી);
	જો (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	પાછા r;
}
#endif /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
પૂર્ણાંક
sshkey_private_to_fileblob(સંરચના sshkey *ચાવી, સંરચના sshbuf *blob,
    અચલ અક્ષર *passphrase, અચલ અક્ષર *comment,
    પૂર્ણાંક format, અચલ અક્ષર *openssh_format_cipher, પૂર્ણાંક openssh_format_rounds)
{
	પસંદગી (ચાવી->type) {
#ifdef WITH_OPENSSL
	સ્થિતિ ચાવી_ECDSA:
	સ્થિતિ ચાવી_RSA:
	સ્થિતિ ચાવી_ED25519:
		તોડો; /* see below */
#નહીંતર /* WITH_OPENSSL */
	સ્થિતિ ચાવી_ED25519:
#endif /* WITH_OPENSSL */
	સ્થિતિ ચાવી_ED25519_SK:
#ifdef WITH_OPENSSL
	સ્થિતિ ચાવી_ECDSA_SK:
#endif /* WITH_OPENSSL */
	સ્થિતિ ચાવી_MLDSA44_ED25519:
		પાછા sshkey_private_to_blob2(ચાવી, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	મૂળભૂત:
		પાછા SSH_ERR_ચાવી_TYPE_UNKNOWN;
	}

#ifdef WITH_OPENSSL
	પસંદગી (format) {
	સ્થિતિ SSHKEY_PRIVATE_OPENSSH:
		પાછા sshkey_private_to_blob2(ચાવી, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	સ્થિતિ SSHKEY_PRIVATE_PEM:
	સ્થિતિ SSHKEY_PRIVATE_PKCS8:
		પાછા sshkey_private_to_blob_pem_pkcs8(ચાવી, blob,
		    format, passphrase, comment);
	મૂળભૂત:
		પાછા SSH_ERR_INVALID_ARGUMENT;
	}
#endif /* WITH_OPENSSL */
}

#ifdef WITH_OPENSSL
સ્થિર પૂર્ણાંક
translate_libcrypto_error(unsigned long pem_err)
{
	પૂર્ણાંક pem_reason = ERR_GET_REASON(pem_err);

	પસંદગી (ERR_GET_LIB(pem_err)) {
	સ્થિતિ ERR_LIB_PEM:
		પસંદગી (pem_reason) {
		સ્થિતિ PEM_R_BAD_PASSWORD_READ:
#ifdef PEM_R_PROBLEMS_GETTING_PASSWORD
		સ્થિતિ PEM_R_PROBLEMS_GETTING_PASSWORD:
#endif
#ifdef PEM_R_BAD_DECRYPT
		સ્થિતિ PEM_R_BAD_DECRYPT:
#endif
			પાછા SSH_ERR_ચાવી_WRONG_PASSPHRASE;
		મૂળભૂત:
			પાછા SSH_ERR_INVALID_FORMAT;
		}
	સ્થિતિ ERR_LIB_EVP:
		પસંદગી (pem_reason) {
#ifdef EVP_R_BAD_DECRYPT
		સ્થિતિ EVP_R_BAD_DECRYPT:
			પાછા SSH_ERR_ચાવી_WRONG_PASSPHRASE;
#endif
#ifdef EVP_R_BN_DECODE_ERROR
		સ્થિતિ EVP_R_BN_DECODE_ERROR:
#endif
		સ્થિતિ EVP_R_DECODE_ERROR:
#ifdef EVP_R_PRIVATE_ચાવી_DECODE_ERROR
		સ્થિતિ EVP_R_PRIVATE_ચાવી_DECODE_ERROR:
#endif
			પાછા SSH_ERR_INVALID_FORMAT;
		મૂળભૂત:
			પાછા SSH_ERR_LIBCRYPTO_ERROR;
		}
	સ્થિતિ ERR_LIB_ASN1:
#ifdef ERR_LIB_OSSL_DECODER
	સ્થિતિ ERR_LIB_OSSL_DECODER:
#endif
		પાછા SSH_ERR_INVALID_FORMAT;
	}
	પાછા SSH_ERR_LIBCRYPTO_ERROR;
}

સ્થિર શૂન્ય
clear_libcrypto_errors(શૂન્ય)
{
	જ્યારે (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
સ્થિર પૂર્ણાંક
convert_libcrypto_error(શૂન્ય)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	જો (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_ચાવી_WRONG_PASSPHRASE)
		પાછા SSH_ERR_ચાવી_WRONG_PASSPHRASE;
	પાછા translate_libcrypto_error(ERR_peek_last_error());
}

સ્થિર પૂર્ણાંક
pem_passphrase_cb(અક્ષર *buf, પૂર્ણાંક size, પૂર્ણાંક rwflag, શૂન્ય *u)
{
	અક્ષર *p = (અક્ષર *)u;
	size_t len;

	જો (p == ખાલી || (len = strlen(p)) == 0)
		પાછા -1;
	જો (size < 0 || len > (size_t)size)
		પાછા -1;
	memcpy(buf, p, len);
	પાછા (પૂર્ણાંક)len;
}

સ્થિર પૂર્ણાંક
sshkey_parse_private_pem_fileblob(સંરચના sshbuf *blob, પૂર્ણાંક type,
    અચલ અક્ષર *passphrase, સંરચના sshkey **keyp)
{
	EVP_PKEY *pk = ખાલી;
	સંરચના sshkey *prv = ખાલી;
	BIO *bio = ખાલી;
	પૂર્ણાંક r;
	RSA *rsa = ખાલી;
	EC_ચાવી *ecdsa = ખાલી;

	જો (keyp != ખાલી)
		*keyp = ખાલી;

	જો ((bio = BIO_new(BIO_s_mem())) == ખાલી || sshbuf_len(blob) > INT_MAX)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (પૂર્ણાંક)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}

	clear_libcrypto_errors();
	જો ((pk = PEM_read_bio_Private_ચાવી(bio, ખાલી, pem_passphrase_cb,
	    (અક્ષર *)passphrase)) == ખાલી) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		જો (passphrase != ખાલી && *passphrase != '\0')
			r = SSH_ERR_ચાવી_WRONG_PASSPHRASE;
		નહીંતર
			r = convert_libcrypto_error();
		જાઓ out;
	}
	જો (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == ચાવી_UNSPEC || type == ચાવી_RSA)) {
		જો ((prv = sshkey_new(ચાવી_UNSPEC)) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		જો ((rsa = EVP_PKEY_get1_RSA(pk)) == ખાલી) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			જાઓ out;
		}
		prv->type = ચાવી_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#endif
		જો (RSA_blinding_on(rsa, ખાલી) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			જાઓ out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		જો ((r = sshkey_check_rsa_length(prv, 0)) != 0)
			જાઓ out;
	} નહીંતર જો (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == ચાવી_UNSPEC || type == ચાવી_ECDSA)) {
		જો ((prv = sshkey_new(ચાવી_UNSPEC)) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		જો ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_ચાવી(pk)) == ખાલી) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			જાઓ out;
		}
		prv->type = ચાવી_ECDSA;
		જો (sshkey_curve_nid_to_name(prv->ecdsa_nid) == ખાલી ||
		    sshkey_ec_validate_public(EC_ચાવી_get0_group(ecdsa),
		    EC_ચાવી_get0_public_ચાવી(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#ifdef DEBUG_PK
		જો (prv != ખાલી && prv->pkey != ખાલી)
			sshkey_dump_ec_ચાવી(EVP_PKEY_get0_EC_ચાવી(prv->pkey));
#endif
#ifdef OPENSSL_HAS_ED25519
	} નહીંતર જો (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == ચાવી_UNSPEC || type == ચાવી_ED25519)) {
		size_t len;

		જો ((prv = sshkey_new(ચાવી_UNSPEC)) == ખાલી ||
		    (prv->ed25519_sk = calloc(1, ED25519_SK_SZ)) == ખાલી ||
		    (prv->ed25519_pk = calloc(1, ED25519_PK_SZ)) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		prv->type = ચાવી_ED25519;
		len = ED25519_PK_SZ;
		જો (!EVP_PKEY_get_raw_public_ચાવી(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			જાઓ out;
		}
		જો (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		જો (!EVP_PKEY_get_raw_private_ચાવી(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			જાઓ out;
		}
		જો (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		/* Append the public key to our private key */
		memcpy(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#ifdef DEBUG_PK
		sshbuf_dump_data(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#endif
#endif /* OPENSSL_HAS_ED25519 */
	} નહીંતર {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	r = 0;
	જો (keyp != ખાલી) {
		*keyp = prv;
		prv = ખાલી;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_ચાવી_free(ecdsa);
	sshkey_free(prv);
	પાછા r;
}
#endif /* WITH_OPENSSL */

પૂર્ણાંક
sshkey_parse_private_fileblob_type(સંરચના sshbuf *blob, પૂર્ણાંક type,
    અચલ અક્ષર *passphrase, સંરચના sshkey **keyp, અક્ષર **commentp)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો (keyp != ખાલી)
		*keyp = ખાલી;
	જો (commentp != ખાલી)
		*commentp = ખાલી;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	જો (r != SSH_ERR_INVALID_FORMAT)
		પાછા r;
#ifdef WITH_OPENSSL
	પાછા sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#નહીંતર
	પાછા SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

પૂર્ણાંક
sshkey_parse_private_fileblob(સંરચના sshbuf *buffer, અચલ અક્ષર *passphrase,
    સંરચના sshkey **keyp, અક્ષર **commentp)
{
	જો (keyp != ખાલી)
		*keyp = ખાલી;
	જો (commentp != ખાલી)
		*commentp = ખાલી;

	પાછા sshkey_parse_private_fileblob_type(buffer, ચાવી_UNSPEC,
	    passphrase, keyp, commentp);
}

શૂન્ય
sshkey_sig_details_free(સંરચના sshkey_sig_details *details)
{
	freezero(details, કદ(*details));
}

પૂર્ણાંક
sshkey_parse_pubkey_from_private_fileblob_type(સંરચના sshbuf *blob, પૂર્ણાંક type,
    સંરચના sshkey **pubkeyp)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો (pubkeyp != ખાલી)
		*pubkeyp = ખાલી;
	/* only new-format private keys bundle a public key inside */
	જો ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		પાછા r;
	પાછા 0;
}
