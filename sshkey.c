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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/mman.h>
#অন্তর্ভাব <netinet/in.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/evp.h>
#অন্তর্ভাব <openssl/err.h>
#অন্তর্ভাব <openssl/pem.h>
#endif

#অন্তর্ভাব "crypto_api.h"

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <resolv.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <util.h>

#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "digest.h"
#define SSHKEY_INTERNAL
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "ssh-sk.h"
#অন্তর্ভাব "ssh-pkcs11.h"

#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#define MARK_BEGIN_LEN		(পরিমাণ(MARK_BEGIN) - 1)
#define MARK_END_LEN		(পরিমাণ(MARK_END) - 1)
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

স্থির পূর্ণাঙ্ক sshkey_from_blob_internal(সংরচনা sshbuf *buf,
    সংরচনা sshkey **keyp, পূর্ণাঙ্ক allow_cert,
    ধ্রুব বর্ণ *alg_allowlist, ধ্রুব বর্ণ *ca_sigalg_allowlist);

/* Supported key types */
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_ed25519_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_ed25519_cert_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_ed25519_sk_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_mldsa44_ed25519_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#ifdef WITH_OPENSSL
# ifdef ENABLE_SK
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_ecdsa_sk_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_ecdsa_sk_cert_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_ecdsa_nistp256_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_ecdsa_nistp384_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_ecdsa_nistp521_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_rsa_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_rsa_cert_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_rsa_sha256_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_rsa_sha256_cert_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_rsa_sha512_impl;
বাহ্য ধ্রুব সংরচনা sshkey_impl sshkey_rsa_sha512_cert_impl;
#endif /* WITH_OPENSSL */

ধ্রুব সংরচনা sshkey_impl * ধ্রুব keyimpls[] = {
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
	রিক্ত
};

স্থির ধ্রুব সংরচনা sshkey_impl *
sshkey_impl_from_type(পূর্ণাঙ্ক type)
{
	পূর্ণাঙ্ক i;

	প্রতি (i = 0; keyimpls[i] != রিক্ত; i++) {
		যদি (keyimpls[i]->type == type)
			প্রত্যাগম keyimpls[i];
	}
	প্রত্যাগম রিক্ত;
}

স্থির ধ্রুব সংরচনা sshkey_impl *
sshkey_impl_from_type_nid(পূর্ণাঙ্ক type, পূর্ণাঙ্ক nid)
{
	পূর্ণাঙ্ক i;

	প্রতি (i = 0; keyimpls[i] != রিক্ত; i++) {
		যদি (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			প্রত্যাগম keyimpls[i];
	}
	প্রত্যাগম রিক্ত;
}

স্থির ধ্রুব সংরচনা sshkey_impl *
sshkey_impl_from_চাবি(ধ্রুব সংরচনা sshkey *k)
{
	যদি (k == রিক্ত)
		প্রত্যাগম রিক্ত;
	প্রত্যাগম sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

ধ্রুব বর্ণ *
sshkey_type(ধ্রুব সংরচনা sshkey *k)
{
	ধ্রুব সংরচনা sshkey_impl *impl;

	যদি ((impl = sshkey_impl_from_চাবি(k)) == রিক্ত)
		প্রত্যাগম "unknown";
	প্রত্যাগম impl->shortname;
}

স্থির ধ্রুব বর্ণ *
sshkey_ssh_name_from_type_nid(পূর্ণাঙ্ক type, পূর্ণাঙ্ক nid)
{
	ধ্রুব সংরচনা sshkey_impl *impl;

	যদি ((impl = sshkey_impl_from_type_nid(type, nid)) == রিক্ত)
		প্রত্যাগম "ssh-unknown";
	প্রত্যাগম impl->name;
}

পূর্ণাঙ্ক
sshkey_type_is_cert(পূর্ণাঙ্ক type)
{
	ধ্রুব সংরচনা sshkey_impl *impl;

	যদি ((impl = sshkey_impl_from_type(type)) == রিক্ত)
		প্রত্যাগম 0;
	প্রত্যাগম impl->cert;
}

ধ্রুব বর্ণ *
sshkey_ssh_name(ধ্রুব সংরচনা sshkey *k)
{
	প্রত্যাগম sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

ধ্রুব বর্ণ *
sshkey_ssh_name_plain(ধ্রুব সংরচনা sshkey *k)
{
	প্রত্যাগম sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

স্থির পূর্ণাঙ্ক
type_from_name(ধ্রুব বর্ণ *name, পূর্ণাঙ্ক allow_short)
{
	পূর্ণাঙ্ক i;
	ধ্রুব সংরচনা sshkey_impl *impl;

	প্রতি (i = 0; keyimpls[i] != রিক্ত; i++) {
		impl = keyimpls[i];
		যদি (impl->name != রিক্ত && strcmp(name, impl->name) == 0)
			প্রত্যাগম impl->type;
		/* Only allow shortname matches for plain key types */
		যদি (allow_short && !impl->cert && impl->shortname != রিক্ত &&
		    strcasecmp(impl->shortname, name) == 0)
			প্রত্যাগম impl->type;
	}
	প্রত্যাগম চাবি_UNSPEC;
}

পূর্ণাঙ্ক
sshkey_type_from_name(ধ্রুব বর্ণ *name)
{
	প্রত্যাগম type_from_name(name, 0);
}

পূর্ণাঙ্ক
sshkey_type_from_shortname(ধ্রুব বর্ণ *name)
{
	প্রত্যাগম type_from_name(name, 1);
}

স্থির পূর্ণাঙ্ক
চাবি_type_is_ecdsa_variant(পূর্ণাঙ্ক type)
{
	বিকল্প (type) {
	পক্ষ চাবি_ECDSA:
	পক্ষ চাবি_ECDSA_CERT:
	পক্ষ চাবি_ECDSA_SK:
	পক্ষ চাবি_ECDSA_SK_CERT:
		প্রত্যাগম 1;
	}
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshkey_ecdsa_nid_from_name(ধ্রুব বর্ণ *name)
{
	পূর্ণাঙ্ক i;

	প্রতি (i = 0; keyimpls[i] != রিক্ত; i++) {
		যদি (!চাবি_type_is_ecdsa_variant(keyimpls[i]->type))
			অনুবর্ত;
		যদি (keyimpls[i]->name != রিক্ত &&
		    strcmp(name, keyimpls[i]->name) == 0)
			প্রত্যাগম keyimpls[i]->nid;
	}
	প্রত্যাগম -1;
}

পূর্ণাঙ্ক
sshkey_match_keyname_to_sigalgs(ধ্রুব বর্ণ *keyname, ধ্রুব বর্ণ *sigalgs)
{
	পূর্ণাঙ্ক ktype;

	যদি (sigalgs == রিক্ত || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == চাবি_UNSPEC)
		প্রত্যাগম 0;
	অন্যথা যদি (ktype == চাবি_RSA) {
		প্রত্যাগম match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} অন্যথা যদি (ktype == চাবি_RSA_CERT) {
		প্রত্যাগম match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} অন্যথা যদি (ktype == চাবি_ECDSA_SK) {
		প্রত্যাগম match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} অন্যথা যদি (ktype == চাবি_ECDSA_SK_CERT) {
		প্রত্যাগম match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} অন্যথা
		প্রত্যাগম match_pattern_list(keyname, sigalgs, 0) == 1;
}

বর্ণ *
sshkey_alg_list(পূর্ণাঙ্ক certs_only, পূর্ণাঙ্ক plain_only, পূর্ণাঙ্ক include_sigonly, বর্ণ sep)
{
	বর্ণ *ret = রিক্ত;
	size_t i;
	ধ্রুব সংরচনা sshkey_impl *impl;
	বর্ণ sep_str[2] = {sep, '\0'};

	প্রতি (i = 0; keyimpls[i] != রিক্ত; i++) {
		impl = keyimpls[i];
		যদি (impl->name == রিক্ত)
			অনুবর্ত;
		যদি (!include_sigonly && impl->sigonly)
			অনুবর্ত;
		যদি ((certs_only && !impl->cert) || (plain_only && impl->cert))
			অনুবর্ত;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
sshkey_names_valid2(ধ্রুব বর্ণ *names, পূর্ণাঙ্ক allow_wildcard, পূর্ণাঙ্ক plain_only)
{
	বর্ণ *s, *cp, *p;
	ধ্রুব সংরচনা sshkey_impl *impl;
	পূর্ণাঙ্ক i, type;

	যদি (names == রিক্ত || strcmp(names, "") == 0)
		প্রত্যাগম 0;
	যদি ((s = cp = strdup(names)) == রিক্ত)
		প্রত্যাগম 0;
	প্রতি ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		যদি (type == চাবি_UNSPEC) {
			যদি (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = রিক্ত;
				প্রতি (i = 0; keyimpls[i] != রিক্ত; i++) {
					যদি (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						ভঙ্গ;
					}
				}
				যদি (impl != রিক্ত)
					অনুবর্ত;
			}
			মুক্ত(s);
			প্রত্যাগম 0;
		} অন্যথা যদি (plain_only && sshkey_type_is_cert(type)) {
			মুক্ত(s);
			প্রত্যাগম 0;
		}
	}
	মুক্ত(s);
	প্রত্যাগম 1;
}

u_int
sshkey_size(ধ্রুব সংরচনা sshkey *k)
{
	ধ্রুব সংরচনা sshkey_impl *impl;

	যদি ((impl = sshkey_impl_from_চাবি(k)) == রিক্ত)
		প্রত্যাগম 0;
	যদি (impl->funcs->size != রিক্ত)
		প্রত্যাগম impl->funcs->size(k);
	প্রত্যাগম impl->keybits;
}

স্থির পূর্ণাঙ্ক
sshkey_type_is_valid_ca(পূর্ণাঙ্ক type)
{
	ধ্রুব সংরচনা sshkey_impl *impl;

	যদি ((impl = sshkey_impl_from_type(type)) == রিক্ত)
		প্রত্যাগম 0;
	/* All non-certificate types may act as CAs */
	প্রত্যাগম !impl->cert;
}

পূর্ণাঙ্ক
sshkey_is_cert(ধ্রুব সংরচনা sshkey *k)
{
	যদি (k == রিক্ত)
		প্রত্যাগম 0;
	প্রত্যাগম sshkey_type_is_cert(k->type);
}

পূর্ণাঙ্ক
sshkey_is_sk(ধ্রুব সংরচনা sshkey *k)
{
	যদি (k == রিক্ত)
		প্রত্যাগম 0;
	বিকল্প (sshkey_type_plain(k->type)) {
	পক্ষ চাবি_ECDSA_SK:
	পক্ষ চাবি_ED25519_SK:
		প্রত্যাগম 1;
	স্বভাব:
		প্রত্যাগম 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
পূর্ণাঙ্ক
sshkey_type_plain(পূর্ণাঙ্ক type)
{
	বিকল্প (type) {
	পক্ষ চাবি_RSA_CERT:
		প্রত্যাগম চাবি_RSA;
	পক্ষ চাবি_ECDSA_CERT:
		প্রত্যাগম চাবি_ECDSA;
	পক্ষ চাবি_ECDSA_SK_CERT:
		প্রত্যাগম চাবি_ECDSA_SK;
	পক্ষ চাবি_ED25519_CERT:
		প্রত্যাগম চাবি_ED25519;
	পক্ষ চাবি_MLDSA44_ED25519_CERT:
		প্রত্যাগম চাবি_MLDSA44_ED25519;
	পক্ষ চাবি_ED25519_SK_CERT:
		প্রত্যাগম চাবি_ED25519_SK;
	স্বভাব:
		প্রত্যাগম type;
	}
}

/* Return the cert equivalent to a plain key type */
স্থির পূর্ণাঙ্ক
sshkey_type_certified(পূর্ণাঙ্ক type)
{
	বিকল্প (type) {
	পক্ষ চাবি_RSA:
		প্রত্যাগম চাবি_RSA_CERT;
	পক্ষ চাবি_ECDSA:
		প্রত্যাগম চাবি_ECDSA_CERT;
	পক্ষ চাবি_ECDSA_SK:
		প্রত্যাগম চাবি_ECDSA_SK_CERT;
	পক্ষ চাবি_ED25519:
		প্রত্যাগম চাবি_ED25519_CERT;
	পক্ষ চাবি_MLDSA44_ED25519:
		প্রত্যাগম চাবি_MLDSA44_ED25519_CERT;
	পক্ষ চাবি_ED25519_SK:
		প্রত্যাগম চাবি_ED25519_SK_CERT;
	স্বভাব:
		প্রত্যাগম -1;
	}
}

#ifdef WITH_OPENSSL
স্থির ধ্রুব EVP_MD *
ssh_digest_to_md(পূর্ণাঙ্ক hash_alg)
{
	বিকল্প (hash_alg) {
	পক্ষ SSH_DIGEST_SHA1:
		প্রত্যাগম EVP_sha1();
	পক্ষ SSH_DIGEST_SHA256:
		প্রত্যাগম EVP_sha256();
	পক্ষ SSH_DIGEST_SHA384:
		প্রত্যাগম EVP_sha384();
	পক্ষ SSH_DIGEST_SHA512:
		প্রত্যাগম EVP_sha512();
	}
	প্রত্যাগম রিক্ত;
}

পূর্ণাঙ্ক
sshkey_pkey_digest_sign(EVP_PKEY *pkey, পূর্ণাঙ্ক hash_alg, u_char **sigp,
    size_t *lenp, ধ্রুব u_char *data, size_t datalen)
{
	EVP_MD_CTX *ctx = রিক্ত;
	u_char *sig = রিক্ত;
	পূর্ণাঙ্ক ret;
	size_t slen;
	ধ্রুব EVP_MD *evpmd;

	*sigp = রিক্ত;
	*lenp = 0;

	slen = EVP_PKEY_size(pkey);
	যদি (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	যদি ((sig = malloc(slen)) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;

	যদি ((ctx = EVP_MD_CTX_new()) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (EVP_DigestSignInit(ctx, রিক্ত, evpmd, রিক্ত, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, data, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = রিক্ত;
	ret = 0;

 out:
	EVP_MD_CTX_free(ctx);
	মুক্ত(sig);
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
sshkey_pkey_digest_verify(EVP_PKEY *pkey, পূর্ণাঙ্ক hash_alg, ধ্রুব u_char *data,
    size_t datalen, u_char *sigbuf, size_t siglen)
{
	EVP_MD_CTX *ctx = রিক্ত;
	পূর্ণাঙ্ক ret = SSH_ERR_INTERNAL_ERROR;
	ধ্রুব EVP_MD *evpmd;

	যদি ((evpmd = ssh_digest_to_md(hash_alg)) == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি ((ctx = EVP_MD_CTX_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি (EVP_DigestVerifyInit(ctx, রিক্ত, evpmd, রিক্ত, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	বিকল্প (EVP_DigestVerify(ctx, sigbuf, siglen, data, datalen)) {
	পক্ষ 1:
		ret = 0;
		ভঙ্গ;
	পক্ষ 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		ভঙ্গ;
	স্বভাব:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ভঙ্গ;
	}

 out:
	EVP_MD_CTX_free(ctx);
	প্রত্যাগম ret;
}

/* XXX: these are really begging for a table-driven approach */
পূর্ণাঙ্ক
sshkey_curve_name_to_nid(ধ্রুব বর্ণ *name)
{
	যদি (strcmp(name, "nistp256") == 0)
		প্রত্যাগম NID_X9_62_prime256v1;
	অন্যথা যদি (strcmp(name, "nistp384") == 0)
		প্রত্যাগম NID_secp384r1;
	অন্যথা যদি (strcmp(name, "nistp521") == 0)
		প্রত্যাগম NID_secp521r1;
	অন্যথা
		প্রত্যাগম -1;
}

u_int
sshkey_curve_nid_to_bits(পূর্ণাঙ্ক nid)
{
	বিকল্প (nid) {
	পক্ষ NID_X9_62_prime256v1:
		প্রত্যাগম 256;
	পক্ষ NID_secp384r1:
		প্রত্যাগম 384;
	পক্ষ NID_secp521r1:
		প্রত্যাগম 521;
	স্বভাব:
		প্রত্যাগম 0;
	}
}

পূর্ণাঙ্ক
sshkey_ecdsa_bits_to_nid(পূর্ণাঙ্ক bits)
{
	বিকল্প (bits) {
	পক্ষ 256:
		প্রত্যাগম NID_X9_62_prime256v1;
	পক্ষ 384:
		প্রত্যাগম NID_secp384r1;
	পক্ষ 521:
		প্রত্যাগম NID_secp521r1;
	স্বভাব:
		প্রত্যাগম -1;
	}
}

ধ্রুব বর্ণ *
sshkey_curve_nid_to_name(পূর্ণাঙ্ক nid)
{
	বিকল্প (nid) {
	পক্ষ NID_X9_62_prime256v1:
		প্রত্যাগম "nistp256";
	পক্ষ NID_secp384r1:
		প্রত্যাগম "nistp384";
	পক্ষ NID_secp521r1:
		প্রত্যাগম "nistp521";
	স্বভাব:
		প্রত্যাগম রিক্ত;
	}
}

পূর্ণাঙ্ক
sshkey_ec_nid_to_hash_alg(পূর্ণাঙ্ক nid)
{
	পূর্ণাঙ্ক kbits = sshkey_curve_nid_to_bits(nid);

	যদি (kbits <= 0)
		প্রত্যাগম -1;

	/* RFC5656 section 6.2.1 */
	যদি (kbits <= 256)
		প্রত্যাগম SSH_DIGEST_SHA256;
	অন্যথা যদি (kbits <= 384)
		প্রত্যাগম SSH_DIGEST_SHA384;
	অন্যথা
		প্রত্যাগম SSH_DIGEST_SHA512;
}
#endif /* WITH_OPENSSL */

স্থির শূন্য
cert_free(সংরচনা sshkey_cert *cert)
{
	u_int i;

	যদি (cert == রিক্ত)
		প্রত্যাগম;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	মুক্ত(cert->চাবি_id);
	প্রতি (i = 0; i < cert->nprincipals; i++)
		মুক্ত(cert->principals[i]);
	মুক্ত(cert->principals);
	sshkey_free(cert->signature_চাবি);
	মুক্ত(cert->signature_type);
	freezero(cert, পরিমাণ(*cert));
}

স্থির সংরচনা sshkey_cert *
cert_new(শূন্য)
{
	সংরচনা sshkey_cert *cert;

	যদি ((cert = calloc(1, পরিমাণ(*cert))) == রিক্ত)
		প্রত্যাগম রিক্ত;
	যদি ((cert->certblob = sshbuf_new()) == রিক্ত ||
	    (cert->critical = sshbuf_new()) == রিক্ত ||
	    (cert->extensions = sshbuf_new()) == রিক্ত) {
		cert_free(cert);
		প্রত্যাগম রিক্ত;
	}
	cert->চাবি_id = রিক্ত;
	cert->principals = রিক্ত;
	cert->signature_চাবি = রিক্ত;
	cert->signature_type = রিক্ত;
	প্রত্যাগম cert;
}

সংরচনা sshkey *
sshkey_new(পূর্ণাঙ্ক type)
{
	সংরচনা sshkey *k;
	ধ্রুব সংরচনা sshkey_impl *impl = রিক্ত;

	যদি (type != চাবি_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == রিক্ত)
		প্রত্যাগম রিক্ত;

	/* All non-certificate types may act as CAs */
	যদি ((k = calloc(1, পরিমাণ(*k))) == রিক্ত)
		প্রত্যাগম রিক্ত;
	k->type = type;
	k->ecdsa_nid = -1;
	যদি (impl != রিক্ত && impl->funcs->alloc != রিক্ত) {
		যদি (impl->funcs->alloc(k) != 0) {
			মুক্ত(k);
			প্রত্যাগম রিক্ত;
		}
	}
	যদি (sshkey_is_cert(k)) {
		যদি ((k->cert = cert_new()) == রিক্ত) {
			sshkey_free(k);
			প্রত্যাগম রিক্ত;
		}
	}

	প্রত্যাগম k;
}

/* Frees common FIDO fields */
শূন্য
sshkey_sk_cleanup(সংরচনা sshkey *k)
{
	মুক্ত(k->sk_application);
	sshbuf_free(k->sk_চাবি_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = রিক্ত;
	k->sk_চাবি_handle = k->sk_reserved = রিক্ত;
}

#যদি defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#নোচেদ্যদি defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#অন্যথা
# define PREKEY_MMAP_FLAG	0
#endif

স্থির পূর্ণাঙ্ক
sshkey_prekey_alloc(u_char **prekeyp, size_t len)
{
#যদি defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = রিক্ত;
	যদি ((prekey = mmap(রিক্ত, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
#যদি defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(শূন্য)madvise(prekey, len, MADV_DONTDUMP);
#endif
	*prekeyp = prekey;
#অন্যথা
	*prekeyp = calloc(1, len);
#endif /* HAVE_MMAP et al */
	প্রত্যাগম 0;
}

স্থির শূন্য
sshkey_prekey_free(শূন্য *prekey, size_t len)
{
#যদি defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	যদি (prekey == রিক্ত)
		প্রত্যাগম;
	munmap(prekey, len);
#অন্যথা
	মুক্ত(prekey);
#endif /* HAVE_MMAP et al */
}

স্থির শূন্য
sshkey_free_contents(সংরচনা sshkey *k)
{
	ধ্রুব সংরচনা sshkey_impl *impl;

	যদি (k == রিক্ত)
		প্রত্যাগম;
	যদি ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_চাবি_free(k);
	যদি ((impl = sshkey_impl_from_type(k->type)) != রিক্ত &&
	    impl->funcs->cleanup != রিক্ত)
		impl->funcs->cleanup(k);
	যদি (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_private, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

শূন্য
sshkey_free(সংরচনা sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, পরিমাণ(*k));
}

স্থির পূর্ণাঙ্ক
cert_compare(সংরচনা sshkey_cert *a, সংরচনা sshkey_cert *b)
{
	যদি (a == রিক্ত && b == রিক্ত)
		প্রত্যাগম 1;
	যদি (a == রিক্ত || b == রিক্ত)
		প্রত্যাগম 0;
	যদি (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		প্রত্যাগম 0;
	যদি (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		প্রত্যাগম 0;
	প্রত্যাগম 1;
}

/* Compares FIDO-specific pubkey fields only */
পূর্ণাঙ্ক
sshkey_sk_fields_equal(ধ্রুব সংরচনা sshkey *a, ধ্রুব সংরচনা sshkey *b)
{
	যদি (a->sk_application == রিক্ত || b->sk_application == রিক্ত)
		প্রত্যাগম 0;
	যদি (strcmp(a->sk_application, b->sk_application) != 0)
		প্রত্যাগম 0;
	প্রত্যাগম 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
পূর্ণাঙ্ক
sshkey_equal_public(ধ্রুব সংরচনা sshkey *a, ধ্রুব সংরচনা sshkey *b)
{
	ধ্রুব সংরচনা sshkey_impl *impl;

	যদি (a == রিক্ত || b == রিক্ত ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		প্রত্যাগম 0;
	যদি ((impl = sshkey_impl_from_type(a->type)) == রিক্ত)
		প্রত্যাগম 0;
	প্রত্যাগম impl->funcs->equal(a, b);
}

পূর্ণাঙ্ক
sshkey_equal(ধ্রুব সংরচনা sshkey *a, ধ্রুব সংরচনা sshkey *b)
{
	যদি (a == রিক্ত || b == রিক্ত || a->type != b->type)
		প্রত্যাগম 0;
	যদি (sshkey_is_cert(a)) {
		যদি (!cert_compare(a->cert, b->cert))
			প্রত্যাগম 0;
	}
	প্রত্যাগম sshkey_equal_public(a, b);
}


/* Serialise common FIDO key parts */
পূর্ণাঙ্ক
sshkey_serialize_sk(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_put_cstring(b, চাবি->sk_application)) != 0)
		প্রত্যাগম r;

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
to_blob_buf(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b, পূর্ণাঙ্ক force_plain,
  গণনা sshkey_serialize_rep opts)
{
	পূর্ণাঙ্ক type, ret = SSH_ERR_INTERNAL_ERROR;
	ধ্রুব বর্ণ *typename;
	ধ্রুব সংরচনা sshkey_impl *impl;

	যদি (চাবি == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(চাবি->type) : চাবি->type;

	যদি (sshkey_type_is_cert(type)) {
		যদি (চাবি->cert == রিক্ত)
			প্রত্যাগম SSH_ERR_EXPECTED_CERT;
		যদি (sshbuf_len(চাবি->cert->certblob) == 0)
			প্রত্যাগম SSH_ERR_চাবি_LACKS_CERTBLOB;
		/* Use the existing blob */
		যদি ((ret = sshbuf_putb(b, চাবি->cert->certblob)) != 0)
			প্রত্যাগম ret;
		প্রত্যাগম 0;
	}
	যদি ((impl = sshkey_impl_from_type(type)) == রিক্ত)
		প্রত্যাগম SSH_ERR_চাবি_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, চাবি->ecdsa_nid);
	যদি ((ret = sshbuf_put_cstring(b, typename)) != 0)
		প্রত্যাগম ret;
	প্রত্যাগম impl->funcs->serialize_public(চাবি, b, opts);
}

পূর্ণাঙ্ক
sshkey_putb(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b)
{
	প্রত্যাগম to_blob_buf(চাবি, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

স্থির পূর্ণাঙ্ক
sshkey_puts_opts_internal(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b,
    গণনা sshkey_serialize_rep opts, পূর্ণাঙ্ক force_plain)
{
	সংরচনা sshbuf *tmp;
	পূর্ণাঙ্ক r;

	যদি ((tmp = sshbuf_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(চাবি, tmp, force_plain, opts);
	যদি (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshkey_puts(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b)
{
	প্রত্যাগম sshkey_puts_opts_internal(চাবি, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

পূর্ণাঙ্ক
sshkey_putb_plain(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b)
{
	প্রত্যাগম to_blob_buf(চাবি, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

পূর্ণাঙ্ক
sshkey_puts_plain(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b)
{
	প্রত্যাগম sshkey_puts_opts_internal(চাবি, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

স্থির পূর্ণাঙ্ক
to_blob(ধ্রুব সংরচনা sshkey *চাবি, u_char **blobp, size_t *lenp, পূর্ণাঙ্ক force_plain,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণাঙ্ক ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	সংরচনা sshbuf *b = রিক্ত;

	যদি (lenp != রিক্ত)
		*lenp = 0;
	যদি (blobp != রিক্ত)
		*blobp = রিক্ত;
	যদি ((b = sshbuf_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((ret = to_blob_buf(চাবি, b, force_plain, opts)) != 0)
		গচ্ছ out;
	len = sshbuf_len(b);
	যদি (lenp != রিক্ত)
		*lenp = len;
	যদি (blobp != রিক্ত) {
		যদি ((*blobp = malloc(len)) == রিক্ত) {
			ret = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
sshkey_to_blob(ধ্রুব সংরচনা sshkey *চাবি, u_char **blobp, size_t *lenp)
{
	প্রত্যাগম to_blob(চাবি, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

পূর্ণাঙ্ক
sshkey_plain_to_blob(ধ্রুব সংরচনা sshkey *চাবি, u_char **blobp, size_t *lenp)
{
	প্রত্যাগম to_blob(চাবি, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

পূর্ণাঙ্ক
sshkey_fingerprint_raw(ধ্রুব সংরচনা sshkey *k, পূর্ণাঙ্ক dgst_alg,
    u_char **retp, size_t *lenp)
{
	u_char *blob = রিক্ত, *ret = রিক্ত;
	size_t blob_len = 0;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি (retp != রিক্ত)
		*retp = রিক্ত;
	যদি (lenp != রিক্ত)
		*lenp = 0;
	যদি (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	যদি ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		গচ্ছ out;
	যদি ((ret = calloc(1, SSH_DIGEST_MAX_LENGTH)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_LENGTH)) != 0)
		গচ্ছ out;
	/* success */
	যদি (retp != রিক্ত) {
		*retp = ret;
		ret = রিক্ত;
	}
	যদি (lenp != রিক্ত)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	মুক্ত(ret);
	যদি (blob != রিক্ত)
		freezero(blob, blob_len);
	প্রত্যাগম r;
}

স্থির বর্ণ *
fingerprint_b64(ধ্রুব বর্ণ *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	বর্ণ *ret;
	size_t plen = strlen(alg) + 1;
	size_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	যদি (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == রিক্ত)
		প্রত্যাগম রিক্ত;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	যদি (dgst_raw_len == 0)
		প্রত্যাগম ret;
	যদি (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		প্রত্যাগম রিক্ত;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	প্রত্যাগম ret;
}

স্থির বর্ণ *
fingerprint_hex(ধ্রুব বর্ণ *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	বর্ণ *retval, hex[5];
	size_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	যদি (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == রিক্ত)
		প্রত্যাগম রিক্ত;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	প্রতি (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, পরিমাণ(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	প্রত্যাগম retval;
}

স্থির বর্ণ *
fingerprint_bubblebabble(u_char *dgst_raw, size_t dgst_raw_len)
{
	বর্ণ vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	বর্ণ consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	বর্ণ *retval;

	rounds = (dgst_raw_len / 2) + 1;
	যদি ((retval = calloc(rounds, 6)) == রিক্ত)
		প্রত্যাগম রিক্ত;
	retval[j++] = 'x';
	প্রতি (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		যদি ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			যদি ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} অন্যথা {
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
	প্রত্যাগম retval;
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
স্থির বর্ণ *
fingerprint_randomart(ধ্রুব বর্ণ *alg, u_char *dgst_raw, size_t dgst_raw_len,
    ধ্রুব সংরচনা sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	বর্ণ	*augmentation_string = " .o+=*BOX@%&#/^SE";
	বর্ণ	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	size_t	 i, tlen, hlen;
	u_int	 b;
	পূর্ণাঙ্ক	 x, y, r;
	size_t	 len = strlen(augmentation_string) - 1;

	যদি ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == রিক্ত)
		প্রত্যাগম রিক্ত;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * পরিমাণ(বর্ণ));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	প্রতি (i = 0; i < dgst_raw_len; i++) {
		পূর্ণাঙ্ক প্রবেশ;
		/* each byte conveys four 2-bit move commands */
		প্রবেশ = dgst_raw[i];
		প্রতি (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (প্রবেশ & 0x1) ? 1 : -1;
			y += (প্রবেশ & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			যদি (field[x][y] < len - 2)
				field[x][y]++;
			প্রবেশ = প্রবেশ >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, পরিমাণ(title), "[%s %u]",
		sshkey_type(k), sshkey_size(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	যদি (r < 0 || r > (পূর্ণাঙ্ক)পরিমাণ(title))
		r = snprintf(title, পরিমাণ(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, পরিমাণ(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	প্রতি (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	memcpy(p, title, tlen);
	p += tlen;
	প্রতি (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	প্রতি (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		প্রতি (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	প্রতি (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	memcpy(p, hash, hlen);
	p += hlen;
	প্রতি (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	প্রত্যাগম retval;
}

বর্ণ *
sshkey_fingerprint(ধ্রুব সংরচনা sshkey *k, পূর্ণাঙ্ক dgst_alg,
    গণনা sshkey_fp_rep dgst_rep)
{
	বর্ণ *retval = রিক্ত;
	u_char *dgst_raw;
	size_t dgst_raw_len;

	যদি (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		প্রত্যাগম রিক্ত;
	বিকল্প (dgst_rep) {
	পক্ষ SSH_FP_DEFAULT:
		যদি (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} অন্যথা {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		ভঙ্গ;
	পক্ষ SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		ভঙ্গ;
	পক্ষ SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		ভঙ্গ;
	পক্ষ SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		ভঙ্গ;
	পক্ষ SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		ভঙ্গ;
	স্বভাব:
		freezero(dgst_raw, dgst_raw_len);
		প্রত্যাগম রিক্ত;
	}
	freezero(dgst_raw, dgst_raw_len);
	প্রত্যাগম retval;
}

স্থির পূর্ণাঙ্ক
peek_type_nid(ধ্রুব বর্ণ *s, size_t l, পূর্ণাঙ্ক *nid)
{
	ধ্রুব সংরচনা sshkey_impl *impl;
	পূর্ণাঙ্ক i;

	প্রতি (i = 0; keyimpls[i] != রিক্ত; i++) {
		impl = keyimpls[i];
		যদি (impl->name == রিক্ত || strlen(impl->name) != l)
			অনুবর্ত;
		যদি (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			যদি (চাবি_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			প্রত্যাগম impl->type;
		}
	}
	প্রত্যাগম চাবি_UNSPEC;
}

/* XXX this can now be made const char * */
পূর্ণাঙ্ক
sshkey_read(সংরচনা sshkey *ret, বর্ণ **cpp)
{
	সংরচনা sshkey *k;
	বর্ণ *cp, *blobcopy;
	size_t space;
	পূর্ণাঙ্ক r, type, curve_nid = -1;
	সংরচনা sshbuf *blob;

	যদি (ret == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি (ret->type != চাবি_UNSPEC && sshkey_impl_from_type(ret->type) == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	যদি (space == strlen(cp))
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	যদি ((type = peek_type_nid(cp, space, &curve_nid)) == চাবি_UNSPEC)
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	প্রতি (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	যদি (*cp == '\0')
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	যদি (ret->type != চাবি_UNSPEC && ret->type != type)
		প্রত্যাগম SSH_ERR_চাবি_TYPE_MISMATCH;
	যদি ((blob = sshbuf_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	যদি ((blobcopy = strndup(cp, space)) == রিক্ত) {
		sshbuf_free(blob);
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	}
	যদি ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		মুক্ত(blobcopy);
		sshbuf_free(blob);
		প্রত্যাগম r;
	}
	মুক্ত(blobcopy);
	যদি ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		প্রত্যাগম r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	প্রতি (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	যদি (k->type != type) {
		sshkey_free(k);
		প্রত্যাগম SSH_ERR_চাবি_TYPE_MISMATCH;
	}
	যদি (চাবি_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		প্রত্যাগম SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, পরিমাণ(*k));

	/* success */
	*cpp = cp;
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshkey_to_base64(ধ্রুব সংরচনা sshkey *চাবি, বর্ণ **b64p)
{
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	সংরচনা sshbuf *b = রিক্ত;
	বর্ণ *uu = রিক্ত;

	যদি (b64p != রিক্ত)
		*b64p = রিক্ত;
	যদি ((b = sshbuf_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshkey_putb(চাবি, b)) != 0)
		গচ্ছ out;
	যদি ((uu = sshbuf_dtob64_string(b, 0)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	/* Success */
	যদি (b64p != রিক্ত) {
		*b64p = uu;
		uu = রিক্ত;
	}
	r = 0;
 out:
	sshbuf_free(b);
	মুক্ত(uu);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshkey_format_text(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b)
{
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	বর্ণ *uu = রিক্ত;

	যদি ((r = sshkey_to_base64(চাবি, &uu)) != 0)
		গচ্ছ out;
	যদি ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(চাবি), uu)) != 0)
		গচ্ছ out;
	r = 0;
 out:
	মুক্ত(uu);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshkey_write(ধ্রুব সংরচনা sshkey *চাবি, FILE *f)
{
	সংরচনা sshbuf *b = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি ((b = sshbuf_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshkey_format_text(চাবি, b)) != 0)
		গচ্ছ out;
	যদি (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		যদি (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		গচ্ছ out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	প্রত্যাগম r;
}

ধ্রুব বর্ণ *
sshkey_cert_type(ধ্রুব সংরচনা sshkey *k)
{
	বিকল্প (k->cert->type) {
	পক্ষ SSH2_CERT_TYPE_USER:
		প্রত্যাগম "user";
	পক্ষ SSH2_CERT_TYPE_HOST:
		প্রত্যাগম "host";
	স্বভাব:
		প্রত্যাগম "unknown";
	}
}

পূর্ণাঙ্ক
sshkey_check_rsa_length(ধ্রুব সংরচনা sshkey *k, পূর্ণাঙ্ক min_size)
{
#ifdef WITH_OPENSSL
	পূর্ণাঙ্ক nbits;

	যদি (k == রিক্ত || k->pkey == রিক্ত ||
	    (k->type != চাবি_RSA && k->type != চাবি_RSA_CERT))
		প্রত্যাগম 0;
	nbits = EVP_PKEY_bits(k->pkey);
	যদি (nbits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    (min_size > 0 && nbits < min_size))
		প্রত্যাগম SSH_ERR_চাবি_LENGTH;
#endif /* WITH_OPENSSL */
	প্রত্যাগম 0;
}

#ifdef WITH_OPENSSL
পূর্ণাঙ্ক
sshkey_ecdsa_চাবি_to_nid(ধ্রুব EC_চাবি *k)
{
	ধ্রুব EC_GROUP *g;
	পূর্ণাঙ্ক nid;

	যদি (k == রিক্ত || (g = EC_চাবি_get0_group(k)) == রিক্ত)
		প্রত্যাগম -1;
	যদি ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		প্রত্যাগম -1;
	প্রত্যাগম nid;
}

পূর্ণাঙ্ক
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	প্রত্যাগম sshkey_ecdsa_চাবি_to_nid(EVP_PKEY_get0_EC_চাবি(pkey));
}
#endif /* WITH_OPENSSL */

পূর্ণাঙ্ক
sshkey_generate(পূর্ণাঙ্ক type, u_int bits, সংরচনা sshkey **keyp)
{
	সংরচনা sshkey *k;
	পূর্ণাঙ্ক ret = SSH_ERR_INTERNAL_ERROR;
	ধ্রুব সংরচনা sshkey_impl *impl;

	যদি (keyp == রিক্ত || sshkey_type_is_cert(type))
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	*keyp = রিক্ত;
	যদি ((impl = sshkey_impl_from_type(type)) == রিক্ত)
		প্রত্যাগম SSH_ERR_চাবি_TYPE_UNKNOWN;
	যদি (impl->funcs->generate == রিক্ত)
		প্রত্যাগম SSH_ERR_FEATURE_UNSUPPORTED;
	যদি ((k = sshkey_new(চাবি_UNSPEC)) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	k->type = type;
	যদি ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		প্রত্যাগম ret;
	}
	/* success */
	*keyp = k;
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshkey_cert_copy(ধ্রুব সংরচনা sshkey *from_চাবি, সংরচনা sshkey *to_চাবি)
{
	u_int i;
	ধ্রুব সংরচনা sshkey_cert *from;
	সংরচনা sshkey_cert *to;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি (to_চাবি == রিক্ত || (from = from_চাবি->cert) == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	যদি ((to = cert_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;

	যদি ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		গচ্ছ out;

	to->serial = from->serial;
	to->type = from->type;
	যদি (from->চাবি_id == রিক্ত)
		to->চাবি_id = রিক্ত;
	অন্যথা যদি ((to->চাবি_id = strdup(from->চাবি_id)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	যদি (from->signature_চাবি == রিক্ত)
		to->signature_চাবি = রিক্ত;
	অন্যথা যদি ((r = sshkey_from_private(from->signature_চাবি,
	    &to->signature_চাবি)) != 0)
		গচ্ছ out;
	যদি (from->signature_type != রিক্ত &&
	    (to->signature_type = strdup(from->signature_type)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	যদি (from->nprincipals > 0) {
		যদি ((to->principals = calloc(from->nprincipals,
		    পরিমাণ(*to->principals))) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		প্রতি (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			যদি (to->principals[i] == রিক্ত) {
				to->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				গচ্ছ out;
			}
		}
	}
	to->nprincipals = from->nprincipals;

	/* success */
	cert_free(to_চাবি->cert);
	to_চাবি->cert = to;
	to = রিক্ত;
	r = 0;
 out:
	cert_free(to);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshkey_copy_public_sk(ধ্রুব সংরচনা sshkey *from, সংরচনা sshkey *to)
{
	/* Append security-key application string */
	যদি ((to->sk_application = strdup(from->sk_application)) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshkey_from_private(ধ্রুব সংরচনা sshkey *k, সংরচনা sshkey **pkp)
{
	সংরচনা sshkey *n = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	ধ্রুব সংরচনা sshkey_impl *impl;

	*pkp = রিক্ত;
	যদি ((impl = sshkey_impl_from_চাবি(k)) == রিক্ত)
		প্রত্যাগম SSH_ERR_চাবি_TYPE_UNKNOWN;
	যদি ((n = sshkey_new(k->type)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = impl->funcs->copy_public(k, n)) != 0)
		গচ্ছ out;
	যদি (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		গচ্ছ out;
	/* success */
	*pkp = n;
	n = রিক্ত;
	r = 0;
 out:
	sshkey_free(n);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshkey_is_shielded(সংরচনা sshkey *k)
{
	প্রত্যাগম k != রিক্ত && k->shielded_private != রিক্ত;
}

পূর্ণাঙ্ক
sshkey_shield_private(সংরচনা sshkey *k)
{
	সংরচনা sshbuf *prvbuf = রিক্ত;
	u_char *prekey = রিক্ত, *enc = রিক্ত, keyiv[SSH_DIGEST_MAX_LENGTH];
	সংরচনা sshcipher_ctx *cctx = রিক্ত;
	ধ্রুব সংরচনা sshcipher *cipher;
	size_t i, enclen = 0;
	সংরচনা sshkey *kswap = রিক্ত, tmp;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	যদি ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == রিক্ত) {
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	যদি (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		গচ্ছ out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	যদি ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		গচ্ছ out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	যদি ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		গচ্ছ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	যদি ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		গচ্ছ out;

	/* Serialise and encrypt the private key using the ephemeral key */
	যদি ((prvbuf = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		গচ্ছ out;
	যদি ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		গচ্ছ out;
	/* pad to cipher blocksize */
	i = 0;
	যাবত্ (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		যদি ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			গচ্ছ out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	যদি ((enc = malloc(enclen)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		গচ্ছ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	যদি ((r = sshkey_from_private(k, &kswap)) != 0)
		গচ্ছ out;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_private = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = রিক্ত; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 out:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, পরিমাণ(keyiv));
	explicit_bzero(&tmp, পরিমাণ(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	প্রত্যাগম r;
}

/* Check deterministic padding after private key */
স্থির পূর্ণাঙ্ক
private2_check_padding(সংরচনা sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	পূর্ণাঙ্ক r;

	i = 0;
	যাবত্ (sshbuf_len(decrypted)) {
		যদি ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			গচ্ছ out;
		যদি (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, পরিমাণ(pad));
	explicit_bzero(&i, পরিমাণ(i));
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshkey_unshield_private(সংরচনা sshkey *k)
{
	সংরচনা sshbuf *prvbuf = রিক্ত;
	u_char *cp, keyiv[SSH_DIGEST_MAX_LENGTH];
	সংরচনা sshcipher_ctx *cctx = রিক্ত;
	ধ্রুব সংরচনা sshcipher *cipher;
	সংরচনা sshkey *kswap = রিক্ত, tmp;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	যদি (!sshkey_is_shielded(k))
		প্রত্যাগম 0; /* nothing to do */

	যদি ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == রিক্ত) {
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	যদি (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		গচ্ছ out;
	}
	/* check size of shielded key blob */
	যদি (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}

	/* Calculate the ephemeral key from the prekey */
	যদি ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		গচ্ছ out;
	যদি ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		গচ্ছ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	যদি ((prvbuf = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		গচ্ছ out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(k->shielded_private, k->shielded_len, stderr);
#endif
	যদি ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		গচ্ছ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	যদি ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		গচ্ছ out;

	যদি ((r = private2_check_padding(prvbuf)) != 0)
		গচ্ছ out;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 out:
	cipher_free(cctx);
	explicit_bzero(keyiv, পরিমাণ(keyiv));
	explicit_bzero(&tmp, পরিমাণ(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
cert_parse(সংরচনা sshbuf *b, সংরচনা sshkey *চাবি, সংরচনা sshbuf *certbuf,
    ধ্রুব বর্ণ *ca_sigalg_allowlist)
{
	সংরচনা sshbuf *principals = রিক্ত, *crit = রিক্ত;
	সংরচনা sshbuf *exts = রিক্ত, *ca = রিক্ত;
	u_char *sig = রিক্ত;
	বর্ণ *sigtype = রিক্ত;
	size_t signed_len = 0, slen = 0, kidlen = 0;
	পূর্ণাঙ্ক ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	যদি ((ret = sshbuf_putb(চাবি->cert->certblob, certbuf)) != 0)
		প্রত্যাগম ret;

	/* Parse body of certificate up to signature */
	যদি ((ret = sshbuf_get_u64(b, &চাবি->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &চাবি->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &চাবি->cert->চাবি_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &চাবি->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &চাবি->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, রিক্ত, রিক্ত)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(চাবি->cert->certblob) - sshbuf_len(b);

	যদি ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}

	/* Is this a signature we're prepared to accept? */
	যদি ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি (ca_sigalg_allowlist != রিক্ত &&
	    match_pattern_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		গচ্ছ out;
	}

	/* Parse CA key and check whether we might accept it */
	যদি (sshkey_from_blob_internal(ca, &চাবি->cert->signature_চাবি, 0,
	    ca_sigalg_allowlist, রিক্ত) != 0) {
		ret = SSH_ERR_চাবি_CERT_INVALID_SIGN_চাবি;
		গচ্ছ out;
	}
	যদি (!sshkey_type_is_valid_ca(চাবি->cert->signature_চাবি->type)) {
		ret = SSH_ERR_চাবি_CERT_INVALID_SIGN_চাবি;
		গচ্ছ out;
	}

	যদি (চাবি->cert->type != SSH2_CERT_TYPE_USER &&
	    চাবি->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_চাবি_CERT_UNKNOWN_TYPE;
		গচ্ছ out;
	}

	/* Parse principals section */
	যাবত্ (sshbuf_len(principals) > 0) {
		বর্ণ *principal = রিক্ত;
		বর্ণ **oprincipals = রিক্ত;

		যদি (চাবি->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
		যদি ((ret = sshbuf_get_cstring(principals, &principal,
		    রিক্ত)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
		oprincipals = চাবি->cert->principals;
		চাবি->cert->principals = recallocarray(চাবি->cert->principals,
		    চাবি->cert->nprincipals, চাবি->cert->nprincipals + 1,
		    পরিমাণ(*চাবি->cert->principals));
		যদি (চাবি->cert->principals == রিক্ত) {
			মুক্ত(principal);
			চাবি->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		চাবি->cert->principals[চাবি->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	যদি ((ret = sshbuf_putb(চাবি->cert->critical, crit)) != 0 ||
	    (exts != রিক্ত &&
	    (ret = sshbuf_putb(চাবি->cert->extensions, exts)) != 0))
		গচ্ছ out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	যাবত্ (sshbuf_len(crit) != 0) {
		যদি ((ret = sshbuf_get_string_direct(crit, রিক্ত, রিক্ত)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, রিক্ত, রিক্ত)) != 0) {
			sshbuf_reset(চাবি->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
	}
	যাবত্ (exts != রিক্ত && sshbuf_len(exts) != 0) {
		যদি ((ret = sshbuf_get_string_direct(exts, রিক্ত, রিক্ত)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, রিক্ত, রিক্ত)) != 0) {
			sshbuf_reset(চাবি->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
	}

	/* Finally, validate signature */
	যদি ((ret = sshkey_verify(চাবি->cert->signature_চাবি, sig, slen,
	    sshbuf_ptr(চাবি->cert->certblob), signed_len, রিক্ত, 0, রিক্ত)) != 0)
		গচ্ছ out;

	/* Success */
	ret = 0;
	চাবি->cert->signature_type = sigtype;
	sigtype = রিক্ত;
 out:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	মুক্ত(sig);
	মুক্ত(sigtype);
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
sshkey_deserialize_sk(সংরচনা sshbuf *b, সংরচনা sshkey *চাবি)
{
	/* Parse additional security-key application string */
	যদি (sshbuf_get_cstring(b, &চাবি->sk_application, রিক্ত) != 0)
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
sshkey_from_blob_internal(সংরচনা sshbuf *b, সংরচনা sshkey **keyp,
    পূর্ণাঙ্ক allow_cert, ধ্রুব বর্ণ *alg_allowlist, ধ্রুব বর্ণ *ca_sigalg_allowlist)
{
	পূর্ণাঙ্ক type, ret = SSH_ERR_INTERNAL_ERROR;
	বর্ণ *ktype = রিক্ত;
	সংরচনা sshkey *চাবি = রিক্ত;
	সংরচনা sshbuf *copy;
	ধ্রুব সংরচনা sshkey_impl *impl;

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	যদি (keyp != রিক্ত)
		*keyp = রিক্ত;
	যদি ((copy = sshbuf_fromb(b)) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (sshbuf_get_cstring(b, &ktype, রিক্ত) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}

	type = sshkey_type_from_name(ktype);
	যদি (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_চাবি_CERT_INVALID_SIGN_চাবি;
		গচ্ছ out;
	}

	যদি (alg_allowlist != রিক্ত &&
	    !sshkey_match_keyname_to_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_চাবি_ALG_UNSUPPORTED;
		গচ্ছ out;
	}

	যদি ((impl = sshkey_impl_from_type(type)) == রিক্ত) {
		ret = SSH_ERR_চাবি_TYPE_UNKNOWN;
		গচ্ছ out;
	}
	যদি ((চাবি = sshkey_new(type)) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		যদি (sshbuf_get_string_direct(b, রিক্ত, রিক্ত) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
	}
	যদি ((ret = impl->funcs->deserialize_public(ktype, b, চাবি)) != 0)
		গচ্ছ out;

	/* Parse certificate potion */
	যদি (sshkey_is_cert(চাবি) &&
	    (ret = cert_parse(b, চাবি, copy, ca_sigalg_allowlist)) != 0)
		গচ্ছ out;

	যদি (চাবি != রিক্ত && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	ret = 0;
	যদি (keyp != রিক্ত) {
		*keyp = চাবি;
		চাবি = রিক্ত;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(চাবি);
	মুক্ত(ktype);
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
sshkey_from_blob(ধ্রুব u_char *blob, size_t blen, সংরচনা sshkey **keyp)
{
	সংরচনা sshbuf *b;
	পূর্ণাঙ্ক r;

	যদি ((b = sshbuf_from(blob, blen)) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1, রিক্ত, রিক্ত);
	sshbuf_free(b);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshkey_fromb(সংরচনা sshbuf *b, সংরচনা sshkey **keyp)
{
	প্রত্যাগম sshkey_from_blob_internal(b, keyp, 1, রিক্ত, রিক্ত);
}

পূর্ণাঙ্ক
sshkey_fromb_allowlist(সংরচনা sshbuf *b, সংরচনা sshkey **keyp,
    ধ্রুব বর্ণ *alg_allowlist, ধ্রুব বর্ণ *ca_sigalg_allowlist)
{
	প্রত্যাগম sshkey_from_blob_internal(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

পূর্ণাঙ্ক
sshkey_froms(সংরচনা sshbuf *buf, সংরচনা sshkey **keyp)
{
	সংরচনা sshbuf *b;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_froms(buf, &b)) != 0)
		প্রত্যাগম r;
	r = sshkey_from_blob_internal(b, keyp, 1, রিক্ত, রিক্ত);
	sshbuf_free(b);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshkey_get_sigtype(ধ্রুব u_char *sig, size_t siglen, বর্ণ **sigtypep)
{
	পূর্ণাঙ্ক r;
	সংরচনা sshbuf *b = রিক্ত;
	বর্ণ *sigtype = রিক্ত;

	যদি (sigtypep != রিক্ত)
		*sigtypep = রিক্ত;
	যদি ((b = sshbuf_from(sig, siglen)) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_get_cstring(b, &sigtype, রিক্ত)) != 0)
		গচ্ছ out;
	/* success */
	যদি (sigtypep != রিক্ত) {
		*sigtypep = sigtype;
		sigtype = রিক্ত;
	}
	r = 0;
 out:
	মুক্ত(sigtype);
	sshbuf_free(b);
	প্রত্যাগম r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
পূর্ণাঙ্ক
sshkey_check_cert_sigtype(ধ্রুব সংরচনা sshkey *চাবি, ধ্রুব বর্ণ *allowed)
{
	যদি (চাবি == রিক্ত || allowed == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি (!sshkey_type_is_cert(চাবি->type))
		প্রত্যাগম 0;
	যদি (চাবি->cert == রিক্ত || চাবি->cert->signature_type == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি (match_pattern_list(চাবি->cert->signature_type, allowed, 0) != 1)
		প্রত্যাগম SSH_ERR_SIGN_ALG_UNSUPPORTED;
	প্রত্যাগম 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
ধ্রুব বর্ণ *
sshkey_sigalg_by_name(ধ্রুব বর্ণ *name)
{
	ধ্রুব সংরচনা sshkey_impl *impl;
	পূর্ণাঙ্ক i;

	প্রতি (i = 0; keyimpls[i] != রিক্ত; i++) {
		impl = keyimpls[i];
		যদি (strcmp(impl->name, name) != 0)
			অনুবর্ত;
		যদি (impl->sigalg != রিক্ত)
			প্রত্যাগম impl->sigalg;
		যদি (!impl->cert)
			প্রত্যাগম impl->name;
		প্রত্যাগম sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	প্রত্যাগম রিক্ত;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
পূর্ণাঙ্ক
sshkey_check_sigtype(ধ্রুব u_char *sig, size_t siglen,
    ধ্রুব বর্ণ *requested_alg)
{
	ধ্রুব বর্ণ *expected_alg;
	বর্ণ *sigtype = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি (requested_alg == রিক্ত)
		প্রত্যাগম 0;
	যদি ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		প্রত্যাগম r;
	r = strcmp(expected_alg, sigtype) == 0;
	মুক্ত(sigtype);
	প্রত্যাগম r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

পূর্ণাঙ্ক
sshkey_sign(সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp,
    ধ্রুব u_char *data, size_t datalen,
    ধ্রুব বর্ণ *alg, ধ্রুব বর্ণ *sk_provider, ধ্রুব বর্ণ *sk_pin, u_int compat)
{
	পূর্ণাঙ্ক was_shielded = sshkey_is_shielded(চাবি);
	পূর্ণাঙ্ক r2, r = SSH_ERR_INTERNAL_ERROR;
	ধ্রুব সংরচনা sshkey_impl *impl;

	যদি (sigp != রিক্ত)
		*sigp = রিক্ত;
	যদি (lenp != রিক্ত)
		*lenp = 0;
	যদি (datalen > SSH_চাবি_MAX_SIGN_DATA_SIZE)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি ((impl = sshkey_impl_from_চাবি(চাবি)) == রিক্ত)
		প্রত্যাগম SSH_ERR_চাবি_TYPE_UNKNOWN;
	যদি ((r = sshkey_unshield_private(চাবি)) != 0)
		প্রত্যাগম r;
	যদি (sshkey_is_sk(চাবি)) {
		r = sshsk_sign(sk_provider, চাবি, sigp, lenp, data,
		    datalen, compat, sk_pin);
	} অন্যথা যদি ((চাবি->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(চাবি, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	} অন্যথা {
		যদি (impl->funcs->sign == রিক্ত)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		অন্যথা {
			r = impl->funcs->sign(চাবি, sigp, lenp, data, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	যদি (was_shielded && (r2 = sshkey_shield_private(চাবি)) != 0)
		প্রত্যাগম r2;
	প্রত্যাগম r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
পূর্ণাঙ্ক
sshkey_verify(ধ্রুব সংরচনা sshkey *চাবি,
    ধ্রুব u_char *sig, size_t siglen,
    ধ্রুব u_char *data, size_t dlen, ধ্রুব বর্ণ *alg, u_int compat,
    সংরচনা sshkey_sig_details **detailsp)
{
	ধ্রুব সংরচনা sshkey_impl *impl;

	যদি (detailsp != রিক্ত)
		*detailsp = রিক্ত;
	যদি (siglen == 0 || dlen > SSH_চাবি_MAX_SIGN_DATA_SIZE)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি ((impl = sshkey_impl_from_চাবি(চাবি)) == রিক্ত)
		প্রত্যাগম SSH_ERR_চাবি_TYPE_UNKNOWN;
	প্রত্যাগম impl->funcs->verify(চাবি, sig, siglen, data, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
পূর্ণাঙ্ক
sshkey_to_certified(সংরচনা sshkey *k)
{
	পূর্ণাঙ্ক newtype;

	যদি ((newtype = sshkey_type_certified(k->type)) == -1)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি ((k->cert = cert_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	প্রত্যাগম 0;
}

/* Convert a certificate to its raw key equivalent */
পূর্ণাঙ্ক
sshkey_drop_cert(সংরচনা sshkey *k)
{
	যদি (!sshkey_type_is_cert(k->type))
		প্রত্যাগম SSH_ERR_চাবি_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = রিক্ত;
	k->type = sshkey_type_plain(k->type);
	প্রত্যাগম 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
পূর্ণাঙ্ক
sshkey_certify_custom(সংরচনা sshkey *k, সংরচনা sshkey *ca, ধ্রুব বর্ণ *alg,
    ধ্রুব বর্ণ *sk_provider, ধ্রুব বর্ণ *sk_pin,
    sshkey_certify_signer *signer, শূন্য *signer_ctx)
{
	ধ্রুব সংরচনা sshkey_impl *impl;
	সংরচনা sshbuf *principals = রিক্ত;
	u_char *ca_blob = রিক্ত, *sig_blob = রিক্ত, nonce[32];
	size_t i, ca_len, sig_len;
	পূর্ণাঙ্ক ret = SSH_ERR_INTERNAL_ERROR;
	সংরচনা sshbuf *cert = রিক্ত;
	বর্ণ *sigtype = রিক্ত;

	যদি (k == রিক্ত || k->cert == রিক্ত ||
	    k->cert->certblob == রিক্ত || ca == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি (!sshkey_is_cert(k))
		প্রত্যাগম SSH_ERR_চাবি_TYPE_UNKNOWN;
	যদি (!sshkey_type_is_valid_ca(ca->type))
		প্রত্যাগম SSH_ERR_চাবি_CERT_INVALID_SIGN_চাবি;
	যদি ((impl = sshkey_impl_from_চাবি(k)) == রিক্ত)
		প্রত্যাগম SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	যদি (alg == রিক্ত)
		alg = k->cert->signature_type;
	অন্যথা যদি (k->cert->signature_type != রিক্ত &&
	    strcmp(alg, k->cert->signature_type) != 0)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	যদি (alg == রিক্ত && ca->type == চাবি_RSA)
		alg = "rsa-sha2-512";

	যদি ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		প্রত্যাগম SSH_ERR_চাবি_CERT_INVALID_SIGN_চাবি;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	যদি ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		গচ্ছ out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, পরিমাণ(nonce));
	যদি ((ret = sshbuf_put_string(cert, nonce, পরিমাণ(nonce))) != 0)
		গচ্ছ out;

	/* Public key next */
	যদি ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		গচ্ছ out;

	/* Then remaining cert fields */
	যদি ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->চাবি_id)) != 0)
		গচ্ছ out;

	যদি ((principals = sshbuf_new()) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	প্রতি (i = 0; i < k->cert->nprincipals; i++) {
		যদি ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			গচ্ছ out;
	}
	যদি ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, রিক্ত, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		গচ্ছ out;

	/* Sign the whole mess */
	যদি ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		গচ্ছ out;
	/* Check and update signature_type against what was actually used */
	যদি ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		গচ্ছ out;
	যদি (alg != রিক্ত && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		গচ্ছ out;
	}
	যদি (k->cert->signature_type == রিক্ত) {
		k->cert->signature_type = sigtype;
		sigtype = রিক্ত;
	}
	/* Append signature and we are done */
	যদি ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		গচ্ছ out;
	ret = 0;
 out:
	যদি (ret != 0)
		sshbuf_reset(cert);
	মুক্ত(sig_blob);
	মুক্ত(ca_blob);
	মুক্ত(sigtype);
	sshbuf_free(principals);
	প্রত্যাগম ret;
}

স্থির পূর্ণাঙ্ক
default_চাবি_sign(সংরচনা sshkey *চাবি, u_char **sigp, size_t *lenp,
    ধ্রুব u_char *data, size_t datalen,
    ধ্রুব বর্ণ *alg, ধ্রুব বর্ণ *sk_provider, ধ্রুব বর্ণ *sk_pin,
    u_int compat, শূন্য *ctx)
{
	যদি (ctx != রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	প্রত্যাগম sshkey_sign(চাবি, sigp, lenp, data, datalen, alg,
	    sk_provider, sk_pin, compat);
}

পূর্ণাঙ্ক
sshkey_certify(সংরচনা sshkey *k, সংরচনা sshkey *ca, ধ্রুব বর্ণ *alg,
    ধ্রুব বর্ণ *sk_provider, ধ্রুব বর্ণ *sk_pin)
{
	প্রত্যাগম sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_চাবি_sign, রিক্ত);
}

পূর্ণাঙ্ক
sshkey_cert_check_authority(ধ্রুব সংরচনা sshkey *k,
    পূর্ণাঙ্ক want_host, পূর্ণাঙ্ক wildcard_pattern, uint64_t verify_time,
    ধ্রুব বর্ণ *name, ধ্রুব বর্ণ **reason)
{
	u_int i, principal_matches;

	যদি (reason == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		প্রত্যাগম SSH_ERR_চাবি_CERT_INVALID;
	}
	যদি (want_host) {
		যদি (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			প্রত্যাগম SSH_ERR_চাবি_CERT_INVALID;
		}
	} অন্যথা {
		যদি (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			প্রত্যাগম SSH_ERR_চাবি_CERT_INVALID;
		}
	}
	যদি (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		প্রত্যাগম SSH_ERR_চাবি_CERT_INVALID;
	}
	যদি (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		প্রত্যাগম SSH_ERR_চাবি_CERT_INVALID;
	}
	যদি (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		প্রত্যাগম SSH_ERR_চাবি_CERT_INVALID;
	}
	যদি (name == রিক্ত)
		প্রত্যাগম 0; /* principal matching not requested */

	principal_matches = 0;
	প্রতি (i = 0; i < k->cert->nprincipals; i++) {
		যদি (wildcard_pattern) {
			যদি (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				ভঙ্গ;
			}
		} অন্যথা যদি (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			ভঙ্গ;
		}
	}
	যদি (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		প্রত্যাগম SSH_ERR_চাবি_CERT_INVALID;
	}
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshkey_cert_check_authority_now(ধ্রুব সংরচনা sshkey *k,
    পূর্ণাঙ্ক want_host, পূর্ণাঙ্ক wildcard_pattern, ধ্রুব বর্ণ *name,
    ধ্রুব বর্ণ **reason)
{
	time_t now;

	যদি ((now = time(রিক্ত)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		প্রত্যাগম SSH_ERR_চাবি_CERT_INVALID;
	}
	প্রত্যাগম sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

পূর্ণাঙ্ক
sshkey_cert_check_host(ধ্রুব সংরচনা sshkey *চাবি, ধ্রুব বর্ণ *host,
    ধ্রুব বর্ণ *ca_sign_algorithms, ধ্রুব বর্ণ **reason)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshkey_cert_check_authority_now(চাবি, 1, 1, host, reason)) != 0)
		প্রত্যাগম r;
	যদি (sshbuf_len(চাবি->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		প্রত্যাগম SSH_ERR_চাবি_CERT_INVALID;
	}
	যদি (ca_sign_algorithms != রিক্ত &&
	    (r = sshkey_check_cert_sigtype(চাবি, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		প্রত্যাগম SSH_ERR_চাবি_CERT_INVALID;
	}
	প্রত্যাগম 0;
}

size_t
sshkey_format_cert_validity(ধ্রুব সংরচনা sshkey_cert *cert, বর্ণ *s, size_t l)
{
	বর্ণ from[32], to[32], ret[128];

	*from = *to = '\0';
	যদি (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		প্রত্যাগম strlcpy(s, "forever", l);

	যদি (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, পরিমাণ(from));
	যদি (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, পরিমাণ(to));

	যদি (cert->valid_after == 0)
		snprintf(ret, পরিমাণ(ret), "before %s", to);
	অন্যথা যদি (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, পরিমাণ(ret), "after %s", from);
	অন্যথা
		snprintf(ret, পরিমাণ(ret), "from %s to %s", from, to);

	প্রত্যাগম strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
পূর্ণাঙ্ক
sshkey_serialize_private_sk(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_put_cstring(b, চাবি->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, চাবি->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, চাবি->sk_চাবি_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, চাবি->sk_reserved)) != 0)
		প্রত্যাগম r;

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
sshkey_private_serialize_opt(সংরচনা sshkey *চাবি, সংরচনা sshbuf *buf,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	পূর্ণাঙ্ক was_shielded = sshkey_is_shielded(চাবি);
	সংরচনা sshbuf *b = রিক্ত;
	ধ্রুব সংরচনা sshkey_impl *impl;

	যদি ((impl = sshkey_impl_from_চাবি(চাবি)) == রিক্ত)
		প্রত্যাগম SSH_ERR_INTERNAL_ERROR;
	যদি ((r = sshkey_unshield_private(চাবি)) != 0)
		প্রত্যাগম r;
	যদি ((b = sshbuf_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_cstring(b, sshkey_ssh_name(চাবি))) != 0)
		গচ্ছ out;
	যদি (sshkey_is_cert(চাবি)) {
		যদি (চাবি->cert == রিক্ত ||
		    sshbuf_len(চাবি->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			গচ্ছ out;
		}
		যদি ((r = sshbuf_put_stringb(b, চাবি->cert->certblob)) != 0)
			গচ্ছ out;
	}
	যদি ((r = impl->funcs->serialize_private(চাবি, b, opts)) != 0)
		গচ্ছ out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	যদি (was_shielded)
		r = sshkey_shield_private(চাবি);
	যদি (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshkey_private_serialize(সংরচনা sshkey *চাবি, সংরচনা sshbuf *b)
{
	প্রত্যাগম sshkey_private_serialize_opt(চাবি, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
পূর্ণাঙ্ক
sshkey_private_deserialize_sk(সংরচনা sshbuf *buf, সংরচনা sshkey *k)
{
	পূর্ণাঙ্ক r;

	যদি ((k->sk_চাবি_handle = sshbuf_new()) == রিক্ত ||
	    (k->sk_reserved = sshbuf_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_get_cstring(buf, &k->sk_application, রিক্ত)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_চাবি_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		প্রত্যাগম r;

	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshkey_private_deserialize(সংরচনা sshbuf *buf, সংরচনা sshkey **kp)
{
	ধ্রুব সংরচনা sshkey_impl *impl;
	বর্ণ *tname = রিক্ত;
	বর্ণ *expect_sk_application = রিক্ত;
	u_char *expect_ed25519_pk = রিক্ত;
	সংরচনা sshkey *k = রিক্ত;
	পূর্ণাঙ্ক type, r = SSH_ERR_INTERNAL_ERROR;

	যদি (kp != রিক্ত)
		*kp = রিক্ত;
	যদি ((r = sshbuf_get_cstring(buf, &tname, রিক্ত)) != 0)
		গচ্ছ out;
	type = sshkey_type_from_name(tname);
	যদি (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		যদি ((r = sshkey_froms(buf, &k)) != 0)
			গচ্ছ out;
		যদি (k->type != type) {
			r = SSH_ERR_চাবি_CERT_MISMATCH;
			গচ্ছ out;
		}
		/* For ECDSA keys, the group must match too */
		যদি (k->type == চাবি_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_চাবি_CERT_MISMATCH;
			গচ্ছ out;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = রিক্ত;
		k->ed25519_pk = রিক্ত;
	} অন্যথা {
		যদি ((k = sshkey_new(type)) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
	}
	যদি ((impl = sshkey_impl_from_type(type)) == রিক্ত) {
		r = SSH_ERR_INTERNAL_ERROR;
		গচ্ছ out;
	}
	যদি ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		গচ্ছ out;

	যদি ((expect_sk_application != রিক্ত && (k->sk_application == রিক্ত ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != রিক্ত && (k->ed25519_pk == রিক্ত ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_চাবি_CERT_MISMATCH;
		গচ্ছ out;
	}
	/* success */
	r = 0;
	যদি (kp != রিক্ত) {
		*kp = k;
		k = রিক্ত;
	}
 out:
	মুক্ত(tname);
	sshkey_free(k);
	মুক্ত(expect_sk_application);
	মুক্ত(expect_ed25519_pk);
	প্রত্যাগম r;
}

#ifdef WITH_OPENSSL
পূর্ণাঙ্ক
sshkey_ec_validate_public(ধ্রুব EC_GROUP *group, ধ্রুব EC_POINT *সার্বজনিক)
{
	EC_POINT *nq = রিক্ত;
	BIGNUM *order = রিক্ত, *cofactor = রিক্ত;
	পূর্ণাঙ্ক ret = SSH_ERR_চাবি_INVALID_EC_মান;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	যদি (EC_POINT_is_at_infinity(group, সার্বজনিক))
		গচ্ছ out;

	যদি ((cofactor = BN_new()) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (EC_GROUP_get_cofactor(group, cofactor, রিক্ত) != 1)
		গচ্ছ out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	যদি (!BN_is_one(cofactor)) {
		যদি ((order = BN_new()) == রিক্ত) {
			ret = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		যদি (EC_GROUP_get_order(group, order, রিক্ত) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			গচ্ছ out;
		}
		যদি ((nq = EC_POINT_new(group)) == রিক্ত) {
			ret = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		যদি (EC_POINT_mul(group, nq, রিক্ত, সার্বজনিক, order, রিক্ত) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			গচ্ছ out;
		}
		যদি (EC_POINT_is_at_infinity(group, nq) != 1)
			গচ্ছ out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
sshkey_ec_validate_private(ধ্রুব EC_চাবি *চাবি)
{
	BIGNUM *order = রিক্ত, *tmp = রিক্ত;
	পূর্ণাঙ্ক ret = SSH_ERR_চাবি_INVALID_EC_মান;

	যদি ((order = BN_new()) == রিক্ত || (tmp = BN_new()) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}

	/* log2(private) > log2(order)/2 */
	যদি (EC_GROUP_get_order(EC_চাবি_get0_group(চাবি), order, রিক্ত) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	যদি (BN_অঙ্ক_bits(EC_চাবি_get0_private_চাবি(চাবি)) <=
	    BN_অঙ্ক_bits(order) / 2)
		গচ্ছ out;

	/* private < order - 1 */
	যদি (!BN_sub(tmp, order, BN_মান_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	যদি (BN_cmp(EC_চাবি_get0_private_চাবি(চাবি), tmp) >= 0)
		গচ্ছ out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	প্রত্যাগম ret;
}

শূন্য
sshkey_dump_ec_point(ধ্রুব EC_GROUP *group, ধ্রুব EC_POINT *point)
{
	BIGNUM *x = রিক্ত, *y = রিক্ত;

	যদি (point == রিক্ত) {
		fputs("point=(NULL)\n", stderr);
		প্রত্যাগম;
	}
	যদি ((x = BN_new()) == রিক্ত || (y = BN_new()) == রিক্ত) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		গচ্ছ out;
	}
	যদি (EC_POINT_get_affine_coordinates(group, point, x, y, রিক্ত) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		গচ্ছ out;
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

শূন্য
sshkey_dump_ec_চাবি(ধ্রুব EC_চাবি *চাবি)
{
	ধ্রুব BIGNUM *exponent;

	sshkey_dump_ec_point(EC_চাবি_get0_group(চাবি),
	    EC_চাবি_get0_public_চাবি(চাবি));
	fputs("exponent=", stderr);
	যদি ((exponent = EC_চাবি_get0_private_চাবি(চাবি)) == রিক্ত)
		fputs("(NULL)", stderr);
	অন্যথা
		BN_print_fp(stderr, EC_চাবি_get0_private_চাবি(চাবি));
	fputs("\n", stderr);
}
#endif /* WITH_OPENSSL */

স্থির পূর্ণাঙ্ক
sshkey_private_to_blob2(সংরচনা sshkey *prv, সংরচনা sshbuf *blob,
    ধ্রুব বর্ণ *passphrase, ধ্রুব বর্ণ *comment, ধ্রুব বর্ণ *ciphername,
    পূর্ণাঙ্ক rounds)
{
	u_char *cp, *চাবি = রিক্ত, *pubkeyblob = রিক্ত;
	u_char salt[SALT_LEN];
	size_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	সংরচনা sshcipher_ctx *ciphercontext = রিক্ত;
	ধ্রুব সংরচনা sshcipher *cipher;
	ধ্রুব বর্ণ *kdfname = KDFNAME;
	সংরচনা sshbuf *encoded = রিক্ত, *encrypted = রিক্ত, *kdf = রিক্ত;

	যদি (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	যদি (rounds > MAX_KDF_ROUNDS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	যদি (passphrase == রিক্ত || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} অন্যথা যদি (ciphername == রিক্ত)
		ciphername = DEFAULT_CIPHERNAME;
	যদি ((cipher = cipher_by_name(ciphername)) == রিক্ত) {
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}

	যদি ((kdf = sshbuf_new()) == রিক্ত ||
	    (encoded = sshbuf_new()) == রিক্ত ||
	    (encrypted = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	যদি ((চাবি = calloc(1, keylen + ivlen)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		যদি (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, চাবি, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			গচ্ছ out;
		}
		যদি ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			গচ্ছ out;
	} অন্যথা যদি (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_চাবি_UNKNOWN_CIPHER;
		গচ্ছ out;
	}
	যদি ((r = cipher_init(&ciphercontext, cipher, চাবি, keylen,
	    চাবি + keylen, ivlen, 1)) != 0)
		গচ্ছ out;

	যদি ((r = sshbuf_put(encoded, AUTH_MAGIC, পরিমাণ(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_to_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		গচ্ছ out;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	যদি ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		গচ্ছ out;

	/* append private key and comment*/
	যদি ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		গচ্ছ out;

	/* padding */
	i = 0;
	যাবত্ (sshbuf_len(encrypted) % blocksize) {
		যদি ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			গচ্ছ out;
	}

	/* length in destination buffer */
	যদি ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		গচ্ছ out;

	/* encrypt */
	যদি ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		গচ্ছ out;
	যদি ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		গচ্ছ out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	যদি ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_END, MARK_END_LEN)) != 0)
		গচ্ছ out;

	/* success */
	r = 0;

 out:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, পরিমাণ(salt));
	যদি (চাবি != রিক্ত)
		freezero(চাবি, keylen + ivlen);
	যদি (pubkeyblob != রিক্ত)
		freezero(pubkeyblob, pubkeylen);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
private2_uudecode(সংরচনা sshbuf *blob, সংরচনা sshbuf **decodedp)
{
	ধ্রুব u_char *cp;
	size_t encoded_len;
	পূর্ণাঙ্ক r;
	u_char last;
	সংরচনা sshbuf *encoded = রিক্ত, *decoded = রিক্ত;

	যদি (blob == রিক্ত || decodedp == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	*decodedp = রিক্ত;

	যদি ((encoded = sshbuf_new()) == রিক্ত ||
	    (decoded = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	যদি (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	যাবত্ (encoded_len > 0) {
		যদি (*cp != '\n' && *cp != '\r') {
			যদি ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				গচ্ছ out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		যদি (last == '\n') {
			যদি (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				যদি ((r = sshbuf_put_u8(encoded, 0)) != 0)
					গচ্ছ out;
				ভঙ্গ;
			}
		}
	}
	যদি (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}

	/* decode base64 */
	যদি ((r = sshbuf_b64tod(decoded, (বর্ণ *)sshbuf_ptr(encoded))) != 0)
		গচ্ছ out;

	/* check magic */
	যদি (sshbuf_len(decoded) < পরিমাণ(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, পরিমাণ(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	/* success */
	*decodedp = decoded;
	decoded = রিক্ত;
	r = 0;
 out:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
private2_decrypt(সংরচনা sshbuf *decoded, ধ্রুব বর্ণ *passphrase,
    সংরচনা sshbuf **decryptedp, সংরচনা sshkey **pubkeyp)
{
	বর্ণ *ciphername = রিক্ত, *kdfname = রিক্ত;
	ধ্রুব সংরচনা sshcipher *cipher = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	সংরচনা sshbuf *kdf = রিক্ত, *decrypted = রিক্ত;
	সংরচনা sshcipher_ctx *ciphercontext = রিক্ত;
	সংরচনা sshkey *pubkey = রিক্ত;
	u_char *চাবি = রিক্ত, *salt = রিক্ত, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	যদি (decoded == রিক্ত || decryptedp == রিক্ত || pubkeyp == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = রিক্ত;
	*pubkeyp = রিক্ত;

	যদি ((decrypted = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}

	/* parse public portion of key */
	যদি ((r = sshbuf_consume(decoded, পরিমাণ(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, রিক্ত)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, রিক্ত)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		গচ্ছ out;

	যদি (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}

	যদি ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		গচ্ছ out;

	যদি ((cipher = cipher_by_name(ciphername)) == রিক্ত) {
		r = SSH_ERR_চাবি_UNKNOWN_CIPHER;
		গচ্ছ out;
	}
	যদি (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_চাবি_UNKNOWN_CIPHER;
		গচ্ছ out;
	}
	যদি (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি ((passphrase == রিক্ত || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_চাবি_WRONG_PASSPHRASE;
		গচ্ছ out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	যদি (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	যদি ((চাবি = calloc(1, keylen + ivlen)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (strcmp(kdfname, "bcrypt") == 0) {
		যদি ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			গচ্ছ out;
		যদি (rounds > MAX_KDF_ROUNDS) {
			r = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
		যদি (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    চাবি, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	যদি (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}

	/* decrypt private portion of key */
	যদি ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, চাবি, keylen,
	    চাবি + keylen, ivlen, 0)) != 0)
		গচ্ছ out;
	যদি ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		যদি (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_চাবি_WRONG_PASSPHRASE;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		গচ্ছ out;
	/* there should be no trailing data */
	যদি (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}

	/* check check bytes */
	যদি ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		গচ্ছ out;
	যদি (check1 != check2) {
		r = SSH_ERR_চাবি_WRONG_PASSPHRASE;
		গচ্ছ out;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = রিক্ত;
	*pubkeyp = pubkey;
	pubkey = রিক্ত;
	r = 0;
 out:
	cipher_free(ciphercontext);
	মুক্ত(ciphername);
	মুক্ত(kdfname);
	sshkey_free(pubkey);
	যদি (salt != রিক্ত) {
		explicit_bzero(salt, slen);
		মুক্ত(salt);
	}
	যদি (চাবি != রিক্ত) {
		explicit_bzero(চাবি, keylen + ivlen);
		মুক্ত(চাবি);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
sshkey_parse_private2(সংরচনা sshbuf *blob, পূর্ণাঙ্ক type, ধ্রুব বর্ণ *passphrase,
    সংরচনা sshkey **keyp, বর্ণ **commentp)
{
	বর্ণ *comment = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	সংরচনা sshbuf *decoded = রিক্ত, *decrypted = রিক্ত;
	সংরচনা sshkey *k = রিক্ত, *pubkey = রিক্ত;

	যদি (keyp != রিক্ত)
		*keyp = রিক্ত;
	যদি (commentp != রিক্ত)
		*commentp = রিক্ত;

	/* Undo base64 encoding and decrypt the private section */
	যদি ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		গচ্ছ out;

	যদি (type != চাবি_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_চাবি_TYPE_MISMATCH;
		গচ্ছ out;
	}

	/* Load the private key and comment */
	যদি ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, রিক্ত)) != 0)
		গচ্ছ out;

	/* Check deterministic padding after private section */
	যদি ((r = private2_check_padding(decrypted)) != 0)
		গচ্ছ out;

	/* Check that the public key in the envelope matches the private key */
	যদি (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}

	/* success */
	r = 0;
	যদি (keyp != রিক্ত) {
		*keyp = k;
		k = রিক্ত;
	}
	যদি (commentp != রিক্ত) {
		*commentp = comment;
		comment = রিক্ত;
	}
 out:
	মুক্ত(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
sshkey_parse_private2_pubkey(সংরচনা sshbuf *blob, পূর্ণাঙ্ক type,
    সংরচনা sshkey **keyp)
{
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	সংরচনা sshbuf *decoded = রিক্ত;
	সংরচনা sshkey *pubkey = রিক্ত;
	u_int nkeys = 0;

	যদি (keyp != রিক্ত)
		*keyp = রিক্ত;

	যদি ((r = private2_uudecode(blob, &decoded)) != 0)
		গচ্ছ out;
	/* parse public key from unencrypted envelope */
	যদি ((r = sshbuf_consume(decoded, পরিমাণ(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		গচ্ছ out;

	যদি (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}

	/* Parse the public key */
	যদি ((r = sshkey_froms(decoded, &pubkey)) != 0)
		গচ্ছ out;

	যদি (type != চাবি_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_চাবি_TYPE_MISMATCH;
		গচ্ছ out;
	}

	/* success */
	r = 0;
	যদি (keyp != রিক্ত) {
		*keyp = pubkey;
		pubkey = রিক্ত;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	প্রত্যাগম r;
}

#ifdef WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
স্থির পূর্ণাঙ্ক
sshkey_private_to_blob_pem_pkcs8(সংরচনা sshkey *চাবি, সংরচনা sshbuf *buf,
    পূর্ণাঙ্ক format, ধ্রুব বর্ণ *_passphrase, ধ্রুব বর্ণ *comment)
{
	পূর্ণাঙ্ক was_shielded = sshkey_is_shielded(চাবি);
	পূর্ণাঙ্ক success, r;
	পূর্ণাঙ্ক blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : রিক্ত;
	ধ্রুব EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : রিক্ত;
	বর্ণ *bptr;
	BIO *bio = রিক্ত;
	সংরচনা sshbuf *blob;
	EVP_PKEY *pkey = রিক্ত;

	যদি (len > 0 && len <= 4)
		প্রত্যাগম SSH_ERR_PASSPHRASE_TOO_SHORT;
	যদি ((blob = sshbuf_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((bio = BIO_new(BIO_s_mem())) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = sshkey_unshield_private(চাবি)) != 0)
		গচ্ছ out;

	বিকল্প (চাবি->type) {
	পক্ষ চাবি_ECDSA:
		যদি (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivate_চাবি(bio,
			    EVP_PKEY_get0_EC_চাবি(চাবি->pkey),
			    cipher, passphrase, len, রিক্ত, রিক্ত);
		} অন্যথা {
			pkey = চাবি->pkey;
			EVP_PKEY_up_ref(চাবি->pkey);
			success = 1;
		}
		ভঙ্গ;
	পক্ষ চাবি_RSA:
		যদি (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivate_চাবি(bio,
			    EVP_PKEY_get0_RSA(চাবি->pkey),
			    cipher, passphrase, len, রিক্ত, রিক্ত);
		} অন্যথা {
			pkey = চাবি->pkey;
			EVP_PKEY_up_ref(চাবি->pkey);
			success = 1;
		}
		ভঙ্গ;
#ifdef OPENSSL_HAS_ED25519
	পক্ষ চাবি_ED25519:
		যদি (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		} অন্যথা {
			pkey = EVP_PKEY_new_raw_private_চাবি(EVP_PKEY_ED25519,
			    রিক্ত, চাবি->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != রিক্ত;
		}
		ভঙ্গ;
#endif
	স্বভাব:
		success = 0;
		ভঙ্গ;
	}
	যদি (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	যদি (format == SSHKEY_PRIVATE_PKCS8) {
		যদি ((success = PEM_write_bio_Private_চাবি(bio, pkey, cipher,
		    passphrase, len, রিক্ত, রিক্ত)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			গচ্ছ out;
		}
	}
	যদি ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_put(blob, bptr, blen)) != 0)
		গচ্ছ out;
	r = 0;
 out:
	যদি (was_shielded)
		r = sshkey_shield_private(চাবি);
	যদি (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	প্রত্যাগম r;
}
#endif /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
পূর্ণাঙ্ক
sshkey_private_to_fileblob(সংরচনা sshkey *চাবি, সংরচনা sshbuf *blob,
    ধ্রুব বর্ণ *passphrase, ধ্রুব বর্ণ *comment,
    পূর্ণাঙ্ক format, ধ্রুব বর্ণ *openssh_format_cipher, পূর্ণাঙ্ক openssh_format_rounds)
{
	বিকল্প (চাবি->type) {
#ifdef WITH_OPENSSL
	পক্ষ চাবি_ECDSA:
	পক্ষ চাবি_RSA:
	পক্ষ চাবি_ED25519:
		ভঙ্গ; /* see below */
#অন্যথা /* WITH_OPENSSL */
	পক্ষ চাবি_ED25519:
#endif /* WITH_OPENSSL */
	পক্ষ চাবি_ED25519_SK:
#ifdef WITH_OPENSSL
	পক্ষ চাবি_ECDSA_SK:
#endif /* WITH_OPENSSL */
	পক্ষ চাবি_MLDSA44_ED25519:
		প্রত্যাগম sshkey_private_to_blob2(চাবি, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	স্বভাব:
		প্রত্যাগম SSH_ERR_চাবি_TYPE_UNKNOWN;
	}

#ifdef WITH_OPENSSL
	বিকল্প (format) {
	পক্ষ SSHKEY_PRIVATE_OPENSSH:
		প্রত্যাগম sshkey_private_to_blob2(চাবি, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	পক্ষ SSHKEY_PRIVATE_PEM:
	পক্ষ SSHKEY_PRIVATE_PKCS8:
		প্রত্যাগম sshkey_private_to_blob_pem_pkcs8(চাবি, blob,
		    format, passphrase, comment);
	স্বভাব:
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	}
#endif /* WITH_OPENSSL */
}

#ifdef WITH_OPENSSL
স্থির পূর্ণাঙ্ক
translate_libcrypto_error(unsigned long pem_err)
{
	পূর্ণাঙ্ক pem_reason = ERR_GET_REASON(pem_err);

	বিকল্প (ERR_GET_LIB(pem_err)) {
	পক্ষ ERR_LIB_PEM:
		বিকল্প (pem_reason) {
		পক্ষ PEM_R_BAD_PASSWORD_READ:
#ifdef PEM_R_PROBLEMS_GETTING_PASSWORD
		পক্ষ PEM_R_PROBLEMS_GETTING_PASSWORD:
#endif
#ifdef PEM_R_BAD_DECRYPT
		পক্ষ PEM_R_BAD_DECRYPT:
#endif
			প্রত্যাগম SSH_ERR_চাবি_WRONG_PASSPHRASE;
		স্বভাব:
			প্রত্যাগম SSH_ERR_INVALID_FORMAT;
		}
	পক্ষ ERR_LIB_EVP:
		বিকল্প (pem_reason) {
#ifdef EVP_R_BAD_DECRYPT
		পক্ষ EVP_R_BAD_DECRYPT:
			প্রত্যাগম SSH_ERR_চাবি_WRONG_PASSPHRASE;
#endif
#ifdef EVP_R_BN_DECODE_ERROR
		পক্ষ EVP_R_BN_DECODE_ERROR:
#endif
		পক্ষ EVP_R_DECODE_ERROR:
#ifdef EVP_R_PRIVATE_চাবি_DECODE_ERROR
		পক্ষ EVP_R_PRIVATE_চাবি_DECODE_ERROR:
#endif
			প্রত্যাগম SSH_ERR_INVALID_FORMAT;
		স্বভাব:
			প্রত্যাগম SSH_ERR_LIBCRYPTO_ERROR;
		}
	পক্ষ ERR_LIB_ASN1:
#ifdef ERR_LIB_OSSL_DECODER
	পক্ষ ERR_LIB_OSSL_DECODER:
#endif
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	}
	প্রত্যাগম SSH_ERR_LIBCRYPTO_ERROR;
}

স্থির শূন্য
clear_libcrypto_errors(শূন্য)
{
	যাবত্ (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
স্থির পূর্ণাঙ্ক
convert_libcrypto_error(শূন্য)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	যদি (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_চাবি_WRONG_PASSPHRASE)
		প্রত্যাগম SSH_ERR_চাবি_WRONG_PASSPHRASE;
	প্রত্যাগম translate_libcrypto_error(ERR_peek_last_error());
}

স্থির পূর্ণাঙ্ক
pem_passphrase_cb(বর্ণ *buf, পূর্ণাঙ্ক size, পূর্ণাঙ্ক rwflag, শূন্য *u)
{
	বর্ণ *p = (বর্ণ *)u;
	size_t len;

	যদি (p == রিক্ত || (len = strlen(p)) == 0)
		প্রত্যাগম -1;
	যদি (size < 0 || len > (size_t)size)
		প্রত্যাগম -1;
	memcpy(buf, p, len);
	প্রত্যাগম (পূর্ণাঙ্ক)len;
}

স্থির পূর্ণাঙ্ক
sshkey_parse_private_pem_fileblob(সংরচনা sshbuf *blob, পূর্ণাঙ্ক type,
    ধ্রুব বর্ণ *passphrase, সংরচনা sshkey **keyp)
{
	EVP_PKEY *pk = রিক্ত;
	সংরচনা sshkey *prv = রিক্ত;
	BIO *bio = রিক্ত;
	পূর্ণাঙ্ক r;
	RSA *rsa = রিক্ত;
	EC_চাবি *ecdsa = রিক্ত;

	যদি (keyp != রিক্ত)
		*keyp = রিক্ত;

	যদি ((bio = BIO_new(BIO_s_mem())) == রিক্ত || sshbuf_len(blob) > INT_MAX)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (পূর্ণাঙ্ক)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}

	clear_libcrypto_errors();
	যদি ((pk = PEM_read_bio_Private_চাবি(bio, রিক্ত, pem_passphrase_cb,
	    (বর্ণ *)passphrase)) == রিক্ত) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		যদি (passphrase != রিক্ত && *passphrase != '\0')
			r = SSH_ERR_চাবি_WRONG_PASSPHRASE;
		অন্যথা
			r = convert_libcrypto_error();
		গচ্ছ out;
	}
	যদি (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == চাবি_UNSPEC || type == চাবি_RSA)) {
		যদি ((prv = sshkey_new(চাবি_UNSPEC)) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		যদি ((rsa = EVP_PKEY_get1_RSA(pk)) == রিক্ত) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			গচ্ছ out;
		}
		prv->type = চাবি_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#endif
		যদি (RSA_blinding_on(rsa, রিক্ত) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			গচ্ছ out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		যদি ((r = sshkey_check_rsa_length(prv, 0)) != 0)
			গচ্ছ out;
	} অন্যথা যদি (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == চাবি_UNSPEC || type == চাবি_ECDSA)) {
		যদি ((prv = sshkey_new(চাবি_UNSPEC)) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		যদি ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_চাবি(pk)) == রিক্ত) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			গচ্ছ out;
		}
		prv->type = চাবি_ECDSA;
		যদি (sshkey_curve_nid_to_name(prv->ecdsa_nid) == রিক্ত ||
		    sshkey_ec_validate_public(EC_চাবি_get0_group(ecdsa),
		    EC_চাবি_get0_public_চাবি(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#ifdef DEBUG_PK
		যদি (prv != রিক্ত && prv->pkey != রিক্ত)
			sshkey_dump_ec_চাবি(EVP_PKEY_get0_EC_চাবি(prv->pkey));
#endif
#ifdef OPENSSL_HAS_ED25519
	} অন্যথা যদি (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == চাবি_UNSPEC || type == চাবি_ED25519)) {
		size_t len;

		যদি ((prv = sshkey_new(চাবি_UNSPEC)) == রিক্ত ||
		    (prv->ed25519_sk = calloc(1, ED25519_SK_SZ)) == রিক্ত ||
		    (prv->ed25519_pk = calloc(1, ED25519_PK_SZ)) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		prv->type = চাবি_ED25519;
		len = ED25519_PK_SZ;
		যদি (!EVP_PKEY_get_raw_public_চাবি(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			গচ্ছ out;
		}
		যদি (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		যদি (!EVP_PKEY_get_raw_private_চাবি(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			গচ্ছ out;
		}
		যদি (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
		/* Append the public key to our private key */
		memcpy(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#ifdef DEBUG_PK
		sshbuf_dump_data(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#endif
#endif /* OPENSSL_HAS_ED25519 */
	} অন্যথা {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	r = 0;
	যদি (keyp != রিক্ত) {
		*keyp = prv;
		prv = রিক্ত;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_চাবি_free(ecdsa);
	sshkey_free(prv);
	প্রত্যাগম r;
}
#endif /* WITH_OPENSSL */

পূর্ণাঙ্ক
sshkey_parse_private_fileblob_type(সংরচনা sshbuf *blob, পূর্ণাঙ্ক type,
    ধ্রুব বর্ণ *passphrase, সংরচনা sshkey **keyp, বর্ণ **commentp)
{
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি (keyp != রিক্ত)
		*keyp = রিক্ত;
	যদি (commentp != রিক্ত)
		*commentp = রিক্ত;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	যদি (r != SSH_ERR_INVALID_FORMAT)
		প্রত্যাগম r;
#ifdef WITH_OPENSSL
	প্রত্যাগম sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#অন্যথা
	প্রত্যাগম SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

পূর্ণাঙ্ক
sshkey_parse_private_fileblob(সংরচনা sshbuf *buffer, ধ্রুব বর্ণ *passphrase,
    সংরচনা sshkey **keyp, বর্ণ **commentp)
{
	যদি (keyp != রিক্ত)
		*keyp = রিক্ত;
	যদি (commentp != রিক্ত)
		*commentp = রিক্ত;

	প্রত্যাগম sshkey_parse_private_fileblob_type(buffer, চাবি_UNSPEC,
	    passphrase, keyp, commentp);
}

শূন্য
sshkey_sig_details_free(সংরচনা sshkey_sig_details *details)
{
	freezero(details, পরিমাণ(*details));
}

পূর্ণাঙ্ক
sshkey_parse_pubkey_from_private_fileblob_type(সংরচনা sshbuf *blob, পূর্ণাঙ্ক type,
    সংরচনা sshkey **pubkeyp)
{
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি (pubkeyp != রিক্ত)
		*pubkeyp = রিক্ত;
	/* only new-format private keys bundle a public key inside */
	যদি ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		প্রত্যাগম r;
	প্রত্যাগম 0;
}
