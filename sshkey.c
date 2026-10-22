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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/mman.h>
#ଅନ୍ତର୍ଭାଵ <netinet/in.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#ଅନ୍ତର୍ଭାଵ <openssl/err.h>
#ଅନ୍ତର୍ଭାଵ <openssl/pem.h>
#endif

#ଅନ୍ତର୍ଭାଵ "crypto_api.h"

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <resolv.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <util.h>

#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "cipher.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#define SSHKEY_INTERNAL
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "ssh-sk.h"
#ଅନ୍ତର୍ଭାଵ "ssh-pkcs11.h"

#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#define MARK_BEGIN_LEN		(ଆକାର(MARK_BEGIN) - 1)
#define MARK_END_LEN		(ଆକାର(MARK_END) - 1)
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

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshkey_from_blob_internal(ସଂରଚନା sshbuf *buf,
    ସଂରଚନା sshkey **keyp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା allow_cert,
    ଅଚଳ ଅକ୍ଷର *alg_allowlist, ଅଚଳ ଅକ୍ଷର *ca_sigalg_allowlist);

/* Supported key types */
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ed25519_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ed25519_cert_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ed25519_sk_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_mldsa44_ed25519_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#ifdef WITH_OPENSSL
# ifdef ENABLE_SK
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_sk_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_sk_cert_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_nistp256_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_nistp384_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_nistp521_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_rsa_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_rsa_cert_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_rsa_sha256_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_rsa_sha256_cert_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_rsa_sha512_impl;
ବାହ୍ୟ ଅଚଳ ସଂରଚନା sshkey_impl sshkey_rsa_sha512_cert_impl;
#endif /* WITH_OPENSSL */

ଅଚଳ ସଂରଚନା sshkey_impl * ଅଚଳ keyimpls[] = {
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
	ଖାଲି
};

ସ୍ଥିର ଅଚଳ ସଂରଚନା sshkey_impl *
sshkey_impl_from_type(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ପାଇଁ (i = 0; keyimpls[i] != ଖାଲି; i++) {
		ଯଦି (keyimpls[i]->type == type)
			ଫେରନ୍ତୁ keyimpls[i];
	}
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର ଅଚଳ ସଂରଚନା sshkey_impl *
sshkey_impl_from_type_nid(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ପାଇଁ (i = 0; keyimpls[i] != ଖାଲି; i++) {
		ଯଦି (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			ଫେରନ୍ତୁ keyimpls[i];
	}
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର ଅଚଳ ସଂରଚନା sshkey_impl *
sshkey_impl_from_ଚାବି(ଅଚଳ ସଂରଚନା sshkey *k)
{
	ଯଦି (k == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ଫେରନ୍ତୁ sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

ଅଚଳ ଅକ୍ଷର *
sshkey_type(ଅଚଳ ସଂରଚନା sshkey *k)
{
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;

	ଯଦି ((impl = sshkey_impl_from_ଚାବି(k)) == ଖାଲି)
		ଫେରନ୍ତୁ "unknown";
	ଫେରନ୍ତୁ impl->shortname;
}

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
sshkey_ssh_name_from_type_nid(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid)
{
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;

	ଯଦି ((impl = sshkey_impl_from_type_nid(type, nid)) == ଖାଲି)
		ଫେରନ୍ତୁ "ssh-unknown";
	ଫେରନ୍ତୁ impl->name;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_type_is_cert(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type)
{
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;

	ଯଦି ((impl = sshkey_impl_from_type(type)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ impl->cert;
}

ଅଚଳ ଅକ୍ଷର *
sshkey_ssh_name(ଅଚଳ ସଂରଚନା sshkey *k)
{
	ଫେରନ୍ତୁ sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

ଅଚଳ ଅକ୍ଷର *
sshkey_ssh_name_plain(ଅଚଳ ସଂରଚନା sshkey *k)
{
	ଫେରନ୍ତୁ sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
type_from_name(ଅଚଳ ଅକ୍ଷର *name, ପୂର୍ଣ୍ଣସଂଖ୍ୟା allow_short)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;

	ପାଇଁ (i = 0; keyimpls[i] != ଖାଲି; i++) {
		impl = keyimpls[i];
		ଯଦି (impl->name != ଖାଲି && strcmp(name, impl->name) == 0)
			ଫେରନ୍ତୁ impl->type;
		/* Only allow shortname matches for plain key types */
		ଯଦି (allow_short && !impl->cert && impl->shortname != ଖାଲି &&
		    strcasecmp(impl->shortname, name) == 0)
			ଫେରନ୍ତୁ impl->type;
	}
	ଫେରନ୍ତୁ ଚାବି_UNSPEC;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_type_from_name(ଅଚଳ ଅକ୍ଷର *name)
{
	ଫେରନ୍ତୁ type_from_name(name, 0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_type_from_shortname(ଅଚଳ ଅକ୍ଷର *name)
{
	ଫେରନ୍ତୁ type_from_name(name, 1);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ଚାବି_type_is_ecdsa_variant(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type)
{
	ବାଛ (type) {
	ସ୍ଥିତି ଚାବି_ECDSA:
	ସ୍ଥିତି ଚାବି_ECDSA_CERT:
	ସ୍ଥିତି ଚାବି_ECDSA_SK:
	ସ୍ଥିତି ଚାବି_ECDSA_SK_CERT:
		ଫେରନ୍ତୁ 1;
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_ecdsa_nid_from_name(ଅଚଳ ଅକ୍ଷର *name)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ପାଇଁ (i = 0; keyimpls[i] != ଖାଲି; i++) {
		ଯଦି (!ଚାବି_type_is_ecdsa_variant(keyimpls[i]->type))
			ଜାରି;
		ଯଦି (keyimpls[i]->name != ଖାଲି &&
		    strcmp(name, keyimpls[i]->name) == 0)
			ଫେରନ୍ତୁ keyimpls[i]->nid;
	}
	ଫେରନ୍ତୁ -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_match_keyname_to_sigalgs(ଅଚଳ ଅକ୍ଷର *keyname, ଅଚଳ ଅକ୍ଷର *sigalgs)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ktype;

	ଯଦି (sigalgs == ଖାଲି || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == ଚାବି_UNSPEC)
		ଫେରନ୍ତୁ 0;
	ଅନ୍ୟଥା ଯଦି (ktype == ଚାବି_RSA) {
		ଫେରନ୍ତୁ match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} ଅନ୍ୟଥା ଯଦି (ktype == ଚାବି_RSA_CERT) {
		ଫେରନ୍ତୁ match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} ଅନ୍ୟଥା ଯଦି (ktype == ଚାବି_ECDSA_SK) {
		ଫେରନ୍ତୁ match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} ଅନ୍ୟଥା ଯଦି (ktype == ଚାବି_ECDSA_SK_CERT) {
		ଫେରନ୍ତୁ match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} ଅନ୍ୟଥା
		ଫେରନ୍ତୁ match_pattern_list(keyname, sigalgs, 0) == 1;
}

ଅକ୍ଷର *
sshkey_alg_list(ପୂର୍ଣ୍ଣସଂଖ୍ୟା certs_only, ପୂର୍ଣ୍ଣସଂଖ୍ୟା plain_only, ପୂର୍ଣ୍ଣସଂଖ୍ୟା include_sigonly, ଅକ୍ଷର sep)
{
	ଅକ୍ଷର *ret = ଖାଲି;
	size_t i;
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;
	ଅକ୍ଷର sep_str[2] = {sep, '\0'};

	ପାଇଁ (i = 0; keyimpls[i] != ଖାଲି; i++) {
		impl = keyimpls[i];
		ଯଦି (impl->name == ଖାଲି)
			ଜାରି;
		ଯଦି (!include_sigonly && impl->sigonly)
			ଜାରି;
		ଯଦି ((certs_only && !impl->cert) || (plain_only && impl->cert))
			ଜାରି;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_names_valid2(ଅଚଳ ଅକ୍ଷର *names, ପୂର୍ଣ୍ଣସଂଖ୍ୟା allow_wildcard, ପୂର୍ଣ୍ଣସଂଖ୍ୟା plain_only)
{
	ଅକ୍ଷର *s, *cp, *p;
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, type;

	ଯଦି (names == ଖାଲି || strcmp(names, "") == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି ((s = cp = strdup(names)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ପାଇଁ ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		ଯଦି (type == ଚାବି_UNSPEC) {
			ଯଦି (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = ଖାଲି;
				ପାଇଁ (i = 0; keyimpls[i] != ଖାଲି; i++) {
					ଯଦି (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						ଭାଙ୍ଗ;
					}
				}
				ଯଦି (impl != ଖାଲି)
					ଜାରି;
			}
			ମୁକ୍ତ(s);
			ଫେରନ୍ତୁ 0;
		} ଅନ୍ୟଥା ଯଦି (plain_only && sshkey_type_is_cert(type)) {
			ମୁକ୍ତ(s);
			ଫେରନ୍ତୁ 0;
		}
	}
	ମୁକ୍ତ(s);
	ଫେରନ୍ତୁ 1;
}

u_int
sshkey_size(ଅଚଳ ସଂରଚନା sshkey *k)
{
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;

	ଯଦି ((impl = sshkey_impl_from_ଚାବି(k)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (impl->funcs->size != ଖାଲି)
		ଫେରନ୍ତୁ impl->funcs->size(k);
	ଫେରନ୍ତୁ impl->keybits;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_type_is_valid_ca(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type)
{
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;

	ଯଦି ((impl = sshkey_impl_from_type(type)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	/* All non-certificate types may act as CAs */
	ଫେରନ୍ତୁ !impl->cert;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_is_cert(ଅଚଳ ସଂରଚନା sshkey *k)
{
	ଯଦି (k == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ sshkey_type_is_cert(k->type);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_is_sk(ଅଚଳ ସଂରଚନା sshkey *k)
{
	ଯଦି (k == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ବାଛ (sshkey_type_plain(k->type)) {
	ସ୍ଥିତି ଚାବି_ECDSA_SK:
	ସ୍ଥିତି ଚାବି_ED25519_SK:
		ଫେରନ୍ତୁ 1;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_type_plain(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type)
{
	ବାଛ (type) {
	ସ୍ଥିତି ଚାବି_RSA_CERT:
		ଫେରନ୍ତୁ ଚାବି_RSA;
	ସ୍ଥିତି ଚାବି_ECDSA_CERT:
		ଫେରନ୍ତୁ ଚାବି_ECDSA;
	ସ୍ଥିତି ଚାବି_ECDSA_SK_CERT:
		ଫେରନ୍ତୁ ଚାବି_ECDSA_SK;
	ସ୍ଥିତି ଚାବି_ED25519_CERT:
		ଫେରନ୍ତୁ ଚାବି_ED25519;
	ସ୍ଥିତି ଚାବି_MLDSA44_ED25519_CERT:
		ଫେରନ୍ତୁ ଚାବି_MLDSA44_ED25519;
	ସ୍ଥିତି ଚାବି_ED25519_SK_CERT:
		ଫେରନ୍ତୁ ଚାବି_ED25519_SK;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ type;
	}
}

/* Return the cert equivalent to a plain key type */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_type_certified(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type)
{
	ବାଛ (type) {
	ସ୍ଥିତି ଚାବି_RSA:
		ଫେରନ୍ତୁ ଚାବି_RSA_CERT;
	ସ୍ଥିତି ଚାବି_ECDSA:
		ଫେରନ୍ତୁ ଚାବି_ECDSA_CERT;
	ସ୍ଥିତି ଚାବି_ECDSA_SK:
		ଫେରନ୍ତୁ ଚାବି_ECDSA_SK_CERT;
	ସ୍ଥିତି ଚାବି_ED25519:
		ଫେରନ୍ତୁ ଚାବି_ED25519_CERT;
	ସ୍ଥିତି ଚାବି_MLDSA44_ED25519:
		ଫେରନ୍ତୁ ଚାବି_MLDSA44_ED25519_CERT;
	ସ୍ଥିତି ଚାବି_ED25519_SK:
		ଫେରନ୍ତୁ ଚାବି_ED25519_SK_CERT;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}
}

#ifdef WITH_OPENSSL
ସ୍ଥିର ଅଚଳ EVP_MD *
ssh_digest_to_md(ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_alg)
{
	ବାଛ (hash_alg) {
	ସ୍ଥିତି SSH_DIGEST_SHA1:
		ଫେରନ୍ତୁ EVP_sha1();
	ସ୍ଥିତି SSH_DIGEST_SHA256:
		ଫେରନ୍ତୁ EVP_sha256();
	ସ୍ଥିତି SSH_DIGEST_SHA384:
		ଫେରନ୍ତୁ EVP_sha384();
	ସ୍ଥିତି SSH_DIGEST_SHA512:
		ଫେରନ୍ତୁ EVP_sha512();
	}
	ଫେରନ୍ତୁ ଖାଲି;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_pkey_digest_sign(EVP_PKEY *pkey, ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_alg, u_char **sigp,
    size_t *lenp, ଅଚଳ u_char *data, size_t datalen)
{
	EVP_MD_CTX *ctx = ଖାଲି;
	u_char *sig = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;
	size_t slen;
	ଅଚଳ EVP_MD *evpmd;

	*sigp = ଖାଲି;
	*lenp = 0;

	slen = EVP_PKEY_size(pkey);
	ଯଦି (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	ଯଦି ((sig = malloc(slen)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;

	ଯଦି ((ctx = EVP_MD_CTX_new()) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (EVP_DigestSignInit(ctx, ଖାଲି, evpmd, ଖାଲି, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, data, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = ଖାଲି;
	ret = 0;

 out:
	EVP_MD_CTX_free(ctx);
	ମୁକ୍ତ(sig);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_pkey_digest_verify(EVP_PKEY *pkey, ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_alg, ଅଚଳ u_char *data,
    size_t datalen, u_char *sigbuf, size_t siglen)
{
	EVP_MD_CTX *ctx = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_INTERNAL_ERROR;
	ଅଚଳ EVP_MD *evpmd;

	ଯଦି ((evpmd = ssh_digest_to_md(hash_alg)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((ctx = EVP_MD_CTX_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି (EVP_DigestVerifyInit(ctx, ଖାଲି, evpmd, ଖାଲି, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ବାଛ (EVP_DigestVerify(ctx, sigbuf, siglen, data, datalen)) {
	ସ୍ଥିତି 1:
		ret = 0;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଭାଙ୍ଗ;
	}

 out:
	EVP_MD_CTX_free(ctx);
	ଫେରନ୍ତୁ ret;
}

/* XXX: these are really begging for a table-driven approach */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_curve_name_to_nid(ଅଚଳ ଅକ୍ଷର *name)
{
	ଯଦି (strcmp(name, "nistp256") == 0)
		ଫେରନ୍ତୁ NID_X9_62_prime256v1;
	ଅନ୍ୟଥା ଯଦି (strcmp(name, "nistp384") == 0)
		ଫେରନ୍ତୁ NID_secp384r1;
	ଅନ୍ୟଥା ଯଦି (strcmp(name, "nistp521") == 0)
		ଫେରନ୍ତୁ NID_secp521r1;
	ଅନ୍ୟଥା
		ଫେରନ୍ତୁ -1;
}

u_int
sshkey_curve_nid_to_bits(ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid)
{
	ବାଛ (nid) {
	ସ୍ଥିତି NID_X9_62_prime256v1:
		ଫେରନ୍ତୁ 256;
	ସ୍ଥିତି NID_secp384r1:
		ଫେରନ୍ତୁ 384;
	ସ୍ଥିତି NID_secp521r1:
		ଫେରନ୍ତୁ 521;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ 0;
	}
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_ecdsa_bits_to_nid(ପୂର୍ଣ୍ଣସଂଖ୍ୟା bits)
{
	ବାଛ (bits) {
	ସ୍ଥିତି 256:
		ଫେରନ୍ତୁ NID_X9_62_prime256v1;
	ସ୍ଥିତି 384:
		ଫେରନ୍ତୁ NID_secp384r1;
	ସ୍ଥିତି 521:
		ଫେରନ୍ତୁ NID_secp521r1;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}
}

ଅଚଳ ଅକ୍ଷର *
sshkey_curve_nid_to_name(ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid)
{
	ବାଛ (nid) {
	ସ୍ଥିତି NID_X9_62_prime256v1:
		ଫେରନ୍ତୁ "nistp256";
	ସ୍ଥିତି NID_secp384r1:
		ଫେରନ୍ତୁ "nistp384";
	ସ୍ଥିତି NID_secp521r1:
		ଫେରନ୍ତୁ "nistp521";
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ ଖାଲି;
	}
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_ec_nid_to_hash_alg(ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା kbits = sshkey_curve_nid_to_bits(nid);

	ଯଦି (kbits <= 0)
		ଫେରନ୍ତୁ -1;

	/* RFC5656 section 6.2.1 */
	ଯଦି (kbits <= 256)
		ଫେରନ୍ତୁ SSH_DIGEST_SHA256;
	ଅନ୍ୟଥା ଯଦି (kbits <= 384)
		ଫେରନ୍ତୁ SSH_DIGEST_SHA384;
	ଅନ୍ୟଥା
		ଫେରନ୍ତୁ SSH_DIGEST_SHA512;
}
#endif /* WITH_OPENSSL */

ସ୍ଥିର ଶୂନ୍ୟ
cert_free(ସଂରଚନା sshkey_cert *cert)
{
	u_int i;

	ଯଦି (cert == ଖାଲି)
		ଫେରନ୍ତୁ;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	ମୁକ୍ତ(cert->ଚାବି_id);
	ପାଇଁ (i = 0; i < cert->nprincipals; i++)
		ମୁକ୍ତ(cert->principals[i]);
	ମୁକ୍ତ(cert->principals);
	sshkey_free(cert->signature_ଚାବି);
	ମୁକ୍ତ(cert->signature_type);
	freezero(cert, ଆକାର(*cert));
}

ସ୍ଥିର ସଂରଚନା sshkey_cert *
cert_new(ଶୂନ୍ୟ)
{
	ସଂରଚନା sshkey_cert *cert;

	ଯଦି ((cert = calloc(1, ଆକାର(*cert))) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ଯଦି ((cert->certblob = sshbuf_new()) == ଖାଲି ||
	    (cert->critical = sshbuf_new()) == ଖାଲି ||
	    (cert->extensions = sshbuf_new()) == ଖାଲି) {
		cert_free(cert);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	cert->ଚାବି_id = ଖାଲି;
	cert->principals = ଖାଲି;
	cert->signature_ଚାବି = ଖାଲି;
	cert->signature_type = ଖାଲି;
	ଫେରନ୍ତୁ cert;
}

ସଂରଚନା sshkey *
sshkey_new(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type)
{
	ସଂରଚନା sshkey *k;
	ଅଚଳ ସଂରଚନା sshkey_impl *impl = ଖାଲି;

	ଯଦି (type != ଚାବି_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;

	/* All non-certificate types may act as CAs */
	ଯଦି ((k = calloc(1, ଆକାର(*k))) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	k->type = type;
	k->ecdsa_nid = -1;
	ଯଦି (impl != ଖାଲି && impl->funcs->alloc != ଖାଲି) {
		ଯଦି (impl->funcs->alloc(k) != 0) {
			ମୁକ୍ତ(k);
			ଫେରନ୍ତୁ ଖାଲି;
		}
	}
	ଯଦି (sshkey_is_cert(k)) {
		ଯଦି ((k->cert = cert_new()) == ଖାଲି) {
			sshkey_free(k);
			ଫେରନ୍ତୁ ଖାଲି;
		}
	}

	ଫେରନ୍ତୁ k;
}

/* Frees common FIDO fields */
ଶୂନ୍ୟ
sshkey_sk_cleanup(ସଂରଚନା sshkey *k)
{
	ମୁକ୍ତ(k->sk_application);
	sshbuf_free(k->sk_ଚାବି_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = ଖାଲି;
	k->sk_ଚାବି_handle = k->sk_reserved = ଖାଲି;
}

#ଯଦି defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#ନଚେତଯଦି defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#ଅନ୍ୟଥା
# define PREKEY_MMAP_FLAG	0
#endif

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_prekey_alloc(u_char **prekeyp, size_t len)
{
#ଯଦି defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = ଖାଲି;
	ଯଦି ((prekey = mmap(ଖାଲି, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
#ଯଦି defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(ଶୂନ୍ୟ)madvise(prekey, len, MADV_DONTDUMP);
#endif
	*prekeyp = prekey;
#ଅନ୍ୟଥା
	*prekeyp = calloc(1, len);
#endif /* HAVE_MMAP et al */
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
sshkey_prekey_free(ଶୂନ୍ୟ *prekey, size_t len)
{
#ଯଦି defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	ଯଦି (prekey == ଖାଲି)
		ଫେରନ୍ତୁ;
	munmap(prekey, len);
#ଅନ୍ୟଥା
	ମୁକ୍ତ(prekey);
#endif /* HAVE_MMAP et al */
}

ସ୍ଥିର ଶୂନ୍ୟ
sshkey_free_contents(ସଂରଚନା sshkey *k)
{
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;

	ଯଦି (k == ଖାଲି)
		ଫେରନ୍ତୁ;
	ଯଦି ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_ଚାବି_free(k);
	ଯଦି ((impl = sshkey_impl_from_type(k->type)) != ଖାଲି &&
	    impl->funcs->cleanup != ଖାଲି)
		impl->funcs->cleanup(k);
	ଯଦି (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_private, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

ଶୂନ୍ୟ
sshkey_free(ସଂରଚନା sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, ଆକାର(*k));
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cert_compare(ସଂରଚନା sshkey_cert *a, ସଂରଚନା sshkey_cert *b)
{
	ଯଦି (a == ଖାଲି && b == ଖାଲି)
		ଫେରନ୍ତୁ 1;
	ଯଦି (a == ଖାଲି || b == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		ଫେରନ୍ତୁ 0;
	ଯଦି (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

/* Compares FIDO-specific pubkey fields only */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_sk_fields_equal(ଅଚଳ ସଂରଚନା sshkey *a, ଅଚଳ ସଂରଚନା sshkey *b)
{
	ଯଦି (a->sk_application == ଖାଲି || b->sk_application == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (strcmp(a->sk_application, b->sk_application) != 0)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_equal_public(ଅଚଳ ସଂରଚନା sshkey *a, ଅଚଳ ସଂରଚନା sshkey *b)
{
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;

	ଯଦି (a == ଖାଲି || b == ଖାଲି ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		ଫେରନ୍ତୁ 0;
	ଯଦି ((impl = sshkey_impl_from_type(a->type)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ impl->funcs->equal(a, b);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_equal(ଅଚଳ ସଂରଚନା sshkey *a, ଅଚଳ ସଂରଚନା sshkey *b)
{
	ଯଦି (a == ଖାଲି || b == ଖାଲି || a->type != b->type)
		ଫେରନ୍ତୁ 0;
	ଯଦି (sshkey_is_cert(a)) {
		ଯଦି (!cert_compare(a->cert, b->cert))
			ଫେରନ୍ତୁ 0;
	}
	ଫେରନ୍ତୁ sshkey_equal_public(a, b);
}


/* Serialise common FIDO key parts */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_serialize_sk(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_put_cstring(b, ଚାବି->sk_application)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
to_blob_buf(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b, ପୂର୍ଣ୍ଣସଂଖ୍ୟା force_plain,
  ଗଣନା sshkey_serialize_rep opts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ret = SSH_ERR_INTERNAL_ERROR;
	ଅଚଳ ଅକ୍ଷର *typename;
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;

	ଯଦି (ଚାବି == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(ଚାବି->type) : ଚାବି->type;

	ଯଦି (sshkey_type_is_cert(type)) {
		ଯଦି (ଚାବି->cert == ଖାଲି)
			ଫେରନ୍ତୁ SSH_ERR_EXPECTED_CERT;
		ଯଦି (sshbuf_len(ଚାବି->cert->certblob) == 0)
			ଫେରନ୍ତୁ SSH_ERR_ଚାବି_LACKS_CERTBLOB;
		/* Use the existing blob */
		ଯଦି ((ret = sshbuf_putb(b, ଚାବି->cert->certblob)) != 0)
			ଫେରନ୍ତୁ ret;
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି ((impl = sshkey_impl_from_type(type)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, ଚାବି->ecdsa_nid);
	ଯଦି ((ret = sshbuf_put_cstring(b, typename)) != 0)
		ଫେରନ୍ତୁ ret;
	ଫେରନ୍ତୁ impl->funcs->serialize_public(ଚାବି, b, opts);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_putb(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b)
{
	ଫେରନ୍ତୁ to_blob_buf(ଚାବି, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_puts_opts_internal(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b,
    ଗଣନା sshkey_serialize_rep opts, ପୂର୍ଣ୍ଣସଂଖ୍ୟା force_plain)
{
	ସଂରଚନା sshbuf *tmp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((tmp = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(ଚାବି, tmp, force_plain, opts);
	ଯଦି (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_puts(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b)
{
	ଫେରନ୍ତୁ sshkey_puts_opts_internal(ଚାବି, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_putb_plain(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b)
{
	ଫେରନ୍ତୁ to_blob_buf(ଚାବି, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_puts_plain(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b)
{
	ଫେରନ୍ତୁ sshkey_puts_opts_internal(ଚାବି, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
to_blob(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, u_char **blobp, size_t *lenp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା force_plain,
    ଗଣନା sshkey_serialize_rep opts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	ସଂରଚନା sshbuf *b = ଖାଲି;

	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	ଯଦି (blobp != ଖାଲି)
		*blobp = ଖାଲି;
	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((ret = to_blob_buf(ଚାବି, b, force_plain, opts)) != 0)
		ଯାଅ out;
	len = sshbuf_len(b);
	ଯଦି (lenp != ଖାଲି)
		*lenp = len;
	ଯଦି (blobp != ଖାଲି) {
		ଯଦି ((*blobp = malloc(len)) == ଖାଲି) {
			ret = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_to_blob(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, u_char **blobp, size_t *lenp)
{
	ଫେରନ୍ତୁ to_blob(ଚାବି, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_plain_to_blob(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, u_char **blobp, size_t *lenp)
{
	ଫେରନ୍ତୁ to_blob(ଚାବି, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_fingerprint_raw(ଅଚଳ ସଂରଚନା sshkey *k, ପୂର୍ଣ୍ଣସଂଖ୍ୟା dgst_alg,
    u_char **retp, size_t *lenp)
{
	u_char *blob = ଖାଲି, *ret = ଖାଲି;
	size_t blob_len = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (retp != ଖାଲି)
		*retp = ଖାଲି;
	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	ଯଦି (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	ଯଦି ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		ଯାଅ out;
	ଯଦି ((ret = calloc(1, SSH_DIGEST_MAX_LENGTH)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_LENGTH)) != 0)
		ଯାଅ out;
	/* success */
	ଯଦି (retp != ଖାଲି) {
		*retp = ret;
		ret = ଖାଲି;
	}
	ଯଦି (lenp != ଖାଲି)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	ମୁକ୍ତ(ret);
	ଯଦି (blob != ଖାଲି)
		freezero(blob, blob_len);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ଅକ୍ଷର *
fingerprint_b64(ଅଚଳ ଅକ୍ଷର *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	ଅକ୍ଷର *ret;
	size_t plen = strlen(alg) + 1;
	size_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	ଯଦି (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	ଯଦି (dgst_raw_len == 0)
		ଫେରନ୍ତୁ ret;
	ଯଦି (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ଅକ୍ଷର *
fingerprint_hex(ଅଚଳ ଅକ୍ଷର *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	ଅକ୍ଷର *retval, hex[5];
	size_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	ଯଦି (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	ପାଇଁ (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, ଆକାର(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	ଫେରନ୍ତୁ retval;
}

ସ୍ଥିର ଅକ୍ଷର *
fingerprint_bubblebabble(u_char *dgst_raw, size_t dgst_raw_len)
{
	ଅକ୍ଷର vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	ଅକ୍ଷର consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	ଅକ୍ଷର *retval;

	rounds = (dgst_raw_len / 2) + 1;
	ଯଦି ((retval = calloc(rounds, 6)) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	retval[j++] = 'x';
	ପାଇଁ (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		ଯଦି ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			ଯଦି ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} ଅନ୍ୟଥା {
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
	ଫେରନ୍ତୁ retval;
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
ସ୍ଥିର ଅକ୍ଷର *
fingerprint_randomart(ଅଚଳ ଅକ୍ଷର *alg, u_char *dgst_raw, size_t dgst_raw_len,
    ଅଚଳ ସଂରଚନା sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	ଅକ୍ଷର	*augmentation_string = " .o+=*BOX@%&#/^SE";
	ଅକ୍ଷର	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	size_t	 i, tlen, hlen;
	u_int	 b;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 x, y, r;
	size_t	 len = strlen(augmentation_string) - 1;

	ଯଦି ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * ଆକାର(ଅକ୍ଷର));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	ପାଇଁ (i = 0; i < dgst_raw_len; i++) {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ;
		/* each byte conveys four 2-bit move commands */
		ନିବେଶ = dgst_raw[i];
		ପାଇଁ (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (ନିବେଶ & 0x1) ? 1 : -1;
			y += (ନିବେଶ & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			ଯଦି (field[x][y] < len - 2)
				field[x][y]++;
			ନିବେଶ = ନିବେଶ >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, ଆକାର(title), "[%s %u]",
		sshkey_type(k), sshkey_size(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	ଯଦି (r < 0 || r > (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)ଆକାର(title))
		r = snprintf(title, ଆକାର(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, ଆକାର(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	ପାଇଁ (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	memcpy(p, title, tlen);
	p += tlen;
	ପାଇଁ (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	ପାଇଁ (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		ପାଇଁ (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	ପାଇଁ (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	memcpy(p, hash, hlen);
	p += hlen;
	ପାଇଁ (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	ଫେରନ୍ତୁ retval;
}

ଅକ୍ଷର *
sshkey_fingerprint(ଅଚଳ ସଂରଚନା sshkey *k, ପୂର୍ଣ୍ଣସଂଖ୍ୟା dgst_alg,
    ଗଣନା sshkey_fp_rep dgst_rep)
{
	ଅକ୍ଷର *retval = ଖାଲି;
	u_char *dgst_raw;
	size_t dgst_raw_len;

	ଯଦି (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		ଫେରନ୍ତୁ ଖାଲି;
	ବାଛ (dgst_rep) {
	ସ୍ଥିତି SSH_FP_DEFAULT:
		ଯଦି (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} ଅନ୍ୟଥା {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		freezero(dgst_raw, dgst_raw_len);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	freezero(dgst_raw, dgst_raw_len);
	ଫେରନ୍ତୁ retval;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
peek_type_nid(ଅଚଳ ଅକ୍ଷର *s, size_t l, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *nid)
{
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ପାଇଁ (i = 0; keyimpls[i] != ଖାଲି; i++) {
		impl = keyimpls[i];
		ଯଦି (impl->name == ଖାଲି || strlen(impl->name) != l)
			ଜାରି;
		ଯଦି (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			ଯଦି (ଚାବି_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			ଫେରନ୍ତୁ impl->type;
		}
	}
	ଫେରନ୍ତୁ ଚାବି_UNSPEC;
}

/* XXX this can now be made const char * */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_read(ସଂରଚନା sshkey *ret, ଅକ୍ଷର **cpp)
{
	ସଂରଚନା sshkey *k;
	ଅକ୍ଷର *cp, *blobcopy;
	size_t space;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, type, curve_nid = -1;
	ସଂରଚନା sshbuf *blob;

	ଯଦି (ret == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (ret->type != ଚାବି_UNSPEC && sshkey_impl_from_type(ret->type) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	ଯଦି (space == strlen(cp))
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଯଦି ((type = peek_type_nid(cp, space, &curve_nid)) == ଚାବି_UNSPEC)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	ପାଇଁ (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	ଯଦି (*cp == '\0')
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଯଦି (ret->type != ଚାବି_UNSPEC && ret->type != type)
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_TYPE_MISMATCH;
	ଯଦି ((blob = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	ଯଦି ((blobcopy = strndup(cp, space)) == ଖାଲି) {
		sshbuf_free(blob);
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	}
	ଯଦି ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		ମୁକ୍ତ(blobcopy);
		sshbuf_free(blob);
		ଫେରନ୍ତୁ r;
	}
	ମୁକ୍ତ(blobcopy);
	ଯଦି ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		ଫେରନ୍ତୁ r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	ପାଇଁ (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	ଯଦି (k->type != type) {
		sshkey_free(k);
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_TYPE_MISMATCH;
	}
	ଯଦି (ଚାବି_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		ଫେରନ୍ତୁ SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, ଆକାର(*k));

	/* success */
	*cpp = cp;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_to_base64(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ଅକ୍ଷର **b64p)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ଅକ୍ଷର *uu = ଖାଲି;

	ଯଦି (b64p != ଖାଲି)
		*b64p = ଖାଲି;
	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshkey_putb(ଚାବି, b)) != 0)
		ଯାଅ out;
	ଯଦି ((uu = sshbuf_dtob64_string(b, 0)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	/* Success */
	ଯଦି (b64p != ଖାଲି) {
		*b64p = uu;
		uu = ଖାଲି;
	}
	r = 0;
 out:
	sshbuf_free(b);
	ମୁକ୍ତ(uu);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_format_text(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ଅକ୍ଷର *uu = ଖାଲି;

	ଯଦି ((r = sshkey_to_base64(ଚାବି, &uu)) != 0)
		ଯାଅ out;
	ଯଦି ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(ଚାବି), uu)) != 0)
		ଯାଅ out;
	r = 0;
 out:
	ମୁକ୍ତ(uu);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_write(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, FILE *f)
{
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshkey_format_text(ଚାବି, b)) != 0)
		ଯାଅ out;
	ଯଦି (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		ଯଦି (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		ଯାଅ out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

ଅଚଳ ଅକ୍ଷର *
sshkey_cert_type(ଅଚଳ ସଂରଚନା sshkey *k)
{
	ବାଛ (k->cert->type) {
	ସ୍ଥିତି SSH2_CERT_TYPE_USER:
		ଫେରନ୍ତୁ "user";
	ସ୍ଥିତି SSH2_CERT_TYPE_HOST:
		ଫେରନ୍ତୁ "host";
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ "unknown";
	}
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_check_rsa_length(ଅଚଳ ସଂରଚନା sshkey *k, ପୂର୍ଣ୍ଣସଂଖ୍ୟା min_size)
{
#ifdef WITH_OPENSSL
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା nbits;

	ଯଦି (k == ଖାଲି || k->pkey == ଖାଲି ||
	    (k->type != ଚାବି_RSA && k->type != ଚାବି_RSA_CERT))
		ଫେରନ୍ତୁ 0;
	nbits = EVP_PKEY_bits(k->pkey);
	ଯଦି (nbits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    (min_size > 0 && nbits < min_size))
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_LENGTH;
#endif /* WITH_OPENSSL */
	ଫେରନ୍ତୁ 0;
}

#ifdef WITH_OPENSSL
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_ecdsa_ଚାବି_to_nid(ଅଚଳ EC_ଚାବି *k)
{
	ଅଚଳ EC_GROUP *g;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid;

	ଯଦି (k == ଖାଲି || (g = EC_ଚାବି_get0_group(k)) == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	ଯଦି ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		ଫେରନ୍ତୁ -1;
	ଫେରନ୍ତୁ nid;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	ଫେରନ୍ତୁ sshkey_ecdsa_ଚାବି_to_nid(EVP_PKEY_get0_EC_ଚାବି(pkey));
}
#endif /* WITH_OPENSSL */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_generate(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, u_int bits, ସଂରଚନା sshkey **keyp)
{
	ସଂରଚନା sshkey *k;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_INTERNAL_ERROR;
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;

	ଯଦି (keyp == ଖାଲି || sshkey_type_is_cert(type))
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	*keyp = ଖାଲି;
	ଯଦି ((impl = sshkey_impl_from_type(type)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_TYPE_UNKNOWN;
	ଯଦି (impl->funcs->generate == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_FEATURE_UNSUPPORTED;
	ଯଦି ((k = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	k->type = type;
	ଯଦି ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		ଫେରନ୍ତୁ ret;
	}
	/* success */
	*keyp = k;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_cert_copy(ଅଚଳ ସଂରଚନା sshkey *from_ଚାବି, ସଂରଚନା sshkey *to_ଚାବି)
{
	u_int i;
	ଅଚଳ ସଂରଚନା sshkey_cert *from;
	ସଂରଚନା sshkey_cert *to;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (to_ଚାବି == ଖାଲି || (from = from_ଚାବି->cert) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	ଯଦି ((to = cert_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;

	ଯଦି ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		ଯାଅ out;

	to->serial = from->serial;
	to->type = from->type;
	ଯଦି (from->ଚାବି_id == ଖାଲି)
		to->ଚାବି_id = ଖାଲି;
	ଅନ୍ୟଥା ଯଦି ((to->ଚାବି_id = strdup(from->ଚାବି_id)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	ଯଦି (from->signature_ଚାବି == ଖାଲି)
		to->signature_ଚାବି = ଖାଲି;
	ଅନ୍ୟଥା ଯଦି ((r = sshkey_from_private(from->signature_ଚାବି,
	    &to->signature_ଚାବି)) != 0)
		ଯାଅ out;
	ଯଦି (from->signature_type != ଖାଲି &&
	    (to->signature_type = strdup(from->signature_type)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	ଯଦି (from->nprincipals > 0) {
		ଯଦି ((to->principals = calloc(from->nprincipals,
		    ଆକାର(*to->principals))) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		ପାଇଁ (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			ଯଦି (to->principals[i] == ଖାଲି) {
				to->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				ଯାଅ out;
			}
		}
	}
	to->nprincipals = from->nprincipals;

	/* success */
	cert_free(to_ଚାବି->cert);
	to_ଚାବି->cert = to;
	to = ଖାଲି;
	r = 0;
 out:
	cert_free(to);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_copy_public_sk(ଅଚଳ ସଂରଚନା sshkey *from, ସଂରଚନା sshkey *to)
{
	/* Append security-key application string */
	ଯଦି ((to->sk_application = strdup(from->sk_application)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_from_private(ଅଚଳ ସଂରଚନା sshkey *k, ସଂରଚନା sshkey **pkp)
{
	ସଂରଚନା sshkey *n = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;

	*pkp = ଖାଲି;
	ଯଦି ((impl = sshkey_impl_from_ଚାବି(k)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_TYPE_UNKNOWN;
	ଯଦି ((n = sshkey_new(k->type)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = impl->funcs->copy_public(k, n)) != 0)
		ଯାଅ out;
	ଯଦି (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		ଯାଅ out;
	/* success */
	*pkp = n;
	n = ଖାଲି;
	r = 0;
 out:
	sshkey_free(n);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_is_shielded(ସଂରଚନା sshkey *k)
{
	ଫେରନ୍ତୁ k != ଖାଲି && k->shielded_private != ଖାଲି;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_shield_private(ସଂରଚନା sshkey *k)
{
	ସଂରଚନା sshbuf *prvbuf = ଖାଲି;
	u_char *prekey = ଖାଲି, *enc = ଖାଲି, keyiv[SSH_DIGEST_MAX_LENGTH];
	ସଂରଚନା sshcipher_ctx *cctx = ଖାଲି;
	ଅଚଳ ସଂରଚନା sshcipher *cipher;
	size_t i, enclen = 0;
	ସଂରଚନା sshkey *kswap = ଖାଲି, tmp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	ଯଦି ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ଖାଲି) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	ଯଦି (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		ଯାଅ out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	ଯଦି ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		ଯାଅ out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	ଯଦି ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		ଯାଅ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	ଯଦି ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		ଯାଅ out;

	/* Serialise and encrypt the private key using the ephemeral key */
	ଯଦି ((prvbuf = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		ଯାଅ out;
	ଯଦି ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		ଯାଅ out;
	/* pad to cipher blocksize */
	i = 0;
	ଯେତେବେଳେ (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		ଯଦି ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			ଯାଅ out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	ଯଦି ((enc = malloc(enclen)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		ଯାଅ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	ଯଦି ((r = sshkey_from_private(k, &kswap)) != 0)
		ଯାଅ out;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_private = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = ଖାଲି; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 out:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, ଆକାର(keyiv));
	explicit_bzero(&tmp, ଆକାର(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	ଫେରନ୍ତୁ r;
}

/* Check deterministic padding after private key */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
private2_check_padding(ସଂରଚନା sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	i = 0;
	ଯେତେବେଳେ (sshbuf_len(decrypted)) {
		ଯଦି ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			ଯାଅ out;
		ଯଦି (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, ଆକାର(pad));
	explicit_bzero(&i, ଆକାର(i));
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_unshield_private(ସଂରଚନା sshkey *k)
{
	ସଂରଚନା sshbuf *prvbuf = ଖାଲି;
	u_char *cp, keyiv[SSH_DIGEST_MAX_LENGTH];
	ସଂରଚନା sshcipher_ctx *cctx = ଖାଲି;
	ଅଚଳ ସଂରଚନା sshcipher *cipher;
	ସଂରଚନା sshkey *kswap = ଖାଲି, tmp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	ଯଦି (!sshkey_is_shielded(k))
		ଫେରନ୍ତୁ 0; /* nothing to do */

	ଯଦି ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ଖାଲି) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	ଯଦି (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		ଯାଅ out;
	}
	/* check size of shielded key blob */
	ଯଦି (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}

	/* Calculate the ephemeral key from the prekey */
	ଯଦି ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		ଯାଅ out;
	ଯଦି ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		ଯାଅ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	ଯଦି ((prvbuf = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		ଯାଅ out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(k->shielded_private, k->shielded_len, stderr);
#endif
	ଯଦି ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		ଯାଅ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	ଯଦି ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		ଯାଅ out;

	ଯଦି ((r = private2_check_padding(prvbuf)) != 0)
		ଯାଅ out;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 out:
	cipher_free(cctx);
	explicit_bzero(keyiv, ଆକାର(keyiv));
	explicit_bzero(&tmp, ଆକାର(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cert_parse(ସଂରଚନା sshbuf *b, ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *certbuf,
    ଅଚଳ ଅକ୍ଷର *ca_sigalg_allowlist)
{
	ସଂରଚନା sshbuf *principals = ଖାଲି, *crit = ଖାଲି;
	ସଂରଚନା sshbuf *exts = ଖାଲି, *ca = ଖାଲି;
	u_char *sig = ଖାଲି;
	ଅକ୍ଷର *sigtype = ଖାଲି;
	size_t signed_len = 0, slen = 0, kidlen = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	ଯଦି ((ret = sshbuf_putb(ଚାବି->cert->certblob, certbuf)) != 0)
		ଫେରନ୍ତୁ ret;

	/* Parse body of certificate up to signature */
	ଯଦି ((ret = sshbuf_get_u64(b, &ଚାବି->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &ଚାବି->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &ଚାବି->cert->ଚାବି_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &ଚାବି->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &ଚାବି->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, ଖାଲି, ଖାଲି)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(ଚାବି->cert->certblob) - sshbuf_len(b);

	ଯଦି ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}

	/* Is this a signature we're prepared to accept? */
	ଯଦି ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (ca_sigalg_allowlist != ଖାଲି &&
	    match_pattern_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ଯାଅ out;
	}

	/* Parse CA key and check whether we might accept it */
	ଯଦି (sshkey_from_blob_internal(ca, &ଚାବି->cert->signature_ଚାବି, 0,
	    ca_sigalg_allowlist, ଖାଲି) != 0) {
		ret = SSH_ERR_ଚାବି_CERT_INVALID_SIGN_ଚାବି;
		ଯାଅ out;
	}
	ଯଦି (!sshkey_type_is_valid_ca(ଚାବି->cert->signature_ଚାବି->type)) {
		ret = SSH_ERR_ଚାବି_CERT_INVALID_SIGN_ଚାବି;
		ଯାଅ out;
	}

	ଯଦି (ଚାବି->cert->type != SSH2_CERT_TYPE_USER &&
	    ଚାବି->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_ଚାବି_CERT_UNKNOWN_TYPE;
		ଯାଅ out;
	}

	/* Parse principals section */
	ଯେତେବେଳେ (sshbuf_len(principals) > 0) {
		ଅକ୍ଷର *principal = ଖାଲି;
		ଅକ୍ଷର **oprincipals = ଖାଲି;

		ଯଦି (ଚାବି->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		ଯଦି ((ret = sshbuf_get_cstring(principals, &principal,
		    ଖାଲି)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		oprincipals = ଚାବି->cert->principals;
		ଚାବି->cert->principals = recallocarray(ଚାବି->cert->principals,
		    ଚାବି->cert->nprincipals, ଚାବି->cert->nprincipals + 1,
		    ଆକାର(*ଚାବି->cert->principals));
		ଯଦି (ଚାବି->cert->principals == ଖାଲି) {
			ମୁକ୍ତ(principal);
			ଚାବି->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		ଚାବି->cert->principals[ଚାବି->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	ଯଦି ((ret = sshbuf_putb(ଚାବି->cert->critical, crit)) != 0 ||
	    (exts != ଖାଲି &&
	    (ret = sshbuf_putb(ଚାବି->cert->extensions, exts)) != 0))
		ଯାଅ out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	ଯେତେବେଳେ (sshbuf_len(crit) != 0) {
		ଯଦି ((ret = sshbuf_get_string_direct(crit, ଖାଲି, ଖାଲି)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, ଖାଲି, ଖାଲି)) != 0) {
			sshbuf_reset(ଚାବି->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
	}
	ଯେତେବେଳେ (exts != ଖାଲି && sshbuf_len(exts) != 0) {
		ଯଦି ((ret = sshbuf_get_string_direct(exts, ଖାଲି, ଖାଲି)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, ଖାଲି, ଖାଲି)) != 0) {
			sshbuf_reset(ଚାବି->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
	}

	/* Finally, validate signature */
	ଯଦି ((ret = sshkey_verify(ଚାବି->cert->signature_ଚାବି, sig, slen,
	    sshbuf_ptr(ଚାବି->cert->certblob), signed_len, ଖାଲି, 0, ଖାଲି)) != 0)
		ଯାଅ out;

	/* Success */
	ret = 0;
	ଚାବି->cert->signature_type = sigtype;
	sigtype = ଖାଲି;
 out:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	ମୁକ୍ତ(sig);
	ମୁକ୍ତ(sigtype);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_deserialize_sk(ସଂରଚନା sshbuf *b, ସଂରଚନା sshkey *ଚାବି)
{
	/* Parse additional security-key application string */
	ଯଦି (sshbuf_get_cstring(b, &ଚାବି->sk_application, ଖାଲି) != 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_from_blob_internal(ସଂରଚନା sshbuf *b, ସଂରଚନା sshkey **keyp,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା allow_cert, ଅଚଳ ଅକ୍ଷର *alg_allowlist, ଅଚଳ ଅକ୍ଷର *ca_sigalg_allowlist)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ret = SSH_ERR_INTERNAL_ERROR;
	ଅକ୍ଷର *ktype = ଖାଲି;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ସଂରଚନା sshbuf *copy;
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	ଯଦି (keyp != ଖାଲି)
		*keyp = ଖାଲି;
	ଯଦି ((copy = sshbuf_fromb(b)) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (sshbuf_get_cstring(b, &ktype, ଖାଲି) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}

	type = sshkey_type_from_name(ktype);
	ଯଦି (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_ଚାବି_CERT_INVALID_SIGN_ଚାବି;
		ଯାଅ out;
	}

	ଯଦି (alg_allowlist != ଖାଲି &&
	    !sshkey_match_keyname_to_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_ଚାବି_ALG_UNSUPPORTED;
		ଯାଅ out;
	}

	ଯଦି ((impl = sshkey_impl_from_type(type)) == ଖାଲି) {
		ret = SSH_ERR_ଚାବି_TYPE_UNKNOWN;
		ଯାଅ out;
	}
	ଯଦି ((ଚାବି = sshkey_new(type)) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		ଯଦି (sshbuf_get_string_direct(b, ଖାଲି, ଖାଲି) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
	}
	ଯଦି ((ret = impl->funcs->deserialize_public(ktype, b, ଚାବି)) != 0)
		ଯାଅ out;

	/* Parse certificate potion */
	ଯଦି (sshkey_is_cert(ଚାବି) &&
	    (ret = cert_parse(b, ଚାବି, copy, ca_sigalg_allowlist)) != 0)
		ଯାଅ out;

	ଯଦି (ଚାବି != ଖାଲି && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ret = 0;
	ଯଦି (keyp != ଖାଲି) {
		*keyp = ଚାବି;
		ଚାବି = ଖାଲି;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(ଚାବି);
	ମୁକ୍ତ(ktype);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_from_blob(ଅଚଳ u_char *blob, size_t blen, ସଂରଚନା sshkey **keyp)
{
	ସଂରଚନା sshbuf *b;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((b = sshbuf_from(blob, blen)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1, ଖାଲି, ଖାଲି);
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_fromb(ସଂରଚନା sshbuf *b, ସଂରଚନା sshkey **keyp)
{
	ଫେରନ୍ତୁ sshkey_from_blob_internal(b, keyp, 1, ଖାଲି, ଖାଲି);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_fromb_allowlist(ସଂରଚନା sshbuf *b, ସଂରଚନା sshkey **keyp,
    ଅଚଳ ଅକ୍ଷର *alg_allowlist, ଅଚଳ ଅକ୍ଷର *ca_sigalg_allowlist)
{
	ଫେରନ୍ତୁ sshkey_from_blob_internal(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_froms(ସଂରଚନା sshbuf *buf, ସଂରଚନା sshkey **keyp)
{
	ସଂରଚନା sshbuf *b;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_froms(buf, &b)) != 0)
		ଫେରନ୍ତୁ r;
	r = sshkey_from_blob_internal(b, keyp, 1, ଖାଲି, ଖାଲି);
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_get_sigtype(ଅଚଳ u_char *sig, size_t siglen, ଅକ୍ଷର **sigtypep)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ଅକ୍ଷର *sigtype = ଖାଲି;

	ଯଦି (sigtypep != ଖାଲି)
		*sigtypep = ଖାଲି;
	ଯଦି ((b = sshbuf_from(sig, siglen)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_get_cstring(b, &sigtype, ଖାଲି)) != 0)
		ଯାଅ out;
	/* success */
	ଯଦି (sigtypep != ଖାଲି) {
		*sigtypep = sigtype;
		sigtype = ଖାଲି;
	}
	r = 0;
 out:
	ମୁକ୍ତ(sigtype);
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_check_cert_sigtype(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *allowed)
{
	ଯଦି (ଚାବି == ଖାଲି || allowed == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (!sshkey_type_is_cert(ଚାବି->type))
		ଫେରନ୍ତୁ 0;
	ଯଦି (ଚାବି->cert == ଖାଲି || ଚାବି->cert->signature_type == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (match_pattern_list(ଚାବି->cert->signature_type, allowed, 0) != 1)
		ଫେରନ୍ତୁ SSH_ERR_SIGN_ALG_UNSUPPORTED;
	ଫେରନ୍ତୁ 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
ଅଚଳ ଅକ୍ଷର *
sshkey_sigalg_by_name(ଅଚଳ ଅକ୍ଷର *name)
{
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ପାଇଁ (i = 0; keyimpls[i] != ଖାଲି; i++) {
		impl = keyimpls[i];
		ଯଦି (strcmp(impl->name, name) != 0)
			ଜାରି;
		ଯଦି (impl->sigalg != ଖାଲି)
			ଫେରନ୍ତୁ impl->sigalg;
		ଯଦି (!impl->cert)
			ଫେରନ୍ତୁ impl->name;
		ଫେରନ୍ତୁ sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	ଫେରନ୍ତୁ ଖାଲି;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_check_sigtype(ଅଚଳ u_char *sig, size_t siglen,
    ଅଚଳ ଅକ୍ଷର *requested_alg)
{
	ଅଚଳ ଅକ୍ଷର *expected_alg;
	ଅକ୍ଷର *sigtype = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (requested_alg == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		ଫେରନ୍ତୁ r;
	r = strcmp(expected_alg, sigtype) == 0;
	ମୁକ୍ତ(sigtype);
	ଫେରନ୍ତୁ r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_sign(ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *alg, ଅଚଳ ଅକ୍ଷର *sk_provider, ଅଚଳ ଅକ୍ଷର *sk_pin, u_int compat)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା was_shielded = sshkey_is_shielded(ଚାବି);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r2, r = SSH_ERR_INTERNAL_ERROR;
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;

	ଯଦି (sigp != ଖାଲି)
		*sigp = ଖାଲି;
	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	ଯଦି (datalen > SSH_ଚାବି_MAX_SIGN_DATA_SIZE)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((impl = sshkey_impl_from_ଚାବି(ଚାବି)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_TYPE_UNKNOWN;
	ଯଦି ((r = sshkey_unshield_private(ଚାବି)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (sshkey_is_sk(ଚାବି)) {
		r = sshsk_sign(sk_provider, ଚାବି, sigp, lenp, data,
		    datalen, compat, sk_pin);
	} ଅନ୍ୟଥା ଯଦି ((ଚାବି->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(ଚାବି, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	} ଅନ୍ୟଥା {
		ଯଦି (impl->funcs->sign == ଖାଲି)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ଅନ୍ୟଥା {
			r = impl->funcs->sign(ଚାବି, sigp, lenp, data, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	ଯଦି (was_shielded && (r2 = sshkey_shield_private(ଚାବି)) != 0)
		ଫେରନ୍ତୁ r2;
	ଫେରନ୍ତୁ r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_verify(ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ u_char *sig, size_t siglen,
    ଅଚଳ u_char *data, size_t dlen, ଅଚଳ ଅକ୍ଷର *alg, u_int compat,
    ସଂରଚନା sshkey_sig_details **detailsp)
{
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;

	ଯଦି (detailsp != ଖାଲି)
		*detailsp = ଖାଲି;
	ଯଦି (siglen == 0 || dlen > SSH_ଚାବି_MAX_SIGN_DATA_SIZE)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((impl = sshkey_impl_from_ଚାବି(ଚାବି)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_TYPE_UNKNOWN;
	ଫେରନ୍ତୁ impl->funcs->verify(ଚାବି, sig, siglen, data, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_to_certified(ସଂରଚନା sshkey *k)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା newtype;

	ଯଦି ((newtype = sshkey_type_certified(k->type)) == -1)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((k->cert = cert_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	ଫେରନ୍ତୁ 0;
}

/* Convert a certificate to its raw key equivalent */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_drop_cert(ସଂରଚନା sshkey *k)
{
	ଯଦି (!sshkey_type_is_cert(k->type))
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = ଖାଲି;
	k->type = sshkey_type_plain(k->type);
	ଫେରନ୍ତୁ 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_certify_custom(ସଂରଚନା sshkey *k, ସଂରଚନା sshkey *ca, ଅଚଳ ଅକ୍ଷର *alg,
    ଅଚଳ ଅକ୍ଷର *sk_provider, ଅଚଳ ଅକ୍ଷର *sk_pin,
    sshkey_certify_signer *signer, ଶୂନ୍ୟ *signer_ctx)
{
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;
	ସଂରଚନା sshbuf *principals = ଖାଲି;
	u_char *ca_blob = ଖାଲି, *sig_blob = ଖାଲି, nonce[32];
	size_t i, ca_len, sig_len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା sshbuf *cert = ଖାଲି;
	ଅକ୍ଷର *sigtype = ଖାଲି;

	ଯଦି (k == ଖାଲି || k->cert == ଖାଲି ||
	    k->cert->certblob == ଖାଲି || ca == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (!sshkey_is_cert(k))
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_TYPE_UNKNOWN;
	ଯଦି (!sshkey_type_is_valid_ca(ca->type))
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_CERT_INVALID_SIGN_ଚାବି;
	ଯଦି ((impl = sshkey_impl_from_ଚାବି(k)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	ଯଦି (alg == ଖାଲି)
		alg = k->cert->signature_type;
	ଅନ୍ୟଥା ଯଦି (k->cert->signature_type != ଖାଲି &&
	    strcmp(alg, k->cert->signature_type) != 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	ଯଦି (alg == ଖାଲି && ca->type == ଚାବି_RSA)
		alg = "rsa-sha2-512";

	ଯଦି ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_CERT_INVALID_SIGN_ଚାବି;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	ଯଦି ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		ଯାଅ out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, ଆକାର(nonce));
	ଯଦି ((ret = sshbuf_put_string(cert, nonce, ଆକାର(nonce))) != 0)
		ଯାଅ out;

	/* Public key next */
	ଯଦି ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		ଯାଅ out;

	/* Then remaining cert fields */
	ଯଦି ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->ଚାବି_id)) != 0)
		ଯାଅ out;

	ଯଦି ((principals = sshbuf_new()) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ପାଇଁ (i = 0; i < k->cert->nprincipals; i++) {
		ଯଦି ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			ଯାଅ out;
	}
	ଯଦି ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, ଖାଲି, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		ଯାଅ out;

	/* Sign the whole mess */
	ଯଦି ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		ଯାଅ out;
	/* Check and update signature_type against what was actually used */
	ଯଦି ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		ଯାଅ out;
	ଯଦି (alg != ଖାଲି && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ଯାଅ out;
	}
	ଯଦି (k->cert->signature_type == ଖାଲି) {
		k->cert->signature_type = sigtype;
		sigtype = ଖାଲି;
	}
	/* Append signature and we are done */
	ଯଦି ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		ଯାଅ out;
	ret = 0;
 out:
	ଯଦି (ret != 0)
		sshbuf_reset(cert);
	ମୁକ୍ତ(sig_blob);
	ମୁକ୍ତ(ca_blob);
	ମୁକ୍ତ(sigtype);
	sshbuf_free(principals);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
default_ଚାବି_sign(ସଂରଚନା sshkey *ଚାବି, u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *alg, ଅଚଳ ଅକ୍ଷର *sk_provider, ଅଚଳ ଅକ୍ଷର *sk_pin,
    u_int compat, ଶୂନ୍ୟ *ctx)
{
	ଯଦି (ctx != ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଫେରନ୍ତୁ sshkey_sign(ଚାବି, sigp, lenp, data, datalen, alg,
	    sk_provider, sk_pin, compat);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_certify(ସଂରଚନା sshkey *k, ସଂରଚନା sshkey *ca, ଅଚଳ ଅକ୍ଷର *alg,
    ଅଚଳ ଅକ୍ଷର *sk_provider, ଅଚଳ ଅକ୍ଷର *sk_pin)
{
	ଫେରନ୍ତୁ sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_ଚାବି_sign, ଖାଲି);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_cert_check_authority(ଅଚଳ ସଂରଚନା sshkey *k,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା want_host, ପୂର୍ଣ୍ଣସଂଖ୍ୟା wildcard_pattern, uint64_t verify_time,
    ଅଚଳ ଅକ୍ଷର *name, ଅଚଳ ଅକ୍ଷର **reason)
{
	u_int i, principal_matches;

	ଯଦି (reason == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_CERT_INVALID;
	}
	ଯଦି (want_host) {
		ଯଦି (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			ଫେରନ୍ତୁ SSH_ERR_ଚାବି_CERT_INVALID;
		}
	} ଅନ୍ୟଥା {
		ଯଦି (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			ଫେରନ୍ତୁ SSH_ERR_ଚାବି_CERT_INVALID;
		}
	}
	ଯଦି (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_CERT_INVALID;
	}
	ଯଦି (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_CERT_INVALID;
	}
	ଯଦି (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_CERT_INVALID;
	}
	ଯଦି (name == ଖାଲି)
		ଫେରନ୍ତୁ 0; /* principal matching not requested */

	principal_matches = 0;
	ପାଇଁ (i = 0; i < k->cert->nprincipals; i++) {
		ଯଦି (wildcard_pattern) {
			ଯଦି (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				ଭାଙ୍ଗ;
			}
		} ଅନ୍ୟଥା ଯଦି (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			ଭାଙ୍ଗ;
		}
	}
	ଯଦି (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_CERT_INVALID;
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_cert_check_authority_now(ଅଚଳ ସଂରଚନା sshkey *k,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା want_host, ପୂର୍ଣ୍ଣସଂଖ୍ୟା wildcard_pattern, ଅଚଳ ଅକ୍ଷର *name,
    ଅଚଳ ଅକ୍ଷର **reason)
{
	time_t now;

	ଯଦି ((now = time(ଖାଲି)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_CERT_INVALID;
	}
	ଫେରନ୍ତୁ sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_cert_check_host(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *host,
    ଅଚଳ ଅକ୍ଷର *ca_sign_algorithms, ଅଚଳ ଅକ୍ଷର **reason)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshkey_cert_check_authority_now(ଚାବି, 1, 1, host, reason)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (sshbuf_len(ଚାବି->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_CERT_INVALID;
	}
	ଯଦି (ca_sign_algorithms != ଖାଲି &&
	    (r = sshkey_check_cert_sigtype(ଚାବି, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_CERT_INVALID;
	}
	ଫେରନ୍ତୁ 0;
}

size_t
sshkey_format_cert_validity(ଅଚଳ ସଂରଚନା sshkey_cert *cert, ଅକ୍ଷର *s, size_t l)
{
	ଅକ୍ଷର from[32], to[32], ret[128];

	*from = *to = '\0';
	ଯଦି (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		ଫେରନ୍ତୁ strlcpy(s, "forever", l);

	ଯଦି (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, ଆକାର(from));
	ଯଦି (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, ଆକାର(to));

	ଯଦି (cert->valid_after == 0)
		snprintf(ret, ଆକାର(ret), "before %s", to);
	ଅନ୍ୟଥା ଯଦି (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, ଆକାର(ret), "after %s", from);
	ଅନ୍ୟଥା
		snprintf(ret, ଆକାର(ret), "from %s to %s", from, to);

	ଫେରନ୍ତୁ strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_serialize_private_sk(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_put_cstring(b, ଚାବି->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, ଚାବି->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, ଚାବି->sk_ଚାବି_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, ଚାବି->sk_reserved)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_private_serialize_opt(ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *buf,
    ଗଣନା sshkey_serialize_rep opts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା was_shielded = sshkey_is_shielded(ଚାବି);
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;

	ଯଦି ((impl = sshkey_impl_from_ଚାବି(ଚାବି)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	ଯଦି ((r = sshkey_unshield_private(ଚାବି)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_put_cstring(b, sshkey_ssh_name(ଚାବି))) != 0)
		ଯାଅ out;
	ଯଦି (sshkey_is_cert(ଚାବି)) {
		ଯଦି (ଚାବି->cert == ଖାଲି ||
		    sshbuf_len(ଚାବି->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_put_stringb(b, ଚାବି->cert->certblob)) != 0)
			ଯାଅ out;
	}
	ଯଦି ((r = impl->funcs->serialize_private(ଚାବି, b, opts)) != 0)
		ଯାଅ out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	ଯଦି (was_shielded)
		r = sshkey_shield_private(ଚାବି);
	ଯଦି (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_private_serialize(ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b)
{
	ଫେରନ୍ତୁ sshkey_private_serialize_opt(ଚାବି, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_private_deserialize_sk(ସଂରଚନା sshbuf *buf, ସଂରଚନା sshkey *k)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((k->sk_ଚାବି_handle = sshbuf_new()) == ଖାଲି ||
	    (k->sk_reserved = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_get_cstring(buf, &k->sk_application, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_ଚାବି_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_private_deserialize(ସଂରଚନା sshbuf *buf, ସଂରଚନା sshkey **kp)
{
	ଅଚଳ ସଂରଚନା sshkey_impl *impl;
	ଅକ୍ଷର *tname = ଖାଲି;
	ଅକ୍ଷର *expect_sk_application = ଖାଲି;
	u_char *expect_ed25519_pk = ଖାଲି;
	ସଂରଚନା sshkey *k = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (kp != ଖାଲି)
		*kp = ଖାଲି;
	ଯଦି ((r = sshbuf_get_cstring(buf, &tname, ଖାଲି)) != 0)
		ଯାଅ out;
	type = sshkey_type_from_name(tname);
	ଯଦି (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		ଯଦି ((r = sshkey_froms(buf, &k)) != 0)
			ଯାଅ out;
		ଯଦି (k->type != type) {
			r = SSH_ERR_ଚାବି_CERT_MISMATCH;
			ଯାଅ out;
		}
		/* For ECDSA keys, the group must match too */
		ଯଦି (k->type == ଚାବି_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_ଚାବି_CERT_MISMATCH;
			ଯାଅ out;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = ଖାଲି;
		k->ed25519_pk = ଖାଲି;
	} ଅନ୍ୟଥା {
		ଯଦି ((k = sshkey_new(type)) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
	}
	ଯଦି ((impl = sshkey_impl_from_type(type)) == ଖାଲି) {
		r = SSH_ERR_INTERNAL_ERROR;
		ଯାଅ out;
	}
	ଯଦି ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		ଯାଅ out;

	ଯଦି ((expect_sk_application != ଖାଲି && (k->sk_application == ଖାଲି ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != ଖାଲି && (k->ed25519_pk == ଖାଲି ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_ଚାବି_CERT_MISMATCH;
		ଯାଅ out;
	}
	/* success */
	r = 0;
	ଯଦି (kp != ଖାଲି) {
		*kp = k;
		k = ଖାଲି;
	}
 out:
	ମୁକ୍ତ(tname);
	sshkey_free(k);
	ମୁକ୍ତ(expect_sk_application);
	ମୁକ୍ତ(expect_ed25519_pk);
	ଫେରନ୍ତୁ r;
}

#ifdef WITH_OPENSSL
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_ec_validate_public(ଅଚଳ EC_GROUP *group, ଅଚଳ EC_POINT *ସର୍ବସାଧାରଣ)
{
	EC_POINT *nq = ଖାଲି;
	BIGNUM *order = ଖାଲି, *cofactor = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_ଚାବି_INVALID_EC_ମୂଲ୍ୟ;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	ଯଦି (EC_POINT_is_at_infinity(group, ସର୍ବସାଧାରଣ))
		ଯାଅ out;

	ଯଦି ((cofactor = BN_new()) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (EC_GROUP_get_cofactor(group, cofactor, ଖାଲି) != 1)
		ଯାଅ out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	ଯଦି (!BN_is_one(cofactor)) {
		ଯଦି ((order = BN_new()) == ଖାଲି) {
			ret = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		ଯଦି (EC_GROUP_get_order(group, order, ଖାଲି) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			ଯାଅ out;
		}
		ଯଦି ((nq = EC_POINT_new(group)) == ଖାଲି) {
			ret = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		ଯଦି (EC_POINT_mul(group, nq, ଖାଲି, ସର୍ବସାଧାରଣ, order, ଖାଲି) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			ଯାଅ out;
		}
		ଯଦି (EC_POINT_is_at_infinity(group, nq) != 1)
			ଯାଅ out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_ec_validate_private(ଅଚଳ EC_ଚାବି *ଚାବି)
{
	BIGNUM *order = ଖାଲି, *tmp = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_ଚାବି_INVALID_EC_ମୂଲ୍ୟ;

	ଯଦି ((order = BN_new()) == ଖାଲି || (tmp = BN_new()) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}

	/* log2(private) > log2(order)/2 */
	ଯଦି (EC_GROUP_get_order(EC_ଚାବି_get0_group(ଚାବି), order, ଖାଲି) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ଯଦି (BN_ଅଙ୍କ_bits(EC_ଚାବି_get0_private_ଚାବି(ଚାବି)) <=
	    BN_ଅଙ୍କ_bits(order) / 2)
		ଯାଅ out;

	/* private < order - 1 */
	ଯଦି (!BN_sub(tmp, order, BN_ମୂଲ୍ୟ_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ଯଦି (BN_cmp(EC_ଚାବି_get0_private_ଚାବି(ଚାବି), tmp) >= 0)
		ଯାଅ out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	ଫେରନ୍ତୁ ret;
}

ଶୂନ୍ୟ
sshkey_dump_ec_point(ଅଚଳ EC_GROUP *group, ଅଚଳ EC_POINT *point)
{
	BIGNUM *x = ଖାଲି, *y = ଖାଲି;

	ଯଦି (point == ଖାଲି) {
		fputs("point=(NULL)\n", stderr);
		ଫେରନ୍ତୁ;
	}
	ଯଦି ((x = BN_new()) == ଖାଲି || (y = BN_new()) == ଖାଲି) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		ଯାଅ out;
	}
	ଯଦି (EC_POINT_get_affine_coordinates(group, point, x, y, ଖାଲି) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		ଯାଅ out;
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

ଶୂନ୍ୟ
sshkey_dump_ec_ଚାବି(ଅଚଳ EC_ଚାବି *ଚାବି)
{
	ଅଚଳ BIGNUM *exponent;

	sshkey_dump_ec_point(EC_ଚାବି_get0_group(ଚାବି),
	    EC_ଚାବି_get0_public_ଚାବି(ଚାବି));
	fputs("exponent=", stderr);
	ଯଦି ((exponent = EC_ଚାବି_get0_private_ଚାବି(ଚାବି)) == ଖାଲି)
		fputs("(NULL)", stderr);
	ଅନ୍ୟଥା
		BN_print_fp(stderr, EC_ଚାବି_get0_private_ଚାବି(ଚାବି));
	fputs("\n", stderr);
}
#endif /* WITH_OPENSSL */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_private_to_blob2(ସଂରଚନା sshkey *prv, ସଂରଚନା sshbuf *blob,
    ଅଚଳ ଅକ୍ଷର *passphrase, ଅଚଳ ଅକ୍ଷର *comment, ଅଚଳ ଅକ୍ଷର *ciphername,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା rounds)
{
	u_char *cp, *ଚାବି = ଖାଲି, *pubkeyblob = ଖାଲି;
	u_char salt[SALT_LEN];
	size_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା sshcipher_ctx *ciphercontext = ଖାଲି;
	ଅଚଳ ସଂରଚନା sshcipher *cipher;
	ଅଚଳ ଅକ୍ଷର *kdfname = KDFNAME;
	ସଂରଚନା sshbuf *encoded = ଖାଲି, *encrypted = ଖାଲି, *kdf = ଖାଲି;

	ଯଦି (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	ଯଦି (rounds > MAX_KDF_ROUNDS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	ଯଦି (passphrase == ଖାଲି || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} ଅନ୍ୟଥା ଯଦି (ciphername == ଖାଲି)
		ciphername = DEFAULT_CIPHERNAME;
	ଯଦି ((cipher = cipher_by_name(ciphername)) == ଖାଲି) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}

	ଯଦି ((kdf = sshbuf_new()) == ଖାଲି ||
	    (encoded = sshbuf_new()) == ଖାଲି ||
	    (encrypted = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	ଯଦି ((ଚାବି = calloc(1, keylen + ivlen)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		ଯଦି (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, ଚାବି, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			ଯାଅ out;
	} ଅନ୍ୟଥା ଯଦି (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_ଚାବି_UNKNOWN_CIPHER;
		ଯାଅ out;
	}
	ଯଦି ((r = cipher_init(&ciphercontext, cipher, ଚାବି, keylen,
	    ଚାବି + keylen, ivlen, 1)) != 0)
		ଯାଅ out;

	ଯଦି ((r = sshbuf_put(encoded, AUTH_MAGIC, ଆକାର(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_to_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		ଯାଅ out;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	ଯଦି ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		ଯାଅ out;

	/* append private key and comment*/
	ଯଦି ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		ଯାଅ out;

	/* padding */
	i = 0;
	ଯେତେବେଳେ (sshbuf_len(encrypted) % blocksize) {
		ଯଦି ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			ଯାଅ out;
	}

	/* length in destination buffer */
	ଯଦି ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		ଯାଅ out;

	/* encrypt */
	ଯଦି ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		ଯାଅ out;
	ଯଦି ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		ଯାଅ out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	ଯଦି ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_END, MARK_END_LEN)) != 0)
		ଯାଅ out;

	/* success */
	r = 0;

 out:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, ଆକାର(salt));
	ଯଦି (ଚାବି != ଖାଲି)
		freezero(ଚାବି, keylen + ivlen);
	ଯଦି (pubkeyblob != ଖାଲି)
		freezero(pubkeyblob, pubkeylen);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
private2_uudecode(ସଂରଚନା sshbuf *blob, ସଂରଚନା sshbuf **decodedp)
{
	ଅଚଳ u_char *cp;
	size_t encoded_len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_char last;
	ସଂରଚନା sshbuf *encoded = ଖାଲି, *decoded = ଖାଲି;

	ଯଦି (blob == ଖାଲି || decodedp == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	*decodedp = ଖାଲି;

	ଯଦି ((encoded = sshbuf_new()) == ଖାଲି ||
	    (decoded = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	ଯଦି (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	ଯେତେବେଳେ (encoded_len > 0) {
		ଯଦି (*cp != '\n' && *cp != '\r') {
			ଯଦି ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				ଯାଅ out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		ଯଦି (last == '\n') {
			ଯଦି (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				ଯଦି ((r = sshbuf_put_u8(encoded, 0)) != 0)
					ଯାଅ out;
				ଭାଙ୍ଗ;
			}
		}
	}
	ଯଦି (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}

	/* decode base64 */
	ଯଦି ((r = sshbuf_b64tod(decoded, (ଅକ୍ଷର *)sshbuf_ptr(encoded))) != 0)
		ଯାଅ out;

	/* check magic */
	ଯଦି (sshbuf_len(decoded) < ଆକାର(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, ଆକାର(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	/* success */
	*decodedp = decoded;
	decoded = ଖାଲି;
	r = 0;
 out:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
private2_decrypt(ସଂରଚନା sshbuf *decoded, ଅଚଳ ଅକ୍ଷର *passphrase,
    ସଂରଚନା sshbuf **decryptedp, ସଂରଚନା sshkey **pubkeyp)
{
	ଅକ୍ଷର *ciphername = ଖାଲି, *kdfname = ଖାଲି;
	ଅଚଳ ସଂରଚନା sshcipher *cipher = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	ସଂରଚନା sshbuf *kdf = ଖାଲି, *decrypted = ଖାଲି;
	ସଂରଚନା sshcipher_ctx *ciphercontext = ଖାଲି;
	ସଂରଚନା sshkey *pubkey = ଖାଲି;
	u_char *ଚାବି = ଖାଲି, *salt = ଖାଲି, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	ଯଦି (decoded == ଖାଲି || decryptedp == ଖାଲି || pubkeyp == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = ଖାଲି;
	*pubkeyp = ଖାଲି;

	ଯଦି ((decrypted = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}

	/* parse public portion of key */
	ଯଦି ((r = sshbuf_consume(decoded, ଆକାର(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, ଖାଲି)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		ଯାଅ out;

	ଯଦି (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}

	ଯଦି ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		ଯାଅ out;

	ଯଦି ((cipher = cipher_by_name(ciphername)) == ଖାଲି) {
		r = SSH_ERR_ଚାବି_UNKNOWN_CIPHER;
		ଯାଅ out;
	}
	ଯଦି (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_ଚାବି_UNKNOWN_CIPHER;
		ଯାଅ out;
	}
	ଯଦି (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି ((passphrase == ଖାଲି || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_ଚାବି_WRONG_PASSPHRASE;
		ଯାଅ out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	ଯଦି (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	ଯଦି ((ଚାବି = calloc(1, keylen + ivlen)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (strcmp(kdfname, "bcrypt") == 0) {
		ଯଦି ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			ଯାଅ out;
		ଯଦି (rounds > MAX_KDF_ROUNDS) {
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		ଯଦି (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    ଚାବି, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	ଯଦି (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}

	/* decrypt private portion of key */
	ଯଦି ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, ଚାବି, keylen,
	    ଚାବି + keylen, ivlen, 0)) != 0)
		ଯାଅ out;
	ଯଦି ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		ଯଦି (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_ଚାବି_WRONG_PASSPHRASE;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		ଯାଅ out;
	/* there should be no trailing data */
	ଯଦି (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}

	/* check check bytes */
	ଯଦି ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		ଯାଅ out;
	ଯଦି (check1 != check2) {
		r = SSH_ERR_ଚାବି_WRONG_PASSPHRASE;
		ଯାଅ out;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = ଖାଲି;
	*pubkeyp = pubkey;
	pubkey = ଖାଲି;
	r = 0;
 out:
	cipher_free(ciphercontext);
	ମୁକ୍ତ(ciphername);
	ମୁକ୍ତ(kdfname);
	sshkey_free(pubkey);
	ଯଦି (salt != ଖାଲି) {
		explicit_bzero(salt, slen);
		ମୁକ୍ତ(salt);
	}
	ଯଦି (ଚାବି != ଖାଲି) {
		explicit_bzero(ଚାବି, keylen + ivlen);
		ମୁକ୍ତ(ଚାବି);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_parse_private2(ସଂରଚନା sshbuf *blob, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ଅଚଳ ଅକ୍ଷର *passphrase,
    ସଂରଚନା sshkey **keyp, ଅକ୍ଷର **commentp)
{
	ଅକ୍ଷର *comment = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା sshbuf *decoded = ଖାଲି, *decrypted = ଖାଲି;
	ସଂରଚନା sshkey *k = ଖାଲି, *pubkey = ଖାଲି;

	ଯଦି (keyp != ଖାଲି)
		*keyp = ଖାଲି;
	ଯଦି (commentp != ଖାଲି)
		*commentp = ଖାଲି;

	/* Undo base64 encoding and decrypt the private section */
	ଯଦି ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		ଯାଅ out;

	ଯଦି (type != ଚାବି_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_ଚାବି_TYPE_MISMATCH;
		ଯାଅ out;
	}

	/* Load the private key and comment */
	ଯଦି ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, ଖାଲି)) != 0)
		ଯାଅ out;

	/* Check deterministic padding after private section */
	ଯଦି ((r = private2_check_padding(decrypted)) != 0)
		ଯାଅ out;

	/* Check that the public key in the envelope matches the private key */
	ଯଦି (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}

	/* success */
	r = 0;
	ଯଦି (keyp != ଖାଲି) {
		*keyp = k;
		k = ଖାଲି;
	}
	ଯଦି (commentp != ଖାଲି) {
		*commentp = comment;
		comment = ଖାଲି;
	}
 out:
	ମୁକ୍ତ(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_parse_private2_pubkey(ସଂରଚନା sshbuf *blob, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type,
    ସଂରଚନା sshkey **keyp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା sshbuf *decoded = ଖାଲି;
	ସଂରଚନା sshkey *pubkey = ଖାଲି;
	u_int nkeys = 0;

	ଯଦି (keyp != ଖାଲି)
		*keyp = ଖାଲି;

	ଯଦି ((r = private2_uudecode(blob, &decoded)) != 0)
		ଯାଅ out;
	/* parse public key from unencrypted envelope */
	ଯଦି ((r = sshbuf_consume(decoded, ଆକାର(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		ଯାଅ out;

	ଯଦି (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}

	/* Parse the public key */
	ଯଦି ((r = sshkey_froms(decoded, &pubkey)) != 0)
		ଯାଅ out;

	ଯଦି (type != ଚାବି_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_ଚାବି_TYPE_MISMATCH;
		ଯାଅ out;
	}

	/* success */
	r = 0;
	ଯଦି (keyp != ଖାଲି) {
		*keyp = pubkey;
		pubkey = ଖାଲି;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	ଫେରନ୍ତୁ r;
}

#ifdef WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_private_to_blob_pem_pkcs8(ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *buf,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା format, ଅଚଳ ଅକ୍ଷର *_passphrase, ଅଚଳ ଅକ୍ଷର *comment)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା was_shielded = sshkey_is_shielded(ଚାବି);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା success, r;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : ଖାଲି;
	ଅଚଳ EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : ଖାଲି;
	ଅକ୍ଷର *bptr;
	BIO *bio = ଖାଲି;
	ସଂରଚନା sshbuf *blob;
	EVP_PKEY *pkey = ଖାଲି;

	ଯଦି (len > 0 && len <= 4)
		ଫେରନ୍ତୁ SSH_ERR_PASSPHRASE_TOO_SHORT;
	ଯଦି ((blob = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((bio = BIO_new(BIO_s_mem())) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshkey_unshield_private(ଚାବି)) != 0)
		ଯାଅ out;

	ବାଛ (ଚାବି->type) {
	ସ୍ଥିତି ଚାବି_ECDSA:
		ଯଦି (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivate_ଚାବି(bio,
			    EVP_PKEY_get0_EC_ଚାବି(ଚାବି->pkey),
			    cipher, passphrase, len, ଖାଲି, ଖାଲି);
		} ଅନ୍ୟଥା {
			pkey = ଚାବି->pkey;
			EVP_PKEY_up_ref(ଚାବି->pkey);
			success = 1;
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି ଚାବି_RSA:
		ଯଦି (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivate_ଚାବି(bio,
			    EVP_PKEY_get0_RSA(ଚାବି->pkey),
			    cipher, passphrase, len, ଖାଲି, ଖାଲି);
		} ଅନ୍ୟଥା {
			pkey = ଚାବି->pkey;
			EVP_PKEY_up_ref(ଚାବି->pkey);
			success = 1;
		}
		ଭାଙ୍ଗ;
#ifdef OPENSSL_HAS_ED25519
	ସ୍ଥିତି ଚାବି_ED25519:
		ଯଦି (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		} ଅନ୍ୟଥା {
			pkey = EVP_PKEY_new_raw_private_ଚାବି(EVP_PKEY_ED25519,
			    ଖାଲି, ଚାବି->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != ଖାଲି;
		}
		ଭାଙ୍ଗ;
#endif
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		success = 0;
		ଭାଙ୍ଗ;
	}
	ଯଦି (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ଯଦି (format == SSHKEY_PRIVATE_PKCS8) {
		ଯଦି ((success = PEM_write_bio_Private_ଚାବି(bio, pkey, cipher,
		    passphrase, len, ଖାଲି, ଖାଲି)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ଯାଅ out;
		}
	}
	ଯଦି ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put(blob, bptr, blen)) != 0)
		ଯାଅ out;
	r = 0;
 out:
	ଯଦି (was_shielded)
		r = sshkey_shield_private(ଚାବି);
	ଯଦି (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	ଫେରନ୍ତୁ r;
}
#endif /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_private_to_fileblob(ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *blob,
    ଅଚଳ ଅକ୍ଷର *passphrase, ଅଚଳ ଅକ୍ଷର *comment,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା format, ଅଚଳ ଅକ୍ଷର *openssh_format_cipher, ପୂର୍ଣ୍ଣସଂଖ୍ୟା openssh_format_rounds)
{
	ବାଛ (ଚାବି->type) {
#ifdef WITH_OPENSSL
	ସ୍ଥିତି ଚାବି_ECDSA:
	ସ୍ଥିତି ଚାବି_RSA:
	ସ୍ଥିତି ଚାବି_ED25519:
		ଭାଙ୍ଗ; /* see below */
#ଅନ୍ୟଥା /* WITH_OPENSSL */
	ସ୍ଥିତି ଚାବି_ED25519:
#endif /* WITH_OPENSSL */
	ସ୍ଥିତି ଚାବି_ED25519_SK:
#ifdef WITH_OPENSSL
	ସ୍ଥିତି ଚାବି_ECDSA_SK:
#endif /* WITH_OPENSSL */
	ସ୍ଥିତି ଚାବି_MLDSA44_ED25519:
		ଫେରନ୍ତୁ sshkey_private_to_blob2(ଚାବି, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_TYPE_UNKNOWN;
	}

#ifdef WITH_OPENSSL
	ବାଛ (format) {
	ସ୍ଥିତି SSHKEY_PRIVATE_OPENSSH:
		ଫେରନ୍ତୁ sshkey_private_to_blob2(ଚାବି, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	ସ୍ଥିତି SSHKEY_PRIVATE_PEM:
	ସ୍ଥିତି SSHKEY_PRIVATE_PKCS8:
		ଫେରନ୍ତୁ sshkey_private_to_blob_pem_pkcs8(ଚାବି, blob,
		    format, passphrase, comment);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	}
#endif /* WITH_OPENSSL */
}

#ifdef WITH_OPENSSL
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
translate_libcrypto_error(unsigned long pem_err)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା pem_reason = ERR_GET_REASON(pem_err);

	ବାଛ (ERR_GET_LIB(pem_err)) {
	ସ୍ଥିତି ERR_LIB_PEM:
		ବାଛ (pem_reason) {
		ସ୍ଥିତି PEM_R_BAD_PASSWORD_READ:
#ifdef PEM_R_PROBLEMS_GETTING_PASSWORD
		ସ୍ଥିତି PEM_R_PROBLEMS_GETTING_PASSWORD:
#endif
#ifdef PEM_R_BAD_DECRYPT
		ସ୍ଥିତି PEM_R_BAD_DECRYPT:
#endif
			ଫେରନ୍ତୁ SSH_ERR_ଚାବି_WRONG_PASSPHRASE;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
		}
	ସ୍ଥିତି ERR_LIB_EVP:
		ବାଛ (pem_reason) {
#ifdef EVP_R_BAD_DECRYPT
		ସ୍ଥିତି EVP_R_BAD_DECRYPT:
			ଫେରନ୍ତୁ SSH_ERR_ଚାବି_WRONG_PASSPHRASE;
#endif
#ifdef EVP_R_BN_DECODE_ERROR
		ସ୍ଥିତି EVP_R_BN_DECODE_ERROR:
#endif
		ସ୍ଥିତି EVP_R_DECODE_ERROR:
#ifdef EVP_R_PRIVATE_ଚାବି_DECODE_ERROR
		ସ୍ଥିତି EVP_R_PRIVATE_ଚାବି_DECODE_ERROR:
#endif
			ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
		}
	ସ୍ଥିତି ERR_LIB_ASN1:
#ifdef ERR_LIB_OSSL_DECODER
	ସ୍ଥିତି ERR_LIB_OSSL_DECODER:
#endif
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
}

ସ୍ଥିର ଶୂନ୍ୟ
clear_libcrypto_errors(ଶୂନ୍ୟ)
{
	ଯେତେବେଳେ (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
convert_libcrypto_error(ଶୂନ୍ୟ)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	ଯଦି (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_ଚାବି_WRONG_PASSPHRASE)
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_WRONG_PASSPHRASE;
	ଫେରନ୍ତୁ translate_libcrypto_error(ERR_peek_last_error());
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pem_passphrase_cb(ଅକ୍ଷର *buf, ପୂର୍ଣ୍ଣସଂଖ୍ୟା size, ପୂର୍ଣ୍ଣସଂଖ୍ୟା rwflag, ଶୂନ୍ୟ *u)
{
	ଅକ୍ଷର *p = (ଅକ୍ଷର *)u;
	size_t len;

	ଯଦି (p == ଖାଲି || (len = strlen(p)) == 0)
		ଫେରନ୍ତୁ -1;
	ଯଦି (size < 0 || len > (size_t)size)
		ଫେରନ୍ତୁ -1;
	memcpy(buf, p, len);
	ଫେରନ୍ତୁ (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)len;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_parse_private_pem_fileblob(ସଂରଚନା sshbuf *blob, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type,
    ଅଚଳ ଅକ୍ଷର *passphrase, ସଂରଚନା sshkey **keyp)
{
	EVP_PKEY *pk = ଖାଲି;
	ସଂରଚନା sshkey *prv = ଖାଲି;
	BIO *bio = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	RSA *rsa = ଖାଲି;
	EC_ଚାବି *ecdsa = ଖାଲି;

	ଯଦି (keyp != ଖାଲି)
		*keyp = ଖାଲି;

	ଯଦି ((bio = BIO_new(BIO_s_mem())) == ଖାଲି || sshbuf_len(blob) > INT_MAX)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}

	clear_libcrypto_errors();
	ଯଦି ((pk = PEM_read_bio_Private_ଚାବି(bio, ଖାଲି, pem_passphrase_cb,
	    (ଅକ୍ଷର *)passphrase)) == ଖାଲି) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		ଯଦି (passphrase != ଖାଲି && *passphrase != '\0')
			r = SSH_ERR_ଚାବି_WRONG_PASSPHRASE;
		ଅନ୍ୟଥା
			r = convert_libcrypto_error();
		ଯାଅ out;
	}
	ଯଦି (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == ଚାବି_UNSPEC || type == ଚାବି_RSA)) {
		ଯଦି ((prv = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		ଯଦି ((rsa = EVP_PKEY_get1_RSA(pk)) == ଖାଲି) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ଯାଅ out;
		}
		prv->type = ଚାବି_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#endif
		ଯଦି (RSA_blinding_on(rsa, ଖାଲି) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ଯାଅ out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		ଯଦି ((r = sshkey_check_rsa_length(prv, 0)) != 0)
			ଯାଅ out;
	} ଅନ୍ୟଥା ଯଦି (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == ଚାବି_UNSPEC || type == ଚାବି_ECDSA)) {
		ଯଦି ((prv = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		ଯଦି ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_ଚାବି(pk)) == ଖାଲି) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ଯାଅ out;
		}
		prv->type = ଚାବି_ECDSA;
		ଯଦି (sshkey_curve_nid_to_name(prv->ecdsa_nid) == ଖାଲି ||
		    sshkey_ec_validate_public(EC_ଚାବି_get0_group(ecdsa),
		    EC_ଚାବି_get0_public_ଚାବି(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#ifdef DEBUG_PK
		ଯଦି (prv != ଖାଲି && prv->pkey != ଖାଲି)
			sshkey_dump_ec_ଚାବି(EVP_PKEY_get0_EC_ଚାବି(prv->pkey));
#endif
#ifdef OPENSSL_HAS_ED25519
	} ଅନ୍ୟଥା ଯଦି (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == ଚାବି_UNSPEC || type == ଚାବି_ED25519)) {
		size_t len;

		ଯଦି ((prv = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି ||
		    (prv->ed25519_sk = calloc(1, ED25519_SK_SZ)) == ଖାଲି ||
		    (prv->ed25519_pk = calloc(1, ED25519_PK_SZ)) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		prv->type = ଚାବି_ED25519;
		len = ED25519_PK_SZ;
		ଯଦି (!EVP_PKEY_get_raw_public_ଚାବି(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ଯାଅ out;
		}
		ଯଦି (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		ଯଦି (!EVP_PKEY_get_raw_private_ଚାବି(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ଯାଅ out;
		}
		ଯଦି (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		/* Append the public key to our private key */
		memcpy(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#ifdef DEBUG_PK
		sshbuf_dump_data(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#endif
#endif /* OPENSSL_HAS_ED25519 */
	} ଅନ୍ୟଥା {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	r = 0;
	ଯଦି (keyp != ଖାଲି) {
		*keyp = prv;
		prv = ଖାଲି;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_ଚାବି_free(ecdsa);
	sshkey_free(prv);
	ଫେରନ୍ତୁ r;
}
#endif /* WITH_OPENSSL */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_parse_private_fileblob_type(ସଂରଚନା sshbuf *blob, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type,
    ଅଚଳ ଅକ୍ଷର *passphrase, ସଂରଚନା sshkey **keyp, ଅକ୍ଷର **commentp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (keyp != ଖାଲି)
		*keyp = ଖାଲି;
	ଯଦି (commentp != ଖାଲି)
		*commentp = ଖାଲି;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	ଯଦି (r != SSH_ERR_INVALID_FORMAT)
		ଫେରନ୍ତୁ r;
#ifdef WITH_OPENSSL
	ଫେରନ୍ତୁ sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#ଅନ୍ୟଥା
	ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_parse_private_fileblob(ସଂରଚନା sshbuf *buffer, ଅଚଳ ଅକ୍ଷର *passphrase,
    ସଂରଚନା sshkey **keyp, ଅକ୍ଷର **commentp)
{
	ଯଦି (keyp != ଖାଲି)
		*keyp = ଖାଲି;
	ଯଦି (commentp != ଖାଲି)
		*commentp = ଖାଲି;

	ଫେରନ୍ତୁ sshkey_parse_private_fileblob_type(buffer, ଚାବି_UNSPEC,
	    passphrase, keyp, commentp);
}

ଶୂନ୍ୟ
sshkey_sig_details_free(ସଂରଚନା sshkey_sig_details *details)
{
	freezero(details, ଆକାର(*details));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_parse_pubkey_from_private_fileblob_type(ସଂରଚନା sshbuf *blob, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type,
    ସଂରଚନା sshkey **pubkeyp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (pubkeyp != ଖାଲି)
		*pubkeyp = ଖାଲି;
	/* only new-format private keys bundle a public key inside */
	ଯଦି ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}
