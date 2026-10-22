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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/mman.h>
#ಅನ್ತರ್ಭಾವ <netinet/in.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ <openssl/err.h>
#ಅನ್ತರ್ಭಾವ <openssl/pem.h>
#endif

#ಅನ್ತರ್ಭಾವ "crypto_api.h"

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <resolv.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <util.h>

#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#define SSHKEY_INTERNAL
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "ssh-sk.h"
#ಅನ್ತರ್ಭಾವ "ssh-pkcs11.h"

#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#define MARK_BEGIN_LEN		(ಪರಿಮಾಣ(MARK_BEGIN) - 1)
#define MARK_END_LEN		(ಪರಿಮಾಣ(MARK_END) - 1)
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

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ sshkey_from_blob_internal(ಸಂರಚನಾ sshbuf *buf,
    ಸಂರಚನಾ sshkey **keyp, ಪೂರ್ಣಾಙ್ಕ allow_cert,
    ಧ್ರುವ ವರ್ಣ *alg_allowlist, ಧ್ರುವ ವರ್ಣ *ca_sigalg_allowlist);

/* Supported key types */
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ed25519_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ed25519_cert_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ed25519_sk_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_mldsa44_ed25519_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#ifdef WITH_OPENSSL
# ifdef ENABLE_SK
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_sk_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_sk_cert_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_nistp256_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_nistp384_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_nistp521_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_rsa_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_rsa_cert_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_rsa_sha256_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_rsa_sha256_cert_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_rsa_sha512_impl;
ಬಾಹ್ಯ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_rsa_sha512_cert_impl;
#endif /* WITH_OPENSSL */

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl * ಧ್ರುವ keyimpls[] = {
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
	ರಿಕ್ತ
};

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *
sshkey_impl_from_type(ಪೂರ್ಣಾಙ್ಕ type)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಪ್ರತಿ (i = 0; keyimpls[i] != ರಿಕ್ತ; i++) {
		ಯದಿ (keyimpls[i]->type == type)
			ಪ್ರತ್ಯಾಗಮ keyimpls[i];
	}
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *
sshkey_impl_from_type_nid(ಪೂರ್ಣಾಙ್ಕ type, ಪೂರ್ಣಾಙ್ಕ nid)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಪ್ರತಿ (i = 0; keyimpls[i] != ರಿಕ್ತ; i++) {
		ಯದಿ (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			ಪ್ರತ್ಯಾಗಮ keyimpls[i];
	}
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *
sshkey_impl_from_ಕೀಲಿ(ಧ್ರುವ ಸಂರಚನಾ sshkey *k)
{
	ಯದಿ (k == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

ಧ್ರುವ ವರ್ಣ *
sshkey_type(ಧ್ರುವ ಸಂರಚನಾ sshkey *k)
{
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;

	ಯದಿ ((impl = sshkey_impl_from_ಕೀಲಿ(k)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ "unknown";
	ಪ್ರತ್ಯಾಗಮ impl->shortname;
}

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
sshkey_ssh_name_from_type_nid(ಪೂರ್ಣಾಙ್ಕ type, ಪೂರ್ಣಾಙ್ಕ nid)
{
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;

	ಯದಿ ((impl = sshkey_impl_from_type_nid(type, nid)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ "ssh-unknown";
	ಪ್ರತ್ಯಾಗಮ impl->name;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_type_is_cert(ಪೂರ್ಣಾಙ್ಕ type)
{
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;

	ಯದಿ ((impl = sshkey_impl_from_type(type)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ impl->cert;
}

ಧ್ರುವ ವರ್ಣ *
sshkey_ssh_name(ಧ್ರುವ ಸಂರಚನಾ sshkey *k)
{
	ಪ್ರತ್ಯಾಗಮ sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

ಧ್ರುವ ವರ್ಣ *
sshkey_ssh_name_plain(ಧ್ರುವ ಸಂರಚನಾ sshkey *k)
{
	ಪ್ರತ್ಯಾಗಮ sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
type_from_name(ಧ್ರುವ ವರ್ಣ *name, ಪೂರ್ಣಾಙ್ಕ allow_short)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;

	ಪ್ರತಿ (i = 0; keyimpls[i] != ರಿಕ್ತ; i++) {
		impl = keyimpls[i];
		ಯದಿ (impl->name != ರಿಕ್ತ && strcmp(name, impl->name) == 0)
			ಪ್ರತ್ಯಾಗಮ impl->type;
		/* Only allow shortname matches for plain key types */
		ಯದಿ (allow_short && !impl->cert && impl->shortname != ರಿಕ್ತ &&
		    strcasecmp(impl->shortname, name) == 0)
			ಪ್ರತ್ಯಾಗಮ impl->type;
	}
	ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ_UNSPEC;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_type_from_name(ಧ್ರುವ ವರ್ಣ *name)
{
	ಪ್ರತ್ಯಾಗಮ type_from_name(name, 0);
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_type_from_shortname(ಧ್ರುವ ವರ್ಣ *name)
{
	ಪ್ರತ್ಯಾಗಮ type_from_name(name, 1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಕೀಲಿ_type_is_ecdsa_variant(ಪೂರ್ಣಾಙ್ಕ type)
{
	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ ಕೀಲಿ_ECDSA:
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_CERT:
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK_CERT:
		ಪ್ರತ್ಯಾಗಮ 1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_ecdsa_nid_from_name(ಧ್ರುವ ವರ್ಣ *name)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಪ್ರತಿ (i = 0; keyimpls[i] != ರಿಕ್ತ; i++) {
		ಯದಿ (!ಕೀಲಿ_type_is_ecdsa_variant(keyimpls[i]->type))
			ಅನುವರ್ತ;
		ಯದಿ (keyimpls[i]->name != ರಿಕ್ತ &&
		    strcmp(name, keyimpls[i]->name) == 0)
			ಪ್ರತ್ಯಾಗಮ keyimpls[i]->nid;
	}
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_match_keyname_to_sigalgs(ಧ್ರುವ ವರ್ಣ *keyname, ಧ್ರುವ ವರ್ಣ *sigalgs)
{
	ಪೂರ್ಣಾಙ್ಕ ktype;

	ಯದಿ (sigalgs == ರಿಕ್ತ || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == ಕೀಲಿ_UNSPEC)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಅನ್ಯಥಾ ಯದಿ (ktype == ಕೀಲಿ_RSA) {
		ಪ್ರತ್ಯಾಗಮ match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} ಅನ್ಯಥಾ ಯದಿ (ktype == ಕೀಲಿ_RSA_CERT) {
		ಪ್ರತ್ಯಾಗಮ match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} ಅನ್ಯಥಾ ಯದಿ (ktype == ಕೀಲಿ_ECDSA_SK) {
		ಪ್ರತ್ಯಾಗಮ match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} ಅನ್ಯಥಾ ಯದಿ (ktype == ಕೀಲಿ_ECDSA_SK_CERT) {
		ಪ್ರತ್ಯಾಗಮ match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ match_pattern_list(keyname, sigalgs, 0) == 1;
}

ವರ್ಣ *
sshkey_alg_list(ಪೂರ್ಣಾಙ್ಕ certs_only, ಪೂರ್ಣಾಙ್ಕ plain_only, ಪೂರ್ಣಾಙ್ಕ include_sigonly, ವರ್ಣ sep)
{
	ವರ್ಣ *ret = ರಿಕ್ತ;
	size_t i;
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;
	ವರ್ಣ sep_str[2] = {sep, '\0'};

	ಪ್ರತಿ (i = 0; keyimpls[i] != ರಿಕ್ತ; i++) {
		impl = keyimpls[i];
		ಯದಿ (impl->name == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ಯದಿ (!include_sigonly && impl->sigonly)
			ಅನುವರ್ತ;
		ಯದಿ ((certs_only && !impl->cert) || (plain_only && impl->cert))
			ಅನುವರ್ತ;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_names_valid2(ಧ್ರುವ ವರ್ಣ *names, ಪೂರ್ಣಾಙ್ಕ allow_wildcard, ಪೂರ್ಣಾಙ್ಕ plain_only)
{
	ವರ್ಣ *s, *cp, *p;
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;
	ಪೂರ್ಣಾಙ್ಕ i, type;

	ಯದಿ (names == ರಿಕ್ತ || strcmp(names, "") == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((s = cp = strdup(names)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತಿ ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		ಯದಿ (type == ಕೀಲಿ_UNSPEC) {
			ಯದಿ (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = ರಿಕ್ತ;
				ಪ್ರತಿ (i = 0; keyimpls[i] != ರಿಕ್ತ; i++) {
					ಯದಿ (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						ಭಙ್ಗ;
					}
				}
				ಯದಿ (impl != ರಿಕ್ತ)
					ಅನುವರ್ತ;
			}
			ಮುಕ್ತ(s);
			ಪ್ರತ್ಯಾಗಮ 0;
		} ಅನ್ಯಥಾ ಯದಿ (plain_only && sshkey_type_is_cert(type)) {
			ಮುಕ್ತ(s);
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	}
	ಮುಕ್ತ(s);
	ಪ್ರತ್ಯಾಗಮ 1;
}

u_int
sshkey_size(ಧ್ರುವ ಸಂರಚನಾ sshkey *k)
{
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;

	ಯದಿ ((impl = sshkey_impl_from_ಕೀಲಿ(k)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (impl->funcs->size != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ impl->funcs->size(k);
	ಪ್ರತ್ಯಾಗಮ impl->keybits;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshkey_type_is_valid_ca(ಪೂರ್ಣಾಙ್ಕ type)
{
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;

	ಯದಿ ((impl = sshkey_impl_from_type(type)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	/* All non-certificate types may act as CAs */
	ಪ್ರತ್ಯಾಗಮ !impl->cert;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_is_cert(ಧ್ರುವ ಸಂರಚನಾ sshkey *k)
{
	ಯದಿ (k == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ sshkey_type_is_cert(k->type);
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_is_sk(ಧ್ರುವ ಸಂರಚನಾ sshkey *k)
{
	ಯದಿ (k == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ವಿಕಲ್ಪ (sshkey_type_plain(k->type)) {
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
	ಪಕ್ಷ ಕೀಲಿ_ED25519_SK:
		ಪ್ರತ್ಯಾಗಮ 1;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
ಪೂರ್ಣಾಙ್ಕ
sshkey_type_plain(ಪೂರ್ಣಾಙ್ಕ type)
{
	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ ಕೀಲಿ_RSA_CERT:
		ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ_RSA;
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_CERT:
		ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ_ECDSA;
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK_CERT:
		ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ_ECDSA_SK;
	ಪಕ್ಷ ಕೀಲಿ_ED25519_CERT:
		ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ_ED25519;
	ಪಕ್ಷ ಕೀಲಿ_MLDSA44_ED25519_CERT:
		ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ_MLDSA44_ED25519;
	ಪಕ್ಷ ಕೀಲಿ_ED25519_SK_CERT:
		ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ_ED25519_SK;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ type;
	}
}

/* Return the cert equivalent to a plain key type */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshkey_type_certified(ಪೂರ್ಣಾಙ್ಕ type)
{
	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ ಕೀಲಿ_RSA:
		ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ_RSA_CERT;
	ಪಕ್ಷ ಕೀಲಿ_ECDSA:
		ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ_ECDSA_CERT;
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
		ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ_ECDSA_SK_CERT;
	ಪಕ್ಷ ಕೀಲಿ_ED25519:
		ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ_ED25519_CERT;
	ಪಕ್ಷ ಕೀಲಿ_MLDSA44_ED25519:
		ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ_MLDSA44_ED25519_CERT;
	ಪಕ್ಷ ಕೀಲಿ_ED25519_SK:
		ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ_ED25519_SK_CERT;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

#ifdef WITH_OPENSSL
ಸ್ಥಿರ ಧ್ರುವ EVP_MD *
ssh_digest_to_md(ಪೂರ್ಣಾಙ್ಕ hash_alg)
{
	ವಿಕಲ್ಪ (hash_alg) {
	ಪಕ್ಷ SSH_DIGEST_SHA1:
		ಪ್ರತ್ಯಾಗಮ EVP_sha1();
	ಪಕ್ಷ SSH_DIGEST_SHA256:
		ಪ್ರತ್ಯಾಗಮ EVP_sha256();
	ಪಕ್ಷ SSH_DIGEST_SHA384:
		ಪ್ರತ್ಯಾಗಮ EVP_sha384();
	ಪಕ್ಷ SSH_DIGEST_SHA512:
		ಪ್ರತ್ಯಾಗಮ EVP_sha512();
	}
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_pkey_digest_sign(EVP_PKEY *pkey, ಪೂರ್ಣಾಙ್ಕ hash_alg, u_char **sigp,
    size_t *lenp, ಧ್ರುವ u_char *data, size_t datalen)
{
	EVP_MD_CTX *ctx = ರಿಕ್ತ;
	u_char *sig = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret;
	size_t slen;
	ಧ್ರುವ EVP_MD *evpmd;

	*sigp = ರಿಕ್ತ;
	*lenp = 0;

	slen = EVP_PKEY_size(pkey);
	ಯದಿ (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	ಯದಿ ((sig = malloc(slen)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;

	ಯದಿ ((ctx = EVP_MD_CTX_new()) == ರಿಕ್ತ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_DigestSignInit(ctx, ರಿಕ್ತ, evpmd, ರಿಕ್ತ, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, data, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = ರಿಕ್ತ;
	ret = 0;

 out:
	EVP_MD_CTX_free(ctx);
	ಮುಕ್ತ(sig);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_pkey_digest_verify(EVP_PKEY *pkey, ಪೂರ್ಣಾಙ್ಕ hash_alg, ಧ್ರುವ u_char *data,
    size_t datalen, u_char *sigbuf, size_t siglen)
{
	EVP_MD_CTX *ctx = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_INTERNAL_ERROR;
	ಧ್ರುವ EVP_MD *evpmd;

	ಯದಿ ((evpmd = ssh_digest_to_md(hash_alg)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((ctx = EVP_MD_CTX_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ (EVP_DigestVerifyInit(ctx, ರಿಕ್ತ, evpmd, ರಿಕ್ತ, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ವಿಕಲ್ಪ (EVP_DigestVerify(ctx, sigbuf, siglen, data, datalen)) {
	ಪಕ್ಷ 1:
		ret = 0;
		ಭಙ್ಗ;
	ಪಕ್ಷ 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಭಙ್ಗ;
	}

 out:
	EVP_MD_CTX_free(ctx);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/* XXX: these are really begging for a table-driven approach */
ಪೂರ್ಣಾಙ್ಕ
sshkey_curve_name_to_nid(ಧ್ರುವ ವರ್ಣ *name)
{
	ಯದಿ (strcmp(name, "nistp256") == 0)
		ಪ್ರತ್ಯಾಗಮ NID_X9_62_prime256v1;
	ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "nistp384") == 0)
		ಪ್ರತ್ಯಾಗಮ NID_secp384r1;
	ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "nistp521") == 0)
		ಪ್ರತ್ಯಾಗಮ NID_secp521r1;
	ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ -1;
}

u_int
sshkey_curve_nid_to_bits(ಪೂರ್ಣಾಙ್ಕ nid)
{
	ವಿಕಲ್ಪ (nid) {
	ಪಕ್ಷ NID_X9_62_prime256v1:
		ಪ್ರತ್ಯಾಗಮ 256;
	ಪಕ್ಷ NID_secp384r1:
		ಪ್ರತ್ಯಾಗಮ 384;
	ಪಕ್ಷ NID_secp521r1:
		ಪ್ರತ್ಯಾಗಮ 521;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ 0;
	}
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_ecdsa_bits_to_nid(ಪೂರ್ಣಾಙ್ಕ bits)
{
	ವಿಕಲ್ಪ (bits) {
	ಪಕ್ಷ 256:
		ಪ್ರತ್ಯಾಗಮ NID_X9_62_prime256v1;
	ಪಕ್ಷ 384:
		ಪ್ರತ್ಯಾಗಮ NID_secp384r1;
	ಪಕ್ಷ 521:
		ಪ್ರತ್ಯಾಗಮ NID_secp521r1;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

ಧ್ರುವ ವರ್ಣ *
sshkey_curve_nid_to_name(ಪೂರ್ಣಾಙ್ಕ nid)
{
	ವಿಕಲ್ಪ (nid) {
	ಪಕ್ಷ NID_X9_62_prime256v1:
		ಪ್ರತ್ಯಾಗಮ "nistp256";
	ಪಕ್ಷ NID_secp384r1:
		ಪ್ರತ್ಯಾಗಮ "nistp384";
	ಪಕ್ಷ NID_secp521r1:
		ಪ್ರತ್ಯಾಗಮ "nistp521";
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_ec_nid_to_hash_alg(ಪೂರ್ಣಾಙ್ಕ nid)
{
	ಪೂರ್ಣಾಙ್ಕ kbits = sshkey_curve_nid_to_bits(nid);

	ಯದಿ (kbits <= 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	/* RFC5656 section 6.2.1 */
	ಯದಿ (kbits <= 256)
		ಪ್ರತ್ಯಾಗಮ SSH_DIGEST_SHA256;
	ಅನ್ಯಥಾ ಯದಿ (kbits <= 384)
		ಪ್ರತ್ಯಾಗಮ SSH_DIGEST_SHA384;
	ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ SSH_DIGEST_SHA512;
}
#endif /* WITH_OPENSSL */

ಸ್ಥಿರ ಶೂನ್ಯ
cert_free(ಸಂರಚನಾ sshkey_cert *cert)
{
	u_int i;

	ಯದಿ (cert == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	ಮುಕ್ತ(cert->ಕೀಲಿ_id);
	ಪ್ರತಿ (i = 0; i < cert->nprincipals; i++)
		ಮುಕ್ತ(cert->principals[i]);
	ಮುಕ್ತ(cert->principals);
	sshkey_free(cert->signature_ಕೀಲಿ);
	ಮುಕ್ತ(cert->signature_type);
	freezero(cert, ಪರಿಮಾಣ(*cert));
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey_cert *
cert_new(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshkey_cert *cert;

	ಯದಿ ((cert = calloc(1, ಪರಿಮಾಣ(*cert))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಯದಿ ((cert->certblob = sshbuf_new()) == ರಿಕ್ತ ||
	    (cert->critical = sshbuf_new()) == ರಿಕ್ತ ||
	    (cert->extensions = sshbuf_new()) == ರಿಕ್ತ) {
		cert_free(cert);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	cert->ಕೀಲಿ_id = ರಿಕ್ತ;
	cert->principals = ರಿಕ್ತ;
	cert->signature_ಕೀಲಿ = ರಿಕ್ತ;
	cert->signature_type = ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ cert;
}

ಸಂರಚನಾ sshkey *
sshkey_new(ಪೂರ್ಣಾಙ್ಕ type)
{
	ಸಂರಚನಾ sshkey *k;
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl = ರಿಕ್ತ;

	ಯದಿ (type != ಕೀಲಿ_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	/* All non-certificate types may act as CAs */
	ಯದಿ ((k = calloc(1, ಪರಿಮಾಣ(*k))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	k->type = type;
	k->ecdsa_nid = -1;
	ಯದಿ (impl != ರಿಕ್ತ && impl->funcs->alloc != ರಿಕ್ತ) {
		ಯದಿ (impl->funcs->alloc(k) != 0) {
			ಮುಕ್ತ(k);
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
		}
	}
	ಯದಿ (sshkey_is_cert(k)) {
		ಯದಿ ((k->cert = cert_new()) == ರಿಕ್ತ) {
			sshkey_free(k);
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
		}
	}

	ಪ್ರತ್ಯಾಗಮ k;
}

/* Frees common FIDO fields */
ಶೂನ್ಯ
sshkey_sk_cleanup(ಸಂರಚನಾ sshkey *k)
{
	ಮುಕ್ತ(k->sk_application);
	sshbuf_free(k->sk_ಕೀಲಿ_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = ರಿಕ್ತ;
	k->sk_ಕೀಲಿ_handle = k->sk_reserved = ರಿಕ್ತ;
}

#ಯದಿ defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#ನೋಚೇದ್ಯದಿ defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#ಅನ್ಯಥಾ
# define PREKEY_MMAP_FLAG	0
#endif

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshkey_prekey_alloc(u_char **prekeyp, size_t len)
{
#ಯದಿ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = ರಿಕ್ತ;
	ಯದಿ ((prekey = mmap(ರಿಕ್ತ, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
#ಯದಿ defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(ಶೂನ್ಯ)madvise(prekey, len, MADV_DONTDUMP);
#endif
	*prekeyp = prekey;
#ಅನ್ಯಥಾ
	*prekeyp = calloc(1, len);
#endif /* HAVE_MMAP et al */
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshkey_prekey_free(ಶೂನ್ಯ *prekey, size_t len)
{
#ಯದಿ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	ಯದಿ (prekey == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	munmap(prekey, len);
#ಅನ್ಯಥಾ
	ಮುಕ್ತ(prekey);
#endif /* HAVE_MMAP et al */
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshkey_free_contents(ಸಂರಚನಾ sshkey *k)
{
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;

	ಯದಿ (k == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_ಕೀಲಿ_free(k);
	ಯದಿ ((impl = sshkey_impl_from_type(k->type)) != ರಿಕ್ತ &&
	    impl->funcs->cleanup != ರಿಕ್ತ)
		impl->funcs->cleanup(k);
	ಯದಿ (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_private, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

ಶೂನ್ಯ
sshkey_free(ಸಂರಚನಾ sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, ಪರಿಮಾಣ(*k));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
cert_compare(ಸಂರಚನಾ sshkey_cert *a, ಸಂರಚನಾ sshkey_cert *b)
{
	ಯದಿ (a == ರಿಕ್ತ && b == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 1;
	ಯದಿ (a == ರಿಕ್ತ || b == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ 1;
}

/* Compares FIDO-specific pubkey fields only */
ಪೂರ್ಣಾಙ್ಕ
sshkey_sk_fields_equal(ಧ್ರುವ ಸಂರಚನಾ sshkey *a, ಧ್ರುವ ಸಂರಚನಾ sshkey *b)
{
	ಯದಿ (a->sk_application == ರಿಕ್ತ || b->sk_application == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (strcmp(a->sk_application, b->sk_application) != 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
ಪೂರ್ಣಾಙ್ಕ
sshkey_equal_public(ಧ್ರುವ ಸಂರಚನಾ sshkey *a, ಧ್ರುವ ಸಂರಚನಾ sshkey *b)
{
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;

	ಯದಿ (a == ರಿಕ್ತ || b == ರಿಕ್ತ ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((impl = sshkey_impl_from_type(a->type)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ impl->funcs->equal(a, b);
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_equal(ಧ್ರುವ ಸಂರಚನಾ sshkey *a, ಧ್ರುವ ಸಂರಚನಾ sshkey *b)
{
	ಯದಿ (a == ರಿಕ್ತ || b == ರಿಕ್ತ || a->type != b->type)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (sshkey_is_cert(a)) {
		ಯದಿ (!cert_compare(a->cert, b->cert))
			ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಪ್ರತ್ಯಾಗಮ sshkey_equal_public(a, b);
}


/* Serialise common FIDO key parts */
ಪೂರ್ಣಾಙ್ಕ
sshkey_serialize_sk(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_put_cstring(b, ಕೀಲಿ->sk_application)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
to_blob_buf(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b, ಪೂರ್ಣಾಙ್ಕ force_plain,
  ಗಣನಾ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಙ್ಕ type, ret = SSH_ERR_INTERNAL_ERROR;
	ಧ್ರುವ ವರ್ಣ *typename;
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(ಕೀಲಿ->type) : ಕೀಲಿ->type;

	ಯದಿ (sshkey_type_is_cert(type)) {
		ಯದಿ (ಕೀಲಿ->cert == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_EXPECTED_CERT;
		ಯದಿ (sshbuf_len(ಕೀಲಿ->cert->certblob) == 0)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_LACKS_CERTBLOB;
		/* Use the existing blob */
		ಯದಿ ((ret = sshbuf_putb(b, ಕೀಲಿ->cert->certblob)) != 0)
			ಪ್ರತ್ಯಾಗಮ ret;
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ ((impl = sshkey_impl_from_type(type)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, ಕೀಲಿ->ecdsa_nid);
	ಯದಿ ((ret = sshbuf_put_cstring(b, typename)) != 0)
		ಪ್ರತ್ಯಾಗಮ ret;
	ಪ್ರತ್ಯಾಗಮ impl->funcs->serialize_public(ಕೀಲಿ, b, opts);
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_putb(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b)
{
	ಪ್ರತ್ಯಾಗಮ to_blob_buf(ಕೀಲಿ, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshkey_puts_opts_internal(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b,
    ಗಣನಾ sshkey_serialize_rep opts, ಪೂರ್ಣಾಙ್ಕ force_plain)
{
	ಸಂರಚನಾ sshbuf *tmp;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((tmp = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(ಕೀಲಿ, tmp, force_plain, opts);
	ಯದಿ (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_puts(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b)
{
	ಪ್ರತ್ಯಾಗಮ sshkey_puts_opts_internal(ಕೀಲಿ, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_putb_plain(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b)
{
	ಪ್ರತ್ಯಾಗಮ to_blob_buf(ಕೀಲಿ, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_puts_plain(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b)
{
	ಪ್ರತ್ಯಾಗಮ sshkey_puts_opts_internal(ಕೀಲಿ, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
to_blob(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, u_char **blobp, size_t *lenp, ಪೂರ್ಣಾಙ್ಕ force_plain,
    ಗಣನಾ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;

	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	ಯದಿ (blobp != ರಿಕ್ತ)
		*blobp = ರಿಕ್ತ;
	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((ret = to_blob_buf(ಕೀಲಿ, b, force_plain, opts)) != 0)
		ಗಚ್ಛ out;
	len = sshbuf_len(b);
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = len;
	ಯದಿ (blobp != ರಿಕ್ತ) {
		ಯದಿ ((*blobp = malloc(len)) == ರಿಕ್ತ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_to_blob(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, u_char **blobp, size_t *lenp)
{
	ಪ್ರತ್ಯಾಗಮ to_blob(ಕೀಲಿ, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_plain_to_blob(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, u_char **blobp, size_t *lenp)
{
	ಪ್ರತ್ಯಾಗಮ to_blob(ಕೀಲಿ, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_fingerprint_raw(ಧ್ರುವ ಸಂರಚನಾ sshkey *k, ಪೂರ್ಣಾಙ್ಕ dgst_alg,
    u_char **retp, size_t *lenp)
{
	u_char *blob = ರಿಕ್ತ, *ret = ರಿಕ್ತ;
	size_t blob_len = 0;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (retp != ರಿಕ್ತ)
		*retp = ರಿಕ್ತ;
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	ಯದಿ (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((ret = calloc(1, SSH_DIGEST_MAX_LENGTH)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_LENGTH)) != 0)
		ಗಚ್ಛ out;
	/* success */
	ಯದಿ (retp != ರಿಕ್ತ) {
		*retp = ret;
		ret = ರಿಕ್ತ;
	}
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	ಮುಕ್ತ(ret);
	ಯದಿ (blob != ರಿಕ್ತ)
		freezero(blob, blob_len);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ವರ್ಣ *
fingerprint_b64(ಧ್ರುವ ವರ್ಣ *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	ವರ್ಣ *ret;
	size_t plen = strlen(alg) + 1;
	size_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	ಯದಿ (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	ಯದಿ (dgst_raw_len == 0)
		ಪ್ರತ್ಯಾಗಮ ret;
	ಯದಿ (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ವರ್ಣ *
fingerprint_hex(ಧ್ರುವ ವರ್ಣ *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	ವರ್ಣ *retval, hex[5];
	size_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	ಯದಿ (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	ಪ್ರತಿ (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, ಪರಿಮಾಣ(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	ಪ್ರತ್ಯಾಗಮ retval;
}

ಸ್ಥಿರ ವರ್ಣ *
fingerprint_bubblebabble(u_char *dgst_raw, size_t dgst_raw_len)
{
	ವರ್ಣ vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	ವರ್ಣ consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	ವರ್ಣ *retval;

	rounds = (dgst_raw_len / 2) + 1;
	ಯದಿ ((retval = calloc(rounds, 6)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	retval[j++] = 'x';
	ಪ್ರತಿ (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		ಯದಿ ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			ಯದಿ ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} ಅನ್ಯಥಾ {
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
	ಪ್ರತ್ಯಾಗಮ retval;
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
ಸ್ಥಿರ ವರ್ಣ *
fingerprint_randomart(ಧ್ರುವ ವರ್ಣ *alg, u_char *dgst_raw, size_t dgst_raw_len,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	ವರ್ಣ	*augmentation_string = " .o+=*BOX@%&#/^SE";
	ವರ್ಣ	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	size_t	 i, tlen, hlen;
	u_int	 b;
	ಪೂರ್ಣಾಙ್ಕ	 x, y, r;
	size_t	 len = strlen(augmentation_string) - 1;

	ಯದಿ ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * ಪರಿಮಾಣ(ವರ್ಣ));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	ಪ್ರತಿ (i = 0; i < dgst_raw_len; i++) {
		ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು;
		/* each byte conveys four 2-bit move commands */
		ಒಳಹರಿವು = dgst_raw[i];
		ಪ್ರತಿ (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (ಒಳಹರಿವು & 0x1) ? 1 : -1;
			y += (ಒಳಹರಿವು & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			ಯದಿ (field[x][y] < len - 2)
				field[x][y]++;
			ಒಳಹರಿವು = ಒಳಹರಿವು >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, ಪರಿಮಾಣ(title), "[%s %u]",
		sshkey_type(k), sshkey_size(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	ಯದಿ (r < 0 || r > (ಪೂರ್ಣಾಙ್ಕ)ಪರಿಮಾಣ(title))
		r = snprintf(title, ಪರಿಮಾಣ(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, ಪರಿಮಾಣ(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	ಪ್ರತಿ (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	memcpy(p, title, tlen);
	p += tlen;
	ಪ್ರತಿ (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	ಪ್ರತಿ (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		ಪ್ರತಿ (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	ಪ್ರತಿ (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	memcpy(p, hash, hlen);
	p += hlen;
	ಪ್ರತಿ (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	ಪ್ರತ್ಯಾಗಮ retval;
}

ವರ್ಣ *
sshkey_fingerprint(ಧ್ರುವ ಸಂರಚನಾ sshkey *k, ಪೂರ್ಣಾಙ್ಕ dgst_alg,
    ಗಣನಾ sshkey_fp_rep dgst_rep)
{
	ವರ್ಣ *retval = ರಿಕ್ತ;
	u_char *dgst_raw;
	size_t dgst_raw_len;

	ಯದಿ (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ವಿಕಲ್ಪ (dgst_rep) {
	ಪಕ್ಷ SSH_FP_DEFAULT:
		ಯದಿ (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} ಅನ್ಯಥಾ {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		freezero(dgst_raw, dgst_raw_len);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	freezero(dgst_raw, dgst_raw_len);
	ಪ್ರತ್ಯಾಗಮ retval;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
peek_type_nid(ಧ್ರುವ ವರ್ಣ *s, size_t l, ಪೂರ್ಣಾಙ್ಕ *nid)
{
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;
	ಪೂರ್ಣಾಙ್ಕ i;

	ಪ್ರತಿ (i = 0; keyimpls[i] != ರಿಕ್ತ; i++) {
		impl = keyimpls[i];
		ಯದಿ (impl->name == ರಿಕ್ತ || strlen(impl->name) != l)
			ಅನುವರ್ತ;
		ಯದಿ (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			ಯದಿ (ಕೀಲಿ_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			ಪ್ರತ್ಯಾಗಮ impl->type;
		}
	}
	ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ_UNSPEC;
}

/* XXX this can now be made const char * */
ಪೂರ್ಣಾಙ್ಕ
sshkey_read(ಸಂರಚನಾ sshkey *ret, ವರ್ಣ **cpp)
{
	ಸಂರಚನಾ sshkey *k;
	ವರ್ಣ *cp, *blobcopy;
	size_t space;
	ಪೂರ್ಣಾಙ್ಕ r, type, curve_nid = -1;
	ಸಂರಚನಾ sshbuf *blob;

	ಯದಿ (ret == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (ret->type != ಕೀಲಿ_UNSPEC && sshkey_impl_from_type(ret->type) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	ಯದಿ (space == strlen(cp))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಯದಿ ((type = peek_type_nid(cp, space, &curve_nid)) == ಕೀಲಿ_UNSPEC)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	ಪ್ರತಿ (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	ಯದಿ (*cp == '\0')
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಯದಿ (ret->type != ಕೀಲಿ_UNSPEC && ret->type != type)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
	ಯದಿ ((blob = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	ಯದಿ ((blobcopy = strndup(cp, space)) == ರಿಕ್ತ) {
		sshbuf_free(blob);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	}
	ಯದಿ ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		ಮುಕ್ತ(blobcopy);
		sshbuf_free(blob);
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಮುಕ್ತ(blobcopy);
	ಯದಿ ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		ಪ್ರತ್ಯಾಗಮ r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	ಪ್ರತಿ (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	ಯದಿ (k->type != type) {
		sshkey_free(k);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
	}
	ಯದಿ (ಕೀಲಿ_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, ಪರಿಮಾಣ(*k));

	/* success */
	*cpp = cp;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_to_base64(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ವರ್ಣ **b64p)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	ವರ್ಣ *uu = ರಿಕ್ತ;

	ಯದಿ (b64p != ರಿಕ್ತ)
		*b64p = ರಿಕ್ತ;
	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshkey_putb(ಕೀಲಿ, b)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((uu = sshbuf_dtob64_string(b, 0)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	/* Success */
	ಯದಿ (b64p != ರಿಕ್ತ) {
		*b64p = uu;
		uu = ರಿಕ್ತ;
	}
	r = 0;
 out:
	sshbuf_free(b);
	ಮುಕ್ತ(uu);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_format_text(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ವರ್ಣ *uu = ರಿಕ್ತ;

	ಯದಿ ((r = sshkey_to_base64(ಕೀಲಿ, &uu)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(ಕೀಲಿ), uu)) != 0)
		ಗಚ್ಛ out;
	r = 0;
 out:
	ಮುಕ್ತ(uu);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_write(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, FILE *f)
{
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshkey_format_text(ಕೀಲಿ, b)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		ಯದಿ (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		ಗಚ್ಛ out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಧ್ರುವ ವರ್ಣ *
sshkey_cert_type(ಧ್ರುವ ಸಂರಚನಾ sshkey *k)
{
	ವಿಕಲ್ಪ (k->cert->type) {
	ಪಕ್ಷ SSH2_CERT_TYPE_USER:
		ಪ್ರತ್ಯಾಗಮ "user";
	ಪಕ್ಷ SSH2_CERT_TYPE_HOST:
		ಪ್ರತ್ಯಾಗಮ "host";
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ "unknown";
	}
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_check_rsa_length(ಧ್ರುವ ಸಂರಚನಾ sshkey *k, ಪೂರ್ಣಾಙ್ಕ min_size)
{
#ifdef WITH_OPENSSL
	ಪೂರ್ಣಾಙ್ಕ nbits;

	ಯದಿ (k == ರಿಕ್ತ || k->pkey == ರಿಕ್ತ ||
	    (k->type != ಕೀಲಿ_RSA && k->type != ಕೀಲಿ_RSA_CERT))
		ಪ್ರತ್ಯಾಗಮ 0;
	nbits = EVP_PKEY_bits(k->pkey);
	ಯದಿ (nbits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    (min_size > 0 && nbits < min_size))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_LENGTH;
#endif /* WITH_OPENSSL */
	ಪ್ರತ್ಯಾಗಮ 0;
}

#ifdef WITH_OPENSSL
ಪೂರ್ಣಾಙ್ಕ
sshkey_ecdsa_ಕೀಲಿ_to_nid(ಧ್ರುವ EC_ಕೀಲಿ *k)
{
	ಧ್ರುವ EC_GROUP *g;
	ಪೂರ್ಣಾಙ್ಕ nid;

	ಯದಿ (k == ರಿಕ್ತ || (g = EC_ಕೀಲಿ_get0_group(k)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪ್ರತ್ಯಾಗಮ nid;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	ಪ್ರತ್ಯಾಗಮ sshkey_ecdsa_ಕೀಲಿ_to_nid(EVP_PKEY_get0_EC_ಕೀಲಿ(pkey));
}
#endif /* WITH_OPENSSL */

ಪೂರ್ಣಾಙ್ಕ
sshkey_generate(ಪೂರ್ಣಾಙ್ಕ type, u_int bits, ಸಂರಚನಾ sshkey **keyp)
{
	ಸಂರಚನಾ sshkey *k;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_INTERNAL_ERROR;
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;

	ಯದಿ (keyp == ರಿಕ್ತ || sshkey_type_is_cert(type))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	*keyp = ರಿಕ್ತ;
	ಯದಿ ((impl = sshkey_impl_from_type(type)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	ಯದಿ (impl->funcs->generate == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_FEATURE_UNSUPPORTED;
	ಯದಿ ((k = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	k->type = type;
	ಯದಿ ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		ಪ್ರತ್ಯಾಗಮ ret;
	}
	/* success */
	*keyp = k;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_cert_copy(ಧ್ರುವ ಸಂರಚನಾ sshkey *from_ಕೀಲಿ, ಸಂರಚನಾ sshkey *to_ಕೀಲಿ)
{
	u_int i;
	ಧ್ರುವ ಸಂರಚನಾ sshkey_cert *from;
	ಸಂರಚನಾ sshkey_cert *to;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (to_ಕೀಲಿ == ರಿಕ್ತ || (from = from_ಕೀಲಿ->cert) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	ಯದಿ ((to = cert_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;

	ಯದಿ ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		ಗಚ್ಛ out;

	to->serial = from->serial;
	to->type = from->type;
	ಯದಿ (from->ಕೀಲಿ_id == ರಿಕ್ತ)
		to->ಕೀಲಿ_id = ರಿಕ್ತ;
	ಅನ್ಯಥಾ ಯದಿ ((to->ಕೀಲಿ_id = strdup(from->ಕೀಲಿ_id)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	ಯದಿ (from->signature_ಕೀಲಿ == ರಿಕ್ತ)
		to->signature_ಕೀಲಿ = ರಿಕ್ತ;
	ಅನ್ಯಥಾ ಯದಿ ((r = sshkey_from_private(from->signature_ಕೀಲಿ,
	    &to->signature_ಕೀಲಿ)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (from->signature_type != ರಿಕ್ತ &&
	    (to->signature_type = strdup(from->signature_type)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (from->nprincipals > 0) {
		ಯದಿ ((to->principals = calloc(from->nprincipals,
		    ಪರಿಮಾಣ(*to->principals))) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		ಪ್ರತಿ (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			ಯದಿ (to->principals[i] == ರಿಕ್ತ) {
				to->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				ಗಚ್ಛ out;
			}
		}
	}
	to->nprincipals = from->nprincipals;

	/* success */
	cert_free(to_ಕೀಲಿ->cert);
	to_ಕೀಲಿ->cert = to;
	to = ರಿಕ್ತ;
	r = 0;
 out:
	cert_free(to);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_copy_public_sk(ಧ್ರುವ ಸಂರಚನಾ sshkey *from, ಸಂರಚನಾ sshkey *to)
{
	/* Append security-key application string */
	ಯದಿ ((to->sk_application = strdup(from->sk_application)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_from_private(ಧ್ರುವ ಸಂರಚನಾ sshkey *k, ಸಂರಚನಾ sshkey **pkp)
{
	ಸಂರಚನಾ sshkey *n = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;

	*pkp = ರಿಕ್ತ;
	ಯದಿ ((impl = sshkey_impl_from_ಕೀಲಿ(k)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	ಯದಿ ((n = sshkey_new(k->type)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = impl->funcs->copy_public(k, n)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		ಗಚ್ಛ out;
	/* success */
	*pkp = n;
	n = ರಿಕ್ತ;
	r = 0;
 out:
	sshkey_free(n);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_is_shielded(ಸಂರಚನಾ sshkey *k)
{
	ಪ್ರತ್ಯಾಗಮ k != ರಿಕ್ತ && k->shielded_private != ರಿಕ್ತ;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_shield_private(ಸಂರಚನಾ sshkey *k)
{
	ಸಂರಚನಾ sshbuf *prvbuf = ರಿಕ್ತ;
	u_char *prekey = ರಿಕ್ತ, *enc = ರಿಕ್ತ, keyiv[SSH_DIGEST_MAX_LENGTH];
	ಸಂರಚನಾ sshcipher_ctx *cctx = ರಿಕ್ತ;
	ಧ್ರುವ ಸಂರಚನಾ sshcipher *cipher;
	size_t i, enclen = 0;
	ಸಂರಚನಾ sshkey *kswap = ರಿಕ್ತ, tmp;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	ಯದಿ ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ರಿಕ್ತ) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		ಗಚ್ಛ out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	ಯದಿ ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		ಗಚ್ಛ out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	ಯದಿ ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		ಗಚ್ಛ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	ಯದಿ ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		ಗಚ್ಛ out;

	/* Serialise and encrypt the private key using the ephemeral key */
	ಯದಿ ((prvbuf = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		ಗಚ್ಛ out;
	/* pad to cipher blocksize */
	i = 0;
	ಯಾವತ್ (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		ಯದಿ ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			ಗಚ್ಛ out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	ಯದಿ ((enc = malloc(enclen)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		ಗಚ್ಛ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	ಯದಿ ((r = sshkey_from_private(k, &kswap)) != 0)
		ಗಚ್ಛ out;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_private = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = ರಿಕ್ತ; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 out:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, ಪರಿಮಾಣ(keyiv));
	explicit_bzero(&tmp, ಪರಿಮಾಣ(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Check deterministic padding after private key */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
private2_check_padding(ಸಂರಚನಾ sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	ಪೂರ್ಣಾಙ್ಕ r;

	i = 0;
	ಯಾವತ್ (sshbuf_len(decrypted)) {
		ಯದಿ ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			ಗಚ್ಛ out;
		ಯದಿ (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, ಪರಿಮಾಣ(pad));
	explicit_bzero(&i, ಪರಿಮಾಣ(i));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_unshield_private(ಸಂರಚನಾ sshkey *k)
{
	ಸಂರಚನಾ sshbuf *prvbuf = ರಿಕ್ತ;
	u_char *cp, keyiv[SSH_DIGEST_MAX_LENGTH];
	ಸಂರಚನಾ sshcipher_ctx *cctx = ರಿಕ್ತ;
	ಧ್ರುವ ಸಂರಚನಾ sshcipher *cipher;
	ಸಂರಚನಾ sshkey *kswap = ರಿಕ್ತ, tmp;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	ಯದಿ (!sshkey_is_shielded(k))
		ಪ್ರತ್ಯಾಗಮ 0; /* nothing to do */

	ಯದಿ ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ರಿಕ್ತ) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		ಗಚ್ಛ out;
	}
	/* check size of shielded key blob */
	ಯದಿ (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}

	/* Calculate the ephemeral key from the prekey */
	ಯದಿ ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		ಗಚ್ಛ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	ಯದಿ ((prvbuf = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		ಗಚ್ಛ out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(k->shielded_private, k->shielded_len, stderr);
#endif
	ಯದಿ ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		ಗಚ್ಛ out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	ಯದಿ ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ ((r = private2_check_padding(prvbuf)) != 0)
		ಗಚ್ಛ out;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 out:
	cipher_free(cctx);
	explicit_bzero(keyiv, ಪರಿಮಾಣ(keyiv));
	explicit_bzero(&tmp, ಪರಿಮಾಣ(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
cert_parse(ಸಂರಚನಾ sshbuf *b, ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *certbuf,
    ಧ್ರುವ ವರ್ಣ *ca_sigalg_allowlist)
{
	ಸಂರಚನಾ sshbuf *principals = ರಿಕ್ತ, *crit = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *exts = ರಿಕ್ತ, *ca = ರಿಕ್ತ;
	u_char *sig = ರಿಕ್ತ;
	ವರ್ಣ *sigtype = ರಿಕ್ತ;
	size_t signed_len = 0, slen = 0, kidlen = 0;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	ಯದಿ ((ret = sshbuf_putb(ಕೀಲಿ->cert->certblob, certbuf)) != 0)
		ಪ್ರತ್ಯಾಗಮ ret;

	/* Parse body of certificate up to signature */
	ಯದಿ ((ret = sshbuf_get_u64(b, &ಕೀಲಿ->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &ಕೀಲಿ->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &ಕೀಲಿ->cert->ಕೀಲಿ_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &ಕೀಲಿ->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &ಕೀಲಿ->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(ಕೀಲಿ->cert->certblob) - sshbuf_len(b);

	ಯದಿ ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}

	/* Is this a signature we're prepared to accept? */
	ಯದಿ ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (ca_sigalg_allowlist != ರಿಕ್ತ &&
	    match_pattern_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ಗಚ್ಛ out;
	}

	/* Parse CA key and check whether we might accept it */
	ಯದಿ (sshkey_from_blob_internal(ca, &ಕೀಲಿ->cert->signature_ಕೀಲಿ, 0,
	    ca_sigalg_allowlist, ರಿಕ್ತ) != 0) {
		ret = SSH_ERR_ಕೀಲಿ_CERT_INVALID_SIGN_ಕೀಲಿ;
		ಗಚ್ಛ out;
	}
	ಯದಿ (!sshkey_type_is_valid_ca(ಕೀಲಿ->cert->signature_ಕೀಲಿ->type)) {
		ret = SSH_ERR_ಕೀಲಿ_CERT_INVALID_SIGN_ಕೀಲಿ;
		ಗಚ್ಛ out;
	}

	ಯದಿ (ಕೀಲಿ->cert->type != SSH2_CERT_TYPE_USER &&
	    ಕೀಲಿ->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_ಕೀಲಿ_CERT_UNKNOWN_TYPE;
		ಗಚ್ಛ out;
	}

	/* Parse principals section */
	ಯಾವತ್ (sshbuf_len(principals) > 0) {
		ವರ್ಣ *principal = ರಿಕ್ತ;
		ವರ್ಣ **oprincipals = ರಿಕ್ತ;

		ಯದಿ (ಕೀಲಿ->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((ret = sshbuf_get_cstring(principals, &principal,
		    ರಿಕ್ತ)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		oprincipals = ಕೀಲಿ->cert->principals;
		ಕೀಲಿ->cert->principals = recallocarray(ಕೀಲಿ->cert->principals,
		    ಕೀಲಿ->cert->nprincipals, ಕೀಲಿ->cert->nprincipals + 1,
		    ಪರಿಮಾಣ(*ಕೀಲಿ->cert->principals));
		ಯದಿ (ಕೀಲಿ->cert->principals == ರಿಕ್ತ) {
			ಮುಕ್ತ(principal);
			ಕೀಲಿ->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		ಕೀಲಿ->cert->principals[ಕೀಲಿ->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	ಯದಿ ((ret = sshbuf_putb(ಕೀಲಿ->cert->critical, crit)) != 0 ||
	    (exts != ರಿಕ್ತ &&
	    (ret = sshbuf_putb(ಕೀಲಿ->cert->extensions, exts)) != 0))
		ಗಚ್ಛ out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	ಯಾವತ್ (sshbuf_len(crit) != 0) {
		ಯದಿ ((ret = sshbuf_get_string_direct(crit, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, ರಿಕ್ತ, ರಿಕ್ತ)) != 0) {
			sshbuf_reset(ಕೀಲಿ->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
	}
	ಯಾವತ್ (exts != ರಿಕ್ತ && sshbuf_len(exts) != 0) {
		ಯದಿ ((ret = sshbuf_get_string_direct(exts, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, ರಿಕ್ತ, ರಿಕ್ತ)) != 0) {
			sshbuf_reset(ಕೀಲಿ->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
	}

	/* Finally, validate signature */
	ಯದಿ ((ret = sshkey_verify(ಕೀಲಿ->cert->signature_ಕೀಲಿ, sig, slen,
	    sshbuf_ptr(ಕೀಲಿ->cert->certblob), signed_len, ರಿಕ್ತ, 0, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;

	/* Success */
	ret = 0;
	ಕೀಲಿ->cert->signature_type = sigtype;
	sigtype = ರಿಕ್ತ;
 out:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	ಮುಕ್ತ(sig);
	ಮುಕ್ತ(sigtype);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_deserialize_sk(ಸಂರಚನಾ sshbuf *b, ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	/* Parse additional security-key application string */
	ಯದಿ (sshbuf_get_cstring(b, &ಕೀಲಿ->sk_application, ರಿಕ್ತ) != 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshkey_from_blob_internal(ಸಂರಚನಾ sshbuf *b, ಸಂರಚನಾ sshkey **keyp,
    ಪೂರ್ಣಾಙ್ಕ allow_cert, ಧ್ರುವ ವರ್ಣ *alg_allowlist, ಧ್ರುವ ವರ್ಣ *ca_sigalg_allowlist)
{
	ಪೂರ್ಣಾಙ್ಕ type, ret = SSH_ERR_INTERNAL_ERROR;
	ವರ್ಣ *ktype = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *copy;
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	ಯದಿ (keyp != ರಿಕ್ತ)
		*keyp = ರಿಕ್ತ;
	ಯದಿ ((copy = sshbuf_fromb(b)) == ರಿಕ್ತ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_get_cstring(b, &ktype, ರಿಕ್ತ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}

	type = sshkey_type_from_name(ktype);
	ಯದಿ (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_ಕೀಲಿ_CERT_INVALID_SIGN_ಕೀಲಿ;
		ಗಚ್ಛ out;
	}

	ಯದಿ (alg_allowlist != ರಿಕ್ತ &&
	    !sshkey_match_keyname_to_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_ಕೀಲಿ_ALG_UNSUPPORTED;
		ಗಚ್ಛ out;
	}

	ಯದಿ ((impl = sshkey_impl_from_type(type)) == ರಿಕ್ತ) {
		ret = SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ಕೀಲಿ = sshkey_new(type)) == ರಿಕ್ತ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		ಯದಿ (sshbuf_get_string_direct(b, ರಿಕ್ತ, ರಿಕ್ತ) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
	}
	ಯದಿ ((ret = impl->funcs->deserialize_public(ktype, b, ಕೀಲಿ)) != 0)
		ಗಚ್ಛ out;

	/* Parse certificate potion */
	ಯದಿ (sshkey_is_cert(ಕೀಲಿ) &&
	    (ret = cert_parse(b, ಕೀಲಿ, copy, ca_sigalg_allowlist)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ (ಕೀಲಿ != ರಿಕ್ತ && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ret = 0;
	ಯದಿ (keyp != ರಿಕ್ತ) {
		*keyp = ಕೀಲಿ;
		ಕೀಲಿ = ರಿಕ್ತ;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(ಕೀಲಿ);
	ಮುಕ್ತ(ktype);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_from_blob(ಧ್ರುವ u_char *blob, size_t blen, ಸಂರಚನಾ sshkey **keyp)
{
	ಸಂರಚನಾ sshbuf *b;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((b = sshbuf_from(blob, blen)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1, ರಿಕ್ತ, ರಿಕ್ತ);
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_fromb(ಸಂರಚನಾ sshbuf *b, ಸಂರಚನಾ sshkey **keyp)
{
	ಪ್ರತ್ಯಾಗಮ sshkey_from_blob_internal(b, keyp, 1, ರಿಕ್ತ, ರಿಕ್ತ);
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_fromb_allowlist(ಸಂರಚನಾ sshbuf *b, ಸಂರಚನಾ sshkey **keyp,
    ಧ್ರುವ ವರ್ಣ *alg_allowlist, ಧ್ರುವ ವರ್ಣ *ca_sigalg_allowlist)
{
	ಪ್ರತ್ಯಾಗಮ sshkey_from_blob_internal(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_froms(ಸಂರಚನಾ sshbuf *buf, ಸಂರಚನಾ sshkey **keyp)
{
	ಸಂರಚನಾ sshbuf *b;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_froms(buf, &b)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	r = sshkey_from_blob_internal(b, keyp, 1, ರಿಕ್ತ, ರಿಕ್ತ);
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_get_sigtype(ಧ್ರುವ u_char *sig, size_t siglen, ವರ್ಣ **sigtypep)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	ವರ್ಣ *sigtype = ರಿಕ್ತ;

	ಯದಿ (sigtypep != ರಿಕ್ತ)
		*sigtypep = ರಿಕ್ತ;
	ಯದಿ ((b = sshbuf_from(sig, siglen)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_get_cstring(b, &sigtype, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;
	/* success */
	ಯದಿ (sigtypep != ರಿಕ್ತ) {
		*sigtypep = sigtype;
		sigtype = ರಿಕ್ತ;
	}
	r = 0;
 out:
	ಮುಕ್ತ(sigtype);
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
ಪೂರ್ಣಾಙ್ಕ
sshkey_check_cert_sigtype(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *allowed)
{
	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ || allowed == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (!sshkey_type_is_cert(ಕೀಲಿ->type))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (ಕೀಲಿ->cert == ರಿಕ್ತ || ಕೀಲಿ->cert->signature_type == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (match_pattern_list(ಕೀಲಿ->cert->signature_type, allowed, 0) != 1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SIGN_ALG_UNSUPPORTED;
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
ಧ್ರುವ ವರ್ಣ *
sshkey_sigalg_by_name(ಧ್ರುವ ವರ್ಣ *name)
{
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;
	ಪೂರ್ಣಾಙ್ಕ i;

	ಪ್ರತಿ (i = 0; keyimpls[i] != ರಿಕ್ತ; i++) {
		impl = keyimpls[i];
		ಯದಿ (strcmp(impl->name, name) != 0)
			ಅನುವರ್ತ;
		ಯದಿ (impl->sigalg != ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ impl->sigalg;
		ಯದಿ (!impl->cert)
			ಪ್ರತ್ಯಾಗಮ impl->name;
		ಪ್ರತ್ಯಾಗಮ sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
ಪೂರ್ಣಾಙ್ಕ
sshkey_check_sigtype(ಧ್ರುವ u_char *sig, size_t siglen,
    ಧ್ರುವ ವರ್ಣ *requested_alg)
{
	ಧ್ರುವ ವರ್ಣ *expected_alg;
	ವರ್ಣ *sigtype = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (requested_alg == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	r = strcmp(expected_alg, sigtype) == 0;
	ಮುಕ್ತ(sigtype);
	ಪ್ರತ್ಯಾಗಮ r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_sign(ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen,
    ಧ್ರುವ ವರ್ಣ *alg, ಧ್ರುವ ವರ್ಣ *sk_provider, ಧ್ರುವ ವರ್ಣ *sk_pin, u_int compat)
{
	ಪೂರ್ಣಾಙ್ಕ was_shielded = sshkey_is_shielded(ಕೀಲಿ);
	ಪೂರ್ಣಾಙ್ಕ r2, r = SSH_ERR_INTERNAL_ERROR;
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;

	ಯದಿ (sigp != ರಿಕ್ತ)
		*sigp = ರಿಕ್ತ;
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	ಯದಿ (datalen > SSH_ಕೀಲಿ_MAX_SIGN_DATA_SIZE)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((impl = sshkey_impl_from_ಕೀಲಿ(ಕೀಲಿ)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	ಯದಿ ((r = sshkey_unshield_private(ಕೀಲಿ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (sshkey_is_sk(ಕೀಲಿ)) {
		r = sshsk_sign(sk_provider, ಕೀಲಿ, sigp, lenp, data,
		    datalen, compat, sk_pin);
	} ಅನ್ಯಥಾ ಯದಿ ((ಕೀಲಿ->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(ಕೀಲಿ, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	} ಅನ್ಯಥಾ {
		ಯದಿ (impl->funcs->sign == ರಿಕ್ತ)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ಅನ್ಯಥಾ {
			r = impl->funcs->sign(ಕೀಲಿ, sigp, lenp, data, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	ಯದಿ (was_shielded && (r2 = sshkey_shield_private(ಕೀಲಿ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r2;
	ಪ್ರತ್ಯಾಗಮ r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
ಪೂರ್ಣಾಙ್ಕ
sshkey_verify(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ u_char *sig, size_t siglen,
    ಧ್ರುವ u_char *data, size_t dlen, ಧ್ರುವ ವರ್ಣ *alg, u_int compat,
    ಸಂರಚನಾ sshkey_sig_details **detailsp)
{
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;

	ಯದಿ (detailsp != ರಿಕ್ತ)
		*detailsp = ರಿಕ್ತ;
	ಯದಿ (siglen == 0 || dlen > SSH_ಕೀಲಿ_MAX_SIGN_DATA_SIZE)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((impl = sshkey_impl_from_ಕೀಲಿ(ಕೀಲಿ)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	ಪ್ರತ್ಯಾಗಮ impl->funcs->verify(ಕೀಲಿ, sig, siglen, data, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
ಪೂರ್ಣಾಙ್ಕ
sshkey_to_certified(ಸಂರಚನಾ sshkey *k)
{
	ಪೂರ್ಣಾಙ್ಕ newtype;

	ಯದಿ ((newtype = sshkey_type_certified(k->type)) == -1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((k->cert = cert_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Convert a certificate to its raw key equivalent */
ಪೂರ್ಣಾಙ್ಕ
sshkey_drop_cert(ಸಂರಚನಾ sshkey *k)
{
	ಯದಿ (!sshkey_type_is_cert(k->type))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = ರಿಕ್ತ;
	k->type = sshkey_type_plain(k->type);
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
ಪೂರ್ಣಾಙ್ಕ
sshkey_certify_custom(ಸಂರಚನಾ sshkey *k, ಸಂರಚನಾ sshkey *ca, ಧ್ರುವ ವರ್ಣ *alg,
    ಧ್ರುವ ವರ್ಣ *sk_provider, ಧ್ರುವ ವರ್ಣ *sk_pin,
    sshkey_certify_signer *signer, ಶೂನ್ಯ *signer_ctx)
{
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;
	ಸಂರಚನಾ sshbuf *principals = ರಿಕ್ತ;
	u_char *ca_blob = ರಿಕ್ತ, *sig_blob = ರಿಕ್ತ, nonce[32];
	size_t i, ca_len, sig_len;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ sshbuf *cert = ರಿಕ್ತ;
	ವರ್ಣ *sigtype = ರಿಕ್ತ;

	ಯದಿ (k == ರಿಕ್ತ || k->cert == ರಿಕ್ತ ||
	    k->cert->certblob == ರಿಕ್ತ || ca == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (!sshkey_is_cert(k))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	ಯದಿ (!sshkey_type_is_valid_ca(ca->type))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_CERT_INVALID_SIGN_ಕೀಲಿ;
	ಯದಿ ((impl = sshkey_impl_from_ಕೀಲಿ(k)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	ಯದಿ (alg == ರಿಕ್ತ)
		alg = k->cert->signature_type;
	ಅನ್ಯಥಾ ಯದಿ (k->cert->signature_type != ರಿಕ್ತ &&
	    strcmp(alg, k->cert->signature_type) != 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	ಯದಿ (alg == ರಿಕ್ತ && ca->type == ಕೀಲಿ_RSA)
		alg = "rsa-sha2-512";

	ಯದಿ ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_CERT_INVALID_SIGN_ಕೀಲಿ;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	ಯದಿ ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		ಗಚ್ಛ out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, ಪರಿಮಾಣ(nonce));
	ಯದಿ ((ret = sshbuf_put_string(cert, nonce, ಪರಿಮಾಣ(nonce))) != 0)
		ಗಚ್ಛ out;

	/* Public key next */
	ಯದಿ ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		ಗಚ್ಛ out;

	/* Then remaining cert fields */
	ಯದಿ ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->ಕೀಲಿ_id)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ ((principals = sshbuf_new()) == ರಿಕ್ತ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಪ್ರತಿ (i = 0; i < k->cert->nprincipals; i++) {
		ಯದಿ ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			ಗಚ್ಛ out;
	}
	ಯದಿ ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, ರಿಕ್ತ, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		ಗಚ್ಛ out;

	/* Sign the whole mess */
	ಯದಿ ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		ಗಚ್ಛ out;
	/* Check and update signature_type against what was actually used */
	ಯದಿ ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (alg != ರಿಕ್ತ && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ಗಚ್ಛ out;
	}
	ಯದಿ (k->cert->signature_type == ರಿಕ್ತ) {
		k->cert->signature_type = sigtype;
		sigtype = ರಿಕ್ತ;
	}
	/* Append signature and we are done */
	ಯದಿ ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		ಗಚ್ಛ out;
	ret = 0;
 out:
	ಯದಿ (ret != 0)
		sshbuf_reset(cert);
	ಮುಕ್ತ(sig_blob);
	ಮುಕ್ತ(ca_blob);
	ಮುಕ್ತ(sigtype);
	sshbuf_free(principals);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
default_ಕೀಲಿ_sign(ಸಂರಚನಾ sshkey *ಕೀಲಿ, u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen,
    ಧ್ರುವ ವರ್ಣ *alg, ಧ್ರುವ ವರ್ಣ *sk_provider, ಧ್ರುವ ವರ್ಣ *sk_pin,
    u_int compat, ಶೂನ್ಯ *ctx)
{
	ಯದಿ (ctx != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಪ್ರತ್ಯಾಗಮ sshkey_sign(ಕೀಲಿ, sigp, lenp, data, datalen, alg,
	    sk_provider, sk_pin, compat);
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_certify(ಸಂರಚನಾ sshkey *k, ಸಂರಚನಾ sshkey *ca, ಧ್ರುವ ವರ್ಣ *alg,
    ಧ್ರುವ ವರ್ಣ *sk_provider, ಧ್ರುವ ವರ್ಣ *sk_pin)
{
	ಪ್ರತ್ಯಾಗಮ sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_ಕೀಲಿ_sign, ರಿಕ್ತ);
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_cert_check_authority(ಧ್ರುವ ಸಂರಚನಾ sshkey *k,
    ಪೂರ್ಣಾಙ್ಕ want_host, ಪೂರ್ಣಾಙ್ಕ wildcard_pattern, uint64_t verify_time,
    ಧ್ರುವ ವರ್ಣ *name, ಧ್ರುವ ವರ್ಣ **reason)
{
	u_int i, principal_matches;

	ಯದಿ (reason == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಯದಿ (want_host) {
		ಯದಿ (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
		}
	} ಅನ್ಯಥಾ {
		ಯದಿ (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
		}
	}
	ಯದಿ (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಯದಿ (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಯದಿ (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಯದಿ (name == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0; /* principal matching not requested */

	principal_matches = 0;
	ಪ್ರತಿ (i = 0; i < k->cert->nprincipals; i++) {
		ಯದಿ (wildcard_pattern) {
			ಯದಿ (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				ಭಙ್ಗ;
			}
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			ಭಙ್ಗ;
		}
	}
	ಯದಿ (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_cert_check_authority_now(ಧ್ರುವ ಸಂರಚನಾ sshkey *k,
    ಪೂರ್ಣಾಙ್ಕ want_host, ಪೂರ್ಣಾಙ್ಕ wildcard_pattern, ಧ್ರುವ ವರ್ಣ *name,
    ಧ್ರುವ ವರ್ಣ **reason)
{
	time_t now;

	ಯದಿ ((now = time(ರಿಕ್ತ)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಪ್ರತ್ಯಾಗಮ sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_cert_check_host(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *host,
    ಧ್ರುವ ವರ್ಣ *ca_sign_algorithms, ಧ್ರುವ ವರ್ಣ **reason)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshkey_cert_check_authority_now(ಕೀಲಿ, 1, 1, host, reason)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (sshbuf_len(ಕೀಲಿ->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಯದಿ (ca_sign_algorithms != ರಿಕ್ತ &&
	    (r = sshkey_check_cert_sigtype(ಕೀಲಿ, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

size_t
sshkey_format_cert_validity(ಧ್ರುವ ಸಂರಚನಾ sshkey_cert *cert, ವರ್ಣ *s, size_t l)
{
	ವರ್ಣ from[32], to[32], ret[128];

	*from = *to = '\0';
	ಯದಿ (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		ಪ್ರತ್ಯಾಗಮ strlcpy(s, "forever", l);

	ಯದಿ (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, ಪರಿಮಾಣ(from));
	ಯದಿ (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, ಪರಿಮಾಣ(to));

	ಯದಿ (cert->valid_after == 0)
		snprintf(ret, ಪರಿಮಾಣ(ret), "before %s", to);
	ಅನ್ಯಥಾ ಯದಿ (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, ಪರಿಮಾಣ(ret), "after %s", from);
	ಅನ್ಯಥಾ
		snprintf(ret, ಪರಿಮಾಣ(ret), "from %s to %s", from, to);

	ಪ್ರತ್ಯಾಗಮ strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
ಪೂರ್ಣಾಙ್ಕ
sshkey_serialize_private_sk(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_put_cstring(b, ಕೀಲಿ->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, ಕೀಲಿ->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, ಕೀಲಿ->sk_ಕೀಲಿ_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, ಕೀಲಿ->sk_reserved)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshkey_private_serialize_opt(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *buf,
    ಗಣನಾ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ಪೂರ್ಣಾಙ್ಕ was_shielded = sshkey_is_shielded(ಕೀಲಿ);
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;

	ಯದಿ ((impl = sshkey_impl_from_ಕೀಲಿ(ಕೀಲಿ)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	ಯದಿ ((r = sshkey_unshield_private(ಕೀಲಿ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_put_cstring(b, sshkey_ssh_name(ಕೀಲಿ))) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (sshkey_is_cert(ಕೀಲಿ)) {
		ಯದಿ (ಕೀಲಿ->cert == ರಿಕ್ತ ||
		    sshbuf_len(ಕೀಲಿ->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_put_stringb(b, ಕೀಲಿ->cert->certblob)) != 0)
			ಗಚ್ಛ out;
	}
	ಯದಿ ((r = impl->funcs->serialize_private(ಕೀಲಿ, b, opts)) != 0)
		ಗಚ್ಛ out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	ಯದಿ (was_shielded)
		r = sshkey_shield_private(ಕೀಲಿ);
	ಯದಿ (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_private_serialize(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b)
{
	ಪ್ರತ್ಯಾಗಮ sshkey_private_serialize_opt(ಕೀಲಿ, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
ಪೂರ್ಣಾಙ್ಕ
sshkey_private_deserialize_sk(ಸಂರಚನಾ sshbuf *buf, ಸಂರಚನಾ sshkey *k)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((k->sk_ಕೀಲಿ_handle = sshbuf_new()) == ರಿಕ್ತ ||
	    (k->sk_reserved = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_get_cstring(buf, &k->sk_application, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_ಕೀಲಿ_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_private_deserialize(ಸಂರಚನಾ sshbuf *buf, ಸಂರಚನಾ sshkey **kp)
{
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl *impl;
	ವರ್ಣ *tname = ರಿಕ್ತ;
	ವರ್ಣ *expect_sk_application = ರಿಕ್ತ;
	u_char *expect_ed25519_pk = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ type, r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (kp != ರಿಕ್ತ)
		*kp = ರಿಕ್ತ;
	ಯದಿ ((r = sshbuf_get_cstring(buf, &tname, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;
	type = sshkey_type_from_name(tname);
	ಯದಿ (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		ಯದಿ ((r = sshkey_froms(buf, &k)) != 0)
			ಗಚ್ಛ out;
		ಯದಿ (k->type != type) {
			r = SSH_ERR_ಕೀಲಿ_CERT_MISMATCH;
			ಗಚ್ಛ out;
		}
		/* For ECDSA keys, the group must match too */
		ಯದಿ (k->type == ಕೀಲಿ_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_ಕೀಲಿ_CERT_MISMATCH;
			ಗಚ್ಛ out;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = ರಿಕ್ತ;
		k->ed25519_pk = ರಿಕ್ತ;
	} ಅನ್ಯಥಾ {
		ಯದಿ ((k = sshkey_new(type)) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
	}
	ಯದಿ ((impl = sshkey_impl_from_type(type)) == ರಿಕ್ತ) {
		r = SSH_ERR_INTERNAL_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ ((expect_sk_application != ರಿಕ್ತ && (k->sk_application == ರಿಕ್ತ ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != ರಿಕ್ತ && (k->ed25519_pk == ರಿಕ್ತ ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_ಕೀಲಿ_CERT_MISMATCH;
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
	ಯದಿ (kp != ರಿಕ್ತ) {
		*kp = k;
		k = ರಿಕ್ತ;
	}
 out:
	ಮುಕ್ತ(tname);
	sshkey_free(k);
	ಮುಕ್ತ(expect_sk_application);
	ಮುಕ್ತ(expect_ed25519_pk);
	ಪ್ರತ್ಯಾಗಮ r;
}

#ifdef WITH_OPENSSL
ಪೂರ್ಣಾಙ್ಕ
sshkey_ec_validate_public(ಧ್ರುವ EC_GROUP *group, ಧ್ರುವ EC_POINT *ಸಾರ್ವಜನಿಕ)
{
	EC_POINT *nq = ರಿಕ್ತ;
	BIGNUM *order = ರಿಕ್ತ, *cofactor = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_ಕೀಲಿ_INVALID_EC_ಮೌಲ್ಯ;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	ಯದಿ (EC_POINT_is_at_infinity(group, ಸಾರ್ವಜನಿಕ))
		ಗಚ್ಛ out;

	ಯದಿ ((cofactor = BN_new()) == ರಿಕ್ತ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (EC_GROUP_get_cofactor(group, cofactor, ರಿಕ್ತ) != 1)
		ಗಚ್ಛ out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	ಯದಿ (!BN_is_one(cofactor)) {
		ಯದಿ ((order = BN_new()) == ರಿಕ್ತ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		ಯದಿ (EC_GROUP_get_order(group, order, ರಿಕ್ತ) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((nq = EC_POINT_new(group)) == ರಿಕ್ತ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		ಯದಿ (EC_POINT_mul(group, nq, ರಿಕ್ತ, ಸಾರ್ವಜನಿಕ, order, ರಿಕ್ತ) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			ಗಚ್ಛ out;
		}
		ಯದಿ (EC_POINT_is_at_infinity(group, nq) != 1)
			ಗಚ್ಛ out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_ec_validate_private(ಧ್ರುವ EC_ಕೀಲಿ *ಕೀಲಿ)
{
	BIGNUM *order = ರಿಕ್ತ, *tmp = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_ERR_ಕೀಲಿ_INVALID_EC_ಮೌಲ್ಯ;

	ಯದಿ ((order = BN_new()) == ರಿಕ್ತ || (tmp = BN_new()) == ರಿಕ್ತ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}

	/* log2(private) > log2(order)/2 */
	ಯದಿ (EC_GROUP_get_order(EC_ಕೀಲಿ_get0_group(ಕೀಲಿ), order, ರಿಕ್ತ) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ (BN_ಅಂಕೆ_bits(EC_ಕೀಲಿ_get0_private_ಕೀಲಿ(ಕೀಲಿ)) <=
	    BN_ಅಂಕೆ_bits(order) / 2)
		ಗಚ್ಛ out;

	/* private < order - 1 */
	ಯದಿ (!BN_sub(tmp, order, BN_ಮೌಲ್ಯ_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ (BN_cmp(EC_ಕೀಲಿ_get0_private_ಕೀಲಿ(ಕೀಲಿ), tmp) >= 0)
		ಗಚ್ಛ out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
sshkey_dump_ec_point(ಧ್ರುವ EC_GROUP *group, ಧ್ರುವ EC_POINT *point)
{
	BIGNUM *x = ರಿಕ್ತ, *y = ರಿಕ್ತ;

	ಯದಿ (point == ರಿಕ್ತ) {
		fputs("point=(NULL)\n", stderr);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ ((x = BN_new()) == ರಿಕ್ತ || (y = BN_new()) == ರಿಕ್ತ) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		ಗಚ್ಛ out;
	}
	ಯದಿ (EC_POINT_get_affine_coordinates(group, point, x, y, ರಿಕ್ತ) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		ಗಚ್ಛ out;
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

ಶೂನ್ಯ
sshkey_dump_ec_ಕೀಲಿ(ಧ್ರುವ EC_ಕೀಲಿ *ಕೀಲಿ)
{
	ಧ್ರುವ BIGNUM *exponent;

	sshkey_dump_ec_point(EC_ಕೀಲಿ_get0_group(ಕೀಲಿ),
	    EC_ಕೀಲಿ_get0_public_ಕೀಲಿ(ಕೀಲಿ));
	fputs("exponent=", stderr);
	ಯದಿ ((exponent = EC_ಕೀಲಿ_get0_private_ಕೀಲಿ(ಕೀಲಿ)) == ರಿಕ್ತ)
		fputs("(NULL)", stderr);
	ಅನ್ಯಥಾ
		BN_print_fp(stderr, EC_ಕೀಲಿ_get0_private_ಕೀಲಿ(ಕೀಲಿ));
	fputs("\n", stderr);
}
#endif /* WITH_OPENSSL */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshkey_private_to_blob2(ಸಂರಚನಾ sshkey *prv, ಸಂರಚನಾ sshbuf *blob,
    ಧ್ರುವ ವರ್ಣ *passphrase, ಧ್ರುವ ವರ್ಣ *comment, ಧ್ರುವ ವರ್ಣ *ciphername,
    ಪೂರ್ಣಾಙ್ಕ rounds)
{
	u_char *cp, *ಕೀಲಿ = ರಿಕ್ತ, *pubkeyblob = ರಿಕ್ತ;
	u_char salt[SALT_LEN];
	size_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ sshcipher_ctx *ciphercontext = ರಿಕ್ತ;
	ಧ್ರುವ ಸಂರಚನಾ sshcipher *cipher;
	ಧ್ರುವ ವರ್ಣ *kdfname = KDFNAME;
	ಸಂರಚನಾ sshbuf *encoded = ರಿಕ್ತ, *encrypted = ರಿಕ್ತ, *kdf = ರಿಕ್ತ;

	ಯದಿ (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	ಯದಿ (rounds > MAX_KDF_ROUNDS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (passphrase == ರಿಕ್ತ || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} ಅನ್ಯಥಾ ಯದಿ (ciphername == ರಿಕ್ತ)
		ciphername = DEFAULT_CIPHERNAME;
	ಯದಿ ((cipher = cipher_by_name(ciphername)) == ರಿಕ್ತ) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}

	ಯದಿ ((kdf = sshbuf_new()) == ರಿಕ್ತ ||
	    (encoded = sshbuf_new()) == ರಿಕ್ತ ||
	    (encrypted = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	ಯದಿ ((ಕೀಲಿ = calloc(1, keylen + ivlen)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		ಯದಿ (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, ಕೀಲಿ, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_ಕೀಲಿ_UNKNOWN_CIPHER;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = cipher_init(&ciphercontext, cipher, ಕೀಲಿ, keylen,
	    ಕೀಲಿ + keylen, ivlen, 1)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ ((r = sshbuf_put(encoded, AUTH_MAGIC, ಪರಿಮಾಣ(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_to_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		ಗಚ್ಛ out;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	ಯದಿ ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		ಗಚ್ಛ out;

	/* append private key and comment*/
	ಯದಿ ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		ಗಚ್ಛ out;

	/* padding */
	i = 0;
	ಯಾವತ್ (sshbuf_len(encrypted) % blocksize) {
		ಯದಿ ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			ಗಚ್ಛ out;
	}

	/* length in destination buffer */
	ಯದಿ ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		ಗಚ್ಛ out;

	/* encrypt */
	ಯದಿ ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		ಗಚ್ಛ out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	ಯದಿ ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_END, MARK_END_LEN)) != 0)
		ಗಚ್ಛ out;

	/* success */
	r = 0;

 out:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, ಪರಿಮಾಣ(salt));
	ಯದಿ (ಕೀಲಿ != ರಿಕ್ತ)
		freezero(ಕೀಲಿ, keylen + ivlen);
	ಯದಿ (pubkeyblob != ರಿಕ್ತ)
		freezero(pubkeyblob, pubkeylen);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
private2_uudecode(ಸಂರಚನಾ sshbuf *blob, ಸಂರಚನಾ sshbuf **decodedp)
{
	ಧ್ರುವ u_char *cp;
	size_t encoded_len;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_char last;
	ಸಂರಚನಾ sshbuf *encoded = ರಿಕ್ತ, *decoded = ರಿಕ್ತ;

	ಯದಿ (blob == ರಿಕ್ತ || decodedp == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	*decodedp = ರಿಕ್ತ;

	ಯದಿ ((encoded = sshbuf_new()) == ರಿಕ್ತ ||
	    (decoded = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	ಯದಿ (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	ಯಾವತ್ (encoded_len > 0) {
		ಯದಿ (*cp != '\n' && *cp != '\r') {
			ಯದಿ ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				ಗಚ್ಛ out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		ಯದಿ (last == '\n') {
			ಯದಿ (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				ಯದಿ ((r = sshbuf_put_u8(encoded, 0)) != 0)
					ಗಚ್ಛ out;
				ಭಙ್ಗ;
			}
		}
	}
	ಯದಿ (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}

	/* decode base64 */
	ಯದಿ ((r = sshbuf_b64tod(decoded, (ವರ್ಣ *)sshbuf_ptr(encoded))) != 0)
		ಗಚ್ಛ out;

	/* check magic */
	ಯದಿ (sshbuf_len(decoded) < ಪರಿಮಾಣ(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, ಪರಿಮಾಣ(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	/* success */
	*decodedp = decoded;
	decoded = ರಿಕ್ತ;
	r = 0;
 out:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
private2_decrypt(ಸಂರಚನಾ sshbuf *decoded, ಧ್ರುವ ವರ್ಣ *passphrase,
    ಸಂರಚನಾ sshbuf **decryptedp, ಸಂರಚನಾ sshkey **pubkeyp)
{
	ವರ್ಣ *ciphername = ರಿಕ್ತ, *kdfname = ರಿಕ್ತ;
	ಧ್ರುವ ಸಂರಚನಾ sshcipher *cipher = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	ಸಂರಚನಾ sshbuf *kdf = ರಿಕ್ತ, *decrypted = ರಿಕ್ತ;
	ಸಂರಚನಾ sshcipher_ctx *ciphercontext = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *pubkey = ರಿಕ್ತ;
	u_char *ಕೀಲಿ = ರಿಕ್ತ, *salt = ರಿಕ್ತ, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	ಯದಿ (decoded == ರಿಕ್ತ || decryptedp == ರಿಕ್ತ || pubkeyp == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = ರಿಕ್ತ;
	*pubkeyp = ರಿಕ್ತ;

	ಯದಿ ((decrypted = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}

	/* parse public portion of key */
	ಯದಿ ((r = sshbuf_consume(decoded, ಪರಿಮಾಣ(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}

	ಯದಿ ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ ((cipher = cipher_by_name(ciphername)) == ರಿಕ್ತ) {
		r = SSH_ERR_ಕೀಲಿ_UNKNOWN_CIPHER;
		ಗಚ್ಛ out;
	}
	ಯದಿ (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_ಕೀಲಿ_UNKNOWN_CIPHER;
		ಗಚ್ಛ out;
	}
	ಯದಿ (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((passphrase == ರಿಕ್ತ || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
		ಗಚ್ಛ out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	ಯದಿ (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	ಯದಿ ((ಕೀಲಿ = calloc(1, keylen + ivlen)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (strcmp(kdfname, "bcrypt") == 0) {
		ಯದಿ ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			ಗಚ್ಛ out;
		ಯದಿ (rounds > MAX_KDF_ROUNDS) {
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		ಯದಿ (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    ಕೀಲಿ, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	ಯದಿ (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}

	/* decrypt private portion of key */
	ಯದಿ ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, ಕೀಲಿ, keylen,
	    ಕೀಲಿ + keylen, ivlen, 0)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		ಯದಿ (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		ಗಚ್ಛ out;
	/* there should be no trailing data */
	ಯದಿ (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}

	/* check check bytes */
	ಯದಿ ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (check1 != check2) {
		r = SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
		ಗಚ್ಛ out;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = ರಿಕ್ತ;
	*pubkeyp = pubkey;
	pubkey = ರಿಕ್ತ;
	r = 0;
 out:
	cipher_free(ciphercontext);
	ಮುಕ್ತ(ciphername);
	ಮುಕ್ತ(kdfname);
	sshkey_free(pubkey);
	ಯದಿ (salt != ರಿಕ್ತ) {
		explicit_bzero(salt, slen);
		ಮುಕ್ತ(salt);
	}
	ಯದಿ (ಕೀಲಿ != ರಿಕ್ತ) {
		explicit_bzero(ಕೀಲಿ, keylen + ivlen);
		ಮುಕ್ತ(ಕೀಲಿ);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshkey_parse_private2(ಸಂರಚನಾ sshbuf *blob, ಪೂರ್ಣಾಙ್ಕ type, ಧ್ರುವ ವರ್ಣ *passphrase,
    ಸಂರಚನಾ sshkey **keyp, ವರ್ಣ **commentp)
{
	ವರ್ಣ *comment = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ sshbuf *decoded = ರಿಕ್ತ, *decrypted = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ, *pubkey = ರಿಕ್ತ;

	ಯದಿ (keyp != ರಿಕ್ತ)
		*keyp = ರಿಕ್ತ;
	ಯದಿ (commentp != ರಿಕ್ತ)
		*commentp = ರಿಕ್ತ;

	/* Undo base64 encoding and decrypt the private section */
	ಯದಿ ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ (type != ಕೀಲಿ_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
		ಗಚ್ಛ out;
	}

	/* Load the private key and comment */
	ಯದಿ ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;

	/* Check deterministic padding after private section */
	ಯದಿ ((r = private2_check_padding(decrypted)) != 0)
		ಗಚ್ಛ out;

	/* Check that the public key in the envelope matches the private key */
	ಯದಿ (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}

	/* success */
	r = 0;
	ಯದಿ (keyp != ರಿಕ್ತ) {
		*keyp = k;
		k = ರಿಕ್ತ;
	}
	ಯದಿ (commentp != ರಿಕ್ತ) {
		*commentp = comment;
		comment = ರಿಕ್ತ;
	}
 out:
	ಮುಕ್ತ(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshkey_parse_private2_pubkey(ಸಂರಚನಾ sshbuf *blob, ಪೂರ್ಣಾಙ್ಕ type,
    ಸಂರಚನಾ sshkey **keyp)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ sshbuf *decoded = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *pubkey = ರಿಕ್ತ;
	u_int nkeys = 0;

	ಯದಿ (keyp != ರಿಕ್ತ)
		*keyp = ರಿಕ್ತ;

	ಯದಿ ((r = private2_uudecode(blob, &decoded)) != 0)
		ಗಚ್ಛ out;
	/* parse public key from unencrypted envelope */
	ಯದಿ ((r = sshbuf_consume(decoded, ಪರಿಮಾಣ(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}

	/* Parse the public key */
	ಯದಿ ((r = sshkey_froms(decoded, &pubkey)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ (type != ಕೀಲಿ_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
		ಗಚ್ಛ out;
	}

	/* success */
	r = 0;
	ಯದಿ (keyp != ರಿಕ್ತ) {
		*keyp = pubkey;
		pubkey = ರಿಕ್ತ;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	ಪ್ರತ್ಯಾಗಮ r;
}

#ifdef WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshkey_private_to_blob_pem_pkcs8(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *buf,
    ಪೂರ್ಣಾಙ್ಕ format, ಧ್ರುವ ವರ್ಣ *_passphrase, ಧ್ರುವ ವರ್ಣ *comment)
{
	ಪೂರ್ಣಾಙ್ಕ was_shielded = sshkey_is_shielded(ಕೀಲಿ);
	ಪೂರ್ಣಾಙ್ಕ success, r;
	ಪೂರ್ಣಾಙ್ಕ blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : ರಿಕ್ತ;
	ಧ್ರುವ EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : ರಿಕ್ತ;
	ವರ್ಣ *bptr;
	BIO *bio = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *blob;
	EVP_PKEY *pkey = ರಿಕ್ತ;

	ಯದಿ (len > 0 && len <= 4)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_PASSPHRASE_TOO_SHORT;
	ಯದಿ ((blob = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((bio = BIO_new(BIO_s_mem())) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshkey_unshield_private(ಕೀಲಿ)) != 0)
		ಗಚ್ಛ out;

	ವಿಕಲ್ಪ (ಕೀಲಿ->type) {
	ಪಕ್ಷ ಕೀಲಿ_ECDSA:
		ಯದಿ (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivate_ಕೀಲಿ(bio,
			    EVP_PKEY_get0_EC_ಕೀಲಿ(ಕೀಲಿ->pkey),
			    cipher, passphrase, len, ರಿಕ್ತ, ರಿಕ್ತ);
		} ಅನ್ಯಥಾ {
			pkey = ಕೀಲಿ->pkey;
			EVP_PKEY_up_ref(ಕೀಲಿ->pkey);
			success = 1;
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ ಕೀಲಿ_RSA:
		ಯದಿ (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivate_ಕೀಲಿ(bio,
			    EVP_PKEY_get0_RSA(ಕೀಲಿ->pkey),
			    cipher, passphrase, len, ರಿಕ್ತ, ರಿಕ್ತ);
		} ಅನ್ಯಥಾ {
			pkey = ಕೀಲಿ->pkey;
			EVP_PKEY_up_ref(ಕೀಲಿ->pkey);
			success = 1;
		}
		ಭಙ್ಗ;
#ifdef OPENSSL_HAS_ED25519
	ಪಕ್ಷ ಕೀಲಿ_ED25519:
		ಯದಿ (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		} ಅನ್ಯಥಾ {
			pkey = EVP_PKEY_new_raw_private_ಕೀಲಿ(EVP_PKEY_ED25519,
			    ರಿಕ್ತ, ಕೀಲಿ->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != ರಿಕ್ತ;
		}
		ಭಙ್ಗ;
#endif
	ಸ್ವಭಾವ:
		success = 0;
		ಭಙ್ಗ;
	}
	ಯದಿ (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ (format == SSHKEY_PRIVATE_PKCS8) {
		ಯದಿ ((success = PEM_write_bio_Private_ಕೀಲಿ(bio, pkey, cipher,
		    passphrase, len, ರಿಕ್ತ, ರಿಕ್ತ)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಗಚ್ಛ out;
		}
	}
	ಯದಿ ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put(blob, bptr, blen)) != 0)
		ಗಚ್ಛ out;
	r = 0;
 out:
	ಯದಿ (was_shielded)
		r = sshkey_shield_private(ಕೀಲಿ);
	ಯದಿ (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	ಪ್ರತ್ಯಾಗಮ r;
}
#endif /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
ಪೂರ್ಣಾಙ್ಕ
sshkey_private_to_fileblob(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *blob,
    ಧ್ರುವ ವರ್ಣ *passphrase, ಧ್ರುವ ವರ್ಣ *comment,
    ಪೂರ್ಣಾಙ್ಕ format, ಧ್ರುವ ವರ್ಣ *openssh_format_cipher, ಪೂರ್ಣಾಙ್ಕ openssh_format_rounds)
{
	ವಿಕಲ್ಪ (ಕೀಲಿ->type) {
#ifdef WITH_OPENSSL
	ಪಕ್ಷ ಕೀಲಿ_ECDSA:
	ಪಕ್ಷ ಕೀಲಿ_RSA:
	ಪಕ್ಷ ಕೀಲಿ_ED25519:
		ಭಙ್ಗ; /* see below */
#ಅನ್ಯಥಾ /* WITH_OPENSSL */
	ಪಕ್ಷ ಕೀಲಿ_ED25519:
#endif /* WITH_OPENSSL */
	ಪಕ್ಷ ಕೀಲಿ_ED25519_SK:
#ifdef WITH_OPENSSL
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
#endif /* WITH_OPENSSL */
	ಪಕ್ಷ ಕೀಲಿ_MLDSA44_ED25519:
		ಪ್ರತ್ಯಾಗಮ sshkey_private_to_blob2(ಕೀಲಿ, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	}

#ifdef WITH_OPENSSL
	ವಿಕಲ್ಪ (format) {
	ಪಕ್ಷ SSHKEY_PRIVATE_OPENSSH:
		ಪ್ರತ್ಯಾಗಮ sshkey_private_to_blob2(ಕೀಲಿ, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	ಪಕ್ಷ SSHKEY_PRIVATE_PEM:
	ಪಕ್ಷ SSHKEY_PRIVATE_PKCS8:
		ಪ್ರತ್ಯಾಗಮ sshkey_private_to_blob_pem_pkcs8(ಕೀಲಿ, blob,
		    format, passphrase, comment);
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	}
#endif /* WITH_OPENSSL */
}

#ifdef WITH_OPENSSL
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
translate_libcrypto_error(unsigned long pem_err)
{
	ಪೂರ್ಣಾಙ್ಕ pem_reason = ERR_GET_REASON(pem_err);

	ವಿಕಲ್ಪ (ERR_GET_LIB(pem_err)) {
	ಪಕ್ಷ ERR_LIB_PEM:
		ವಿಕಲ್ಪ (pem_reason) {
		ಪಕ್ಷ PEM_R_BAD_PASSWORD_READ:
#ifdef PEM_R_PROBLEMS_GETTING_PASSWORD
		ಪಕ್ಷ PEM_R_PROBLEMS_GETTING_PASSWORD:
#endif
#ifdef PEM_R_BAD_DECRYPT
		ಪಕ್ಷ PEM_R_BAD_DECRYPT:
#endif
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
		ಸ್ವಭಾವ:
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
		}
	ಪಕ್ಷ ERR_LIB_EVP:
		ವಿಕಲ್ಪ (pem_reason) {
#ifdef EVP_R_BAD_DECRYPT
		ಪಕ್ಷ EVP_R_BAD_DECRYPT:
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
#endif
#ifdef EVP_R_BN_DECODE_ERROR
		ಪಕ್ಷ EVP_R_BN_DECODE_ERROR:
#endif
		ಪಕ್ಷ EVP_R_DECODE_ERROR:
#ifdef EVP_R_PRIVATE_ಕೀಲಿ_DECODE_ERROR
		ಪಕ್ಷ EVP_R_PRIVATE_ಕೀಲಿ_DECODE_ERROR:
#endif
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
		ಸ್ವಭಾವ:
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
		}
	ಪಕ್ಷ ERR_LIB_ASN1:
#ifdef ERR_LIB_OSSL_DECODER
	ಪಕ್ಷ ERR_LIB_OSSL_DECODER:
#endif
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
}

ಸ್ಥಿರ ಶೂನ್ಯ
clear_libcrypto_errors(ಶೂನ್ಯ)
{
	ಯಾವತ್ (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
convert_libcrypto_error(ಶೂನ್ಯ)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	ಯದಿ (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
	ಪ್ರತ್ಯಾಗಮ translate_libcrypto_error(ERR_peek_last_error());
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pem_passphrase_cb(ವರ್ಣ *buf, ಪೂರ್ಣಾಙ್ಕ size, ಪೂರ್ಣಾಙ್ಕ rwflag, ಶೂನ್ಯ *u)
{
	ವರ್ಣ *p = (ವರ್ಣ *)u;
	size_t len;

	ಯದಿ (p == ರಿಕ್ತ || (len = strlen(p)) == 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (size < 0 || len > (size_t)size)
		ಪ್ರತ್ಯಾಗಮ -1;
	memcpy(buf, p, len);
	ಪ್ರತ್ಯಾಗಮ (ಪೂರ್ಣಾಙ್ಕ)len;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshkey_parse_private_pem_fileblob(ಸಂರಚನಾ sshbuf *blob, ಪೂರ್ಣಾಙ್ಕ type,
    ಧ್ರುವ ವರ್ಣ *passphrase, ಸಂರಚನಾ sshkey **keyp)
{
	EVP_PKEY *pk = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *prv = ರಿಕ್ತ;
	BIO *bio = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;
	RSA *rsa = ರಿಕ್ತ;
	EC_ಕೀಲಿ *ecdsa = ರಿಕ್ತ;

	ಯದಿ (keyp != ರಿಕ್ತ)
		*keyp = ರಿಕ್ತ;

	ಯದಿ ((bio = BIO_new(BIO_s_mem())) == ರಿಕ್ತ || sshbuf_len(blob) > INT_MAX)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (ಪೂರ್ಣಾಙ್ಕ)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}

	clear_libcrypto_errors();
	ಯದಿ ((pk = PEM_read_bio_Private_ಕೀಲಿ(bio, ರಿಕ್ತ, pem_passphrase_cb,
	    (ವರ್ಣ *)passphrase)) == ರಿಕ್ತ) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		ಯದಿ (passphrase != ರಿಕ್ತ && *passphrase != '\0')
			r = SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
		ಅನ್ಯಥಾ
			r = convert_libcrypto_error();
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == ಕೀಲಿ_UNSPEC || type == ಕೀಲಿ_RSA)) {
		ಯದಿ ((prv = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((rsa = EVP_PKEY_get1_RSA(pk)) == ರಿಕ್ತ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಗಚ್ಛ out;
		}
		prv->type = ಕೀಲಿ_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#endif
		ಯದಿ (RSA_blinding_on(rsa, ರಿಕ್ತ) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಗಚ್ಛ out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		ಯದಿ ((r = sshkey_check_rsa_length(prv, 0)) != 0)
			ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ ಯದಿ (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == ಕೀಲಿ_UNSPEC || type == ಕೀಲಿ_ECDSA)) {
		ಯದಿ ((prv = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_ಕೀಲಿ(pk)) == ರಿಕ್ತ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಗಚ್ಛ out;
		}
		prv->type = ಕೀಲಿ_ECDSA;
		ಯದಿ (sshkey_curve_nid_to_name(prv->ecdsa_nid) == ರಿಕ್ತ ||
		    sshkey_ec_validate_public(EC_ಕೀಲಿ_get0_group(ecdsa),
		    EC_ಕೀಲಿ_get0_public_ಕೀಲಿ(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#ifdef DEBUG_PK
		ಯದಿ (prv != ರಿಕ್ತ && prv->pkey != ರಿಕ್ತ)
			sshkey_dump_ec_ಕೀಲಿ(EVP_PKEY_get0_EC_ಕೀಲಿ(prv->pkey));
#endif
#ifdef OPENSSL_HAS_ED25519
	} ಅನ್ಯಥಾ ಯದಿ (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == ಕೀಲಿ_UNSPEC || type == ಕೀಲಿ_ED25519)) {
		size_t len;

		ಯದಿ ((prv = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ ||
		    (prv->ed25519_sk = calloc(1, ED25519_SK_SZ)) == ರಿಕ್ತ ||
		    (prv->ed25519_pk = calloc(1, ED25519_PK_SZ)) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		prv->type = ಕೀಲಿ_ED25519;
		len = ED25519_PK_SZ;
		ಯದಿ (!EVP_PKEY_get_raw_public_ಕೀಲಿ(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಗಚ್ಛ out;
		}
		ಯದಿ (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		ಯದಿ (!EVP_PKEY_get_raw_private_ಕೀಲಿ(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಗಚ್ಛ out;
		}
		ಯದಿ (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		/* Append the public key to our private key */
		memcpy(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#ifdef DEBUG_PK
		sshbuf_dump_data(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#endif
#endif /* OPENSSL_HAS_ED25519 */
	} ಅನ್ಯಥಾ {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	r = 0;
	ಯದಿ (keyp != ರಿಕ್ತ) {
		*keyp = prv;
		prv = ರಿಕ್ತ;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_ಕೀಲಿ_free(ecdsa);
	sshkey_free(prv);
	ಪ್ರತ್ಯಾಗಮ r;
}
#endif /* WITH_OPENSSL */

ಪೂರ್ಣಾಙ್ಕ
sshkey_parse_private_fileblob_type(ಸಂರಚನಾ sshbuf *blob, ಪೂರ್ಣಾಙ್ಕ type,
    ಧ್ರುವ ವರ್ಣ *passphrase, ಸಂರಚನಾ sshkey **keyp, ವರ್ಣ **commentp)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (keyp != ರಿಕ್ತ)
		*keyp = ರಿಕ್ತ;
	ಯದಿ (commentp != ರಿಕ್ತ)
		*commentp = ರಿಕ್ತ;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	ಯದಿ (r != SSH_ERR_INVALID_FORMAT)
		ಪ್ರತ್ಯಾಗಮ r;
#ifdef WITH_OPENSSL
	ಪ್ರತ್ಯಾಗಮ sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#ಅನ್ಯಥಾ
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_parse_private_fileblob(ಸಂರಚನಾ sshbuf *buffer, ಧ್ರುವ ವರ್ಣ *passphrase,
    ಸಂರಚನಾ sshkey **keyp, ವರ್ಣ **commentp)
{
	ಯದಿ (keyp != ರಿಕ್ತ)
		*keyp = ರಿಕ್ತ;
	ಯದಿ (commentp != ರಿಕ್ತ)
		*commentp = ರಿಕ್ತ;

	ಪ್ರತ್ಯಾಗಮ sshkey_parse_private_fileblob_type(buffer, ಕೀಲಿ_UNSPEC,
	    passphrase, keyp, commentp);
}

ಶೂನ್ಯ
sshkey_sig_details_free(ಸಂರಚನಾ sshkey_sig_details *details)
{
	freezero(details, ಪರಿಮಾಣ(*details));
}

ಪೂರ್ಣಾಙ್ಕ
sshkey_parse_pubkey_from_private_fileblob_type(ಸಂರಚನಾ sshbuf *blob, ಪೂರ್ಣಾಙ್ಕ type,
    ಸಂರಚನಾ sshkey **pubkeyp)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (pubkeyp != ರಿಕ್ತ)
		*pubkeyp = ರಿಕ್ತ;
	/* only new-format private keys bundle a public key inside */
	ಯದಿ ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ 0;
}
