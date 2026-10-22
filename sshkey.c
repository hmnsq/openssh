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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/mman.h>
#അന്തര്ഭാവ <netinet/in.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/evp.h>
#അന്തര്ഭാവ <openssl/err.h>
#അന്തര്ഭാവ <openssl/pem.h>
#endif

#അന്തര്ഭാവ "crypto_api.h"

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <resolv.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <util.h>

#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "cipher.h"
#അന്തര്ഭാവ "digest.h"
#define SSHKEY_INTERNAL
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "ssh-sk.h"
#അന്തര്ഭാവ "ssh-pkcs11.h"

#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#define MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define MARK_END		"-----END OPENSSH PRIVATE KEY-----\n"
#define MARK_BEGIN_LEN		(വലുപ്പം(MARK_BEGIN) - 1)
#define MARK_END_LEN		(വലുപ്പം(MARK_END) - 1)
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

സ്ഥിതം പൂർണ്ണസംഖ്യ sshkey_from_blob_internal(ഘടന sshbuf *buf,
    ഘടന sshkey **keyp, പൂർണ്ണസംഖ്യ allow_cert,
    സ്ഥിരം അക്ഷരം *alg_allowlist, സ്ഥിരം അക്ഷരം *ca_sigalg_allowlist);

/* Supported key types */
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_ed25519_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_ed25519_cert_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_ed25519_sk_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_mldsa44_ed25519_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#ifdef WITH_OPENSSL
# ifdef ENABLE_SK
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_sk_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_sk_cert_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_nistp256_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_nistp384_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_nistp521_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_rsa_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_rsa_cert_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_rsa_sha256_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_rsa_sha256_cert_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_rsa_sha512_impl;
ബാഹ്യ സ്ഥിരം ഘടന sshkey_impl sshkey_rsa_sha512_cert_impl;
#endif /* WITH_OPENSSL */

സ്ഥിരം ഘടന sshkey_impl * സ്ഥിരം keyimpls[] = {
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
	ശൂന്യ
};

സ്ഥിതം സ്ഥിരം ഘടന sshkey_impl *
sshkey_impl_from_type(പൂർണ്ണസംഖ്യ type)
{
	പൂർണ്ണസംഖ്യ i;

	വേണ്ടി (i = 0; keyimpls[i] != ശൂന്യ; i++) {
		എങ്കിൽ (keyimpls[i]->type == type)
			തിരികെ keyimpls[i];
	}
	തിരികെ ശൂന്യ;
}

സ്ഥിതം സ്ഥിരം ഘടന sshkey_impl *
sshkey_impl_from_type_nid(പൂർണ്ണസംഖ്യ type, പൂർണ്ണസംഖ്യ nid)
{
	പൂർണ്ണസംഖ്യ i;

	വേണ്ടി (i = 0; keyimpls[i] != ശൂന്യ; i++) {
		എങ്കിൽ (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			തിരികെ keyimpls[i];
	}
	തിരികെ ശൂന്യ;
}

സ്ഥിതം സ്ഥിരം ഘടന sshkey_impl *
sshkey_impl_from_താക്കോൽ(സ്ഥിരം ഘടന sshkey *k)
{
	എങ്കിൽ (k == ശൂന്യ)
		തിരികെ ശൂന്യ;
	തിരികെ sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

സ്ഥിരം അക്ഷരം *
sshkey_type(സ്ഥിരം ഘടന sshkey *k)
{
	സ്ഥിരം ഘടന sshkey_impl *impl;

	എങ്കിൽ ((impl = sshkey_impl_from_താക്കോൽ(k)) == ശൂന്യ)
		തിരികെ "unknown";
	തിരികെ impl->shortname;
}

സ്ഥിതം സ്ഥിരം അക്ഷരം *
sshkey_ssh_name_from_type_nid(പൂർണ്ണസംഖ്യ type, പൂർണ്ണസംഖ്യ nid)
{
	സ്ഥിരം ഘടന sshkey_impl *impl;

	എങ്കിൽ ((impl = sshkey_impl_from_type_nid(type, nid)) == ശൂന്യ)
		തിരികെ "ssh-unknown";
	തിരികെ impl->name;
}

പൂർണ്ണസംഖ്യ
sshkey_type_is_cert(പൂർണ്ണസംഖ്യ type)
{
	സ്ഥിരം ഘടന sshkey_impl *impl;

	എങ്കിൽ ((impl = sshkey_impl_from_type(type)) == ശൂന്യ)
		തിരികെ 0;
	തിരികെ impl->cert;
}

സ്ഥിരം അക്ഷരം *
sshkey_ssh_name(സ്ഥിരം ഘടന sshkey *k)
{
	തിരികെ sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

സ്ഥിരം അക്ഷരം *
sshkey_ssh_name_plain(സ്ഥിരം ഘടന sshkey *k)
{
	തിരികെ sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
type_from_name(സ്ഥിരം അക്ഷരം *name, പൂർണ്ണസംഖ്യ allow_short)
{
	പൂർണ്ണസംഖ്യ i;
	സ്ഥിരം ഘടന sshkey_impl *impl;

	വേണ്ടി (i = 0; keyimpls[i] != ശൂന്യ; i++) {
		impl = keyimpls[i];
		എങ്കിൽ (impl->name != ശൂന്യ && strcmp(name, impl->name) == 0)
			തിരികെ impl->type;
		/* Only allow shortname matches for plain key types */
		എങ്കിൽ (allow_short && !impl->cert && impl->shortname != ശൂന്യ &&
		    strcasecmp(impl->shortname, name) == 0)
			തിരികെ impl->type;
	}
	തിരികെ താക്കോൽ_UNSPEC;
}

പൂർണ്ണസംഖ്യ
sshkey_type_from_name(സ്ഥിരം അക്ഷരം *name)
{
	തിരികെ type_from_name(name, 0);
}

പൂർണ്ണസംഖ്യ
sshkey_type_from_shortname(സ്ഥിരം അക്ഷരം *name)
{
	തിരികെ type_from_name(name, 1);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
താക്കോൽ_type_is_ecdsa_variant(പൂർണ്ണസംഖ്യ type)
{
	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ താക്കോൽ_ECDSA:
	അവസ്ഥ താക്കോൽ_ECDSA_CERT:
	അവസ്ഥ താക്കോൽ_ECDSA_SK:
	അവസ്ഥ താക്കോൽ_ECDSA_SK_CERT:
		തിരികെ 1;
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshkey_ecdsa_nid_from_name(സ്ഥിരം അക്ഷരം *name)
{
	പൂർണ്ണസംഖ്യ i;

	വേണ്ടി (i = 0; keyimpls[i] != ശൂന്യ; i++) {
		എങ്കിൽ (!താക്കോൽ_type_is_ecdsa_variant(keyimpls[i]->type))
			തുടരുക;
		എങ്കിൽ (keyimpls[i]->name != ശൂന്യ &&
		    strcmp(name, keyimpls[i]->name) == 0)
			തിരികെ keyimpls[i]->nid;
	}
	തിരികെ -1;
}

പൂർണ്ണസംഖ്യ
sshkey_match_keyname_to_sigalgs(സ്ഥിരം അക്ഷരം *keyname, സ്ഥിരം അക്ഷരം *sigalgs)
{
	പൂർണ്ണസംഖ്യ ktype;

	എങ്കിൽ (sigalgs == ശൂന്യ || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == താക്കോൽ_UNSPEC)
		തിരികെ 0;
	അല്ലെങ്കിൽ എങ്കിൽ (ktype == താക്കോൽ_RSA) {
		തിരികെ match_pattern_list("ssh-rsa", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512", sigalgs, 0) == 1;
	} അല്ലെങ്കിൽ എങ്കിൽ (ktype == താക്കോൽ_RSA_CERT) {
		തിരികെ match_pattern_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} അല്ലെങ്കിൽ എങ്കിൽ (ktype == താക്കോൽ_ECDSA_SK) {
		തിരികെ match_pattern_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} അല്ലെങ്കിൽ എങ്കിൽ (ktype == താക്കോൽ_ECDSA_SK_CERT) {
		തിരികെ match_pattern_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || match_pattern_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} അല്ലെങ്കിൽ
		തിരികെ match_pattern_list(keyname, sigalgs, 0) == 1;
}

അക്ഷരം *
sshkey_alg_list(പൂർണ്ണസംഖ്യ certs_only, പൂർണ്ണസംഖ്യ plain_only, പൂർണ്ണസംഖ്യ include_sigonly, അക്ഷരം sep)
{
	അക്ഷരം *ret = ശൂന്യ;
	size_t i;
	സ്ഥിരം ഘടന sshkey_impl *impl;
	അക്ഷരം sep_str[2] = {sep, '\0'};

	വേണ്ടി (i = 0; keyimpls[i] != ശൂന്യ; i++) {
		impl = keyimpls[i];
		എങ്കിൽ (impl->name == ശൂന്യ)
			തുടരുക;
		എങ്കിൽ (!include_sigonly && impl->sigonly)
			തുടരുക;
		എങ്കിൽ ((certs_only && !impl->cert) || (plain_only && impl->cert))
			തുടരുക;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sshkey_names_valid2(സ്ഥിരം അക്ഷരം *names, പൂർണ്ണസംഖ്യ allow_wildcard, പൂർണ്ണസംഖ്യ plain_only)
{
	അക്ഷരം *s, *cp, *p;
	സ്ഥിരം ഘടന sshkey_impl *impl;
	പൂർണ്ണസംഖ്യ i, type;

	എങ്കിൽ (names == ശൂന്യ || strcmp(names, "") == 0)
		തിരികെ 0;
	എങ്കിൽ ((s = cp = strdup(names)) == ശൂന്യ)
		തിരികെ 0;
	വേണ്ടി ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		എങ്കിൽ (type == താക്കോൽ_UNSPEC) {
			എങ്കിൽ (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = ശൂന്യ;
				വേണ്ടി (i = 0; keyimpls[i] != ശൂന്യ; i++) {
					എങ്കിൽ (match_pattern_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						നിർത്തുക;
					}
				}
				എങ്കിൽ (impl != ശൂന്യ)
					തുടരുക;
			}
			സ്വതന്ത്രം(s);
			തിരികെ 0;
		} അല്ലെങ്കിൽ എങ്കിൽ (plain_only && sshkey_type_is_cert(type)) {
			സ്വതന്ത്രം(s);
			തിരികെ 0;
		}
	}
	സ്വതന്ത്രം(s);
	തിരികെ 1;
}

u_int
sshkey_size(സ്ഥിരം ഘടന sshkey *k)
{
	സ്ഥിരം ഘടന sshkey_impl *impl;

	എങ്കിൽ ((impl = sshkey_impl_from_താക്കോൽ(k)) == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (impl->funcs->size != ശൂന്യ)
		തിരികെ impl->funcs->size(k);
	തിരികെ impl->keybits;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshkey_type_is_valid_ca(പൂർണ്ണസംഖ്യ type)
{
	സ്ഥിരം ഘടന sshkey_impl *impl;

	എങ്കിൽ ((impl = sshkey_impl_from_type(type)) == ശൂന്യ)
		തിരികെ 0;
	/* All non-certificate types may act as CAs */
	തിരികെ !impl->cert;
}

പൂർണ്ണസംഖ്യ
sshkey_is_cert(സ്ഥിരം ഘടന sshkey *k)
{
	എങ്കിൽ (k == ശൂന്യ)
		തിരികെ 0;
	തിരികെ sshkey_type_is_cert(k->type);
}

പൂർണ്ണസംഖ്യ
sshkey_is_sk(സ്ഥിരം ഘടന sshkey *k)
{
	എങ്കിൽ (k == ശൂന്യ)
		തിരികെ 0;
	തിരഞ്ഞെടുപ്പ് (sshkey_type_plain(k->type)) {
	അവസ്ഥ താക്കോൽ_ECDSA_SK:
	അവസ്ഥ താക്കോൽ_ED25519_SK:
		തിരികെ 1;
	സ്ഥിരസ്ഥിതി:
		തിരികെ 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
പൂർണ്ണസംഖ്യ
sshkey_type_plain(പൂർണ്ണസംഖ്യ type)
{
	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ താക്കോൽ_RSA_CERT:
		തിരികെ താക്കോൽ_RSA;
	അവസ്ഥ താക്കോൽ_ECDSA_CERT:
		തിരികെ താക്കോൽ_ECDSA;
	അവസ്ഥ താക്കോൽ_ECDSA_SK_CERT:
		തിരികെ താക്കോൽ_ECDSA_SK;
	അവസ്ഥ താക്കോൽ_ED25519_CERT:
		തിരികെ താക്കോൽ_ED25519;
	അവസ്ഥ താക്കോൽ_MLDSA44_ED25519_CERT:
		തിരികെ താക്കോൽ_MLDSA44_ED25519;
	അവസ്ഥ താക്കോൽ_ED25519_SK_CERT:
		തിരികെ താക്കോൽ_ED25519_SK;
	സ്ഥിരസ്ഥിതി:
		തിരികെ type;
	}
}

/* Return the cert equivalent to a plain key type */
സ്ഥിതം പൂർണ്ണസംഖ്യ
sshkey_type_certified(പൂർണ്ണസംഖ്യ type)
{
	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ താക്കോൽ_RSA:
		തിരികെ താക്കോൽ_RSA_CERT;
	അവസ്ഥ താക്കോൽ_ECDSA:
		തിരികെ താക്കോൽ_ECDSA_CERT;
	അവസ്ഥ താക്കോൽ_ECDSA_SK:
		തിരികെ താക്കോൽ_ECDSA_SK_CERT;
	അവസ്ഥ താക്കോൽ_ED25519:
		തിരികെ താക്കോൽ_ED25519_CERT;
	അവസ്ഥ താക്കോൽ_MLDSA44_ED25519:
		തിരികെ താക്കോൽ_MLDSA44_ED25519_CERT;
	അവസ്ഥ താക്കോൽ_ED25519_SK:
		തിരികെ താക്കോൽ_ED25519_SK_CERT;
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}
}

#ifdef WITH_OPENSSL
സ്ഥിതം സ്ഥിരം EVP_MD *
ssh_digest_to_md(പൂർണ്ണസംഖ്യ hash_alg)
{
	തിരഞ്ഞെടുപ്പ് (hash_alg) {
	അവസ്ഥ SSH_DIGEST_SHA1:
		തിരികെ EVP_sha1();
	അവസ്ഥ SSH_DIGEST_SHA256:
		തിരികെ EVP_sha256();
	അവസ്ഥ SSH_DIGEST_SHA384:
		തിരികെ EVP_sha384();
	അവസ്ഥ SSH_DIGEST_SHA512:
		തിരികെ EVP_sha512();
	}
	തിരികെ ശൂന്യ;
}

പൂർണ്ണസംഖ്യ
sshkey_pkey_digest_sign(EVP_PKEY *pkey, പൂർണ്ണസംഖ്യ hash_alg, u_char **sigp,
    size_t *lenp, സ്ഥിരം u_char *data, size_t datalen)
{
	EVP_MD_CTX *ctx = ശൂന്യ;
	u_char *sig = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret;
	size_t slen;
	സ്ഥിരം EVP_MD *evpmd;

	*sigp = ശൂന്യ;
	*lenp = 0;

	slen = EVP_PKEY_size(pkey);
	എങ്കിൽ (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_to_md(hash_alg)) == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	എങ്കിൽ ((sig = malloc(slen)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;

	എങ്കിൽ ((ctx = EVP_MD_CTX_new()) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (EVP_DigestSignInit(ctx, ശൂന്യ, evpmd, ശൂന്യ, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, data, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = ശൂന്യ;
	ret = 0;

 out:
	EVP_MD_CTX_free(ctx);
	സ്വതന്ത്രം(sig);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sshkey_pkey_digest_verify(EVP_PKEY *pkey, പൂർണ്ണസംഖ്യ hash_alg, സ്ഥിരം u_char *data,
    size_t datalen, u_char *sigbuf, size_t siglen)
{
	EVP_MD_CTX *ctx = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret = SSH_ERR_INTERNAL_ERROR;
	സ്ഥിരം EVP_MD *evpmd;

	എങ്കിൽ ((evpmd = ssh_digest_to_md(hash_alg)) == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((ctx = EVP_MD_CTX_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ (EVP_DigestVerifyInit(ctx, ശൂന്യ, evpmd, ശൂന്യ, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	തിരഞ്ഞെടുപ്പ് (EVP_DigestVerify(ctx, sigbuf, siglen, data, datalen)) {
	അവസ്ഥ 1:
		ret = 0;
		നിർത്തുക;
	അവസ്ഥ 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		നിർത്തുക;
	}

 out:
	EVP_MD_CTX_free(ctx);
	തിരികെ ret;
}

/* XXX: these are really begging for a table-driven approach */
പൂർണ്ണസംഖ്യ
sshkey_curve_name_to_nid(സ്ഥിരം അക്ഷരം *name)
{
	എങ്കിൽ (strcmp(name, "nistp256") == 0)
		തിരികെ NID_X9_62_prime256v1;
	അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "nistp384") == 0)
		തിരികെ NID_secp384r1;
	അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "nistp521") == 0)
		തിരികെ NID_secp521r1;
	അല്ലെങ്കിൽ
		തിരികെ -1;
}

u_int
sshkey_curve_nid_to_bits(പൂർണ്ണസംഖ്യ nid)
{
	തിരഞ്ഞെടുപ്പ് (nid) {
	അവസ്ഥ NID_X9_62_prime256v1:
		തിരികെ 256;
	അവസ്ഥ NID_secp384r1:
		തിരികെ 384;
	അവസ്ഥ NID_secp521r1:
		തിരികെ 521;
	സ്ഥിരസ്ഥിതി:
		തിരികെ 0;
	}
}

പൂർണ്ണസംഖ്യ
sshkey_ecdsa_bits_to_nid(പൂർണ്ണസംഖ്യ bits)
{
	തിരഞ്ഞെടുപ്പ് (bits) {
	അവസ്ഥ 256:
		തിരികെ NID_X9_62_prime256v1;
	അവസ്ഥ 384:
		തിരികെ NID_secp384r1;
	അവസ്ഥ 521:
		തിരികെ NID_secp521r1;
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}
}

സ്ഥിരം അക്ഷരം *
sshkey_curve_nid_to_name(പൂർണ്ണസംഖ്യ nid)
{
	തിരഞ്ഞെടുപ്പ് (nid) {
	അവസ്ഥ NID_X9_62_prime256v1:
		തിരികെ "nistp256";
	അവസ്ഥ NID_secp384r1:
		തിരികെ "nistp384";
	അവസ്ഥ NID_secp521r1:
		തിരികെ "nistp521";
	സ്ഥിരസ്ഥിതി:
		തിരികെ ശൂന്യ;
	}
}

പൂർണ്ണസംഖ്യ
sshkey_ec_nid_to_hash_alg(പൂർണ്ണസംഖ്യ nid)
{
	പൂർണ്ണസംഖ്യ kbits = sshkey_curve_nid_to_bits(nid);

	എങ്കിൽ (kbits <= 0)
		തിരികെ -1;

	/* RFC5656 section 6.2.1 */
	എങ്കിൽ (kbits <= 256)
		തിരികെ SSH_DIGEST_SHA256;
	അല്ലെങ്കിൽ എങ്കിൽ (kbits <= 384)
		തിരികെ SSH_DIGEST_SHA384;
	അല്ലെങ്കിൽ
		തിരികെ SSH_DIGEST_SHA512;
}
#endif /* WITH_OPENSSL */

സ്ഥിതം ശൂന്യം
cert_free(ഘടന sshkey_cert *cert)
{
	u_int i;

	എങ്കിൽ (cert == ശൂന്യ)
		തിരികെ;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	സ്വതന്ത്രം(cert->താക്കോൽ_id);
	വേണ്ടി (i = 0; i < cert->nprincipals; i++)
		സ്വതന്ത്രം(cert->principals[i]);
	സ്വതന്ത്രം(cert->principals);
	sshkey_free(cert->signature_താക്കോൽ);
	സ്വതന്ത്രം(cert->signature_type);
	freezero(cert, വലുപ്പം(*cert));
}

സ്ഥിതം ഘടന sshkey_cert *
cert_new(ശൂന്യം)
{
	ഘടന sshkey_cert *cert;

	എങ്കിൽ ((cert = calloc(1, വലുപ്പം(*cert))) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	എങ്കിൽ ((cert->certblob = sshbuf_new()) == ശൂന്യ ||
	    (cert->critical = sshbuf_new()) == ശൂന്യ ||
	    (cert->extensions = sshbuf_new()) == ശൂന്യ) {
		cert_free(cert);
		തിരികെ ശൂന്യ;
	}
	cert->താക്കോൽ_id = ശൂന്യ;
	cert->principals = ശൂന്യ;
	cert->signature_താക്കോൽ = ശൂന്യ;
	cert->signature_type = ശൂന്യ;
	തിരികെ cert;
}

ഘടന sshkey *
sshkey_new(പൂർണ്ണസംഖ്യ type)
{
	ഘടന sshkey *k;
	സ്ഥിരം ഘടന sshkey_impl *impl = ശൂന്യ;

	എങ്കിൽ (type != താക്കോൽ_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == ശൂന്യ)
		തിരികെ ശൂന്യ;

	/* All non-certificate types may act as CAs */
	എങ്കിൽ ((k = calloc(1, വലുപ്പം(*k))) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	k->type = type;
	k->ecdsa_nid = -1;
	എങ്കിൽ (impl != ശൂന്യ && impl->funcs->alloc != ശൂന്യ) {
		എങ്കിൽ (impl->funcs->alloc(k) != 0) {
			സ്വതന്ത്രം(k);
			തിരികെ ശൂന്യ;
		}
	}
	എങ്കിൽ (sshkey_is_cert(k)) {
		എങ്കിൽ ((k->cert = cert_new()) == ശൂന്യ) {
			sshkey_free(k);
			തിരികെ ശൂന്യ;
		}
	}

	തിരികെ k;
}

/* Frees common FIDO fields */
ശൂന്യം
sshkey_sk_cleanup(ഘടന sshkey *k)
{
	സ്വതന്ത്രം(k->sk_application);
	sshbuf_free(k->sk_താക്കോൽ_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = ശൂന്യ;
	k->sk_താക്കോൽ_handle = k->sk_reserved = ശൂന്യ;
}

#എങ്കിൽ defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#അല്ലെങ്കിലെങ്കിൽ defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#അല്ലെങ്കിൽ
# define PREKEY_MMAP_FLAG	0
#endif

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshkey_prekey_alloc(u_char **prekeyp, size_t len)
{
#എങ്കിൽ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = ശൂന്യ;
	എങ്കിൽ ((prekey = mmap(ശൂന്യ, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		തിരികെ SSH_ERR_SYSTEM_ERROR;
#എങ്കിൽ defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(ശൂന്യം)madvise(prekey, len, MADV_DONTDUMP);
#endif
	*prekeyp = prekey;
#അല്ലെങ്കിൽ
	*prekeyp = calloc(1, len);
#endif /* HAVE_MMAP et al */
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
sshkey_prekey_free(ശൂന്യം *prekey, size_t len)
{
#എങ്കിൽ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	എങ്കിൽ (prekey == ശൂന്യ)
		തിരികെ;
	munmap(prekey, len);
#അല്ലെങ്കിൽ
	സ്വതന്ത്രം(prekey);
#endif /* HAVE_MMAP et al */
}

സ്ഥിതം ശൂന്യം
sshkey_free_contents(ഘടന sshkey *k)
{
	സ്ഥിരം ഘടന sshkey_impl *impl;

	എങ്കിൽ (k == ശൂന്യ)
		തിരികെ;
	എങ്കിൽ ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_താക്കോൽ_free(k);
	എങ്കിൽ ((impl = sshkey_impl_from_type(k->type)) != ശൂന്യ &&
	    impl->funcs->cleanup != ശൂന്യ)
		impl->funcs->cleanup(k);
	എങ്കിൽ (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_private, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

ശൂന്യം
sshkey_free(ഘടന sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, വലുപ്പം(*k));
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
cert_compare(ഘടന sshkey_cert *a, ഘടന sshkey_cert *b)
{
	എങ്കിൽ (a == ശൂന്യ && b == ശൂന്യ)
		തിരികെ 1;
	എങ്കിൽ (a == ശൂന്യ || b == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		തിരികെ 0;
	എങ്കിൽ (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		തിരികെ 0;
	തിരികെ 1;
}

/* Compares FIDO-specific pubkey fields only */
പൂർണ്ണസംഖ്യ
sshkey_sk_fields_equal(സ്ഥിരം ഘടന sshkey *a, സ്ഥിരം ഘടന sshkey *b)
{
	എങ്കിൽ (a->sk_application == ശൂന്യ || b->sk_application == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (strcmp(a->sk_application, b->sk_application) != 0)
		തിരികെ 0;
	തിരികെ 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
പൂർണ്ണസംഖ്യ
sshkey_equal_public(സ്ഥിരം ഘടന sshkey *a, സ്ഥിരം ഘടന sshkey *b)
{
	സ്ഥിരം ഘടന sshkey_impl *impl;

	എങ്കിൽ (a == ശൂന്യ || b == ശൂന്യ ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		തിരികെ 0;
	എങ്കിൽ ((impl = sshkey_impl_from_type(a->type)) == ശൂന്യ)
		തിരികെ 0;
	തിരികെ impl->funcs->equal(a, b);
}

പൂർണ്ണസംഖ്യ
sshkey_equal(സ്ഥിരം ഘടന sshkey *a, സ്ഥിരം ഘടന sshkey *b)
{
	എങ്കിൽ (a == ശൂന്യ || b == ശൂന്യ || a->type != b->type)
		തിരികെ 0;
	എങ്കിൽ (sshkey_is_cert(a)) {
		എങ്കിൽ (!cert_compare(a->cert, b->cert))
			തിരികെ 0;
	}
	തിരികെ sshkey_equal_public(a, b);
}


/* Serialise common FIDO key parts */
പൂർണ്ണസംഖ്യ
sshkey_serialize_sk(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_put_cstring(b, താക്കോൽ->sk_application)) != 0)
		തിരികെ r;

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
to_blob_buf(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b, പൂർണ്ണസംഖ്യ force_plain,
  എണ്ണൽ sshkey_serialize_rep opts)
{
	പൂർണ്ണസംഖ്യ type, ret = SSH_ERR_INTERNAL_ERROR;
	സ്ഥിരം അക്ഷരം *typename;
	സ്ഥിരം ഘടന sshkey_impl *impl;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	type = force_plain ? sshkey_type_plain(താക്കോൽ->type) : താക്കോൽ->type;

	എങ്കിൽ (sshkey_type_is_cert(type)) {
		എങ്കിൽ (താക്കോൽ->cert == ശൂന്യ)
			തിരികെ SSH_ERR_EXPECTED_CERT;
		എങ്കിൽ (sshbuf_len(താക്കോൽ->cert->certblob) == 0)
			തിരികെ SSH_ERR_താക്കോൽ_LACKS_CERTBLOB;
		/* Use the existing blob */
		എങ്കിൽ ((ret = sshbuf_putb(b, താക്കോൽ->cert->certblob)) != 0)
			തിരികെ ret;
		തിരികെ 0;
	}
	എങ്കിൽ ((impl = sshkey_impl_from_type(type)) == ശൂന്യ)
		തിരികെ SSH_ERR_താക്കോൽ_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, താക്കോൽ->ecdsa_nid);
	എങ്കിൽ ((ret = sshbuf_put_cstring(b, typename)) != 0)
		തിരികെ ret;
	തിരികെ impl->funcs->serialize_public(താക്കോൽ, b, opts);
}

പൂർണ്ണസംഖ്യ
sshkey_putb(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b)
{
	തിരികെ to_blob_buf(താക്കോൽ, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshkey_puts_opts_internal(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b,
    എണ്ണൽ sshkey_serialize_rep opts, പൂർണ്ണസംഖ്യ force_plain)
{
	ഘടന sshbuf *tmp;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((tmp = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	r = to_blob_buf(താക്കോൽ, tmp, force_plain, opts);
	എങ്കിൽ (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshkey_puts(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b)
{
	തിരികെ sshkey_puts_opts_internal(താക്കോൽ, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

പൂർണ്ണസംഖ്യ
sshkey_putb_plain(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b)
{
	തിരികെ to_blob_buf(താക്കോൽ, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

പൂർണ്ണസംഖ്യ
sshkey_puts_plain(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b)
{
	തിരികെ sshkey_puts_opts_internal(താക്കോൽ, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
to_blob(സ്ഥിരം ഘടന sshkey *താക്കോൽ, u_char **blobp, size_t *lenp, പൂർണ്ണസംഖ്യ force_plain,
    എണ്ണൽ sshkey_serialize_rep opts)
{
	പൂർണ്ണസംഖ്യ ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;
	ഘടന sshbuf *b = ശൂന്യ;

	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	എങ്കിൽ (blobp != ശൂന്യ)
		*blobp = ശൂന്യ;
	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((ret = to_blob_buf(താക്കോൽ, b, force_plain, opts)) != 0)
		പോകുക out;
	len = sshbuf_len(b);
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = len;
	എങ്കിൽ (blobp != ശൂന്യ) {
		എങ്കിൽ ((*blobp = malloc(len)) == ശൂന്യ) {
			ret = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		memcpy(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 out:
	sshbuf_free(b);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sshkey_to_blob(സ്ഥിരം ഘടന sshkey *താക്കോൽ, u_char **blobp, size_t *lenp)
{
	തിരികെ to_blob(താക്കോൽ, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

പൂർണ്ണസംഖ്യ
sshkey_plain_to_blob(സ്ഥിരം ഘടന sshkey *താക്കോൽ, u_char **blobp, size_t *lenp)
{
	തിരികെ to_blob(താക്കോൽ, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

പൂർണ്ണസംഖ്യ
sshkey_fingerprint_raw(സ്ഥിരം ഘടന sshkey *k, പൂർണ്ണസംഖ്യ dgst_alg,
    u_char **retp, size_t *lenp)
{
	u_char *blob = ശൂന്യ, *ret = ശൂന്യ;
	size_t blob_len = 0;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (retp != ശൂന്യ)
		*retp = ശൂന്യ;
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	എങ്കിൽ (ssh_digest_bytes(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	എങ്കിൽ ((r = to_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		പോകുക out;
	എങ്കിൽ ((ret = calloc(1, SSH_DIGEST_MAX_LENGTH)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = ssh_digest_memory(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_LENGTH)) != 0)
		പോകുക out;
	/* success */
	എങ്കിൽ (retp != ശൂന്യ) {
		*retp = ret;
		ret = ശൂന്യ;
	}
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = ssh_digest_bytes(dgst_alg);
	r = 0;
 out:
	സ്വതന്ത്രം(ret);
	എങ്കിൽ (blob != ശൂന്യ)
		freezero(blob, blob_len);
	തിരികെ r;
}

സ്ഥിതം അക്ഷരം *
fingerprint_b64(സ്ഥിരം അക്ഷരം *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	അക്ഷരം *ret;
	size_t plen = strlen(alg) + 1;
	size_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	എങ്കിൽ (dgst_raw_len > 65536 || (ret = calloc(1, rlen)) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	എങ്കിൽ (dgst_raw_len == 0)
		തിരികെ ret;
	എങ്കിൽ (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		തിരികെ ശൂന്യ;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	തിരികെ ret;
}

സ്ഥിതം അക്ഷരം *
fingerprint_hex(സ്ഥിരം അക്ഷരം *alg, u_char *dgst_raw, size_t dgst_raw_len)
{
	അക്ഷരം *retval, hex[5];
	size_t i, rlen = dgst_raw_len * 3 + strlen(alg) + 2;

	എങ്കിൽ (dgst_raw_len > 65536 || (retval = calloc(1, rlen)) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	വേണ്ടി (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, വലുപ്പം(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	തിരികെ retval;
}

സ്ഥിതം അക്ഷരം *
fingerprint_bubblebabble(u_char *dgst_raw, size_t dgst_raw_len)
{
	അക്ഷരം vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	അക്ഷരം consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, rounds, seed = 1;
	അക്ഷരം *retval;

	rounds = (dgst_raw_len / 2) + 1;
	എങ്കിൽ ((retval = calloc(rounds, 6)) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	retval[j++] = 'x';
	വേണ്ടി (i = 0; i < rounds; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		എങ്കിൽ ((i + 1 < rounds) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			എങ്കിൽ ((i + 1) < rounds) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} അല്ലെങ്കിൽ {
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
	തിരികെ retval;
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
സ്ഥിതം അക്ഷരം *
fingerprint_randomart(സ്ഥിരം അക്ഷരം *alg, u_char *dgst_raw, size_t dgst_raw_len,
    സ്ഥിരം ഘടന sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	അക്ഷരം	*augmentation_string = " .o+=*BOX@%&#/^SE";
	അക്ഷരം	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 field[FLDSIZE_X][FLDSIZE_Y];
	size_t	 i, tlen, hlen;
	u_int	 b;
	പൂർണ്ണസംഖ്യ	 x, y, r;
	size_t	 len = strlen(augmentation_string) - 1;

	എങ്കിൽ ((retval = calloc((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == ശൂന്യ)
		തിരികെ ശൂന്യ;

	/* initialize field */
	memset(field, 0, FLDSIZE_X * FLDSIZE_Y * വലുപ്പം(അക്ഷരം));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	വേണ്ടി (i = 0; i < dgst_raw_len; i++) {
		പൂർണ്ണസംഖ്യ നിവേശം;
		/* each byte conveys four 2-bit move commands */
		നിവേശം = dgst_raw[i];
		വേണ്ടി (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (നിവേശം & 0x1) ? 1 : -1;
			y += (നിവേശം & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = MAXIMUM(x, 0);
			y = MAXIMUM(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			എങ്കിൽ (field[x][y] < len - 2)
				field[x][y]++;
			നിവേശം = നിവേശം >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* assemble title */
	r = snprintf(title, വലുപ്പം(title), "[%s %u]",
		sshkey_type(k), sshkey_size(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	എങ്കിൽ (r < 0 || r > (പൂർണ്ണസംഖ്യ)വലുപ്പം(title))
		r = snprintf(title, വലുപ്പം(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : strlen(title);

	/* assemble hash ID. */
	r = snprintf(hash, വലുപ്പം(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : strlen(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	വേണ്ടി (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	memcpy(p, title, tlen);
	p += tlen;
	വേണ്ടി (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	വേണ്ടി (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		വേണ്ടി (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(field[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	വേണ്ടി (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	memcpy(p, hash, hlen);
	p += hlen;
	വേണ്ടി (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	തിരികെ retval;
}

അക്ഷരം *
sshkey_fingerprint(സ്ഥിരം ഘടന sshkey *k, പൂർണ്ണസംഖ്യ dgst_alg,
    എണ്ണൽ sshkey_fp_rep dgst_rep)
{
	അക്ഷരം *retval = ശൂന്യ;
	u_char *dgst_raw;
	size_t dgst_raw_len;

	എങ്കിൽ (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		തിരികെ ശൂന്യ;
	തിരഞ്ഞെടുപ്പ് (dgst_rep) {
	അവസ്ഥ SSH_FP_DEFAULT:
		എങ്കിൽ (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} അല്ലെങ്കിൽ {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		നിർത്തുക;
	അവസ്ഥ SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		നിർത്തുക;
	അവസ്ഥ SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		നിർത്തുക;
	അവസ്ഥ SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		നിർത്തുക;
	അവസ്ഥ SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		freezero(dgst_raw, dgst_raw_len);
		തിരികെ ശൂന്യ;
	}
	freezero(dgst_raw, dgst_raw_len);
	തിരികെ retval;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
peek_type_nid(സ്ഥിരം അക്ഷരം *s, size_t l, പൂർണ്ണസംഖ്യ *nid)
{
	സ്ഥിരം ഘടന sshkey_impl *impl;
	പൂർണ്ണസംഖ്യ i;

	വേണ്ടി (i = 0; keyimpls[i] != ശൂന്യ; i++) {
		impl = keyimpls[i];
		എങ്കിൽ (impl->name == ശൂന്യ || strlen(impl->name) != l)
			തുടരുക;
		എങ്കിൽ (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			എങ്കിൽ (താക്കോൽ_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			തിരികെ impl->type;
		}
	}
	തിരികെ താക്കോൽ_UNSPEC;
}

/* XXX this can now be made const char * */
പൂർണ്ണസംഖ്യ
sshkey_read(ഘടന sshkey *ret, അക്ഷരം **cpp)
{
	ഘടന sshkey *k;
	അക്ഷരം *cp, *blobcopy;
	size_t space;
	പൂർണ്ണസംഖ്യ r, type, curve_nid = -1;
	ഘടന sshbuf *blob;

	എങ്കിൽ (ret == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (ret->type != താക്കോൽ_UNSPEC && sshkey_impl_from_type(ret->type) == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	എങ്കിൽ (space == strlen(cp))
		തിരികെ SSH_ERR_INVALID_FORMAT;
	എങ്കിൽ ((type = peek_type_nid(cp, space, &curve_nid)) == താക്കോൽ_UNSPEC)
		തിരികെ SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	വേണ്ടി (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	എങ്കിൽ (*cp == '\0')
		തിരികെ SSH_ERR_INVALID_FORMAT;
	എങ്കിൽ (ret->type != താക്കോൽ_UNSPEC && ret->type != type)
		തിരികെ SSH_ERR_താക്കോൽ_TYPE_MISMATCH;
	എങ്കിൽ ((blob = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	എങ്കിൽ ((blobcopy = strndup(cp, space)) == ശൂന്യ) {
		sshbuf_free(blob);
		തിരികെ SSH_ERR_ALLOC_FAIL;
	}
	എങ്കിൽ ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		സ്വതന്ത്രം(blobcopy);
		sshbuf_free(blob);
		തിരികെ r;
	}
	സ്വതന്ത്രം(blobcopy);
	എങ്കിൽ ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		തിരികെ r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	വേണ്ടി (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	എങ്കിൽ (k->type != type) {
		sshkey_free(k);
		തിരികെ SSH_ERR_താക്കോൽ_TYPE_MISMATCH;
	}
	എങ്കിൽ (താക്കോൽ_type_is_ecdsa_variant(type) && curve_nid != k->ecdsa_nid) {
		sshkey_free(k);
		തിരികെ SSH_ERR_EC_CURVE_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, വലുപ്പം(*k));

	/* success */
	*cpp = cp;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshkey_to_base64(സ്ഥിരം ഘടന sshkey *താക്കോൽ, അക്ഷരം **b64p)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	ഘടന sshbuf *b = ശൂന്യ;
	അക്ഷരം *uu = ശൂന്യ;

	എങ്കിൽ (b64p != ശൂന്യ)
		*b64p = ശൂന്യ;
	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshkey_putb(താക്കോൽ, b)) != 0)
		പോകുക out;
	എങ്കിൽ ((uu = sshbuf_dtob64_string(b, 0)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	/* Success */
	എങ്കിൽ (b64p != ശൂന്യ) {
		*b64p = uu;
		uu = ശൂന്യ;
	}
	r = 0;
 out:
	sshbuf_free(b);
	സ്വതന്ത്രം(uu);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshkey_format_text(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	അക്ഷരം *uu = ശൂന്യ;

	എങ്കിൽ ((r = sshkey_to_base64(താക്കോൽ, &uu)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(താക്കോൽ), uu)) != 0)
		പോകുക out;
	r = 0;
 out:
	സ്വതന്ത്രം(uu);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshkey_write(സ്ഥിരം ഘടന sshkey *താക്കോൽ, FILE *f)
{
	ഘടന sshbuf *b = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshkey_format_text(താക്കോൽ, b)) != 0)
		പോകുക out;
	എങ്കിൽ (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		എങ്കിൽ (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		പോകുക out;
	}
	/* Success */
	r = 0;
 out:
	sshbuf_free(b);
	തിരികെ r;
}

സ്ഥിരം അക്ഷരം *
sshkey_cert_type(സ്ഥിരം ഘടന sshkey *k)
{
	തിരഞ്ഞെടുപ്പ് (k->cert->type) {
	അവസ്ഥ SSH2_CERT_TYPE_USER:
		തിരികെ "user";
	അവസ്ഥ SSH2_CERT_TYPE_HOST:
		തിരികെ "host";
	സ്ഥിരസ്ഥിതി:
		തിരികെ "unknown";
	}
}

പൂർണ്ണസംഖ്യ
sshkey_check_rsa_length(സ്ഥിരം ഘടന sshkey *k, പൂർണ്ണസംഖ്യ min_size)
{
#ifdef WITH_OPENSSL
	പൂർണ്ണസംഖ്യ nbits;

	എങ്കിൽ (k == ശൂന്യ || k->pkey == ശൂന്യ ||
	    (k->type != താക്കോൽ_RSA && k->type != താക്കോൽ_RSA_CERT))
		തിരികെ 0;
	nbits = EVP_PKEY_bits(k->pkey);
	എങ്കിൽ (nbits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    (min_size > 0 && nbits < min_size))
		തിരികെ SSH_ERR_താക്കോൽ_LENGTH;
#endif /* WITH_OPENSSL */
	തിരികെ 0;
}

#ifdef WITH_OPENSSL
പൂർണ്ണസംഖ്യ
sshkey_ecdsa_താക്കോൽ_to_nid(സ്ഥിരം EC_താക്കോൽ *k)
{
	സ്ഥിരം EC_GROUP *g;
	പൂർണ്ണസംഖ്യ nid;

	എങ്കിൽ (k == ശൂന്യ || (g = EC_താക്കോൽ_get0_group(k)) == ശൂന്യ)
		തിരികെ -1;
	എങ്കിൽ ((nid = EC_GROUP_get_curve_name(g)) <= 0)
		തിരികെ -1;
	തിരികെ nid;
}

പൂർണ്ണസംഖ്യ
sshkey_ecdsa_pkey_to_nid(EVP_PKEY *pkey)
{
	തിരികെ sshkey_ecdsa_താക്കോൽ_to_nid(EVP_PKEY_get0_EC_താക്കോൽ(pkey));
}
#endif /* WITH_OPENSSL */

പൂർണ്ണസംഖ്യ
sshkey_generate(പൂർണ്ണസംഖ്യ type, u_int bits, ഘടന sshkey **keyp)
{
	ഘടന sshkey *k;
	പൂർണ്ണസംഖ്യ ret = SSH_ERR_INTERNAL_ERROR;
	സ്ഥിരം ഘടന sshkey_impl *impl;

	എങ്കിൽ (keyp == ശൂന്യ || sshkey_type_is_cert(type))
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	*keyp = ശൂന്യ;
	എങ്കിൽ ((impl = sshkey_impl_from_type(type)) == ശൂന്യ)
		തിരികെ SSH_ERR_താക്കോൽ_TYPE_UNKNOWN;
	എങ്കിൽ (impl->funcs->generate == ശൂന്യ)
		തിരികെ SSH_ERR_FEATURE_UNSUPPORTED;
	എങ്കിൽ ((k = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	k->type = type;
	എങ്കിൽ ((ret = impl->funcs->generate(k, bits)) != 0) {
		sshkey_free(k);
		തിരികെ ret;
	}
	/* success */
	*keyp = k;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshkey_cert_copy(സ്ഥിരം ഘടന sshkey *from_താക്കോൽ, ഘടന sshkey *to_താക്കോൽ)
{
	u_int i;
	സ്ഥിരം ഘടന sshkey_cert *from;
	ഘടന sshkey_cert *to;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (to_താക്കോൽ == ശൂന്യ || (from = from_താക്കോൽ->cert) == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	എങ്കിൽ ((to = cert_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;

	എങ്കിൽ ((r = sshbuf_putb(to->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(to->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(to->extensions, from->extensions)) != 0)
		പോകുക out;

	to->serial = from->serial;
	to->type = from->type;
	എങ്കിൽ (from->താക്കോൽ_id == ശൂന്യ)
		to->താക്കോൽ_id = ശൂന്യ;
	അല്ലെങ്കിൽ എങ്കിൽ ((to->താക്കോൽ_id = strdup(from->താക്കോൽ_id)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	to->valid_after = from->valid_after;
	to->valid_before = from->valid_before;
	എങ്കിൽ (from->signature_താക്കോൽ == ശൂന്യ)
		to->signature_താക്കോൽ = ശൂന്യ;
	അല്ലെങ്കിൽ എങ്കിൽ ((r = sshkey_from_private(from->signature_താക്കോൽ,
	    &to->signature_താക്കോൽ)) != 0)
		പോകുക out;
	എങ്കിൽ (from->signature_type != ശൂന്യ &&
	    (to->signature_type = strdup(from->signature_type)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	എങ്കിൽ (from->nprincipals > 0) {
		എങ്കിൽ ((to->principals = calloc(from->nprincipals,
		    വലുപ്പം(*to->principals))) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		വേണ്ടി (i = 0; i < from->nprincipals; i++) {
			to->principals[i] = strdup(from->principals[i]);
			എങ്കിൽ (to->principals[i] == ശൂന്യ) {
				to->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				പോകുക out;
			}
		}
	}
	to->nprincipals = from->nprincipals;

	/* success */
	cert_free(to_താക്കോൽ->cert);
	to_താക്കോൽ->cert = to;
	to = ശൂന്യ;
	r = 0;
 out:
	cert_free(to);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshkey_copy_public_sk(സ്ഥിരം ഘടന sshkey *from, ഘടന sshkey *to)
{
	/* Append security-key application string */
	എങ്കിൽ ((to->sk_application = strdup(from->sk_application)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshkey_from_private(സ്ഥിരം ഘടന sshkey *k, ഘടന sshkey **pkp)
{
	ഘടന sshkey *n = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	സ്ഥിരം ഘടന sshkey_impl *impl;

	*pkp = ശൂന്യ;
	എങ്കിൽ ((impl = sshkey_impl_from_താക്കോൽ(k)) == ശൂന്യ)
		തിരികെ SSH_ERR_താക്കോൽ_TYPE_UNKNOWN;
	എങ്കിൽ ((n = sshkey_new(k->type)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = impl->funcs->copy_public(k, n)) != 0)
		പോകുക out;
	എങ്കിൽ (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		പോകുക out;
	/* success */
	*pkp = n;
	n = ശൂന്യ;
	r = 0;
 out:
	sshkey_free(n);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshkey_is_shielded(ഘടന sshkey *k)
{
	തിരികെ k != ശൂന്യ && k->shielded_private != ശൂന്യ;
}

പൂർണ്ണസംഖ്യ
sshkey_shield_private(ഘടന sshkey *k)
{
	ഘടന sshbuf *prvbuf = ശൂന്യ;
	u_char *prekey = ശൂന്യ, *enc = ശൂന്യ, keyiv[SSH_DIGEST_MAX_LENGTH];
	ഘടന sshcipher_ctx *cctx = ശൂന്യ;
	സ്ഥിരം ഘടന sshcipher *cipher;
	size_t i, enclen = 0;
	ഘടന sshkey *kswap = ശൂന്യ, tmp;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	എങ്കിൽ ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ശൂന്യ) {
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	എങ്കിൽ (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		പോകുക out;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	എങ്കിൽ ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		പോകുക out;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	എങ്കിൽ ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		പോകുക out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif
	എങ്കിൽ ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		പോകുക out;

	/* Serialise and encrypt the private key using the ephemeral key */
	എങ്കിൽ ((prvbuf = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (sshkey_is_shielded(k) && (r = sshkey_unshield_private(k)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = sshkey_private_serialize(k, prvbuf)) != 0)
		പോകുക out;
	/* pad to cipher blocksize */
	i = 0;
	ആകുമ്പോൾ (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		എങ്കിൽ ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			പോകുക out;
	}
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	എങ്കിൽ ((enc = malloc(enclen)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		പോകുക out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(enc, enclen, stderr);
#endif

	/* Make a scrubbed, public-only copy of our private key argument */
	എങ്കിൽ ((r = sshkey_from_private(k, &kswap)) != 0)
		പോകുക out;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_private = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = ശൂന്യ; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 out:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, വലുപ്പം(keyiv));
	explicit_bzero(&tmp, വലുപ്പം(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	തിരികെ r;
}

/* Check deterministic padding after private key */
സ്ഥിതം പൂർണ്ണസംഖ്യ
private2_check_padding(ഘടന sshbuf *decrypted)
{
	u_char pad;
	size_t i;
	പൂർണ്ണസംഖ്യ r;

	i = 0;
	ആകുമ്പോൾ (sshbuf_len(decrypted)) {
		എങ്കിൽ ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			പോകുക out;
		എങ്കിൽ (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
	}
	/* success */
	r = 0;
 out:
	explicit_bzero(&pad, വലുപ്പം(pad));
	explicit_bzero(&i, വലുപ്പം(i));
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshkey_unshield_private(ഘടന sshkey *k)
{
	ഘടന sshbuf *prvbuf = ശൂന്യ;
	u_char *cp, keyiv[SSH_DIGEST_MAX_LENGTH];
	ഘടന sshcipher_ctx *cctx = ശൂന്യ;
	സ്ഥിരം ഘടന sshcipher *cipher;
	ഘടന sshkey *kswap = ശൂന്യ, tmp;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

#ifdef DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#endif
	എങ്കിൽ (!sshkey_is_shielded(k))
		തിരികെ 0; /* nothing to do */

	എങ്കിൽ ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ശൂന്യ) {
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	എങ്കിൽ (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_INTERNAL_ERROR;
		പോകുക out;
	}
	/* check size of shielded key blob */
	എങ്കിൽ (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}

	/* Calculate the ephemeral key from the prekey */
	എങ്കിൽ ((r = ssh_digest_memory(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_LENGTH)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		പോകുക out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_data(keyiv, ssh_digest_bytes(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#endif

	/* Decrypt and parse the shielded private key using the ephemeral key */
	എങ്കിൽ ((prvbuf = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		പോകുക out;
	/* decrypt */
#ifdef DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_data(k->shielded_private, k->shielded_len, stderr);
#endif
	എങ്കിൽ ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_private, k->shielded_len, 0, 0)) != 0)
		പോകുക out;
#ifdef DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#endif
	/* Parse private key */
	എങ്കിൽ ((r = sshkey_private_deserialize(prvbuf, &kswap)) != 0)
		പോകുക out;

	എങ്കിൽ ((r = private2_check_padding(prvbuf)) != 0)
		പോകുക out;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 out:
	cipher_free(cctx);
	explicit_bzero(keyiv, വലുപ്പം(keyiv));
	explicit_bzero(&tmp, വലുപ്പം(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
cert_parse(ഘടന sshbuf *b, ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *certbuf,
    സ്ഥിരം അക്ഷരം *ca_sigalg_allowlist)
{
	ഘടന sshbuf *principals = ശൂന്യ, *crit = ശൂന്യ;
	ഘടന sshbuf *exts = ശൂന്യ, *ca = ശൂന്യ;
	u_char *sig = ശൂന്യ;
	അക്ഷരം *sigtype = ശൂന്യ;
	size_t signed_len = 0, slen = 0, kidlen = 0;
	പൂർണ്ണസംഖ്യ ret = SSH_ERR_INTERNAL_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	എങ്കിൽ ((ret = sshbuf_putb(താക്കോൽ->cert->certblob, certbuf)) != 0)
		തിരികെ ret;

	/* Parse body of certificate up to signature */
	എങ്കിൽ ((ret = sshbuf_get_u64(b, &താക്കോൽ->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &താക്കോൽ->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &താക്കോൽ->cert->താക്കോൽ_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &താക്കോൽ->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &താക്കോൽ->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, ശൂന്യ, ശൂന്യ)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(താക്കോൽ->cert->certblob) - sshbuf_len(b);

	എങ്കിൽ ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}

	/* Is this a signature we're prepared to accept? */
	എങ്കിൽ ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (ca_sigalg_allowlist != ശൂന്യ &&
	    match_pattern_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		പോകുക out;
	}

	/* Parse CA key and check whether we might accept it */
	എങ്കിൽ (sshkey_from_blob_internal(ca, &താക്കോൽ->cert->signature_താക്കോൽ, 0,
	    ca_sigalg_allowlist, ശൂന്യ) != 0) {
		ret = SSH_ERR_താക്കോൽ_CERT_INVALID_SIGN_താക്കോൽ;
		പോകുക out;
	}
	എങ്കിൽ (!sshkey_type_is_valid_ca(താക്കോൽ->cert->signature_താക്കോൽ->type)) {
		ret = SSH_ERR_താക്കോൽ_CERT_INVALID_SIGN_താക്കോൽ;
		പോകുക out;
	}

	എങ്കിൽ (താക്കോൽ->cert->type != SSH2_CERT_TYPE_USER &&
	    താക്കോൽ->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_താക്കോൽ_CERT_UNKNOWN_TYPE;
		പോകുക out;
	}

	/* Parse principals section */
	ആകുമ്പോൾ (sshbuf_len(principals) > 0) {
		അക്ഷരം *principal = ശൂന്യ;
		അക്ഷരം **oprincipals = ശൂന്യ;

		എങ്കിൽ (താക്കോൽ->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		എങ്കിൽ ((ret = sshbuf_get_cstring(principals, &principal,
		    ശൂന്യ)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		oprincipals = താക്കോൽ->cert->principals;
		താക്കോൽ->cert->principals = recallocarray(താക്കോൽ->cert->principals,
		    താക്കോൽ->cert->nprincipals, താക്കോൽ->cert->nprincipals + 1,
		    വലുപ്പം(*താക്കോൽ->cert->principals));
		എങ്കിൽ (താക്കോൽ->cert->principals == ശൂന്യ) {
			സ്വതന്ത്രം(principal);
			താക്കോൽ->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		താക്കോൽ->cert->principals[താക്കോൽ->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	എങ്കിൽ ((ret = sshbuf_putb(താക്കോൽ->cert->critical, crit)) != 0 ||
	    (exts != ശൂന്യ &&
	    (ret = sshbuf_putb(താക്കോൽ->cert->extensions, exts)) != 0))
		പോകുക out;

	/*
	 * Validate critical options and extensions sections format.
	 */
	ആകുമ്പോൾ (sshbuf_len(crit) != 0) {
		എങ്കിൽ ((ret = sshbuf_get_string_direct(crit, ശൂന്യ, ശൂന്യ)) != 0 ||
		    (ret = sshbuf_get_string_direct(crit, ശൂന്യ, ശൂന്യ)) != 0) {
			sshbuf_reset(താക്കോൽ->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
	}
	ആകുമ്പോൾ (exts != ശൂന്യ && sshbuf_len(exts) != 0) {
		എങ്കിൽ ((ret = sshbuf_get_string_direct(exts, ശൂന്യ, ശൂന്യ)) != 0 ||
		    (ret = sshbuf_get_string_direct(exts, ശൂന്യ, ശൂന്യ)) != 0) {
			sshbuf_reset(താക്കോൽ->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
	}

	/* Finally, validate signature */
	എങ്കിൽ ((ret = sshkey_verify(താക്കോൽ->cert->signature_താക്കോൽ, sig, slen,
	    sshbuf_ptr(താക്കോൽ->cert->certblob), signed_len, ശൂന്യ, 0, ശൂന്യ)) != 0)
		പോകുക out;

	/* Success */
	ret = 0;
	താക്കോൽ->cert->signature_type = sigtype;
	sigtype = ശൂന്യ;
 out:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	സ്വതന്ത്രം(sig);
	സ്വതന്ത്രം(sigtype);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sshkey_deserialize_sk(ഘടന sshbuf *b, ഘടന sshkey *താക്കോൽ)
{
	/* Parse additional security-key application string */
	എങ്കിൽ (sshbuf_get_cstring(b, &താക്കോൽ->sk_application, ശൂന്യ) != 0)
		തിരികെ SSH_ERR_INVALID_FORMAT;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshkey_from_blob_internal(ഘടന sshbuf *b, ഘടന sshkey **keyp,
    പൂർണ്ണസംഖ്യ allow_cert, സ്ഥിരം അക്ഷരം *alg_allowlist, സ്ഥിരം അക്ഷരം *ca_sigalg_allowlist)
{
	പൂർണ്ണസംഖ്യ type, ret = SSH_ERR_INTERNAL_ERROR;
	അക്ഷരം *ktype = ശൂന്യ;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	ഘടന sshbuf *copy;
	സ്ഥിരം ഘടന sshkey_impl *impl;

#ifdef DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#endif
	എങ്കിൽ (keyp != ശൂന്യ)
		*keyp = ശൂന്യ;
	എങ്കിൽ ((copy = sshbuf_fromb(b)) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_get_cstring(b, &ktype, ശൂന്യ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}

	type = sshkey_type_from_name(ktype);
	എങ്കിൽ (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_താക്കോൽ_CERT_INVALID_SIGN_താക്കോൽ;
		പോകുക out;
	}

	എങ്കിൽ (alg_allowlist != ശൂന്യ &&
	    !sshkey_match_keyname_to_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_താക്കോൽ_ALG_UNSUPPORTED;
		പോകുക out;
	}

	എങ്കിൽ ((impl = sshkey_impl_from_type(type)) == ശൂന്യ) {
		ret = SSH_ERR_താക്കോൽ_TYPE_UNKNOWN;
		പോകുക out;
	}
	എങ്കിൽ ((താക്കോൽ = sshkey_new(type)) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		എങ്കിൽ (sshbuf_get_string_direct(b, ശൂന്യ, ശൂന്യ) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
	}
	എങ്കിൽ ((ret = impl->funcs->deserialize_public(ktype, b, താക്കോൽ)) != 0)
		പോകുക out;

	/* Parse certificate potion */
	എങ്കിൽ (sshkey_is_cert(താക്കോൽ) &&
	    (ret = cert_parse(b, താക്കോൽ, copy, ca_sigalg_allowlist)) != 0)
		പോകുക out;

	എങ്കിൽ (താക്കോൽ != ശൂന്യ && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	ret = 0;
	എങ്കിൽ (keyp != ശൂന്യ) {
		*keyp = താക്കോൽ;
		താക്കോൽ = ശൂന്യ;
	}
 out:
	sshbuf_free(copy);
	sshkey_free(താക്കോൽ);
	സ്വതന്ത്രം(ktype);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sshkey_from_blob(സ്ഥിരം u_char *blob, size_t blen, ഘടന sshkey **keyp)
{
	ഘടന sshbuf *b;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((b = sshbuf_from(blob, blen)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_internal(b, keyp, 1, ശൂന്യ, ശൂന്യ);
	sshbuf_free(b);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshkey_fromb(ഘടന sshbuf *b, ഘടന sshkey **keyp)
{
	തിരികെ sshkey_from_blob_internal(b, keyp, 1, ശൂന്യ, ശൂന്യ);
}

പൂർണ്ണസംഖ്യ
sshkey_fromb_allowlist(ഘടന sshbuf *b, ഘടന sshkey **keyp,
    സ്ഥിരം അക്ഷരം *alg_allowlist, സ്ഥിരം അക്ഷരം *ca_sigalg_allowlist)
{
	തിരികെ sshkey_from_blob_internal(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

പൂർണ്ണസംഖ്യ
sshkey_froms(ഘടന sshbuf *buf, ഘടന sshkey **keyp)
{
	ഘടന sshbuf *b;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_froms(buf, &b)) != 0)
		തിരികെ r;
	r = sshkey_from_blob_internal(b, keyp, 1, ശൂന്യ, ശൂന്യ);
	sshbuf_free(b);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshkey_get_sigtype(സ്ഥിരം u_char *sig, size_t siglen, അക്ഷരം **sigtypep)
{
	പൂർണ്ണസംഖ്യ r;
	ഘടന sshbuf *b = ശൂന്യ;
	അക്ഷരം *sigtype = ശൂന്യ;

	എങ്കിൽ (sigtypep != ശൂന്യ)
		*sigtypep = ശൂന്യ;
	എങ്കിൽ ((b = sshbuf_from(sig, siglen)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_get_cstring(b, &sigtype, ശൂന്യ)) != 0)
		പോകുക out;
	/* success */
	എങ്കിൽ (sigtypep != ശൂന്യ) {
		*sigtypep = sigtype;
		sigtype = ശൂന്യ;
	}
	r = 0;
 out:
	സ്വതന്ത്രം(sigtype);
	sshbuf_free(b);
	തിരികെ r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
പൂർണ്ണസംഖ്യ
sshkey_check_cert_sigtype(സ്ഥിരം ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *allowed)
{
	എങ്കിൽ (താക്കോൽ == ശൂന്യ || allowed == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (!sshkey_type_is_cert(താക്കോൽ->type))
		തിരികെ 0;
	എങ്കിൽ (താക്കോൽ->cert == ശൂന്യ || താക്കോൽ->cert->signature_type == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (match_pattern_list(താക്കോൽ->cert->signature_type, allowed, 0) != 1)
		തിരികെ SSH_ERR_SIGN_ALG_UNSUPPORTED;
	തിരികെ 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
സ്ഥിരം അക്ഷരം *
sshkey_sigalg_by_name(സ്ഥിരം അക്ഷരം *name)
{
	സ്ഥിരം ഘടന sshkey_impl *impl;
	പൂർണ്ണസംഖ്യ i;

	വേണ്ടി (i = 0; keyimpls[i] != ശൂന്യ; i++) {
		impl = keyimpls[i];
		എങ്കിൽ (strcmp(impl->name, name) != 0)
			തുടരുക;
		എങ്കിൽ (impl->sigalg != ശൂന്യ)
			തിരികെ impl->sigalg;
		എങ്കിൽ (!impl->cert)
			തിരികെ impl->name;
		തിരികെ sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	തിരികെ ശൂന്യ;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
പൂർണ്ണസംഖ്യ
sshkey_check_sigtype(സ്ഥിരം u_char *sig, size_t siglen,
    സ്ഥിരം അക്ഷരം *requested_alg)
{
	സ്ഥിരം അക്ഷരം *expected_alg;
	അക്ഷരം *sigtype = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (requested_alg == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		തിരികെ r;
	r = strcmp(expected_alg, sigtype) == 0;
	സ്വതന്ത്രം(sigtype);
	തിരികെ r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

പൂർണ്ണസംഖ്യ
sshkey_sign(ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *alg, സ്ഥിരം അക്ഷരം *sk_provider, സ്ഥിരം അക്ഷരം *sk_pin, u_int compat)
{
	പൂർണ്ണസംഖ്യ was_shielded = sshkey_is_shielded(താക്കോൽ);
	പൂർണ്ണസംഖ്യ r2, r = SSH_ERR_INTERNAL_ERROR;
	സ്ഥിരം ഘടന sshkey_impl *impl;

	എങ്കിൽ (sigp != ശൂന്യ)
		*sigp = ശൂന്യ;
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	എങ്കിൽ (datalen > SSH_താക്കോൽ_MAX_SIGN_DATA_SIZE)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((impl = sshkey_impl_from_താക്കോൽ(താക്കോൽ)) == ശൂന്യ)
		തിരികെ SSH_ERR_താക്കോൽ_TYPE_UNKNOWN;
	എങ്കിൽ ((r = sshkey_unshield_private(താക്കോൽ)) != 0)
		തിരികെ r;
	എങ്കിൽ (sshkey_is_sk(താക്കോൽ)) {
		r = sshsk_sign(sk_provider, താക്കോൽ, sigp, lenp, data,
		    datalen, compat, sk_pin);
	} അല്ലെങ്കിൽ എങ്കിൽ ((താക്കോൽ->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(താക്കോൽ, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (impl->funcs->sign == ശൂന്യ)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		അല്ലെങ്കിൽ {
			r = impl->funcs->sign(താക്കോൽ, sigp, lenp, data, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	എങ്കിൽ (was_shielded && (r2 = sshkey_shield_private(താക്കോൽ)) != 0)
		തിരികെ r2;
	തിരികെ r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
പൂർണ്ണസംഖ്യ
sshkey_verify(സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം u_char *sig, size_t siglen,
    സ്ഥിരം u_char *data, size_t dlen, സ്ഥിരം അക്ഷരം *alg, u_int compat,
    ഘടന sshkey_sig_details **detailsp)
{
	സ്ഥിരം ഘടന sshkey_impl *impl;

	എങ്കിൽ (detailsp != ശൂന്യ)
		*detailsp = ശൂന്യ;
	എങ്കിൽ (siglen == 0 || dlen > SSH_താക്കോൽ_MAX_SIGN_DATA_SIZE)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((impl = sshkey_impl_from_താക്കോൽ(താക്കോൽ)) == ശൂന്യ)
		തിരികെ SSH_ERR_താക്കോൽ_TYPE_UNKNOWN;
	തിരികെ impl->funcs->verify(താക്കോൽ, sig, siglen, data, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
പൂർണ്ണസംഖ്യ
sshkey_to_certified(ഘടന sshkey *k)
{
	പൂർണ്ണസംഖ്യ newtype;

	എങ്കിൽ ((newtype = sshkey_type_certified(k->type)) == -1)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((k->cert = cert_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	തിരികെ 0;
}

/* Convert a certificate to its raw key equivalent */
പൂർണ്ണസംഖ്യ
sshkey_drop_cert(ഘടന sshkey *k)
{
	എങ്കിൽ (!sshkey_type_is_cert(k->type))
		തിരികെ SSH_ERR_താക്കോൽ_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = ശൂന്യ;
	k->type = sshkey_type_plain(k->type);
	തിരികെ 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
പൂർണ്ണസംഖ്യ
sshkey_certify_custom(ഘടന sshkey *k, ഘടന sshkey *ca, സ്ഥിരം അക്ഷരം *alg,
    സ്ഥിരം അക്ഷരം *sk_provider, സ്ഥിരം അക്ഷരം *sk_pin,
    sshkey_certify_signer *signer, ശൂന്യം *signer_ctx)
{
	സ്ഥിരം ഘടന sshkey_impl *impl;
	ഘടന sshbuf *principals = ശൂന്യ;
	u_char *ca_blob = ശൂന്യ, *sig_blob = ശൂന്യ, nonce[32];
	size_t i, ca_len, sig_len;
	പൂർണ്ണസംഖ്യ ret = SSH_ERR_INTERNAL_ERROR;
	ഘടന sshbuf *cert = ശൂന്യ;
	അക്ഷരം *sigtype = ശൂന്യ;

	എങ്കിൽ (k == ശൂന്യ || k->cert == ശൂന്യ ||
	    k->cert->certblob == ശൂന്യ || ca == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (!sshkey_is_cert(k))
		തിരികെ SSH_ERR_താക്കോൽ_TYPE_UNKNOWN;
	എങ്കിൽ (!sshkey_type_is_valid_ca(ca->type))
		തിരികെ SSH_ERR_താക്കോൽ_CERT_INVALID_SIGN_താക്കോൽ;
	എങ്കിൽ ((impl = sshkey_impl_from_താക്കോൽ(k)) == ശൂന്യ)
		തിരികെ SSH_ERR_INTERNAL_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	എങ്കിൽ (alg == ശൂന്യ)
		alg = k->cert->signature_type;
	അല്ലെങ്കിൽ എങ്കിൽ (k->cert->signature_type != ശൂന്യ &&
	    strcmp(alg, k->cert->signature_type) != 0)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	എങ്കിൽ (alg == ശൂന്യ && ca->type == താക്കോൽ_RSA)
		alg = "rsa-sha2-512";

	എങ്കിൽ ((ret = sshkey_to_blob(ca, &ca_blob, &ca_len)) != 0)
		തിരികെ SSH_ERR_താക്കോൽ_CERT_INVALID_SIGN_താക്കോൽ;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	എങ്കിൽ ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		പോകുക out;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, വലുപ്പം(nonce));
	എങ്കിൽ ((ret = sshbuf_put_string(cert, nonce, വലുപ്പം(nonce))) != 0)
		പോകുക out;

	/* Public key next */
	എങ്കിൽ ((ret = impl->funcs->serialize_public(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		പോകുക out;

	/* Then remaining cert fields */
	എങ്കിൽ ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->താക്കോൽ_id)) != 0)
		പോകുക out;

	എങ്കിൽ ((principals = sshbuf_new()) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	വേണ്ടി (i = 0; i < k->cert->nprincipals; i++) {
		എങ്കിൽ ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			പോകുക out;
	}
	എങ്കിൽ ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, ശൂന്യ, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		പോകുക out;

	/* Sign the whole mess */
	എങ്കിൽ ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		പോകുക out;
	/* Check and update signature_type against what was actually used */
	എങ്കിൽ ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		പോകുക out;
	എങ്കിൽ (alg != ശൂന്യ && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		പോകുക out;
	}
	എങ്കിൽ (k->cert->signature_type == ശൂന്യ) {
		k->cert->signature_type = sigtype;
		sigtype = ശൂന്യ;
	}
	/* Append signature and we are done */
	എങ്കിൽ ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		പോകുക out;
	ret = 0;
 out:
	എങ്കിൽ (ret != 0)
		sshbuf_reset(cert);
	സ്വതന്ത്രം(sig_blob);
	സ്വതന്ത്രം(ca_blob);
	സ്വതന്ത്രം(sigtype);
	sshbuf_free(principals);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
default_താക്കോൽ_sign(ഘടന sshkey *താക്കോൽ, u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *alg, സ്ഥിരം അക്ഷരം *sk_provider, സ്ഥിരം അക്ഷരം *sk_pin,
    u_int compat, ശൂന്യം *ctx)
{
	എങ്കിൽ (ctx != ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	തിരികെ sshkey_sign(താക്കോൽ, sigp, lenp, data, datalen, alg,
	    sk_provider, sk_pin, compat);
}

പൂർണ്ണസംഖ്യ
sshkey_certify(ഘടന sshkey *k, ഘടന sshkey *ca, സ്ഥിരം അക്ഷരം *alg,
    സ്ഥിരം അക്ഷരം *sk_provider, സ്ഥിരം അക്ഷരം *sk_pin)
{
	തിരികെ sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_താക്കോൽ_sign, ശൂന്യ);
}

പൂർണ്ണസംഖ്യ
sshkey_cert_check_authority(സ്ഥിരം ഘടന sshkey *k,
    പൂർണ്ണസംഖ്യ want_host, പൂർണ്ണസംഖ്യ wildcard_pattern, uint64_t verify_time,
    സ്ഥിരം അക്ഷരം *name, സ്ഥിരം അക്ഷരം **reason)
{
	u_int i, principal_matches;

	എങ്കിൽ (reason == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		തിരികെ SSH_ERR_താക്കോൽ_CERT_INVALID;
	}
	എങ്കിൽ (want_host) {
		എങ്കിൽ (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			തിരികെ SSH_ERR_താക്കോൽ_CERT_INVALID;
		}
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			തിരികെ SSH_ERR_താക്കോൽ_CERT_INVALID;
		}
	}
	എങ്കിൽ (verify_time < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		തിരികെ SSH_ERR_താക്കോൽ_CERT_INVALID;
	}
	എങ്കിൽ (verify_time >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		തിരികെ SSH_ERR_താക്കോൽ_CERT_INVALID;
	}
	എങ്കിൽ (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		തിരികെ SSH_ERR_താക്കോൽ_CERT_INVALID;
	}
	എങ്കിൽ (name == ശൂന്യ)
		തിരികെ 0; /* principal matching not requested */

	principal_matches = 0;
	വേണ്ടി (i = 0; i < k->cert->nprincipals; i++) {
		എങ്കിൽ (wildcard_pattern) {
			എങ്കിൽ (match_pattern(name, k->cert->principals[i])) {
				principal_matches = 1;
				നിർത്തുക;
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			നിർത്തുക;
		}
	}
	എങ്കിൽ (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		തിരികെ SSH_ERR_താക്കോൽ_CERT_INVALID;
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshkey_cert_check_authority_now(സ്ഥിരം ഘടന sshkey *k,
    പൂർണ്ണസംഖ്യ want_host, പൂർണ്ണസംഖ്യ wildcard_pattern, സ്ഥിരം അക്ഷരം *name,
    സ്ഥിരം അക്ഷരം **reason)
{
	time_t now;

	എങ്കിൽ ((now = time(ശൂന്യ)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		തിരികെ SSH_ERR_താക്കോൽ_CERT_INVALID;
	}
	തിരികെ sshkey_cert_check_authority(k, want_host, wildcard_pattern,
	    (uint64_t)now, name, reason);
}

പൂർണ്ണസംഖ്യ
sshkey_cert_check_host(സ്ഥിരം ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *host,
    സ്ഥിരം അക്ഷരം *ca_sign_algorithms, സ്ഥിരം അക്ഷരം **reason)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshkey_cert_check_authority_now(താക്കോൽ, 1, 1, host, reason)) != 0)
		തിരികെ r;
	എങ്കിൽ (sshbuf_len(താക്കോൽ->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		തിരികെ SSH_ERR_താക്കോൽ_CERT_INVALID;
	}
	എങ്കിൽ (ca_sign_algorithms != ശൂന്യ &&
	    (r = sshkey_check_cert_sigtype(താക്കോൽ, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		തിരികെ SSH_ERR_താക്കോൽ_CERT_INVALID;
	}
	തിരികെ 0;
}

size_t
sshkey_format_cert_validity(സ്ഥിരം ഘടന sshkey_cert *cert, അക്ഷരം *s, size_t l)
{
	അക്ഷരം from[32], to[32], ret[128];

	*from = *to = '\0';
	എങ്കിൽ (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		തിരികെ strlcpy(s, "forever", l);

	എങ്കിൽ (cert->valid_after != 0)
		format_absolute_time(cert->valid_after, from, വലുപ്പം(from));
	എങ്കിൽ (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_time(cert->valid_before, to, വലുപ്പം(to));

	എങ്കിൽ (cert->valid_after == 0)
		snprintf(ret, വലുപ്പം(ret), "before %s", to);
	അല്ലെങ്കിൽ എങ്കിൽ (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, വലുപ്പം(ret), "after %s", from);
	അല്ലെങ്കിൽ
		snprintf(ret, വലുപ്പം(ret), "from %s to %s", from, to);

	തിരികെ strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
പൂർണ്ണസംഖ്യ
sshkey_serialize_private_sk(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_put_cstring(b, താക്കോൽ->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, താക്കോൽ->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, താക്കോൽ->sk_താക്കോൽ_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, താക്കോൽ->sk_reserved)) != 0)
		തിരികെ r;

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshkey_private_serialize_opt(ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *buf,
    എണ്ണൽ sshkey_serialize_rep opts)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	പൂർണ്ണസംഖ്യ was_shielded = sshkey_is_shielded(താക്കോൽ);
	ഘടന sshbuf *b = ശൂന്യ;
	സ്ഥിരം ഘടന sshkey_impl *impl;

	എങ്കിൽ ((impl = sshkey_impl_from_താക്കോൽ(താക്കോൽ)) == ശൂന്യ)
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	എങ്കിൽ ((r = sshkey_unshield_private(താക്കോൽ)) != 0)
		തിരികെ r;
	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_put_cstring(b, sshkey_ssh_name(താക്കോൽ))) != 0)
		പോകുക out;
	എങ്കിൽ (sshkey_is_cert(താക്കോൽ)) {
		എങ്കിൽ (താക്കോൽ->cert == ശൂന്യ ||
		    sshbuf_len(താക്കോൽ->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_put_stringb(b, താക്കോൽ->cert->certblob)) != 0)
			പോകുക out;
	}
	എങ്കിൽ ((r = impl->funcs->serialize_private(താക്കോൽ, b, opts)) != 0)
		പോകുക out;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 out:
	എങ്കിൽ (was_shielded)
		r = sshkey_shield_private(താക്കോൽ);
	എങ്കിൽ (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshkey_private_serialize(ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b)
{
	തിരികെ sshkey_private_serialize_opt(താക്കോൽ, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
പൂർണ്ണസംഖ്യ
sshkey_private_deserialize_sk(ഘടന sshbuf *buf, ഘടന sshkey *k)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((k->sk_താക്കോൽ_handle = sshbuf_new()) == ശൂന്യ ||
	    (k->sk_reserved = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_get_cstring(buf, &k->sk_application, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_താക്കോൽ_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		തിരികെ r;

	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshkey_private_deserialize(ഘടന sshbuf *buf, ഘടന sshkey **kp)
{
	സ്ഥിരം ഘടന sshkey_impl *impl;
	അക്ഷരം *tname = ശൂന്യ;
	അക്ഷരം *expect_sk_application = ശൂന്യ;
	u_char *expect_ed25519_pk = ശൂന്യ;
	ഘടന sshkey *k = ശൂന്യ;
	പൂർണ്ണസംഖ്യ type, r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (kp != ശൂന്യ)
		*kp = ശൂന്യ;
	എങ്കിൽ ((r = sshbuf_get_cstring(buf, &tname, ശൂന്യ)) != 0)
		പോകുക out;
	type = sshkey_type_from_name(tname);
	എങ്കിൽ (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		എങ്കിൽ ((r = sshkey_froms(buf, &k)) != 0)
			പോകുക out;
		എങ്കിൽ (k->type != type) {
			r = SSH_ERR_താക്കോൽ_CERT_MISMATCH;
			പോകുക out;
		}
		/* For ECDSA keys, the group must match too */
		എങ്കിൽ (k->type == താക്കോൽ_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_താക്കോൽ_CERT_MISMATCH;
			പോകുക out;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = ശൂന്യ;
		k->ed25519_pk = ശൂന്യ;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((k = sshkey_new(type)) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
	}
	എങ്കിൽ ((impl = sshkey_impl_from_type(type)) == ശൂന്യ) {
		r = SSH_ERR_INTERNAL_ERROR;
		പോകുക out;
	}
	എങ്കിൽ ((r = impl->funcs->deserialize_private(tname, buf, k)) != 0)
		പോകുക out;

	എങ്കിൽ ((expect_sk_application != ശൂന്യ && (k->sk_application == ശൂന്യ ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != ശൂന്യ && (k->ed25519_pk == ശൂന്യ ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_താക്കോൽ_CERT_MISMATCH;
		പോകുക out;
	}
	/* success */
	r = 0;
	എങ്കിൽ (kp != ശൂന്യ) {
		*kp = k;
		k = ശൂന്യ;
	}
 out:
	സ്വതന്ത്രം(tname);
	sshkey_free(k);
	സ്വതന്ത്രം(expect_sk_application);
	സ്വതന്ത്രം(expect_ed25519_pk);
	തിരികെ r;
}

#ifdef WITH_OPENSSL
പൂർണ്ണസംഖ്യ
sshkey_ec_validate_public(സ്ഥിരം EC_GROUP *group, സ്ഥിരം EC_POINT *പൊതു)
{
	EC_POINT *nq = ശൂന്യ;
	BIGNUM *order = ശൂന്യ, *cofactor = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret = SSH_ERR_താക്കോൽ_INVALID_EC_മൂല്യം;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	എങ്കിൽ (EC_POINT_is_at_infinity(group, പൊതു))
		പോകുക out;

	എങ്കിൽ ((cofactor = BN_new()) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (EC_GROUP_get_cofactor(group, cofactor, ശൂന്യ) != 1)
		പോകുക out;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	എങ്കിൽ (!BN_is_one(cofactor)) {
		എങ്കിൽ ((order = BN_new()) == ശൂന്യ) {
			ret = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		എങ്കിൽ (EC_GROUP_get_order(group, order, ശൂന്യ) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			പോകുക out;
		}
		എങ്കിൽ ((nq = EC_POINT_new(group)) == ശൂന്യ) {
			ret = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		എങ്കിൽ (EC_POINT_mul(group, nq, ശൂന്യ, പൊതു, order, ശൂന്യ) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			പോകുക out;
		}
		എങ്കിൽ (EC_POINT_is_at_infinity(group, nq) != 1)
			പോകുക out;
	}

	/* success */
	ret = 0;
 out:
	BN_clear_free(cofactor);
	BN_clear_free(order);
	EC_POINT_free(nq);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sshkey_ec_validate_private(സ്ഥിരം EC_താക്കോൽ *താക്കോൽ)
{
	BIGNUM *order = ശൂന്യ, *tmp = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret = SSH_ERR_താക്കോൽ_INVALID_EC_മൂല്യം;

	എങ്കിൽ ((order = BN_new()) == ശൂന്യ || (tmp = BN_new()) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}

	/* log2(private) > log2(order)/2 */
	എങ്കിൽ (EC_GROUP_get_order(EC_താക്കോൽ_get0_group(താക്കോൽ), order, ശൂന്യ) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	എങ്കിൽ (BN_അക്കം_bits(EC_താക്കോൽ_get0_private_താക്കോൽ(താക്കോൽ)) <=
	    BN_അക്കം_bits(order) / 2)
		പോകുക out;

	/* private < order - 1 */
	എങ്കിൽ (!BN_sub(tmp, order, BN_മൂല്യം_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	എങ്കിൽ (BN_cmp(EC_താക്കോൽ_get0_private_താക്കോൽ(താക്കോൽ), tmp) >= 0)
		പോകുക out;
	ret = 0;
 out:
	BN_clear_free(order);
	BN_clear_free(tmp);
	തിരികെ ret;
}

ശൂന്യം
sshkey_dump_ec_point(സ്ഥിരം EC_GROUP *group, സ്ഥിരം EC_POINT *point)
{
	BIGNUM *x = ശൂന്യ, *y = ശൂന്യ;

	എങ്കിൽ (point == ശൂന്യ) {
		fputs("point=(NULL)\n", stderr);
		തിരികെ;
	}
	എങ്കിൽ ((x = BN_new()) == ശൂന്യ || (y = BN_new()) == ശൂന്യ) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		പോകുക out;
	}
	എങ്കിൽ (EC_POINT_get_affine_coordinates(group, point, x, y, ശൂന്യ) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		പോകുക out;
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

ശൂന്യം
sshkey_dump_ec_താക്കോൽ(സ്ഥിരം EC_താക്കോൽ *താക്കോൽ)
{
	സ്ഥിരം BIGNUM *exponent;

	sshkey_dump_ec_point(EC_താക്കോൽ_get0_group(താക്കോൽ),
	    EC_താക്കോൽ_get0_public_താക്കോൽ(താക്കോൽ));
	fputs("exponent=", stderr);
	എങ്കിൽ ((exponent = EC_താക്കോൽ_get0_private_താക്കോൽ(താക്കോൽ)) == ശൂന്യ)
		fputs("(NULL)", stderr);
	അല്ലെങ്കിൽ
		BN_print_fp(stderr, EC_താക്കോൽ_get0_private_താക്കോൽ(താക്കോൽ));
	fputs("\n", stderr);
}
#endif /* WITH_OPENSSL */

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshkey_private_to_blob2(ഘടന sshkey *prv, ഘടന sshbuf *blob,
    സ്ഥിരം അക്ഷരം *passphrase, സ്ഥിരം അക്ഷരം *comment, സ്ഥിരം അക്ഷരം *ciphername,
    പൂർണ്ണസംഖ്യ rounds)
{
	u_char *cp, *താക്കോൽ = ശൂന്യ, *pubkeyblob = ശൂന്യ;
	u_char salt[SALT_LEN];
	size_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	ഘടന sshcipher_ctx *ciphercontext = ശൂന്യ;
	സ്ഥിരം ഘടന sshcipher *cipher;
	സ്ഥിരം അക്ഷരം *kdfname = KDFNAME;
	ഘടന sshbuf *encoded = ശൂന്യ, *encrypted = ശൂന്യ, *kdf = ശൂന്യ;

	എങ്കിൽ (rounds <= 0)
		rounds = DEFAULT_ROUNDS;
	എങ്കിൽ (rounds > MAX_KDF_ROUNDS) {
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	എങ്കിൽ (passphrase == ശൂന്യ || !strlen(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} അല്ലെങ്കിൽ എങ്കിൽ (ciphername == ശൂന്യ)
		ciphername = DEFAULT_CIPHERNAME;
	എങ്കിൽ ((cipher = cipher_by_name(ciphername)) == ശൂന്യ) {
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}

	എങ്കിൽ ((kdf = sshbuf_new()) == ശൂന്യ ||
	    (encoded = sshbuf_new()) == ശൂന്യ ||
	    (encrypted = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	എങ്കിൽ ((താക്കോൽ = calloc(1, keylen + ivlen)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		എങ്കിൽ (bcrypt_pbkdf(passphrase, strlen(passphrase),
		    salt, SALT_LEN, താക്കോൽ, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_ARGUMENT;
			പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, rounds)) != 0)
			പോകുക out;
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_താക്കോൽ_UNKNOWN_CIPHER;
		പോകുക out;
	}
	എങ്കിൽ ((r = cipher_init(&ciphercontext, cipher, താക്കോൽ, keylen,
	    താക്കോൽ + keylen, ivlen, 1)) != 0)
		പോകുക out;

	എങ്കിൽ ((r = sshbuf_put(encoded, AUTH_MAGIC, വലുപ്പം(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_to_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		പോകുക out;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	എങ്കിൽ ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		പോകുക out;

	/* append private key and comment*/
	എങ്കിൽ ((r = sshkey_private_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		പോകുക out;

	/* padding */
	i = 0;
	ആകുമ്പോൾ (sshbuf_len(encrypted) % blocksize) {
		എങ്കിൽ ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			പോകുക out;
	}

	/* length in destination buffer */
	എങ്കിൽ ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		പോകുക out;

	/* encrypt */
	എങ്കിൽ ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		പോകുക out;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	എങ്കിൽ ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_END, MARK_END_LEN)) != 0)
		പോകുക out;

	/* success */
	r = 0;

 out:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, വലുപ്പം(salt));
	എങ്കിൽ (താക്കോൽ != ശൂന്യ)
		freezero(താക്കോൽ, keylen + ivlen);
	എങ്കിൽ (pubkeyblob != ശൂന്യ)
		freezero(pubkeyblob, pubkeylen);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
private2_uudecode(ഘടന sshbuf *blob, ഘടന sshbuf **decodedp)
{
	സ്ഥിരം u_char *cp;
	size_t encoded_len;
	പൂർണ്ണസംഖ്യ r;
	u_char last;
	ഘടന sshbuf *encoded = ശൂന്യ, *decoded = ശൂന്യ;

	എങ്കിൽ (blob == ശൂന്യ || decodedp == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	*decodedp = ശൂന്യ;

	എങ്കിൽ ((encoded = sshbuf_new()) == ശൂന്യ ||
	    (decoded = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	എങ്കിൽ (encoded_len < (MARK_BEGIN_LEN + MARK_END_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	ആകുമ്പോൾ (encoded_len > 0) {
		എങ്കിൽ (*cp != '\n' && *cp != '\r') {
			എങ്കിൽ ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				പോകുക out;
		}
		last = *cp;
		encoded_len--;
		cp++;
		എങ്കിൽ (last == '\n') {
			എങ്കിൽ (encoded_len >= MARK_END_LEN &&
			    memcmp(cp, MARK_END, MARK_END_LEN) == 0) {
				/* \0 terminate */
				എങ്കിൽ ((r = sshbuf_put_u8(encoded, 0)) != 0)
					പോകുക out;
				നിർത്തുക;
			}
		}
	}
	എങ്കിൽ (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}

	/* decode base64 */
	എങ്കിൽ ((r = sshbuf_b64tod(decoded, (അക്ഷരം *)sshbuf_ptr(encoded))) != 0)
		പോകുക out;

	/* check magic */
	എങ്കിൽ (sshbuf_len(decoded) < വലുപ്പം(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, വലുപ്പം(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	/* success */
	*decodedp = decoded;
	decoded = ശൂന്യ;
	r = 0;
 out:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
private2_decrypt(ഘടന sshbuf *decoded, സ്ഥിരം അക്ഷരം *passphrase,
    ഘടന sshbuf **decryptedp, ഘടന sshkey **pubkeyp)
{
	അക്ഷരം *ciphername = ശൂന്യ, *kdfname = ശൂന്യ;
	സ്ഥിരം ഘടന sshcipher *cipher = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	size_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	ഘടന sshbuf *kdf = ശൂന്യ, *decrypted = ശൂന്യ;
	ഘടന sshcipher_ctx *ciphercontext = ശൂന്യ;
	ഘടന sshkey *pubkey = ശൂന്യ;
	u_char *താക്കോൽ = ശൂന്യ, *salt = ശൂന്യ, *dp;
	u_int blocksize, rounds, nkeys, encrypted_len, check1, check2;

	എങ്കിൽ (decoded == ശൂന്യ || decryptedp == ശൂന്യ || pubkeyp == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	*decryptedp = ശൂന്യ;
	*pubkeyp = ശൂന്യ;

	എങ്കിൽ ((decrypted = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}

	/* parse public portion of key */
	എങ്കിൽ ((r = sshbuf_consume(decoded, വലുപ്പം(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, ശൂന്യ)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		പോകുക out;

	എങ്കിൽ (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}

	എങ്കിൽ ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		പോകുക out;

	എങ്കിൽ ((cipher = cipher_by_name(ciphername)) == ശൂന്യ) {
		r = SSH_ERR_താക്കോൽ_UNKNOWN_CIPHER;
		പോകുക out;
	}
	എങ്കിൽ (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_താക്കോൽ_UNKNOWN_CIPHER;
		പോകുക out;
	}
	എങ്കിൽ (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ ((passphrase == ശൂന്യ || strlen(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE;
		പോകുക out;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	എങ്കിൽ (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	എങ്കിൽ ((താക്കോൽ = calloc(1, keylen + ivlen)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (strcmp(kdfname, "bcrypt") == 0) {
		എങ്കിൽ ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &rounds)) != 0)
			പോകുക out;
		എങ്കിൽ (rounds > MAX_KDF_ROUNDS) {
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		എങ്കിൽ (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, slen,
		    താക്കോൽ, keylen + ivlen, rounds) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
	}

	/* check that an appropriate amount of auth data is present */
	എങ്കിൽ (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}

	/* decrypt private portion of key */
	എങ്കിൽ ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, താക്കോൽ, keylen,
	    താക്കോൽ + keylen, ivlen, 0)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		എങ്കിൽ (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		പോകുക out;
	/* there should be no trailing data */
	എങ്കിൽ (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}

	/* check check bytes */
	എങ്കിൽ ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		പോകുക out;
	എങ്കിൽ (check1 != check2) {
		r = SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE;
		പോകുക out;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = ശൂന്യ;
	*pubkeyp = pubkey;
	pubkey = ശൂന്യ;
	r = 0;
 out:
	cipher_free(ciphercontext);
	സ്വതന്ത്രം(ciphername);
	സ്വതന്ത്രം(kdfname);
	sshkey_free(pubkey);
	എങ്കിൽ (salt != ശൂന്യ) {
		explicit_bzero(salt, slen);
		സ്വതന്ത്രം(salt);
	}
	എങ്കിൽ (താക്കോൽ != ശൂന്യ) {
		explicit_bzero(താക്കോൽ, keylen + ivlen);
		സ്വതന്ത്രം(താക്കോൽ);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshkey_parse_private2(ഘടന sshbuf *blob, പൂർണ്ണസംഖ്യ type, സ്ഥിരം അക്ഷരം *passphrase,
    ഘടന sshkey **keyp, അക്ഷരം **commentp)
{
	അക്ഷരം *comment = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	ഘടന sshbuf *decoded = ശൂന്യ, *decrypted = ശൂന്യ;
	ഘടന sshkey *k = ശൂന്യ, *pubkey = ശൂന്യ;

	എങ്കിൽ (keyp != ശൂന്യ)
		*keyp = ശൂന്യ;
	എങ്കിൽ (commentp != ശൂന്യ)
		*commentp = ശൂന്യ;

	/* Undo base64 encoding and decrypt the private section */
	എങ്കിൽ ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		പോകുക out;

	എങ്കിൽ (type != താക്കോൽ_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_താക്കോൽ_TYPE_MISMATCH;
		പോകുക out;
	}

	/* Load the private key and comment */
	എങ്കിൽ ((r = sshkey_private_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, ശൂന്യ)) != 0)
		പോകുക out;

	/* Check deterministic padding after private section */
	എങ്കിൽ ((r = private2_check_padding(decrypted)) != 0)
		പോകുക out;

	/* Check that the public key in the envelope matches the private key */
	എങ്കിൽ (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}

	/* success */
	r = 0;
	എങ്കിൽ (keyp != ശൂന്യ) {
		*keyp = k;
		k = ശൂന്യ;
	}
	എങ്കിൽ (commentp != ശൂന്യ) {
		*commentp = comment;
		comment = ശൂന്യ;
	}
 out:
	സ്വതന്ത്രം(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshkey_parse_private2_pubkey(ഘടന sshbuf *blob, പൂർണ്ണസംഖ്യ type,
    ഘടന sshkey **keyp)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	ഘടന sshbuf *decoded = ശൂന്യ;
	ഘടന sshkey *pubkey = ശൂന്യ;
	u_int nkeys = 0;

	എങ്കിൽ (keyp != ശൂന്യ)
		*keyp = ശൂന്യ;

	എങ്കിൽ ((r = private2_uudecode(blob, &decoded)) != 0)
		പോകുക out;
	/* parse public key from unencrypted envelope */
	എങ്കിൽ ((r = sshbuf_consume(decoded, വലുപ്പം(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		പോകുക out;

	എങ്കിൽ (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}

	/* Parse the public key */
	എങ്കിൽ ((r = sshkey_froms(decoded, &pubkey)) != 0)
		പോകുക out;

	എങ്കിൽ (type != താക്കോൽ_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_താക്കോൽ_TYPE_MISMATCH;
		പോകുക out;
	}

	/* success */
	r = 0;
	എങ്കിൽ (keyp != ശൂന്യ) {
		*keyp = pubkey;
		pubkey = ശൂന്യ;
	}
 out:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	തിരികെ r;
}

#ifdef WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
സ്ഥിതം പൂർണ്ണസംഖ്യ
sshkey_private_to_blob_pem_pkcs8(ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *buf,
    പൂർണ്ണസംഖ്യ format, സ്ഥിരം അക്ഷരം *_passphrase, സ്ഥിരം അക്ഷരം *comment)
{
	പൂർണ്ണസംഖ്യ was_shielded = sshkey_is_shielded(താക്കോൽ);
	പൂർണ്ണസംഖ്യ success, r;
	പൂർണ്ണസംഖ്യ blen, len = strlen(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : ശൂന്യ;
	സ്ഥിരം EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : ശൂന്യ;
	അക്ഷരം *bptr;
	BIO *bio = ശൂന്യ;
	ഘടന sshbuf *blob;
	EVP_PKEY *pkey = ശൂന്യ;

	എങ്കിൽ (len > 0 && len <= 4)
		തിരികെ SSH_ERR_PASSPHRASE_TOO_SHORT;
	എങ്കിൽ ((blob = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((bio = BIO_new(BIO_s_mem())) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshkey_unshield_private(താക്കോൽ)) != 0)
		പോകുക out;

	തിരഞ്ഞെടുപ്പ് (താക്കോൽ->type) {
	അവസ്ഥ താക്കോൽ_ECDSA:
		എങ്കിൽ (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_ECPrivate_താക്കോൽ(bio,
			    EVP_PKEY_get0_EC_താക്കോൽ(താക്കോൽ->pkey),
			    cipher, passphrase, len, ശൂന്യ, ശൂന്യ);
		} അല്ലെങ്കിൽ {
			pkey = താക്കോൽ->pkey;
			EVP_PKEY_up_ref(താക്കോൽ->pkey);
			success = 1;
		}
		നിർത്തുക;
	അവസ്ഥ താക്കോൽ_RSA:
		എങ്കിൽ (format == SSHKEY_PRIVATE_PEM) {
			success = PEM_write_bio_RSAPrivate_താക്കോൽ(bio,
			    EVP_PKEY_get0_RSA(താക്കോൽ->pkey),
			    cipher, passphrase, len, ശൂന്യ, ശൂന്യ);
		} അല്ലെങ്കിൽ {
			pkey = താക്കോൽ->pkey;
			EVP_PKEY_up_ref(താക്കോൽ->pkey);
			success = 1;
		}
		നിർത്തുക;
#ifdef OPENSSL_HAS_ED25519
	അവസ്ഥ താക്കോൽ_ED25519:
		എങ്കിൽ (format == SSHKEY_PRIVATE_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		} അല്ലെങ്കിൽ {
			pkey = EVP_PKEY_new_raw_private_താക്കോൽ(EVP_PKEY_ED25519,
			    ശൂന്യ, താക്കോൽ->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != ശൂന്യ;
		}
		നിർത്തുക;
#endif
	സ്ഥിരസ്ഥിതി:
		success = 0;
		നിർത്തുക;
	}
	എങ്കിൽ (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	എങ്കിൽ (format == SSHKEY_PRIVATE_PKCS8) {
		എങ്കിൽ ((success = PEM_write_bio_Private_താക്കോൽ(bio, pkey, cipher,
		    passphrase, len, ശൂന്യ, ശൂന്യ)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			പോകുക out;
		}
	}
	എങ്കിൽ ((blen = BIO_get_mem_data(bio, &bptr)) <= 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put(blob, bptr, blen)) != 0)
		പോകുക out;
	r = 0;
 out:
	എങ്കിൽ (was_shielded)
		r = sshkey_shield_private(താക്കോൽ);
	എങ്കിൽ (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	തിരികെ r;
}
#endif /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
പൂർണ്ണസംഖ്യ
sshkey_private_to_fileblob(ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *blob,
    സ്ഥിരം അക്ഷരം *passphrase, സ്ഥിരം അക്ഷരം *comment,
    പൂർണ്ണസംഖ്യ format, സ്ഥിരം അക്ഷരം *openssh_format_cipher, പൂർണ്ണസംഖ്യ openssh_format_rounds)
{
	തിരഞ്ഞെടുപ്പ് (താക്കോൽ->type) {
#ifdef WITH_OPENSSL
	അവസ്ഥ താക്കോൽ_ECDSA:
	അവസ്ഥ താക്കോൽ_RSA:
	അവസ്ഥ താക്കോൽ_ED25519:
		നിർത്തുക; /* see below */
#അല്ലെങ്കിൽ /* WITH_OPENSSL */
	അവസ്ഥ താക്കോൽ_ED25519:
#endif /* WITH_OPENSSL */
	അവസ്ഥ താക്കോൽ_ED25519_SK:
#ifdef WITH_OPENSSL
	അവസ്ഥ താക്കോൽ_ECDSA_SK:
#endif /* WITH_OPENSSL */
	അവസ്ഥ താക്കോൽ_MLDSA44_ED25519:
		തിരികെ sshkey_private_to_blob2(താക്കോൽ, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	സ്ഥിരസ്ഥിതി:
		തിരികെ SSH_ERR_താക്കോൽ_TYPE_UNKNOWN;
	}

#ifdef WITH_OPENSSL
	തിരഞ്ഞെടുപ്പ് (format) {
	അവസ്ഥ SSHKEY_PRIVATE_OPENSSH:
		തിരികെ sshkey_private_to_blob2(താക്കോൽ, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_rounds);
	അവസ്ഥ SSHKEY_PRIVATE_PEM:
	അവസ്ഥ SSHKEY_PRIVATE_PKCS8:
		തിരികെ sshkey_private_to_blob_pem_pkcs8(താക്കോൽ, blob,
		    format, passphrase, comment);
	സ്ഥിരസ്ഥിതി:
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	}
#endif /* WITH_OPENSSL */
}

#ifdef WITH_OPENSSL
സ്ഥിതം പൂർണ്ണസംഖ്യ
translate_libcrypto_error(unsigned long pem_err)
{
	പൂർണ്ണസംഖ്യ pem_reason = ERR_GET_REASON(pem_err);

	തിരഞ്ഞെടുപ്പ് (ERR_GET_LIB(pem_err)) {
	അവസ്ഥ ERR_LIB_PEM:
		തിരഞ്ഞെടുപ്പ് (pem_reason) {
		അവസ്ഥ PEM_R_BAD_PASSWORD_READ:
#ifdef PEM_R_PROBLEMS_GETTING_PASSWORD
		അവസ്ഥ PEM_R_PROBLEMS_GETTING_PASSWORD:
#endif
#ifdef PEM_R_BAD_DECRYPT
		അവസ്ഥ PEM_R_BAD_DECRYPT:
#endif
			തിരികെ SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE;
		സ്ഥിരസ്ഥിതി:
			തിരികെ SSH_ERR_INVALID_FORMAT;
		}
	അവസ്ഥ ERR_LIB_EVP:
		തിരഞ്ഞെടുപ്പ് (pem_reason) {
#ifdef EVP_R_BAD_DECRYPT
		അവസ്ഥ EVP_R_BAD_DECRYPT:
			തിരികെ SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE;
#endif
#ifdef EVP_R_BN_DECODE_ERROR
		അവസ്ഥ EVP_R_BN_DECODE_ERROR:
#endif
		അവസ്ഥ EVP_R_DECODE_ERROR:
#ifdef EVP_R_PRIVATE_താക്കോൽ_DECODE_ERROR
		അവസ്ഥ EVP_R_PRIVATE_താക്കോൽ_DECODE_ERROR:
#endif
			തിരികെ SSH_ERR_INVALID_FORMAT;
		സ്ഥിരസ്ഥിതി:
			തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
		}
	അവസ്ഥ ERR_LIB_ASN1:
#ifdef ERR_LIB_OSSL_DECODER
	അവസ്ഥ ERR_LIB_OSSL_DECODER:
#endif
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
}

സ്ഥിതം ശൂന്യം
clear_libcrypto_errors(ശൂന്യം)
{
	ആകുമ്പോൾ (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
convert_libcrypto_error(ശൂന്യം)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	എങ്കിൽ (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE)
		തിരികെ SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE;
	തിരികെ translate_libcrypto_error(ERR_peek_last_error());
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pem_passphrase_cb(അക്ഷരം *buf, പൂർണ്ണസംഖ്യ size, പൂർണ്ണസംഖ്യ rwflag, ശൂന്യം *u)
{
	അക്ഷരം *p = (അക്ഷരം *)u;
	size_t len;

	എങ്കിൽ (p == ശൂന്യ || (len = strlen(p)) == 0)
		തിരികെ -1;
	എങ്കിൽ (size < 0 || len > (size_t)size)
		തിരികെ -1;
	memcpy(buf, p, len);
	തിരികെ (പൂർണ്ണസംഖ്യ)len;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshkey_parse_private_pem_fileblob(ഘടന sshbuf *blob, പൂർണ്ണസംഖ്യ type,
    സ്ഥിരം അക്ഷരം *passphrase, ഘടന sshkey **keyp)
{
	EVP_PKEY *pk = ശൂന്യ;
	ഘടന sshkey *prv = ശൂന്യ;
	BIO *bio = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;
	RSA *rsa = ശൂന്യ;
	EC_താക്കോൽ *ecdsa = ശൂന്യ;

	എങ്കിൽ (keyp != ശൂന്യ)
		*keyp = ശൂന്യ;

	എങ്കിൽ ((bio = BIO_new(BIO_s_mem())) == ശൂന്യ || sshbuf_len(blob) > INT_MAX)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (പൂർണ്ണസംഖ്യ)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}

	clear_libcrypto_errors();
	എങ്കിൽ ((pk = PEM_read_bio_Private_താക്കോൽ(bio, ശൂന്യ, pem_passphrase_cb,
	    (അക്ഷരം *)passphrase)) == ശൂന്യ) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		എങ്കിൽ (passphrase != ശൂന്യ && *passphrase != '\0')
			r = SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE;
		അല്ലെങ്കിൽ
			r = convert_libcrypto_error();
		പോകുക out;
	}
	എങ്കിൽ (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA &&
	    (type == താക്കോൽ_UNSPEC || type == താക്കോൽ_RSA)) {
		എങ്കിൽ ((prv = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		എങ്കിൽ ((rsa = EVP_PKEY_get1_RSA(pk)) == ശൂന്യ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			പോകുക out;
		}
		prv->type = താക്കോൽ_RSA;
#ifdef DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#endif
		എങ്കിൽ (RSA_blinding_on(rsa, ശൂന്യ) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			പോകുക out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
		എങ്കിൽ ((r = sshkey_check_rsa_length(prv, 0)) != 0)
			പോകുക out;
	} അല്ലെങ്കിൽ എങ്കിൽ (EVP_PKEY_base_id(pk) == EVP_PKEY_EC &&
	    (type == താക്കോൽ_UNSPEC || type == താക്കോൽ_ECDSA)) {
		എങ്കിൽ ((prv = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		എങ്കിൽ ((prv->ecdsa_nid = sshkey_ecdsa_fixup_group(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_താക്കോൽ(pk)) == ശൂന്യ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			പോകുക out;
		}
		prv->type = താക്കോൽ_ECDSA;
		എങ്കിൽ (sshkey_curve_nid_to_name(prv->ecdsa_nid) == ശൂന്യ ||
		    sshkey_ec_validate_public(EC_താക്കോൽ_get0_group(ecdsa),
		    EC_താക്കോൽ_get0_public_താക്കോൽ(ecdsa)) != 0 ||
		    sshkey_ec_validate_private(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		EVP_PKEY_up_ref(pk);
		prv->pkey = pk;
#ifdef DEBUG_PK
		എങ്കിൽ (prv != ശൂന്യ && prv->pkey != ശൂന്യ)
			sshkey_dump_ec_താക്കോൽ(EVP_PKEY_get0_EC_താക്കോൽ(prv->pkey));
#endif
#ifdef OPENSSL_HAS_ED25519
	} അല്ലെങ്കിൽ എങ്കിൽ (EVP_PKEY_base_id(pk) == EVP_PKEY_ED25519 &&
	    (type == താക്കോൽ_UNSPEC || type == താക്കോൽ_ED25519)) {
		size_t len;

		എങ്കിൽ ((prv = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ ||
		    (prv->ed25519_sk = calloc(1, ED25519_SK_SZ)) == ശൂന്യ ||
		    (prv->ed25519_pk = calloc(1, ED25519_PK_SZ)) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		prv->type = താക്കോൽ_ED25519;
		len = ED25519_PK_SZ;
		എങ്കിൽ (!EVP_PKEY_get_raw_public_താക്കോൽ(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			പോകുക out;
		}
		എങ്കിൽ (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		എങ്കിൽ (!EVP_PKEY_get_raw_private_താക്കോൽ(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			പോകുക out;
		}
		എങ്കിൽ (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		/* Append the public key to our private key */
		memcpy(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#ifdef DEBUG_PK
		sshbuf_dump_data(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#endif
#endif /* OPENSSL_HAS_ED25519 */
	} അല്ലെങ്കിൽ {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	r = 0;
	എങ്കിൽ (keyp != ശൂന്യ) {
		*keyp = prv;
		prv = ശൂന്യ;
	}
 out:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_താക്കോൽ_free(ecdsa);
	sshkey_free(prv);
	തിരികെ r;
}
#endif /* WITH_OPENSSL */

പൂർണ്ണസംഖ്യ
sshkey_parse_private_fileblob_type(ഘടന sshbuf *blob, പൂർണ്ണസംഖ്യ type,
    സ്ഥിരം അക്ഷരം *passphrase, ഘടന sshkey **keyp, അക്ഷരം **commentp)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (keyp != ശൂന്യ)
		*keyp = ശൂന്യ;
	എങ്കിൽ (commentp != ശൂന്യ)
		*commentp = ശൂന്യ;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	എങ്കിൽ (r != SSH_ERR_INVALID_FORMAT)
		തിരികെ r;
#ifdef WITH_OPENSSL
	തിരികെ sshkey_parse_private_pem_fileblob(blob, type,
	    passphrase, keyp);
#അല്ലെങ്കിൽ
	തിരികെ SSH_ERR_INVALID_FORMAT;
#endif /* WITH_OPENSSL */
}

പൂർണ്ണസംഖ്യ
sshkey_parse_private_fileblob(ഘടന sshbuf *buffer, സ്ഥിരം അക്ഷരം *passphrase,
    ഘടന sshkey **keyp, അക്ഷരം **commentp)
{
	എങ്കിൽ (keyp != ശൂന്യ)
		*keyp = ശൂന്യ;
	എങ്കിൽ (commentp != ശൂന്യ)
		*commentp = ശൂന്യ;

	തിരികെ sshkey_parse_private_fileblob_type(buffer, താക്കോൽ_UNSPEC,
	    passphrase, keyp, commentp);
}

ശൂന്യം
sshkey_sig_details_free(ഘടന sshkey_sig_details *details)
{
	freezero(details, വലുപ്പം(*details));
}

പൂർണ്ണസംഖ്യ
sshkey_parse_pubkey_from_private_fileblob_type(ഘടന sshbuf *blob, പൂർണ്ണസംഖ്യ type,
    ഘടന sshkey **pubkeyp)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (pubkeyp != ശൂന്യ)
		*pubkeyp = ശൂന്യ;
	/* only new-format private keys bundle a public key inside */
	എങ്കിൽ ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		തിരികെ r;
	തിരികെ 0;
}
