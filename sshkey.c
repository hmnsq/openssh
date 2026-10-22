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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/mman.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/err.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/pem.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <resolv.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <util.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHKEY_ਅੰਦਰੂਨੀ
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-sk.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-pkcs11.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MARK_ਸਿਰਾ		"-----END OPENSSH PRIVATE KEY-----\n"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MARK_BEGIN_LEN		(ਆਕਾਰ(MARK_BEGIN) - 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MARK_ਸਿਰਾ_LEN		(ਆਕਾਰ(MARK_ਸਿਰਾ) - 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KDFNAME			"bcrypt"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AUTH_MAGIC		"openssh-key-v1"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SALT_LEN		16
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DEFAULT_CIPHERNAME	"aes256-ctr"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	DEFAULT_ਗੇੜ		32
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	MAX_KDF_ਗੇੜ		(1<<20)

/*
 * Constants relating to "shielding" support; protection of keys expected
 * to remain in memory for long durations
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHKEY_SHIELD_PREKEY_LEN	(16 * 1024)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHKEY_SHIELD_CIPHER		"aes256-ctr" /* XXX want AES-EME* */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHKEY_SHIELD_PREKEY_HASH	SSH_DIGEST_SHA512

ਸਥਿਰ ਪੂਰਨ sshkey_from_blob_ਅੰਦਰੂਨੀ(ਬਣਤਰ sshbuf *buf,
    ਬਣਤਰ sshkey **keyp, ਪੂਰਨ allow_cert,
    ਅਚਲ ਅੱਖਰ *alg_allowlist, ਅਚਲ ਅੱਖਰ *ca_sigalg_allowlist);

/* Supported key types */
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ed25519_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ed25519_cert_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ed25519_sk_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_mldsa44_ed25519_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
# ifdef ENABLE_SK
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_sk_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_sk_cert_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_nistp256_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_nistp384_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_nistp521_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_rsa_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_rsa_cert_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_rsa_sha256_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_rsa_sha256_cert_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_rsa_sha512_impl;
ਬਾਹਰੀ ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_rsa_sha512_cert_impl;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਅਚਲ ਬਣਤਰ sshkey_impl * ਅਚਲ keyimpls[] = {
	&sshkey_ed25519_impl,
	&sshkey_ed25519_cert_impl,
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_SK
	&sshkey_ed25519_sk_impl,
	&sshkey_ed25519_sk_cert_impl,
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_MLDSA
	&sshkey_mldsa44_ed25519_impl,
	&sshkey_mldsa44_ed25519_cert_impl,
#ਜੇ_ਅੰਤ /* USE_MLDSA */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
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
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਨਿਰਾ
};

ਸਥਿਰ ਅਚਲ ਬਣਤਰ sshkey_impl *
sshkey_impl_from_type(ਪੂਰਨ type)
{
	ਪੂਰਨ i;

	ਲਈ (i = 0; keyimpls[i] != ਨਿਰਾ; i++) {
		ਜੇ (keyimpls[i]->type == type)
			ਵਾਪਸ keyimpls[i];
	}
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ ਅਚਲ ਬਣਤਰ sshkey_impl *
sshkey_impl_from_type_nid(ਪੂਰਨ type, ਪੂਰਨ nid)
{
	ਪੂਰਨ i;

	ਲਈ (i = 0; keyimpls[i] != ਨਿਰਾ; i++) {
		ਜੇ (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			ਵਾਪਸ keyimpls[i];
	}
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ ਅਚਲ ਬਣਤਰ sshkey_impl *
sshkey_impl_from_ਕੁੰਜੀ(ਅਚਲ ਬਣਤਰ sshkey *k)
{
	ਜੇ (k == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਵਾਪਸ sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

ਅਚਲ ਅੱਖਰ *
sshkey_type(ਅਚਲ ਬਣਤਰ sshkey *k)
{
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;

	ਜੇ ((impl = sshkey_impl_from_ਕੁੰਜੀ(k)) == ਨਿਰਾ)
		ਵਾਪਸ "unknown";
	ਵਾਪਸ impl->shortname;
}

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
sshkey_ssh_name_from_type_nid(ਪੂਰਨ type, ਪੂਰਨ nid)
{
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;

	ਜੇ ((impl = sshkey_impl_from_type_nid(type, nid)) == ਨਿਰਾ)
		ਵਾਪਸ "ssh-unknown";
	ਵਾਪਸ impl->name;
}

ਪੂਰਨ
sshkey_type_is_cert(ਪੂਰਨ type)
{
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;

	ਜੇ ((impl = sshkey_impl_from_type(type)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਵਾਪਸ impl->cert;
}

ਅਚਲ ਅੱਖਰ *
sshkey_ssh_name(ਅਚਲ ਬਣਤਰ sshkey *k)
{
	ਵਾਪਸ sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

ਅਚਲ ਅੱਖਰ *
sshkey_ssh_name_plain(ਅਚਲ ਬਣਤਰ sshkey *k)
{
	ਵਾਪਸ sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

ਸਥਿਰ ਪੂਰਨ
type_from_name(ਅਚਲ ਅੱਖਰ *name, ਪੂਰਨ allow_short)
{
	ਪੂਰਨ i;
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;

	ਲਈ (i = 0; keyimpls[i] != ਨਿਰਾ; i++) {
		impl = keyimpls[i];
		ਜੇ (impl->name != ਨਿਰਾ && strcmp(name, impl->name) == 0)
			ਵਾਪਸ impl->type;
		/* Only allow shortname matches for plain key types */
		ਜੇ (allow_short && !impl->cert && impl->shortname != ਨਿਰਾ &&
		    strcasecmp(impl->shortname, name) == 0)
			ਵਾਪਸ impl->type;
	}
	ਵਾਪਸ ਕੁੰਜੀ_UNSPEC;
}

ਪੂਰਨ
sshkey_type_from_name(ਅਚਲ ਅੱਖਰ *name)
{
	ਵਾਪਸ type_from_name(name, 0);
}

ਪੂਰਨ
sshkey_type_from_shortname(ਅਚਲ ਅੱਖਰ *name)
{
	ਵਾਪਸ type_from_name(name, 1);
}

ਸਥਿਰ ਪੂਰਨ
ਕੁੰਜੀ_type_is_ecdsa_variant(ਪੂਰਨ type)
{
	ਚੋਣ (type) {
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_CERT:
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK_CERT:
		ਵਾਪਸ 1;
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshkey_ecdsa_nid_from_name(ਅਚਲ ਅੱਖਰ *name)
{
	ਪੂਰਨ i;

	ਲਈ (i = 0; keyimpls[i] != ਨਿਰਾ; i++) {
		ਜੇ (!ਕੁੰਜੀ_type_is_ecdsa_variant(keyimpls[i]->type))
			ਜਾਰੀ;
		ਜੇ (keyimpls[i]->name != ਨਿਰਾ &&
		    strcmp(name, keyimpls[i]->name) == 0)
			ਵਾਪਸ keyimpls[i]->nid;
	}
	ਵਾਪਸ -1;
}

ਪੂਰਨ
sshkey_ਮੇਲ_keyname_ਮੰਜ਼ਿਲ_sigalgs(ਅਚਲ ਅੱਖਰ *keyname, ਅਚਲ ਅੱਖਰ *sigalgs)
{
	ਪੂਰਨ ktype;

	ਜੇ (sigalgs == ਨਿਰਾ || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == ਕੁੰਜੀ_UNSPEC)
		ਵਾਪਸ 0;
	ਨਹੀਂਤਾਂ ਜੇ (ktype == ਕੁੰਜੀ_RSA) {
		ਵਾਪਸ ਮੇਲ_ਨਮੂਨਾ_list("ssh-rsa", sigalgs, 0) == 1 ||
		    ਮੇਲ_ਨਮੂਨਾ_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    ਮੇਲ_ਨਮੂਨਾ_list("rsa-sha2-512", sigalgs, 0) == 1;
	} ਨਹੀਂਤਾਂ ਜੇ (ktype == ਕੁੰਜੀ_RSA_CERT) {
		ਵਾਪਸ ਮੇਲ_ਨਮੂਨਾ_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    ਮੇਲ_ਨਮੂਨਾ_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    ਮੇਲ_ਨਮੂਨਾ_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} ਨਹੀਂਤਾਂ ਜੇ (ktype == ਕੁੰਜੀ_ECDSA_SK) {
		ਵਾਪਸ ਮੇਲ_ਨਮੂਨਾ_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || ਮੇਲ_ਨਮੂਨਾ_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} ਨਹੀਂਤਾਂ ਜੇ (ktype == ਕੁੰਜੀ_ECDSA_SK_CERT) {
		ਵਾਪਸ ਮੇਲ_ਨਮੂਨਾ_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || ਮੇਲ_ਨਮੂਨਾ_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} ਨਹੀਂਤਾਂ
		ਵਾਪਸ ਮੇਲ_ਨਮੂਨਾ_list(keyname, sigalgs, 0) == 1;
}

ਅੱਖਰ *
sshkey_alg_list(ਪੂਰਨ certs_only, ਪੂਰਨ plain_only, ਪੂਰਨ include_sigonly, ਅੱਖਰ sep)
{
	ਅੱਖਰ *ret = ਨਿਰਾ;
	ਮਾਪ_t i;
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;
	ਅੱਖਰ sep_str[2] = {sep, '\0'};

	ਲਈ (i = 0; keyimpls[i] != ਨਿਰਾ; i++) {
		impl = keyimpls[i];
		ਜੇ (impl->name == ਨਿਰਾ)
			ਜਾਰੀ;
		ਜੇ (!include_sigonly && impl->sigonly)
			ਜਾਰੀ;
		ਜੇ ((certs_only && !impl->cert) || (plain_only && impl->cert))
			ਜਾਰੀ;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sshkey_ਨਾਂ_valid2(ਅਚਲ ਅੱਖਰ *ਨਾਂ, ਪੂਰਨ allow_wildcard, ਪੂਰਨ plain_only)
{
	ਅੱਖਰ *s, *cp, *p;
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;
	ਪੂਰਨ i, type;

	ਜੇ (ਨਾਂ == ਨਿਰਾ || strcmp(ਨਾਂ, "") == 0)
		ਵਾਪਸ 0;
	ਜੇ ((s = cp = strdup(ਨਾਂ)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਲਈ ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		ਜੇ (type == ਕੁੰਜੀ_UNSPEC) {
			ਜੇ (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = ਨਿਰਾ;
				ਲਈ (i = 0; keyimpls[i] != ਨਿਰਾ; i++) {
					ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						ਰੋਕੋ;
					}
				}
				ਜੇ (impl != ਨਿਰਾ)
					ਜਾਰੀ;
			}
			ਮੁਕਤ(s);
			ਵਾਪਸ 0;
		} ਨਹੀਂਤਾਂ ਜੇ (plain_only && sshkey_type_is_cert(type)) {
			ਮੁਕਤ(s);
			ਵਾਪਸ 0;
		}
	}
	ਮੁਕਤ(s);
	ਵਾਪਸ 1;
}

u_int
sshkey_ਮਾਪ(ਅਚਲ ਬਣਤਰ sshkey *k)
{
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;

	ਜੇ ((impl = sshkey_impl_from_ਕੁੰਜੀ(k)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (impl->funcs->ਮਾਪ != ਨਿਰਾ)
		ਵਾਪਸ impl->funcs->ਮਾਪ(k);
	ਵਾਪਸ impl->keybits;
}

ਸਥਿਰ ਪੂਰਨ
sshkey_type_is_valid_ca(ਪੂਰਨ type)
{
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;

	ਜੇ ((impl = sshkey_impl_from_type(type)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	/* All non-certificate types may act as CAs */
	ਵਾਪਸ !impl->cert;
}

ਪੂਰਨ
sshkey_is_cert(ਅਚਲ ਬਣਤਰ sshkey *k)
{
	ਜੇ (k == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਵਾਪਸ sshkey_type_is_cert(k->type);
}

ਪੂਰਨ
sshkey_is_sk(ਅਚਲ ਬਣਤਰ sshkey *k)
{
	ਜੇ (k == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਚੋਣ (sshkey_type_plain(k->type)) {
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
	ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK:
		ਵਾਪਸ 1;
	ਮੂਲ:
		ਵਾਪਸ 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
ਪੂਰਨ
sshkey_type_plain(ਪੂਰਨ type)
{
	ਚੋਣ (type) {
	ਹਾਲਤ ਕੁੰਜੀ_RSA_CERT:
		ਵਾਪਸ ਕੁੰਜੀ_RSA;
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_CERT:
		ਵਾਪਸ ਕੁੰਜੀ_ECDSA;
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK_CERT:
		ਵਾਪਸ ਕੁੰਜੀ_ECDSA_SK;
	ਹਾਲਤ ਕੁੰਜੀ_ED25519_CERT:
		ਵਾਪਸ ਕੁੰਜੀ_ED25519;
	ਹਾਲਤ ਕੁੰਜੀ_MLDSA44_ED25519_CERT:
		ਵਾਪਸ ਕੁੰਜੀ_MLDSA44_ED25519;
	ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK_CERT:
		ਵਾਪਸ ਕੁੰਜੀ_ED25519_SK;
	ਮੂਲ:
		ਵਾਪਸ type;
	}
}

/* Return the cert equivalent to a plain key type */
ਸਥਿਰ ਪੂਰਨ
sshkey_type_certified(ਪੂਰਨ type)
{
	ਚੋਣ (type) {
	ਹਾਲਤ ਕੁੰਜੀ_RSA:
		ਵਾਪਸ ਕੁੰਜੀ_RSA_CERT;
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
		ਵਾਪਸ ਕੁੰਜੀ_ECDSA_CERT;
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
		ਵਾਪਸ ਕੁੰਜੀ_ECDSA_SK_CERT;
	ਹਾਲਤ ਕੁੰਜੀ_ED25519:
		ਵਾਪਸ ਕੁੰਜੀ_ED25519_CERT;
	ਹਾਲਤ ਕੁੰਜੀ_MLDSA44_ED25519:
		ਵਾਪਸ ਕੁੰਜੀ_MLDSA44_ED25519_CERT;
	ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK:
		ਵਾਪਸ ਕੁੰਜੀ_ED25519_SK_CERT;
	ਮੂਲ:
		ਵਾਪਸ -1;
	}
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਸਥਿਰ ਅਚਲ EVP_MD *
ssh_digest_ਮੰਜ਼ਿਲ_md(ਪੂਰਨ hash_alg)
{
	ਚੋਣ (hash_alg) {
	ਹਾਲਤ SSH_DIGEST_SHA1:
		ਵਾਪਸ EVP_sha1();
	ਹਾਲਤ SSH_DIGEST_SHA256:
		ਵਾਪਸ EVP_sha256();
	ਹਾਲਤ SSH_DIGEST_SHA384:
		ਵਾਪਸ EVP_sha384();
	ਹਾਲਤ SSH_DIGEST_SHA512:
		ਵਾਪਸ EVP_sha512();
	}
	ਵਾਪਸ ਨਿਰਾ;
}

ਪੂਰਨ
sshkey_pkey_digest_sign(EVP_PKEY *pkey, ਪੂਰਨ hash_alg, u_char **sigp,
    ਮਾਪ_t *lenp, ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen)
{
	EVP_MD_CTX *ctx = ਨਿਰਾ;
	u_char *sig = ਨਿਰਾ;
	ਪੂਰਨ ret;
	ਮਾਪ_t slen;
	ਅਚਲ EVP_MD *evpmd;

	*sigp = ਨਿਰਾ;
	*lenp = 0;

	slen = EVP_PKEY_ਮਾਪ(pkey);
	ਜੇ (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_ਮੰਜ਼ਿਲ_md(hash_alg)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	ਜੇ ((sig = ਸਮ੍ਰਿਤੀ_ਦਿਓ(slen)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;

	ਜੇ ((ctx = EVP_MD_CTX_new()) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_DigestSignInit(ctx, ਨਿਰਾ, evpmd, ਨਿਰਾ, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, ਅੰਕੜੇ, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = ਨਿਰਾ;
	ret = 0;

 ਬਾਹਰਲਾ:
	EVP_MD_CTX_free(ctx);
	ਮੁਕਤ(sig);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sshkey_pkey_digest_verify(EVP_PKEY *pkey, ਪੂਰਨ hash_alg, ਅਚਲ u_char *ਅੰਕੜੇ,
    ਮਾਪ_t datalen, u_char *sigbuf, ਮਾਪ_t siglen)
{
	EVP_MD_CTX *ctx = ਨਿਰਾ;
	ਪੂਰਨ ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਅਚਲ EVP_MD *evpmd;

	ਜੇ ((evpmd = ssh_digest_ਮੰਜ਼ਿਲ_md(hash_alg)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((ctx = EVP_MD_CTX_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ (EVP_DigestVerifyInit(ctx, ਨਿਰਾ, evpmd, ਨਿਰਾ, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਚੋਣ (EVP_DigestVerify(ctx, sigbuf, siglen, ਅੰਕੜੇ, datalen)) {
	ਹਾਲਤ 1:
		ret = 0;
		ਰੋਕੋ;
	ਹਾਲਤ 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		ਰੋਕੋ;
	ਮੂਲ:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਰੋਕੋ;
	}

 ਬਾਹਰਲਾ:
	EVP_MD_CTX_free(ctx);
	ਵਾਪਸ ret;
}

/* XXX: these are really begging for a table-driven approach */
ਪੂਰਨ
sshkey_ਵਕਰ_name_ਮੰਜ਼ਿਲ_nid(ਅਚਲ ਅੱਖਰ *name)
{
	ਜੇ (strcmp(name, "nistp256") == 0)
		ਵਾਪਸ NID_X9_62_prime256v1;
	ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "nistp384") == 0)
		ਵਾਪਸ NID_secp384r1;
	ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "nistp521") == 0)
		ਵਾਪਸ NID_secp521r1;
	ਨਹੀਂਤਾਂ
		ਵਾਪਸ -1;
}

u_int
sshkey_ਵਕਰ_nid_ਮੰਜ਼ਿਲ_ਬਿੱਟ(ਪੂਰਨ nid)
{
	ਚੋਣ (nid) {
	ਹਾਲਤ NID_X9_62_prime256v1:
		ਵਾਪਸ 256;
	ਹਾਲਤ NID_secp384r1:
		ਵਾਪਸ 384;
	ਹਾਲਤ NID_secp521r1:
		ਵਾਪਸ 521;
	ਮੂਲ:
		ਵਾਪਸ 0;
	}
}

ਪੂਰਨ
sshkey_ecdsa_ਬਿੱਟ_ਮੰਜ਼ਿਲ_nid(ਪੂਰਨ ਬਿੱਟ)
{
	ਚੋਣ (ਬਿੱਟ) {
	ਹਾਲਤ 256:
		ਵਾਪਸ NID_X9_62_prime256v1;
	ਹਾਲਤ 384:
		ਵਾਪਸ NID_secp384r1;
	ਹਾਲਤ 521:
		ਵਾਪਸ NID_secp521r1;
	ਮੂਲ:
		ਵਾਪਸ -1;
	}
}

ਅਚਲ ਅੱਖਰ *
sshkey_ਵਕਰ_nid_ਮੰਜ਼ਿਲ_name(ਪੂਰਨ nid)
{
	ਚੋਣ (nid) {
	ਹਾਲਤ NID_X9_62_prime256v1:
		ਵਾਪਸ "nistp256";
	ਹਾਲਤ NID_secp384r1:
		ਵਾਪਸ "nistp384";
	ਹਾਲਤ NID_secp521r1:
		ਵਾਪਸ "nistp521";
	ਮੂਲ:
		ਵਾਪਸ ਨਿਰਾ;
	}
}

ਪੂਰਨ
sshkey_ec_nid_ਮੰਜ਼ਿਲ_hash_alg(ਪੂਰਨ nid)
{
	ਪੂਰਨ kbits = sshkey_ਵਕਰ_nid_ਮੰਜ਼ਿਲ_ਬਿੱਟ(nid);

	ਜੇ (kbits <= 0)
		ਵਾਪਸ -1;

	/* RFC5656 section 6.2.1 */
	ਜੇ (kbits <= 256)
		ਵਾਪਸ SSH_DIGEST_SHA256;
	ਨਹੀਂਤਾਂ ਜੇ (kbits <= 384)
		ਵਾਪਸ SSH_DIGEST_SHA384;
	ਨਹੀਂਤਾਂ
		ਵਾਪਸ SSH_DIGEST_SHA512;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਸਥਿਰ ਖਾਲੀ
cert_free(ਬਣਤਰ sshkey_cert *cert)
{
	u_int i;

	ਜੇ (cert == ਨਿਰਾ)
		ਵਾਪਸ;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	ਮੁਕਤ(cert->ਕੁੰਜੀ_id);
	ਲਈ (i = 0; i < cert->nprincipals; i++)
		ਮੁਕਤ(cert->principals[i]);
	ਮੁਕਤ(cert->principals);
	sshkey_free(cert->signature_ਕੁੰਜੀ);
	ਮੁਕਤ(cert->signature_type);
	freezero(cert, ਆਕਾਰ(*cert));
}

ਸਥਿਰ ਬਣਤਰ sshkey_cert *
cert_new(ਖਾਲੀ)
{
	ਬਣਤਰ sshkey_cert *cert;

	ਜੇ ((cert = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*cert))) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਜੇ ((cert->certblob = sshbuf_new()) == ਨਿਰਾ ||
	    (cert->critical = sshbuf_new()) == ਨਿਰਾ ||
	    (cert->extensions = sshbuf_new()) == ਨਿਰਾ) {
		cert_free(cert);
		ਵਾਪਸ ਨਿਰਾ;
	}
	cert->ਕੁੰਜੀ_id = ਨਿਰਾ;
	cert->principals = ਨਿਰਾ;
	cert->signature_ਕੁੰਜੀ = ਨਿਰਾ;
	cert->signature_type = ਨਿਰਾ;
	ਵਾਪਸ cert;
}

ਬਣਤਰ sshkey *
sshkey_new(ਪੂਰਨ type)
{
	ਬਣਤਰ sshkey *k;
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl = ਨਿਰਾ;

	ਜੇ (type != ਕੁੰਜੀ_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;

	/* All non-certificate types may act as CAs */
	ਜੇ ((k = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*k))) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	k->type = type;
	k->ecdsa_nid = -1;
	ਜੇ (impl != ਨਿਰਾ && impl->funcs->alloc != ਨਿਰਾ) {
		ਜੇ (impl->funcs->alloc(k) != 0) {
			ਮੁਕਤ(k);
			ਵਾਪਸ ਨਿਰਾ;
		}
	}
	ਜੇ (sshkey_is_cert(k)) {
		ਜੇ ((k->cert = cert_new()) == ਨਿਰਾ) {
			sshkey_free(k);
			ਵਾਪਸ ਨਿਰਾ;
		}
	}

	ਵਾਪਸ k;
}

/* Frees common FIDO fields */
ਖਾਲੀ
sshkey_sk_cleanup(ਬਣਤਰ sshkey *k)
{
	ਮੁਕਤ(k->sk_application);
	sshbuf_free(k->sk_ਕੁੰਜੀ_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = ਨਿਰਾ;
	k->sk_ਕੁੰਜੀ_handle = k->sk_reserved = ਨਿਰਾ;
}

#ਜੇ defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#ਜਾਂਜੇ defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#ਨਹੀਂਤਾਂ
# define PREKEY_MMAP_FLAG	0
#ਜੇ_ਅੰਤ

ਸਥਿਰ ਪੂਰਨ
sshkey_prekey_alloc(u_char **prekeyp, ਮਾਪ_t len)
{
#ਜੇ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = ਨਿਰਾ;
	ਜੇ ((prekey = mmap(ਨਿਰਾ, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
#ਜੇ defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(ਖਾਲੀ)madvise(prekey, len, MADV_DONTDUMP);
#ਜੇ_ਅੰਤ
	*prekeyp = prekey;
#ਨਹੀਂਤਾਂ
	*prekeyp = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, len);
#ਜੇ_ਅੰਤ /* HAVE_MMAP et al */
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
sshkey_prekey_free(ਖਾਲੀ *prekey, ਮਾਪ_t len)
{
#ਜੇ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	ਜੇ (prekey == ਨਿਰਾ)
		ਵਾਪਸ;
	munmap(prekey, len);
#ਨਹੀਂਤਾਂ
	ਮੁਕਤ(prekey);
#ਜੇ_ਅੰਤ /* HAVE_MMAP et al */
}

ਸਥਿਰ ਖਾਲੀ
sshkey_free_contents(ਬਣਤਰ sshkey *k)
{
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;

	ਜੇ (k == ਨਿਰਾ)
		ਵਾਪਸ;
	ਜੇ ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_ਕੁੰਜੀ_free(k);
	ਜੇ ((impl = sshkey_impl_from_type(k->type)) != ਨਿਰਾ &&
	    impl->funcs->cleanup != ਨਿਰਾ)
		impl->funcs->cleanup(k);
	ਜੇ (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_ਨਿੱਜੀ, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

ਖਾਲੀ
sshkey_free(ਬਣਤਰ sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, ਆਕਾਰ(*k));
}

ਸਥਿਰ ਪੂਰਨ
cert_compare(ਬਣਤਰ sshkey_cert *a, ਬਣਤਰ sshkey_cert *b)
{
	ਜੇ (a == ਨਿਰਾ && b == ਨਿਰਾ)
		ਵਾਪਸ 1;
	ਜੇ (a == ਨਿਰਾ || b == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		ਵਾਪਸ 0;
	ਜੇ (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

/* Compares FIDO-specific pubkey fields only */
ਪੂਰਨ
sshkey_sk_fields_equal(ਅਚਲ ਬਣਤਰ sshkey *a, ਅਚਲ ਬਣਤਰ sshkey *b)
{
	ਜੇ (a->sk_application == ਨਿਰਾ || b->sk_application == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (strcmp(a->sk_application, b->sk_application) != 0)
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
ਪੂਰਨ
sshkey_equal_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *a, ਅਚਲ ਬਣਤਰ sshkey *b)
{
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;

	ਜੇ (a == ਨਿਰਾ || b == ਨਿਰਾ ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		ਵਾਪਸ 0;
	ਜੇ ((impl = sshkey_impl_from_type(a->type)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਵਾਪਸ impl->funcs->equal(a, b);
}

ਪੂਰਨ
sshkey_equal(ਅਚਲ ਬਣਤਰ sshkey *a, ਅਚਲ ਬਣਤਰ sshkey *b)
{
	ਜੇ (a == ਨਿਰਾ || b == ਨਿਰਾ || a->type != b->type)
		ਵਾਪਸ 0;
	ਜੇ (sshkey_is_cert(a)) {
		ਜੇ (!cert_compare(a->cert, b->cert))
			ਵਾਪਸ 0;
	}
	ਵਾਪਸ sshkey_equal_ਜਨਤਕ(a, b);
}


/* Serialise common FIDO key parts */
ਪੂਰਨ
sshkey_serialize_sk(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_put_cstring(b, ਕੁੰਜੀ->sk_application)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਮੰਜ਼ਿਲ_blob_buf(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b, ਪੂਰਨ force_plain,
  ਗਿਣਤੀ sshkey_serialize_rep opts)
{
	ਪੂਰਨ type, ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਅਚਲ ਅੱਖਰ *typename;
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	type = force_plain ? sshkey_type_plain(ਕੁੰਜੀ->type) : ਕੁੰਜੀ->type;

	ਜੇ (sshkey_type_is_cert(type)) {
		ਜੇ (ਕੁੰਜੀ->cert == ਨਿਰਾ)
			ਵਾਪਸ SSH_ERR_EXPECTED_CERT;
		ਜੇ (sshbuf_len(ਕੁੰਜੀ->cert->certblob) == 0)
			ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_LACKS_CERTBLOB;
		/* Use the existing blob */
		ਜੇ ((ret = sshbuf_putb(b, ਕੁੰਜੀ->cert->certblob)) != 0)
			ਵਾਪਸ ret;
		ਵਾਪਸ 0;
	}
	ਜੇ ((impl = sshkey_impl_from_type(type)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, ਕੁੰਜੀ->ecdsa_nid);
	ਜੇ ((ret = sshbuf_put_cstring(b, typename)) != 0)
		ਵਾਪਸ ret;
	ਵਾਪਸ impl->funcs->serialize_ਜਨਤਕ(ਕੁੰਜੀ, b, opts);
}

ਪੂਰਨ
sshkey_putb(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b)
{
	ਵਾਪਸ ਮੰਜ਼ਿਲ_blob_buf(ਕੁੰਜੀ, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

ਸਥਿਰ ਪੂਰਨ
sshkey_puts_opts_ਅੰਦਰੂਨੀ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b,
    ਗਿਣਤੀ sshkey_serialize_rep opts, ਪੂਰਨ force_plain)
{
	ਬਣਤਰ sshbuf *tmp;
	ਪੂਰਨ r;

	ਜੇ ((tmp = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	r = ਮੰਜ਼ਿਲ_blob_buf(ਕੁੰਜੀ, tmp, force_plain, opts);
	ਜੇ (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshkey_puts(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b)
{
	ਵਾਪਸ sshkey_puts_opts_ਅੰਦਰੂਨੀ(ਕੁੰਜੀ, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

ਪੂਰਨ
sshkey_putb_plain(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b)
{
	ਵਾਪਸ ਮੰਜ਼ਿਲ_blob_buf(ਕੁੰਜੀ, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

ਪੂਰਨ
sshkey_puts_plain(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b)
{
	ਵਾਪਸ sshkey_puts_opts_ਅੰਦਰੂਨੀ(ਕੁੰਜੀ, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

ਸਥਿਰ ਪੂਰਨ
ਮੰਜ਼ਿਲ_blob(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, u_char **blobp, ਮਾਪ_t *lenp, ਪੂਰਨ force_plain,
    ਗਿਣਤੀ sshkey_serialize_rep opts)
{
	ਪੂਰਨ ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਮਾਪ_t len;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;

	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	ਜੇ (blobp != ਨਿਰਾ)
		*blobp = ਨਿਰਾ;
	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((ret = ਮੰਜ਼ਿਲ_blob_buf(ਕੁੰਜੀ, b, force_plain, opts)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	len = sshbuf_len(b);
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = len;
	ਜੇ (blobp != ਨਿਰਾ) {
		ਜੇ ((*blobp = ਸਮ੍ਰਿਤੀ_ਦਿਓ(len)) == ਨਿਰਾ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sshkey_ਮੰਜ਼ਿਲ_blob(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, u_char **blobp, ਮਾਪ_t *lenp)
{
	ਵਾਪਸ ਮੰਜ਼ਿਲ_blob(ਕੁੰਜੀ, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

ਪੂਰਨ
sshkey_plain_ਮੰਜ਼ਿਲ_blob(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, u_char **blobp, ਮਾਪ_t *lenp)
{
	ਵਾਪਸ ਮੰਜ਼ਿਲ_blob(ਕੁੰਜੀ, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

ਪੂਰਨ
sshkey_fingerprint_raw(ਅਚਲ ਬਣਤਰ sshkey *k, ਪੂਰਨ dgst_alg,
    u_char **retp, ਮਾਪ_t *lenp)
{
	u_char *blob = ਨਿਰਾ, *ret = ਨਿਰਾ;
	ਮਾਪ_t blob_len = 0;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (retp != ਨਿਰਾ)
		*retp = ਨਿਰਾ;
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	ਜੇ (ssh_digest_ਬਾਈਟਾਂ(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = ਮੰਜ਼ਿਲ_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((ret = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, SSH_DIGEST_MAX_ਲੰਮਾਈ)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = ssh_digest_ਸਮ੍ਰਿਤੀ(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_ਲੰਮਾਈ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	ਜੇ (retp != ਨਿਰਾ) {
		*retp = ret;
		ret = ਨਿਰਾ;
	}
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = ssh_digest_ਬਾਈਟਾਂ(dgst_alg);
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(ret);
	ਜੇ (blob != ਨਿਰਾ)
		freezero(blob, blob_len);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਅੱਖਰ *
fingerprint_b64(ਅਚਲ ਅੱਖਰ *alg, u_char *dgst_raw, ਮਾਪ_t dgst_raw_len)
{
	ਅੱਖਰ *ret;
	ਮਾਪ_t plen = ਲੜੀ_ਲੰਬਾਈ(alg) + 1;
	ਮਾਪ_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	ਜੇ (dgst_raw_len > 65536 || (ret = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, rlen)) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	ਜੇ (dgst_raw_len == 0)
		ਵਾਪਸ ret;
	ਜੇ (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		ਵਾਪਸ ਨਿਰਾ;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਅੱਖਰ *
fingerprint_hex(ਅਚਲ ਅੱਖਰ *alg, u_char *dgst_raw, ਮਾਪ_t dgst_raw_len)
{
	ਅੱਖਰ *retval, hex[5];
	ਮਾਪ_t i, rlen = dgst_raw_len * 3 + ਲੜੀ_ਲੰਬਾਈ(alg) + 2;

	ਜੇ (dgst_raw_len > 65536 || (retval = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, rlen)) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	ਲਈ (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, ਆਕਾਰ(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	ਵਾਪਸ retval;
}

ਸਥਿਰ ਅੱਖਰ *
fingerprint_bubblebabble(u_char *dgst_raw, ਮਾਪ_t dgst_raw_len)
{
	ਅੱਖਰ vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	ਅੱਖਰ consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, ਗੇੜ, ਬੀਜ = 1;
	ਅੱਖਰ *retval;

	ਗੇੜ = (dgst_raw_len / 2) + 1;
	ਜੇ ((retval = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਗੇੜ, 6)) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	retval[j++] = 'x';
	ਲਈ (i = 0; i < ਗੇੜ; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		ਜੇ ((i + 1 < ਗੇੜ) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    ਬੀਜ) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (ਬੀਜ / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			ਜੇ ((i + 1) < ਗੇੜ) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				ਬੀਜ = ((ਬੀਜ * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} ਨਹੀਂਤਾਂ {
			idx0 = ਬੀਜ % 6;
			idx1 = 16;
			idx2 = ਬੀਜ / 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
		}
	}
	retval[j++] = 'x';
	retval[j++] = '\0';
	ਵਾਪਸ retval;
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
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	FLDBASE		8
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	FLDSIZE_Y	(FLDBASE + 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	FLDSIZE_X	(FLDBASE * 2 + 1)
ਸਥਿਰ ਅੱਖਰ *
fingerprint_randomart(ਅਚਲ ਅੱਖਰ *alg, u_char *dgst_raw, ਮਾਪ_t dgst_raw_len,
    ਅਚਲ ਬਣਤਰ sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	ਅੱਖਰ	*augmentation_string = " .o+=*BOX@%&#/^SE";
	ਅੱਖਰ	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 ਖੇਤਰ[FLDSIZE_X][FLDSIZE_Y];
	ਮਾਪ_t	 i, tlen, hlen;
	u_int	 b;
	ਪੂਰਨ	 x, y, r;
	ਮਾਪ_t	 len = ਲੜੀ_ਲੰਬਾਈ(augmentation_string) - 1;

	ਜੇ ((retval = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;

	/* initialize field */
	memset(ਖੇਤਰ, 0, FLDSIZE_X * FLDSIZE_Y * ਆਕਾਰ(ਅੱਖਰ));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	ਲਈ (i = 0; i < dgst_raw_len; i++) {
		ਪੂਰਨ ਨਿਵੇਸ਼;
		/* each byte conveys four 2-bit move commands */
		ਨਿਵੇਸ਼ = dgst_raw[i];
		ਲਈ (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (ਨਿਵੇਸ਼ & 0x1) ? 1 : -1;
			y += (ਨਿਵੇਸ਼ & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = ਵੱਧ_ਤੋਂ_ਵੱਧ(x, 0);
			y = ਵੱਧ_ਤੋਂ_ਵੱਧ(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			ਜੇ (ਖੇਤਰ[x][y] < len - 2)
				ਖੇਤਰ[x][y]++;
			ਨਿਵੇਸ਼ = ਨਿਵੇਸ਼ >> 2;
		}
	}

	/* mark starting point and end point*/
	ਖੇਤਰ[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	ਖੇਤਰ[x][y] = len;

	/* assemble title */
	r = snprintf(title, ਆਕਾਰ(title), "[%s %u]",
		sshkey_type(k), sshkey_ਮਾਪ(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	ਜੇ (r < 0 || r > (ਪੂਰਨ)ਆਕਾਰ(title))
		r = snprintf(title, ਆਕਾਰ(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : ਲੜੀ_ਲੰਬਾਈ(title);

	/* assemble hash ID. */
	r = snprintf(hash, ਆਕਾਰ(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : ਲੜੀ_ਲੰਬਾਈ(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	ਲਈ (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(p, title, tlen);
	p += tlen;
	ਲਈ (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	ਲਈ (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		ਲਈ (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(ਖੇਤਰ[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	ਲਈ (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(p, hash, hlen);
	p += hlen;
	ਲਈ (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	ਵਾਪਸ retval;
}

ਅੱਖਰ *
sshkey_fingerprint(ਅਚਲ ਬਣਤਰ sshkey *k, ਪੂਰਨ dgst_alg,
    ਗਿਣਤੀ sshkey_fp_rep dgst_rep)
{
	ਅੱਖਰ *retval = ਨਿਰਾ;
	u_char *dgst_raw;
	ਮਾਪ_t dgst_raw_len;

	ਜੇ (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		ਵਾਪਸ ਨਿਰਾ;
	ਚੋਣ (dgst_rep) {
	ਹਾਲਤ SSH_FP_DEFAULT:
		ਜੇ (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} ਨਹੀਂਤਾਂ {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		ਰੋਕੋ;
	ਹਾਲਤ SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		ਰੋਕੋ;
	ਹਾਲਤ SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		ਰੋਕੋ;
	ਹਾਲਤ SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		ਰੋਕੋ;
	ਹਾਲਤ SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		ਰੋਕੋ;
	ਮੂਲ:
		freezero(dgst_raw, dgst_raw_len);
		ਵਾਪਸ ਨਿਰਾ;
	}
	freezero(dgst_raw, dgst_raw_len);
	ਵਾਪਸ retval;
}

ਸਥਿਰ ਪੂਰਨ
peek_type_nid(ਅਚਲ ਅੱਖਰ *s, ਮਾਪ_t l, ਪੂਰਨ *nid)
{
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;
	ਪੂਰਨ i;

	ਲਈ (i = 0; keyimpls[i] != ਨਿਰਾ; i++) {
		impl = keyimpls[i];
		ਜੇ (impl->name == ਨਿਰਾ || ਲੜੀ_ਲੰਬਾਈ(impl->name) != l)
			ਜਾਰੀ;
		ਜੇ (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			ਜੇ (ਕੁੰਜੀ_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			ਵਾਪਸ impl->type;
		}
	}
	ਵਾਪਸ ਕੁੰਜੀ_UNSPEC;
}

/* XXX this can now be made const char * */
ਪੂਰਨ
sshkey_read(ਬਣਤਰ sshkey *ret, ਅੱਖਰ **cpp)
{
	ਬਣਤਰ sshkey *k;
	ਅੱਖਰ *cp, *blobcopy;
	ਮਾਪ_t space;
	ਪੂਰਨ r, type, ਵਕਰ_nid = -1;
	ਬਣਤਰ sshbuf *blob;

	ਜੇ (ret == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (ret->type != ਕੁੰਜੀ_UNSPEC && sshkey_impl_from_type(ret->type) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	ਜੇ (space == ਲੜੀ_ਲੰਬਾਈ(cp))
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਜੇ ((type = peek_type_nid(cp, space, &ਵਕਰ_nid)) == ਕੁੰਜੀ_UNSPEC)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	ਲਈ (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	ਜੇ (*cp == '\0')
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਜੇ (ret->type != ਕੁੰਜੀ_UNSPEC && ret->type != type)
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_TYPE_MISMATCH;
	ਜੇ ((blob = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	ਜੇ ((blobcopy = strndup(cp, space)) == ਨਿਰਾ) {
		sshbuf_free(blob);
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	}
	ਜੇ ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		ਮੁਕਤ(blobcopy);
		sshbuf_free(blob);
		ਵਾਪਸ r;
	}
	ਮੁਕਤ(blobcopy);
	ਜੇ ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		ਵਾਪਸ r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	ਲਈ (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	ਜੇ (k->type != type) {
		sshkey_free(k);
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_TYPE_MISMATCH;
	}
	ਜੇ (ਕੁੰਜੀ_type_is_ecdsa_variant(type) && ਵਕਰ_nid != k->ecdsa_nid) {
		sshkey_free(k);
		ਵਾਪਸ SSH_ERR_EC_ਵਕਰ_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, ਆਕਾਰ(*k));

	/* success */
	*cpp = cp;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshkey_ਮੰਜ਼ਿਲ_base64(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅੱਖਰ **b64p)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਅੱਖਰ *uu = ਨਿਰਾ;

	ਜੇ (b64p != ਨਿਰਾ)
		*b64p = ਨਿਰਾ;
	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshkey_putb(ਕੁੰਜੀ, b)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((uu = sshbuf_dtob64_string(b, 0)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Success */
	ਜੇ (b64p != ਨਿਰਾ) {
		*b64p = uu;
		uu = ਨਿਰਾ;
	}
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਮੁਕਤ(uu);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshkey_format_ਪਾਠ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਅੱਖਰ *uu = ਨਿਰਾ;

	ਜੇ ((r = sshkey_ਮੰਜ਼ਿਲ_base64(ਕੁੰਜੀ, &uu)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(ਕੁੰਜੀ), uu)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(uu);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshkey_write(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, FILE *f)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshkey_format_ਪਾਠ(ਕੁੰਜੀ, b)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		ਜੇ (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਵਾਪਸ r;
}

ਅਚਲ ਅੱਖਰ *
sshkey_cert_type(ਅਚਲ ਬਣਤਰ sshkey *k)
{
	ਚੋਣ (k->cert->type) {
	ਹਾਲਤ SSH2_CERT_TYPE_USER:
		ਵਾਪਸ "user";
	ਹਾਲਤ SSH2_CERT_TYPE_HOST:
		ਵਾਪਸ "host";
	ਮੂਲ:
		ਵਾਪਸ "unknown";
	}
}

ਪੂਰਨ
sshkey_check_rsa_ਲੰਮਾਈ(ਅਚਲ ਬਣਤਰ sshkey *k, ਪੂਰਨ min_ਮਾਪ)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਪੂਰਨ nbits;

	ਜੇ (k == ਨਿਰਾ || k->pkey == ਨਿਰਾ ||
	    (k->type != ਕੁੰਜੀ_RSA && k->type != ਕੁੰਜੀ_RSA_CERT))
		ਵਾਪਸ 0;
	nbits = EVP_PKEY_ਬਿੱਟ(k->pkey);
	ਜੇ (nbits < SSH_RSA_MINIMUM_MODULUS_ਮਾਪ ||
	    (min_ਮਾਪ > 0 && nbits < min_ਮਾਪ))
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_ਲੰਮਾਈ;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਵਾਪਸ 0;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਪੂਰਨ
sshkey_ecdsa_ਕੁੰਜੀ_ਮੰਜ਼ਿਲ_nid(ਅਚਲ EC_ਕੁੰਜੀ *k)
{
	ਅਚਲ EC_ਸਮੂਹ *g;
	ਪੂਰਨ nid;

	ਜੇ (k == ਨਿਰਾ || (g = EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(k)) == ਨਿਰਾ)
		ਵਾਪਸ -1;
	ਜੇ ((nid = EC_ਸਮੂਹ_get_ਵਕਰ_name(g)) <= 0)
		ਵਾਪਸ -1;
	ਵਾਪਸ nid;
}

ਪੂਰਨ
sshkey_ecdsa_pkey_ਮੰਜ਼ਿਲ_nid(EVP_PKEY *pkey)
{
	ਵਾਪਸ sshkey_ecdsa_ਕੁੰਜੀ_ਮੰਜ਼ਿਲ_nid(EVP_PKEY_get0_EC_ਕੁੰਜੀ(pkey));
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਪੂਰਨ
sshkey_generate(ਪੂਰਨ type, u_int ਬਿੱਟ, ਬਣਤਰ sshkey **keyp)
{
	ਬਣਤਰ sshkey *k;
	ਪੂਰਨ ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;

	ਜੇ (keyp == ਨਿਰਾ || sshkey_type_is_cert(type))
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	*keyp = ਨਿਰਾ;
	ਜੇ ((impl = sshkey_impl_from_type(type)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN;
	ਜੇ (impl->funcs->generate == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_FEATURE_UNSUPPORTED;
	ਜੇ ((k = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	k->type = type;
	ਜੇ ((ret = impl->funcs->generate(k, ਬਿੱਟ)) != 0) {
		sshkey_free(k);
		ਵਾਪਸ ret;
	}
	/* success */
	*keyp = k;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshkey_cert_copy(ਅਚਲ ਬਣਤਰ sshkey *from_ਕੁੰਜੀ, ਬਣਤਰ sshkey *ਮੰਜ਼ਿਲ_ਕੁੰਜੀ)
{
	u_int i;
	ਅਚਲ ਬਣਤਰ sshkey_cert *from;
	ਬਣਤਰ sshkey_cert *ਮੰਜ਼ਿਲ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (ਮੰਜ਼ਿਲ_ਕੁੰਜੀ == ਨਿਰਾ || (from = from_ਕੁੰਜੀ->cert) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	ਜੇ ((ਮੰਜ਼ਿਲ = cert_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;

	ਜੇ ((r = sshbuf_putb(ਮੰਜ਼ਿਲ->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(ਮੰਜ਼ਿਲ->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(ਮੰਜ਼ਿਲ->extensions, from->extensions)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਮੰਜ਼ਿਲ->serial = from->serial;
	ਮੰਜ਼ਿਲ->type = from->type;
	ਜੇ (from->ਕੁੰਜੀ_id == ਨਿਰਾ)
		ਮੰਜ਼ਿਲ->ਕੁੰਜੀ_id = ਨਿਰਾ;
	ਨਹੀਂਤਾਂ ਜੇ ((ਮੰਜ਼ਿਲ->ਕੁੰਜੀ_id = strdup(from->ਕੁੰਜੀ_id)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਮੰਜ਼ਿਲ->valid_after = from->valid_after;
	ਮੰਜ਼ਿਲ->valid_before = from->valid_before;
	ਜੇ (from->signature_ਕੁੰਜੀ == ਨਿਰਾ)
		ਮੰਜ਼ਿਲ->signature_ਕੁੰਜੀ = ਨਿਰਾ;
	ਨਹੀਂਤਾਂ ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(from->signature_ਕੁੰਜੀ,
	    &ਮੰਜ਼ਿਲ->signature_ਕੁੰਜੀ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (from->signature_type != ਨਿਰਾ &&
	    (ਮੰਜ਼ਿਲ->signature_type = strdup(from->signature_type)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (from->nprincipals > 0) {
		ਜੇ ((ਮੰਜ਼ਿਲ->principals = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(from->nprincipals,
		    ਆਕਾਰ(*ਮੰਜ਼ਿਲ->principals))) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਲਈ (i = 0; i < from->nprincipals; i++) {
			ਮੰਜ਼ਿਲ->principals[i] = strdup(from->principals[i]);
			ਜੇ (ਮੰਜ਼ਿਲ->principals[i] == ਨਿਰਾ) {
				ਮੰਜ਼ਿਲ->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
		}
	}
	ਮੰਜ਼ਿਲ->nprincipals = from->nprincipals;

	/* success */
	cert_free(ਮੰਜ਼ਿਲ_ਕੁੰਜੀ->cert);
	ਮੰਜ਼ਿਲ_ਕੁੰਜੀ->cert = ਮੰਜ਼ਿਲ;
	ਮੰਜ਼ਿਲ = ਨਿਰਾ;
	r = 0;
 ਬਾਹਰਲਾ:
	cert_free(ਮੰਜ਼ਿਲ);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshkey_copy_ਜਨਤਕ_sk(ਅਚਲ ਬਣਤਰ sshkey *from, ਬਣਤਰ sshkey *ਮੰਜ਼ਿਲ)
{
	/* Append security-key application string */
	ਜੇ ((ਮੰਜ਼ਿਲ->sk_application = strdup(from->sk_application)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshkey_from_ਨਿੱਜੀ(ਅਚਲ ਬਣਤਰ sshkey *k, ਬਣਤਰ sshkey **pkp)
{
	ਬਣਤਰ sshkey *n = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;

	*pkp = ਨਿਰਾ;
	ਜੇ ((impl = sshkey_impl_from_ਕੁੰਜੀ(k)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN;
	ਜੇ ((n = sshkey_new(k->type)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = impl->funcs->copy_ਜਨਤਕ(k, n)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	*pkp = n;
	n = ਨਿਰਾ;
	r = 0;
 ਬਾਹਰਲਾ:
	sshkey_free(n);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshkey_is_shielded(ਬਣਤਰ sshkey *k)
{
	ਵਾਪਸ k != ਨਿਰਾ && k->shielded_ਨਿੱਜੀ != ਨਿਰਾ;
}

ਪੂਰਨ
sshkey_shield_ਨਿੱਜੀ(ਬਣਤਰ sshkey *k)
{
	ਬਣਤਰ sshbuf *prvbuf = ਨਿਰਾ;
	u_char *prekey = ਨਿਰਾ, *enc = ਨਿਰਾ, keyiv[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	ਬਣਤਰ sshcipher_ctx *cctx = ਨਿਰਾ;
	ਅਚਲ ਬਣਤਰ sshcipher *cipher;
	ਮਾਪ_t i, enclen = 0;
	ਬਣਤਰ sshkey *kswap = ਨਿਰਾ, tmp;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#ਜੇ_ਅੰਤ
	ਜੇ ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ਨਿਰਾ) {
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_ਬਾਈਟਾਂ(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	ਜੇ ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	ਜੇ ((r = ssh_digest_ਸਮ੍ਰਿਤੀ(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_ਲੰਮਾਈ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_ਅੰਕੜੇ(keyiv, ssh_digest_ਬਾਈਟਾਂ(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#ਜੇ_ਅੰਤ
	ਜੇ ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Serialise and encrypt the private key using the ephemeral key */
	ਜੇ ((prvbuf = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshkey_is_shielded(k) && (r = sshkey_unshield_ਨਿੱਜੀ(k)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = sshkey_ਨਿੱਜੀ_serialize(k, prvbuf)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* pad to cipher blocksize */
	i = 0;
	ਜਦੋਂ (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		ਜੇ ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#ਜੇ_ਅੰਤ
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	ਜੇ ((enc = ਸਮ੍ਰਿਤੀ_ਦਿਓ(enclen)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_ਅੰਕੜੇ(enc, enclen, stderr);
#ਜੇ_ਅੰਤ

	/* Make a scrubbed, public-only copy of our private key argument */
	ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(k, &kswap)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_ਨਿੱਜੀ = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = ਨਿਰਾ; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 ਬਾਹਰਲਾ:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, ਆਕਾਰ(keyiv));
	explicit_bzero(&tmp, ਆਕਾਰ(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	ਵਾਪਸ r;
}

/* Check deterministic padding after private key */
ਸਥਿਰ ਪੂਰਨ
private2_check_padding(ਬਣਤਰ sshbuf *decrypted)
{
	u_char pad;
	ਮਾਪ_t i;
	ਪੂਰਨ r;

	i = 0;
	ਜਦੋਂ (sshbuf_len(decrypted)) {
		ਜੇ ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	explicit_bzero(&pad, ਆਕਾਰ(pad));
	explicit_bzero(&i, ਆਕਾਰ(i));
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshkey_unshield_ਨਿੱਜੀ(ਬਣਤਰ sshkey *k)
{
	ਬਣਤਰ sshbuf *prvbuf = ਨਿਰਾ;
	u_char *cp, keyiv[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	ਬਣਤਰ sshcipher_ctx *cctx = ਨਿਰਾ;
	ਅਚਲ ਬਣਤਰ sshcipher *cipher;
	ਬਣਤਰ sshkey *kswap = ਨਿਰਾ, tmp;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#ਜੇ_ਅੰਤ
	ਜੇ (!sshkey_is_shielded(k))
		ਵਾਪਸ 0; /* nothing to do */

	ਜੇ ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ਨਿਰਾ) {
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_ਬਾਈਟਾਂ(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* check size of shielded key blob */
	ਜੇ (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Calculate the ephemeral key from the prekey */
	ਜੇ ((r = ssh_digest_ਸਮ੍ਰਿਤੀ(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_ਲੰਮਾਈ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_ਅੰਕੜੇ(keyiv, ssh_digest_ਬਾਈਟਾਂ(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#ਜੇ_ਅੰਤ

	/* Decrypt and parse the shielded private key using the ephemeral key */
	ਜੇ ((prvbuf = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* decrypt */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_ਅੰਕੜੇ(k->shielded_ਨਿੱਜੀ, k->shielded_len, stderr);
#ਜੇ_ਅੰਤ
	ਜੇ ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_ਨਿੱਜੀ, k->shielded_len, 0, 0)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#ਜੇ_ਅੰਤ
	/* Parse private key */
	ਜੇ ((r = sshkey_ਨਿੱਜੀ_deserialize(prvbuf, &kswap)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((r = private2_check_padding(prvbuf)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 ਬਾਹਰਲਾ:
	cipher_free(cctx);
	explicit_bzero(keyiv, ਆਕਾਰ(keyiv));
	explicit_bzero(&tmp, ਆਕਾਰ(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
cert_parse(ਬਣਤਰ sshbuf *b, ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *certbuf,
    ਅਚਲ ਅੱਖਰ *ca_sigalg_allowlist)
{
	ਬਣਤਰ sshbuf *principals = ਨਿਰਾ, *crit = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *exts = ਨਿਰਾ, *ca = ਨਿਰਾ;
	u_char *sig = ਨਿਰਾ;
	ਅੱਖਰ *sigtype = ਨਿਰਾ;
	ਮਾਪ_t signed_len = 0, slen = 0, kidlen = 0;
	ਪੂਰਨ ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	ਜੇ ((ret = sshbuf_putb(ਕੁੰਜੀ->cert->certblob, certbuf)) != 0)
		ਵਾਪਸ ret;

	/* Parse body of certificate up to signature */
	ਜੇ ((ret = sshbuf_get_u64(b, &ਕੁੰਜੀ->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &ਕੁੰਜੀ->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &ਕੁੰਜੀ->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &ਕੁੰਜੀ->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_ਸਿੱਧਾ(b, ਨਿਰਾ, ਨਿਰਾ)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(ਕੁੰਜੀ->cert->certblob) - sshbuf_len(b);

	ਜੇ ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Is this a signature we're prepared to accept? */
	ਜੇ ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (ca_sigalg_allowlist != ਨਿਰਾ &&
	    ਮੇਲ_ਨਮੂਨਾ_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Parse CA key and check whether we might accept it */
	ਜੇ (sshkey_from_blob_ਅੰਦਰੂਨੀ(ca, &ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ, 0,
	    ca_sigalg_allowlist, ਨਿਰਾ) != 0) {
		ret = SSH_ERR_ਕੁੰਜੀ_CERT_INVALID_SIGN_ਕੁੰਜੀ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (!sshkey_type_is_valid_ca(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ->type)) {
		ret = SSH_ERR_ਕੁੰਜੀ_CERT_INVALID_SIGN_ਕੁੰਜੀ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (ਕੁੰਜੀ->cert->type != SSH2_CERT_TYPE_USER &&
	    ਕੁੰਜੀ->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_ਕੁੰਜੀ_CERT_UNKNOWN_TYPE;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Parse principals section */
	ਜਦੋਂ (sshbuf_len(principals) > 0) {
		ਅੱਖਰ *principal = ਨਿਰਾ;
		ਅੱਖਰ **oprincipals = ਨਿਰਾ;

		ਜੇ (ਕੁੰਜੀ->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((ret = sshbuf_get_cstring(principals, &principal,
		    ਨਿਰਾ)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		oprincipals = ਕੁੰਜੀ->cert->principals;
		ਕੁੰਜੀ->cert->principals = recallocarray(ਕੁੰਜੀ->cert->principals,
		    ਕੁੰਜੀ->cert->nprincipals, ਕੁੰਜੀ->cert->nprincipals + 1,
		    ਆਕਾਰ(*ਕੁੰਜੀ->cert->principals));
		ਜੇ (ਕੁੰਜੀ->cert->principals == ਨਿਰਾ) {
			ਮੁਕਤ(principal);
			ਕੁੰਜੀ->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਕੁੰਜੀ->cert->principals[ਕੁੰਜੀ->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	ਜੇ ((ret = sshbuf_putb(ਕੁੰਜੀ->cert->critical, crit)) != 0 ||
	    (exts != ਨਿਰਾ &&
	    (ret = sshbuf_putb(ਕੁੰਜੀ->cert->extensions, exts)) != 0))
		ਜਾਓ ਬਾਹਰਲਾ;

	/*
	 * Validate critical options and extensions sections format.
	 */
	ਜਦੋਂ (sshbuf_len(crit) != 0) {
		ਜੇ ((ret = sshbuf_get_string_ਸਿੱਧਾ(crit, ਨਿਰਾ, ਨਿਰਾ)) != 0 ||
		    (ret = sshbuf_get_string_ਸਿੱਧਾ(crit, ਨਿਰਾ, ਨਿਰਾ)) != 0) {
			sshbuf_reset(ਕੁੰਜੀ->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	ਜਦੋਂ (exts != ਨਿਰਾ && sshbuf_len(exts) != 0) {
		ਜੇ ((ret = sshbuf_get_string_ਸਿੱਧਾ(exts, ਨਿਰਾ, ਨਿਰਾ)) != 0 ||
		    (ret = sshbuf_get_string_ਸਿੱਧਾ(exts, ਨਿਰਾ, ਨਿਰਾ)) != 0) {
			sshbuf_reset(ਕੁੰਜੀ->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	/* Finally, validate signature */
	ਜੇ ((ret = sshkey_verify(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ, sig, slen,
	    sshbuf_ptr(ਕੁੰਜੀ->cert->certblob), signed_len, ਨਿਰਾ, 0, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Success */
	ret = 0;
	ਕੁੰਜੀ->cert->signature_type = sigtype;
	sigtype = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	ਮੁਕਤ(sig);
	ਮੁਕਤ(sigtype);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sshkey_deserialize_sk(ਬਣਤਰ sshbuf *b, ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	/* Parse additional security-key application string */
	ਜੇ (sshbuf_get_cstring(b, &ਕੁੰਜੀ->sk_application, ਨਿਰਾ) != 0)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
sshkey_from_blob_ਅੰਦਰੂਨੀ(ਬਣਤਰ sshbuf *b, ਬਣਤਰ sshkey **keyp,
    ਪੂਰਨ allow_cert, ਅਚਲ ਅੱਖਰ *alg_allowlist, ਅਚਲ ਅੱਖਰ *ca_sigalg_allowlist)
{
	ਪੂਰਨ type, ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਅੱਖਰ *ktype = ਨਿਰਾ;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *copy;
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#ਜੇ_ਅੰਤ
	ਜੇ (keyp != ਨਿਰਾ)
		*keyp = ਨਿਰਾ;
	ਜੇ ((copy = sshbuf_fromb(b)) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_get_cstring(b, &ktype, ਨਿਰਾ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	type = sshkey_type_from_name(ktype);
	ਜੇ (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_ਕੁੰਜੀ_CERT_INVALID_SIGN_ਕੁੰਜੀ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (alg_allowlist != ਨਿਰਾ &&
	    !sshkey_ਮੇਲ_keyname_ਮੰਜ਼ਿਲ_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_ਕੁੰਜੀ_ALG_UNSUPPORTED;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((impl = sshkey_impl_from_type(type)) == ਨਿਰਾ) {
		ret = SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ਕੁੰਜੀ = sshkey_new(type)) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		ਜੇ (sshbuf_get_string_ਸਿੱਧਾ(b, ਨਿਰਾ, ਨਿਰਾ) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	ਜੇ ((ret = impl->funcs->deserialize_ਜਨਤਕ(ktype, b, ਕੁੰਜੀ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Parse certificate potion */
	ਜੇ (sshkey_is_cert(ਕੁੰਜੀ) &&
	    (ret = cert_parse(b, ਕੁੰਜੀ, copy, ca_sigalg_allowlist)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ (ਕੁੰਜੀ != ਨਿਰਾ && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ret = 0;
	ਜੇ (keyp != ਨਿਰਾ) {
		*keyp = ਕੁੰਜੀ;
		ਕੁੰਜੀ = ਨਿਰਾ;
	}
 ਬਾਹਰਲਾ:
	sshbuf_free(copy);
	sshkey_free(ਕੁੰਜੀ);
	ਮੁਕਤ(ktype);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sshkey_from_blob(ਅਚਲ u_char *blob, ਮਾਪ_t blen, ਬਣਤਰ sshkey **keyp)
{
	ਬਣਤਰ sshbuf *b;
	ਪੂਰਨ r;

	ਜੇ ((b = sshbuf_from(blob, blen)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_ਅੰਦਰੂਨੀ(b, keyp, 1, ਨਿਰਾ, ਨਿਰਾ);
	sshbuf_free(b);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshkey_fromb(ਬਣਤਰ sshbuf *b, ਬਣਤਰ sshkey **keyp)
{
	ਵਾਪਸ sshkey_from_blob_ਅੰਦਰੂਨੀ(b, keyp, 1, ਨਿਰਾ, ਨਿਰਾ);
}

ਪੂਰਨ
sshkey_fromb_allowlist(ਬਣਤਰ sshbuf *b, ਬਣਤਰ sshkey **keyp,
    ਅਚਲ ਅੱਖਰ *alg_allowlist, ਅਚਲ ਅੱਖਰ *ca_sigalg_allowlist)
{
	ਵਾਪਸ sshkey_from_blob_ਅੰਦਰੂਨੀ(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

ਪੂਰਨ
sshkey_froms(ਬਣਤਰ sshbuf *buf, ਬਣਤਰ sshkey **keyp)
{
	ਬਣਤਰ sshbuf *b;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_froms(buf, &b)) != 0)
		ਵਾਪਸ r;
	r = sshkey_from_blob_ਅੰਦਰੂਨੀ(b, keyp, 1, ਨਿਰਾ, ਨਿਰਾ);
	sshbuf_free(b);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshkey_get_sigtype(ਅਚਲ u_char *sig, ਮਾਪ_t siglen, ਅੱਖਰ **sigtypep)
{
	ਪੂਰਨ r;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਅੱਖਰ *sigtype = ਨਿਰਾ;

	ਜੇ (sigtypep != ਨਿਰਾ)
		*sigtypep = ਨਿਰਾ;
	ਜੇ ((b = sshbuf_from(sig, siglen)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_get_cstring(b, &sigtype, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	ਜੇ (sigtypep != ਨਿਰਾ) {
		*sigtypep = sigtype;
		sigtype = ਨਿਰਾ;
	}
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(sigtype);
	sshbuf_free(b);
	ਵਾਪਸ r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
ਪੂਰਨ
sshkey_check_cert_sigtype(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *allowed)
{
	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ || allowed == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (!sshkey_type_is_cert(ਕੁੰਜੀ->type))
		ਵਾਪਸ 0;
	ਜੇ (ਕੁੰਜੀ->cert == ਨਿਰਾ || ਕੁੰਜੀ->cert->signature_type == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(ਕੁੰਜੀ->cert->signature_type, allowed, 0) != 1)
		ਵਾਪਸ SSH_ERR_SIGN_ALG_UNSUPPORTED;
	ਵਾਪਸ 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
ਅਚਲ ਅੱਖਰ *
sshkey_sigalg_by_name(ਅਚਲ ਅੱਖਰ *name)
{
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;
	ਪੂਰਨ i;

	ਲਈ (i = 0; keyimpls[i] != ਨਿਰਾ; i++) {
		impl = keyimpls[i];
		ਜੇ (strcmp(impl->name, name) != 0)
			ਜਾਰੀ;
		ਜੇ (impl->sigalg != ਨਿਰਾ)
			ਵਾਪਸ impl->sigalg;
		ਜੇ (!impl->cert)
			ਵਾਪਸ impl->name;
		ਵਾਪਸ sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	ਵਾਪਸ ਨਿਰਾ;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
ਪੂਰਨ
sshkey_check_sigtype(ਅਚਲ u_char *sig, ਮਾਪ_t siglen,
    ਅਚਲ ਅੱਖਰ *requested_alg)
{
	ਅਚਲ ਅੱਖਰ *expected_alg;
	ਅੱਖਰ *sigtype = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ (requested_alg == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		ਵਾਪਸ r;
	r = strcmp(expected_alg, sigtype) == 0;
	ਮੁਕਤ(sigtype);
	ਵਾਪਸ r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ਪੂਰਨ
sshkey_sign(ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *alg, ਅਚਲ ਅੱਖਰ *sk_provider, ਅਚਲ ਅੱਖਰ *sk_pin, u_int compat)
{
	ਪੂਰਨ was_shielded = sshkey_is_shielded(ਕੁੰਜੀ);
	ਪੂਰਨ r2, r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;

	ਜੇ (sigp != ਨਿਰਾ)
		*sigp = ਨਿਰਾ;
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	ਜੇ (datalen > SSH_ਕੁੰਜੀ_MAX_SIGN_ਅੰਕੜੇ_ਮਾਪ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((impl = sshkey_impl_from_ਕੁੰਜੀ(ਕੁੰਜੀ)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN;
	ਜੇ ((r = sshkey_unshield_ਨਿੱਜੀ(ਕੁੰਜੀ)) != 0)
		ਵਾਪਸ r;
	ਜੇ (sshkey_is_sk(ਕੁੰਜੀ)) {
		r = sshsk_sign(sk_provider, ਕੁੰਜੀ, sigp, lenp, ਅੰਕੜੇ,
		    datalen, compat, sk_pin);
	} ਨਹੀਂਤਾਂ ਜੇ ((ਕੁੰਜੀ->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(ਕੁੰਜੀ, sigp, lenp, ਅੰਕੜੇ, datalen,
		    alg, sk_provider, sk_pin, compat);
	} ਨਹੀਂਤਾਂ {
		ਜੇ (impl->funcs->sign == ਨਿਰਾ)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ਨਹੀਂਤਾਂ {
			r = impl->funcs->sign(ਕੁੰਜੀ, sigp, lenp, ਅੰਕੜੇ, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	ਜੇ (was_shielded && (r2 = sshkey_shield_ਨਿੱਜੀ(ਕੁੰਜੀ)) != 0)
		ਵਾਪਸ r2;
	ਵਾਪਸ r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
ਪੂਰਨ
sshkey_verify(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ u_char *sig, ਮਾਪ_t siglen,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t dlen, ਅਚਲ ਅੱਖਰ *alg, u_int compat,
    ਬਣਤਰ sshkey_sig_details **detailsp)
{
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;

	ਜੇ (detailsp != ਨਿਰਾ)
		*detailsp = ਨਿਰਾ;
	ਜੇ (siglen == 0 || dlen > SSH_ਕੁੰਜੀ_MAX_SIGN_ਅੰਕੜੇ_ਮਾਪ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((impl = sshkey_impl_from_ਕੁੰਜੀ(ਕੁੰਜੀ)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN;
	ਵਾਪਸ impl->funcs->verify(ਕੁੰਜੀ, sig, siglen, ਅੰਕੜੇ, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
ਪੂਰਨ
sshkey_ਮੰਜ਼ਿਲ_certified(ਬਣਤਰ sshkey *k)
{
	ਪੂਰਨ newtype;

	ਜੇ ((newtype = sshkey_type_certified(k->type)) == -1)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((k->cert = cert_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	ਵਾਪਸ 0;
}

/* Convert a certificate to its raw key equivalent */
ਪੂਰਨ
sshkey_drop_cert(ਬਣਤਰ sshkey *k)
{
	ਜੇ (!sshkey_type_is_cert(k->type))
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = ਨਿਰਾ;
	k->type = sshkey_type_plain(k->type);
	ਵਾਪਸ 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
ਪੂਰਨ
sshkey_certify_custom(ਬਣਤਰ sshkey *k, ਬਣਤਰ sshkey *ca, ਅਚਲ ਅੱਖਰ *alg,
    ਅਚਲ ਅੱਖਰ *sk_provider, ਅਚਲ ਅੱਖਰ *sk_pin,
    sshkey_certify_signer *signer, ਖਾਲੀ *signer_ctx)
{
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;
	ਬਣਤਰ sshbuf *principals = ਨਿਰਾ;
	u_char *ca_blob = ਨਿਰਾ, *sig_blob = ਨਿਰਾ, nonce[32];
	ਮਾਪ_t i, ca_len, sig_len;
	ਪੂਰਨ ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ sshbuf *cert = ਨਿਰਾ;
	ਅੱਖਰ *sigtype = ਨਿਰਾ;

	ਜੇ (k == ਨਿਰਾ || k->cert == ਨਿਰਾ ||
	    k->cert->certblob == ਨਿਰਾ || ca == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (!sshkey_is_cert(k))
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN;
	ਜੇ (!sshkey_type_is_valid_ca(ca->type))
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID_SIGN_ਕੁੰਜੀ;
	ਜੇ ((impl = sshkey_impl_from_ਕੁੰਜੀ(k)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	ਜੇ (alg == ਨਿਰਾ)
		alg = k->cert->signature_type;
	ਨਹੀਂਤਾਂ ਜੇ (k->cert->signature_type != ਨਿਰਾ &&
	    strcmp(alg, k->cert->signature_type) != 0)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	ਜੇ (alg == ਨਿਰਾ && ca->type == ਕੁੰਜੀ_RSA)
		alg = "rsa-sha2-512";

	ਜੇ ((ret = sshkey_ਮੰਜ਼ਿਲ_blob(ca, &ca_blob, &ca_len)) != 0)
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID_SIGN_ਕੁੰਜੀ;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	ਜੇ ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, ਆਕਾਰ(nonce));
	ਜੇ ((ret = sshbuf_put_string(cert, nonce, ਆਕਾਰ(nonce))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Public key next */
	ਜੇ ((ret = impl->funcs->serialize_ਜਨਤਕ(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Then remaining cert fields */
	ਜੇ ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->ਕੁੰਜੀ_id)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((principals = sshbuf_new()) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਲਈ (i = 0; i < k->cert->nprincipals; i++) {
		ਜੇ ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, ਨਿਰਾ, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Sign the whole mess */
	ਜੇ ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* Check and update signature_type against what was actually used */
	ਜੇ ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (alg != ਨਿਰਾ && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (k->cert->signature_type == ਨਿਰਾ) {
		k->cert->signature_type = sigtype;
		sigtype = ਨਿਰਾ;
	}
	/* Append signature and we are done */
	ਜੇ ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ret = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (ret != 0)
		sshbuf_reset(cert);
	ਮੁਕਤ(sig_blob);
	ਮੁਕਤ(ca_blob);
	ਮੁਕਤ(sigtype);
	sshbuf_free(principals);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
default_ਕੁੰਜੀ_sign(ਬਣਤਰ sshkey *ਕੁੰਜੀ, u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *alg, ਅਚਲ ਅੱਖਰ *sk_provider, ਅਚਲ ਅੱਖਰ *sk_pin,
    u_int compat, ਖਾਲੀ *ctx)
{
	ਜੇ (ctx != ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਵਾਪਸ sshkey_sign(ਕੁੰਜੀ, sigp, lenp, ਅੰਕੜੇ, datalen, alg,
	    sk_provider, sk_pin, compat);
}

ਪੂਰਨ
sshkey_certify(ਬਣਤਰ sshkey *k, ਬਣਤਰ sshkey *ca, ਅਚਲ ਅੱਖਰ *alg,
    ਅਚਲ ਅੱਖਰ *sk_provider, ਅਚਲ ਅੱਖਰ *sk_pin)
{
	ਵਾਪਸ sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_ਕੁੰਜੀ_sign, ਨਿਰਾ);
}

ਪੂਰਨ
sshkey_cert_check_authority(ਅਚਲ ਬਣਤਰ sshkey *k,
    ਪੂਰਨ want_host, ਪੂਰਨ wildcard_ਨਮੂਨਾ, uint64_t verify_ਸਮਾਂ,
    ਅਚਲ ਅੱਖਰ *name, ਅਚਲ ਅੱਖਰ **reason)
{
	u_int i, principal_matches;

	ਜੇ (reason == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID;
	}
	ਜੇ (want_host) {
		ਜੇ (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID;
		}
	} ਨਹੀਂਤਾਂ {
		ਜੇ (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID;
		}
	}
	ਜੇ (verify_ਸਮਾਂ < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID;
	}
	ਜੇ (verify_ਸਮਾਂ >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID;
	}
	ਜੇ (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID;
	}
	ਜੇ (name == ਨਿਰਾ)
		ਵਾਪਸ 0; /* principal matching not requested */

	principal_matches = 0;
	ਲਈ (i = 0; i < k->cert->nprincipals; i++) {
		ਜੇ (wildcard_ਨਮੂਨਾ) {
			ਜੇ (ਮੇਲ_ਨਮੂਨਾ(name, k->cert->principals[i])) {
				principal_matches = 1;
				ਰੋਕੋ;
			}
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			ਰੋਕੋ;
		}
	}
	ਜੇ (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID;
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshkey_cert_check_authority_now(ਅਚਲ ਬਣਤਰ sshkey *k,
    ਪੂਰਨ want_host, ਪੂਰਨ wildcard_ਨਮੂਨਾ, ਅਚਲ ਅੱਖਰ *name,
    ਅਚਲ ਅੱਖਰ **reason)
{
	time_t now;

	ਜੇ ((now = time(ਨਿਰਾ)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID;
	}
	ਵਾਪਸ sshkey_cert_check_authority(k, want_host, wildcard_ਨਮੂਨਾ,
	    (uint64_t)now, name, reason);
}

ਪੂਰਨ
sshkey_cert_check_host(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *host,
    ਅਚਲ ਅੱਖਰ *ca_sign_algorithms, ਅਚਲ ਅੱਖਰ **reason)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshkey_cert_check_authority_now(ਕੁੰਜੀ, 1, 1, host, reason)) != 0)
		ਵਾਪਸ r;
	ਜੇ (sshbuf_len(ਕੁੰਜੀ->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID;
	}
	ਜੇ (ca_sign_algorithms != ਨਿਰਾ &&
	    (r = sshkey_check_cert_sigtype(ਕੁੰਜੀ, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_CERT_INVALID;
	}
	ਵਾਪਸ 0;
}

ਮਾਪ_t
sshkey_format_cert_validity(ਅਚਲ ਬਣਤਰ sshkey_cert *cert, ਅੱਖਰ *s, ਮਾਪ_t l)
{
	ਅੱਖਰ from[32], ਮੰਜ਼ਿਲ[32], ret[128];

	*from = *ਮੰਜ਼ਿਲ = '\0';
	ਜੇ (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		ਵਾਪਸ strlcpy(s, "forever", l);

	ਜੇ (cert->valid_after != 0)
		format_absolute_ਸਮਾਂ(cert->valid_after, from, ਆਕਾਰ(from));
	ਜੇ (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_ਸਮਾਂ(cert->valid_before, ਮੰਜ਼ਿਲ, ਆਕਾਰ(ਮੰਜ਼ਿਲ));

	ਜੇ (cert->valid_after == 0)
		snprintf(ret, ਆਕਾਰ(ret), "before %s", ਮੰਜ਼ਿਲ);
	ਨਹੀਂਤਾਂ ਜੇ (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, ਆਕਾਰ(ret), "after %s", from);
	ਨਹੀਂਤਾਂ
		snprintf(ret, ਆਕਾਰ(ret), "from %s to %s", from, ਮੰਜ਼ਿਲ);

	ਵਾਪਸ strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
ਪੂਰਨ
sshkey_serialize_ਨਿੱਜੀ_sk(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_put_cstring(b, ਕੁੰਜੀ->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, ਕੁੰਜੀ->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, ਕੁੰਜੀ->sk_ਕੁੰਜੀ_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, ਕੁੰਜੀ->sk_reserved)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
sshkey_ਨਿੱਜੀ_serialize_opt(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *buf,
    ਗਿਣਤੀ sshkey_serialize_rep opts)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਪੂਰਨ was_shielded = sshkey_is_shielded(ਕੁੰਜੀ);
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;

	ਜੇ ((impl = sshkey_impl_from_ਕੁੰਜੀ(ਕੁੰਜੀ)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਜੇ ((r = sshkey_unshield_ਨਿੱਜੀ(ਕੁੰਜੀ)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put_cstring(b, sshkey_ssh_name(ਕੁੰਜੀ))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (sshkey_is_cert(ਕੁੰਜੀ)) {
		ਜੇ (ਕੁੰਜੀ->cert == ਨਿਰਾ ||
		    sshbuf_len(ਕੁੰਜੀ->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ਦਲੀਲ;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_put_stringb(b, ਕੁੰਜੀ->cert->certblob)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = impl->funcs->serialize_ਨਿੱਜੀ(ਕੁੰਜੀ, b, opts)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (was_shielded)
		r = sshkey_shield_ਨਿੱਜੀ(ਕੁੰਜੀ);
	ਜੇ (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	ਵਾਪਸ r;
}

ਪੂਰਨ
sshkey_ਨਿੱਜੀ_serialize(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b)
{
	ਵਾਪਸ sshkey_ਨਿੱਜੀ_serialize_opt(ਕੁੰਜੀ, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
ਪੂਰਨ
sshkey_ਨਿੱਜੀ_deserialize_sk(ਬਣਤਰ sshbuf *buf, ਬਣਤਰ sshkey *k)
{
	ਪੂਰਨ r;

	ਜੇ ((k->sk_ਕੁੰਜੀ_handle = sshbuf_new()) == ਨਿਰਾ ||
	    (k->sk_reserved = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_get_cstring(buf, &k->sk_application, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_ਕੁੰਜੀ_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshkey_ਨਿੱਜੀ_deserialize(ਬਣਤਰ sshbuf *buf, ਬਣਤਰ sshkey **kp)
{
	ਅਚਲ ਬਣਤਰ sshkey_impl *impl;
	ਅੱਖਰ *tname = ਨਿਰਾ;
	ਅੱਖਰ *expect_sk_application = ਨਿਰਾ;
	u_char *expect_ed25519_pk = ਨਿਰਾ;
	ਬਣਤਰ sshkey *k = ਨਿਰਾ;
	ਪੂਰਨ type, r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (kp != ਨਿਰਾ)
		*kp = ਨਿਰਾ;
	ਜੇ ((r = sshbuf_get_cstring(buf, &tname, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	type = sshkey_type_from_name(tname);
	ਜੇ (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		ਜੇ ((r = sshkey_froms(buf, &k)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ (k->type != type) {
			r = SSH_ERR_ਕੁੰਜੀ_CERT_MISMATCH;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/* For ECDSA keys, the group must match too */
		ਜੇ (k->type == ਕੁੰਜੀ_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_ਕੁੰਜੀ_CERT_MISMATCH;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = ਨਿਰਾ;
		k->ed25519_pk = ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((k = sshkey_new(type)) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	ਜੇ ((impl = sshkey_impl_from_type(type)) == ਨਿਰਾ) {
		r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = impl->funcs->deserialize_ਨਿੱਜੀ(tname, buf, k)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((expect_sk_application != ਨਿਰਾ && (k->sk_application == ਨਿਰਾ ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != ਨਿਰਾ && (k->ed25519_pk == ਨਿਰਾ ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_ਕੁੰਜੀ_CERT_MISMATCH;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
	ਜੇ (kp != ਨਿਰਾ) {
		*kp = k;
		k = ਨਿਰਾ;
	}
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(tname);
	sshkey_free(k);
	ਮੁਕਤ(expect_sk_application);
	ਮੁਕਤ(expect_ed25519_pk);
	ਵਾਪਸ r;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਪੂਰਨ
sshkey_ec_validate_ਜਨਤਕ(ਅਚਲ EC_ਸਮੂਹ *ਸਮੂਹ, ਅਚਲ EC_ਬਿੰਦੂ *ਜਨਤਕ)
{
	EC_ਬਿੰਦੂ *nq = ਨਿਰਾ;
	BIGNUM *ਕ੍ਰਮ = ਨਿਰਾ, *cofactor = ਨਿਰਾ;
	ਪੂਰਨ ret = SSH_ERR_ਕੁੰਜੀ_INVALID_EC_ਮੁੱਲ;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	ਜੇ (EC_ਬਿੰਦੂ_is_at_infinity(ਸਮੂਹ, ਜਨਤਕ))
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((cofactor = BN_new()) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EC_ਸਮੂਹ_get_cofactor(ਸਮੂਹ, cofactor, ਨਿਰਾ) != 1)
		ਜਾਓ ਬਾਹਰਲਾ;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	ਜੇ (!BN_is_one(cofactor)) {
		ਜੇ ((ਕ੍ਰਮ = BN_new()) == ਨਿਰਾ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (EC_ਸਮੂਹ_get_ਕ੍ਰਮ(ਸਮੂਹ, ਕ੍ਰਮ, ਨਿਰਾ) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((nq = EC_ਬਿੰਦੂ_new(ਸਮੂਹ)) == ਨਿਰਾ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (EC_ਬਿੰਦੂ_mul(ਸਮੂਹ, nq, ਨਿਰਾ, ਜਨਤਕ, ਕ੍ਰਮ, ਨਿਰਾ) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (EC_ਬਿੰਦੂ_is_at_infinity(ਸਮੂਹ, nq) != 1)
			ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* success */
	ret = 0;
 ਬਾਹਰਲਾ:
	BN_clear_free(cofactor);
	BN_clear_free(ਕ੍ਰਮ);
	EC_ਬਿੰਦੂ_free(nq);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sshkey_ec_validate_ਨਿੱਜੀ(ਅਚਲ EC_ਕੁੰਜੀ *ਕੁੰਜੀ)
{
	BIGNUM *ਕ੍ਰਮ = ਨਿਰਾ, *tmp = ਨਿਰਾ;
	ਪੂਰਨ ret = SSH_ERR_ਕੁੰਜੀ_INVALID_EC_ਮੁੱਲ;

	ਜੇ ((ਕ੍ਰਮ = BN_new()) == ਨਿਰਾ || (tmp = BN_new()) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* log2(private) > log2(order)/2 */
	ਜੇ (EC_ਸਮੂਹ_get_ਕ੍ਰਮ(EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(ਕੁੰਜੀ), ਕ੍ਰਮ, ਨਿਰਾ) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (BN_ਅੰਕ_ਬਿੱਟ(EC_ਕੁੰਜੀ_get0_ਨਿੱਜੀ_ਕੁੰਜੀ(ਕੁੰਜੀ)) <=
	    BN_ਅੰਕ_ਬਿੱਟ(ਕ੍ਰਮ) / 2)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* private < order - 1 */
	ਜੇ (!BN_sub(tmp, ਕ੍ਰਮ, BN_ਮੁੱਲ_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (BN_cmp(EC_ਕੁੰਜੀ_get0_ਨਿੱਜੀ_ਕੁੰਜੀ(ਕੁੰਜੀ), tmp) >= 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ret = 0;
 ਬਾਹਰਲਾ:
	BN_clear_free(ਕ੍ਰਮ);
	BN_clear_free(tmp);
	ਵਾਪਸ ret;
}

ਖਾਲੀ
sshkey_dump_ec_ਬਿੰਦੂ(ਅਚਲ EC_ਸਮੂਹ *ਸਮੂਹ, ਅਚਲ EC_ਬਿੰਦੂ *ਬਿੰਦੂ)
{
	BIGNUM *x = ਨਿਰਾ, *y = ਨਿਰਾ;

	ਜੇ (ਬਿੰਦੂ == ਨਿਰਾ) {
		fputs("point=(NULL)\n", stderr);
		ਵਾਪਸ;
	}
	ਜੇ ((x = BN_new()) == ਨਿਰਾ || (y = BN_new()) == ਨਿਰਾ) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EC_ਬਿੰਦੂ_get_affine_coordinates(ਸਮੂਹ, ਬਿੰਦੂ, x, y, ਨਿਰਾ) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	fputs("x=", stderr);
	BN_print_fp(stderr, x);
	fputs("\ny=", stderr);
	BN_print_fp(stderr, y);
	fputs("\n", stderr);
 ਬਾਹਰਲਾ:
	BN_clear_free(x);
	BN_clear_free(y);
}

ਖਾਲੀ
sshkey_dump_ec_ਕੁੰਜੀ(ਅਚਲ EC_ਕੁੰਜੀ *ਕੁੰਜੀ)
{
	ਅਚਲ BIGNUM *exponent;

	sshkey_dump_ec_ਬਿੰਦੂ(EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(ਕੁੰਜੀ),
	    EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(ਕੁੰਜੀ));
	fputs("exponent=", stderr);
	ਜੇ ((exponent = EC_ਕੁੰਜੀ_get0_ਨਿੱਜੀ_ਕੁੰਜੀ(ਕੁੰਜੀ)) == ਨਿਰਾ)
		fputs("(NULL)", stderr);
	ਨਹੀਂਤਾਂ
		BN_print_fp(stderr, EC_ਕੁੰਜੀ_get0_ਨਿੱਜੀ_ਕੁੰਜੀ(ਕੁੰਜੀ));
	fputs("\n", stderr);
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਸਥਿਰ ਪੂਰਨ
sshkey_ਨਿੱਜੀ_ਮੰਜ਼ਿਲ_blob2(ਬਣਤਰ sshkey *prv, ਬਣਤਰ sshbuf *blob,
    ਅਚਲ ਅੱਖਰ *passphrase, ਅਚਲ ਅੱਖਰ *comment, ਅਚਲ ਅੱਖਰ *ciphername,
    ਪੂਰਨ ਗੇੜ)
{
	u_char *cp, *ਕੁੰਜੀ = ਨਿਰਾ, *pubkeyblob = ਨਿਰਾ;
	u_char salt[SALT_LEN];
	ਮਾਪ_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ sshcipher_ctx *ciphercontext = ਨਿਰਾ;
	ਅਚਲ ਬਣਤਰ sshcipher *cipher;
	ਅਚਲ ਅੱਖਰ *kdfname = KDFNAME;
	ਬਣਤਰ sshbuf *encoded = ਨਿਰਾ, *encrypted = ਨਿਰਾ, *kdf = ਨਿਰਾ;

	ਜੇ (ਗੇੜ <= 0)
		ਗੇੜ = DEFAULT_ਗੇੜ;
	ਜੇ (ਗੇੜ > MAX_KDF_ਗੇੜ) {
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (passphrase == ਨਿਰਾ || !ਲੜੀ_ਲੰਬਾਈ(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} ਨਹੀਂਤਾਂ ਜੇ (ciphername == ਨਿਰਾ)
		ciphername = DEFAULT_CIPHERNAME;
	ਜੇ ((cipher = cipher_by_name(ciphername)) == ਨਿਰਾ) {
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((kdf = sshbuf_new()) == ਨਿਰਾ ||
	    (encoded = sshbuf_new()) == ਨਿਰਾ ||
	    (encrypted = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	ਜੇ ((ਕੁੰਜੀ = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, keylen + ivlen)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		ਜੇ (bcrypt_pbkdf(passphrase, ਲੜੀ_ਲੰਬਾਈ(passphrase),
		    salt, SALT_LEN, ਕੁੰਜੀ, keylen + ivlen, ਗੇੜ) < 0) {
			r = SSH_ERR_INVALID_ਦਲੀਲ;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, ਗੇੜ)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_ਕੁੰਜੀ_UNKNOWN_CIPHER;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = cipher_init(&ciphercontext, cipher, ਕੁੰਜੀ, keylen,
	    ਕੁੰਜੀ + keylen, ivlen, 1)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((r = sshbuf_put(encoded, AUTH_MAGIC, ਆਕਾਰ(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_ਮੰਜ਼ਿਲ_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	ਜੇ ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* append private key and comment*/
	ਜੇ ((r = sshkey_ਨਿੱਜੀ_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* padding */
	i = 0;
	ਜਦੋਂ (sshbuf_len(encrypted) % blocksize) {
		ਜੇ ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* length in destination buffer */
	ਜੇ ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* encrypt */
	ਜੇ ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	ਜੇ ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_ਸਿਰਾ, MARK_ਸਿਰਾ_LEN)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* success */
	r = 0;

 ਬਾਹਰਲਾ:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, ਆਕਾਰ(salt));
	ਜੇ (ਕੁੰਜੀ != ਨਿਰਾ)
		freezero(ਕੁੰਜੀ, keylen + ivlen);
	ਜੇ (pubkeyblob != ਨਿਰਾ)
		freezero(pubkeyblob, pubkeylen);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
private2_uudecode(ਬਣਤਰ sshbuf *blob, ਬਣਤਰ sshbuf **decodedp)
{
	ਅਚਲ u_char *cp;
	ਮਾਪ_t encoded_len;
	ਪੂਰਨ r;
	u_char ਆਖਰੀ;
	ਬਣਤਰ sshbuf *encoded = ਨਿਰਾ, *decoded = ਨਿਰਾ;

	ਜੇ (blob == ਨਿਰਾ || decodedp == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	*decodedp = ਨਿਰਾ;

	ਜੇ ((encoded = sshbuf_new()) == ਨਿਰਾ ||
	    (decoded = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	ਜੇ (encoded_len < (MARK_BEGIN_LEN + MARK_ਸਿਰਾ_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	ਜਦੋਂ (encoded_len > 0) {
		ਜੇ (*cp != '\n' && *cp != '\r') {
			ਜੇ ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਆਖਰੀ = *cp;
		encoded_len--;
		cp++;
		ਜੇ (ਆਖਰੀ == '\n') {
			ਜੇ (encoded_len >= MARK_ਸਿਰਾ_LEN &&
			    memcmp(cp, MARK_ਸਿਰਾ, MARK_ਸਿਰਾ_LEN) == 0) {
				/* \0 terminate */
				ਜੇ ((r = sshbuf_put_u8(encoded, 0)) != 0)
					ਜਾਓ ਬਾਹਰਲਾ;
				ਰੋਕੋ;
			}
		}
	}
	ਜੇ (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* decode base64 */
	ਜੇ ((r = sshbuf_b64tod(decoded, (ਅੱਖਰ *)sshbuf_ptr(encoded))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* check magic */
	ਜੇ (sshbuf_len(decoded) < ਆਕਾਰ(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, ਆਕਾਰ(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	*decodedp = decoded;
	decoded = ਨਿਰਾ;
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
private2_decrypt(ਬਣਤਰ sshbuf *decoded, ਅਚਲ ਅੱਖਰ *passphrase,
    ਬਣਤਰ sshbuf **decryptedp, ਬਣਤਰ sshkey **pubkeyp)
{
	ਅੱਖਰ *ciphername = ਨਿਰਾ, *kdfname = ਨਿਰਾ;
	ਅਚਲ ਬਣਤਰ sshcipher *cipher = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਮਾਪ_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	ਬਣਤਰ sshbuf *kdf = ਨਿਰਾ, *decrypted = ਨਿਰਾ;
	ਬਣਤਰ sshcipher_ctx *ciphercontext = ਨਿਰਾ;
	ਬਣਤਰ sshkey *pubkey = ਨਿਰਾ;
	u_char *ਕੁੰਜੀ = ਨਿਰਾ, *salt = ਨਿਰਾ, *dp;
	u_int blocksize, ਗੇੜ, nkeys, encrypted_len, check1, check2;

	ਜੇ (decoded == ਨਿਰਾ || decryptedp == ਨਿਰਾ || pubkeyp == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	*decryptedp = ਨਿਰਾ;
	*pubkeyp = ਨਿਰਾ;

	ਜੇ ((decrypted = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* parse public portion of key */
	ਜੇ ((r = sshbuf_consume(decoded, ਆਕਾਰ(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((cipher = cipher_by_name(ciphername)) == ਨਿਰਾ) {
		r = SSH_ERR_ਕੁੰਜੀ_UNKNOWN_CIPHER;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_ਕੁੰਜੀ_UNKNOWN_CIPHER;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((passphrase == ਨਿਰਾ || ਲੜੀ_ਲੰਬਾਈ(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	ਜੇ (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	ਜੇ ((ਕੁੰਜੀ = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, keylen + ivlen)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (strcmp(kdfname, "bcrypt") == 0) {
		ਜੇ ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &ਗੇੜ)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ (ਗੇੜ > MAX_KDF_ਗੇੜ) {
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (bcrypt_pbkdf(passphrase, ਲੜੀ_ਲੰਬਾਈ(passphrase), salt, slen,
		    ਕੁੰਜੀ, keylen + ivlen, ਗੇੜ) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	/* check that an appropriate amount of auth data is present */
	ਜੇ (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* decrypt private portion of key */
	ਜੇ ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, ਕੁੰਜੀ, keylen,
	    ਕੁੰਜੀ + keylen, ivlen, 0)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		ਜੇ (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* there should be no trailing data */
	ਜੇ (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* check check bytes */
	ਜੇ ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (check1 != check2) {
		r = SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = ਨਿਰਾ;
	*pubkeyp = pubkey;
	pubkey = ਨਿਰਾ;
	r = 0;
 ਬਾਹਰਲਾ:
	cipher_free(ciphercontext);
	ਮੁਕਤ(ciphername);
	ਮੁਕਤ(kdfname);
	sshkey_free(pubkey);
	ਜੇ (salt != ਨਿਰਾ) {
		explicit_bzero(salt, slen);
		ਮੁਕਤ(salt);
	}
	ਜੇ (ਕੁੰਜੀ != ਨਿਰਾ) {
		explicit_bzero(ਕੁੰਜੀ, keylen + ivlen);
		ਮੁਕਤ(ਕੁੰਜੀ);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
sshkey_parse_private2(ਬਣਤਰ sshbuf *blob, ਪੂਰਨ type, ਅਚਲ ਅੱਖਰ *passphrase,
    ਬਣਤਰ sshkey **keyp, ਅੱਖਰ **commentp)
{
	ਅੱਖਰ *comment = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ sshbuf *decoded = ਨਿਰਾ, *decrypted = ਨਿਰਾ;
	ਬਣਤਰ sshkey *k = ਨਿਰਾ, *pubkey = ਨਿਰਾ;

	ਜੇ (keyp != ਨਿਰਾ)
		*keyp = ਨਿਰਾ;
	ਜੇ (commentp != ਨਿਰਾ)
		*commentp = ਨਿਰਾ;

	/* Undo base64 encoding and decrypt the private section */
	ਜੇ ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ (type != ਕੁੰਜੀ_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_ਕੁੰਜੀ_TYPE_MISMATCH;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Load the private key and comment */
	ਜੇ ((r = sshkey_ਨਿੱਜੀ_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Check deterministic padding after private section */
	ਜੇ ((r = private2_check_padding(decrypted)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Check that the public key in the envelope matches the private key */
	ਜੇ (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* success */
	r = 0;
	ਜੇ (keyp != ਨਿਰਾ) {
		*keyp = k;
		k = ਨਿਰਾ;
	}
	ਜੇ (commentp != ਨਿਰਾ) {
		*commentp = comment;
		comment = ਨਿਰਾ;
	}
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
sshkey_parse_private2_pubkey(ਬਣਤਰ sshbuf *blob, ਪੂਰਨ type,
    ਬਣਤਰ sshkey **keyp)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ sshbuf *decoded = ਨਿਰਾ;
	ਬਣਤਰ sshkey *pubkey = ਨਿਰਾ;
	u_int nkeys = 0;

	ਜੇ (keyp != ਨਿਰਾ)
		*keyp = ਨਿਰਾ;

	ਜੇ ((r = private2_uudecode(blob, &decoded)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* parse public key from unencrypted envelope */
	ਜੇ ((r = sshbuf_consume(decoded, ਆਕਾਰ(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Parse the public key */
	ਜੇ ((r = sshkey_froms(decoded, &pubkey)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ (type != ਕੁੰਜੀ_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_ਕੁੰਜੀ_TYPE_MISMATCH;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* success */
	r = 0;
	ਜੇ (keyp != ਨਿਰਾ) {
		*keyp = pubkey;
		pubkey = ਨਿਰਾ;
	}
 ਬਾਹਰਲਾ:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	ਵਾਪਸ r;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
ਸਥਿਰ ਪੂਰਨ
sshkey_ਨਿੱਜੀ_ਮੰਜ਼ਿਲ_blob_pem_pkcs8(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *buf,
    ਪੂਰਨ format, ਅਚਲ ਅੱਖਰ *_passphrase, ਅਚਲ ਅੱਖਰ *comment)
{
	ਪੂਰਨ was_shielded = sshkey_is_shielded(ਕੁੰਜੀ);
	ਪੂਰਨ success, r;
	ਪੂਰਨ blen, len = ਲੜੀ_ਲੰਬਾਈ(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : ਨਿਰਾ;
	ਅਚਲ EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : ਨਿਰਾ;
	ਅੱਖਰ *bptr;
	BIO *bio = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *blob;
	EVP_PKEY *pkey = ਨਿਰਾ;

	ਜੇ (len > 0 && len <= 4)
		ਵਾਪਸ SSH_ERR_PASSPHRASE_TOO_SHORT;
	ਜੇ ((blob = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((bio = BIO_new(BIO_s_mem())) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshkey_unshield_ਨਿੱਜੀ(ਕੁੰਜੀ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਚੋਣ (ਕੁੰਜੀ->type) {
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
		ਜੇ (format == SSHKEY_ਨਿੱਜੀ_PEM) {
			success = PEM_write_bio_ECPrivate_ਕੁੰਜੀ(bio,
			    EVP_PKEY_get0_EC_ਕੁੰਜੀ(ਕੁੰਜੀ->pkey),
			    cipher, passphrase, len, ਨਿਰਾ, ਨਿਰਾ);
		} ਨਹੀਂਤਾਂ {
			pkey = ਕੁੰਜੀ->pkey;
			EVP_PKEY_ਉੱਪਰ_ref(ਕੁੰਜੀ->pkey);
			success = 1;
		}
		ਰੋਕੋ;
	ਹਾਲਤ ਕੁੰਜੀ_RSA:
		ਜੇ (format == SSHKEY_ਨਿੱਜੀ_PEM) {
			success = PEM_write_bio_RSAPrivate_ਕੁੰਜੀ(bio,
			    EVP_PKEY_get0_RSA(ਕੁੰਜੀ->pkey),
			    cipher, passphrase, len, ਨਿਰਾ, ਨਿਰਾ);
		} ਨਹੀਂਤਾਂ {
			pkey = ਕੁੰਜੀ->pkey;
			EVP_PKEY_ਉੱਪਰ_ref(ਕੁੰਜੀ->pkey);
			success = 1;
		}
		ਰੋਕੋ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ OPENSSL_HAS_ED25519
	ਹਾਲਤ ਕੁੰਜੀ_ED25519:
		ਜੇ (format == SSHKEY_ਨਿੱਜੀ_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		} ਨਹੀਂਤਾਂ {
			pkey = EVP_PKEY_new_raw_ਨਿੱਜੀ_ਕੁੰਜੀ(EVP_PKEY_ED25519,
			    ਨਿਰਾ, ਕੁੰਜੀ->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != ਨਿਰਾ;
		}
		ਰੋਕੋ;
#ਜੇ_ਅੰਤ
	ਮੂਲ:
		success = 0;
		ਰੋਕੋ;
	}
	ਜੇ (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (format == SSHKEY_ਨਿੱਜੀ_PKCS8) {
		ਜੇ ((success = PEM_write_bio_ਨਿੱਜੀ_ਕੁੰਜੀ(bio, pkey, cipher,
		    passphrase, len, ਨਿਰਾ, ਨਿਰਾ)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	ਜੇ ((blen = BIO_get_mem_ਅੰਕੜੇ(bio, &bptr)) <= 0) {
		r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put(blob, bptr, blen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	r = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (was_shielded)
		r = sshkey_shield_ਨਿੱਜੀ(ਕੁੰਜੀ);
	ਜੇ (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	ਵਾਪਸ r;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
ਪੂਰਨ
sshkey_ਨਿੱਜੀ_ਮੰਜ਼ਿਲ_fileblob(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *blob,
    ਅਚਲ ਅੱਖਰ *passphrase, ਅਚਲ ਅੱਖਰ *comment,
    ਪੂਰਨ format, ਅਚਲ ਅੱਖਰ *openssh_format_cipher, ਪੂਰਨ openssh_format_ਗੇੜ)
{
	ਚੋਣ (ਕੁੰਜੀ->type) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
	ਹਾਲਤ ਕੁੰਜੀ_RSA:
	ਹਾਲਤ ਕੁੰਜੀ_ED25519:
		ਰੋਕੋ; /* see below */
#ਨਹੀਂਤਾਂ /* WITH_OPENSSL */
	ਹਾਲਤ ਕੁੰਜੀ_ED25519:
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK:
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਹਾਲਤ ਕੁੰਜੀ_MLDSA44_ED25519:
		ਵਾਪਸ sshkey_ਨਿੱਜੀ_ਮੰਜ਼ਿਲ_blob2(ਕੁੰਜੀ, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_ਗੇੜ);
	ਮੂਲ:
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN;
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਚੋਣ (format) {
	ਹਾਲਤ SSHKEY_ਨਿੱਜੀ_OPENSSH:
		ਵਾਪਸ sshkey_ਨਿੱਜੀ_ਮੰਜ਼ਿਲ_blob2(ਕੁੰਜੀ, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_ਗੇੜ);
	ਹਾਲਤ SSHKEY_ਨਿੱਜੀ_PEM:
	ਹਾਲਤ SSHKEY_ਨਿੱਜੀ_PKCS8:
		ਵਾਪਸ sshkey_ਨਿੱਜੀ_ਮੰਜ਼ਿਲ_blob_pem_pkcs8(ਕੁੰਜੀ, blob,
		    format, passphrase, comment);
	ਮੂਲ:
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਸਥਿਰ ਪੂਰਨ
translate_libcrypto_error(ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ pem_err)
{
	ਪੂਰਨ pem_reason = ERR_GET_REASON(pem_err);

	ਚੋਣ (ERR_GET_LIB(pem_err)) {
	ਹਾਲਤ ERR_LIB_PEM:
		ਚੋਣ (pem_reason) {
		ਹਾਲਤ PEM_R_BAD_PASSWORD_READ:
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PEM_R_PROBLEMS_GETTING_PASSWORD
		ਹਾਲਤ PEM_R_PROBLEMS_GETTING_PASSWORD:
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ PEM_R_BAD_DECRYPT
		ਹਾਲਤ PEM_R_BAD_DECRYPT:
#ਜੇ_ਅੰਤ
			ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE;
		ਮੂਲ:
			ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
		}
	ਹਾਲਤ ERR_LIB_EVP:
		ਚੋਣ (pem_reason) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ EVP_R_BAD_DECRYPT
		ਹਾਲਤ EVP_R_BAD_DECRYPT:
			ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE;
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ EVP_R_BN_DECODE_ERROR
		ਹਾਲਤ EVP_R_BN_DECODE_ERROR:
#ਜੇ_ਅੰਤ
		ਹਾਲਤ EVP_R_DECODE_ERROR:
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ EVP_R_ਨਿੱਜੀ_ਕੁੰਜੀ_DECODE_ERROR
		ਹਾਲਤ EVP_R_ਨਿੱਜੀ_ਕੁੰਜੀ_DECODE_ERROR:
#ਜੇ_ਅੰਤ
			ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
		ਮੂਲ:
			ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
		}
	ਹਾਲਤ ERR_LIB_ASN1:
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ERR_LIB_OSSL_DECODER
	ਹਾਲਤ ERR_LIB_OSSL_DECODER:
#ਜੇ_ਅੰਤ
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
}

ਸਥਿਰ ਖਾਲੀ
clear_libcrypto_errors(ਖਾਲੀ)
{
	ਜਦੋਂ (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
ਸਥਿਰ ਪੂਰਨ
convert_libcrypto_error(ਖਾਲੀ)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	ਜੇ (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE)
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE;
	ਵਾਪਸ translate_libcrypto_error(ERR_peek_ਆਖਰੀ_error());
}

ਸਥਿਰ ਪੂਰਨ
pem_passphrase_cb(ਅੱਖਰ *buf, ਪੂਰਨ ਮਾਪ, ਪੂਰਨ rwflag, ਖਾਲੀ *u)
{
	ਅੱਖਰ *p = (ਅੱਖਰ *)u;
	ਮਾਪ_t len;

	ਜੇ (p == ਨਿਰਾ || (len = ਲੜੀ_ਲੰਬਾਈ(p)) == 0)
		ਵਾਪਸ -1;
	ਜੇ (ਮਾਪ < 0 || len > (ਮਾਪ_t)ਮਾਪ)
		ਵਾਪਸ -1;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(buf, p, len);
	ਵਾਪਸ (ਪੂਰਨ)len;
}

ਸਥਿਰ ਪੂਰਨ
sshkey_parse_ਨਿੱਜੀ_pem_fileblob(ਬਣਤਰ sshbuf *blob, ਪੂਰਨ type,
    ਅਚਲ ਅੱਖਰ *passphrase, ਬਣਤਰ sshkey **keyp)
{
	EVP_PKEY *pk = ਨਿਰਾ;
	ਬਣਤਰ sshkey *prv = ਨਿਰਾ;
	BIO *bio = ਨਿਰਾ;
	ਪੂਰਨ r;
	RSA *rsa = ਨਿਰਾ;
	EC_ਕੁੰਜੀ *ecdsa = ਨਿਰਾ;

	ਜੇ (keyp != ਨਿਰਾ)
		*keyp = ਨਿਰਾ;

	ਜੇ ((bio = BIO_new(BIO_s_mem())) == ਨਿਰਾ || sshbuf_len(blob) > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (ਪੂਰਨ)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	clear_libcrypto_errors();
	ਜੇ ((pk = PEM_read_bio_ਨਿੱਜੀ_ਕੁੰਜੀ(bio, ਨਿਰਾ, pem_passphrase_cb,
	    (ਅੱਖਰ *)passphrase)) == ਨਿਰਾ) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		ਜੇ (passphrase != ਨਿਰਾ && *passphrase != '\0')
			r = SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE;
		ਨਹੀਂਤਾਂ
			r = convert_libcrypto_error();
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_PKEY_ਅਧਾਰ_id(pk) == EVP_PKEY_RSA &&
	    (type == ਕੁੰਜੀ_UNSPEC || type == ਕੁੰਜੀ_RSA)) {
		ਜੇ ((prv = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((rsa = EVP_PKEY_get1_RSA(pk)) == ਨਿਰਾ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		prv->type = ਕੁੰਜੀ_RSA;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#ਜੇ_ਅੰਤ
		ਜੇ (RSA_blinding_on(rsa, ਨਿਰਾ) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		EVP_PKEY_ਉੱਪਰ_ref(pk);
		prv->pkey = pk;
		ਜੇ ((r = sshkey_check_rsa_ਲੰਮਾਈ(prv, 0)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (EVP_PKEY_ਅਧਾਰ_id(pk) == EVP_PKEY_EC &&
	    (type == ਕੁੰਜੀ_UNSPEC || type == ਕੁੰਜੀ_ECDSA)) {
		ਜੇ ((prv = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((prv->ecdsa_nid = sshkey_ecdsa_fixup_ਸਮੂਹ(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_ਕੁੰਜੀ(pk)) == ਨਿਰਾ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		prv->type = ਕੁੰਜੀ_ECDSA;
		ਜੇ (sshkey_ਵਕਰ_nid_ਮੰਜ਼ਿਲ_name(prv->ecdsa_nid) == ਨਿਰਾ ||
		    sshkey_ec_validate_ਜਨਤਕ(EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(ecdsa),
		    EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(ecdsa)) != 0 ||
		    sshkey_ec_validate_ਨਿੱਜੀ(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		EVP_PKEY_ਉੱਪਰ_ref(pk);
		prv->pkey = pk;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
		ਜੇ (prv != ਨਿਰਾ && prv->pkey != ਨਿਰਾ)
			sshkey_dump_ec_ਕੁੰਜੀ(EVP_PKEY_get0_EC_ਕੁੰਜੀ(prv->pkey));
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ OPENSSL_HAS_ED25519
	} ਨਹੀਂਤਾਂ ਜੇ (EVP_PKEY_ਅਧਾਰ_id(pk) == EVP_PKEY_ED25519 &&
	    (type == ਕੁੰਜੀ_UNSPEC || type == ਕੁੰਜੀ_ED25519)) {
		ਮਾਪ_t len;

		ਜੇ ((prv = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ ||
		    (prv->ed25519_sk = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ED25519_SK_SZ)) == ਨਿਰਾ ||
		    (prv->ed25519_pk = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ED25519_PK_SZ)) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		prv->type = ਕੁੰਜੀ_ED25519;
		len = ED25519_PK_SZ;
		ਜੇ (!EVP_PKEY_get_raw_ਜਨਤਕ_ਕੁੰਜੀ(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		ਜੇ (!EVP_PKEY_get_raw_ਨਿੱਜੀ_ਕੁੰਜੀ(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/* Append the public key to our private key */
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_PK
		sshbuf_dump_ਅੰਕੜੇ(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#ਜੇ_ਅੰਤ
#ਜੇ_ਅੰਤ /* OPENSSL_HAS_ED25519 */
	} ਨਹੀਂਤਾਂ {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	r = 0;
	ਜੇ (keyp != ਨਿਰਾ) {
		*keyp = prv;
		prv = ਨਿਰਾ;
	}
 ਬਾਹਰਲਾ:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_ਕੁੰਜੀ_free(ecdsa);
	sshkey_free(prv);
	ਵਾਪਸ r;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਪੂਰਨ
sshkey_parse_ਨਿੱਜੀ_fileblob_type(ਬਣਤਰ sshbuf *blob, ਪੂਰਨ type,
    ਅਚਲ ਅੱਖਰ *passphrase, ਬਣਤਰ sshkey **keyp, ਅੱਖਰ **commentp)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (keyp != ਨਿਰਾ)
		*keyp = ਨਿਰਾ;
	ਜੇ (commentp != ਨਿਰਾ)
		*commentp = ਨਿਰਾ;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	ਜੇ (r != SSH_ERR_INVALID_FORMAT)
		ਵਾਪਸ r;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਵਾਪਸ sshkey_parse_ਨਿੱਜੀ_pem_fileblob(blob, type,
	    passphrase, keyp);
#ਨਹੀਂਤਾਂ
	ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
}

ਪੂਰਨ
sshkey_parse_ਨਿੱਜੀ_fileblob(ਬਣਤਰ sshbuf *ਬਫਰ, ਅਚਲ ਅੱਖਰ *passphrase,
    ਬਣਤਰ sshkey **keyp, ਅੱਖਰ **commentp)
{
	ਜੇ (keyp != ਨਿਰਾ)
		*keyp = ਨਿਰਾ;
	ਜੇ (commentp != ਨਿਰਾ)
		*commentp = ਨਿਰਾ;

	ਵਾਪਸ sshkey_parse_ਨਿੱਜੀ_fileblob_type(ਬਫਰ, ਕੁੰਜੀ_UNSPEC,
	    passphrase, keyp, commentp);
}

ਖਾਲੀ
sshkey_sig_details_free(ਬਣਤਰ sshkey_sig_details *details)
{
	freezero(details, ਆਕਾਰ(*details));
}

ਪੂਰਨ
sshkey_parse_pubkey_from_ਨਿੱਜੀ_fileblob_type(ਬਣਤਰ sshbuf *blob, ਪੂਰਨ type,
    ਬਣਤਰ sshkey **pubkeyp)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (pubkeyp != ਨਿਰਾ)
		*pubkeyp = ਨਿਰਾ;
	/* only new-format private keys bundle a public key inside */
	ਜੇ ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}
