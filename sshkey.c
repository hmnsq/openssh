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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ <openssl/err.h>
#ಅನ್ತರ್ಭಾವ <openssl/pem.h>
#ಆದರೆ_ಅಂತ್ಯ

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
#ವ್ಯಾಖ್ಯಾನಿಸು SSHKEY_ಆಂತರಿಕ
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "ssh-sk.h"
#ಅನ್ತರ್ಭಾವ "ssh-pkcs11.h"

#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#ವ್ಯಾಖ್ಯಾನಿಸು MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#ವ್ಯಾಖ್ಯಾನಿಸು MARK_ಕೊನೆ		"-----END OPENSSH PRIVATE KEY-----\n"
#ವ್ಯಾಖ್ಯಾನಿಸು MARK_BEGIN_LEN		(ಗಾತ್ರ(MARK_BEGIN) - 1)
#ವ್ಯಾಖ್ಯಾನಿಸು MARK_ಕೊನೆ_LEN		(ಗಾತ್ರ(MARK_ಕೊನೆ) - 1)
#ವ್ಯಾಖ್ಯಾನಿಸು KDFNAME			"bcrypt"
#ವ್ಯಾಖ್ಯಾನಿಸು AUTH_MAGIC		"openssh-key-v1"
#ವ್ಯಾಖ್ಯಾನಿಸು SALT_LEN		16
#ವ್ಯಾಖ್ಯಾನಿಸು DEFAULT_CIPHERNAME	"aes256-ctr"
#ವ್ಯಾಖ್ಯಾನಿಸು	DEFAULT_ಸುತ್ತುಗಳು		32
#ವ್ಯಾಖ್ಯಾನಿಸು	MAX_KDF_ಸುತ್ತುಗಳು		(1<<20)

/*
 * Constants relating to "shielding" support; protection of keys expected
 * to remain in memory for long durations
 */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHKEY_SHIELD_PREKEY_LEN	(16 * 1024)
#ವ್ಯಾಖ್ಯಾನಿಸು SSHKEY_SHIELD_CIPHER		"aes256-ctr" /* XXX want AES-EME* */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHKEY_SHIELD_PREKEY_HASH	SSH_DIGEST_SHA512

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ sshkey_from_blob_ಆಂತರಿಕ(ರಚನೆ sshbuf *buf,
    ರಚನೆ sshkey **keyp, ಪೂರ್ಣಾಂಕ allow_cert,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg_allowlist, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ca_sigalg_allowlist);

/* Supported key types */
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ed25519_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ed25519_cert_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ed25519_sk_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_mldsa44_ed25519_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
# ifdef ENABLE_SK
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_sk_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_sk_cert_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_nistp256_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_nistp384_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_nistp521_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_rsa_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_rsa_cert_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_rsa_sha256_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_rsa_sha256_cert_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_rsa_sha512_impl;
ಬಾಹ್ಯ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_rsa_sha512_cert_impl;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl * ಸ್ಥಿರಾಂಕ keyimpls[] = {
	&sshkey_ed25519_impl,
	&sshkey_ed25519_cert_impl,
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_SK
	&sshkey_ed25519_sk_impl,
	&sshkey_ed25519_sk_cert_impl,
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_MLDSA
	&sshkey_mldsa44_ed25519_impl,
	&sshkey_mldsa44_ed25519_cert_impl,
#ಆದರೆ_ಅಂತ್ಯ /* USE_MLDSA */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
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
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಖಾಲಿ
};

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *
sshkey_impl_from_type(ಪೂರ್ಣಾಂಕ type)
{
	ಪೂರ್ಣಾಂಕ i;

	ಗಾಗಿ (i = 0; keyimpls[i] != ಖಾಲಿ; i++) {
		ಆದರೆ (keyimpls[i]->type == type)
			ಹಿಂತಿರುಗಿ keyimpls[i];
	}
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *
sshkey_impl_from_type_nid(ಪೂರ್ಣಾಂಕ type, ಪೂರ್ಣಾಂಕ nid)
{
	ಪೂರ್ಣಾಂಕ i;

	ಗಾಗಿ (i = 0; keyimpls[i] != ಖಾಲಿ; i++) {
		ಆದರೆ (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			ಹಿಂತಿರುಗಿ keyimpls[i];
	}
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *
sshkey_impl_from_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k)
{
	ಆದರೆ (k == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
sshkey_type(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;

	ಆದರೆ ((impl = sshkey_impl_from_ಕೀಲಿ(k)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ "unknown";
	ಹಿಂತಿರುಗಿ impl->shortname;
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
sshkey_ssh_name_from_type_nid(ಪೂರ್ಣಾಂಕ type, ಪೂರ್ಣಾಂಕ nid)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;

	ಆದರೆ ((impl = sshkey_impl_from_type_nid(type, nid)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ "ssh-unknown";
	ಹಿಂತಿರುಗಿ impl->name;
}

ಪೂರ್ಣಾಂಕ
sshkey_type_is_cert(ಪೂರ್ಣಾಂಕ type)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;

	ಆದರೆ ((impl = sshkey_impl_from_type(type)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ impl->cert;
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
sshkey_ssh_name(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k)
{
	ಹಿಂತಿರುಗಿ sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
sshkey_ssh_name_plain(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k)
{
	ಹಿಂತಿರುಗಿ sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
type_from_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಪೂರ್ಣಾಂಕ allow_short)
{
	ಪೂರ್ಣಾಂಕ i;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;

	ಗಾಗಿ (i = 0; keyimpls[i] != ಖಾಲಿ; i++) {
		impl = keyimpls[i];
		ಆದರೆ (impl->name != ಖಾಲಿ && strcmp(name, impl->name) == 0)
			ಹಿಂತಿರುಗಿ impl->type;
		/* Only allow shortname matches for plain key types */
		ಆದರೆ (allow_short && !impl->cert && impl->shortname != ಖಾಲಿ &&
		    strcasecmp(impl->shortname, name) == 0)
			ಹಿಂತಿರುಗಿ impl->type;
	}
	ಹಿಂತಿರುಗಿ ಕೀಲಿ_UNSPEC;
}

ಪೂರ್ಣಾಂಕ
sshkey_type_from_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಹಿಂತಿರುಗಿ type_from_name(name, 0);
}

ಪೂರ್ಣಾಂಕ
sshkey_type_from_shortname(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಹಿಂತಿರುಗಿ type_from_name(name, 1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಕೀಲಿ_type_is_ecdsa_variant(ಪೂರ್ಣಾಂಕ type)
{
	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_CERT:
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK_CERT:
		ಹಿಂತಿರುಗಿ 1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshkey_ecdsa_nid_from_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಪೂರ್ಣಾಂಕ i;

	ಗಾಗಿ (i = 0; keyimpls[i] != ಖಾಲಿ; i++) {
		ಆದರೆ (!ಕೀಲಿ_type_is_ecdsa_variant(keyimpls[i]->type))
			ಮುಂದುವರಿ;
		ಆದರೆ (keyimpls[i]->name != ಖಾಲಿ &&
		    strcmp(name, keyimpls[i]->name) == 0)
			ಹಿಂತಿರುಗಿ keyimpls[i]->nid;
	}
	ಹಿಂತಿರುಗಿ -1;
}

ಪೂರ್ಣಾಂಕ
sshkey_ಹೊಂದಿಕೆ_keyname_ಗಮ್ಯ_sigalgs(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *keyname, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sigalgs)
{
	ಪೂರ್ಣಾಂಕ ktype;

	ಆದರೆ (sigalgs == ಖಾಲಿ || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == ಕೀಲಿ_UNSPEC)
		ಹಿಂತಿರುಗಿ 0;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ktype == ಕೀಲಿ_RSA) {
		ಹಿಂತಿರುಗಿ ಹೊಂದಿಕೆ_ನಮೂನೆ_list("ssh-rsa", sigalgs, 0) == 1 ||
		    ಹೊಂದಿಕೆ_ನಮೂನೆ_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    ಹೊಂದಿಕೆ_ನಮೂನೆ_list("rsa-sha2-512", sigalgs, 0) == 1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ktype == ಕೀಲಿ_RSA_CERT) {
		ಹಿಂತಿರುಗಿ ಹೊಂದಿಕೆ_ನಮೂನೆ_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    ಹೊಂದಿಕೆ_ನಮೂನೆ_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    ಹೊಂದಿಕೆ_ನಮೂನೆ_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ktype == ಕೀಲಿ_ECDSA_SK) {
		ಹಿಂತಿರುಗಿ ಹೊಂದಿಕೆ_ನಮೂನೆ_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || ಹೊಂದಿಕೆ_ನಮೂನೆ_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ktype == ಕೀಲಿ_ECDSA_SK_CERT) {
		ಹಿಂತಿರುಗಿ ಹೊಂದಿಕೆ_ನಮೂನೆ_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || ಹೊಂದಿಕೆ_ನಮೂನೆ_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ ಹೊಂದಿಕೆ_ನಮೂನೆ_list(keyname, sigalgs, 0) == 1;
}

ಅಕ್ಷರ *
sshkey_alg_list(ಪೂರ್ಣಾಂಕ certs_only, ಪೂರ್ಣಾಂಕ plain_only, ಪೂರ್ಣಾಂಕ include_sigonly, ಅಕ್ಷರ sep)
{
	ಅಕ್ಷರ *ret = ಖಾಲಿ;
	ಗಾತ್ರ_t i;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;
	ಅಕ್ಷರ sep_str[2] = {sep, '\0'};

	ಗಾಗಿ (i = 0; keyimpls[i] != ಖಾಲಿ; i++) {
		impl = keyimpls[i];
		ಆದರೆ (impl->name == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆದರೆ (!include_sigonly && impl->sigonly)
			ಮುಂದುವರಿ;
		ಆದರೆ ((certs_only && !impl->cert) || (plain_only && impl->cert))
			ಮುಂದುವರಿ;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sshkey_ಹೆಸರುಗಳು_valid2(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಹೆಸರುಗಳು, ಪೂರ್ಣಾಂಕ allow_wildcard, ಪೂರ್ಣಾಂಕ plain_only)
{
	ಅಕ್ಷರ *s, *cp, *p;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;
	ಪೂರ್ಣಾಂಕ i, type;

	ಆದರೆ (ಹೆಸರುಗಳು == ಖಾಲಿ || strcmp(ಹೆಸರುಗಳು, "") == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((s = cp = strdup(ಹೆಸರುಗಳು)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಗಾಗಿ ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		ಆದರೆ (type == ಕೀಲಿ_UNSPEC) {
			ಆದರೆ (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = ಖಾಲಿ;
				ಗಾಗಿ (i = 0; keyimpls[i] != ಖಾಲಿ; i++) {
					ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						ನಿಲ್ಲಿಸು;
					}
				}
				ಆದರೆ (impl != ಖಾಲಿ)
					ಮುಂದುವರಿ;
			}
			ಬಿಡುಗಡೆ(s);
			ಹಿಂತಿರುಗಿ 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (plain_only && sshkey_type_is_cert(type)) {
			ಬಿಡುಗಡೆ(s);
			ಹಿಂತಿರುಗಿ 0;
		}
	}
	ಬಿಡುಗಡೆ(s);
	ಹಿಂತಿರುಗಿ 1;
}

u_int
sshkey_ಗಾತ್ರ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;

	ಆದರೆ ((impl = sshkey_impl_from_ಕೀಲಿ(k)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (impl->funcs->ಗಾತ್ರ_2 != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ impl->funcs->ಗಾತ್ರ_2(k);
	ಹಿಂತಿರುಗಿ impl->keybits;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshkey_type_is_valid_ca(ಪೂರ್ಣಾಂಕ type)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;

	ಆದರೆ ((impl = sshkey_impl_from_type(type)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	/* All non-certificate types may act as CAs */
	ಹಿಂತಿರುಗಿ !impl->cert;
}

ಪೂರ್ಣಾಂಕ
sshkey_is_cert(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k)
{
	ಆದರೆ (k == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ sshkey_type_is_cert(k->type);
}

ಪೂರ್ಣಾಂಕ
sshkey_is_sk(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k)
{
	ಆದರೆ (k == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆಯ್ಕೆ (sshkey_type_plain(k->type)) {
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK:
		ಹಿಂತಿರುಗಿ 1;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
ಪೂರ್ಣಾಂಕ
sshkey_type_plain(ಪೂರ್ಣಾಂಕ type)
{
	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA_CERT:
		ಹಿಂತಿರುಗಿ ಕೀಲಿ_RSA;
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_CERT:
		ಹಿಂತಿರುಗಿ ಕೀಲಿ_ECDSA;
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK_CERT:
		ಹಿಂತಿರುಗಿ ಕೀಲಿ_ECDSA_SK;
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_CERT:
		ಹಿಂತಿರುಗಿ ಕೀಲಿ_ED25519;
	ಸ್ಥಿತಿ ಕೀಲಿ_MLDSA44_ED25519_CERT:
		ಹಿಂತಿರುಗಿ ಕೀಲಿ_MLDSA44_ED25519;
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK_CERT:
		ಹಿಂತಿರುಗಿ ಕೀಲಿ_ED25519_SK;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ type;
	}
}

/* Return the cert equivalent to a plain key type */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshkey_type_certified(ಪೂರ್ಣಾಂಕ type)
{
	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
		ಹಿಂತಿರುಗಿ ಕೀಲಿ_RSA_CERT;
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
		ಹಿಂತಿರುಗಿ ಕೀಲಿ_ECDSA_CERT;
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
		ಹಿಂತಿರುಗಿ ಕೀಲಿ_ECDSA_SK_CERT;
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519:
		ಹಿಂತಿರುಗಿ ಕೀಲಿ_ED25519_CERT;
	ಸ್ಥಿತಿ ಕೀಲಿ_MLDSA44_ED25519:
		ಹಿಂತಿರುಗಿ ಕೀಲಿ_MLDSA44_ED25519_CERT;
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK:
		ಹಿಂತಿರುಗಿ ಕೀಲಿ_ED25519_SK_CERT;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ EVP_MD *
ssh_digest_ಗಮ್ಯ_md(ಪೂರ್ಣಾಂಕ hash_alg)
{
	ಆಯ್ಕೆ (hash_alg) {
	ಸ್ಥಿತಿ SSH_DIGEST_SHA1:
		ಹಿಂತಿರುಗಿ EVP_sha1();
	ಸ್ಥಿತಿ SSH_DIGEST_SHA256:
		ಹಿಂತಿರುಗಿ EVP_sha256();
	ಸ್ಥಿತಿ SSH_DIGEST_SHA384:
		ಹಿಂತಿರುಗಿ EVP_sha384();
	ಸ್ಥಿತಿ SSH_DIGEST_SHA512:
		ಹಿಂತಿರುಗಿ EVP_sha512();
	}
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಪೂರ್ಣಾಂಕ
sshkey_pkey_digest_sign(EVP_PKEY *pkey, ಪೂರ್ಣಾಂಕ hash_alg, u_char **sigp,
    ಗಾತ್ರ_t *lenp, ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen)
{
	EVP_MD_CTX *ctx = ಖಾಲಿ;
	u_char *sig = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret;
	ಗಾತ್ರ_t slen;
	ಸ್ಥಿರಾಂಕ EVP_MD *evpmd;

	*sigp = ಖಾಲಿ;
	*lenp = 0;

	slen = EVP_PKEY_ಗಾತ್ರ(pkey);
	ಆದರೆ (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_ಗಮ್ಯ_md(hash_alg)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	ಆದರೆ ((sig = ಸ್ಮರಣೆ_ಕೊಡು(slen)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;

	ಆದರೆ ((ctx = EVP_MD_CTX_new()) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_DigestSignInit(ctx, ಖಾಲಿ, evpmd, ಖಾಲಿ, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, ದತ್ತಾಂಶ, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = ಖಾಲಿ;
	ret = 0;

 ಹೊರಹೋಗು:
	EVP_MD_CTX_free(ctx);
	ಬಿಡುಗಡೆ(sig);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sshkey_pkey_digest_verify(EVP_PKEY *pkey, ಪೂರ್ಣಾಂಕ hash_alg, ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ,
    ಗಾತ್ರ_t datalen, u_char *sigbuf, ಗಾತ್ರ_t siglen)
{
	EVP_MD_CTX *ctx = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಸ್ಥಿರಾಂಕ EVP_MD *evpmd;

	ಆದರೆ ((evpmd = ssh_digest_ಗಮ್ಯ_md(hash_alg)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((ctx = EVP_MD_CTX_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ (EVP_DigestVerifyInit(ctx, ಖಾಲಿ, evpmd, ಖಾಲಿ, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆಯ್ಕೆ (EVP_DigestVerify(ctx, sigbuf, siglen, ದತ್ತಾಂಶ, datalen)) {
	ಸ್ಥಿತಿ 1:
		ret = 0;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ನಿಲ್ಲಿಸು;
	}

 ಹೊರಹೋಗು:
	EVP_MD_CTX_free(ctx);
	ಹಿಂತಿರುಗಿ ret;
}

/* XXX: these are really begging for a table-driven approach */
ಪೂರ್ಣಾಂಕ
sshkey_ವಕ್ರ_name_ಗಮ್ಯ_nid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಆದರೆ (strcmp(name, "nistp256") == 0)
		ಹಿಂತಿರುಗಿ NID_X9_62_prime256v1;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "nistp384") == 0)
		ಹಿಂತಿರುಗಿ NID_secp384r1;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "nistp521") == 0)
		ಹಿಂತಿರುಗಿ NID_secp521r1;
	ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ -1;
}

u_int
sshkey_ವಕ್ರ_nid_ಗಮ್ಯ_ಬಿಟ್ಟುಗಳು(ಪೂರ್ಣಾಂಕ nid)
{
	ಆಯ್ಕೆ (nid) {
	ಸ್ಥಿತಿ NID_X9_62_prime256v1:
		ಹಿಂತಿರುಗಿ 256;
	ಸ್ಥಿತಿ NID_secp384r1:
		ಹಿಂತಿರುಗಿ 384;
	ಸ್ಥಿತಿ NID_secp521r1:
		ಹಿಂತಿರುಗಿ 521;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ 0;
	}
}

ಪೂರ್ಣಾಂಕ
sshkey_ecdsa_ಬಿಟ್ಟುಗಳು_ಗಮ್ಯ_nid(ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು)
{
	ಆಯ್ಕೆ (ಬಿಟ್ಟುಗಳು) {
	ಸ್ಥಿತಿ 256:
		ಹಿಂತಿರುಗಿ NID_X9_62_prime256v1;
	ಸ್ಥಿತಿ 384:
		ಹಿಂತಿರುಗಿ NID_secp384r1;
	ಸ್ಥಿತಿ 521:
		ಹಿಂತಿರುಗಿ NID_secp521r1;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
sshkey_ವಕ್ರ_nid_ಗಮ್ಯ_name(ಪೂರ್ಣಾಂಕ nid)
{
	ಆಯ್ಕೆ (nid) {
	ಸ್ಥಿತಿ NID_X9_62_prime256v1:
		ಹಿಂತಿರುಗಿ "nistp256";
	ಸ್ಥಿತಿ NID_secp384r1:
		ಹಿಂತಿರುಗಿ "nistp384";
	ಸ್ಥಿತಿ NID_secp521r1:
		ಹಿಂತಿರುಗಿ "nistp521";
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
}

ಪೂರ್ಣಾಂಕ
sshkey_ec_nid_ಗಮ್ಯ_hash_alg(ಪೂರ್ಣಾಂಕ nid)
{
	ಪೂರ್ಣಾಂಕ kbits = sshkey_ವಕ್ರ_nid_ಗಮ್ಯ_ಬಿಟ್ಟುಗಳು(nid);

	ಆದರೆ (kbits <= 0)
		ಹಿಂತಿರುಗಿ -1;

	/* RFC5656 section 6.2.1 */
	ಆದರೆ (kbits <= 256)
		ಹಿಂತಿರುಗಿ SSH_DIGEST_SHA256;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (kbits <= 384)
		ಹಿಂತಿರುಗಿ SSH_DIGEST_SHA384;
	ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ SSH_DIGEST_SHA512;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

ಸ್ಥಿರ ಶೂನ್ಯ
cert_free(ರಚನೆ sshkey_cert *cert)
{
	u_int i;

	ಆದರೆ (cert == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	ಬಿಡುಗಡೆ(cert->ಕೀಲಿ_id);
	ಗಾಗಿ (i = 0; i < cert->nprincipals; i++)
		ಬಿಡುಗಡೆ(cert->principals[i]);
	ಬಿಡುಗಡೆ(cert->principals);
	sshkey_free(cert->signature_ಕೀಲಿ);
	ಬಿಡುಗಡೆ(cert->signature_type);
	freezero(cert, ಗಾತ್ರ(*cert));
}

ಸ್ಥಿರ ರಚನೆ sshkey_cert *
cert_new(ಶೂನ್ಯ)
{
	ರಚನೆ sshkey_cert *cert;

	ಆದರೆ ((cert = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*cert))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಆದರೆ ((cert->certblob = sshbuf_new()) == ಖಾಲಿ ||
	    (cert->critical = sshbuf_new()) == ಖಾಲಿ ||
	    (cert->extensions = sshbuf_new()) == ಖಾಲಿ) {
		cert_free(cert);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	cert->ಕೀಲಿ_id = ಖಾಲಿ;
	cert->principals = ಖಾಲಿ;
	cert->signature_ಕೀಲಿ = ಖಾಲಿ;
	cert->signature_type = ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ cert;
}

ರಚನೆ sshkey *
sshkey_new(ಪೂರ್ಣಾಂಕ type)
{
	ರಚನೆ sshkey *k;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl = ಖಾಲಿ;

	ಆದರೆ (type != ಕೀಲಿ_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	/* All non-certificate types may act as CAs */
	ಆದರೆ ((k = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*k))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	k->type = type;
	k->ecdsa_nid = -1;
	ಆದರೆ (impl != ಖಾಲಿ && impl->funcs->alloc != ಖಾಲಿ) {
		ಆದರೆ (impl->funcs->alloc(k) != 0) {
			ಬಿಡುಗಡೆ(k);
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
		}
	}
	ಆದರೆ (sshkey_is_cert(k)) {
		ಆದರೆ ((k->cert = cert_new()) == ಖಾಲಿ) {
			sshkey_free(k);
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
		}
	}

	ಹಿಂತಿರುಗಿ k;
}

/* Frees common FIDO fields */
ಶೂನ್ಯ
sshkey_sk_cleanup(ರಚನೆ sshkey *k)
{
	ಬಿಡುಗಡೆ(k->sk_application);
	sshbuf_free(k->sk_ಕೀಲಿ_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = ಖಾಲಿ;
	k->sk_ಕೀಲಿ_handle = k->sk_reserved = ಖಾಲಿ;
}

#ಆದರೆ defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#ಅಥವಾಆದರೆ defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#ಇಲ್ಲದಿದ್ದರೆ
# define PREKEY_MMAP_FLAG	0
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshkey_prekey_alloc(u_char **prekeyp, ಗಾತ್ರ_t len)
{
#ಆದರೆ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = ಖಾಲಿ;
	ಆದರೆ ((prekey = mmap(ಖಾಲಿ, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
#ಆದರೆ defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(ಶೂನ್ಯ)madvise(prekey, len, MADV_DONTDUMP);
#ಆದರೆ_ಅಂತ್ಯ
	*prekeyp = prekey;
#ಇಲ್ಲದಿದ್ದರೆ
	*prekeyp = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, len);
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_MMAP et al */
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshkey_prekey_free(ಶೂನ್ಯ *prekey, ಗಾತ್ರ_t len)
{
#ಆದರೆ defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	ಆದರೆ (prekey == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	munmap(prekey, len);
#ಇಲ್ಲದಿದ್ದರೆ
	ಬಿಡುಗಡೆ(prekey);
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_MMAP et al */
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshkey_free_contents(ರಚನೆ sshkey *k)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;

	ಆದರೆ (k == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_ಕೀಲಿ_free(k);
	ಆದರೆ ((impl = sshkey_impl_from_type(k->type)) != ಖಾಲಿ &&
	    impl->funcs->cleanup != ಖಾಲಿ)
		impl->funcs->cleanup(k);
	ಆದರೆ (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_ಖಾಸಗಿ, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

ಶೂನ್ಯ
sshkey_free(ರಚನೆ sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, ಗಾತ್ರ(*k));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
cert_compare(ರಚನೆ sshkey_cert *a, ರಚನೆ sshkey_cert *b)
{
	ಆದರೆ (a == ಖಾಲಿ && b == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 1;
	ಆದರೆ (a == ಖಾಲಿ || b == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

/* Compares FIDO-specific pubkey fields only */
ಪೂರ್ಣಾಂಕ
sshkey_sk_fields_equal(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *a, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *b)
{
	ಆದರೆ (a->sk_application == ಖಾಲಿ || b->sk_application == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (strcmp(a->sk_application, b->sk_application) != 0)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
ಪೂರ್ಣಾಂಕ
sshkey_equal_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *a, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *b)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;

	ಆದರೆ (a == ಖಾಲಿ || b == ಖಾಲಿ ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((impl = sshkey_impl_from_type(a->type)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ impl->funcs->equal(a, b);
}

ಪೂರ್ಣಾಂಕ
sshkey_equal(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *a, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *b)
{
	ಆದರೆ (a == ಖಾಲಿ || b == ಖಾಲಿ || a->type != b->type)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (sshkey_is_cert(a)) {
		ಆದರೆ (!cert_compare(a->cert, b->cert))
			ಹಿಂತಿರುಗಿ 0;
	}
	ಹಿಂತಿರುಗಿ sshkey_equal_ಬಹಿರಂಗ(a, b);
}


/* Serialise common FIDO key parts */
ಪೂರ್ಣಾಂಕ
sshkey_serialize_sk(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_put_cstring(b, ಕೀಲಿ->sk_application)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಗಮ್ಯ_blob_buf(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b, ಪೂರ್ಣಾಂಕ force_plain,
  ಎಣಿಕೆ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಂಕ type, ret = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *typename;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	type = force_plain ? sshkey_type_plain(ಕೀಲಿ->type) : ಕೀಲಿ->type;

	ಆದರೆ (sshkey_type_is_cert(type)) {
		ಆದರೆ (ಕೀಲಿ->cert == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ SSH_ERR_EXPECTED_CERT;
		ಆದರೆ (sshbuf_len(ಕೀಲಿ->cert->certblob) == 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_LACKS_CERTBLOB;
		/* Use the existing blob */
		ಆದರೆ ((ret = sshbuf_putb(b, ಕೀಲಿ->cert->certblob)) != 0)
			ಹಿಂತಿರುಗಿ ret;
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ ((impl = sshkey_impl_from_type(type)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, ಕೀಲಿ->ecdsa_nid);
	ಆದರೆ ((ret = sshbuf_put_cstring(b, typename)) != 0)
		ಹಿಂತಿರುಗಿ ret;
	ಹಿಂತಿರುಗಿ impl->funcs->serialize_ಬಹಿರಂಗ(ಕೀಲಿ, b, opts);
}

ಪೂರ್ಣಾಂಕ
sshkey_putb(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b)
{
	ಹಿಂತಿರುಗಿ ಗಮ್ಯ_blob_buf(ಕೀಲಿ, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshkey_puts_opts_ಆಂತರಿಕ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b,
    ಎಣಿಕೆ sshkey_serialize_rep opts, ಪೂರ್ಣಾಂಕ force_plain)
{
	ರಚನೆ sshbuf *tmp;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((tmp = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	r = ಗಮ್ಯ_blob_buf(ಕೀಲಿ, tmp, force_plain, opts);
	ಆದರೆ (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshkey_puts(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b)
{
	ಹಿಂತಿರುಗಿ sshkey_puts_opts_ಆಂತರಿಕ(ಕೀಲಿ, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

ಪೂರ್ಣಾಂಕ
sshkey_putb_plain(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b)
{
	ಹಿಂತಿರುಗಿ ಗಮ್ಯ_blob_buf(ಕೀಲಿ, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

ಪೂರ್ಣಾಂಕ
sshkey_puts_plain(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b)
{
	ಹಿಂತಿರುಗಿ sshkey_puts_opts_ಆಂತರಿಕ(ಕೀಲಿ, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಗಮ್ಯ_blob(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, u_char **blobp, ಗಾತ್ರ_t *lenp, ಪೂರ್ಣಾಂಕ force_plain,
    ಎಣಿಕೆ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಗಾತ್ರ_t len;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;

	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	ಆದರೆ (blobp != ಖಾಲಿ)
		*blobp = ಖಾಲಿ;
	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((ret = ಗಮ್ಯ_blob_buf(ಕೀಲಿ, b, force_plain, opts)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	len = sshbuf_len(b);
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = len;
	ಆದರೆ (blobp != ಖಾಲಿ) {
		ಆದರೆ ((*blobp = ಸ್ಮರಣೆ_ಕೊಡು(len)) == ಖಾಲಿ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಸ್ಮರಣೆ_ನಕಲು(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sshkey_ಗಮ್ಯ_blob(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, u_char **blobp, ಗಾತ್ರ_t *lenp)
{
	ಹಿಂತಿರುಗಿ ಗಮ್ಯ_blob(ಕೀಲಿ, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

ಪೂರ್ಣಾಂಕ
sshkey_plain_ಗಮ್ಯ_blob(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, u_char **blobp, ಗಾತ್ರ_t *lenp)
{
	ಹಿಂತಿರುಗಿ ಗಮ್ಯ_blob(ಕೀಲಿ, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

ಪೂರ್ಣಾಂಕ
sshkey_fingerprint_raw(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k, ಪೂರ್ಣಾಂಕ dgst_alg,
    u_char **retp, ಗಾತ್ರ_t *lenp)
{
	u_char *blob = ಖಾಲಿ, *ret = ಖಾಲಿ;
	ಗಾತ್ರ_t blob_len = 0;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (retp != ಖಾಲಿ)
		*retp = ಖಾಲಿ;
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	ಆದರೆ (ssh_digest_ಬೈಟುಗಳು(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = ಗಮ್ಯ_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((ret = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, SSH_DIGEST_MAX_ಉದ್ದಳತೆ)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = ssh_digest_ಸ್ಮರಣೆ(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_ಉದ್ದಳತೆ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	ಆದರೆ (retp != ಖಾಲಿ) {
		*retp = ret;
		ret = ಖಾಲಿ;
	}
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = ssh_digest_ಬೈಟುಗಳು(dgst_alg);
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(ret);
	ಆದರೆ (blob != ಖಾಲಿ)
		freezero(blob, blob_len);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
fingerprint_b64(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, u_char *dgst_raw, ಗಾತ್ರ_t dgst_raw_len)
{
	ಅಕ್ಷರ *ret;
	ಗಾತ್ರ_t plen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(alg) + 1;
	ಗಾತ್ರ_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	ಆದರೆ (dgst_raw_len > 65536 || (ret = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, rlen)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	ಆದರೆ (dgst_raw_len == 0)
		ಹಿಂತಿರುಗಿ ret;
	ಆದರೆ (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
fingerprint_hex(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, u_char *dgst_raw, ಗಾತ್ರ_t dgst_raw_len)
{
	ಅಕ್ಷರ *retval, hex[5];
	ಗಾತ್ರ_t i, rlen = dgst_raw_len * 3 + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(alg) + 2;

	ಆದರೆ (dgst_raw_len > 65536 || (retval = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, rlen)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	ಗಾಗಿ (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, ಗಾತ್ರ(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	ಹಿಂತಿರುಗಿ retval;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
fingerprint_bubblebabble(u_char *dgst_raw, ಗಾತ್ರ_t dgst_raw_len)
{
	ಅಕ್ಷರ vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	ಅಕ್ಷರ consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, ಸುತ್ತುಗಳು, ಬೀಜ = 1;
	ಅಕ್ಷರ *retval;

	ಸುತ್ತುಗಳು = (dgst_raw_len / 2) + 1;
	ಆದರೆ ((retval = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(ಸುತ್ತುಗಳು, 6)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	retval[j++] = 'x';
	ಗಾಗಿ (i = 0; i < ಸುತ್ತುಗಳು; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		ಆದರೆ ((i + 1 < ಸುತ್ತುಗಳು) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    ಬೀಜ) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (ಬೀಜ / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			ಆದರೆ ((i + 1) < ಸುತ್ತುಗಳು) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				ಬೀಜ = ((ಬೀಜ * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} ಇಲ್ಲದಿದ್ದರೆ {
			idx0 = ಬೀಜ % 6;
			idx1 = 16;
			idx2 = ಬೀಜ / 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
		}
	}
	retval[j++] = 'x';
	retval[j++] = '\0';
	ಹಿಂತಿರುಗಿ retval;
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
#ವ್ಯಾಖ್ಯಾನಿಸು	FLDBASE		8
#ವ್ಯಾಖ್ಯಾನಿಸು	FLDSIZE_Y	(FLDBASE + 1)
#ವ್ಯಾಖ್ಯಾನಿಸು	FLDSIZE_X	(FLDBASE * 2 + 1)
ಸ್ಥಿರ ಅಕ್ಷರ *
fingerprint_randomart(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, u_char *dgst_raw, ಗಾತ್ರ_t dgst_raw_len,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	ಅಕ್ಷರ	*augmentation_string = " .o+=*BOX@%&#/^SE";
	ಅಕ್ಷರ	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 ಕ್ಷೇತ್ರ[FLDSIZE_X][FLDSIZE_Y];
	ಗಾತ್ರ_t	 i, tlen, hlen;
	u_int	 b;
	ಪೂರ್ಣಾಂಕ	 x, y, r;
	ಗಾತ್ರ_t	 len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(augmentation_string) - 1;

	ಆದರೆ ((retval = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	/* initialize field */
	memset(ಕ್ಷೇತ್ರ, 0, FLDSIZE_X * FLDSIZE_Y * ಗಾತ್ರ(ಅಕ್ಷರ));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	ಗಾಗಿ (i = 0; i < dgst_raw_len; i++) {
		ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು;
		/* each byte conveys four 2-bit move commands */
		ಒಳಹರಿವು = dgst_raw[i];
		ಗಾಗಿ (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (ಒಳಹರಿವು & 0x1) ? 1 : -1;
			y += (ಒಳಹರಿವು & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = ಗರಿಷ್ಠ(x, 0);
			y = ಗರಿಷ್ಠ(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			ಆದರೆ (ಕ್ಷೇತ್ರ[x][y] < len - 2)
				ಕ್ಷೇತ್ರ[x][y]++;
			ಒಳಹರಿವು = ಒಳಹರಿವು >> 2;
		}
	}

	/* mark starting point and end point*/
	ಕ್ಷೇತ್ರ[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	ಕ್ಷೇತ್ರ[x][y] = len;

	/* assemble title */
	r = snprintf(title, ಗಾತ್ರ(title), "[%s %u]",
		sshkey_type(k), sshkey_ಗಾತ್ರ(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	ಆದರೆ (r < 0 || r > (ಪೂರ್ಣಾಂಕ)ಗಾತ್ರ(title))
		r = snprintf(title, ಗಾತ್ರ(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(title);

	/* assemble hash ID. */
	r = snprintf(hash, ಗಾತ್ರ(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	ಗಾಗಿ (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	ಸ್ಮರಣೆ_ನಕಲು(p, title, tlen);
	p += tlen;
	ಗಾಗಿ (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	ಗಾಗಿ (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		ಗಾಗಿ (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(ಕ್ಷೇತ್ರ[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	ಗಾಗಿ (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	ಸ್ಮರಣೆ_ನಕಲು(p, hash, hlen);
	p += hlen;
	ಗಾಗಿ (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	ಹಿಂತಿರುಗಿ retval;
}

ಅಕ್ಷರ *
sshkey_fingerprint(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k, ಪೂರ್ಣಾಂಕ dgst_alg,
    ಎಣಿಕೆ sshkey_fp_rep dgst_rep)
{
	ಅಕ್ಷರ *retval = ಖಾಲಿ;
	u_char *dgst_raw;
	ಗಾತ್ರ_t dgst_raw_len;

	ಆದರೆ (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಆಯ್ಕೆ (dgst_rep) {
	ಸ್ಥಿತಿ SSH_FP_DEFAULT:
		ಆದರೆ (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} ಇಲ್ಲದಿದ್ದರೆ {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		freezero(dgst_raw, dgst_raw_len);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	freezero(dgst_raw, dgst_raw_len);
	ಹಿಂತಿರುಗಿ retval;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
peek_type_nid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ಗಾತ್ರ_t l, ಪೂರ್ಣಾಂಕ *nid)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;
	ಪೂರ್ಣಾಂಕ i;

	ಗಾಗಿ (i = 0; keyimpls[i] != ಖಾಲಿ; i++) {
		impl = keyimpls[i];
		ಆದರೆ (impl->name == ಖಾಲಿ || ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(impl->name) != l)
			ಮುಂದುವರಿ;
		ಆದರೆ (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			ಆದರೆ (ಕೀಲಿ_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			ಹಿಂತಿರುಗಿ impl->type;
		}
	}
	ಹಿಂತಿರುಗಿ ಕೀಲಿ_UNSPEC;
}

/* XXX this can now be made const char * */
ಪೂರ್ಣಾಂಕ
sshkey_read(ರಚನೆ sshkey *ret, ಅಕ್ಷರ **cpp)
{
	ರಚನೆ sshkey *k;
	ಅಕ್ಷರ *cp, *blobcopy;
	ಗಾತ್ರ_t space;
	ಪೂರ್ಣಾಂಕ r, type, ವಕ್ರ_nid = -1;
	ರಚನೆ sshbuf *blob;

	ಆದರೆ (ret == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (ret->type != ಕೀಲಿ_UNSPEC && sshkey_impl_from_type(ret->type) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	ಆದರೆ (space == ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(cp))
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಆದರೆ ((type = peek_type_nid(cp, space, &ವಕ್ರ_nid)) == ಕೀಲಿ_UNSPEC)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	ಗಾಗಿ (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	ಆದರೆ (*cp == '\0')
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಆದರೆ (ret->type != ಕೀಲಿ_UNSPEC && ret->type != type)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
	ಆದರೆ ((blob = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	ಆದರೆ ((blobcopy = strndup(cp, space)) == ಖಾಲಿ) {
		sshbuf_free(blob);
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	}
	ಆದರೆ ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		ಬಿಡುಗಡೆ(blobcopy);
		sshbuf_free(blob);
		ಹಿಂತಿರುಗಿ r;
	}
	ಬಿಡುಗಡೆ(blobcopy);
	ಆದರೆ ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		ಹಿಂತಿರುಗಿ r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	ಗಾಗಿ (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	ಆದರೆ (k->type != type) {
		sshkey_free(k);
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
	}
	ಆದರೆ (ಕೀಲಿ_type_is_ecdsa_variant(type) && ವಕ್ರ_nid != k->ecdsa_nid) {
		sshkey_free(k);
		ಹಿಂತಿರುಗಿ SSH_ERR_EC_ವಕ್ರ_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, ಗಾತ್ರ(*k));

	/* success */
	*cpp = cp;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshkey_ಗಮ್ಯ_base64(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ಅಕ್ಷರ **b64p)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಅಕ್ಷರ *uu = ಖಾಲಿ;

	ಆದರೆ (b64p != ಖಾಲಿ)
		*b64p = ಖಾಲಿ;
	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshkey_putb(ಕೀಲಿ, b)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((uu = sshbuf_dtob64_string(b, 0)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Success */
	ಆದರೆ (b64p != ಖಾಲಿ) {
		*b64p = uu;
		uu = ಖಾಲಿ;
	}
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಬಿಡುಗಡೆ(uu);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshkey_format_ಪಠ್ಯ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಅಕ್ಷರ *uu = ಖಾಲಿ;

	ಆದರೆ ((r = sshkey_ಗಮ್ಯ_base64(ಕೀಲಿ, &uu)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(ಕೀಲಿ), uu)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(uu);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshkey_write(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, FILE *f)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshkey_format_ಪಠ್ಯ(ಕೀಲಿ, b)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		ಆದರೆ (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
sshkey_cert_type(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k)
{
	ಆಯ್ಕೆ (k->cert->type) {
	ಸ್ಥಿತಿ SSH2_CERT_TYPE_USER:
		ಹಿಂತಿರುಗಿ "user";
	ಸ್ಥಿತಿ SSH2_CERT_TYPE_HOST:
		ಹಿಂತಿರುಗಿ "host";
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ "unknown";
	}
}

ಪೂರ್ಣಾಂಕ
sshkey_check_rsa_ಉದ್ದಳತೆ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k, ಪೂರ್ಣಾಂಕ min_ಗಾತ್ರ)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಪೂರ್ಣಾಂಕ nbits;

	ಆದರೆ (k == ಖಾಲಿ || k->pkey == ಖಾಲಿ ||
	    (k->type != ಕೀಲಿ_RSA && k->type != ಕೀಲಿ_RSA_CERT))
		ಹಿಂತಿರುಗಿ 0;
	nbits = EVP_PKEY_ಬಿಟ್ಟುಗಳು(k->pkey);
	ಆದರೆ (nbits < SSH_RSA_MINIMUM_MODULUS_ಗಾತ್ರ ||
	    (min_ಗಾತ್ರ > 0 && nbits < min_ಗಾತ್ರ))
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_ಉದ್ದಳತೆ;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಹಿಂತಿರುಗಿ 0;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಪೂರ್ಣಾಂಕ
sshkey_ecdsa_ಕೀಲಿ_ಗಮ್ಯ_nid(ಸ್ಥಿರಾಂಕ EC_ಕೀಲಿ *k)
{
	ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *g;
	ಪೂರ್ಣಾಂಕ nid;

	ಆದರೆ (k == ಖಾಲಿ || (g = EC_ಕೀಲಿ_get0_ಗುಂಪು(k)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ ((nid = EC_ಗುಂಪು_get_ವಕ್ರ_name(g)) <= 0)
		ಹಿಂತಿರುಗಿ -1;
	ಹಿಂತಿರುಗಿ nid;
}

ಪೂರ್ಣಾಂಕ
sshkey_ecdsa_pkey_ಗಮ್ಯ_nid(EVP_PKEY *pkey)
{
	ಹಿಂತಿರುಗಿ sshkey_ecdsa_ಕೀಲಿ_ಗಮ್ಯ_nid(EVP_PKEY_get0_EC_ಕೀಲಿ(pkey));
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

ಪೂರ್ಣಾಂಕ
sshkey_generate(ಪೂರ್ಣಾಂಕ type, u_int ಬಿಟ್ಟುಗಳು, ರಚನೆ sshkey **keyp)
{
	ರಚನೆ sshkey *k;
	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;

	ಆದರೆ (keyp == ಖಾಲಿ || sshkey_type_is_cert(type))
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	*keyp = ಖಾಲಿ;
	ಆದರೆ ((impl = sshkey_impl_from_type(type)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	ಆದರೆ (impl->funcs->generate == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_FEATURE_UNSUPPORTED;
	ಆದರೆ ((k = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	k->type = type;
	ಆದರೆ ((ret = impl->funcs->generate(k, ಬಿಟ್ಟುಗಳು)) != 0) {
		sshkey_free(k);
		ಹಿಂತಿರುಗಿ ret;
	}
	/* success */
	*keyp = k;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshkey_cert_copy(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *from_ಕೀಲಿ, ರಚನೆ sshkey *ಗಮ್ಯ_ಕೀಲಿ)
{
	u_int i;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_cert *from;
	ರಚನೆ sshkey_cert *ಗಮ್ಯ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (ಗಮ್ಯ_ಕೀಲಿ == ಖಾಲಿ || (from = from_ಕೀಲಿ->cert) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	ಆದರೆ ((ಗಮ್ಯ = cert_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;

	ಆದರೆ ((r = sshbuf_putb(ಗಮ್ಯ->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(ಗಮ್ಯ->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(ಗಮ್ಯ->extensions, from->extensions)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಗಮ್ಯ->serial = from->serial;
	ಗಮ್ಯ->type = from->type;
	ಆದರೆ (from->ಕೀಲಿ_id == ಖಾಲಿ)
		ಗಮ್ಯ->ಕೀಲಿ_id = ಖಾಲಿ;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((ಗಮ್ಯ->ಕೀಲಿ_id = strdup(from->ಕೀಲಿ_id)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಗಮ್ಯ->valid_after = from->valid_after;
	ಗಮ್ಯ->valid_before = from->valid_before;
	ಆದರೆ (from->signature_ಕೀಲಿ == ಖಾಲಿ)
		ಗಮ್ಯ->signature_ಕೀಲಿ = ಖಾಲಿ;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(from->signature_ಕೀಲಿ,
	    &ಗಮ್ಯ->signature_ಕೀಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (from->signature_type != ಖಾಲಿ &&
	    (ಗಮ್ಯ->signature_type = strdup(from->signature_type)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (from->nprincipals > 0) {
		ಆದರೆ ((ಗಮ್ಯ->principals = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(from->nprincipals,
		    ಗಾತ್ರ(*ಗಮ್ಯ->principals))) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಗಾಗಿ (i = 0; i < from->nprincipals; i++) {
			ಗಮ್ಯ->principals[i] = strdup(from->principals[i]);
			ಆದರೆ (ಗಮ್ಯ->principals[i] == ಖಾಲಿ) {
				ಗಮ್ಯ->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				ಹೋಗು ಹೊರಹೋಗು;
			}
		}
	}
	ಗಮ್ಯ->nprincipals = from->nprincipals;

	/* success */
	cert_free(ಗಮ್ಯ_ಕೀಲಿ->cert);
	ಗಮ್ಯ_ಕೀಲಿ->cert = ಗಮ್ಯ;
	ಗಮ್ಯ = ಖಾಲಿ;
	r = 0;
 ಹೊರಹೋಗು:
	cert_free(ಗಮ್ಯ);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshkey_copy_ಬಹಿರಂಗ_sk(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *from, ರಚನೆ sshkey *ಗಮ್ಯ)
{
	/* Append security-key application string */
	ಆದರೆ ((ಗಮ್ಯ->sk_application = strdup(from->sk_application)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshkey_from_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k, ರಚನೆ sshkey **pkp)
{
	ರಚನೆ sshkey *n = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;

	*pkp = ಖಾಲಿ;
	ಆದರೆ ((impl = sshkey_impl_from_ಕೀಲಿ(k)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	ಆದರೆ ((n = sshkey_new(k->type)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = impl->funcs->copy_ಬಹಿರಂಗ(k, n)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	*pkp = n;
	n = ಖಾಲಿ;
	r = 0;
 ಹೊರಹೋಗು:
	sshkey_free(n);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshkey_is_shielded(ರಚನೆ sshkey *k)
{
	ಹಿಂತಿರುಗಿ k != ಖಾಲಿ && k->shielded_ಖಾಸಗಿ != ಖಾಲಿ;
}

ಪೂರ್ಣಾಂಕ
sshkey_shield_ಖಾಸಗಿ(ರಚನೆ sshkey *k)
{
	ರಚನೆ sshbuf *prvbuf = ಖಾಲಿ;
	u_char *prekey = ಖಾಲಿ, *enc = ಖಾಲಿ, keyiv[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];
	ರಚನೆ sshcipher_ctx *cctx = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *cipher;
	ಗಾತ್ರ_t i, enclen = 0;
	ರಚನೆ sshkey *kswap = ಖಾಲಿ, tmp;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ಖಾಲಿ) {
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_ಬೈಟುಗಳು(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_ಆಂತರಿಕ_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	ಆದರೆ ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	ಆದರೆ ((r = ssh_digest_ಸ್ಮರಣೆ(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_ಉದ್ದಳತೆ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_ದತ್ತಾಂಶ(keyiv, ssh_digest_ಬೈಟುಗಳು(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Serialise and encrypt the private key using the ephemeral key */
	ಆದರೆ ((prvbuf = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshkey_is_shielded(k) && (r = sshkey_unshield_ಖಾಸಗಿ(k)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_serialize(k, prvbuf)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* pad to cipher blocksize */
	i = 0;
	ಆಗ (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		ಆದರೆ ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	ಆದರೆ ((enc = ಸ್ಮರಣೆ_ಕೊಡು(enclen)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_ದತ್ತಾಂಶ(enc, enclen, stderr);
#ಆದರೆ_ಅಂತ್ಯ

	/* Make a scrubbed, public-only copy of our private key argument */
	ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(k, &kswap)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_ಖಾಸಗಿ = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = ಖಾಲಿ; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 ಹೊರಹೋಗು:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, ಗಾತ್ರ(keyiv));
	explicit_bzero(&tmp, ಗಾತ್ರ(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	ಹಿಂತಿರುಗಿ r;
}

/* Check deterministic padding after private key */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
private2_check_padding(ರಚನೆ sshbuf *decrypted)
{
	u_char pad;
	ಗಾತ್ರ_t i;
	ಪೂರ್ಣಾಂಕ r;

	i = 0;
	ಆಗ (sshbuf_len(decrypted)) {
		ಆದರೆ ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	explicit_bzero(&pad, ಗಾತ್ರ(pad));
	explicit_bzero(&i, ಗಾತ್ರ(i));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshkey_unshield_ಖಾಸಗಿ(ರಚನೆ sshkey *k)
{
	ರಚನೆ sshbuf *prvbuf = ಖಾಲಿ;
	u_char *cp, keyiv[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];
	ರಚನೆ sshcipher_ctx *cctx = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *cipher;
	ರಚನೆ sshkey *kswap = ಖಾಲಿ, tmp;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (!sshkey_is_shielded(k))
		ಹಿಂತಿರುಗಿ 0; /* nothing to do */

	ಆದರೆ ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == ಖಾಲಿ) {
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_ಬೈಟುಗಳು(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_ಆಂತರಿಕ_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* check size of shielded key blob */
	ಆದರೆ (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Calculate the ephemeral key from the prekey */
	ಆದರೆ ((r = ssh_digest_ಸ್ಮರಣೆ(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_ಉದ್ದಳತೆ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_ದತ್ತಾಂಶ(keyiv, ssh_digest_ಬೈಟುಗಳು(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#ಆದರೆ_ಅಂತ್ಯ

	/* Decrypt and parse the shielded private key using the ephemeral key */
	ಆದರೆ ((prvbuf = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* decrypt */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_ದತ್ತಾಂಶ(k->shielded_ಖಾಸಗಿ, k->shielded_len, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_ಖಾಸಗಿ, k->shielded_len, 0, 0)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	/* Parse private key */
	ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_deserialize(prvbuf, &kswap)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((r = private2_check_padding(prvbuf)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 ಹೊರಹೋಗು:
	cipher_free(cctx);
	explicit_bzero(keyiv, ಗಾತ್ರ(keyiv));
	explicit_bzero(&tmp, ಗಾತ್ರ(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
cert_parse(ರಚನೆ sshbuf *b, ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *certbuf,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ca_sigalg_allowlist)
{
	ರಚನೆ sshbuf *principals = ಖಾಲಿ, *crit = ಖಾಲಿ;
	ರಚನೆ sshbuf *exts = ಖಾಲಿ, *ca = ಖಾಲಿ;
	u_char *sig = ಖಾಲಿ;
	ಅಕ್ಷರ *sigtype = ಖಾಲಿ;
	ಗಾತ್ರ_t signed_len = 0, slen = 0, kidlen = 0;
	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಆಂತರಿಕ_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	ಆದರೆ ((ret = sshbuf_putb(ಕೀಲಿ->cert->certblob, certbuf)) != 0)
		ಹಿಂತಿರುಗಿ ret;

	/* Parse body of certificate up to signature */
	ಆದರೆ ((ret = sshbuf_get_u64(b, &ಕೀಲಿ->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &ಕೀಲಿ->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &ಕೀಲಿ->cert->ಕೀಲಿ_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &ಕೀಲಿ->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &ಕೀಲಿ->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_ನೇರ(b, ಖಾಲಿ, ಖಾಲಿ)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(ಕೀಲಿ->cert->certblob) - sshbuf_len(b);

	ಆದರೆ ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Is this a signature we're prepared to accept? */
	ಆದರೆ ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (ca_sigalg_allowlist != ಖಾಲಿ &&
	    ಹೊಂದಿಕೆ_ನಮೂನೆ_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Parse CA key and check whether we might accept it */
	ಆದರೆ (sshkey_from_blob_ಆಂತರಿಕ(ca, &ಕೀಲಿ->cert->signature_ಕೀಲಿ, 0,
	    ca_sigalg_allowlist, ಖಾಲಿ) != 0) {
		ret = SSH_ERR_ಕೀಲಿ_CERT_INVALID_SIGN_ಕೀಲಿ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (!sshkey_type_is_valid_ca(ಕೀಲಿ->cert->signature_ಕೀಲಿ->type)) {
		ret = SSH_ERR_ಕೀಲಿ_CERT_INVALID_SIGN_ಕೀಲಿ;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (ಕೀಲಿ->cert->type != SSH2_CERT_TYPE_USER &&
	    ಕೀಲಿ->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_ಕೀಲಿ_CERT_UNKNOWN_TYPE;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Parse principals section */
	ಆಗ (sshbuf_len(principals) > 0) {
		ಅಕ್ಷರ *principal = ಖಾಲಿ;
		ಅಕ್ಷರ **oprincipals = ಖಾಲಿ;

		ಆದರೆ (ಕೀಲಿ->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((ret = sshbuf_get_cstring(principals, &principal,
		    ಖಾಲಿ)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		oprincipals = ಕೀಲಿ->cert->principals;
		ಕೀಲಿ->cert->principals = recallocarray(ಕೀಲಿ->cert->principals,
		    ಕೀಲಿ->cert->nprincipals, ಕೀಲಿ->cert->nprincipals + 1,
		    ಗಾತ್ರ(*ಕೀಲಿ->cert->principals));
		ಆದರೆ (ಕೀಲಿ->cert->principals == ಖಾಲಿ) {
			ಬಿಡುಗಡೆ(principal);
			ಕೀಲಿ->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಕೀಲಿ->cert->principals[ಕೀಲಿ->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	ಆದರೆ ((ret = sshbuf_putb(ಕೀಲಿ->cert->critical, crit)) != 0 ||
	    (exts != ಖಾಲಿ &&
	    (ret = sshbuf_putb(ಕೀಲಿ->cert->extensions, exts)) != 0))
		ಹೋಗು ಹೊರಹೋಗು;

	/*
	 * Validate critical options and extensions sections format.
	 */
	ಆಗ (sshbuf_len(crit) != 0) {
		ಆದರೆ ((ret = sshbuf_get_string_ನೇರ(crit, ಖಾಲಿ, ಖಾಲಿ)) != 0 ||
		    (ret = sshbuf_get_string_ನೇರ(crit, ಖಾಲಿ, ಖಾಲಿ)) != 0) {
			sshbuf_reset(ಕೀಲಿ->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	ಆಗ (exts != ಖಾಲಿ && sshbuf_len(exts) != 0) {
		ಆದರೆ ((ret = sshbuf_get_string_ನೇರ(exts, ಖಾಲಿ, ಖಾಲಿ)) != 0 ||
		    (ret = sshbuf_get_string_ನೇರ(exts, ಖಾಲಿ, ಖಾಲಿ)) != 0) {
			sshbuf_reset(ಕೀಲಿ->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	/* Finally, validate signature */
	ಆದರೆ ((ret = sshkey_verify(ಕೀಲಿ->cert->signature_ಕೀಲಿ, sig, slen,
	    sshbuf_ptr(ಕೀಲಿ->cert->certblob), signed_len, ಖಾಲಿ, 0, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Success */
	ret = 0;
	ಕೀಲಿ->cert->signature_type = sigtype;
	sigtype = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	ಬಿಡುಗಡೆ(sig);
	ಬಿಡುಗಡೆ(sigtype);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sshkey_deserialize_sk(ರಚನೆ sshbuf *b, ರಚನೆ sshkey *ಕೀಲಿ)
{
	/* Parse additional security-key application string */
	ಆದರೆ (sshbuf_get_cstring(b, &ಕೀಲಿ->sk_application, ಖಾಲಿ) != 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshkey_from_blob_ಆಂತರಿಕ(ರಚನೆ sshbuf *b, ರಚನೆ sshkey **keyp,
    ಪೂರ್ಣಾಂಕ allow_cert, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg_allowlist, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ca_sigalg_allowlist)
{
	ಪೂರ್ಣಾಂಕ type, ret = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಅಕ್ಷರ *ktype = ಖಾಲಿ;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ರಚನೆ sshbuf *copy;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (keyp != ಖಾಲಿ)
		*keyp = ಖಾಲಿ;
	ಆದರೆ ((copy = sshbuf_fromb(b)) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_get_cstring(b, &ktype, ಖಾಲಿ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	type = sshkey_type_from_name(ktype);
	ಆದರೆ (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_ಕೀಲಿ_CERT_INVALID_SIGN_ಕೀಲಿ;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (alg_allowlist != ಖಾಲಿ &&
	    !sshkey_ಹೊಂದಿಕೆ_keyname_ಗಮ್ಯ_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_ಕೀಲಿ_ALG_UNSUPPORTED;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((impl = sshkey_impl_from_type(type)) == ಖಾಲಿ) {
		ret = SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ಕೀಲಿ = sshkey_new(type)) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		ಆದರೆ (sshbuf_get_string_ನೇರ(b, ಖಾಲಿ, ಖಾಲಿ) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	ಆದರೆ ((ret = impl->funcs->deserialize_ಬಹಿರಂಗ(ktype, b, ಕೀಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Parse certificate potion */
	ಆದರೆ (sshkey_is_cert(ಕೀಲಿ) &&
	    (ret = cert_parse(b, ಕೀಲಿ, copy, ca_sigalg_allowlist)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ (ಕೀಲಿ != ಖಾಲಿ && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ret = 0;
	ಆದರೆ (keyp != ಖಾಲಿ) {
		*keyp = ಕೀಲಿ;
		ಕೀಲಿ = ಖಾಲಿ;
	}
 ಹೊರಹೋಗು:
	sshbuf_free(copy);
	sshkey_free(ಕೀಲಿ);
	ಬಿಡುಗಡೆ(ktype);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sshkey_from_blob(ಸ್ಥಿರಾಂಕ u_char *blob, ಗಾತ್ರ_t blen, ರಚನೆ sshkey **keyp)
{
	ರಚನೆ sshbuf *b;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((b = sshbuf_from(blob, blen)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_ಆಂತರಿಕ(b, keyp, 1, ಖಾಲಿ, ಖಾಲಿ);
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshkey_fromb(ರಚನೆ sshbuf *b, ರಚನೆ sshkey **keyp)
{
	ಹಿಂತಿರುಗಿ sshkey_from_blob_ಆಂತರಿಕ(b, keyp, 1, ಖಾಲಿ, ಖಾಲಿ);
}

ಪೂರ್ಣಾಂಕ
sshkey_fromb_allowlist(ರಚನೆ sshbuf *b, ರಚನೆ sshkey **keyp,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg_allowlist, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ca_sigalg_allowlist)
{
	ಹಿಂತಿರುಗಿ sshkey_from_blob_ಆಂತರಿಕ(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

ಪೂರ್ಣಾಂಕ
sshkey_froms(ರಚನೆ sshbuf *buf, ರಚನೆ sshkey **keyp)
{
	ರಚನೆ sshbuf *b;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_froms(buf, &b)) != 0)
		ಹಿಂತಿರುಗಿ r;
	r = sshkey_from_blob_ಆಂತರಿಕ(b, keyp, 1, ಖಾಲಿ, ಖಾಲಿ);
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshkey_get_sigtype(ಸ್ಥಿರಾಂಕ u_char *sig, ಗಾತ್ರ_t siglen, ಅಕ್ಷರ **sigtypep)
{
	ಪೂರ್ಣಾಂಕ r;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಅಕ್ಷರ *sigtype = ಖಾಲಿ;

	ಆದರೆ (sigtypep != ಖಾಲಿ)
		*sigtypep = ಖಾಲಿ;
	ಆದರೆ ((b = sshbuf_from(sig, siglen)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_get_cstring(b, &sigtype, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	ಆದರೆ (sigtypep != ಖಾಲಿ) {
		*sigtypep = sigtype;
		sigtype = ಖಾಲಿ;
	}
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(sigtype);
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
ಪೂರ್ಣಾಂಕ
sshkey_check_cert_sigtype(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *allowed)
{
	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ || allowed == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (!sshkey_type_is_cert(ಕೀಲಿ->type))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (ಕೀಲಿ->cert == ಖಾಲಿ || ಕೀಲಿ->cert->signature_type == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list(ಕೀಲಿ->cert->signature_type, allowed, 0) != 1)
		ಹಿಂತಿರುಗಿ SSH_ERR_SIGN_ALG_UNSUPPORTED;
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
sshkey_sigalg_by_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;
	ಪೂರ್ಣಾಂಕ i;

	ಗಾಗಿ (i = 0; keyimpls[i] != ಖಾಲಿ; i++) {
		impl = keyimpls[i];
		ಆದರೆ (strcmp(impl->name, name) != 0)
			ಮುಂದುವರಿ;
		ಆದರೆ (impl->sigalg != ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ impl->sigalg;
		ಆದರೆ (!impl->cert)
			ಹಿಂತಿರುಗಿ impl->name;
		ಹಿಂತಿರುಗಿ sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
ಪೂರ್ಣಾಂಕ
sshkey_check_sigtype(ಸ್ಥಿರಾಂಕ u_char *sig, ಗಾತ್ರ_t siglen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *requested_alg)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *expected_alg;
	ಅಕ್ಷರ *sigtype = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (requested_alg == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		ಹಿಂತಿರುಗಿ r;
	r = strcmp(expected_alg, sigtype) == 0;
	ಬಿಡುಗಡೆ(sigtype);
	ಹಿಂತಿರುಗಿ r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ಪೂರ್ಣಾಂಕ
sshkey_sign(ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin, u_int compat)
{
	ಪೂರ್ಣಾಂಕ was_shielded = sshkey_is_shielded(ಕೀಲಿ);
	ಪೂರ್ಣಾಂಕ r2, r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;

	ಆದರೆ (sigp != ಖಾಲಿ)
		*sigp = ಖಾಲಿ;
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	ಆದರೆ (datalen > SSH_ಕೀಲಿ_MAX_SIGN_ದತ್ತಾಂಶ_ಗಾತ್ರ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((impl = sshkey_impl_from_ಕೀಲಿ(ಕೀಲಿ)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	ಆದರೆ ((r = sshkey_unshield_ಖಾಸಗಿ(ಕೀಲಿ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (sshkey_is_sk(ಕೀಲಿ)) {
		r = sshsk_sign(sk_provider, ಕೀಲಿ, sigp, lenp, ದತ್ತಾಂಶ,
		    datalen, compat, sk_pin);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((ಕೀಲಿ->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(ಕೀಲಿ, sigp, lenp, ದತ್ತಾಂಶ, datalen,
		    alg, sk_provider, sk_pin, compat);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (impl->funcs->sign == ಖಾಲಿ)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ಇಲ್ಲದಿದ್ದರೆ {
			r = impl->funcs->sign(ಕೀಲಿ, sigp, lenp, ದತ್ತಾಂಶ, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	ಆದರೆ (was_shielded && (r2 = sshkey_shield_ಖಾಸಗಿ(ಕೀಲಿ)) != 0)
		ಹಿಂತಿರುಗಿ r2;
	ಹಿಂತಿರುಗಿ r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
ಪೂರ್ಣಾಂಕ
sshkey_verify(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ u_char *sig, ಗಾತ್ರ_t siglen,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t dlen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, u_int compat,
    ರಚನೆ sshkey_sig_details **detailsp)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;

	ಆದರೆ (detailsp != ಖಾಲಿ)
		*detailsp = ಖಾಲಿ;
	ಆದರೆ (siglen == 0 || dlen > SSH_ಕೀಲಿ_MAX_SIGN_ದತ್ತಾಂಶ_ಗಾತ್ರ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((impl = sshkey_impl_from_ಕೀಲಿ(ಕೀಲಿ)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	ಹಿಂತಿರುಗಿ impl->funcs->verify(ಕೀಲಿ, sig, siglen, ದತ್ತಾಂಶ, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
ಪೂರ್ಣಾಂಕ
sshkey_ಗಮ್ಯ_certified(ರಚನೆ sshkey *k)
{
	ಪೂರ್ಣಾಂಕ newtype;

	ಆದರೆ ((newtype = sshkey_type_certified(k->type)) == -1)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((k->cert = cert_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	ಹಿಂತಿರುಗಿ 0;
}

/* Convert a certificate to its raw key equivalent */
ಪೂರ್ಣಾಂಕ
sshkey_drop_cert(ರಚನೆ sshkey *k)
{
	ಆದರೆ (!sshkey_type_is_cert(k->type))
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = ಖಾಲಿ;
	k->type = sshkey_type_plain(k->type);
	ಹಿಂತಿರುಗಿ 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
ಪೂರ್ಣಾಂಕ
sshkey_certify_custom(ರಚನೆ sshkey *k, ರಚನೆ sshkey *ca, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin,
    sshkey_certify_signer *signer, ಶೂನ್ಯ *signer_ctx)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;
	ರಚನೆ sshbuf *principals = ಖಾಲಿ;
	u_char *ca_blob = ಖಾಲಿ, *sig_blob = ಖಾಲಿ, nonce[32];
	ಗಾತ್ರ_t i, ca_len, sig_len;
	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ sshbuf *cert = ಖಾಲಿ;
	ಅಕ್ಷರ *sigtype = ಖಾಲಿ;

	ಆದರೆ (k == ಖಾಲಿ || k->cert == ಖಾಲಿ ||
	    k->cert->certblob == ಖಾಲಿ || ca == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (!sshkey_is_cert(k))
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	ಆದರೆ (!sshkey_type_is_valid_ca(ca->type))
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_CERT_INVALID_SIGN_ಕೀಲಿ;
	ಆದರೆ ((impl = sshkey_impl_from_ಕೀಲಿ(k)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	ಆದರೆ (alg == ಖಾಲಿ)
		alg = k->cert->signature_type;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (k->cert->signature_type != ಖಾಲಿ &&
	    strcmp(alg, k->cert->signature_type) != 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	ಆದರೆ (alg == ಖಾಲಿ && ca->type == ಕೀಲಿ_RSA)
		alg = "rsa-sha2-512";

	ಆದರೆ ((ret = sshkey_ಗಮ್ಯ_blob(ca, &ca_blob, &ca_len)) != 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_CERT_INVALID_SIGN_ಕೀಲಿ;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	ಆದರೆ ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, ಗಾತ್ರ(nonce));
	ಆದರೆ ((ret = sshbuf_put_string(cert, nonce, ಗಾತ್ರ(nonce))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Public key next */
	ಆದರೆ ((ret = impl->funcs->serialize_ಬಹಿರಂಗ(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Then remaining cert fields */
	ಆದರೆ ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->ಕೀಲಿ_id)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((principals = sshbuf_new()) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಗಾಗಿ (i = 0; i < k->cert->nprincipals; i++) {
		ಆದರೆ ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, ಖಾಲಿ, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Sign the whole mess */
	ಆದರೆ ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* Check and update signature_type against what was actually used */
	ಆದರೆ ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (alg != ಖಾಲಿ && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (k->cert->signature_type == ಖಾಲಿ) {
		k->cert->signature_type = sigtype;
		sigtype = ಖಾಲಿ;
	}
	/* Append signature and we are done */
	ಆದರೆ ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ret = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (ret != 0)
		sshbuf_reset(cert);
	ಬಿಡುಗಡೆ(sig_blob);
	ಬಿಡುಗಡೆ(ca_blob);
	ಬಿಡುಗಡೆ(sigtype);
	sshbuf_free(principals);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
default_ಕೀಲಿ_sign(ರಚನೆ sshkey *ಕೀಲಿ, u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin,
    u_int compat, ಶೂನ್ಯ *ctx)
{
	ಆದರೆ (ctx != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಹಿಂತಿರುಗಿ sshkey_sign(ಕೀಲಿ, sigp, lenp, ದತ್ತಾಂಶ, datalen, alg,
	    sk_provider, sk_pin, compat);
}

ಪೂರ್ಣಾಂಕ
sshkey_certify(ರಚನೆ sshkey *k, ರಚನೆ sshkey *ca, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin)
{
	ಹಿಂತಿರುಗಿ sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_ಕೀಲಿ_sign, ಖಾಲಿ);
}

ಪೂರ್ಣಾಂಕ
sshkey_cert_check_authority(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k,
    ಪೂರ್ಣಾಂಕ want_host, ಪೂರ್ಣಾಂಕ wildcard_ನಮೂನೆ, uint64_t verify_ಸಮಯ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **reason)
{
	u_int i, principal_matches;

	ಆದರೆ (reason == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಆದರೆ (want_host) {
		ಆದರೆ (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
		}
	}
	ಆದರೆ (verify_ಸಮಯ < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಆದರೆ (verify_ಸಮಯ >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಆದರೆ (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಆದರೆ (name == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0; /* principal matching not requested */

	principal_matches = 0;
	ಗಾಗಿ (i = 0; i < k->cert->nprincipals; i++) {
		ಆದರೆ (wildcard_ನಮೂನೆ) {
			ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ(name, k->cert->principals[i])) {
				principal_matches = 1;
				ನಿಲ್ಲಿಸು;
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			ನಿಲ್ಲಿಸು;
		}
	}
	ಆದರೆ (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshkey_cert_check_authority_now(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k,
    ಪೂರ್ಣಾಂಕ want_host, ಪೂರ್ಣಾಂಕ wildcard_ನಮೂನೆ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **reason)
{
	time_t now;

	ಆದರೆ ((now = time(ಖಾಲಿ)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಹಿಂತಿರುಗಿ sshkey_cert_check_authority(k, want_host, wildcard_ನಮೂನೆ,
	    (uint64_t)now, name, reason);
}

ಪೂರ್ಣಾಂಕ
sshkey_cert_check_host(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ca_sign_algorithms, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **reason)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshkey_cert_check_authority_now(ಕೀಲಿ, 1, 1, host, reason)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (sshbuf_len(ಕೀಲಿ->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಆದರೆ (ca_sign_algorithms != ಖಾಲಿ &&
	    (r = sshkey_check_cert_sigtype(ಕೀಲಿ, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_CERT_INVALID;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಗಾತ್ರ_t
sshkey_format_cert_validity(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_cert *cert, ಅಕ್ಷರ *s, ಗಾತ್ರ_t l)
{
	ಅಕ್ಷರ from[32], ಗಮ್ಯ[32], ret[128];

	*from = *ಗಮ್ಯ = '\0';
	ಆದರೆ (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		ಹಿಂತಿರುಗಿ strlcpy(s, "forever", l);

	ಆದರೆ (cert->valid_after != 0)
		format_absolute_ಸಮಯ(cert->valid_after, from, ಗಾತ್ರ(from));
	ಆದರೆ (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_ಸಮಯ(cert->valid_before, ಗಮ್ಯ, ಗಾತ್ರ(ಗಮ್ಯ));

	ಆದರೆ (cert->valid_after == 0)
		snprintf(ret, ಗಾತ್ರ(ret), "before %s", ಗಮ್ಯ);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, ಗಾತ್ರ(ret), "after %s", from);
	ಇಲ್ಲದಿದ್ದರೆ
		snprintf(ret, ಗಾತ್ರ(ret), "from %s to %s", from, ಗಮ್ಯ);

	ಹಿಂತಿರುಗಿ strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
ಪೂರ್ಣಾಂಕ
sshkey_serialize_ಖಾಸಗಿ_sk(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_put_cstring(b, ಕೀಲಿ->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, ಕೀಲಿ->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, ಕೀಲಿ->sk_ಕೀಲಿ_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, ಕೀಲಿ->sk_reserved)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshkey_ಖಾಸಗಿ_serialize_opt(ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *buf,
    ಎಣಿಕೆ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಪೂರ್ಣಾಂಕ was_shielded = sshkey_is_shielded(ಕೀಲಿ);
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;

	ಆದರೆ ((impl = sshkey_impl_from_ಕೀಲಿ(ಕೀಲಿ)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಆದರೆ ((r = sshkey_unshield_ಖಾಸಗಿ(ಕೀಲಿ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put_cstring(b, sshkey_ssh_name(ಕೀಲಿ))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (sshkey_is_cert(ಕೀಲಿ)) {
		ಆದರೆ (ಕೀಲಿ->cert == ಖಾಲಿ ||
		    sshbuf_len(ಕೀಲಿ->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_ವಾದ;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_put_stringb(b, ಕೀಲಿ->cert->certblob)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = impl->funcs->serialize_ಖಾಸಗಿ(ಕೀಲಿ, b, opts)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (was_shielded)
		r = sshkey_shield_ಖಾಸಗಿ(ಕೀಲಿ);
	ಆದರೆ (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshkey_ಖಾಸಗಿ_serialize(ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b)
{
	ಹಿಂತಿರುಗಿ sshkey_ಖಾಸಗಿ_serialize_opt(ಕೀಲಿ, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
ಪೂರ್ಣಾಂಕ
sshkey_ಖಾಸಗಿ_deserialize_sk(ರಚನೆ sshbuf *buf, ರಚನೆ sshkey *k)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((k->sk_ಕೀಲಿ_handle = sshbuf_new()) == ಖಾಲಿ ||
	    (k->sk_reserved = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_get_cstring(buf, &k->sk_application, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_ಕೀಲಿ_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshkey_ಖಾಸಗಿ_deserialize(ರಚನೆ sshbuf *buf, ರಚನೆ sshkey **kp)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl *impl;
	ಅಕ್ಷರ *tname = ಖಾಲಿ;
	ಅಕ್ಷರ *expect_sk_application = ಖಾಲಿ;
	u_char *expect_ed25519_pk = ಖಾಲಿ;
	ರಚನೆ sshkey *k = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ type, r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (kp != ಖಾಲಿ)
		*kp = ಖಾಲಿ;
	ಆದರೆ ((r = sshbuf_get_cstring(buf, &tname, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	type = sshkey_type_from_name(tname);
	ಆದರೆ (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		ಆದರೆ ((r = sshkey_froms(buf, &k)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ (k->type != type) {
			r = SSH_ERR_ಕೀಲಿ_CERT_MISMATCH;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/* For ECDSA keys, the group must match too */
		ಆದರೆ (k->type == ಕೀಲಿ_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_ಕೀಲಿ_CERT_MISMATCH;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = ಖಾಲಿ;
		k->ed25519_pk = ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((k = sshkey_new(type)) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	ಆದರೆ ((impl = sshkey_impl_from_type(type)) == ಖಾಲಿ) {
		r = SSH_ERR_ಆಂತರಿಕ_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = impl->funcs->deserialize_ಖಾಸಗಿ(tname, buf, k)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((expect_sk_application != ಖಾಲಿ && (k->sk_application == ಖಾಲಿ ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != ಖಾಲಿ && (k->ed25519_pk == ಖಾಲಿ ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_ಕೀಲಿ_CERT_MISMATCH;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
	ಆದರೆ (kp != ಖಾಲಿ) {
		*kp = k;
		k = ಖಾಲಿ;
	}
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(tname);
	sshkey_free(k);
	ಬಿಡುಗಡೆ(expect_sk_application);
	ಬಿಡುಗಡೆ(expect_ed25519_pk);
	ಹಿಂತಿರುಗಿ r;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಪೂರ್ಣಾಂಕ
sshkey_ec_validate_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *ಗುಂಪು, ಸ್ಥಿರಾಂಕ EC_ಬಿಂದು *ಸಾರ್ವಜನಿಕ)
{
	EC_ಬಿಂದು *nq = ಖಾಲಿ;
	BIGNUM *ಕ್ರಮ = ಖಾಲಿ, *cofactor = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಕೀಲಿ_INVALID_EC_ಮೌಲ್ಯ;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	ಆದರೆ (EC_ಬಿಂದು_is_at_infinity(ಗುಂಪು, ಸಾರ್ವಜನಿಕ))
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((cofactor = BN_new()) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EC_ಗುಂಪು_get_cofactor(ಗುಂಪು, cofactor, ಖಾಲಿ) != 1)
		ಹೋಗು ಹೊರಹೋಗು;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	ಆದರೆ (!BN_is_one(cofactor)) {
		ಆದರೆ ((ಕ್ರಮ = BN_new()) == ಖಾಲಿ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (EC_ಗುಂಪು_get_ಕ್ರಮ(ಗುಂಪು, ಕ್ರಮ, ಖಾಲಿ) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((nq = EC_ಬಿಂದು_new(ಗುಂಪು)) == ಖಾಲಿ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (EC_ಬಿಂದು_mul(ಗುಂಪು, nq, ಖಾಲಿ, ಸಾರ್ವಜನಿಕ, ಕ್ರಮ, ಖಾಲಿ) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (EC_ಬಿಂದು_is_at_infinity(ಗುಂಪು, nq) != 1)
			ಹೋಗು ಹೊರಹೋಗು;
	}

	/* success */
	ret = 0;
 ಹೊರಹೋಗು:
	BN_clear_free(cofactor);
	BN_clear_free(ಕ್ರಮ);
	EC_ಬಿಂದು_free(nq);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sshkey_ec_validate_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ EC_ಕೀಲಿ *ಕೀಲಿ)
{
	BIGNUM *ಕ್ರಮ = ಖಾಲಿ, *tmp = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret = SSH_ERR_ಕೀಲಿ_INVALID_EC_ಮೌಲ್ಯ;

	ಆದರೆ ((ಕ್ರಮ = BN_new()) == ಖಾಲಿ || (tmp = BN_new()) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* log2(private) > log2(order)/2 */
	ಆದರೆ (EC_ಗುಂಪು_get_ಕ್ರಮ(EC_ಕೀಲಿ_get0_ಗುಂಪು(ಕೀಲಿ), ಕ್ರಮ, ಖಾಲಿ) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (BN_ಅಂಕೆ_ಬಿಟ್ಟುಗಳು(EC_ಕೀಲಿ_get0_ಖಾಸಗಿ_ಕೀಲಿ(ಕೀಲಿ)) <=
	    BN_ಅಂಕೆ_ಬಿಟ್ಟುಗಳು(ಕ್ರಮ) / 2)
		ಹೋಗು ಹೊರಹೋಗು;

	/* private < order - 1 */
	ಆದರೆ (!BN_sub(tmp, ಕ್ರಮ, BN_ಮೌಲ್ಯ_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (BN_cmp(EC_ಕೀಲಿ_get0_ಖಾಸಗಿ_ಕೀಲಿ(ಕೀಲಿ), tmp) >= 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ret = 0;
 ಹೊರಹೋಗು:
	BN_clear_free(ಕ್ರಮ);
	BN_clear_free(tmp);
	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
sshkey_dump_ec_ಬಿಂದು(ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *ಗುಂಪು, ಸ್ಥಿರಾಂಕ EC_ಬಿಂದು *ಬಿಂದು)
{
	BIGNUM *x = ಖಾಲಿ, *y = ಖಾಲಿ;

	ಆದರೆ (ಬಿಂದು == ಖಾಲಿ) {
		fputs("point=(NULL)\n", stderr);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ ((x = BN_new()) == ಖಾಲಿ || (y = BN_new()) == ಖಾಲಿ) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EC_ಬಿಂದು_get_affine_coordinates(ಗುಂಪು, ಬಿಂದು, x, y, ಖಾಲಿ) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	fputs("x=", stderr);
	BN_print_fp(stderr, x);
	fputs("\ny=", stderr);
	BN_print_fp(stderr, y);
	fputs("\n", stderr);
 ಹೊರಹೋಗು:
	BN_clear_free(x);
	BN_clear_free(y);
}

ಶೂನ್ಯ
sshkey_dump_ec_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ EC_ಕೀಲಿ *ಕೀಲಿ)
{
	ಸ್ಥಿರಾಂಕ BIGNUM *exponent;

	sshkey_dump_ec_ಬಿಂದು(EC_ಕೀಲಿ_get0_ಗುಂಪು(ಕೀಲಿ),
	    EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(ಕೀಲಿ));
	fputs("exponent=", stderr);
	ಆದರೆ ((exponent = EC_ಕೀಲಿ_get0_ಖಾಸಗಿ_ಕೀಲಿ(ಕೀಲಿ)) == ಖಾಲಿ)
		fputs("(NULL)", stderr);
	ಇಲ್ಲದಿದ್ದರೆ
		BN_print_fp(stderr, EC_ಕೀಲಿ_get0_ಖಾಸಗಿ_ಕೀಲಿ(ಕೀಲಿ));
	fputs("\n", stderr);
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshkey_ಖಾಸಗಿ_ಗಮ್ಯ_blob2(ರಚನೆ sshkey *prv, ರಚನೆ sshbuf *blob,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comment, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ciphername,
    ಪೂರ್ಣಾಂಕ ಸುತ್ತುಗಳು)
{
	u_char *cp, *ಕೀಲಿ = ಖಾಲಿ, *pubkeyblob = ಖಾಲಿ;
	u_char salt[SALT_LEN];
	ಗಾತ್ರ_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ sshcipher_ctx *ciphercontext = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *cipher;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *kdfname = KDFNAME;
	ರಚನೆ sshbuf *encoded = ಖಾಲಿ, *encrypted = ಖಾಲಿ, *kdf = ಖಾಲಿ;

	ಆದರೆ (ಸುತ್ತುಗಳು <= 0)
		ಸುತ್ತುಗಳು = DEFAULT_ಸುತ್ತುಗಳು;
	ಆದರೆ (ಸುತ್ತುಗಳು > MAX_KDF_ಸುತ್ತುಗಳು) {
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (passphrase == ಖಾಲಿ || !ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ciphername == ಖಾಲಿ)
		ciphername = DEFAULT_CIPHERNAME;
	ಆದರೆ ((cipher = cipher_by_name(ciphername)) == ಖಾಲಿ) {
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((kdf = sshbuf_new()) == ಖಾಲಿ ||
	    (encoded = sshbuf_new()) == ಖಾಲಿ ||
	    (encrypted = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	ಆದರೆ ((ಕೀಲಿ = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, keylen + ivlen)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		ಆದರೆ (bcrypt_pbkdf(passphrase, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase),
		    salt, SALT_LEN, ಕೀಲಿ, keylen + ivlen, ಸುತ್ತುಗಳು) < 0) {
			r = SSH_ERR_INVALID_ವಾದ;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, ಸುತ್ತುಗಳು)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_ಕೀಲಿ_UNKNOWN_CIPHER;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = cipher_init(&ciphercontext, cipher, ಕೀಲಿ, keylen,
	    ಕೀಲಿ + keylen, ivlen, 1)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((r = sshbuf_put(encoded, AUTH_MAGIC, ಗಾತ್ರ(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_ಗಮ್ಯ_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	ಆದರೆ ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* append private key and comment*/
	ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* padding */
	i = 0;
	ಆಗ (sshbuf_len(encrypted) % blocksize) {
		ಆದರೆ ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}

	/* length in destination buffer */
	ಆದರೆ ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* encrypt */
	ಆದರೆ ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	ಆದರೆ ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_ಕೊನೆ, MARK_ಕೊನೆ_LEN)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* success */
	r = 0;

 ಹೊರಹೋಗು:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, ಗಾತ್ರ(salt));
	ಆದರೆ (ಕೀಲಿ != ಖಾಲಿ)
		freezero(ಕೀಲಿ, keylen + ivlen);
	ಆದರೆ (pubkeyblob != ಖಾಲಿ)
		freezero(pubkeyblob, pubkeylen);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
private2_uudecode(ರಚನೆ sshbuf *blob, ರಚನೆ sshbuf **decodedp)
{
	ಸ್ಥಿರಾಂಕ u_char *cp;
	ಗಾತ್ರ_t encoded_len;
	ಪೂರ್ಣಾಂಕ r;
	u_char ಕೊನೆಯ;
	ರಚನೆ sshbuf *encoded = ಖಾಲಿ, *decoded = ಖಾಲಿ;

	ಆದರೆ (blob == ಖಾಲಿ || decodedp == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	*decodedp = ಖಾಲಿ;

	ಆದರೆ ((encoded = sshbuf_new()) == ಖಾಲಿ ||
	    (decoded = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	ಆದರೆ (encoded_len < (MARK_BEGIN_LEN + MARK_ಕೊನೆ_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	ಆಗ (encoded_len > 0) {
		ಆದರೆ (*cp != '\n' && *cp != '\r') {
			ಆದರೆ ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
		}
		ಕೊನೆಯ = *cp;
		encoded_len--;
		cp++;
		ಆದರೆ (ಕೊನೆಯ == '\n') {
			ಆದರೆ (encoded_len >= MARK_ಕೊನೆ_LEN &&
			    memcmp(cp, MARK_ಕೊನೆ, MARK_ಕೊನೆ_LEN) == 0) {
				/* \0 terminate */
				ಆದರೆ ((r = sshbuf_put_u8(encoded, 0)) != 0)
					ಹೋಗು ಹೊರಹೋಗು;
				ನಿಲ್ಲಿಸು;
			}
		}
	}
	ಆದರೆ (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* decode base64 */
	ಆದರೆ ((r = sshbuf_b64tod(decoded, (ಅಕ್ಷರ *)sshbuf_ptr(encoded))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* check magic */
	ಆದರೆ (sshbuf_len(decoded) < ಗಾತ್ರ(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, ಗಾತ್ರ(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	*decodedp = decoded;
	decoded = ಖಾಲಿ;
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
private2_decrypt(ರಚನೆ sshbuf *decoded, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase,
    ರಚನೆ sshbuf **decryptedp, ರಚನೆ sshkey **pubkeyp)
{
	ಅಕ್ಷರ *ciphername = ಖಾಲಿ, *kdfname = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *cipher = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಗಾತ್ರ_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	ರಚನೆ sshbuf *kdf = ಖಾಲಿ, *decrypted = ಖಾಲಿ;
	ರಚನೆ sshcipher_ctx *ciphercontext = ಖಾಲಿ;
	ರಚನೆ sshkey *pubkey = ಖಾಲಿ;
	u_char *ಕೀಲಿ = ಖಾಲಿ, *salt = ಖಾಲಿ, *dp;
	u_int blocksize, ಸುತ್ತುಗಳು, nkeys, encrypted_len, check1, check2;

	ಆದರೆ (decoded == ಖಾಲಿ || decryptedp == ಖಾಲಿ || pubkeyp == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	*decryptedp = ಖಾಲಿ;
	*pubkeyp = ಖಾಲಿ;

	ಆದರೆ ((decrypted = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* parse public portion of key */
	ಆದರೆ ((r = sshbuf_consume(decoded, ಗಾತ್ರ(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((cipher = cipher_by_name(ciphername)) == ಖಾಲಿ) {
		r = SSH_ERR_ಕೀಲಿ_UNKNOWN_CIPHER;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_ಕೀಲಿ_UNKNOWN_CIPHER;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((passphrase == ಖಾಲಿ || ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	ಆದರೆ (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	ಆದರೆ ((ಕೀಲಿ = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, keylen + ivlen)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (strcmp(kdfname, "bcrypt") == 0) {
		ಆದರೆ ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &ಸುತ್ತುಗಳು)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ (ಸುತ್ತುಗಳು > MAX_KDF_ಸುತ್ತುಗಳು) {
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (bcrypt_pbkdf(passphrase, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase), salt, slen,
		    ಕೀಲಿ, keylen + ivlen, ಸುತ್ತುಗಳು) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	/* check that an appropriate amount of auth data is present */
	ಆದರೆ (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* decrypt private portion of key */
	ಆದರೆ ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, ಕೀಲಿ, keylen,
	    ಕೀಲಿ + keylen, ivlen, 0)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		ಆದರೆ (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* there should be no trailing data */
	ಆದರೆ (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* check check bytes */
	ಆದರೆ ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (check1 != check2) {
		r = SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = ಖಾಲಿ;
	*pubkeyp = pubkey;
	pubkey = ಖಾಲಿ;
	r = 0;
 ಹೊರಹೋಗು:
	cipher_free(ciphercontext);
	ಬಿಡುಗಡೆ(ciphername);
	ಬಿಡುಗಡೆ(kdfname);
	sshkey_free(pubkey);
	ಆದರೆ (salt != ಖಾಲಿ) {
		explicit_bzero(salt, slen);
		ಬಿಡುಗಡೆ(salt);
	}
	ಆದರೆ (ಕೀಲಿ != ಖಾಲಿ) {
		explicit_bzero(ಕೀಲಿ, keylen + ivlen);
		ಬಿಡುಗಡೆ(ಕೀಲಿ);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshkey_parse_private2(ರಚನೆ sshbuf *blob, ಪೂರ್ಣಾಂಕ type, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase,
    ರಚನೆ sshkey **keyp, ಅಕ್ಷರ **commentp)
{
	ಅಕ್ಷರ *comment = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ sshbuf *decoded = ಖಾಲಿ, *decrypted = ಖಾಲಿ;
	ರಚನೆ sshkey *k = ಖಾಲಿ, *pubkey = ಖಾಲಿ;

	ಆದರೆ (keyp != ಖಾಲಿ)
		*keyp = ಖಾಲಿ;
	ಆದರೆ (commentp != ಖಾಲಿ)
		*commentp = ಖಾಲಿ;

	/* Undo base64 encoding and decrypt the private section */
	ಆದರೆ ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ (type != ಕೀಲಿ_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Load the private key and comment */
	ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Check deterministic padding after private section */
	ಆದರೆ ((r = private2_check_padding(decrypted)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Check that the public key in the envelope matches the private key */
	ಆದರೆ (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* success */
	r = 0;
	ಆದರೆ (keyp != ಖಾಲಿ) {
		*keyp = k;
		k = ಖಾಲಿ;
	}
	ಆದರೆ (commentp != ಖಾಲಿ) {
		*commentp = comment;
		comment = ಖಾಲಿ;
	}
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshkey_parse_private2_pubkey(ರಚನೆ sshbuf *blob, ಪೂರ್ಣಾಂಕ type,
    ರಚನೆ sshkey **keyp)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ sshbuf *decoded = ಖಾಲಿ;
	ರಚನೆ sshkey *pubkey = ಖಾಲಿ;
	u_int nkeys = 0;

	ಆದರೆ (keyp != ಖಾಲಿ)
		*keyp = ಖಾಲಿ;

	ಆದರೆ ((r = private2_uudecode(blob, &decoded)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* parse public key from unencrypted envelope */
	ಆದರೆ ((r = sshbuf_consume(decoded, ಗಾತ್ರ(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Parse the public key */
	ಆದರೆ ((r = sshkey_froms(decoded, &pubkey)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ (type != ಕೀಲಿ_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* success */
	r = 0;
	ಆದರೆ (keyp != ಖಾಲಿ) {
		*keyp = pubkey;
		pubkey = ಖಾಲಿ;
	}
 ಹೊರಹೋಗು:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	ಹಿಂತಿರುಗಿ r;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshkey_ಖಾಸಗಿ_ಗಮ್ಯ_blob_pem_pkcs8(ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *buf,
    ಪೂರ್ಣಾಂಕ format, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *_passphrase, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comment)
{
	ಪೂರ್ಣಾಂಕ was_shielded = sshkey_is_shielded(ಕೀಲಿ);
	ಪೂರ್ಣಾಂಕ success, r;
	ಪೂರ್ಣಾಂಕ blen, len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : ಖಾಲಿ;
	ಅಕ್ಷರ *bptr;
	BIO *bio = ಖಾಲಿ;
	ರಚನೆ sshbuf *blob;
	EVP_PKEY *pkey = ಖಾಲಿ;

	ಆದರೆ (len > 0 && len <= 4)
		ಹಿಂತಿರುಗಿ SSH_ERR_PASSPHRASE_TOO_SHORT;
	ಆದರೆ ((blob = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((bio = BIO_new(BIO_s_mem())) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshkey_unshield_ಖಾಸಗಿ(ಕೀಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆಯ್ಕೆ (ಕೀಲಿ->type) {
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
		ಆದರೆ (format == SSHKEY_ಖಾಸಗಿ_PEM) {
			success = PEM_write_bio_ECPrivate_ಕೀಲಿ(bio,
			    EVP_PKEY_get0_EC_ಕೀಲಿ(ಕೀಲಿ->pkey),
			    cipher, passphrase, len, ಖಾಲಿ, ಖಾಲಿ);
		} ಇಲ್ಲದಿದ್ದರೆ {
			pkey = ಕೀಲಿ->pkey;
			EVP_PKEY_ಮೇಲೆ_ref(ಕೀಲಿ->pkey);
			success = 1;
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
		ಆದರೆ (format == SSHKEY_ಖಾಸಗಿ_PEM) {
			success = PEM_write_bio_RSAPrivate_ಕೀಲಿ(bio,
			    EVP_PKEY_get0_RSA(ಕೀಲಿ->pkey),
			    cipher, passphrase, len, ಖಾಲಿ, ಖಾಲಿ);
		} ಇಲ್ಲದಿದ್ದರೆ {
			pkey = ಕೀಲಿ->pkey;
			EVP_PKEY_ಮೇಲೆ_ref(ಕೀಲಿ->pkey);
			success = 1;
		}
		ನಿಲ್ಲಿಸು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ OPENSSL_HAS_ED25519
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519:
		ಆದರೆ (format == SSHKEY_ಖಾಸಗಿ_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		} ಇಲ್ಲದಿದ್ದರೆ {
			pkey = EVP_PKEY_new_raw_ಖಾಸಗಿ_ಕೀಲಿ(EVP_PKEY_ED25519,
			    ಖಾಲಿ, ಕೀಲಿ->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != ಖಾಲಿ;
		}
		ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ
	ಪೂರ್ವನಿಯೋಜಿತ:
		success = 0;
		ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (format == SSHKEY_ಖಾಸಗಿ_PKCS8) {
		ಆದರೆ ((success = PEM_write_bio_ಖಾಸಗಿ_ಕೀಲಿ(bio, pkey, cipher,
		    passphrase, len, ಖಾಲಿ, ಖಾಲಿ)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	ಆದರೆ ((blen = BIO_get_mem_ದತ್ತಾಂಶ(bio, &bptr)) <= 0) {
		r = SSH_ERR_ಆಂತರಿಕ_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put(blob, bptr, blen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	r = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (was_shielded)
		r = sshkey_shield_ಖಾಸಗಿ(ಕೀಲಿ);
	ಆದರೆ (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	ಹಿಂತಿರುಗಿ r;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
ಪೂರ್ಣಾಂಕ
sshkey_ಖಾಸಗಿ_ಗಮ್ಯ_fileblob(ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *blob,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comment,
    ಪೂರ್ಣಾಂಕ format, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *openssh_format_cipher, ಪೂರ್ಣಾಂಕ openssh_format_ಸುತ್ತುಗಳು)
{
	ಆಯ್ಕೆ (ಕೀಲಿ->type) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519:
		ನಿಲ್ಲಿಸು; /* see below */
#ಇಲ್ಲದಿದ್ದರೆ /* WITH_OPENSSL */
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519:
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK:
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಸ್ಥಿತಿ ಕೀಲಿ_MLDSA44_ED25519:
		ಹಿಂತಿರುಗಿ sshkey_ಖಾಸಗಿ_ಗಮ್ಯ_blob2(ಕೀಲಿ, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_ಸುತ್ತುಗಳು);
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಆಯ್ಕೆ (format) {
	ಸ್ಥಿತಿ SSHKEY_ಖಾಸಗಿ_OPENSSH:
		ಹಿಂತಿರುಗಿ sshkey_ಖಾಸಗಿ_ಗಮ್ಯ_blob2(ಕೀಲಿ, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_ಸುತ್ತುಗಳು);
	ಸ್ಥಿತಿ SSHKEY_ಖಾಸಗಿ_PEM:
	ಸ್ಥಿತಿ SSHKEY_ಖಾಸಗಿ_PKCS8:
		ಹಿಂತಿರುಗಿ sshkey_ಖಾಸಗಿ_ಗಮ್ಯ_blob_pem_pkcs8(ಕೀಲಿ, blob,
		    format, passphrase, comment);
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
translate_libcrypto_error(ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ pem_err)
{
	ಪೂರ್ಣಾಂಕ pem_reason = ERR_GET_REASON(pem_err);

	ಆಯ್ಕೆ (ERR_GET_LIB(pem_err)) {
	ಸ್ಥಿತಿ ERR_LIB_PEM:
		ಆಯ್ಕೆ (pem_reason) {
		ಸ್ಥಿತಿ PEM_R_BAD_PASSWORD_READ:
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PEM_R_PROBLEMS_GETTING_PASSWORD
		ಸ್ಥಿತಿ PEM_R_PROBLEMS_GETTING_PASSWORD:
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ PEM_R_BAD_DECRYPT
		ಸ್ಥಿತಿ PEM_R_BAD_DECRYPT:
#ಆದರೆ_ಅಂತ್ಯ
			ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
		}
	ಸ್ಥಿತಿ ERR_LIB_EVP:
		ಆಯ್ಕೆ (pem_reason) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ EVP_R_BAD_DECRYPT
		ಸ್ಥಿತಿ EVP_R_BAD_DECRYPT:
			ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ EVP_R_BN_DECODE_ERROR
		ಸ್ಥಿತಿ EVP_R_BN_DECODE_ERROR:
#ಆದರೆ_ಅಂತ್ಯ
		ಸ್ಥಿತಿ EVP_R_DECODE_ERROR:
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ EVP_R_ಖಾಸಗಿ_ಕೀಲಿ_DECODE_ERROR
		ಸ್ಥಿತಿ EVP_R_ಖಾಸಗಿ_ಕೀಲಿ_DECODE_ERROR:
#ಆದರೆ_ಅಂತ್ಯ
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
		}
	ಸ್ಥಿತಿ ERR_LIB_ASN1:
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ERR_LIB_OSSL_DECODER
	ಸ್ಥಿತಿ ERR_LIB_OSSL_DECODER:
#ಆದರೆ_ಅಂತ್ಯ
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
}

ಸ್ಥಿರ ಶೂನ್ಯ
clear_libcrypto_errors(ಶೂನ್ಯ)
{
	ಆಗ (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
convert_libcrypto_error(ಶೂನ್ಯ)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	ಆದರೆ (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
	ಹಿಂತಿರುಗಿ translate_libcrypto_error(ERR_peek_ಕೊನೆಯ_error());
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pem_passphrase_cb(ಅಕ್ಷರ *buf, ಪೂರ್ಣಾಂಕ ಗಾತ್ರ_2, ಪೂರ್ಣಾಂಕ rwflag, ಶೂನ್ಯ *u)
{
	ಅಕ್ಷರ *p = (ಅಕ್ಷರ *)u;
	ಗಾತ್ರ_t len;

	ಆದರೆ (p == ಖಾಲಿ || (len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(p)) == 0)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (ಗಾತ್ರ_2 < 0 || len > (ಗಾತ್ರ_t)ಗಾತ್ರ_2)
		ಹಿಂತಿರುಗಿ -1;
	ಸ್ಮರಣೆ_ನಕಲು(buf, p, len);
	ಹಿಂತಿರುಗಿ (ಪೂರ್ಣಾಂಕ)len;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshkey_parse_ಖಾಸಗಿ_pem_fileblob(ರಚನೆ sshbuf *blob, ಪೂರ್ಣಾಂಕ type,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase, ರಚನೆ sshkey **keyp)
{
	EVP_PKEY *pk = ಖಾಲಿ;
	ರಚನೆ sshkey *prv = ಖಾಲಿ;
	BIO *bio = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;
	RSA *rsa = ಖಾಲಿ;
	EC_ಕೀಲಿ *ecdsa = ಖಾಲಿ;

	ಆದರೆ (keyp != ಖಾಲಿ)
		*keyp = ಖಾಲಿ;

	ಆದರೆ ((bio = BIO_new(BIO_s_mem())) == ಖಾಲಿ || sshbuf_len(blob) > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (ಪೂರ್ಣಾಂಕ)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	clear_libcrypto_errors();
	ಆದರೆ ((pk = PEM_read_bio_ಖಾಸಗಿ_ಕೀಲಿ(bio, ಖಾಲಿ, pem_passphrase_cb,
	    (ಅಕ್ಷರ *)passphrase)) == ಖಾಲಿ) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		ಆದರೆ (passphrase != ಖಾಲಿ && *passphrase != '\0')
			r = SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
		ಇಲ್ಲದಿದ್ದರೆ
			r = convert_libcrypto_error();
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_PKEY_ತಳ_id(pk) == EVP_PKEY_RSA &&
	    (type == ಕೀಲಿ_UNSPEC || type == ಕೀಲಿ_RSA)) {
		ಆದರೆ ((prv = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((rsa = EVP_PKEY_get1_RSA(pk)) == ಖಾಲಿ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		prv->type = ಕೀಲಿ_RSA;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#ಆದರೆ_ಅಂತ್ಯ
		ಆದರೆ (RSA_blinding_on(rsa, ಖಾಲಿ) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		EVP_PKEY_ಮೇಲೆ_ref(pk);
		prv->pkey = pk;
		ಆದರೆ ((r = sshkey_check_rsa_ಉದ್ದಳತೆ(prv, 0)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (EVP_PKEY_ತಳ_id(pk) == EVP_PKEY_EC &&
	    (type == ಕೀಲಿ_UNSPEC || type == ಕೀಲಿ_ECDSA)) {
		ಆದರೆ ((prv = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((prv->ecdsa_nid = sshkey_ecdsa_fixup_ಗುಂಪು(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_ಕೀಲಿ(pk)) == ಖಾಲಿ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		prv->type = ಕೀಲಿ_ECDSA;
		ಆದರೆ (sshkey_ವಕ್ರ_nid_ಗಮ್ಯ_name(prv->ecdsa_nid) == ಖಾಲಿ ||
		    sshkey_ec_validate_ಬಹಿರಂಗ(EC_ಕೀಲಿ_get0_ಗುಂಪು(ecdsa),
		    EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(ecdsa)) != 0 ||
		    sshkey_ec_validate_ಖಾಸಗಿ(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		EVP_PKEY_ಮೇಲೆ_ref(pk);
		prv->pkey = pk;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
		ಆದರೆ (prv != ಖಾಲಿ && prv->pkey != ಖಾಲಿ)
			sshkey_dump_ec_ಕೀಲಿ(EVP_PKEY_get0_EC_ಕೀಲಿ(prv->pkey));
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ OPENSSL_HAS_ED25519
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (EVP_PKEY_ತಳ_id(pk) == EVP_PKEY_ED25519 &&
	    (type == ಕೀಲಿ_UNSPEC || type == ಕೀಲಿ_ED25519)) {
		ಗಾತ್ರ_t len;

		ಆದರೆ ((prv = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ ||
		    (prv->ed25519_sk = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ED25519_SK_SZ)) == ಖಾಲಿ ||
		    (prv->ed25519_pk = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ED25519_PK_SZ)) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		prv->type = ಕೀಲಿ_ED25519;
		len = ED25519_PK_SZ;
		ಆದರೆ (!EVP_PKEY_get_raw_ಬಹಿರಂಗ_ಕೀಲಿ(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		ಆದರೆ (!EVP_PKEY_get_raw_ಖಾಸಗಿ_ಕೀಲಿ(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/* Append the public key to our private key */
		ಸ್ಮರಣೆ_ನಕಲು(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
		sshbuf_dump_ದತ್ತಾಂಶ(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ /* OPENSSL_HAS_ED25519 */
	} ಇಲ್ಲದಿದ್ದರೆ {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	r = 0;
	ಆದರೆ (keyp != ಖಾಲಿ) {
		*keyp = prv;
		prv = ಖಾಲಿ;
	}
 ಹೊರಹೋಗು:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_ಕೀಲಿ_free(ecdsa);
	sshkey_free(prv);
	ಹಿಂತಿರುಗಿ r;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

ಪೂರ್ಣಾಂಕ
sshkey_parse_ಖಾಸಗಿ_fileblob_type(ರಚನೆ sshbuf *blob, ಪೂರ್ಣಾಂಕ type,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase, ರಚನೆ sshkey **keyp, ಅಕ್ಷರ **commentp)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (keyp != ಖಾಲಿ)
		*keyp = ಖಾಲಿ;
	ಆದರೆ (commentp != ಖಾಲಿ)
		*commentp = ಖಾಲಿ;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	ಆದರೆ (r != SSH_ERR_INVALID_FORMAT)
		ಹಿಂತಿರುಗಿ r;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಹಿಂತಿರುಗಿ sshkey_parse_ಖಾಸಗಿ_pem_fileblob(blob, type,
	    passphrase, keyp);
#ಇಲ್ಲದಿದ್ದರೆ
	ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
}

ಪೂರ್ಣಾಂಕ
sshkey_parse_ಖಾಸಗಿ_fileblob(ರಚನೆ sshbuf *ಬಫರ್, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase,
    ರಚನೆ sshkey **keyp, ಅಕ್ಷರ **commentp)
{
	ಆದರೆ (keyp != ಖಾಲಿ)
		*keyp = ಖಾಲಿ;
	ಆದರೆ (commentp != ಖಾಲಿ)
		*commentp = ಖಾಲಿ;

	ಹಿಂತಿರುಗಿ sshkey_parse_ಖಾಸಗಿ_fileblob_type(ಬಫರ್, ಕೀಲಿ_UNSPEC,
	    passphrase, keyp, commentp);
}

ಶೂನ್ಯ
sshkey_sig_details_free(ರಚನೆ sshkey_sig_details *details)
{
	freezero(details, ಗಾತ್ರ(*details));
}

ಪೂರ್ಣಾಂಕ
sshkey_parse_pubkey_from_ಖಾಸಗಿ_fileblob_type(ರಚನೆ sshbuf *blob, ಪೂರ್ಣಾಂಕ type,
    ರಚನೆ sshkey **pubkeyp)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (pubkeyp != ಖಾಲಿ)
		*pubkeyp = ಖಾಲಿ;
	/* only new-format private keys bundle a public key inside */
	ಆದರೆ ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}
