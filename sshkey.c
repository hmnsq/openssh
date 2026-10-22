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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/mman.h>
#ضمن <netinet/in.h>

#که_تعریف_شوی WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/err.h>
#ضمن <openssl/pem.h>
#د_که_پای

#ضمن "crypto_api.h"

#ضمن <errno.h>
#ضمن <limits.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <resolv.h>
#ضمن <time.h>
#ضمن <util.h>

#ضمن "ssh2.h"
#ضمن "ssherr.h"
#ضمن "misc.h"
#ضمن "sshbuf.h"
#ضمن "cipher.h"
#ضمن "digest.h"
#تعریف_کړه SSHKEY_دننی
#ضمن "sshkey.h"
#ضمن "match.h"
#ضمن "ssh-sk.h"
#ضمن "ssh-pkcs11.h"

#ضمن "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#تعریف_کړه MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#تعریف_کړه MARK_پای_ټکی		"-----END OPENSSH PRIVATE KEY-----\n"
#تعریف_کړه MARK_BEGIN_LEN		(حجم(MARK_BEGIN) - 1)
#تعریف_کړه MARK_پای_ټکی_LEN		(حجم(MARK_پای_ټکی) - 1)
#تعریف_کړه KDFNAME			"bcrypt"
#تعریف_کړه AUTH_MAGIC		"openssh-key-v1"
#تعریف_کړه SALT_LEN		16
#تعریف_کړه DEFAULT_CIPHERNAME	"aes256-ctr"
#تعریف_کړه	DEFAULT_پړاوونه		32
#تعریف_کړه	MAX_KDF_پړاوونه		(1<<20)

/*
 * Constants relating to "shielding" support; protection of keys expected
 * to remain in memory for long durations
 */
#تعریف_کړه SSHKEY_SHIELD_PREKEY_LEN	(16 * 1024)
#تعریف_کړه SSHKEY_SHIELD_CIPHER		"aes256-ctr" /* XXX want AES-EME* */
#تعریف_کړه SSHKEY_SHIELD_PREKEY_HASH	SSH_DIGEST_SHA512

ساكن صحيح sshkey_from_blob_دننی(بنية sshbuf *buf,
    بنية sshkey **keyp, صحيح allow_cert,
    ثابت حرف *alg_allowlist, ثابت حرف *ca_sigalg_allowlist);

/* Supported key types */
خارجي ثابت بنية sshkey_impl sshkey_ed25519_impl;
خارجي ثابت بنية sshkey_impl sshkey_ed25519_cert_impl;
خارجي ثابت بنية sshkey_impl sshkey_ed25519_sk_impl;
خارجي ثابت بنية sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
خارجي ثابت بنية sshkey_impl sshkey_mldsa44_ed25519_impl;
خارجي ثابت بنية sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#که_تعریف_شوی WITH_OPENSSL
# ifdef ENABLE_SK
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_sk_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_sk_cert_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_nistp256_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_nistp384_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_nistp521_impl;
خارجي ثابت بنية sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
خارجي ثابت بنية sshkey_impl sshkey_rsa_impl;
خارجي ثابت بنية sshkey_impl sshkey_rsa_cert_impl;
خارجي ثابت بنية sshkey_impl sshkey_rsa_sha256_impl;
خارجي ثابت بنية sshkey_impl sshkey_rsa_sha256_cert_impl;
خارجي ثابت بنية sshkey_impl sshkey_rsa_sha512_impl;
خارجي ثابت بنية sshkey_impl sshkey_rsa_sha512_cert_impl;
#د_که_پای /* WITH_OPENSSL */

ثابت بنية sshkey_impl * ثابت keyimpls[] = {
	&sshkey_ed25519_impl,
	&sshkey_ed25519_cert_impl,
#که_تعریف_شوی ENABLE_SK
	&sshkey_ed25519_sk_impl,
	&sshkey_ed25519_sk_cert_impl,
#د_که_پای
#که_تعریف_شوی USE_MLDSA
	&sshkey_mldsa44_ed25519_impl,
	&sshkey_mldsa44_ed25519_cert_impl,
#د_که_پای /* USE_MLDSA */
#که_تعریف_شوی WITH_OPENSSL
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
#د_که_پای /* WITH_OPENSSL */
	عدم
};

ساكن ثابت بنية sshkey_impl *
sshkey_impl_from_type(صحيح type)
{
	صحيح i;

	لكل (i = 0; keyimpls[i] != عدم; i++) {
		إذا (keyimpls[i]->type == type)
			أرجع keyimpls[i];
	}
	أرجع عدم;
}

ساكن ثابت بنية sshkey_impl *
sshkey_impl_from_type_nid(صحيح type, صحيح nid)
{
	صحيح i;

	لكل (i = 0; keyimpls[i] != عدم; i++) {
		إذا (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			أرجع keyimpls[i];
	}
	أرجع عدم;
}

ساكن ثابت بنية sshkey_impl *
sshkey_impl_from_کلی(ثابت بنية sshkey *k)
{
	إذا (k == عدم)
		أرجع عدم;
	أرجع sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

ثابت حرف *
sshkey_type(ثابت بنية sshkey *k)
{
	ثابت بنية sshkey_impl *impl;

	إذا ((impl = sshkey_impl_from_کلی(k)) == عدم)
		أرجع "unknown";
	أرجع impl->shortname;
}

ساكن ثابت حرف *
sshkey_ssh_name_from_type_nid(صحيح type, صحيح nid)
{
	ثابت بنية sshkey_impl *impl;

	إذا ((impl = sshkey_impl_from_type_nid(type, nid)) == عدم)
		أرجع "ssh-unknown";
	أرجع impl->name;
}

صحيح
sshkey_type_is_cert(صحيح type)
{
	ثابت بنية sshkey_impl *impl;

	إذا ((impl = sshkey_impl_from_type(type)) == عدم)
		أرجع 0;
	أرجع impl->cert;
}

ثابت حرف *
sshkey_ssh_name(ثابت بنية sshkey *k)
{
	أرجع sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

ثابت حرف *
sshkey_ssh_name_plain(ثابت بنية sshkey *k)
{
	أرجع sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

ساكن صحيح
type_from_name(ثابت حرف *name, صحيح allow_short)
{
	صحيح i;
	ثابت بنية sshkey_impl *impl;

	لكل (i = 0; keyimpls[i] != عدم; i++) {
		impl = keyimpls[i];
		إذا (impl->name != عدم && strcmp(name, impl->name) == 0)
			أرجع impl->type;
		/* Only allow shortname matches for plain key types */
		إذا (allow_short && !impl->cert && impl->shortname != عدم &&
		    strcasecmp(impl->shortname, name) == 0)
			أرجع impl->type;
	}
	أرجع کلی_UNSPEC;
}

صحيح
sshkey_type_from_name(ثابت حرف *name)
{
	أرجع type_from_name(name, 0);
}

صحيح
sshkey_type_from_shortname(ثابت حرف *name)
{
	أرجع type_from_name(name, 1);
}

ساكن صحيح
کلی_type_is_ecdsa_variant(صحيح type)
{
	بدل (type) {
	حالة کلی_ECDSA:
	حالة کلی_ECDSA_CERT:
	حالة کلی_ECDSA_SK:
	حالة کلی_ECDSA_SK_CERT:
		أرجع 1;
	}
	أرجع 0;
}

صحيح
sshkey_ecdsa_nid_from_name(ثابت حرف *name)
{
	صحيح i;

	لكل (i = 0; keyimpls[i] != عدم; i++) {
		إذا (!کلی_type_is_ecdsa_variant(keyimpls[i]->type))
			استمر;
		إذا (keyimpls[i]->name != عدم &&
		    strcmp(name, keyimpls[i]->name) == 0)
			أرجع keyimpls[i]->nid;
	}
	أرجع -1;
}

صحيح
sshkey_سمون_keyname_منزل_sigalgs(ثابت حرف *keyname, ثابت حرف *sigalgs)
{
	صحيح ktype;

	إذا (sigalgs == عدم || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == کلی_UNSPEC)
		أرجع 0;
	وإلا إذا (ktype == کلی_RSA) {
		أرجع سمون_نمونه_list("ssh-rsa", sigalgs, 0) == 1 ||
		    سمون_نمونه_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    سمون_نمونه_list("rsa-sha2-512", sigalgs, 0) == 1;
	} وإلا إذا (ktype == کلی_RSA_CERT) {
		أرجع سمون_نمونه_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    سمون_نمونه_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    سمون_نمونه_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} وإلا إذا (ktype == کلی_ECDSA_SK) {
		أرجع سمون_نمونه_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || سمون_نمونه_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} وإلا إذا (ktype == کلی_ECDSA_SK_CERT) {
		أرجع سمون_نمونه_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || سمون_نمونه_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} وإلا
		أرجع سمون_نمونه_list(keyname, sigalgs, 0) == 1;
}

حرف *
sshkey_alg_list(صحيح certs_only, صحيح plain_only, صحيح include_sigonly, حرف sep)
{
	حرف *ret = عدم;
	اندازه_t i;
	ثابت بنية sshkey_impl *impl;
	حرف sep_str[2] = {sep, '\0'};

	لكل (i = 0; keyimpls[i] != عدم; i++) {
		impl = keyimpls[i];
		إذا (impl->name == عدم)
			استمر;
		إذا (!include_sigonly && impl->sigonly)
			استمر;
		إذا ((certs_only && !impl->cert) || (plain_only && impl->cert))
			استمر;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	أرجع ret;
}

صحيح
sshkey_نومونه_valid2(ثابت حرف *نومونه, صحيح allow_wildcard, صحيح plain_only)
{
	حرف *s, *cp, *p;
	ثابت بنية sshkey_impl *impl;
	صحيح i, type;

	إذا (نومونه == عدم || strcmp(نومونه, "") == 0)
		أرجع 0;
	إذا ((s = cp = strdup(نومونه)) == عدم)
		أرجع 0;
	لكل ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		إذا (type == کلی_UNSPEC) {
			إذا (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = عدم;
				لكل (i = 0; keyimpls[i] != عدم; i++) {
					إذا (سمون_نمونه_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						اكسر;
					}
				}
				إذا (impl != عدم)
					استمر;
			}
			حرر(s);
			أرجع 0;
		} وإلا إذا (plain_only && sshkey_type_is_cert(type)) {
			حرر(s);
			أرجع 0;
		}
	}
	حرر(s);
	أرجع 1;
}

u_int
sshkey_اندازه(ثابت بنية sshkey *k)
{
	ثابت بنية sshkey_impl *impl;

	إذا ((impl = sshkey_impl_from_کلی(k)) == عدم)
		أرجع 0;
	إذا (impl->funcs->اندازه != عدم)
		أرجع impl->funcs->اندازه(k);
	أرجع impl->keybits;
}

ساكن صحيح
sshkey_type_is_valid_ca(صحيح type)
{
	ثابت بنية sshkey_impl *impl;

	إذا ((impl = sshkey_impl_from_type(type)) == عدم)
		أرجع 0;
	/* All non-certificate types may act as CAs */
	أرجع !impl->cert;
}

صحيح
sshkey_is_cert(ثابت بنية sshkey *k)
{
	إذا (k == عدم)
		أرجع 0;
	أرجع sshkey_type_is_cert(k->type);
}

صحيح
sshkey_is_sk(ثابت بنية sshkey *k)
{
	إذا (k == عدم)
		أرجع 0;
	بدل (sshkey_type_plain(k->type)) {
	حالة کلی_ECDSA_SK:
	حالة کلی_ED25519_SK:
		أرجع 1;
	افتراضي:
		أرجع 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
صحيح
sshkey_type_plain(صحيح type)
{
	بدل (type) {
	حالة کلی_RSA_CERT:
		أرجع کلی_RSA;
	حالة کلی_ECDSA_CERT:
		أرجع کلی_ECDSA;
	حالة کلی_ECDSA_SK_CERT:
		أرجع کلی_ECDSA_SK;
	حالة کلی_ED25519_CERT:
		أرجع کلی_ED25519;
	حالة کلی_MLDSA44_ED25519_CERT:
		أرجع کلی_MLDSA44_ED25519;
	حالة کلی_ED25519_SK_CERT:
		أرجع کلی_ED25519_SK;
	افتراضي:
		أرجع type;
	}
}

/* Return the cert equivalent to a plain key type */
ساكن صحيح
sshkey_type_certified(صحيح type)
{
	بدل (type) {
	حالة کلی_RSA:
		أرجع کلی_RSA_CERT;
	حالة کلی_ECDSA:
		أرجع کلی_ECDSA_CERT;
	حالة کلی_ECDSA_SK:
		أرجع کلی_ECDSA_SK_CERT;
	حالة کلی_ED25519:
		أرجع کلی_ED25519_CERT;
	حالة کلی_MLDSA44_ED25519:
		أرجع کلی_MLDSA44_ED25519_CERT;
	حالة کلی_ED25519_SK:
		أرجع کلی_ED25519_SK_CERT;
	افتراضي:
		أرجع -1;
	}
}

#که_تعریف_شوی WITH_OPENSSL
ساكن ثابت EVP_MD *
ssh_digest_منزل_md(صحيح hash_alg)
{
	بدل (hash_alg) {
	حالة SSH_DIGEST_SHA1:
		أرجع EVP_sha1();
	حالة SSH_DIGEST_SHA256:
		أرجع EVP_sha256();
	حالة SSH_DIGEST_SHA384:
		أرجع EVP_sha384();
	حالة SSH_DIGEST_SHA512:
		أرجع EVP_sha512();
	}
	أرجع عدم;
}

صحيح
sshkey_pkey_digest_sign(EVP_PKEY *pkey, صحيح hash_alg, u_char **sigp,
    اندازه_t *lenp, ثابت u_char *معلومات, اندازه_t datalen)
{
	EVP_MD_CTX *ctx = عدم;
	u_char *sig = عدم;
	صحيح ret;
	اندازه_t slen;
	ثابت EVP_MD *evpmd;

	*sigp = عدم;
	*lenp = 0;

	slen = EVP_PKEY_اندازه(pkey);
	إذا (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_منزل_md(hash_alg)) == عدم)
		أرجع SSH_ERR_INVALID_دلیل;

	إذا ((sig = حافظه_ورکړه(slen)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	إذا ((ctx = EVP_MD_CTX_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (EVP_DigestSignInit(ctx, عدم, evpmd, عدم, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, معلومات, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = عدم;
	ret = 0;

 بهر:
	EVP_MD_CTX_free(ctx);
	حرر(sig);
	أرجع ret;
}

صحيح
sshkey_pkey_digest_verify(EVP_PKEY *pkey, صحيح hash_alg, ثابت u_char *معلومات,
    اندازه_t datalen, u_char *sigbuf, اندازه_t siglen)
{
	EVP_MD_CTX *ctx = عدم;
	صحيح ret = SSH_ERR_دننی_ERROR;
	ثابت EVP_MD *evpmd;

	إذا ((evpmd = ssh_digest_منزل_md(hash_alg)) == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا ((ctx = EVP_MD_CTX_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (EVP_DigestVerifyInit(ctx, عدم, evpmd, عدم, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	بدل (EVP_DigestVerify(ctx, sigbuf, siglen, معلومات, datalen)) {
	حالة 1:
		ret = 0;
		اكسر;
	حالة 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		اكسر;
	افتراضي:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اكسر;
	}

 بهر:
	EVP_MD_CTX_free(ctx);
	أرجع ret;
}

/* XXX: these are really begging for a table-driven approach */
صحيح
sshkey_منحني_name_منزل_nid(ثابت حرف *name)
{
	إذا (strcmp(name, "nistp256") == 0)
		أرجع NID_X9_62_prime256v1;
	وإلا إذا (strcmp(name, "nistp384") == 0)
		أرجع NID_secp384r1;
	وإلا إذا (strcmp(name, "nistp521") == 0)
		أرجع NID_secp521r1;
	وإلا
		أرجع -1;
}

u_int
sshkey_منحني_nid_منزل_بټونه(صحيح nid)
{
	بدل (nid) {
	حالة NID_X9_62_prime256v1:
		أرجع 256;
	حالة NID_secp384r1:
		أرجع 384;
	حالة NID_secp521r1:
		أرجع 521;
	افتراضي:
		أرجع 0;
	}
}

صحيح
sshkey_ecdsa_بټونه_منزل_nid(صحيح بټونه)
{
	بدل (بټونه) {
	حالة 256:
		أرجع NID_X9_62_prime256v1;
	حالة 384:
		أرجع NID_secp384r1;
	حالة 521:
		أرجع NID_secp521r1;
	افتراضي:
		أرجع -1;
	}
}

ثابت حرف *
sshkey_منحني_nid_منزل_name(صحيح nid)
{
	بدل (nid) {
	حالة NID_X9_62_prime256v1:
		أرجع "nistp256";
	حالة NID_secp384r1:
		أرجع "nistp384";
	حالة NID_secp521r1:
		أرجع "nistp521";
	افتراضي:
		أرجع عدم;
	}
}

صحيح
sshkey_ec_nid_منزل_hash_alg(صحيح nid)
{
	صحيح kbits = sshkey_منحني_nid_منزل_بټونه(nid);

	إذا (kbits <= 0)
		أرجع -1;

	/* RFC5656 section 6.2.1 */
	إذا (kbits <= 256)
		أرجع SSH_DIGEST_SHA256;
	وإلا إذا (kbits <= 384)
		أرجع SSH_DIGEST_SHA384;
	وإلا
		أرجع SSH_DIGEST_SHA512;
}
#د_که_پای /* WITH_OPENSSL */

ساكن فراغ
cert_free(بنية sshkey_cert *cert)
{
	u_int i;

	إذا (cert == عدم)
		أرجع;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	حرر(cert->کلی_id);
	لكل (i = 0; i < cert->nprincipals; i++)
		حرر(cert->principals[i]);
	حرر(cert->principals);
	sshkey_free(cert->signature_کلی);
	حرر(cert->signature_type);
	freezero(cert, حجم(*cert));
}

ساكن بنية sshkey_cert *
cert_new(فراغ)
{
	بنية sshkey_cert *cert;

	إذا ((cert = حافظه_صفر_ورکړه(1, حجم(*cert))) == عدم)
		أرجع عدم;
	إذا ((cert->certblob = sshbuf_new()) == عدم ||
	    (cert->critical = sshbuf_new()) == عدم ||
	    (cert->extensions = sshbuf_new()) == عدم) {
		cert_free(cert);
		أرجع عدم;
	}
	cert->کلی_id = عدم;
	cert->principals = عدم;
	cert->signature_کلی = عدم;
	cert->signature_type = عدم;
	أرجع cert;
}

بنية sshkey *
sshkey_new(صحيح type)
{
	بنية sshkey *k;
	ثابت بنية sshkey_impl *impl = عدم;

	إذا (type != کلی_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == عدم)
		أرجع عدم;

	/* All non-certificate types may act as CAs */
	إذا ((k = حافظه_صفر_ورکړه(1, حجم(*k))) == عدم)
		أرجع عدم;
	k->type = type;
	k->ecdsa_nid = -1;
	إذا (impl != عدم && impl->funcs->alloc != عدم) {
		إذا (impl->funcs->alloc(k) != 0) {
			حرر(k);
			أرجع عدم;
		}
	}
	إذا (sshkey_is_cert(k)) {
		إذا ((k->cert = cert_new()) == عدم) {
			sshkey_free(k);
			أرجع عدم;
		}
	}

	أرجع k;
}

/* Frees common FIDO fields */
فراغ
sshkey_sk_cleanup(بنية sshkey *k)
{
	حرر(k->sk_application);
	sshbuf_free(k->sk_کلی_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = عدم;
	k->sk_کلی_handle = k->sk_reserved = عدم;
}

#إذا defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#وإلاإذا defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#وإلا
# define PREKEY_MMAP_FLAG	0
#د_که_پای

ساكن صحيح
sshkey_prekey_alloc(u_char **prekeyp, اندازه_t len)
{
#إذا defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = عدم;
	إذا ((prekey = mmap(عدم, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		أرجع SSH_ERR_SYSTEM_ERROR;
#إذا defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(فراغ)madvise(prekey, len, MADV_DONTDUMP);
#د_که_پای
	*prekeyp = prekey;
#وإلا
	*prekeyp = حافظه_صفر_ورکړه(1, len);
#د_که_پای /* HAVE_MMAP et al */
	أرجع 0;
}

ساكن فراغ
sshkey_prekey_free(فراغ *prekey, اندازه_t len)
{
#إذا defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	إذا (prekey == عدم)
		أرجع;
	munmap(prekey, len);
#وإلا
	حرر(prekey);
#د_که_پای /* HAVE_MMAP et al */
}

ساكن فراغ
sshkey_free_contents(بنية sshkey *k)
{
	ثابت بنية sshkey_impl *impl;

	إذا (k == عدم)
		أرجع;
	إذا ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_کلی_free(k);
	إذا ((impl = sshkey_impl_from_type(k->type)) != عدم &&
	    impl->funcs->cleanup != عدم)
		impl->funcs->cleanup(k);
	إذا (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_شخصي, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

فراغ
sshkey_free(بنية sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, حجم(*k));
}

ساكن صحيح
cert_compare(بنية sshkey_cert *a, بنية sshkey_cert *b)
{
	إذا (a == عدم && b == عدم)
		أرجع 1;
	إذا (a == عدم || b == عدم)
		أرجع 0;
	إذا (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		أرجع 0;
	إذا (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		أرجع 0;
	أرجع 1;
}

/* Compares FIDO-specific pubkey fields only */
صحيح
sshkey_sk_fields_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	إذا (a->sk_application == عدم || b->sk_application == عدم)
		أرجع 0;
	إذا (strcmp(a->sk_application, b->sk_application) != 0)
		أرجع 0;
	أرجع 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
صحيح
sshkey_equal_عامه(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	ثابت بنية sshkey_impl *impl;

	إذا (a == عدم || b == عدم ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		أرجع 0;
	إذا ((impl = sshkey_impl_from_type(a->type)) == عدم)
		أرجع 0;
	أرجع impl->funcs->equal(a, b);
}

صحيح
sshkey_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	إذا (a == عدم || b == عدم || a->type != b->type)
		أرجع 0;
	إذا (sshkey_is_cert(a)) {
		إذا (!cert_compare(a->cert, b->cert))
			أرجع 0;
	}
	أرجع sshkey_equal_عامه(a, b);
}


/* Serialise common FIDO key parts */
صحيح
sshkey_serialize_sk(ثابت بنية sshkey *کلی, بنية sshbuf *b)
{
	صحيح r;

	إذا ((r = sshbuf_put_cstring(b, کلی->sk_application)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
منزل_blob_buf(ثابت بنية sshkey *کلی, بنية sshbuf *b, صحيح force_plain,
  تعداد sshkey_serialize_rep opts)
{
	صحيح type, ret = SSH_ERR_دننی_ERROR;
	ثابت حرف *typename;
	ثابت بنية sshkey_impl *impl;

	إذا (کلی == عدم)
		أرجع SSH_ERR_INVALID_دلیل;

	type = force_plain ? sshkey_type_plain(کلی->type) : کلی->type;

	إذا (sshkey_type_is_cert(type)) {
		إذا (کلی->cert == عدم)
			أرجع SSH_ERR_EXPECTED_CERT;
		إذا (sshbuf_len(کلی->cert->certblob) == 0)
			أرجع SSH_ERR_کلی_LACKS_CERTBLOB;
		/* Use the existing blob */
		إذا ((ret = sshbuf_putb(b, کلی->cert->certblob)) != 0)
			أرجع ret;
		أرجع 0;
	}
	إذا ((impl = sshkey_impl_from_type(type)) == عدم)
		أرجع SSH_ERR_کلی_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, کلی->ecdsa_nid);
	إذا ((ret = sshbuf_put_cstring(b, typename)) != 0)
		أرجع ret;
	أرجع impl->funcs->serialize_عامه(کلی, b, opts);
}

صحيح
sshkey_putb(ثابت بنية sshkey *کلی, بنية sshbuf *b)
{
	أرجع منزل_blob_buf(کلی, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

ساكن صحيح
sshkey_puts_opts_دننی(ثابت بنية sshkey *کلی, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts, صحيح force_plain)
{
	بنية sshbuf *tmp;
	صحيح r;

	إذا ((tmp = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	r = منزل_blob_buf(کلی, tmp, force_plain, opts);
	إذا (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	أرجع r;
}

صحيح
sshkey_puts(ثابت بنية sshkey *کلی, بنية sshbuf *b)
{
	أرجع sshkey_puts_opts_دننی(کلی, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

صحيح
sshkey_putb_plain(ثابت بنية sshkey *کلی, بنية sshbuf *b)
{
	أرجع منزل_blob_buf(کلی, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

صحيح
sshkey_puts_plain(ثابت بنية sshkey *کلی, بنية sshbuf *b)
{
	أرجع sshkey_puts_opts_دننی(کلی, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

ساكن صحيح
منزل_blob(ثابت بنية sshkey *کلی, u_char **blobp, اندازه_t *lenp, صحيح force_plain,
    تعداد sshkey_serialize_rep opts)
{
	صحيح ret = SSH_ERR_دننی_ERROR;
	اندازه_t len;
	بنية sshbuf *b = عدم;

	إذا (lenp != عدم)
		*lenp = 0;
	إذا (blobp != عدم)
		*blobp = عدم;
	إذا ((b = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((ret = منزل_blob_buf(کلی, b, force_plain, opts)) != 0)
		اذهب بهر;
	len = sshbuf_len(b);
	إذا (lenp != عدم)
		*lenp = len;
	إذا (blobp != عدم) {
		إذا ((*blobp = حافظه_ورکړه(len)) == عدم) {
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب بهر;
		}
		حافظه_نقل(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 بهر:
	sshbuf_free(b);
	أرجع ret;
}

صحيح
sshkey_منزل_blob(ثابت بنية sshkey *کلی, u_char **blobp, اندازه_t *lenp)
{
	أرجع منزل_blob(کلی, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

صحيح
sshkey_plain_منزل_blob(ثابت بنية sshkey *کلی, u_char **blobp, اندازه_t *lenp)
{
	أرجع منزل_blob(کلی, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

صحيح
sshkey_fingerprint_raw(ثابت بنية sshkey *k, صحيح dgst_alg,
    u_char **retp, اندازه_t *lenp)
{
	u_char *blob = عدم, *ret = عدم;
	اندازه_t blob_len = 0;
	صحيح r = SSH_ERR_دننی_ERROR;

	إذا (retp != عدم)
		*retp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	إذا (ssh_digest_بایټونه(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_دلیل;
		اذهب بهر;
	}
	إذا ((r = منزل_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		اذهب بهر;
	إذا ((ret = حافظه_صفر_ورکړه(1, SSH_DIGEST_MAX_اوږدتیا)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = ssh_digest_حافظه(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_اوږدتیا)) != 0)
		اذهب بهر;
	/* success */
	إذا (retp != عدم) {
		*retp = ret;
		ret = عدم;
	}
	إذا (lenp != عدم)
		*lenp = ssh_digest_بایټونه(dgst_alg);
	r = 0;
 بهر:
	حرر(ret);
	إذا (blob != عدم)
		freezero(blob, blob_len);
	أرجع r;
}

ساكن حرف *
fingerprint_b64(ثابت حرف *alg, u_char *dgst_raw, اندازه_t dgst_raw_len)
{
	حرف *ret;
	اندازه_t plen = مزي_اوږدوالی(alg) + 1;
	اندازه_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	إذا (dgst_raw_len > 65536 || (ret = حافظه_صفر_ورکړه(1, rlen)) == عدم)
		أرجع عدم;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	إذا (dgst_raw_len == 0)
		أرجع ret;
	إذا (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		أرجع عدم;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	أرجع ret;
}

ساكن حرف *
fingerprint_hex(ثابت حرف *alg, u_char *dgst_raw, اندازه_t dgst_raw_len)
{
	حرف *retval, hex[5];
	اندازه_t i, rlen = dgst_raw_len * 3 + مزي_اوږدوالی(alg) + 2;

	إذا (dgst_raw_len > 65536 || (retval = حافظه_صفر_ورکړه(1, rlen)) == عدم)
		أرجع عدم;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	لكل (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, حجم(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	أرجع retval;
}

ساكن حرف *
fingerprint_bubblebabble(u_char *dgst_raw, اندازه_t dgst_raw_len)
{
	حرف vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	حرف consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, پړاوونه, تخم = 1;
	حرف *retval;

	پړاوونه = (dgst_raw_len / 2) + 1;
	إذا ((retval = حافظه_صفر_ورکړه(پړاوونه, 6)) == عدم)
		أرجع عدم;
	retval[j++] = 'x';
	لكل (i = 0; i < پړاوونه; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		إذا ((i + 1 < پړاوونه) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    تخم) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (تخم / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			إذا ((i + 1) < پړاوونه) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				تخم = ((تخم * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} وإلا {
			idx0 = تخم % 6;
			idx1 = 16;
			idx2 = تخم / 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
		}
	}
	retval[j++] = 'x';
	retval[j++] = '\0';
	أرجع retval;
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
#تعریف_کړه	FLDBASE		8
#تعریف_کړه	FLDSIZE_Y	(FLDBASE + 1)
#تعریف_کړه	FLDSIZE_X	(FLDBASE * 2 + 1)
ساكن حرف *
fingerprint_randomart(ثابت حرف *alg, u_char *dgst_raw, اندازه_t dgst_raw_len,
    ثابت بنية sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	حرف	*augmentation_string = " .o+=*BOX@%&#/^SE";
	حرف	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 ډګر[FLDSIZE_X][FLDSIZE_Y];
	اندازه_t	 i, tlen, hlen;
	u_int	 b;
	صحيح	 x, y, r;
	اندازه_t	 len = مزي_اوږدوالی(augmentation_string) - 1;

	إذا ((retval = حافظه_صفر_ورکړه((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == عدم)
		أرجع عدم;

	/* initialize field */
	memset(ډګر, 0, FLDSIZE_X * FLDSIZE_Y * حجم(حرف));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	لكل (i = 0; i < dgst_raw_len; i++) {
		صحيح ننوت;
		/* each byte conveys four 2-bit move commands */
		ننوت = dgst_raw[i];
		لكل (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (ننوت & 0x1) ? 1 : -1;
			y += (ننوت & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = اعظمي(x, 0);
			y = اعظمي(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			إذا (ډګر[x][y] < len - 2)
				ډګر[x][y]++;
			ننوت = ننوت >> 2;
		}
	}

	/* mark starting point and end point*/
	ډګر[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	ډګر[x][y] = len;

	/* assemble title */
	r = snprintf(title, حجم(title), "[%s %u]",
		sshkey_type(k), sshkey_اندازه(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	إذا (r < 0 || r > (صحيح)حجم(title))
		r = snprintf(title, حجم(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : مزي_اوږدوالی(title);

	/* assemble hash ID. */
	r = snprintf(hash, حجم(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : مزي_اوږدوالی(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	لكل (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	حافظه_نقل(p, title, tlen);
	p += tlen;
	لكل (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	لكل (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		لكل (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(ډګر[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	لكل (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	حافظه_نقل(p, hash, hlen);
	p += hlen;
	لكل (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	أرجع retval;
}

حرف *
sshkey_fingerprint(ثابت بنية sshkey *k, صحيح dgst_alg,
    تعداد sshkey_fp_rep dgst_rep)
{
	حرف *retval = عدم;
	u_char *dgst_raw;
	اندازه_t dgst_raw_len;

	إذا (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		أرجع عدم;
	بدل (dgst_rep) {
	حالة SSH_FP_DEFAULT:
		إذا (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} وإلا {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		اكسر;
	حالة SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		اكسر;
	حالة SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		اكسر;
	حالة SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		اكسر;
	حالة SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		اكسر;
	افتراضي:
		freezero(dgst_raw, dgst_raw_len);
		أرجع عدم;
	}
	freezero(dgst_raw, dgst_raw_len);
	أرجع retval;
}

ساكن صحيح
peek_type_nid(ثابت حرف *s, اندازه_t l, صحيح *nid)
{
	ثابت بنية sshkey_impl *impl;
	صحيح i;

	لكل (i = 0; keyimpls[i] != عدم; i++) {
		impl = keyimpls[i];
		إذا (impl->name == عدم || مزي_اوږدوالی(impl->name) != l)
			استمر;
		إذا (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			إذا (کلی_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			أرجع impl->type;
		}
	}
	أرجع کلی_UNSPEC;
}

/* XXX this can now be made const char * */
صحيح
sshkey_read(بنية sshkey *ret, حرف **cpp)
{
	بنية sshkey *k;
	حرف *cp, *blobcopy;
	اندازه_t space;
	صحيح r, type, منحني_nid = -1;
	بنية sshbuf *blob;

	إذا (ret == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا (ret->type != کلی_UNSPEC && sshkey_impl_from_type(ret->type) == عدم)
		أرجع SSH_ERR_INVALID_دلیل;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	إذا (space == مزي_اوږدوالی(cp))
		أرجع SSH_ERR_INVALID_FORMAT;
	إذا ((type = peek_type_nid(cp, space, &منحني_nid)) == کلی_UNSPEC)
		أرجع SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	لكل (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	إذا (*cp == '\0')
		أرجع SSH_ERR_INVALID_FORMAT;
	إذا (ret->type != کلی_UNSPEC && ret->type != type)
		أرجع SSH_ERR_کلی_TYPE_MISMATCH;
	إذا ((blob = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	إذا ((blobcopy = strndup(cp, space)) == عدم) {
		sshbuf_free(blob);
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	إذا ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		حرر(blobcopy);
		sshbuf_free(blob);
		أرجع r;
	}
	حرر(blobcopy);
	إذا ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		أرجع r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	لكل (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	إذا (k->type != type) {
		sshkey_free(k);
		أرجع SSH_ERR_کلی_TYPE_MISMATCH;
	}
	إذا (کلی_type_is_ecdsa_variant(type) && منحني_nid != k->ecdsa_nid) {
		sshkey_free(k);
		أرجع SSH_ERR_EC_منحني_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, حجم(*k));

	/* success */
	*cpp = cp;
	أرجع 0;
}

صحيح
sshkey_منزل_base64(ثابت بنية sshkey *کلی, حرف **b64p)
{
	صحيح r = SSH_ERR_دننی_ERROR;
	بنية sshbuf *b = عدم;
	حرف *uu = عدم;

	إذا (b64p != عدم)
		*b64p = عدم;
	إذا ((b = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshkey_putb(کلی, b)) != 0)
		اذهب بهر;
	إذا ((uu = sshbuf_dtob64_string(b, 0)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	/* Success */
	إذا (b64p != عدم) {
		*b64p = uu;
		uu = عدم;
	}
	r = 0;
 بهر:
	sshbuf_free(b);
	حرر(uu);
	أرجع r;
}

صحيح
sshkey_format_متن(ثابت بنية sshkey *کلی, بنية sshbuf *b)
{
	صحيح r = SSH_ERR_دننی_ERROR;
	حرف *uu = عدم;

	إذا ((r = sshkey_منزل_base64(کلی, &uu)) != 0)
		اذهب بهر;
	إذا ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(کلی), uu)) != 0)
		اذهب بهر;
	r = 0;
 بهر:
	حرر(uu);
	أرجع r;
}

صحيح
sshkey_write(ثابت بنية sshkey *کلی, FILE *f)
{
	بنية sshbuf *b = عدم;
	صحيح r = SSH_ERR_دننی_ERROR;

	إذا ((b = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshkey_format_متن(کلی, b)) != 0)
		اذهب بهر;
	إذا (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		إذا (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		اذهب بهر;
	}
	/* Success */
	r = 0;
 بهر:
	sshbuf_free(b);
	أرجع r;
}

ثابت حرف *
sshkey_cert_type(ثابت بنية sshkey *k)
{
	بدل (k->cert->type) {
	حالة SSH2_CERT_TYPE_USER:
		أرجع "user";
	حالة SSH2_CERT_TYPE_HOST:
		أرجع "host";
	افتراضي:
		أرجع "unknown";
	}
}

صحيح
sshkey_check_rsa_اوږدتیا(ثابت بنية sshkey *k, صحيح min_اندازه)
{
#که_تعریف_شوی WITH_OPENSSL
	صحيح nbits;

	إذا (k == عدم || k->pkey == عدم ||
	    (k->type != کلی_RSA && k->type != کلی_RSA_CERT))
		أرجع 0;
	nbits = EVP_PKEY_بټونه(k->pkey);
	إذا (nbits < SSH_RSA_MINIMUM_MODULUS_اندازه ||
	    (min_اندازه > 0 && nbits < min_اندازه))
		أرجع SSH_ERR_کلی_اوږدتیا;
#د_که_پای /* WITH_OPENSSL */
	أرجع 0;
}

#که_تعریف_شوی WITH_OPENSSL
صحيح
sshkey_ecdsa_کلی_منزل_nid(ثابت EC_کلی *k)
{
	ثابت EC_ډله *g;
	صحيح nid;

	إذا (k == عدم || (g = EC_کلی_get0_ډله(k)) == عدم)
		أرجع -1;
	إذا ((nid = EC_ډله_get_منحني_name(g)) <= 0)
		أرجع -1;
	أرجع nid;
}

صحيح
sshkey_ecdsa_pkey_منزل_nid(EVP_PKEY *pkey)
{
	أرجع sshkey_ecdsa_کلی_منزل_nid(EVP_PKEY_get0_EC_کلی(pkey));
}
#د_که_پای /* WITH_OPENSSL */

صحيح
sshkey_generate(صحيح type, u_int بټونه, بنية sshkey **keyp)
{
	بنية sshkey *k;
	صحيح ret = SSH_ERR_دننی_ERROR;
	ثابت بنية sshkey_impl *impl;

	إذا (keyp == عدم || sshkey_type_is_cert(type))
		أرجع SSH_ERR_INVALID_دلیل;
	*keyp = عدم;
	إذا ((impl = sshkey_impl_from_type(type)) == عدم)
		أرجع SSH_ERR_کلی_TYPE_UNKNOWN;
	إذا (impl->funcs->generate == عدم)
		أرجع SSH_ERR_FEATURE_UNSUPPORTED;
	إذا ((k = sshkey_new(کلی_UNSPEC)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	k->type = type;
	إذا ((ret = impl->funcs->generate(k, بټونه)) != 0) {
		sshkey_free(k);
		أرجع ret;
	}
	/* success */
	*keyp = k;
	أرجع 0;
}

صحيح
sshkey_cert_copy(ثابت بنية sshkey *from_کلی, بنية sshkey *منزل_کلی)
{
	u_int i;
	ثابت بنية sshkey_cert *from;
	بنية sshkey_cert *منزل;
	صحيح r = SSH_ERR_دننی_ERROR;

	إذا (منزل_کلی == عدم || (from = from_کلی->cert) == عدم)
		أرجع SSH_ERR_INVALID_دلیل;

	إذا ((منزل = cert_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	إذا ((r = sshbuf_putb(منزل->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(منزل->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(منزل->extensions, from->extensions)) != 0)
		اذهب بهر;

	منزل->serial = from->serial;
	منزل->type = from->type;
	إذا (from->کلی_id == عدم)
		منزل->کلی_id = عدم;
	وإلا إذا ((منزل->کلی_id = strdup(from->کلی_id)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	منزل->valid_after = from->valid_after;
	منزل->valid_before = from->valid_before;
	إذا (from->signature_کلی == عدم)
		منزل->signature_کلی = عدم;
	وإلا إذا ((r = sshkey_from_شخصي(from->signature_کلی,
	    &منزل->signature_کلی)) != 0)
		اذهب بهر;
	إذا (from->signature_type != عدم &&
	    (منزل->signature_type = strdup(from->signature_type)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_دلیل;
		اذهب بهر;
	}
	إذا (from->nprincipals > 0) {
		إذا ((منزل->principals = حافظه_صفر_ورکړه(from->nprincipals,
		    حجم(*منزل->principals))) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بهر;
		}
		لكل (i = 0; i < from->nprincipals; i++) {
			منزل->principals[i] = strdup(from->principals[i]);
			إذا (منزل->principals[i] == عدم) {
				منزل->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				اذهب بهر;
			}
		}
	}
	منزل->nprincipals = from->nprincipals;

	/* success */
	cert_free(منزل_کلی->cert);
	منزل_کلی->cert = منزل;
	منزل = عدم;
	r = 0;
 بهر:
	cert_free(منزل);
	أرجع r;
}

صحيح
sshkey_copy_عامه_sk(ثابت بنية sshkey *from, بنية sshkey *منزل)
{
	/* Append security-key application string */
	إذا ((منزل->sk_application = strdup(from->sk_application)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	أرجع 0;
}

صحيح
sshkey_from_شخصي(ثابت بنية sshkey *k, بنية sshkey **pkp)
{
	بنية sshkey *n = عدم;
	صحيح r = SSH_ERR_دننی_ERROR;
	ثابت بنية sshkey_impl *impl;

	*pkp = عدم;
	إذا ((impl = sshkey_impl_from_کلی(k)) == عدم)
		أرجع SSH_ERR_کلی_TYPE_UNKNOWN;
	إذا ((n = sshkey_new(k->type)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = impl->funcs->copy_عامه(k, n)) != 0)
		اذهب بهر;
	إذا (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		اذهب بهر;
	/* success */
	*pkp = n;
	n = عدم;
	r = 0;
 بهر:
	sshkey_free(n);
	أرجع r;
}

صحيح
sshkey_is_shielded(بنية sshkey *k)
{
	أرجع k != عدم && k->shielded_شخصي != عدم;
}

صحيح
sshkey_shield_شخصي(بنية sshkey *k)
{
	بنية sshbuf *prvbuf = عدم;
	u_char *prekey = عدم, *enc = عدم, keyiv[SSH_DIGEST_MAX_اوږدتیا];
	بنية sshcipher_ctx *cctx = عدم;
	ثابت بنية sshcipher *cipher;
	اندازه_t i, enclen = 0;
	بنية sshkey *kswap = عدم, tmp;
	صحيح r = SSH_ERR_دننی_ERROR;

#که_تعریف_شوی DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#د_که_پای
	إذا ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == عدم) {
		r = SSH_ERR_INVALID_دلیل;
		اذهب بهر;
	}
	إذا (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_بایټونه(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_دننی_ERROR;
		اذهب بهر;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	إذا ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		اذهب بهر;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	إذا ((r = ssh_digest_حافظه(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_اوږدتیا)) != 0)
		اذهب بهر;
#که_تعریف_شوی DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_معلومات(keyiv, ssh_digest_بایټونه(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#د_که_پای
	إذا ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		اذهب بهر;

	/* Serialise and encrypt the private key using the ephemeral key */
	إذا ((prvbuf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (sshkey_is_shielded(k) && (r = sshkey_unshield_شخصي(k)) != 0)
		اذهب بهر;
	إذا ((r = sshkey_شخصي_serialize(k, prvbuf)) != 0)
		اذهب بهر;
	/* pad to cipher blocksize */
	i = 0;
	طالما (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		إذا ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			اذهب بهر;
	}
#که_تعریف_شوی DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#د_که_پای
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	إذا ((enc = حافظه_ورکړه(enclen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		اذهب بهر;
#که_تعریف_شوی DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_معلومات(enc, enclen, stderr);
#د_که_پای

	/* Make a scrubbed, public-only copy of our private key argument */
	إذا ((r = sshkey_from_شخصي(k, &kswap)) != 0)
		اذهب بهر;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_شخصي = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = عدم; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 بهر:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, حجم(keyiv));
	explicit_bzero(&tmp, حجم(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	أرجع r;
}

/* Check deterministic padding after private key */
ساكن صحيح
private2_check_padding(بنية sshbuf *decrypted)
{
	u_char pad;
	اندازه_t i;
	صحيح r;

	i = 0;
	طالما (sshbuf_len(decrypted)) {
		إذا ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			اذهب بهر;
		إذا (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
	}
	/* success */
	r = 0;
 بهر:
	explicit_bzero(&pad, حجم(pad));
	explicit_bzero(&i, حجم(i));
	أرجع r;
}

صحيح
sshkey_unshield_شخصي(بنية sshkey *k)
{
	بنية sshbuf *prvbuf = عدم;
	u_char *cp, keyiv[SSH_DIGEST_MAX_اوږدتیا];
	بنية sshcipher_ctx *cctx = عدم;
	ثابت بنية sshcipher *cipher;
	بنية sshkey *kswap = عدم, tmp;
	صحيح r = SSH_ERR_دننی_ERROR;

#که_تعریف_شوی DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#د_که_پای
	إذا (!sshkey_is_shielded(k))
		أرجع 0; /* nothing to do */

	إذا ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == عدم) {
		r = SSH_ERR_INVALID_دلیل;
		اذهب بهر;
	}
	إذا (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_بایټونه(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_دننی_ERROR;
		اذهب بهر;
	}
	/* check size of shielded key blob */
	إذا (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}

	/* Calculate the ephemeral key from the prekey */
	إذا ((r = ssh_digest_حافظه(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_اوږدتیا)) != 0)
		اذهب بهر;
	إذا ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		اذهب بهر;
#که_تعریف_شوی DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_معلومات(keyiv, ssh_digest_بایټونه(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#د_که_پای

	/* Decrypt and parse the shielded private key using the ephemeral key */
	إذا ((prvbuf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		اذهب بهر;
	/* decrypt */
#که_تعریف_شوی DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_معلومات(k->shielded_شخصي, k->shielded_len, stderr);
#د_که_پای
	إذا ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_شخصي, k->shielded_len, 0, 0)) != 0)
		اذهب بهر;
#که_تعریف_شوی DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#د_که_پای
	/* Parse private key */
	إذا ((r = sshkey_شخصي_deserialize(prvbuf, &kswap)) != 0)
		اذهب بهر;

	إذا ((r = private2_check_padding(prvbuf)) != 0)
		اذهب بهر;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 بهر:
	cipher_free(cctx);
	explicit_bzero(keyiv, حجم(keyiv));
	explicit_bzero(&tmp, حجم(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	أرجع r;
}

ساكن صحيح
cert_parse(بنية sshbuf *b, بنية sshkey *کلی, بنية sshbuf *certbuf,
    ثابت حرف *ca_sigalg_allowlist)
{
	بنية sshbuf *principals = عدم, *crit = عدم;
	بنية sshbuf *exts = عدم, *ca = عدم;
	u_char *sig = عدم;
	حرف *sigtype = عدم;
	اندازه_t signed_len = 0, slen = 0, kidlen = 0;
	صحيح ret = SSH_ERR_دننی_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	إذا ((ret = sshbuf_putb(کلی->cert->certblob, certbuf)) != 0)
		أرجع ret;

	/* Parse body of certificate up to signature */
	إذا ((ret = sshbuf_get_u64(b, &کلی->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &کلی->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &کلی->cert->کلی_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &کلی->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &کلی->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_مستقیم(b, عدم, عدم)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(کلی->cert->certblob) - sshbuf_len(b);

	إذا ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}

	/* Is this a signature we're prepared to accept? */
	إذا ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	إذا (ca_sigalg_allowlist != عدم &&
	    سمون_نمونه_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		اذهب بهر;
	}

	/* Parse CA key and check whether we might accept it */
	إذا (sshkey_from_blob_دننی(ca, &کلی->cert->signature_کلی, 0,
	    ca_sigalg_allowlist, عدم) != 0) {
		ret = SSH_ERR_کلی_CERT_INVALID_SIGN_کلی;
		اذهب بهر;
	}
	إذا (!sshkey_type_is_valid_ca(کلی->cert->signature_کلی->type)) {
		ret = SSH_ERR_کلی_CERT_INVALID_SIGN_کلی;
		اذهب بهر;
	}

	إذا (کلی->cert->type != SSH2_CERT_TYPE_USER &&
	    کلی->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_کلی_CERT_UNKNOWN_TYPE;
		اذهب بهر;
	}

	/* Parse principals section */
	طالما (sshbuf_len(principals) > 0) {
		حرف *principal = عدم;
		حرف **oprincipals = عدم;

		إذا (کلی->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
		إذا ((ret = sshbuf_get_cstring(principals, &principal,
		    عدم)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
		oprincipals = کلی->cert->principals;
		کلی->cert->principals = recallocarray(کلی->cert->principals,
		    کلی->cert->nprincipals, کلی->cert->nprincipals + 1,
		    حجم(*کلی->cert->principals));
		إذا (کلی->cert->principals == عدم) {
			حرر(principal);
			کلی->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب بهر;
		}
		کلی->cert->principals[کلی->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	إذا ((ret = sshbuf_putb(کلی->cert->critical, crit)) != 0 ||
	    (exts != عدم &&
	    (ret = sshbuf_putb(کلی->cert->extensions, exts)) != 0))
		اذهب بهر;

	/*
	 * Validate critical options and extensions sections format.
	 */
	طالما (sshbuf_len(crit) != 0) {
		إذا ((ret = sshbuf_get_string_مستقیم(crit, عدم, عدم)) != 0 ||
		    (ret = sshbuf_get_string_مستقیم(crit, عدم, عدم)) != 0) {
			sshbuf_reset(کلی->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
	}
	طالما (exts != عدم && sshbuf_len(exts) != 0) {
		إذا ((ret = sshbuf_get_string_مستقیم(exts, عدم, عدم)) != 0 ||
		    (ret = sshbuf_get_string_مستقیم(exts, عدم, عدم)) != 0) {
			sshbuf_reset(کلی->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
	}

	/* Finally, validate signature */
	إذا ((ret = sshkey_verify(کلی->cert->signature_کلی, sig, slen,
	    sshbuf_ptr(کلی->cert->certblob), signed_len, عدم, 0, عدم)) != 0)
		اذهب بهر;

	/* Success */
	ret = 0;
	کلی->cert->signature_type = sigtype;
	sigtype = عدم;
 بهر:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	حرر(sig);
	حرر(sigtype);
	أرجع ret;
}

صحيح
sshkey_deserialize_sk(بنية sshbuf *b, بنية sshkey *کلی)
{
	/* Parse additional security-key application string */
	إذا (sshbuf_get_cstring(b, &کلی->sk_application, عدم) != 0)
		أرجع SSH_ERR_INVALID_FORMAT;
	أرجع 0;
}

ساكن صحيح
sshkey_from_blob_دننی(بنية sshbuf *b, بنية sshkey **keyp,
    صحيح allow_cert, ثابت حرف *alg_allowlist, ثابت حرف *ca_sigalg_allowlist)
{
	صحيح type, ret = SSH_ERR_دننی_ERROR;
	حرف *ktype = عدم;
	بنية sshkey *کلی = عدم;
	بنية sshbuf *copy;
	ثابت بنية sshkey_impl *impl;

#که_تعریف_شوی DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#د_که_پای
	إذا (keyp != عدم)
		*keyp = عدم;
	إذا ((copy = sshbuf_fromb(b)) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (sshbuf_get_cstring(b, &ktype, عدم) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}

	type = sshkey_type_from_name(ktype);
	إذا (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_کلی_CERT_INVALID_SIGN_کلی;
		اذهب بهر;
	}

	إذا (alg_allowlist != عدم &&
	    !sshkey_سمون_keyname_منزل_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_کلی_ALG_UNSUPPORTED;
		اذهب بهر;
	}

	إذا ((impl = sshkey_impl_from_type(type)) == عدم) {
		ret = SSH_ERR_کلی_TYPE_UNKNOWN;
		اذهب بهر;
	}
	إذا ((کلی = sshkey_new(type)) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		إذا (sshbuf_get_string_مستقیم(b, عدم, عدم) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
	}
	إذا ((ret = impl->funcs->deserialize_عامه(ktype, b, کلی)) != 0)
		اذهب بهر;

	/* Parse certificate potion */
	إذا (sshkey_is_cert(کلی) &&
	    (ret = cert_parse(b, کلی, copy, ca_sigalg_allowlist)) != 0)
		اذهب بهر;

	إذا (کلی != عدم && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	ret = 0;
	إذا (keyp != عدم) {
		*keyp = کلی;
		کلی = عدم;
	}
 بهر:
	sshbuf_free(copy);
	sshkey_free(کلی);
	حرر(ktype);
	أرجع ret;
}

صحيح
sshkey_from_blob(ثابت u_char *blob, اندازه_t blen, بنية sshkey **keyp)
{
	بنية sshbuf *b;
	صحيح r;

	إذا ((b = sshbuf_from(blob, blen)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_دننی(b, keyp, 1, عدم, عدم);
	sshbuf_free(b);
	أرجع r;
}

صحيح
sshkey_fromb(بنية sshbuf *b, بنية sshkey **keyp)
{
	أرجع sshkey_from_blob_دننی(b, keyp, 1, عدم, عدم);
}

صحيح
sshkey_fromb_allowlist(بنية sshbuf *b, بنية sshkey **keyp,
    ثابت حرف *alg_allowlist, ثابت حرف *ca_sigalg_allowlist)
{
	أرجع sshkey_from_blob_دننی(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

صحيح
sshkey_froms(بنية sshbuf *buf, بنية sshkey **keyp)
{
	بنية sshbuf *b;
	صحيح r;

	إذا ((r = sshbuf_froms(buf, &b)) != 0)
		أرجع r;
	r = sshkey_from_blob_دننی(b, keyp, 1, عدم, عدم);
	sshbuf_free(b);
	أرجع r;
}

صحيح
sshkey_get_sigtype(ثابت u_char *sig, اندازه_t siglen, حرف **sigtypep)
{
	صحيح r;
	بنية sshbuf *b = عدم;
	حرف *sigtype = عدم;

	إذا (sigtypep != عدم)
		*sigtypep = عدم;
	إذا ((b = sshbuf_from(sig, siglen)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_get_cstring(b, &sigtype, عدم)) != 0)
		اذهب بهر;
	/* success */
	إذا (sigtypep != عدم) {
		*sigtypep = sigtype;
		sigtype = عدم;
	}
	r = 0;
 بهر:
	حرر(sigtype);
	sshbuf_free(b);
	أرجع r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
صحيح
sshkey_check_cert_sigtype(ثابت بنية sshkey *کلی, ثابت حرف *allowed)
{
	إذا (کلی == عدم || allowed == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا (!sshkey_type_is_cert(کلی->type))
		أرجع 0;
	إذا (کلی->cert == عدم || کلی->cert->signature_type == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا (سمون_نمونه_list(کلی->cert->signature_type, allowed, 0) != 1)
		أرجع SSH_ERR_SIGN_ALG_UNSUPPORTED;
	أرجع 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
ثابت حرف *
sshkey_sigalg_by_name(ثابت حرف *name)
{
	ثابت بنية sshkey_impl *impl;
	صحيح i;

	لكل (i = 0; keyimpls[i] != عدم; i++) {
		impl = keyimpls[i];
		إذا (strcmp(impl->name, name) != 0)
			استمر;
		إذا (impl->sigalg != عدم)
			أرجع impl->sigalg;
		إذا (!impl->cert)
			أرجع impl->name;
		أرجع sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	أرجع عدم;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
صحيح
sshkey_check_sigtype(ثابت u_char *sig, اندازه_t siglen,
    ثابت حرف *requested_alg)
{
	ثابت حرف *expected_alg;
	حرف *sigtype = عدم;
	صحيح r;

	إذا (requested_alg == عدم)
		أرجع 0;
	إذا ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		أرجع r;
	r = strcmp(expected_alg, sigtype) == 0;
	حرر(sigtype);
	أرجع r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

صحيح
sshkey_sign(بنية sshkey *کلی,
    u_char **sigp, اندازه_t *lenp,
    ثابت u_char *معلومات, اندازه_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	صحيح was_shielded = sshkey_is_shielded(کلی);
	صحيح r2, r = SSH_ERR_دننی_ERROR;
	ثابت بنية sshkey_impl *impl;

	إذا (sigp != عدم)
		*sigp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	إذا (datalen > SSH_کلی_MAX_SIGN_معلومات_اندازه)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا ((impl = sshkey_impl_from_کلی(کلی)) == عدم)
		أرجع SSH_ERR_کلی_TYPE_UNKNOWN;
	إذا ((r = sshkey_unshield_شخصي(کلی)) != 0)
		أرجع r;
	إذا (sshkey_is_sk(کلی)) {
		r = sshsk_sign(sk_provider, کلی, sigp, lenp, معلومات,
		    datalen, compat, sk_pin);
	} وإلا إذا ((کلی->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(کلی, sigp, lenp, معلومات, datalen,
		    alg, sk_provider, sk_pin, compat);
	} وإلا {
		إذا (impl->funcs->sign == عدم)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		وإلا {
			r = impl->funcs->sign(کلی, sigp, lenp, معلومات, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	إذا (was_shielded && (r2 = sshkey_shield_شخصي(کلی)) != 0)
		أرجع r2;
	أرجع r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
صحيح
sshkey_verify(ثابت بنية sshkey *کلی,
    ثابت u_char *sig, اندازه_t siglen,
    ثابت u_char *معلومات, اندازه_t dlen, ثابت حرف *alg, u_int compat,
    بنية sshkey_sig_details **detailsp)
{
	ثابت بنية sshkey_impl *impl;

	إذا (detailsp != عدم)
		*detailsp = عدم;
	إذا (siglen == 0 || dlen > SSH_کلی_MAX_SIGN_معلومات_اندازه)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا ((impl = sshkey_impl_from_کلی(کلی)) == عدم)
		أرجع SSH_ERR_کلی_TYPE_UNKNOWN;
	أرجع impl->funcs->verify(کلی, sig, siglen, معلومات, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
صحيح
sshkey_منزل_certified(بنية sshkey *k)
{
	صحيح newtype;

	إذا ((newtype = sshkey_type_certified(k->type)) == -1)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا ((k->cert = cert_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	أرجع 0;
}

/* Convert a certificate to its raw key equivalent */
صحيح
sshkey_drop_cert(بنية sshkey *k)
{
	إذا (!sshkey_type_is_cert(k->type))
		أرجع SSH_ERR_کلی_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = عدم;
	k->type = sshkey_type_plain(k->type);
	أرجع 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
صحيح
sshkey_certify_custom(بنية sshkey *k, بنية sshkey *ca, ثابت حرف *alg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    sshkey_certify_signer *signer, فراغ *signer_ctx)
{
	ثابت بنية sshkey_impl *impl;
	بنية sshbuf *principals = عدم;
	u_char *ca_blob = عدم, *sig_blob = عدم, nonce[32];
	اندازه_t i, ca_len, sig_len;
	صحيح ret = SSH_ERR_دننی_ERROR;
	بنية sshbuf *cert = عدم;
	حرف *sigtype = عدم;

	إذا (k == عدم || k->cert == عدم ||
	    k->cert->certblob == عدم || ca == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا (!sshkey_is_cert(k))
		أرجع SSH_ERR_کلی_TYPE_UNKNOWN;
	إذا (!sshkey_type_is_valid_ca(ca->type))
		أرجع SSH_ERR_کلی_CERT_INVALID_SIGN_کلی;
	إذا ((impl = sshkey_impl_from_کلی(k)) == عدم)
		أرجع SSH_ERR_دننی_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	إذا (alg == عدم)
		alg = k->cert->signature_type;
	وإلا إذا (k->cert->signature_type != عدم &&
	    strcmp(alg, k->cert->signature_type) != 0)
		أرجع SSH_ERR_INVALID_دلیل;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	إذا (alg == عدم && ca->type == کلی_RSA)
		alg = "rsa-sha2-512";

	إذا ((ret = sshkey_منزل_blob(ca, &ca_blob, &ca_len)) != 0)
		أرجع SSH_ERR_کلی_CERT_INVALID_SIGN_کلی;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	إذا ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		اذهب بهر;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, حجم(nonce));
	إذا ((ret = sshbuf_put_string(cert, nonce, حجم(nonce))) != 0)
		اذهب بهر;

	/* Public key next */
	إذا ((ret = impl->funcs->serialize_عامه(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		اذهب بهر;

	/* Then remaining cert fields */
	إذا ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->کلی_id)) != 0)
		اذهب بهر;

	إذا ((principals = sshbuf_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	لكل (i = 0; i < k->cert->nprincipals; i++) {
		إذا ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			اذهب بهر;
	}
	إذا ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, عدم, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		اذهب بهر;

	/* Sign the whole mess */
	إذا ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		اذهب بهر;
	/* Check and update signature_type against what was actually used */
	إذا ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		اذهب بهر;
	إذا (alg != عدم && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		اذهب بهر;
	}
	إذا (k->cert->signature_type == عدم) {
		k->cert->signature_type = sigtype;
		sigtype = عدم;
	}
	/* Append signature and we are done */
	إذا ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		اذهب بهر;
	ret = 0;
 بهر:
	إذا (ret != 0)
		sshbuf_reset(cert);
	حرر(sig_blob);
	حرر(ca_blob);
	حرر(sigtype);
	sshbuf_free(principals);
	أرجع ret;
}

ساكن صحيح
default_کلی_sign(بنية sshkey *کلی, u_char **sigp, اندازه_t *lenp,
    ثابت u_char *معلومات, اندازه_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    u_int compat, فراغ *ctx)
{
	إذا (ctx != عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	أرجع sshkey_sign(کلی, sigp, lenp, معلومات, datalen, alg,
	    sk_provider, sk_pin, compat);
}

صحيح
sshkey_certify(بنية sshkey *k, بنية sshkey *ca, ثابت حرف *alg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin)
{
	أرجع sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_کلی_sign, عدم);
}

صحيح
sshkey_cert_check_authority(ثابت بنية sshkey *k,
    صحيح want_host, صحيح wildcard_نمونه, uint64_t verify_وخت,
    ثابت حرف *name, ثابت حرف **reason)
{
	u_int i, principal_matches;

	إذا (reason == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		أرجع SSH_ERR_کلی_CERT_INVALID;
	}
	إذا (want_host) {
		إذا (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			أرجع SSH_ERR_کلی_CERT_INVALID;
		}
	} وإلا {
		إذا (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			أرجع SSH_ERR_کلی_CERT_INVALID;
		}
	}
	إذا (verify_وخت < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		أرجع SSH_ERR_کلی_CERT_INVALID;
	}
	إذا (verify_وخت >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		أرجع SSH_ERR_کلی_CERT_INVALID;
	}
	إذا (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		أرجع SSH_ERR_کلی_CERT_INVALID;
	}
	إذا (name == عدم)
		أرجع 0; /* principal matching not requested */

	principal_matches = 0;
	لكل (i = 0; i < k->cert->nprincipals; i++) {
		إذا (wildcard_نمونه) {
			إذا (سمون_نمونه(name, k->cert->principals[i])) {
				principal_matches = 1;
				اكسر;
			}
		} وإلا إذا (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			اكسر;
		}
	}
	إذا (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		أرجع SSH_ERR_کلی_CERT_INVALID;
	}
	أرجع 0;
}

صحيح
sshkey_cert_check_authority_now(ثابت بنية sshkey *k,
    صحيح want_host, صحيح wildcard_نمونه, ثابت حرف *name,
    ثابت حرف **reason)
{
	time_t now;

	إذا ((now = time(عدم)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		أرجع SSH_ERR_کلی_CERT_INVALID;
	}
	أرجع sshkey_cert_check_authority(k, want_host, wildcard_نمونه,
	    (uint64_t)now, name, reason);
}

صحيح
sshkey_cert_check_host(ثابت بنية sshkey *کلی, ثابت حرف *host,
    ثابت حرف *ca_sign_algorithms, ثابت حرف **reason)
{
	صحيح r;

	إذا ((r = sshkey_cert_check_authority_now(کلی, 1, 1, host, reason)) != 0)
		أرجع r;
	إذا (sshbuf_len(کلی->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		أرجع SSH_ERR_کلی_CERT_INVALID;
	}
	إذا (ca_sign_algorithms != عدم &&
	    (r = sshkey_check_cert_sigtype(کلی, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		أرجع SSH_ERR_کلی_CERT_INVALID;
	}
	أرجع 0;
}

اندازه_t
sshkey_format_cert_validity(ثابت بنية sshkey_cert *cert, حرف *s, اندازه_t l)
{
	حرف from[32], منزل[32], ret[128];

	*from = *منزل = '\0';
	إذا (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		أرجع strlcpy(s, "forever", l);

	إذا (cert->valid_after != 0)
		format_absolute_وخت(cert->valid_after, from, حجم(from));
	إذا (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_وخت(cert->valid_before, منزل, حجم(منزل));

	إذا (cert->valid_after == 0)
		snprintf(ret, حجم(ret), "before %s", منزل);
	وإلا إذا (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, حجم(ret), "after %s", from);
	وإلا
		snprintf(ret, حجم(ret), "from %s to %s", from, منزل);

	أرجع strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
صحيح
sshkey_serialize_شخصي_sk(ثابت بنية sshkey *کلی, بنية sshbuf *b)
{
	صحيح r;

	إذا ((r = sshbuf_put_cstring(b, کلی->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, کلی->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, کلی->sk_کلی_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, کلی->sk_reserved)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
sshkey_شخصي_serialize_opt(بنية sshkey *کلی, بنية sshbuf *buf,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r = SSH_ERR_دننی_ERROR;
	صحيح was_shielded = sshkey_is_shielded(کلی);
	بنية sshbuf *b = عدم;
	ثابت بنية sshkey_impl *impl;

	إذا ((impl = sshkey_impl_from_کلی(کلی)) == عدم)
		أرجع SSH_ERR_دننی_ERROR;
	إذا ((r = sshkey_unshield_شخصي(کلی)) != 0)
		أرجع r;
	إذا ((b = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_cstring(b, sshkey_ssh_name(کلی))) != 0)
		اذهب بهر;
	إذا (sshkey_is_cert(کلی)) {
		إذا (کلی->cert == عدم ||
		    sshbuf_len(کلی->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_دلیل;
			اذهب بهر;
		}
		إذا ((r = sshbuf_put_stringb(b, کلی->cert->certblob)) != 0)
			اذهب بهر;
	}
	إذا ((r = impl->funcs->serialize_شخصي(کلی, b, opts)) != 0)
		اذهب بهر;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 بهر:
	إذا (was_shielded)
		r = sshkey_shield_شخصي(کلی);
	إذا (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	أرجع r;
}

صحيح
sshkey_شخصي_serialize(بنية sshkey *کلی, بنية sshbuf *b)
{
	أرجع sshkey_شخصي_serialize_opt(کلی, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
صحيح
sshkey_شخصي_deserialize_sk(بنية sshbuf *buf, بنية sshkey *k)
{
	صحيح r;

	إذا ((k->sk_کلی_handle = sshbuf_new()) == عدم ||
	    (k->sk_reserved = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_get_cstring(buf, &k->sk_application, عدم)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_کلی_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		أرجع r;

	أرجع 0;
}

صحيح
sshkey_شخصي_deserialize(بنية sshbuf *buf, بنية sshkey **kp)
{
	ثابت بنية sshkey_impl *impl;
	حرف *tname = عدم;
	حرف *expect_sk_application = عدم;
	u_char *expect_ed25519_pk = عدم;
	بنية sshkey *k = عدم;
	صحيح type, r = SSH_ERR_دننی_ERROR;

	إذا (kp != عدم)
		*kp = عدم;
	إذا ((r = sshbuf_get_cstring(buf, &tname, عدم)) != 0)
		اذهب بهر;
	type = sshkey_type_from_name(tname);
	إذا (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		إذا ((r = sshkey_froms(buf, &k)) != 0)
			اذهب بهر;
		إذا (k->type != type) {
			r = SSH_ERR_کلی_CERT_MISMATCH;
			اذهب بهر;
		}
		/* For ECDSA keys, the group must match too */
		إذا (k->type == کلی_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_کلی_CERT_MISMATCH;
			اذهب بهر;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = عدم;
		k->ed25519_pk = عدم;
	} وإلا {
		إذا ((k = sshkey_new(type)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بهر;
		}
	}
	إذا ((impl = sshkey_impl_from_type(type)) == عدم) {
		r = SSH_ERR_دننی_ERROR;
		اذهب بهر;
	}
	إذا ((r = impl->funcs->deserialize_شخصي(tname, buf, k)) != 0)
		اذهب بهر;

	إذا ((expect_sk_application != عدم && (k->sk_application == عدم ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != عدم && (k->ed25519_pk == عدم ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_کلی_CERT_MISMATCH;
		اذهب بهر;
	}
	/* success */
	r = 0;
	إذا (kp != عدم) {
		*kp = k;
		k = عدم;
	}
 بهر:
	حرر(tname);
	sshkey_free(k);
	حرر(expect_sk_application);
	حرر(expect_ed25519_pk);
	أرجع r;
}

#که_تعریف_شوی WITH_OPENSSL
صحيح
sshkey_ec_validate_عامه(ثابت EC_ډله *ډله, ثابت EC_ټکی *عام)
{
	EC_ټکی *nq = عدم;
	BIGNUM *ترتیب = عدم, *cofactor = عدم;
	صحيح ret = SSH_ERR_کلی_INVALID_EC_ارزښت;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	إذا (EC_ټکی_is_at_infinity(ډله, عام))
		اذهب بهر;

	إذا ((cofactor = BN_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (EC_ډله_get_cofactor(ډله, cofactor, عدم) != 1)
		اذهب بهر;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	إذا (!BN_is_one(cofactor)) {
		إذا ((ترتیب = BN_new()) == عدم) {
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب بهر;
		}
		إذا (EC_ډله_get_ترتیب(ډله, ترتیب, عدم) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب بهر;
		}
		إذا ((nq = EC_ټکی_new(ډله)) == عدم) {
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب بهر;
		}
		إذا (EC_ټکی_mul(ډله, nq, عدم, عام, ترتیب, عدم) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب بهر;
		}
		إذا (EC_ټکی_is_at_infinity(ډله, nq) != 1)
			اذهب بهر;
	}

	/* success */
	ret = 0;
 بهر:
	BN_clear_free(cofactor);
	BN_clear_free(ترتیب);
	EC_ټکی_free(nq);
	أرجع ret;
}

صحيح
sshkey_ec_validate_شخصي(ثابت EC_کلی *کلی)
{
	BIGNUM *ترتیب = عدم, *tmp = عدم;
	صحيح ret = SSH_ERR_کلی_INVALID_EC_ارزښت;

	إذا ((ترتیب = BN_new()) == عدم || (tmp = BN_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}

	/* log2(private) > log2(order)/2 */
	إذا (EC_ډله_get_ترتیب(EC_کلی_get0_ډله(کلی), ترتیب, عدم) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	إذا (BN_عدد_بټونه(EC_کلی_get0_شخصي_کلی(کلی)) <=
	    BN_عدد_بټونه(ترتیب) / 2)
		اذهب بهر;

	/* private < order - 1 */
	إذا (!BN_sub(tmp, ترتیب, BN_ارزښت_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	إذا (BN_cmp(EC_کلی_get0_شخصي_کلی(کلی), tmp) >= 0)
		اذهب بهر;
	ret = 0;
 بهر:
	BN_clear_free(ترتیب);
	BN_clear_free(tmp);
	أرجع ret;
}

فراغ
sshkey_dump_ec_ټکی(ثابت EC_ډله *ډله, ثابت EC_ټکی *ټکی)
{
	BIGNUM *x = عدم, *y = عدم;

	إذا (ټکی == عدم) {
		fputs("point=(NULL)\n", stderr);
		أرجع;
	}
	إذا ((x = BN_new()) == عدم || (y = BN_new()) == عدم) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		اذهب بهر;
	}
	إذا (EC_ټکی_get_affine_coordinates(ډله, ټکی, x, y, عدم) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		اذهب بهر;
	}
	fputs("x=", stderr);
	BN_print_fp(stderr, x);
	fputs("\ny=", stderr);
	BN_print_fp(stderr, y);
	fputs("\n", stderr);
 بهر:
	BN_clear_free(x);
	BN_clear_free(y);
}

فراغ
sshkey_dump_ec_کلی(ثابت EC_کلی *کلی)
{
	ثابت BIGNUM *exponent;

	sshkey_dump_ec_ټکی(EC_کلی_get0_ډله(کلی),
	    EC_کلی_get0_عامه_کلی(کلی));
	fputs("exponent=", stderr);
	إذا ((exponent = EC_کلی_get0_شخصي_کلی(کلی)) == عدم)
		fputs("(NULL)", stderr);
	وإلا
		BN_print_fp(stderr, EC_کلی_get0_شخصي_کلی(کلی));
	fputs("\n", stderr);
}
#د_که_پای /* WITH_OPENSSL */

ساكن صحيح
sshkey_شخصي_منزل_blob2(بنية sshkey *prv, بنية sshbuf *blob,
    ثابت حرف *passphrase, ثابت حرف *comment, ثابت حرف *ciphername,
    صحيح پړاوونه)
{
	u_char *cp, *کلی = عدم, *pubkeyblob = عدم;
	u_char salt[SALT_LEN];
	اندازه_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	صحيح r = SSH_ERR_دننی_ERROR;
	بنية sshcipher_ctx *ciphercontext = عدم;
	ثابت بنية sshcipher *cipher;
	ثابت حرف *kdfname = KDFNAME;
	بنية sshbuf *encoded = عدم, *encrypted = عدم, *kdf = عدم;

	إذا (پړاوونه <= 0)
		پړاوونه = DEFAULT_پړاوونه;
	إذا (پړاوونه > MAX_KDF_پړاوونه) {
		r = SSH_ERR_INVALID_دلیل;
		اذهب بهر;
	}
	إذا (passphrase == عدم || !مزي_اوږدوالی(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} وإلا إذا (ciphername == عدم)
		ciphername = DEFAULT_CIPHERNAME;
	إذا ((cipher = cipher_by_name(ciphername)) == عدم) {
		r = SSH_ERR_INVALID_دلیل;
		اذهب بهر;
	}

	إذا ((kdf = sshbuf_new()) == عدم ||
	    (encoded = sshbuf_new()) == عدم ||
	    (encrypted = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	إذا ((کلی = حافظه_صفر_ورکړه(1, keylen + ivlen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		إذا (bcrypt_pbkdf(passphrase, مزي_اوږدوالی(passphrase),
		    salt, SALT_LEN, کلی, keylen + ivlen, پړاوونه) < 0) {
			r = SSH_ERR_INVALID_دلیل;
			اذهب بهر;
		}
		إذا ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, پړاوونه)) != 0)
			اذهب بهر;
	} وإلا إذا (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_کلی_UNKNOWN_CIPHER;
		اذهب بهر;
	}
	إذا ((r = cipher_init(&ciphercontext, cipher, کلی, keylen,
	    کلی + keylen, ivlen, 1)) != 0)
		اذهب بهر;

	إذا ((r = sshbuf_put(encoded, AUTH_MAGIC, حجم(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_منزل_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		اذهب بهر;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	إذا ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		اذهب بهر;

	/* append private key and comment*/
	إذا ((r = sshkey_شخصي_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		اذهب بهر;

	/* padding */
	i = 0;
	طالما (sshbuf_len(encrypted) % blocksize) {
		إذا ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			اذهب بهر;
	}

	/* length in destination buffer */
	إذا ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		اذهب بهر;

	/* encrypt */
	إذا ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		اذهب بهر;
	إذا ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		اذهب بهر;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	إذا ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_پای_ټکی, MARK_پای_ټکی_LEN)) != 0)
		اذهب بهر;

	/* success */
	r = 0;

 بهر:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, حجم(salt));
	إذا (کلی != عدم)
		freezero(کلی, keylen + ivlen);
	إذا (pubkeyblob != عدم)
		freezero(pubkeyblob, pubkeylen);
	أرجع r;
}

ساكن صحيح
private2_uudecode(بنية sshbuf *blob, بنية sshbuf **decodedp)
{
	ثابت u_char *cp;
	اندازه_t encoded_len;
	صحيح r;
	u_char وروستی;
	بنية sshbuf *encoded = عدم, *decoded = عدم;

	إذا (blob == عدم || decodedp == عدم)
		أرجع SSH_ERR_INVALID_دلیل;

	*decodedp = عدم;

	إذا ((encoded = sshbuf_new()) == عدم ||
	    (decoded = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	إذا (encoded_len < (MARK_BEGIN_LEN + MARK_پای_ټکی_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	طالما (encoded_len > 0) {
		إذا (*cp != '\n' && *cp != '\r') {
			إذا ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				اذهب بهر;
		}
		وروستی = *cp;
		encoded_len--;
		cp++;
		إذا (وروستی == '\n') {
			إذا (encoded_len >= MARK_پای_ټکی_LEN &&
			    memcmp(cp, MARK_پای_ټکی, MARK_پای_ټکی_LEN) == 0) {
				/* \0 terminate */
				إذا ((r = sshbuf_put_u8(encoded, 0)) != 0)
					اذهب بهر;
				اكسر;
			}
		}
	}
	إذا (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}

	/* decode base64 */
	إذا ((r = sshbuf_b64tod(decoded, (حرف *)sshbuf_ptr(encoded))) != 0)
		اذهب بهر;

	/* check magic */
	إذا (sshbuf_len(decoded) < حجم(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, حجم(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	/* success */
	*decodedp = decoded;
	decoded = عدم;
	r = 0;
 بهر:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	أرجع r;
}

ساكن صحيح
private2_decrypt(بنية sshbuf *decoded, ثابت حرف *passphrase,
    بنية sshbuf **decryptedp, بنية sshkey **pubkeyp)
{
	حرف *ciphername = عدم, *kdfname = عدم;
	ثابت بنية sshcipher *cipher = عدم;
	صحيح r = SSH_ERR_دننی_ERROR;
	اندازه_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	بنية sshbuf *kdf = عدم, *decrypted = عدم;
	بنية sshcipher_ctx *ciphercontext = عدم;
	بنية sshkey *pubkey = عدم;
	u_char *کلی = عدم, *salt = عدم, *dp;
	u_int blocksize, پړاوونه, nkeys, encrypted_len, check1, check2;

	إذا (decoded == عدم || decryptedp == عدم || pubkeyp == عدم)
		أرجع SSH_ERR_INVALID_دلیل;

	*decryptedp = عدم;
	*pubkeyp = عدم;

	إذا ((decrypted = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}

	/* parse public portion of key */
	إذا ((r = sshbuf_consume(decoded, حجم(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, عدم)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		اذهب بهر;

	إذا (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}

	إذا ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		اذهب بهر;

	إذا ((cipher = cipher_by_name(ciphername)) == عدم) {
		r = SSH_ERR_کلی_UNKNOWN_CIPHER;
		اذهب بهر;
	}
	إذا (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_کلی_UNKNOWN_CIPHER;
		اذهب بهر;
	}
	إذا (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	إذا ((passphrase == عدم || مزي_اوږدوالی(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_کلی_WRONG_PASSPHRASE;
		اذهب بهر;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	إذا (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	إذا ((کلی = حافظه_صفر_ورکړه(1, keylen + ivlen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (strcmp(kdfname, "bcrypt") == 0) {
		إذا ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &پړاوونه)) != 0)
			اذهب بهر;
		إذا (پړاوونه > MAX_KDF_پړاوونه) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
		إذا (bcrypt_pbkdf(passphrase, مزي_اوږدوالی(passphrase), salt, slen,
		    کلی, keylen + ivlen, پړاوونه) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
	}

	/* check that an appropriate amount of auth data is present */
	إذا (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}

	/* decrypt private portion of key */
	إذا ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, کلی, keylen,
	    کلی + keylen, ivlen, 0)) != 0)
		اذهب بهر;
	إذا ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		إذا (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_کلی_WRONG_PASSPHRASE;
		اذهب بهر;
	}
	إذا ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		اذهب بهر;
	/* there should be no trailing data */
	إذا (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}

	/* check check bytes */
	إذا ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		اذهب بهر;
	إذا (check1 != check2) {
		r = SSH_ERR_کلی_WRONG_PASSPHRASE;
		اذهب بهر;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = عدم;
	*pubkeyp = pubkey;
	pubkey = عدم;
	r = 0;
 بهر:
	cipher_free(ciphercontext);
	حرر(ciphername);
	حرر(kdfname);
	sshkey_free(pubkey);
	إذا (salt != عدم) {
		explicit_bzero(salt, slen);
		حرر(salt);
	}
	إذا (کلی != عدم) {
		explicit_bzero(کلی, keylen + ivlen);
		حرر(کلی);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	أرجع r;
}

ساكن صحيح
sshkey_parse_private2(بنية sshbuf *blob, صحيح type, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	حرف *comment = عدم;
	صحيح r = SSH_ERR_دننی_ERROR;
	بنية sshbuf *decoded = عدم, *decrypted = عدم;
	بنية sshkey *k = عدم, *pubkey = عدم;

	إذا (keyp != عدم)
		*keyp = عدم;
	إذا (commentp != عدم)
		*commentp = عدم;

	/* Undo base64 encoding and decrypt the private section */
	إذا ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		اذهب بهر;

	إذا (type != کلی_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_کلی_TYPE_MISMATCH;
		اذهب بهر;
	}

	/* Load the private key and comment */
	إذا ((r = sshkey_شخصي_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, عدم)) != 0)
		اذهب بهر;

	/* Check deterministic padding after private section */
	إذا ((r = private2_check_padding(decrypted)) != 0)
		اذهب بهر;

	/* Check that the public key in the envelope matches the private key */
	إذا (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}

	/* success */
	r = 0;
	إذا (keyp != عدم) {
		*keyp = k;
		k = عدم;
	}
	إذا (commentp != عدم) {
		*commentp = comment;
		comment = عدم;
	}
 بهر:
	حرر(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	أرجع r;
}

ساكن صحيح
sshkey_parse_private2_pubkey(بنية sshbuf *blob, صحيح type,
    بنية sshkey **keyp)
{
	صحيح r = SSH_ERR_دننی_ERROR;
	بنية sshbuf *decoded = عدم;
	بنية sshkey *pubkey = عدم;
	u_int nkeys = 0;

	إذا (keyp != عدم)
		*keyp = عدم;

	إذا ((r = private2_uudecode(blob, &decoded)) != 0)
		اذهب بهر;
	/* parse public key from unencrypted envelope */
	إذا ((r = sshbuf_consume(decoded, حجم(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		اذهب بهر;

	إذا (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}

	/* Parse the public key */
	إذا ((r = sshkey_froms(decoded, &pubkey)) != 0)
		اذهب بهر;

	إذا (type != کلی_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_کلی_TYPE_MISMATCH;
		اذهب بهر;
	}

	/* success */
	r = 0;
	إذا (keyp != عدم) {
		*keyp = pubkey;
		pubkey = عدم;
	}
 بهر:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	أرجع r;
}

#که_تعریف_شوی WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
ساكن صحيح
sshkey_شخصي_منزل_blob_pem_pkcs8(بنية sshkey *کلی, بنية sshbuf *buf,
    صحيح format, ثابت حرف *_passphrase, ثابت حرف *comment)
{
	صحيح was_shielded = sshkey_is_shielded(کلی);
	صحيح success, r;
	صحيح blen, len = مزي_اوږدوالی(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : عدم;
	ثابت EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : عدم;
	حرف *bptr;
	BIO *bio = عدم;
	بنية sshbuf *blob;
	EVP_PKEY *pkey = عدم;

	إذا (len > 0 && len <= 4)
		أرجع SSH_ERR_PASSPHRASE_TOO_SHORT;
	إذا ((blob = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((bio = BIO_new(BIO_s_mem())) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = sshkey_unshield_شخصي(کلی)) != 0)
		اذهب بهر;

	بدل (کلی->type) {
	حالة کلی_ECDSA:
		إذا (format == SSHKEY_شخصي_PEM) {
			success = PEM_write_bio_ECPrivate_کلی(bio,
			    EVP_PKEY_get0_EC_کلی(کلی->pkey),
			    cipher, passphrase, len, عدم, عدم);
		} وإلا {
			pkey = کلی->pkey;
			EVP_PKEY_پورته_ref(کلی->pkey);
			success = 1;
		}
		اكسر;
	حالة کلی_RSA:
		إذا (format == SSHKEY_شخصي_PEM) {
			success = PEM_write_bio_RSAPrivate_کلی(bio,
			    EVP_PKEY_get0_RSA(کلی->pkey),
			    cipher, passphrase, len, عدم, عدم);
		} وإلا {
			pkey = کلی->pkey;
			EVP_PKEY_پورته_ref(کلی->pkey);
			success = 1;
		}
		اكسر;
#که_تعریف_شوی OPENSSL_HAS_ED25519
	حالة کلی_ED25519:
		إذا (format == SSHKEY_شخصي_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		} وإلا {
			pkey = EVP_PKEY_new_raw_شخصي_کلی(EVP_PKEY_ED25519,
			    عدم, کلی->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != عدم;
		}
		اكسر;
#د_که_پای
	افتراضي:
		success = 0;
		اكسر;
	}
	إذا (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	إذا (format == SSHKEY_شخصي_PKCS8) {
		إذا ((success = PEM_write_bio_شخصي_کلی(bio, pkey, cipher,
		    passphrase, len, عدم, عدم)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب بهر;
		}
	}
	إذا ((blen = BIO_get_mem_معلومات(bio, &bptr)) <= 0) {
		r = SSH_ERR_دننی_ERROR;
		اذهب بهر;
	}
	إذا ((r = sshbuf_put(blob, bptr, blen)) != 0)
		اذهب بهر;
	r = 0;
 بهر:
	إذا (was_shielded)
		r = sshkey_shield_شخصي(کلی);
	إذا (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	أرجع r;
}
#د_که_پای /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
صحيح
sshkey_شخصي_منزل_fileblob(بنية sshkey *کلی, بنية sshbuf *blob,
    ثابت حرف *passphrase, ثابت حرف *comment,
    صحيح format, ثابت حرف *openssh_format_cipher, صحيح openssh_format_پړاوونه)
{
	بدل (کلی->type) {
#که_تعریف_شوی WITH_OPENSSL
	حالة کلی_ECDSA:
	حالة کلی_RSA:
	حالة کلی_ED25519:
		اكسر; /* see below */
#وإلا /* WITH_OPENSSL */
	حالة کلی_ED25519:
#د_که_پای /* WITH_OPENSSL */
	حالة کلی_ED25519_SK:
#که_تعریف_شوی WITH_OPENSSL
	حالة کلی_ECDSA_SK:
#د_که_پای /* WITH_OPENSSL */
	حالة کلی_MLDSA44_ED25519:
		أرجع sshkey_شخصي_منزل_blob2(کلی, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_پړاوونه);
	افتراضي:
		أرجع SSH_ERR_کلی_TYPE_UNKNOWN;
	}

#که_تعریف_شوی WITH_OPENSSL
	بدل (format) {
	حالة SSHKEY_شخصي_OPENSSH:
		أرجع sshkey_شخصي_منزل_blob2(کلی, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_پړاوونه);
	حالة SSHKEY_شخصي_PEM:
	حالة SSHKEY_شخصي_PKCS8:
		أرجع sshkey_شخصي_منزل_blob_pem_pkcs8(کلی, blob,
		    format, passphrase, comment);
	افتراضي:
		أرجع SSH_ERR_INVALID_دلیل;
	}
#د_که_پای /* WITH_OPENSSL */
}

#که_تعریف_شوی WITH_OPENSSL
ساكن صحيح
translate_libcrypto_error(بینښه اوږد pem_err)
{
	صحيح pem_reason = ERR_GET_REASON(pem_err);

	بدل (ERR_GET_LIB(pem_err)) {
	حالة ERR_LIB_PEM:
		بدل (pem_reason) {
		حالة PEM_R_BAD_PASSWORD_READ:
#که_تعریف_شوی PEM_R_PROBLEMS_GETTING_PASSWORD
		حالة PEM_R_PROBLEMS_GETTING_PASSWORD:
#د_که_پای
#که_تعریف_شوی PEM_R_BAD_DECRYPT
		حالة PEM_R_BAD_DECRYPT:
#د_که_پای
			أرجع SSH_ERR_کلی_WRONG_PASSPHRASE;
		افتراضي:
			أرجع SSH_ERR_INVALID_FORMAT;
		}
	حالة ERR_LIB_EVP:
		بدل (pem_reason) {
#که_تعریف_شوی EVP_R_BAD_DECRYPT
		حالة EVP_R_BAD_DECRYPT:
			أرجع SSH_ERR_کلی_WRONG_PASSPHRASE;
#د_که_پای
#که_تعریف_شوی EVP_R_BN_DECODE_ERROR
		حالة EVP_R_BN_DECODE_ERROR:
#د_که_پای
		حالة EVP_R_DECODE_ERROR:
#که_تعریف_شوی EVP_R_شخصي_کلی_DECODE_ERROR
		حالة EVP_R_شخصي_کلی_DECODE_ERROR:
#د_که_پای
			أرجع SSH_ERR_INVALID_FORMAT;
		افتراضي:
			أرجع SSH_ERR_LIBCRYPTO_ERROR;
		}
	حالة ERR_LIB_ASN1:
#که_تعریف_شوی ERR_LIB_OSSL_DECODER
	حالة ERR_LIB_OSSL_DECODER:
#د_که_پای
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	أرجع SSH_ERR_LIBCRYPTO_ERROR;
}

ساكن فراغ
clear_libcrypto_errors(فراغ)
{
	طالما (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
ساكن صحيح
convert_libcrypto_error(فراغ)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	إذا (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_کلی_WRONG_PASSPHRASE)
		أرجع SSH_ERR_کلی_WRONG_PASSPHRASE;
	أرجع translate_libcrypto_error(ERR_peek_وروستی_error());
}

ساكن صحيح
pem_passphrase_cb(حرف *buf, صحيح اندازه, صحيح rwflag, فراغ *u)
{
	حرف *p = (حرف *)u;
	اندازه_t len;

	إذا (p == عدم || (len = مزي_اوږدوالی(p)) == 0)
		أرجع -1;
	إذا (اندازه < 0 || len > (اندازه_t)اندازه)
		أرجع -1;
	حافظه_نقل(buf, p, len);
	أرجع (صحيح)len;
}

ساكن صحيح
sshkey_parse_شخصي_pem_fileblob(بنية sshbuf *blob, صحيح type,
    ثابت حرف *passphrase, بنية sshkey **keyp)
{
	EVP_PKEY *pk = عدم;
	بنية sshkey *prv = عدم;
	BIO *bio = عدم;
	صحيح r;
	RSA *rsa = عدم;
	EC_کلی *ecdsa = عدم;

	إذا (keyp != عدم)
		*keyp = عدم;

	إذا ((bio = BIO_new(BIO_s_mem())) == عدم || sshbuf_len(blob) > لوی_عدد)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (صحيح)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}

	clear_libcrypto_errors();
	إذا ((pk = PEM_read_bio_شخصي_کلی(bio, عدم, pem_passphrase_cb,
	    (حرف *)passphrase)) == عدم) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		إذا (passphrase != عدم && *passphrase != '\0')
			r = SSH_ERR_کلی_WRONG_PASSPHRASE;
		وإلا
			r = convert_libcrypto_error();
		اذهب بهر;
	}
	إذا (EVP_PKEY_بنسټ_id(pk) == EVP_PKEY_RSA &&
	    (type == کلی_UNSPEC || type == کلی_RSA)) {
		إذا ((prv = sshkey_new(کلی_UNSPEC)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بهر;
		}
		إذا ((rsa = EVP_PKEY_get1_RSA(pk)) == عدم) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب بهر;
		}
		prv->type = کلی_RSA;
#که_تعریف_شوی DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#د_که_پای
		إذا (RSA_blinding_on(rsa, عدم) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب بهر;
		}
		EVP_PKEY_پورته_ref(pk);
		prv->pkey = pk;
		إذا ((r = sshkey_check_rsa_اوږدتیا(prv, 0)) != 0)
			اذهب بهر;
	} وإلا إذا (EVP_PKEY_بنسټ_id(pk) == EVP_PKEY_EC &&
	    (type == کلی_UNSPEC || type == کلی_ECDSA)) {
		إذا ((prv = sshkey_new(کلی_UNSPEC)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بهر;
		}
		إذا ((prv->ecdsa_nid = sshkey_ecdsa_fixup_ډله(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_کلی(pk)) == عدم) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب بهر;
		}
		prv->type = کلی_ECDSA;
		إذا (sshkey_منحني_nid_منزل_name(prv->ecdsa_nid) == عدم ||
		    sshkey_ec_validate_عامه(EC_کلی_get0_ډله(ecdsa),
		    EC_کلی_get0_عامه_کلی(ecdsa)) != 0 ||
		    sshkey_ec_validate_شخصي(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
		EVP_PKEY_پورته_ref(pk);
		prv->pkey = pk;
#که_تعریف_شوی DEBUG_PK
		إذا (prv != عدم && prv->pkey != عدم)
			sshkey_dump_ec_کلی(EVP_PKEY_get0_EC_کلی(prv->pkey));
#د_که_پای
#که_تعریف_شوی OPENSSL_HAS_ED25519
	} وإلا إذا (EVP_PKEY_بنسټ_id(pk) == EVP_PKEY_ED25519 &&
	    (type == کلی_UNSPEC || type == کلی_ED25519)) {
		اندازه_t len;

		إذا ((prv = sshkey_new(کلی_UNSPEC)) == عدم ||
		    (prv->ed25519_sk = حافظه_صفر_ورکړه(1, ED25519_SK_SZ)) == عدم ||
		    (prv->ed25519_pk = حافظه_صفر_ورکړه(1, ED25519_PK_SZ)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بهر;
		}
		prv->type = کلی_ED25519;
		len = ED25519_PK_SZ;
		إذا (!EVP_PKEY_get_raw_عامه_کلی(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب بهر;
		}
		إذا (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		إذا (!EVP_PKEY_get_raw_شخصي_کلی(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب بهر;
		}
		إذا (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
		/* Append the public key to our private key */
		حافظه_نقل(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#که_تعریف_شوی DEBUG_PK
		sshbuf_dump_معلومات(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#د_که_پای
#د_که_پای /* OPENSSL_HAS_ED25519 */
	} وإلا {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	r = 0;
	إذا (keyp != عدم) {
		*keyp = prv;
		prv = عدم;
	}
 بهر:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_کلی_free(ecdsa);
	sshkey_free(prv);
	أرجع r;
}
#د_که_پای /* WITH_OPENSSL */

صحيح
sshkey_parse_شخصي_fileblob_type(بنية sshbuf *blob, صحيح type,
    ثابت حرف *passphrase, بنية sshkey **keyp, حرف **commentp)
{
	صحيح r = SSH_ERR_دننی_ERROR;

	إذا (keyp != عدم)
		*keyp = عدم;
	إذا (commentp != عدم)
		*commentp = عدم;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	إذا (r != SSH_ERR_INVALID_FORMAT)
		أرجع r;
#که_تعریف_شوی WITH_OPENSSL
	أرجع sshkey_parse_شخصي_pem_fileblob(blob, type,
	    passphrase, keyp);
#وإلا
	أرجع SSH_ERR_INVALID_FORMAT;
#د_که_پای /* WITH_OPENSSL */
}

صحيح
sshkey_parse_شخصي_fileblob(بنية sshbuf *بفر, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp)
{
	إذا (keyp != عدم)
		*keyp = عدم;
	إذا (commentp != عدم)
		*commentp = عدم;

	أرجع sshkey_parse_شخصي_fileblob_type(بفر, کلی_UNSPEC,
	    passphrase, keyp, commentp);
}

فراغ
sshkey_sig_details_free(بنية sshkey_sig_details *details)
{
	freezero(details, حجم(*details));
}

صحيح
sshkey_parse_pubkey_from_شخصي_fileblob_type(بنية sshbuf *blob, صحيح type,
    بنية sshkey **pubkeyp)
{
	صحيح r = SSH_ERR_دننی_ERROR;

	إذا (pubkeyp != عدم)
		*pubkeyp = عدم;
	/* only new-format private keys bundle a public key inside */
	إذا ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		أرجع r;
	أرجع 0;
}
