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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/mman.h>
#شامل <netinet/in.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/evp.h>
#شامل <openssl/err.h>
#شامل <openssl/pem.h>
#اگر_ختم

#شامل "crypto_api.h"

#شامل <errno.h>
#شامل <limits.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <resolv.h>
#شامل <time.h>
#شامل <util.h>

#شامل "ssh2.h"
#شامل "ssherr.h"
#شامل "misc.h"
#شامل "sshbuf.h"
#شامل "cipher.h"
#شامل "digest.h"
#تعریف_کرو SSHKEY_اندرونی
#شامل "sshkey.h"
#شامل "match.h"
#شامل "ssh-sk.h"
#شامل "ssh-pkcs11.h"

#شامل "openbsd-compat/openssl-compat.h"

/* openssh private key file format */
#تعریف_کرو MARK_BEGIN		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
#تعریف_کرو MARK_انتہا		"-----END OPENSSH PRIVATE KEY-----\n"
#تعریف_کرو MARK_BEGIN_LEN		(حجم(MARK_BEGIN) - 1)
#تعریف_کرو MARK_انتہا_LEN		(حجم(MARK_انتہا) - 1)
#تعریف_کرو KDFNAME			"bcrypt"
#تعریف_کرو AUTH_MAGIC		"openssh-key-v1"
#تعریف_کرو SALT_LEN		16
#تعریف_کرو DEFAULT_CIPHERNAME	"aes256-ctr"
#تعریف_کرو	DEFAULT_دور		32
#تعریف_کرو	MAX_KDF_دور		(1<<20)

/*
 * Constants relating to "shielding" support; protection of keys expected
 * to remain in memory for long durations
 */
#تعریف_کرو SSHKEY_SHIELD_PREKEY_LEN	(16 * 1024)
#تعریف_کرو SSHKEY_SHIELD_CIPHER		"aes256-ctr" /* XXX want AES-EME* */
#تعریف_کرو SSHKEY_SHIELD_PREKEY_HASH	SSH_DIGEST_SHA512

ساکن صحیح sshkey_from_blob_اندرونی(ساخت sshbuf *buf,
    ساخت sshkey **keyp, صحیح allow_cert,
    ثابت حرف *alg_allowlist, ثابت حرف *ca_sigalg_allowlist);

/* Supported key types */
خارجی ثابت ساخت sshkey_impl sshkey_ed25519_impl;
خارجی ثابت ساخت sshkey_impl sshkey_ed25519_cert_impl;
خارجی ثابت ساخت sshkey_impl sshkey_ed25519_sk_impl;
خارجی ثابت ساخت sshkey_impl sshkey_ed25519_sk_cert_impl;
# ifdef USE_MLDSA
خارجی ثابت ساخت sshkey_impl sshkey_mldsa44_ed25519_impl;
خارجی ثابت ساخت sshkey_impl sshkey_mldsa44_ed25519_cert_impl;
# endif /* USE_MLDSA */
#اگر_تعریف_شدہ WITH_OPENSSL
# ifdef ENABLE_SK
خارجی ثابت ساخت sshkey_impl sshkey_ecdsa_sk_impl;
خارجی ثابت ساخت sshkey_impl sshkey_ecdsa_sk_cert_impl;
خارجی ثابت ساخت sshkey_impl sshkey_ecdsa_sk_webauthn_impl;
خارجی ثابت ساخت sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl;
# endif /* ENABLE_SK */
خارجی ثابت ساخت sshkey_impl sshkey_ecdsa_nistp256_impl;
خارجی ثابت ساخت sshkey_impl sshkey_ecdsa_nistp256_cert_impl;
خارجی ثابت ساخت sshkey_impl sshkey_ecdsa_nistp384_impl;
خارجی ثابت ساخت sshkey_impl sshkey_ecdsa_nistp384_cert_impl;
خارجی ثابت ساخت sshkey_impl sshkey_ecdsa_nistp521_impl;
خارجی ثابت ساخت sshkey_impl sshkey_ecdsa_nistp521_cert_impl;
خارجی ثابت ساخت sshkey_impl sshkey_rsa_impl;
خارجی ثابت ساخت sshkey_impl sshkey_rsa_cert_impl;
خارجی ثابت ساخت sshkey_impl sshkey_rsa_sha256_impl;
خارجی ثابت ساخت sshkey_impl sshkey_rsa_sha256_cert_impl;
خارجی ثابت ساخت sshkey_impl sshkey_rsa_sha512_impl;
خارجی ثابت ساخت sshkey_impl sshkey_rsa_sha512_cert_impl;
#اگر_ختم /* WITH_OPENSSL */

ثابت ساخت sshkey_impl * ثابت keyimpls[] = {
	&sshkey_ed25519_impl,
	&sshkey_ed25519_cert_impl,
#اگر_تعریف_شدہ ENABLE_SK
	&sshkey_ed25519_sk_impl,
	&sshkey_ed25519_sk_cert_impl,
#اگر_ختم
#اگر_تعریف_شدہ USE_MLDSA
	&sshkey_mldsa44_ed25519_impl,
	&sshkey_mldsa44_ed25519_cert_impl,
#اگر_ختم /* USE_MLDSA */
#اگر_تعریف_شدہ WITH_OPENSSL
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
#اگر_ختم /* WITH_OPENSSL */
	تہی
};

ساکن ثابت ساخت sshkey_impl *
sshkey_impl_from_type(صحیح type)
{
	صحیح i;

	برائے (i = 0; keyimpls[i] != تہی; i++) {
		اگر (keyimpls[i]->type == type)
			واپس keyimpls[i];
	}
	واپس تہی;
}

ساکن ثابت ساخت sshkey_impl *
sshkey_impl_from_type_nid(صحیح type, صحیح nid)
{
	صحیح i;

	برائے (i = 0; keyimpls[i] != تہی; i++) {
		اگر (keyimpls[i]->type == type &&
		    (keyimpls[i]->nid == 0 || keyimpls[i]->nid == nid))
			واپس keyimpls[i];
	}
	واپس تہی;
}

ساکن ثابت ساخت sshkey_impl *
sshkey_impl_from_کلید(ثابت ساخت sshkey *k)
{
	اگر (k == تہی)
		واپس تہی;
	واپس sshkey_impl_from_type_nid(k->type, k->ecdsa_nid);
}

ثابت حرف *
sshkey_type(ثابت ساخت sshkey *k)
{
	ثابت ساخت sshkey_impl *impl;

	اگر ((impl = sshkey_impl_from_کلید(k)) == تہی)
		واپس "unknown";
	واپس impl->shortname;
}

ساکن ثابت حرف *
sshkey_ssh_name_from_type_nid(صحیح type, صحیح nid)
{
	ثابت ساخت sshkey_impl *impl;

	اگر ((impl = sshkey_impl_from_type_nid(type, nid)) == تہی)
		واپس "ssh-unknown";
	واپس impl->name;
}

صحیح
sshkey_type_is_cert(صحیح type)
{
	ثابت ساخت sshkey_impl *impl;

	اگر ((impl = sshkey_impl_from_type(type)) == تہی)
		واپس 0;
	واپس impl->cert;
}

ثابت حرف *
sshkey_ssh_name(ثابت ساخت sshkey *k)
{
	واپس sshkey_ssh_name_from_type_nid(k->type, k->ecdsa_nid);
}

ثابت حرف *
sshkey_ssh_name_plain(ثابت ساخت sshkey *k)
{
	واپس sshkey_ssh_name_from_type_nid(sshkey_type_plain(k->type),
	    k->ecdsa_nid);
}

ساکن صحیح
type_from_name(ثابت حرف *name, صحیح allow_short)
{
	صحیح i;
	ثابت ساخت sshkey_impl *impl;

	برائے (i = 0; keyimpls[i] != تہی; i++) {
		impl = keyimpls[i];
		اگر (impl->name != تہی && strcmp(name, impl->name) == 0)
			واپس impl->type;
		/* Only allow shortname matches for plain key types */
		اگر (allow_short && !impl->cert && impl->shortname != تہی &&
		    strcasecmp(impl->shortname, name) == 0)
			واپس impl->type;
	}
	واپس کلید_UNSPEC;
}

صحیح
sshkey_type_from_name(ثابت حرف *name)
{
	واپس type_from_name(name, 0);
}

صحیح
sshkey_type_from_shortname(ثابت حرف *name)
{
	واپس type_from_name(name, 1);
}

ساکن صحیح
کلید_type_is_ecdsa_variant(صحیح type)
{
	انتخاب (type) {
	حالت کلید_ECDSA:
	حالت کلید_ECDSA_CERT:
	حالت کلید_ECDSA_SK:
	حالت کلید_ECDSA_SK_CERT:
		واپس 1;
	}
	واپس 0;
}

صحیح
sshkey_ecdsa_nid_from_name(ثابت حرف *name)
{
	صحیح i;

	برائے (i = 0; keyimpls[i] != تہی; i++) {
		اگر (!کلید_type_is_ecdsa_variant(keyimpls[i]->type))
			جاری;
		اگر (keyimpls[i]->name != تہی &&
		    strcmp(name, keyimpls[i]->name) == 0)
			واپس keyimpls[i]->nid;
	}
	واپس -1;
}

صحیح
sshkey_مطابقت_keyname_مقصد_sigalgs(ثابت حرف *keyname, ثابت حرف *sigalgs)
{
	صحیح ktype;

	اگر (sigalgs == تہی || *sigalgs == '\0' ||
	    (ktype = sshkey_type_from_name(keyname)) == کلید_UNSPEC)
		واپس 0;
	ورنہ اگر (ktype == کلید_RSA) {
		واپس مطابقت_نمونہ_list("ssh-rsa", sigalgs, 0) == 1 ||
		    مطابقت_نمونہ_list("rsa-sha2-256", sigalgs, 0) == 1 ||
		    مطابقت_نمونہ_list("rsa-sha2-512", sigalgs, 0) == 1;
	} ورنہ اگر (ktype == کلید_RSA_CERT) {
		واپس مطابقت_نمونہ_list("ssh-rsa-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    مطابقت_نمونہ_list("rsa-sha2-256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 ||
		    مطابقت_نمونہ_list("rsa-sha2-512-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} ورنہ اگر (ktype == کلید_ECDSA_SK) {
		واپس مطابقت_نمونہ_list("sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1 || مطابقت_نمونہ_list(
		    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		    sigalgs, 0) == 1;
	} ورنہ اگر (ktype == کلید_ECDSA_SK_CERT) {
		واپس مطابقت_نمونہ_list(
		    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1 || مطابقت_نمونہ_list(
		    "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		    sigalgs, 0) == 1;
	} ورنہ
		واپس مطابقت_نمونہ_list(keyname, sigalgs, 0) == 1;
}

حرف *
sshkey_alg_list(صحیح certs_only, صحیح plain_only, صحیح include_sigonly, حرف sep)
{
	حرف *ret = تہی;
	سائز_t i;
	ثابت ساخت sshkey_impl *impl;
	حرف sep_str[2] = {sep, '\0'};

	برائے (i = 0; keyimpls[i] != تہی; i++) {
		impl = keyimpls[i];
		اگر (impl->name == تہی)
			جاری;
		اگر (!include_sigonly && impl->sigonly)
			جاری;
		اگر ((certs_only && !impl->cert) || (plain_only && impl->cert))
			جاری;
		xextendf(&ret, sep_str, "%s", impl->name);
	}
	واپس ret;
}

صحیح
sshkey_نام_valid2(ثابت حرف *نام, صحیح allow_wildcard, صحیح plain_only)
{
	حرف *s, *cp, *p;
	ثابت ساخت sshkey_impl *impl;
	صحیح i, type;

	اگر (نام == تہی || strcmp(نام, "") == 0)
		واپس 0;
	اگر ((s = cp = strdup(نام)) == تہی)
		واپس 0;
	برائے ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		type = sshkey_type_from_name(p);
		اگر (type == کلید_UNSPEC) {
			اگر (allow_wildcard) {
				/*
				 * Try matching key types against the string.
				 * If any has a positive or negative match then
				 * the component is accepted.
				 */
				impl = تہی;
				برائے (i = 0; keyimpls[i] != تہی; i++) {
					اگر (مطابقت_نمونہ_list(
					    keyimpls[i]->name, p, 0) != 0) {
						impl = keyimpls[i];
						توڑو;
					}
				}
				اگر (impl != تہی)
					جاری;
			}
			آزاد(s);
			واپس 0;
		} ورنہ اگر (plain_only && sshkey_type_is_cert(type)) {
			آزاد(s);
			واپس 0;
		}
	}
	آزاد(s);
	واپس 1;
}

u_int
sshkey_سائز(ثابت ساخت sshkey *k)
{
	ثابت ساخت sshkey_impl *impl;

	اگر ((impl = sshkey_impl_from_کلید(k)) == تہی)
		واپس 0;
	اگر (impl->funcs->سائز != تہی)
		واپس impl->funcs->سائز(k);
	واپس impl->keybits;
}

ساکن صحیح
sshkey_type_is_valid_ca(صحیح type)
{
	ثابت ساخت sshkey_impl *impl;

	اگر ((impl = sshkey_impl_from_type(type)) == تہی)
		واپس 0;
	/* All non-certificate types may act as CAs */
	واپس !impl->cert;
}

صحیح
sshkey_is_cert(ثابت ساخت sshkey *k)
{
	اگر (k == تہی)
		واپس 0;
	واپس sshkey_type_is_cert(k->type);
}

صحیح
sshkey_is_sk(ثابت ساخت sshkey *k)
{
	اگر (k == تہی)
		واپس 0;
	انتخاب (sshkey_type_plain(k->type)) {
	حالت کلید_ECDSA_SK:
	حالت کلید_ED25519_SK:
		واپس 1;
	طےشدہ:
		واپس 0;
	}
}

/* Return the cert-less equivalent to a certified key type */
صحیح
sshkey_type_plain(صحیح type)
{
	انتخاب (type) {
	حالت کلید_RSA_CERT:
		واپس کلید_RSA;
	حالت کلید_ECDSA_CERT:
		واپس کلید_ECDSA;
	حالت کلید_ECDSA_SK_CERT:
		واپس کلید_ECDSA_SK;
	حالت کلید_ED25519_CERT:
		واپس کلید_ED25519;
	حالت کلید_MLDSA44_ED25519_CERT:
		واپس کلید_MLDSA44_ED25519;
	حالت کلید_ED25519_SK_CERT:
		واپس کلید_ED25519_SK;
	طےشدہ:
		واپس type;
	}
}

/* Return the cert equivalent to a plain key type */
ساکن صحیح
sshkey_type_certified(صحیح type)
{
	انتخاب (type) {
	حالت کلید_RSA:
		واپس کلید_RSA_CERT;
	حالت کلید_ECDSA:
		واپس کلید_ECDSA_CERT;
	حالت کلید_ECDSA_SK:
		واپس کلید_ECDSA_SK_CERT;
	حالت کلید_ED25519:
		واپس کلید_ED25519_CERT;
	حالت کلید_MLDSA44_ED25519:
		واپس کلید_MLDSA44_ED25519_CERT;
	حالت کلید_ED25519_SK:
		واپس کلید_ED25519_SK_CERT;
	طےشدہ:
		واپس -1;
	}
}

#اگر_تعریف_شدہ WITH_OPENSSL
ساکن ثابت EVP_MD *
ssh_digest_مقصد_md(صحیح hash_alg)
{
	انتخاب (hash_alg) {
	حالت SSH_DIGEST_SHA1:
		واپس EVP_sha1();
	حالت SSH_DIGEST_SHA256:
		واپس EVP_sha256();
	حالت SSH_DIGEST_SHA384:
		واپس EVP_sha384();
	حالت SSH_DIGEST_SHA512:
		واپس EVP_sha512();
	}
	واپس تہی;
}

صحیح
sshkey_pkey_digest_sign(EVP_PKEY *pkey, صحیح hash_alg, u_char **sigp,
    سائز_t *lenp, ثابت u_char *ڈیٹا, سائز_t datalen)
{
	EVP_MD_CTX *ctx = تہی;
	u_char *sig = تہی;
	صحیح ret;
	سائز_t slen;
	ثابت EVP_MD *evpmd;

	*sigp = تہی;
	*lenp = 0;

	slen = EVP_PKEY_سائز(pkey);
	اگر (slen <= 0 || slen > SSHBUF_MAX_BIGNUM ||
	   (evpmd = ssh_digest_مقصد_md(hash_alg)) == تہی)
		واپس SSH_ERR_INVALID_دلیل;

	اگر ((sig = حافظہ_دو(slen)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;

	اگر ((ctx = EVP_MD_CTX_new()) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (EVP_DigestSignInit(ctx, تہی, evpmd, تہی, pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, ڈیٹا, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}

	*sigp = sig;
	*lenp = slen;
	/* Now owned by the caller */
	sig = تہی;
	ret = 0;

 برآمد:
	EVP_MD_CTX_free(ctx);
	آزاد(sig);
	واپس ret;
}

صحیح
sshkey_pkey_digest_verify(EVP_PKEY *pkey, صحیح hash_alg, ثابت u_char *ڈیٹا,
    سائز_t datalen, u_char *sigbuf, سائز_t siglen)
{
	EVP_MD_CTX *ctx = تہی;
	صحیح ret = SSH_ERR_اندرونی_ERROR;
	ثابت EVP_MD *evpmd;

	اگر ((evpmd = ssh_digest_مقصد_md(hash_alg)) == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((ctx = EVP_MD_CTX_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر (EVP_DigestVerifyInit(ctx, تہی, evpmd, تہی, pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	انتخاب (EVP_DigestVerify(ctx, sigbuf, siglen, ڈیٹا, datalen)) {
	حالت 1:
		ret = 0;
		توڑو;
	حالت 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		توڑو;
	طےشدہ:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		توڑو;
	}

 برآمد:
	EVP_MD_CTX_free(ctx);
	واپس ret;
}

/* XXX: these are really begging for a table-driven approach */
صحیح
sshkey_خم_name_مقصد_nid(ثابت حرف *name)
{
	اگر (strcmp(name, "nistp256") == 0)
		واپس NID_X9_62_prime256v1;
	ورنہ اگر (strcmp(name, "nistp384") == 0)
		واپس NID_secp384r1;
	ورنہ اگر (strcmp(name, "nistp521") == 0)
		واپس NID_secp521r1;
	ورنہ
		واپس -1;
}

u_int
sshkey_خم_nid_مقصد_بٹ(صحیح nid)
{
	انتخاب (nid) {
	حالت NID_X9_62_prime256v1:
		واپس 256;
	حالت NID_secp384r1:
		واپس 384;
	حالت NID_secp521r1:
		واپس 521;
	طےشدہ:
		واپس 0;
	}
}

صحیح
sshkey_ecdsa_بٹ_مقصد_nid(صحیح بٹ)
{
	انتخاب (بٹ) {
	حالت 256:
		واپس NID_X9_62_prime256v1;
	حالت 384:
		واپس NID_secp384r1;
	حالت 521:
		واپس NID_secp521r1;
	طےشدہ:
		واپس -1;
	}
}

ثابت حرف *
sshkey_خم_nid_مقصد_name(صحیح nid)
{
	انتخاب (nid) {
	حالت NID_X9_62_prime256v1:
		واپس "nistp256";
	حالت NID_secp384r1:
		واپس "nistp384";
	حالت NID_secp521r1:
		واپس "nistp521";
	طےشدہ:
		واپس تہی;
	}
}

صحیح
sshkey_ec_nid_مقصد_hash_alg(صحیح nid)
{
	صحیح kbits = sshkey_خم_nid_مقصد_بٹ(nid);

	اگر (kbits <= 0)
		واپس -1;

	/* RFC5656 section 6.2.1 */
	اگر (kbits <= 256)
		واپس SSH_DIGEST_SHA256;
	ورنہ اگر (kbits <= 384)
		واپس SSH_DIGEST_SHA384;
	ورنہ
		واپس SSH_DIGEST_SHA512;
}
#اگر_ختم /* WITH_OPENSSL */

ساکن خالی
cert_free(ساخت sshkey_cert *cert)
{
	u_int i;

	اگر (cert == تہی)
		واپس;
	sshbuf_free(cert->certblob);
	sshbuf_free(cert->critical);
	sshbuf_free(cert->extensions);
	آزاد(cert->کلید_id);
	برائے (i = 0; i < cert->nprincipals; i++)
		آزاد(cert->principals[i]);
	آزاد(cert->principals);
	sshkey_free(cert->signature_کلید);
	آزاد(cert->signature_type);
	freezero(cert, حجم(*cert));
}

ساکن ساخت sshkey_cert *
cert_new(خالی)
{
	ساخت sshkey_cert *cert;

	اگر ((cert = صفر_حافظہ_دو(1, حجم(*cert))) == تہی)
		واپس تہی;
	اگر ((cert->certblob = sshbuf_new()) == تہی ||
	    (cert->critical = sshbuf_new()) == تہی ||
	    (cert->extensions = sshbuf_new()) == تہی) {
		cert_free(cert);
		واپس تہی;
	}
	cert->کلید_id = تہی;
	cert->principals = تہی;
	cert->signature_کلید = تہی;
	cert->signature_type = تہی;
	واپس cert;
}

ساخت sshkey *
sshkey_new(صحیح type)
{
	ساخت sshkey *k;
	ثابت ساخت sshkey_impl *impl = تہی;

	اگر (type != کلید_UNSPEC &&
	    (impl = sshkey_impl_from_type(type)) == تہی)
		واپس تہی;

	/* All non-certificate types may act as CAs */
	اگر ((k = صفر_حافظہ_دو(1, حجم(*k))) == تہی)
		واپس تہی;
	k->type = type;
	k->ecdsa_nid = -1;
	اگر (impl != تہی && impl->funcs->alloc != تہی) {
		اگر (impl->funcs->alloc(k) != 0) {
			آزاد(k);
			واپس تہی;
		}
	}
	اگر (sshkey_is_cert(k)) {
		اگر ((k->cert = cert_new()) == تہی) {
			sshkey_free(k);
			واپس تہی;
		}
	}

	واپس k;
}

/* Frees common FIDO fields */
خالی
sshkey_sk_cleanup(ساخت sshkey *k)
{
	آزاد(k->sk_application);
	sshbuf_free(k->sk_کلید_handle);
	sshbuf_free(k->sk_reserved);
	k->sk_application = تہی;
	k->sk_کلید_handle = k->sk_reserved = تہی;
}

#اگر defined(MAP_CONCEAL)
# define PREKEY_MMAP_FLAG	MAP_CONCEAL
#وگرنہ_اگر defined(MAP_NOCORE)
# define PREKEY_MMAP_FLAG	MAP_NOCORE
#ورنہ
# define PREKEY_MMAP_FLAG	0
#اگر_ختم

ساکن صحیح
sshkey_prekey_alloc(u_char **prekeyp, سائز_t len)
{
#اگر defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	u_char *prekey;

	*prekeyp = تہی;
	اگر ((prekey = mmap(تہی, len, PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE|PREKEY_MMAP_FLAG, -1, 0)) == MAP_FAILED)
		واپس SSH_ERR_SYSTEM_ERROR;
#اگر defined(MADV_DONTDUMP) && !defined(MAP_CONCEAL) && !defined(MAP_NOCORE)
	(خالی)madvise(prekey, len, MADV_DONTDUMP);
#اگر_ختم
	*prekeyp = prekey;
#ورنہ
	*prekeyp = صفر_حافظہ_دو(1, len);
#اگر_ختم /* HAVE_MMAP et al */
	واپس 0;
}

ساکن خالی
sshkey_prekey_free(خالی *prekey, سائز_t len)
{
#اگر defined(HAVE_MMAP) && defined(MAP_ANON) && defined(MAP_PRIVATE)
	اگر (prekey == تہی)
		واپس;
	munmap(prekey, len);
#ورنہ
	آزاد(prekey);
#اگر_ختم /* HAVE_MMAP et al */
}

ساکن خالی
sshkey_free_contents(ساخت sshkey *k)
{
	ثابت ساخت sshkey_impl *impl;

	اگر (k == تہی)
		واپس;
	اگر ((k->flags & SSHKEY_FLAG_EXT) != 0)
		pkcs11_کلید_free(k);
	اگر ((impl = sshkey_impl_from_type(k->type)) != تہی &&
	    impl->funcs->cleanup != تہی)
		impl->funcs->cleanup(k);
	اگر (sshkey_is_cert(k))
		cert_free(k->cert);
	freezero(k->shielded_نجی, k->shielded_len);
	sshkey_prekey_free(k->shield_prekey, k->shield_prekey_len);
}

خالی
sshkey_free(ساخت sshkey *k)
{
	sshkey_free_contents(k);
	freezero(k, حجم(*k));
}

ساکن صحیح
cert_compare(ساخت sshkey_cert *a, ساخت sshkey_cert *b)
{
	اگر (a == تہی && b == تہی)
		واپس 1;
	اگر (a == تہی || b == تہی)
		واپس 0;
	اگر (sshbuf_len(a->certblob) != sshbuf_len(b->certblob))
		واپس 0;
	اگر (timingsafe_bcmp(sshbuf_ptr(a->certblob), sshbuf_ptr(b->certblob),
	    sshbuf_len(a->certblob)) != 0)
		واپس 0;
	واپس 1;
}

/* Compares FIDO-specific pubkey fields only */
صحیح
sshkey_sk_fields_equal(ثابت ساخت sshkey *a, ثابت ساخت sshkey *b)
{
	اگر (a->sk_application == تہی || b->sk_application == تہی)
		واپس 0;
	اگر (strcmp(a->sk_application, b->sk_application) != 0)
		واپس 0;
	واپس 1;
}

/*
 * Compare public portions of key only, allowing comparisons between
 * certificates and plain keys too.
 */
صحیح
sshkey_equal_عوامی(ثابت ساخت sshkey *a, ثابت ساخت sshkey *b)
{
	ثابت ساخت sshkey_impl *impl;

	اگر (a == تہی || b == تہی ||
	    sshkey_type_plain(a->type) != sshkey_type_plain(b->type))
		واپس 0;
	اگر ((impl = sshkey_impl_from_type(a->type)) == تہی)
		واپس 0;
	واپس impl->funcs->equal(a, b);
}

صحیح
sshkey_equal(ثابت ساخت sshkey *a, ثابت ساخت sshkey *b)
{
	اگر (a == تہی || b == تہی || a->type != b->type)
		واپس 0;
	اگر (sshkey_is_cert(a)) {
		اگر (!cert_compare(a->cert, b->cert))
			واپس 0;
	}
	واپس sshkey_equal_عوامی(a, b);
}


/* Serialise common FIDO key parts */
صحیح
sshkey_serialize_sk(ثابت ساخت sshkey *کلید, ساخت sshbuf *b)
{
	صحیح r;

	اگر ((r = sshbuf_put_cstring(b, کلید->sk_application)) != 0)
		واپس r;

	واپس 0;
}

ساکن صحیح
مقصد_blob_buf(ثابت ساخت sshkey *کلید, ساخت sshbuf *b, صحیح force_plain,
  شمار sshkey_serialize_rep opts)
{
	صحیح type, ret = SSH_ERR_اندرونی_ERROR;
	ثابت حرف *typename;
	ثابت ساخت sshkey_impl *impl;

	اگر (کلید == تہی)
		واپس SSH_ERR_INVALID_دلیل;

	type = force_plain ? sshkey_type_plain(کلید->type) : کلید->type;

	اگر (sshkey_type_is_cert(type)) {
		اگر (کلید->cert == تہی)
			واپس SSH_ERR_EXPECTED_CERT;
		اگر (sshbuf_len(کلید->cert->certblob) == 0)
			واپس SSH_ERR_کلید_LACKS_CERTBLOB;
		/* Use the existing blob */
		اگر ((ret = sshbuf_putb(b, کلید->cert->certblob)) != 0)
			واپس ret;
		واپس 0;
	}
	اگر ((impl = sshkey_impl_from_type(type)) == تہی)
		واپس SSH_ERR_کلید_TYPE_UNKNOWN;

	typename = sshkey_ssh_name_from_type_nid(type, کلید->ecdsa_nid);
	اگر ((ret = sshbuf_put_cstring(b, typename)) != 0)
		واپس ret;
	واپس impl->funcs->serialize_عوامی(کلید, b, opts);
}

صحیح
sshkey_putb(ثابت ساخت sshkey *کلید, ساخت sshbuf *b)
{
	واپس مقصد_blob_buf(کلید, b, 0, SSHKEY_SERIALIZE_DEFAULT);
}

ساکن صحیح
sshkey_puts_opts_اندرونی(ثابت ساخت sshkey *کلید, ساخت sshbuf *b,
    شمار sshkey_serialize_rep opts, صحیح force_plain)
{
	ساخت sshbuf *tmp;
	صحیح r;

	اگر ((tmp = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	r = مقصد_blob_buf(کلید, tmp, force_plain, opts);
	اگر (r == 0)
		r = sshbuf_put_stringb(b, tmp);
	sshbuf_free(tmp);
	واپس r;
}

صحیح
sshkey_puts(ثابت ساخت sshkey *کلید, ساخت sshbuf *b)
{
	واپس sshkey_puts_opts_اندرونی(کلید, b, SSHKEY_SERIALIZE_DEFAULT, 0);
}

صحیح
sshkey_putb_plain(ثابت ساخت sshkey *کلید, ساخت sshbuf *b)
{
	واپس مقصد_blob_buf(کلید, b, 1, SSHKEY_SERIALIZE_DEFAULT);
}

صحیح
sshkey_puts_plain(ثابت ساخت sshkey *کلید, ساخت sshbuf *b)
{
	واپس sshkey_puts_opts_اندرونی(کلید, b, SSHKEY_SERIALIZE_DEFAULT, 1);
}

ساکن صحیح
مقصد_blob(ثابت ساخت sshkey *کلید, u_char **blobp, سائز_t *lenp, صحیح force_plain,
    شمار sshkey_serialize_rep opts)
{
	صحیح ret = SSH_ERR_اندرونی_ERROR;
	سائز_t len;
	ساخت sshbuf *b = تہی;

	اگر (lenp != تہی)
		*lenp = 0;
	اگر (blobp != تہی)
		*blobp = تہی;
	اگر ((b = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((ret = مقصد_blob_buf(کلید, b, force_plain, opts)) != 0)
		جاؤ برآمد;
	len = sshbuf_len(b);
	اگر (lenp != تہی)
		*lenp = len;
	اگر (blobp != تہی) {
		اگر ((*blobp = حافظہ_دو(len)) == تہی) {
			ret = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		حافظہ_نقل(*blobp, sshbuf_ptr(b), len);
	}
	ret = 0;
 برآمد:
	sshbuf_free(b);
	واپس ret;
}

صحیح
sshkey_مقصد_blob(ثابت ساخت sshkey *کلید, u_char **blobp, سائز_t *lenp)
{
	واپس مقصد_blob(کلید, blobp, lenp, 0, SSHKEY_SERIALIZE_DEFAULT);
}

صحیح
sshkey_plain_مقصد_blob(ثابت ساخت sshkey *کلید, u_char **blobp, سائز_t *lenp)
{
	واپس مقصد_blob(کلید, blobp, lenp, 1, SSHKEY_SERIALIZE_DEFAULT);
}

صحیح
sshkey_fingerprint_raw(ثابت ساخت sshkey *k, صحیح dgst_alg,
    u_char **retp, سائز_t *lenp)
{
	u_char *blob = تہی, *ret = تہی;
	سائز_t blob_len = 0;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	اگر (retp != تہی)
		*retp = تہی;
	اگر (lenp != تہی)
		*lenp = 0;
	اگر (ssh_digest_بائٹیں(dgst_alg) == 0) {
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	اگر ((r = مقصد_blob(k, &blob, &blob_len, 1, SSHKEY_SERIALIZE_DEFAULT))
	    != 0)
		جاؤ برآمد;
	اگر ((ret = صفر_حافظہ_دو(1, SSH_DIGEST_MAX_لمبائی)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = ssh_digest_حافظہ(dgst_alg, blob, blob_len,
	    ret, SSH_DIGEST_MAX_لمبائی)) != 0)
		جاؤ برآمد;
	/* success */
	اگر (retp != تہی) {
		*retp = ret;
		ret = تہی;
	}
	اگر (lenp != تہی)
		*lenp = ssh_digest_بائٹیں(dgst_alg);
	r = 0;
 برآمد:
	آزاد(ret);
	اگر (blob != تہی)
		freezero(blob, blob_len);
	واپس r;
}

ساکن حرف *
fingerprint_b64(ثابت حرف *alg, u_char *dgst_raw, سائز_t dgst_raw_len)
{
	حرف *ret;
	سائز_t plen = لڑی_لمبائی(alg) + 1;
	سائز_t rlen = ((dgst_raw_len + 2) / 3) * 4 + plen + 1;

	اگر (dgst_raw_len > 65536 || (ret = صفر_حافظہ_دو(1, rlen)) == تہی)
		واپس تہی;
	strlcpy(ret, alg, rlen);
	strlcat(ret, ":", rlen);
	اگر (dgst_raw_len == 0)
		واپس ret;
	اگر (b64_ntop(dgst_raw, dgst_raw_len, ret + plen, rlen - plen) == -1) {
		freezero(ret, rlen);
		واپس تہی;
	}
	/* Trim padding characters from end */
	ret[strcspn(ret, "=")] = '\0';
	واپس ret;
}

ساکن حرف *
fingerprint_hex(ثابت حرف *alg, u_char *dgst_raw, سائز_t dgst_raw_len)
{
	حرف *retval, hex[5];
	سائز_t i, rlen = dgst_raw_len * 3 + لڑی_لمبائی(alg) + 2;

	اگر (dgst_raw_len > 65536 || (retval = صفر_حافظہ_دو(1, rlen)) == تہی)
		واپس تہی;
	strlcpy(retval, alg, rlen);
	strlcat(retval, ":", rlen);
	برائے (i = 0; i < dgst_raw_len; i++) {
		snprintf(hex, حجم(hex), "%s%02x",
		    i > 0 ? ":" : "", dgst_raw[i]);
		strlcat(retval, hex, rlen);
	}
	واپس retval;
}

ساکن حرف *
fingerprint_bubblebabble(u_char *dgst_raw, سائز_t dgst_raw_len)
{
	حرف vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	حرف consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	u_int i, j = 0, دور, بیج = 1;
	حرف *retval;

	دور = (dgst_raw_len / 2) + 1;
	اگر ((retval = صفر_حافظہ_دو(دور, 6)) == تہی)
		واپس تہی;
	retval[j++] = 'x';
	برائے (i = 0; i < دور; i++) {
		u_int idx0, idx1, idx2, idx3, idx4;
		اگر ((i + 1 < دور) || (dgst_raw_len % 2 != 0)) {
			idx0 = (((((u_int)(dgst_raw[2 * i])) >> 6) & 3) +
			    بیج) % 6;
			idx1 = (((u_int)(dgst_raw[2 * i])) >> 2) & 15;
			idx2 = ((((u_int)(dgst_raw[2 * i])) & 3) +
			    (بیج / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			اگر ((i + 1) < دور) {
				idx3 = (((u_int)(dgst_raw[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((u_int)(dgst_raw[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				بیج = ((بیج * 5) +
				    ((((u_int)(dgst_raw[2 * i])) * 7) +
				    ((u_int)(dgst_raw[(2 * i) + 1])))) % 36;
			}
		} ورنہ {
			idx0 = بیج % 6;
			idx1 = 16;
			idx2 = بیج / 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
		}
	}
	retval[j++] = 'x';
	retval[j++] = '\0';
	واپس retval;
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
#تعریف_کرو	FLDBASE		8
#تعریف_کرو	FLDSIZE_Y	(FLDBASE + 1)
#تعریف_کرو	FLDSIZE_X	(FLDBASE * 2 + 1)
ساکن حرف *
fingerprint_randomart(ثابت حرف *alg, u_char *dgst_raw, سائز_t dgst_raw_len,
    ثابت ساخت sshkey *k)
{
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	حرف	*augmentation_string = " .o+=*BOX@%&#/^SE";
	حرف	*retval, *p, title[FLDSIZE_X], hash[FLDSIZE_X];
	u_char	 میدان[FLDSIZE_X][FLDSIZE_Y];
	سائز_t	 i, tlen, hlen;
	u_int	 b;
	صحیح	 x, y, r;
	سائز_t	 len = لڑی_لمبائی(augmentation_string) - 1;

	اگر ((retval = صفر_حافظہ_دو((FLDSIZE_X + 3), (FLDSIZE_Y + 2))) == تہی)
		واپس تہی;

	/* initialize field */
	memset(میدان, 0, FLDSIZE_X * FLDSIZE_Y * حجم(حرف));
	x = FLDSIZE_X / 2;
	y = FLDSIZE_Y / 2;

	/* process raw key */
	برائے (i = 0; i < dgst_raw_len; i++) {
		صحیح داخلہ;
		/* each byte conveys four 2-bit move commands */
		داخلہ = dgst_raw[i];
		برائے (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (داخلہ & 0x1) ? 1 : -1;
			y += (داخلہ & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = زیادہ_سے_زیادہ(x, 0);
			y = زیادہ_سے_زیادہ(y, 0);
			x = MINIMUM(x, FLDSIZE_X - 1);
			y = MINIMUM(y, FLDSIZE_Y - 1);

			/* augment the field */
			اگر (میدان[x][y] < len - 2)
				میدان[x][y]++;
			داخلہ = داخلہ >> 2;
		}
	}

	/* mark starting point and end point*/
	میدان[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	میدان[x][y] = len;

	/* assemble title */
	r = snprintf(title, حجم(title), "[%s %u]",
		sshkey_type(k), sshkey_سائز(k));
	/* If [type size] won't fit, then try [type]; fits "[ED25519-CERT]" */
	اگر (r < 0 || r > (صحیح)حجم(title))
		r = snprintf(title, حجم(title), "[%s]", sshkey_type(k));
	tlen = (r <= 0) ? 0 : لڑی_لمبائی(title);

	/* assemble hash ID. */
	r = snprintf(hash, حجم(hash), "[%s]", alg);
	hlen = (r <= 0) ? 0 : لڑی_لمبائی(hash);

	/* output upper border */
	p = retval;
	*p++ = '+';
	برائے (i = 0; i < (FLDSIZE_X - tlen) / 2; i++)
		*p++ = '-';
	حافظہ_نقل(p, title, tlen);
	p += tlen;
	برائے (i += tlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	برائے (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		برائے (x = 0; x < FLDSIZE_X; x++)
			*p++ = augmentation_string[MINIMUM(میدان[x][y], len)];
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	برائے (i = 0; i < (FLDSIZE_X - hlen) / 2; i++)
		*p++ = '-';
	حافظہ_نقل(p, hash, hlen);
	p += hlen;
	برائے (i += hlen; i < FLDSIZE_X; i++)
		*p++ = '-';
	*p++ = '+';

	واپس retval;
}

حرف *
sshkey_fingerprint(ثابت ساخت sshkey *k, صحیح dgst_alg,
    شمار sshkey_fp_rep dgst_rep)
{
	حرف *retval = تہی;
	u_char *dgst_raw;
	سائز_t dgst_raw_len;

	اگر (sshkey_fingerprint_raw(k, dgst_alg, &dgst_raw, &dgst_raw_len) != 0)
		واپس تہی;
	انتخاب (dgst_rep) {
	حالت SSH_FP_DEFAULT:
		اگر (dgst_alg == SSH_DIGEST_MD5) {
			retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		} ورنہ {
			retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
			    dgst_raw, dgst_raw_len);
		}
		توڑو;
	حالت SSH_FP_HEX:
		retval = fingerprint_hex(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		توڑو;
	حالت SSH_FP_BASE64:
		retval = fingerprint_b64(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len);
		توڑو;
	حالت SSH_FP_BUBBLEBABBLE:
		retval = fingerprint_bubblebabble(dgst_raw, dgst_raw_len);
		توڑو;
	حالت SSH_FP_RANDOMART:
		retval = fingerprint_randomart(ssh_digest_alg_name(dgst_alg),
		    dgst_raw, dgst_raw_len, k);
		توڑو;
	طےشدہ:
		freezero(dgst_raw, dgst_raw_len);
		واپس تہی;
	}
	freezero(dgst_raw, dgst_raw_len);
	واپس retval;
}

ساکن صحیح
peek_type_nid(ثابت حرف *s, سائز_t l, صحیح *nid)
{
	ثابت ساخت sshkey_impl *impl;
	صحیح i;

	برائے (i = 0; keyimpls[i] != تہی; i++) {
		impl = keyimpls[i];
		اگر (impl->name == تہی || لڑی_لمبائی(impl->name) != l)
			جاری;
		اگر (memcmp(s, impl->name, l) == 0) {
			*nid = -1;
			اگر (کلید_type_is_ecdsa_variant(impl->type))
				*nid = impl->nid;
			واپس impl->type;
		}
	}
	واپس کلید_UNSPEC;
}

/* XXX this can now be made const char * */
صحیح
sshkey_read(ساخت sshkey *ret, حرف **cpp)
{
	ساخت sshkey *k;
	حرف *cp, *blobcopy;
	سائز_t space;
	صحیح r, type, خم_nid = -1;
	ساخت sshbuf *blob;

	اگر (ret == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (ret->type != کلید_UNSPEC && sshkey_impl_from_type(ret->type) == تہی)
		واپس SSH_ERR_INVALID_دلیل;

	/* Decode type */
	cp = *cpp;
	space = strcspn(cp, " \t");
	اگر (space == لڑی_لمبائی(cp))
		واپس SSH_ERR_INVALID_FORMAT;
	اگر ((type = peek_type_nid(cp, space, &خم_nid)) == کلید_UNSPEC)
		واپس SSH_ERR_INVALID_FORMAT;

	/* skip whitespace */
	برائے (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;
	اگر (*cp == '\0')
		واپس SSH_ERR_INVALID_FORMAT;
	اگر (ret->type != کلید_UNSPEC && ret->type != type)
		واپس SSH_ERR_کلید_TYPE_MISMATCH;
	اگر ((blob = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;

	/* find end of keyblob and decode */
	space = strcspn(cp, " \t");
	اگر ((blobcopy = strndup(cp, space)) == تہی) {
		sshbuf_free(blob);
		واپس SSH_ERR_ALLOC_FAIL;
	}
	اگر ((r = sshbuf_b64tod(blob, blobcopy)) != 0) {
		آزاد(blobcopy);
		sshbuf_free(blob);
		واپس r;
	}
	آزاد(blobcopy);
	اگر ((r = sshkey_fromb(blob, &k)) != 0) {
		sshbuf_free(blob);
		واپس r;
	}
	sshbuf_free(blob);

	/* skip whitespace and leave cp at start of comment */
	برائے (cp += space; *cp == ' ' || *cp == '\t'; cp++)
		;

	/* ensure type of blob matches type at start of line */
	اگر (k->type != type) {
		sshkey_free(k);
		واپس SSH_ERR_کلید_TYPE_MISMATCH;
	}
	اگر (کلید_type_is_ecdsa_variant(type) && خم_nid != k->ecdsa_nid) {
		sshkey_free(k);
		واپس SSH_ERR_EC_خم_MISMATCH;
	}

	/* Fill in ret from parsed key */
	sshkey_free_contents(ret);
	*ret = *k;
	freezero(k, حجم(*k));

	/* success */
	*cpp = cp;
	واپس 0;
}

صحیح
sshkey_مقصد_base64(ثابت ساخت sshkey *کلید, حرف **b64p)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;
	ساخت sshbuf *b = تہی;
	حرف *uu = تہی;

	اگر (b64p != تہی)
		*b64p = تہی;
	اگر ((b = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshkey_putb(کلید, b)) != 0)
		جاؤ برآمد;
	اگر ((uu = sshbuf_dtob64_string(b, 0)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	/* Success */
	اگر (b64p != تہی) {
		*b64p = uu;
		uu = تہی;
	}
	r = 0;
 برآمد:
	sshbuf_free(b);
	آزاد(uu);
	واپس r;
}

صحیح
sshkey_format_متن(ثابت ساخت sshkey *کلید, ساخت sshbuf *b)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;
	حرف *uu = تہی;

	اگر ((r = sshkey_مقصد_base64(کلید, &uu)) != 0)
		جاؤ برآمد;
	اگر ((r = sshbuf_putf(b, "%s %s",
	    sshkey_ssh_name(کلید), uu)) != 0)
		جاؤ برآمد;
	r = 0;
 برآمد:
	آزاد(uu);
	واپس r;
}

صحیح
sshkey_write(ثابت ساخت sshkey *کلید, FILE *f)
{
	ساخت sshbuf *b = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	اگر ((b = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshkey_format_متن(کلید, b)) != 0)
		جاؤ برآمد;
	اگر (fwrite(sshbuf_ptr(b), sshbuf_len(b), 1, f) != 1) {
		اگر (feof(f))
			errno = EPIPE;
		r = SSH_ERR_SYSTEM_ERROR;
		جاؤ برآمد;
	}
	/* Success */
	r = 0;
 برآمد:
	sshbuf_free(b);
	واپس r;
}

ثابت حرف *
sshkey_cert_type(ثابت ساخت sshkey *k)
{
	انتخاب (k->cert->type) {
	حالت SSH2_CERT_TYPE_USER:
		واپس "user";
	حالت SSH2_CERT_TYPE_HOST:
		واپس "host";
	طےشدہ:
		واپس "unknown";
	}
}

صحیح
sshkey_check_rsa_لمبائی(ثابت ساخت sshkey *k, صحیح min_سائز)
{
#اگر_تعریف_شدہ WITH_OPENSSL
	صحیح nbits;

	اگر (k == تہی || k->pkey == تہی ||
	    (k->type != کلید_RSA && k->type != کلید_RSA_CERT))
		واپس 0;
	nbits = EVP_PKEY_بٹ(k->pkey);
	اگر (nbits < SSH_RSA_MINIMUM_MODULUS_سائز ||
	    (min_سائز > 0 && nbits < min_سائز))
		واپس SSH_ERR_کلید_لمبائی;
#اگر_ختم /* WITH_OPENSSL */
	واپس 0;
}

#اگر_تعریف_شدہ WITH_OPENSSL
صحیح
sshkey_ecdsa_کلید_مقصد_nid(ثابت EC_کلید *k)
{
	ثابت EC_گروہ *g;
	صحیح nid;

	اگر (k == تہی || (g = EC_کلید_get0_گروہ(k)) == تہی)
		واپس -1;
	اگر ((nid = EC_گروہ_get_خم_name(g)) <= 0)
		واپس -1;
	واپس nid;
}

صحیح
sshkey_ecdsa_pkey_مقصد_nid(EVP_PKEY *pkey)
{
	واپس sshkey_ecdsa_کلید_مقصد_nid(EVP_PKEY_get0_EC_کلید(pkey));
}
#اگر_ختم /* WITH_OPENSSL */

صحیح
sshkey_generate(صحیح type, u_int بٹ, ساخت sshkey **keyp)
{
	ساخت sshkey *k;
	صحیح ret = SSH_ERR_اندرونی_ERROR;
	ثابت ساخت sshkey_impl *impl;

	اگر (keyp == تہی || sshkey_type_is_cert(type))
		واپس SSH_ERR_INVALID_دلیل;
	*keyp = تہی;
	اگر ((impl = sshkey_impl_from_type(type)) == تہی)
		واپس SSH_ERR_کلید_TYPE_UNKNOWN;
	اگر (impl->funcs->generate == تہی)
		واپس SSH_ERR_FEATURE_UNSUPPORTED;
	اگر ((k = sshkey_new(کلید_UNSPEC)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	k->type = type;
	اگر ((ret = impl->funcs->generate(k, بٹ)) != 0) {
		sshkey_free(k);
		واپس ret;
	}
	/* success */
	*keyp = k;
	واپس 0;
}

صحیح
sshkey_cert_copy(ثابت ساخت sshkey *from_کلید, ساخت sshkey *مقصد_کلید)
{
	u_int i;
	ثابت ساخت sshkey_cert *from;
	ساخت sshkey_cert *مقصد;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	اگر (مقصد_کلید == تہی || (from = from_کلید->cert) == تہی)
		واپس SSH_ERR_INVALID_دلیل;

	اگر ((مقصد = cert_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;

	اگر ((r = sshbuf_putb(مقصد->certblob, from->certblob)) != 0 ||
	    (r = sshbuf_putb(مقصد->critical, from->critical)) != 0 ||
	    (r = sshbuf_putb(مقصد->extensions, from->extensions)) != 0)
		جاؤ برآمد;

	مقصد->serial = from->serial;
	مقصد->type = from->type;
	اگر (from->کلید_id == تہی)
		مقصد->کلید_id = تہی;
	ورنہ اگر ((مقصد->کلید_id = strdup(from->کلید_id)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	مقصد->valid_after = from->valid_after;
	مقصد->valid_before = from->valid_before;
	اگر (from->signature_کلید == تہی)
		مقصد->signature_کلید = تہی;
	ورنہ اگر ((r = sshkey_from_نجی(from->signature_کلید,
	    &مقصد->signature_کلید)) != 0)
		جاؤ برآمد;
	اگر (from->signature_type != تہی &&
	    (مقصد->signature_type = strdup(from->signature_type)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (from->nprincipals > SSHKEY_CERT_MAX_PRINCIPALS) {
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	اگر (from->nprincipals > 0) {
		اگر ((مقصد->principals = صفر_حافظہ_دو(from->nprincipals,
		    حجم(*مقصد->principals))) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		برائے (i = 0; i < from->nprincipals; i++) {
			مقصد->principals[i] = strdup(from->principals[i]);
			اگر (مقصد->principals[i] == تہی) {
				مقصد->nprincipals = i;
				r = SSH_ERR_ALLOC_FAIL;
				جاؤ برآمد;
			}
		}
	}
	مقصد->nprincipals = from->nprincipals;

	/* success */
	cert_free(مقصد_کلید->cert);
	مقصد_کلید->cert = مقصد;
	مقصد = تہی;
	r = 0;
 برآمد:
	cert_free(مقصد);
	واپس r;
}

صحیح
sshkey_copy_عوامی_sk(ثابت ساخت sshkey *from, ساخت sshkey *مقصد)
{
	/* Append security-key application string */
	اگر ((مقصد->sk_application = strdup(from->sk_application)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	واپس 0;
}

صحیح
sshkey_from_نجی(ثابت ساخت sshkey *k, ساخت sshkey **pkp)
{
	ساخت sshkey *n = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;
	ثابت ساخت sshkey_impl *impl;

	*pkp = تہی;
	اگر ((impl = sshkey_impl_from_کلید(k)) == تہی)
		واپس SSH_ERR_کلید_TYPE_UNKNOWN;
	اگر ((n = sshkey_new(k->type)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = impl->funcs->copy_عوامی(k, n)) != 0)
		جاؤ برآمد;
	اگر (sshkey_is_cert(k) && (r = sshkey_cert_copy(k, n)) != 0)
		جاؤ برآمد;
	/* success */
	*pkp = n;
	n = تہی;
	r = 0;
 برآمد:
	sshkey_free(n);
	واپس r;
}

صحیح
sshkey_is_shielded(ساخت sshkey *k)
{
	واپس k != تہی && k->shielded_نجی != تہی;
}

صحیح
sshkey_shield_نجی(ساخت sshkey *k)
{
	ساخت sshbuf *prvbuf = تہی;
	u_char *prekey = تہی, *enc = تہی, keyiv[SSH_DIGEST_MAX_لمبائی];
	ساخت sshcipher_ctx *cctx = تہی;
	ثابت ساخت sshcipher *cipher;
	سائز_t i, enclen = 0;
	ساخت sshkey *kswap = تہی, tmp;
	صحیح r = SSH_ERR_اندرونی_ERROR;

#اگر_تعریف_شدہ DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#اگر_ختم
	اگر ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == تہی) {
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	اگر (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_بائٹیں(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_اندرونی_ERROR;
		جاؤ برآمد;
	}

	/* Prepare a random pre-key, and from it an ephemeral key */
	اگر ((r = sshkey_prekey_alloc(&prekey, SSHKEY_SHIELD_PREKEY_LEN)) != 0)
		جاؤ برآمد;
	arc4random_buf(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	اگر ((r = ssh_digest_حافظہ(SSHKEY_SHIELD_PREKEY_HASH,
	    prekey, SSHKEY_SHIELD_PREKEY_LEN,
	    keyiv, SSH_DIGEST_MAX_لمبائی)) != 0)
		جاؤ برآمد;
#اگر_تعریف_شدہ DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_ڈیٹا(keyiv, ssh_digest_بائٹیں(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#اگر_ختم
	اگر ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 1)) != 0)
		جاؤ برآمد;

	/* Serialise and encrypt the private key using the ephemeral key */
	اگر ((prvbuf = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (sshkey_is_shielded(k) && (r = sshkey_unshield_نجی(k)) != 0)
		جاؤ برآمد;
	اگر ((r = sshkey_نجی_serialize(k, prvbuf)) != 0)
		جاؤ برآمد;
	/* pad to cipher blocksize */
	i = 0;
	جب (sshbuf_len(prvbuf) % cipher_blocksize(cipher)) {
		اگر ((r = sshbuf_put_u8(prvbuf, ++i & 0xff)) != 0)
			جاؤ برآمد;
	}
#اگر_تعریف_شدہ DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#اگر_ختم
	/* encrypt */
	enclen = sshbuf_len(prvbuf);
	اگر ((enc = حافظہ_دو(enclen)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = cipher_crypt(cctx, 0, enc,
	    sshbuf_ptr(prvbuf), sshbuf_len(prvbuf), 0, 0)) != 0)
		جاؤ برآمد;
#اگر_تعریف_شدہ DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_ڈیٹا(enc, enclen, stderr);
#اگر_ختم

	/* Make a scrubbed, public-only copy of our private key argument */
	اگر ((r = sshkey_from_نجی(k, &kswap)) != 0)
		جاؤ برآمد;

	/* Swap the private key out (it will be destroyed below) */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* Insert the shielded key into our argument */
	k->shielded_نجی = enc;
	k->shielded_len = enclen;
	k->shield_prekey = prekey;
	k->shield_prekey_len = SSHKEY_SHIELD_PREKEY_LEN;
	enc = prekey = تہی; /* transferred */
	enclen = 0;

	/* preserve key fields that are required for correct operation */
	k->sk_flags = kswap->sk_flags;

	/* success */
	r = 0;

 برآمد:
	/* XXX behaviour on error - invalidate original private key? */
	cipher_free(cctx);
	explicit_bzero(keyiv, حجم(keyiv));
	explicit_bzero(&tmp, حجم(tmp));
	freezero(enc, enclen);
	sshkey_prekey_free(prekey, SSHKEY_SHIELD_PREKEY_LEN);
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	واپس r;
}

/* Check deterministic padding after private key */
ساکن صحیح
private2_check_padding(ساخت sshbuf *decrypted)
{
	u_char pad;
	سائز_t i;
	صحیح r;

	i = 0;
	جب (sshbuf_len(decrypted)) {
		اگر ((r = sshbuf_get_u8(decrypted, &pad)) != 0)
			جاؤ برآمد;
		اگر (pad != (++i & 0xff)) {
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
	}
	/* success */
	r = 0;
 برآمد:
	explicit_bzero(&pad, حجم(pad));
	explicit_bzero(&i, حجم(i));
	واپس r;
}

صحیح
sshkey_unshield_نجی(ساخت sshkey *k)
{
	ساخت sshbuf *prvbuf = تہی;
	u_char *cp, keyiv[SSH_DIGEST_MAX_لمبائی];
	ساخت sshcipher_ctx *cctx = تہی;
	ثابت ساخت sshcipher *cipher;
	ساخت sshkey *kswap = تہی, tmp;
	صحیح r = SSH_ERR_اندرونی_ERROR;

#اگر_تعریف_شدہ DEBUG_PK
	fprintf(stderr, "%s: entering for %s\n", __func__, sshkey_ssh_name(k));
#اگر_ختم
	اگر (!sshkey_is_shielded(k))
		واپس 0; /* nothing to do */

	اگر ((cipher = cipher_by_name(SSHKEY_SHIELD_CIPHER)) == تہی) {
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	اگر (cipher_keylen(cipher) + cipher_ivlen(cipher) >
	    ssh_digest_بائٹیں(SSHKEY_SHIELD_PREKEY_HASH)) {
		r = SSH_ERR_اندرونی_ERROR;
		جاؤ برآمد;
	}
	/* check size of shielded key blob */
	اگر (k->shielded_len < cipher_blocksize(cipher) ||
	    (k->shielded_len % cipher_blocksize(cipher)) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}

	/* Calculate the ephemeral key from the prekey */
	اگر ((r = ssh_digest_حافظہ(SSHKEY_SHIELD_PREKEY_HASH,
	    k->shield_prekey, k->shield_prekey_len,
	    keyiv, SSH_DIGEST_MAX_لمبائی)) != 0)
		جاؤ برآمد;
	اگر ((r = cipher_init(&cctx, cipher, keyiv, cipher_keylen(cipher),
	    keyiv + cipher_keylen(cipher), cipher_ivlen(cipher), 0)) != 0)
		جاؤ برآمد;
#اگر_تعریف_شدہ DEBUG_PK
	fprintf(stderr, "%s: key+iv\n", __func__);
	sshbuf_dump_ڈیٹا(keyiv, ssh_digest_بائٹیں(SSHKEY_SHIELD_PREKEY_HASH),
	    stderr);
#اگر_ختم

	/* Decrypt and parse the shielded private key using the ephemeral key */
	اگر ((prvbuf = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_reserve(prvbuf, k->shielded_len, &cp)) != 0)
		جاؤ برآمد;
	/* decrypt */
#اگر_تعریف_شدہ DEBUG_PK
	fprintf(stderr, "%s: encrypted\n", __func__);
	sshbuf_dump_ڈیٹا(k->shielded_نجی, k->shielded_len, stderr);
#اگر_ختم
	اگر ((r = cipher_crypt(cctx, 0, cp,
	    k->shielded_نجی, k->shielded_len, 0, 0)) != 0)
		جاؤ برآمد;
#اگر_تعریف_شدہ DEBUG_PK
	fprintf(stderr, "%s: serialised\n", __func__);
	sshbuf_dump(prvbuf, stderr);
#اگر_ختم
	/* Parse private key */
	اگر ((r = sshkey_نجی_deserialize(prvbuf, &kswap)) != 0)
		جاؤ برآمد;

	اگر ((r = private2_check_padding(prvbuf)) != 0)
		جاؤ برآمد;

	/* Swap the parsed key back into place */
	tmp = *kswap;
	*kswap = *k;
	*k = tmp;

	/* success */
	r = 0;

 برآمد:
	cipher_free(cctx);
	explicit_bzero(keyiv, حجم(keyiv));
	explicit_bzero(&tmp, حجم(tmp));
	sshkey_free(kswap);
	sshbuf_free(prvbuf);
	واپس r;
}

ساکن صحیح
cert_parse(ساخت sshbuf *b, ساخت sshkey *کلید, ساخت sshbuf *certbuf,
    ثابت حرف *ca_sigalg_allowlist)
{
	ساخت sshbuf *principals = تہی, *crit = تہی;
	ساخت sshbuf *exts = تہی, *ca = تہی;
	u_char *sig = تہی;
	حرف *sigtype = تہی;
	سائز_t signed_len = 0, slen = 0, kidlen = 0;
	صحیح ret = SSH_ERR_اندرونی_ERROR;

	/* Copy the entire key blob for verification and later serialisation */
	اگر ((ret = sshbuf_putb(کلید->cert->certblob, certbuf)) != 0)
		واپس ret;

	/* Parse body of certificate up to signature */
	اگر ((ret = sshbuf_get_u64(b, &کلید->cert->serial)) != 0 ||
	    (ret = sshbuf_get_u32(b, &کلید->cert->type)) != 0 ||
	    (ret = sshbuf_get_cstring(b, &کلید->cert->کلید_id, &kidlen)) != 0 ||
	    (ret = sshbuf_froms(b, &principals)) != 0 ||
	    (ret = sshbuf_get_u64(b, &کلید->cert->valid_after)) != 0 ||
	    (ret = sshbuf_get_u64(b, &کلید->cert->valid_before)) != 0 ||
	    (ret = sshbuf_froms(b, &crit)) != 0 ||
	    (ret = sshbuf_froms(b, &exts)) != 0 ||
	    (ret = sshbuf_get_string_براہ_راست(b, تہی, تہی)) != 0 ||
	    (ret = sshbuf_froms(b, &ca)) != 0) {
		/* XXX debug print error for ret */
		ret = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}

	/* Signature is left in the buffer so we can calculate this length */
	signed_len = sshbuf_len(کلید->cert->certblob) - sshbuf_len(b);

	اگر ((ret = sshbuf_get_string(b, &sig, &slen)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}

	/* Is this a signature we're prepared to accept? */
	اگر ((ret = sshkey_get_sigtype(sig, slen, &sigtype)) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (ca_sigalg_allowlist != تہی &&
	    مطابقت_نمونہ_list(sigtype, ca_sigalg_allowlist, 0) != 1) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		جاؤ برآمد;
	}

	/* Parse CA key and check whether we might accept it */
	اگر (sshkey_from_blob_اندرونی(ca, &کلید->cert->signature_کلید, 0,
	    ca_sigalg_allowlist, تہی) != 0) {
		ret = SSH_ERR_کلید_CERT_INVALID_SIGN_کلید;
		جاؤ برآمد;
	}
	اگر (!sshkey_type_is_valid_ca(کلید->cert->signature_کلید->type)) {
		ret = SSH_ERR_کلید_CERT_INVALID_SIGN_کلید;
		جاؤ برآمد;
	}

	اگر (کلید->cert->type != SSH2_CERT_TYPE_USER &&
	    کلید->cert->type != SSH2_CERT_TYPE_HOST) {
		ret = SSH_ERR_کلید_CERT_UNKNOWN_TYPE;
		جاؤ برآمد;
	}

	/* Parse principals section */
	جب (sshbuf_len(principals) > 0) {
		حرف *principal = تہی;
		حرف **oprincipals = تہی;

		اگر (کلید->cert->nprincipals >= SSHKEY_CERT_MAX_PRINCIPALS) {
			ret = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		اگر ((ret = sshbuf_get_cstring(principals, &principal,
		    تہی)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		oprincipals = کلید->cert->principals;
		کلید->cert->principals = recallocarray(کلید->cert->principals,
		    کلید->cert->nprincipals, کلید->cert->nprincipals + 1,
		    حجم(*کلید->cert->principals));
		اگر (کلید->cert->principals == تہی) {
			آزاد(principal);
			کلید->cert->principals = oprincipals;
			ret = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		کلید->cert->principals[کلید->cert->nprincipals++] = principal;
	}

	/*
	 * Stash a copies of the critical options and extensions sections
	 * for later use.
	 */
	اگر ((ret = sshbuf_putb(کلید->cert->critical, crit)) != 0 ||
	    (exts != تہی &&
	    (ret = sshbuf_putb(کلید->cert->extensions, exts)) != 0))
		جاؤ برآمد;

	/*
	 * Validate critical options and extensions sections format.
	 */
	جب (sshbuf_len(crit) != 0) {
		اگر ((ret = sshbuf_get_string_براہ_راست(crit, تہی, تہی)) != 0 ||
		    (ret = sshbuf_get_string_براہ_راست(crit, تہی, تہی)) != 0) {
			sshbuf_reset(کلید->cert->critical);
			ret = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
	}
	جب (exts != تہی && sshbuf_len(exts) != 0) {
		اگر ((ret = sshbuf_get_string_براہ_راست(exts, تہی, تہی)) != 0 ||
		    (ret = sshbuf_get_string_براہ_راست(exts, تہی, تہی)) != 0) {
			sshbuf_reset(کلید->cert->extensions);
			ret = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
	}

	/* Finally, validate signature */
	اگر ((ret = sshkey_verify(کلید->cert->signature_کلید, sig, slen,
	    sshbuf_ptr(کلید->cert->certblob), signed_len, تہی, 0, تہی)) != 0)
		جاؤ برآمد;

	/* Success */
	ret = 0;
	کلید->cert->signature_type = sigtype;
	sigtype = تہی;
 برآمد:
	sshbuf_free(ca);
	sshbuf_free(crit);
	sshbuf_free(exts);
	sshbuf_free(principals);
	آزاد(sig);
	آزاد(sigtype);
	واپس ret;
}

صحیح
sshkey_deserialize_sk(ساخت sshbuf *b, ساخت sshkey *کلید)
{
	/* Parse additional security-key application string */
	اگر (sshbuf_get_cstring(b, &کلید->sk_application, تہی) != 0)
		واپس SSH_ERR_INVALID_FORMAT;
	واپس 0;
}

ساکن صحیح
sshkey_from_blob_اندرونی(ساخت sshbuf *b, ساخت sshkey **keyp,
    صحیح allow_cert, ثابت حرف *alg_allowlist, ثابت حرف *ca_sigalg_allowlist)
{
	صحیح type, ret = SSH_ERR_اندرونی_ERROR;
	حرف *ktype = تہی;
	ساخت sshkey *کلید = تہی;
	ساخت sshbuf *copy;
	ثابت ساخت sshkey_impl *impl;

#اگر_تعریف_شدہ DEBUG_PK /* XXX */
	sshbuf_dump(b, stderr);
#اگر_ختم
	اگر (keyp != تہی)
		*keyp = تہی;
	اگر ((copy = sshbuf_fromb(b)) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (sshbuf_get_cstring(b, &ktype, تہی) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}

	type = sshkey_type_from_name(ktype);
	اگر (!allow_cert && sshkey_type_is_cert(type)) {
		ret = SSH_ERR_کلید_CERT_INVALID_SIGN_کلید;
		جاؤ برآمد;
	}

	اگر (alg_allowlist != تہی &&
	    !sshkey_مطابقت_keyname_مقصد_sigalgs(ktype, alg_allowlist)) {
		ret = SSH_ERR_کلید_ALG_UNSUPPORTED;
		جاؤ برآمد;
	}

	اگر ((impl = sshkey_impl_from_type(type)) == تہی) {
		ret = SSH_ERR_کلید_TYPE_UNKNOWN;
		جاؤ برآمد;
	}
	اگر ((کلید = sshkey_new(type)) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (sshkey_type_is_cert(type)) {
		/* Skip nonce that precedes all certificates */
		اگر (sshbuf_get_string_براہ_راست(b, تہی, تہی) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
	}
	اگر ((ret = impl->funcs->deserialize_عوامی(ktype, b, کلید)) != 0)
		جاؤ برآمد;

	/* Parse certificate potion */
	اگر (sshkey_is_cert(کلید) &&
	    (ret = cert_parse(b, کلید, copy, ca_sigalg_allowlist)) != 0)
		جاؤ برآمد;

	اگر (کلید != تہی && sshbuf_len(b) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	ret = 0;
	اگر (keyp != تہی) {
		*keyp = کلید;
		کلید = تہی;
	}
 برآمد:
	sshbuf_free(copy);
	sshkey_free(کلید);
	آزاد(ktype);
	واپس ret;
}

صحیح
sshkey_from_blob(ثابت u_char *blob, سائز_t blen, ساخت sshkey **keyp)
{
	ساخت sshbuf *b;
	صحیح r;

	اگر ((b = sshbuf_from(blob, blen)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	r = sshkey_from_blob_اندرونی(b, keyp, 1, تہی, تہی);
	sshbuf_free(b);
	واپس r;
}

صحیح
sshkey_fromb(ساخت sshbuf *b, ساخت sshkey **keyp)
{
	واپس sshkey_from_blob_اندرونی(b, keyp, 1, تہی, تہی);
}

صحیح
sshkey_fromb_allowlist(ساخت sshbuf *b, ساخت sshkey **keyp,
    ثابت حرف *alg_allowlist, ثابت حرف *ca_sigalg_allowlist)
{
	واپس sshkey_from_blob_اندرونی(b, keyp, 1,
	    alg_allowlist, ca_sigalg_allowlist);
}

صحیح
sshkey_froms(ساخت sshbuf *buf, ساخت sshkey **keyp)
{
	ساخت sshbuf *b;
	صحیح r;

	اگر ((r = sshbuf_froms(buf, &b)) != 0)
		واپس r;
	r = sshkey_from_blob_اندرونی(b, keyp, 1, تہی, تہی);
	sshbuf_free(b);
	واپس r;
}

صحیح
sshkey_get_sigtype(ثابت u_char *sig, سائز_t siglen, حرف **sigtypep)
{
	صحیح r;
	ساخت sshbuf *b = تہی;
	حرف *sigtype = تہی;

	اگر (sigtypep != تہی)
		*sigtypep = تہی;
	اگر ((b = sshbuf_from(sig, siglen)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_get_cstring(b, &sigtype, تہی)) != 0)
		جاؤ برآمد;
	/* success */
	اگر (sigtypep != تہی) {
		*sigtypep = sigtype;
		sigtype = تہی;
	}
	r = 0;
 برآمد:
	آزاد(sigtype);
	sshbuf_free(b);
	واپس r;
}

/*
 *
 * Checks whether a certificate's signature type is allowed.
 * Returns 0 (success) if the certificate signature type appears in the
 * "allowed" pattern-list, or the key is not a certificate to begin with.
 * Otherwise returns a ssherr.h code.
 */
صحیح
sshkey_check_cert_sigtype(ثابت ساخت sshkey *کلید, ثابت حرف *allowed)
{
	اگر (کلید == تہی || allowed == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (!sshkey_type_is_cert(کلید->type))
		واپس 0;
	اگر (کلید->cert == تہی || کلید->cert->signature_type == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (مطابقت_نمونہ_list(کلید->cert->signature_type, allowed, 0) != 1)
		واپس SSH_ERR_SIGN_ALG_UNSUPPORTED;
	واپس 0;
}

/*
 * Returns the expected signature algorithm for a given public key algorithm.
 */
ثابت حرف *
sshkey_sigalg_by_name(ثابت حرف *name)
{
	ثابت ساخت sshkey_impl *impl;
	صحیح i;

	برائے (i = 0; keyimpls[i] != تہی; i++) {
		impl = keyimpls[i];
		اگر (strcmp(impl->name, name) != 0)
			جاری;
		اگر (impl->sigalg != تہی)
			واپس impl->sigalg;
		اگر (!impl->cert)
			واپس impl->name;
		واپس sshkey_ssh_name_from_type_nid(
		    sshkey_type_plain(impl->type), impl->nid);
	}
	واپس تہی;
}

/*
 * Verifies that the signature algorithm appearing inside the signature blob
 * matches that which was requested.
 */
صحیح
sshkey_check_sigtype(ثابت u_char *sig, سائز_t siglen,
    ثابت حرف *requested_alg)
{
	ثابت حرف *expected_alg;
	حرف *sigtype = تہی;
	صحیح r;

	اگر (requested_alg == تہی)
		واپس 0;
	اگر ((expected_alg = sshkey_sigalg_by_name(requested_alg)) == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0)
		واپس r;
	r = strcmp(expected_alg, sigtype) == 0;
	آزاد(sigtype);
	واپس r ? 0 : SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

صحیح
sshkey_sign(ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	صحیح was_shielded = sshkey_is_shielded(کلید);
	صحیح r2, r = SSH_ERR_اندرونی_ERROR;
	ثابت ساخت sshkey_impl *impl;

	اگر (sigp != تہی)
		*sigp = تہی;
	اگر (lenp != تہی)
		*lenp = 0;
	اگر (datalen > SSH_کلید_MAX_SIGN_ڈیٹا_سائز)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((impl = sshkey_impl_from_کلید(کلید)) == تہی)
		واپس SSH_ERR_کلید_TYPE_UNKNOWN;
	اگر ((r = sshkey_unshield_نجی(کلید)) != 0)
		واپس r;
	اگر (sshkey_is_sk(کلید)) {
		r = sshsk_sign(sk_provider, کلید, sigp, lenp, ڈیٹا,
		    datalen, compat, sk_pin);
	} ورنہ اگر ((کلید->flags & SSHKEY_FLAG_EXT) != 0) {
		r = pkcs11_sign(کلید, sigp, lenp, ڈیٹا, datalen,
		    alg, sk_provider, sk_pin, compat);
	} ورنہ {
		اگر (impl->funcs->sign == تہی)
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ورنہ {
			r = impl->funcs->sign(کلید, sigp, lenp, ڈیٹا, datalen,
			    alg, sk_provider, sk_pin, compat);
		 }
	}
	اگر (was_shielded && (r2 = sshkey_shield_نجی(کلید)) != 0)
		واپس r2;
	واپس r;
}

/*
 * ssh_key_verify returns 0 for a correct signature and < 0 on error.
 * If "alg" specified, then the signature must use that algorithm.
 */
صحیح
sshkey_verify(ثابت ساخت sshkey *کلید,
    ثابت u_char *sig, سائز_t siglen,
    ثابت u_char *ڈیٹا, سائز_t dlen, ثابت حرف *alg, u_int compat,
    ساخت sshkey_sig_details **detailsp)
{
	ثابت ساخت sshkey_impl *impl;

	اگر (detailsp != تہی)
		*detailsp = تہی;
	اگر (siglen == 0 || dlen > SSH_کلید_MAX_SIGN_ڈیٹا_سائز)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((impl = sshkey_impl_from_کلید(کلید)) == تہی)
		واپس SSH_ERR_کلید_TYPE_UNKNOWN;
	واپس impl->funcs->verify(کلید, sig, siglen, ڈیٹا, dlen,
	    alg, compat, detailsp);
}

/* Convert a plain key to their _CERT equivalent */
صحیح
sshkey_مقصد_certified(ساخت sshkey *k)
{
	صحیح newtype;

	اگر ((newtype = sshkey_type_certified(k->type)) == -1)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((k->cert = cert_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	k->type = newtype;
	واپس 0;
}

/* Convert a certificate to its raw key equivalent */
صحیح
sshkey_drop_cert(ساخت sshkey *k)
{
	اگر (!sshkey_type_is_cert(k->type))
		واپس SSH_ERR_کلید_TYPE_UNKNOWN;
	cert_free(k->cert);
	k->cert = تہی;
	k->type = sshkey_type_plain(k->type);
	واپس 0;
}

/* Sign a certified key, (re-)generating the signed certblob. */
صحیح
sshkey_certify_custom(ساخت sshkey *k, ساخت sshkey *ca, ثابت حرف *alg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    sshkey_certify_signer *signer, خالی *signer_ctx)
{
	ثابت ساخت sshkey_impl *impl;
	ساخت sshbuf *principals = تہی;
	u_char *ca_blob = تہی, *sig_blob = تہی, nonce[32];
	سائز_t i, ca_len, sig_len;
	صحیح ret = SSH_ERR_اندرونی_ERROR;
	ساخت sshbuf *cert = تہی;
	حرف *sigtype = تہی;

	اگر (k == تہی || k->cert == تہی ||
	    k->cert->certblob == تہی || ca == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (!sshkey_is_cert(k))
		واپس SSH_ERR_کلید_TYPE_UNKNOWN;
	اگر (!sshkey_type_is_valid_ca(ca->type))
		واپس SSH_ERR_کلید_CERT_INVALID_SIGN_کلید;
	اگر ((impl = sshkey_impl_from_کلید(k)) == تہی)
		واپس SSH_ERR_اندرونی_ERROR;

	/*
	 * If no alg specified as argument but a signature_type was set,
	 * then prefer that. If both were specified, then they must match.
	 */
	اگر (alg == تہی)
		alg = k->cert->signature_type;
	ورنہ اگر (k->cert->signature_type != تہی &&
	    strcmp(alg, k->cert->signature_type) != 0)
		واپس SSH_ERR_INVALID_دلیل;

	/*
	 * If no signing algorithm or signature_type was specified and we're
	 * using a RSA key, then default to a good signature algorithm.
	 */
	اگر (alg == تہی && ca->type == کلید_RSA)
		alg = "rsa-sha2-512";

	اگر ((ret = sshkey_مقصد_blob(ca, &ca_blob, &ca_len)) != 0)
		واپس SSH_ERR_کلید_CERT_INVALID_SIGN_کلید;

	cert = k->cert->certblob; /* for readability */
	sshbuf_reset(cert);
	اگر ((ret = sshbuf_put_cstring(cert, sshkey_ssh_name(k))) != 0)
		جاؤ برآمد;

	/* -v01 certs put nonce first */
	arc4random_buf(&nonce, حجم(nonce));
	اگر ((ret = sshbuf_put_string(cert, nonce, حجم(nonce))) != 0)
		جاؤ برآمد;

	/* Public key next */
	اگر ((ret = impl->funcs->serialize_عوامی(k, cert,
	    SSHKEY_SERIALIZE_DEFAULT)) != 0)
		جاؤ برآمد;

	/* Then remaining cert fields */
	اگر ((ret = sshbuf_put_u64(cert, k->cert->serial)) != 0 ||
	    (ret = sshbuf_put_u32(cert, k->cert->type)) != 0 ||
	    (ret = sshbuf_put_cstring(cert, k->cert->کلید_id)) != 0)
		جاؤ برآمد;

	اگر ((principals = sshbuf_new()) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	برائے (i = 0; i < k->cert->nprincipals; i++) {
		اگر ((ret = sshbuf_put_cstring(principals,
		    k->cert->principals[i])) != 0)
			جاؤ برآمد;
	}
	اگر ((ret = sshbuf_put_stringb(cert, principals)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_after)) != 0 ||
	    (ret = sshbuf_put_u64(cert, k->cert->valid_before)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->critical)) != 0 ||
	    (ret = sshbuf_put_stringb(cert, k->cert->extensions)) != 0 ||
	    (ret = sshbuf_put_string(cert, تہی, 0)) != 0 || /* Reserved */
	    (ret = sshbuf_put_string(cert, ca_blob, ca_len)) != 0)
		جاؤ برآمد;

	/* Sign the whole mess */
	اگر ((ret = signer(ca, &sig_blob, &sig_len, sshbuf_ptr(cert),
	    sshbuf_len(cert), alg, sk_provider, sk_pin, 0, signer_ctx)) != 0)
		جاؤ برآمد;
	/* Check and update signature_type against what was actually used */
	اگر ((ret = sshkey_get_sigtype(sig_blob, sig_len, &sigtype)) != 0)
		جاؤ برآمد;
	اگر (alg != تہی && strcmp(alg, sigtype) != 0) {
		ret = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		جاؤ برآمد;
	}
	اگر (k->cert->signature_type == تہی) {
		k->cert->signature_type = sigtype;
		sigtype = تہی;
	}
	/* Append signature and we are done */
	اگر ((ret = sshbuf_put_string(cert, sig_blob, sig_len)) != 0)
		جاؤ برآمد;
	ret = 0;
 برآمد:
	اگر (ret != 0)
		sshbuf_reset(cert);
	آزاد(sig_blob);
	آزاد(ca_blob);
	آزاد(sigtype);
	sshbuf_free(principals);
	واپس ret;
}

ساکن صحیح
default_کلید_sign(ساخت sshkey *کلید, u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    u_int compat, خالی *ctx)
{
	اگر (ctx != تہی)
		واپس SSH_ERR_INVALID_دلیل;
	واپس sshkey_sign(کلید, sigp, lenp, ڈیٹا, datalen, alg,
	    sk_provider, sk_pin, compat);
}

صحیح
sshkey_certify(ساخت sshkey *k, ساخت sshkey *ca, ثابت حرف *alg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin)
{
	واپس sshkey_certify_custom(k, ca, alg, sk_provider, sk_pin,
	    default_کلید_sign, تہی);
}

صحیح
sshkey_cert_check_authority(ثابت ساخت sshkey *k,
    صحیح want_host, صحیح wildcard_نمونہ, uint64_t verify_وقت,
    ثابت حرف *name, ثابت حرف **reason)
{
	u_int i, principal_matches;

	اگر (reason == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (!sshkey_is_cert(k)) {
		*reason = "Key is not a certificate";
		واپس SSH_ERR_کلید_CERT_INVALID;
	}
	اگر (want_host) {
		اگر (k->cert->type != SSH2_CERT_TYPE_HOST) {
			*reason = "Certificate invalid: not a host certificate";
			واپس SSH_ERR_کلید_CERT_INVALID;
		}
	} ورنہ {
		اگر (k->cert->type != SSH2_CERT_TYPE_USER) {
			*reason = "Certificate invalid: not a user certificate";
			واپس SSH_ERR_کلید_CERT_INVALID;
		}
	}
	اگر (verify_وقت < k->cert->valid_after) {
		*reason = "Certificate invalid: not yet valid";
		واپس SSH_ERR_کلید_CERT_INVALID;
	}
	اگر (verify_وقت >= k->cert->valid_before) {
		*reason = "Certificate invalid: expired";
		واپس SSH_ERR_کلید_CERT_INVALID;
	}
	اگر (k->cert->nprincipals == 0) {
		*reason = "Certificate lacks principal list";
		واپس SSH_ERR_کلید_CERT_INVALID;
	}
	اگر (name == تہی)
		واپس 0; /* principal matching not requested */

	principal_matches = 0;
	برائے (i = 0; i < k->cert->nprincipals; i++) {
		اگر (wildcard_نمونہ) {
			اگر (مطابقت_نمونہ(name, k->cert->principals[i])) {
				principal_matches = 1;
				توڑو;
			}
		} ورنہ اگر (strcmp(name, k->cert->principals[i]) == 0) {
			principal_matches = 1;
			توڑو;
		}
	}
	اگر (!principal_matches) {
		*reason = "Certificate invalid: name is not a listed "
		    "principal";
		واپس SSH_ERR_کلید_CERT_INVALID;
	}
	واپس 0;
}

صحیح
sshkey_cert_check_authority_now(ثابت ساخت sshkey *k,
    صحیح want_host, صحیح wildcard_نمونہ, ثابت حرف *name,
    ثابت حرف **reason)
{
	time_t now;

	اگر ((now = time(تہی)) < 0) {
		/* yikes - system clock before epoch! */
		*reason = "Certificate invalid: not yet valid";
		واپس SSH_ERR_کلید_CERT_INVALID;
	}
	واپس sshkey_cert_check_authority(k, want_host, wildcard_نمونہ,
	    (uint64_t)now, name, reason);
}

صحیح
sshkey_cert_check_host(ثابت ساخت sshkey *کلید, ثابت حرف *host,
    ثابت حرف *ca_sign_algorithms, ثابت حرف **reason)
{
	صحیح r;

	اگر ((r = sshkey_cert_check_authority_now(کلید, 1, 1, host, reason)) != 0)
		واپس r;
	اگر (sshbuf_len(کلید->cert->critical) != 0) {
		*reason = "Certificate contains unsupported critical options";
		واپس SSH_ERR_کلید_CERT_INVALID;
	}
	اگر (ca_sign_algorithms != تہی &&
	    (r = sshkey_check_cert_sigtype(کلید, ca_sign_algorithms)) != 0) {
		*reason = "Certificate signed with disallowed algorithm";
		واپس SSH_ERR_کلید_CERT_INVALID;
	}
	واپس 0;
}

سائز_t
sshkey_format_cert_validity(ثابت ساخت sshkey_cert *cert, حرف *s, سائز_t l)
{
	حرف from[32], مقصد[32], ret[128];

	*from = *مقصد = '\0';
	اگر (cert->valid_after == 0 &&
	    cert->valid_before == 0xffffffffffffffffULL)
		واپس strlcpy(s, "forever", l);

	اگر (cert->valid_after != 0)
		format_absolute_وقت(cert->valid_after, from, حجم(from));
	اگر (cert->valid_before != 0xffffffffffffffffULL)
		format_absolute_وقت(cert->valid_before, مقصد, حجم(مقصد));

	اگر (cert->valid_after == 0)
		snprintf(ret, حجم(ret), "before %s", مقصد);
	ورنہ اگر (cert->valid_before == 0xffffffffffffffffULL)
		snprintf(ret, حجم(ret), "after %s", from);
	ورنہ
		snprintf(ret, حجم(ret), "from %s to %s", from, مقصد);

	واپس strlcpy(s, ret, l);
}

/* Common serialization for FIDO private keys */
صحیح
sshkey_serialize_نجی_sk(ثابت ساخت sshkey *کلید, ساخت sshbuf *b)
{
	صحیح r;

	اگر ((r = sshbuf_put_cstring(b, کلید->sk_application)) != 0 ||
	    (r = sshbuf_put_u8(b, کلید->sk_flags)) != 0 ||
	    (r = sshbuf_put_stringb(b, کلید->sk_کلید_handle)) != 0 ||
	    (r = sshbuf_put_stringb(b, کلید->sk_reserved)) != 0)
		واپس r;

	واپس 0;
}

ساکن صحیح
sshkey_نجی_serialize_opt(ساخت sshkey *کلید, ساخت sshbuf *buf,
    شمار sshkey_serialize_rep opts)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;
	صحیح was_shielded = sshkey_is_shielded(کلید);
	ساخت sshbuf *b = تہی;
	ثابت ساخت sshkey_impl *impl;

	اگر ((impl = sshkey_impl_from_کلید(کلید)) == تہی)
		واپس SSH_ERR_اندرونی_ERROR;
	اگر ((r = sshkey_unshield_نجی(کلید)) != 0)
		واپس r;
	اگر ((b = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_cstring(b, sshkey_ssh_name(کلید))) != 0)
		جاؤ برآمد;
	اگر (sshkey_is_cert(کلید)) {
		اگر (کلید->cert == تہی ||
		    sshbuf_len(کلید->cert->certblob) == 0) {
			r = SSH_ERR_INVALID_دلیل;
			جاؤ برآمد;
		}
		اگر ((r = sshbuf_put_stringb(b, کلید->cert->certblob)) != 0)
			جاؤ برآمد;
	}
	اگر ((r = impl->funcs->serialize_نجی(کلید, b, opts)) != 0)
		جاؤ برآمد;

	/*
	 * success (but we still need to append the output to buf after
	 * possibly re-shielding the private key)
	 */
	r = 0;
 برآمد:
	اگر (was_shielded)
		r = sshkey_shield_نجی(کلید);
	اگر (r == 0)
		r = sshbuf_putb(buf, b);
	sshbuf_free(b);

	واپس r;
}

صحیح
sshkey_نجی_serialize(ساخت sshkey *کلید, ساخت sshbuf *b)
{
	واپس sshkey_نجی_serialize_opt(کلید, b,
	    SSHKEY_SERIALIZE_DEFAULT);
}


/* Shared deserialization of FIDO private key components */
صحیح
sshkey_نجی_deserialize_sk(ساخت sshbuf *buf, ساخت sshkey *k)
{
	صحیح r;

	اگر ((k->sk_کلید_handle = sshbuf_new()) == تہی ||
	    (k->sk_reserved = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_get_cstring(buf, &k->sk_application, تہی)) != 0 ||
	    (r = sshbuf_get_u8(buf, &k->sk_flags)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_کلید_handle)) != 0 ||
	    (r = sshbuf_get_stringb(buf, k->sk_reserved)) != 0)
		واپس r;

	واپس 0;
}

صحیح
sshkey_نجی_deserialize(ساخت sshbuf *buf, ساخت sshkey **kp)
{
	ثابت ساخت sshkey_impl *impl;
	حرف *tname = تہی;
	حرف *expect_sk_application = تہی;
	u_char *expect_ed25519_pk = تہی;
	ساخت sshkey *k = تہی;
	صحیح type, r = SSH_ERR_اندرونی_ERROR;

	اگر (kp != تہی)
		*kp = تہی;
	اگر ((r = sshbuf_get_cstring(buf, &tname, تہی)) != 0)
		جاؤ برآمد;
	type = sshkey_type_from_name(tname);
	اگر (sshkey_type_is_cert(type)) {
		/*
		 * Certificate key private keys begin with the certificate
		 * itself. Make sure this matches the type of the enclosing
		 * private key.
		 */
		اگر ((r = sshkey_froms(buf, &k)) != 0)
			جاؤ برآمد;
		اگر (k->type != type) {
			r = SSH_ERR_کلید_CERT_MISMATCH;
			جاؤ برآمد;
		}
		/* For ECDSA keys, the group must match too */
		اگر (k->type == کلید_ECDSA &&
		    k->ecdsa_nid != sshkey_ecdsa_nid_from_name(tname)) {
			r = SSH_ERR_کلید_CERT_MISMATCH;
			جاؤ برآمد;
		}
		/*
		 * Several fields are redundant between certificate and
		 * private key body, we require these to match.
		 */
		expect_sk_application = k->sk_application;
		expect_ed25519_pk = k->ed25519_pk;
		k->sk_application = تہی;
		k->ed25519_pk = تہی;
	} ورنہ {
		اگر ((k = sshkey_new(type)) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
	}
	اگر ((impl = sshkey_impl_from_type(type)) == تہی) {
		r = SSH_ERR_اندرونی_ERROR;
		جاؤ برآمد;
	}
	اگر ((r = impl->funcs->deserialize_نجی(tname, buf, k)) != 0)
		جاؤ برآمد;

	اگر ((expect_sk_application != تہی && (k->sk_application == تہی ||
	    strcmp(expect_sk_application, k->sk_application) != 0)) ||
	    (expect_ed25519_pk != تہی && (k->ed25519_pk == تہی ||
	    memcmp(expect_ed25519_pk, k->ed25519_pk, ED25519_PK_SZ) != 0))) {
		r = SSH_ERR_کلید_CERT_MISMATCH;
		جاؤ برآمد;
	}
	/* success */
	r = 0;
	اگر (kp != تہی) {
		*kp = k;
		k = تہی;
	}
 برآمد:
	آزاد(tname);
	sshkey_free(k);
	آزاد(expect_sk_application);
	آزاد(expect_ed25519_pk);
	واپس r;
}

#اگر_تعریف_شدہ WITH_OPENSSL
صحیح
sshkey_ec_validate_عوامی(ثابت EC_گروہ *گروہ, ثابت EC_نقطہ *عوامی)
{
	EC_نقطہ *nq = تہی;
	BIGNUM *ترتیب = تہی, *cofactor = تہی;
	صحیح ret = SSH_ERR_کلید_INVALID_EC_قدر;

	/*
	 * NB. This assumes OpenSSL has already verified that the public
	 * point lies on the curve and that its coordinates are in [0, p).
	 * This is done by EC_POINT_oct2point() on at least OpenSSL >= 1.1,
	 * LibreSSL and BoringSSL.
	 */

	/* Q != infinity */
	اگر (EC_نقطہ_is_at_infinity(گروہ, عوامی))
		جاؤ برآمد;

	اگر ((cofactor = BN_new()) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (EC_گروہ_get_cofactor(گروہ, cofactor, تہی) != 1)
		جاؤ برآمد;

	/*
	 * Verify nQ == infinity (n == order of subgroup)
	 * This check may be skipped for curves with cofactor 1, as per
	 * NIST SP 800-56A, 5.6.2.3.
	 */
	اگر (!BN_is_one(cofactor)) {
		اگر ((ترتیب = BN_new()) == تہی) {
			ret = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		اگر (EC_گروہ_get_ترتیب(گروہ, ترتیب, تہی) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			جاؤ برآمد;
		}
		اگر ((nq = EC_نقطہ_new(گروہ)) == تہی) {
			ret = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		اگر (EC_نقطہ_mul(گروہ, nq, تہی, عوامی, ترتیب, تہی) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			جاؤ برآمد;
		}
		اگر (EC_نقطہ_is_at_infinity(گروہ, nq) != 1)
			جاؤ برآمد;
	}

	/* success */
	ret = 0;
 برآمد:
	BN_clear_free(cofactor);
	BN_clear_free(ترتیب);
	EC_نقطہ_free(nq);
	واپس ret;
}

صحیح
sshkey_ec_validate_نجی(ثابت EC_کلید *کلید)
{
	BIGNUM *ترتیب = تہی, *tmp = تہی;
	صحیح ret = SSH_ERR_کلید_INVALID_EC_قدر;

	اگر ((ترتیب = BN_new()) == تہی || (tmp = BN_new()) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}

	/* log2(private) > log2(order)/2 */
	اگر (EC_گروہ_get_ترتیب(EC_کلید_get0_گروہ(کلید), ترتیب, تہی) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	اگر (BN_عدد_بٹ(EC_کلید_get0_نجی_کلید(کلید)) <=
	    BN_عدد_بٹ(ترتیب) / 2)
		جاؤ برآمد;

	/* private < order - 1 */
	اگر (!BN_sub(tmp, ترتیب, BN_قدر_one())) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	اگر (BN_cmp(EC_کلید_get0_نجی_کلید(کلید), tmp) >= 0)
		جاؤ برآمد;
	ret = 0;
 برآمد:
	BN_clear_free(ترتیب);
	BN_clear_free(tmp);
	واپس ret;
}

خالی
sshkey_dump_ec_نقطہ(ثابت EC_گروہ *گروہ, ثابت EC_نقطہ *نقطہ)
{
	BIGNUM *x = تہی, *y = تہی;

	اگر (نقطہ == تہی) {
		fputs("point=(NULL)\n", stderr);
		واپس;
	}
	اگر ((x = BN_new()) == تہی || (y = BN_new()) == تہی) {
		fprintf(stderr, "%s: BN_new failed\n", __func__);
		جاؤ برآمد;
	}
	اگر (EC_نقطہ_get_affine_coordinates(گروہ, نقطہ, x, y, تہی) != 1) {
		fprintf(stderr, "%s: EC_POINT_get_affine_coordinates\n",
		    __func__);
		جاؤ برآمد;
	}
	fputs("x=", stderr);
	BN_print_fp(stderr, x);
	fputs("\ny=", stderr);
	BN_print_fp(stderr, y);
	fputs("\n", stderr);
 برآمد:
	BN_clear_free(x);
	BN_clear_free(y);
}

خالی
sshkey_dump_ec_کلید(ثابت EC_کلید *کلید)
{
	ثابت BIGNUM *exponent;

	sshkey_dump_ec_نقطہ(EC_کلید_get0_گروہ(کلید),
	    EC_کلید_get0_عوامی_کلید(کلید));
	fputs("exponent=", stderr);
	اگر ((exponent = EC_کلید_get0_نجی_کلید(کلید)) == تہی)
		fputs("(NULL)", stderr);
	ورنہ
		BN_print_fp(stderr, EC_کلید_get0_نجی_کلید(کلید));
	fputs("\n", stderr);
}
#اگر_ختم /* WITH_OPENSSL */

ساکن صحیح
sshkey_نجی_مقصد_blob2(ساخت sshkey *prv, ساخت sshbuf *blob,
    ثابت حرف *passphrase, ثابت حرف *comment, ثابت حرف *ciphername,
    صحیح دور)
{
	u_char *cp, *کلید = تہی, *pubkeyblob = تہی;
	u_char salt[SALT_LEN];
	سائز_t i, pubkeylen, keylen, ivlen, blocksize, authlen;
	u_int check;
	صحیح r = SSH_ERR_اندرونی_ERROR;
	ساخت sshcipher_ctx *ciphercontext = تہی;
	ثابت ساخت sshcipher *cipher;
	ثابت حرف *kdfname = KDFNAME;
	ساخت sshbuf *encoded = تہی, *encrypted = تہی, *kdf = تہی;

	اگر (دور <= 0)
		دور = DEFAULT_دور;
	اگر (دور > MAX_KDF_دور) {
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	اگر (passphrase == تہی || !لڑی_لمبائی(passphrase)) {
		ciphername = "none";
		kdfname = "none";
	} ورنہ اگر (ciphername == تہی)
		ciphername = DEFAULT_CIPHERNAME;
	اگر ((cipher = cipher_by_name(ciphername)) == تہی) {
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}

	اگر ((kdf = sshbuf_new()) == تہی ||
	    (encoded = sshbuf_new()) == تہی ||
	    (encrypted = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	blocksize = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	اگر ((کلید = صفر_حافظہ_دو(1, keylen + ivlen)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (strcmp(kdfname, "bcrypt") == 0) {
		arc4random_buf(salt, SALT_LEN);
		اگر (bcrypt_pbkdf(passphrase, لڑی_لمبائی(passphrase),
		    salt, SALT_LEN, کلید, keylen + ivlen, دور) < 0) {
			r = SSH_ERR_INVALID_دلیل;
			جاؤ برآمد;
		}
		اگر ((r = sshbuf_put_string(kdf, salt, SALT_LEN)) != 0 ||
		    (r = sshbuf_put_u32(kdf, دور)) != 0)
			جاؤ برآمد;
	} ورنہ اگر (strcmp(kdfname, "none") != 0) {
		/* Unsupported KDF type */
		r = SSH_ERR_کلید_UNKNOWN_CIPHER;
		جاؤ برآمد;
	}
	اگر ((r = cipher_init(&ciphercontext, cipher, کلید, keylen,
	    کلید + keylen, ivlen, 1)) != 0)
		جاؤ برآمد;

	اگر ((r = sshbuf_put(encoded, AUTH_MAGIC, حجم(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_put_cstring(encoded, ciphername)) != 0 ||
	    (r = sshbuf_put_cstring(encoded, kdfname)) != 0 ||
	    (r = sshbuf_put_stringb(encoded, kdf)) != 0 ||
	    (r = sshbuf_put_u32(encoded, 1)) != 0 ||	/* number of keys */
	    (r = sshkey_مقصد_blob(prv, &pubkeyblob, &pubkeylen)) != 0 ||
	    (r = sshbuf_put_string(encoded, pubkeyblob, pubkeylen)) != 0)
		جاؤ برآمد;

	/* set up the buffer that will be encrypted */

	/* Random check bytes */
	check = arc4random();
	اگر ((r = sshbuf_put_u32(encrypted, check)) != 0 ||
	    (r = sshbuf_put_u32(encrypted, check)) != 0)
		جاؤ برآمد;

	/* append private key and comment*/
	اگر ((r = sshkey_نجی_serialize(prv, encrypted)) != 0 ||
	    (r = sshbuf_put_cstring(encrypted, comment)) != 0)
		جاؤ برآمد;

	/* padding */
	i = 0;
	جب (sshbuf_len(encrypted) % blocksize) {
		اگر ((r = sshbuf_put_u8(encrypted, ++i & 0xff)) != 0)
			جاؤ برآمد;
	}

	/* length in destination buffer */
	اگر ((r = sshbuf_put_u32(encoded, sshbuf_len(encrypted))) != 0)
		جاؤ برآمد;

	/* encrypt */
	اگر ((r = sshbuf_reserve(encoded,
	    sshbuf_len(encrypted) + authlen, &cp)) != 0)
		جاؤ برآمد;
	اگر ((r = cipher_crypt(ciphercontext, 0, cp,
	    sshbuf_ptr(encrypted), sshbuf_len(encrypted), 0, authlen)) != 0)
		جاؤ برآمد;

	sshbuf_reset(blob);

	/* assemble uuencoded key */
	اگر ((r = sshbuf_put(blob, MARK_BEGIN, MARK_BEGIN_LEN)) != 0 ||
	    (r = sshbuf_dtob64(encoded, blob, 1)) != 0 ||
	    (r = sshbuf_put(blob, MARK_انتہا, MARK_انتہا_LEN)) != 0)
		جاؤ برآمد;

	/* success */
	r = 0;

 برآمد:
	sshbuf_free(kdf);
	sshbuf_free(encoded);
	sshbuf_free(encrypted);
	cipher_free(ciphercontext);
	explicit_bzero(salt, حجم(salt));
	اگر (کلید != تہی)
		freezero(کلید, keylen + ivlen);
	اگر (pubkeyblob != تہی)
		freezero(pubkeyblob, pubkeylen);
	واپس r;
}

ساکن صحیح
private2_uudecode(ساخت sshbuf *blob, ساخت sshbuf **decodedp)
{
	ثابت u_char *cp;
	سائز_t encoded_len;
	صحیح r;
	u_char آخری;
	ساخت sshbuf *encoded = تہی, *decoded = تہی;

	اگر (blob == تہی || decodedp == تہی)
		واپس SSH_ERR_INVALID_دلیل;

	*decodedp = تہی;

	اگر ((encoded = sshbuf_new()) == تہی ||
	    (decoded = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}

	/* check preamble */
	cp = sshbuf_ptr(blob);
	encoded_len = sshbuf_len(blob);
	اگر (encoded_len < (MARK_BEGIN_LEN + MARK_انتہا_LEN) ||
	    memcmp(cp, MARK_BEGIN, MARK_BEGIN_LEN) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	cp += MARK_BEGIN_LEN;
	encoded_len -= MARK_BEGIN_LEN;

	/* Look for end marker, removing whitespace as we go */
	جب (encoded_len > 0) {
		اگر (*cp != '\n' && *cp != '\r') {
			اگر ((r = sshbuf_put_u8(encoded, *cp)) != 0)
				جاؤ برآمد;
		}
		آخری = *cp;
		encoded_len--;
		cp++;
		اگر (آخری == '\n') {
			اگر (encoded_len >= MARK_انتہا_LEN &&
			    memcmp(cp, MARK_انتہا, MARK_انتہا_LEN) == 0) {
				/* \0 terminate */
				اگر ((r = sshbuf_put_u8(encoded, 0)) != 0)
					جاؤ برآمد;
				توڑو;
			}
		}
	}
	اگر (encoded_len == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}

	/* decode base64 */
	اگر ((r = sshbuf_b64tod(decoded, (حرف *)sshbuf_ptr(encoded))) != 0)
		جاؤ برآمد;

	/* check magic */
	اگر (sshbuf_len(decoded) < حجم(AUTH_MAGIC) ||
	    memcmp(sshbuf_ptr(decoded), AUTH_MAGIC, حجم(AUTH_MAGIC))) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	/* success */
	*decodedp = decoded;
	decoded = تہی;
	r = 0;
 برآمد:
	sshbuf_free(encoded);
	sshbuf_free(decoded);
	واپس r;
}

ساکن صحیح
private2_decrypt(ساخت sshbuf *decoded, ثابت حرف *passphrase,
    ساخت sshbuf **decryptedp, ساخت sshkey **pubkeyp)
{
	حرف *ciphername = تہی, *kdfname = تہی;
	ثابت ساخت sshcipher *cipher = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;
	سائز_t keylen = 0, ivlen = 0, authlen = 0, slen = 0;
	ساخت sshbuf *kdf = تہی, *decrypted = تہی;
	ساخت sshcipher_ctx *ciphercontext = تہی;
	ساخت sshkey *pubkey = تہی;
	u_char *کلید = تہی, *salt = تہی, *dp;
	u_int blocksize, دور, nkeys, encrypted_len, check1, check2;

	اگر (decoded == تہی || decryptedp == تہی || pubkeyp == تہی)
		واپس SSH_ERR_INVALID_دلیل;

	*decryptedp = تہی;
	*pubkeyp = تہی;

	اگر ((decrypted = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}

	/* parse public portion of key */
	اگر ((r = sshbuf_consume(decoded, حجم(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &ciphername, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(decoded, &kdfname, تہی)) != 0 ||
	    (r = sshbuf_froms(decoded, &kdf)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		جاؤ برآمد;

	اگر (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}

	اگر ((r = sshkey_froms(decoded, &pubkey)) != 0 ||
	    (r = sshbuf_get_u32(decoded, &encrypted_len)) != 0)
		جاؤ برآمد;

	اگر ((cipher = cipher_by_name(ciphername)) == تہی) {
		r = SSH_ERR_کلید_UNKNOWN_CIPHER;
		جاؤ برآمد;
	}
	اگر (strcmp(kdfname, "none") != 0 && strcmp(kdfname, "bcrypt") != 0) {
		r = SSH_ERR_کلید_UNKNOWN_CIPHER;
		جاؤ برآمد;
	}
	اگر (strcmp(kdfname, "none") == 0 && strcmp(ciphername, "none") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر ((passphrase == تہی || لڑی_لمبائی(passphrase) == 0) &&
	    strcmp(kdfname, "none") != 0) {
		/* passphrase required */
		r = SSH_ERR_کلید_WRONG_PASSPHRASE;
		جاؤ برآمد;
	}

	/* check size of encrypted key blob */
	blocksize = cipher_blocksize(cipher);
	اگر (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}

	/* setup key */
	keylen = cipher_keylen(cipher);
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	اگر ((کلید = صفر_حافظہ_دو(1, keylen + ivlen)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (strcmp(kdfname, "bcrypt") == 0) {
		اگر ((r = sshbuf_get_string(kdf, &salt, &slen)) != 0 ||
		    (r = sshbuf_get_u32(kdf, &دور)) != 0)
			جاؤ برآمد;
		اگر (دور > MAX_KDF_دور) {
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		اگر (bcrypt_pbkdf(passphrase, لڑی_لمبائی(passphrase), salt, slen,
		    کلید, keylen + ivlen, دور) < 0) {
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
	}

	/* check that an appropriate amount of auth data is present */
	اگر (sshbuf_len(decoded) < authlen ||
	    sshbuf_len(decoded) - authlen < encrypted_len) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}

	/* decrypt private portion of key */
	اگر ((r = sshbuf_reserve(decrypted, encrypted_len, &dp)) != 0 ||
	    (r = cipher_init(&ciphercontext, cipher, کلید, keylen,
	    کلید + keylen, ivlen, 0)) != 0)
		جاؤ برآمد;
	اگر ((r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(decoded),
	    encrypted_len, 0, authlen)) != 0) {
		/* an integrity error here indicates an incorrect passphrase */
		اگر (r == SSH_ERR_MAC_INVALID)
			r = SSH_ERR_کلید_WRONG_PASSPHRASE;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_consume(decoded, encrypted_len + authlen)) != 0)
		جاؤ برآمد;
	/* there should be no trailing data */
	اگر (sshbuf_len(decoded) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}

	/* check check bytes */
	اگر ((r = sshbuf_get_u32(decrypted, &check1)) != 0 ||
	    (r = sshbuf_get_u32(decrypted, &check2)) != 0)
		جاؤ برآمد;
	اگر (check1 != check2) {
		r = SSH_ERR_کلید_WRONG_PASSPHRASE;
		جاؤ برآمد;
	}
	/* success */
	*decryptedp = decrypted;
	decrypted = تہی;
	*pubkeyp = pubkey;
	pubkey = تہی;
	r = 0;
 برآمد:
	cipher_free(ciphercontext);
	آزاد(ciphername);
	آزاد(kdfname);
	sshkey_free(pubkey);
	اگر (salt != تہی) {
		explicit_bzero(salt, slen);
		آزاد(salt);
	}
	اگر (کلید != تہی) {
		explicit_bzero(کلید, keylen + ivlen);
		آزاد(کلید);
	}
	sshbuf_free(kdf);
	sshbuf_free(decrypted);
	واپس r;
}

ساکن صحیح
sshkey_parse_private2(ساخت sshbuf *blob, صحیح type, ثابت حرف *passphrase,
    ساخت sshkey **keyp, حرف **commentp)
{
	حرف *comment = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;
	ساخت sshbuf *decoded = تہی, *decrypted = تہی;
	ساخت sshkey *k = تہی, *pubkey = تہی;

	اگر (keyp != تہی)
		*keyp = تہی;
	اگر (commentp != تہی)
		*commentp = تہی;

	/* Undo base64 encoding and decrypt the private section */
	اگر ((r = private2_uudecode(blob, &decoded)) != 0 ||
	    (r = private2_decrypt(decoded, passphrase,
	    &decrypted, &pubkey)) != 0)
		جاؤ برآمد;

	اگر (type != کلید_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_کلید_TYPE_MISMATCH;
		جاؤ برآمد;
	}

	/* Load the private key and comment */
	اگر ((r = sshkey_نجی_deserialize(decrypted, &k)) != 0 ||
	    (r = sshbuf_get_cstring(decrypted, &comment, تہی)) != 0)
		جاؤ برآمد;

	/* Check deterministic padding after private section */
	اگر ((r = private2_check_padding(decrypted)) != 0)
		جاؤ برآمد;

	/* Check that the public key in the envelope matches the private key */
	اگر (!sshkey_equal(pubkey, k)) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}

	/* success */
	r = 0;
	اگر (keyp != تہی) {
		*keyp = k;
		k = تہی;
	}
	اگر (commentp != تہی) {
		*commentp = comment;
		comment = تہی;
	}
 برآمد:
	آزاد(comment);
	sshbuf_free(decoded);
	sshbuf_free(decrypted);
	sshkey_free(k);
	sshkey_free(pubkey);
	واپس r;
}

ساکن صحیح
sshkey_parse_private2_pubkey(ساخت sshbuf *blob, صحیح type,
    ساخت sshkey **keyp)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;
	ساخت sshbuf *decoded = تہی;
	ساخت sshkey *pubkey = تہی;
	u_int nkeys = 0;

	اگر (keyp != تہی)
		*keyp = تہی;

	اگر ((r = private2_uudecode(blob, &decoded)) != 0)
		جاؤ برآمد;
	/* parse public key from unencrypted envelope */
	اگر ((r = sshbuf_consume(decoded, حجم(AUTH_MAGIC))) != 0 ||
	    (r = sshbuf_skip_string(decoded)) != 0 || /* cipher */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF alg */
	    (r = sshbuf_skip_string(decoded)) != 0 || /* KDF hint */
	    (r = sshbuf_get_u32(decoded, &nkeys)) != 0)
		جاؤ برآمد;

	اگر (nkeys != 1) {
		/* XXX only one key supported at present */
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}

	/* Parse the public key */
	اگر ((r = sshkey_froms(decoded, &pubkey)) != 0)
		جاؤ برآمد;

	اگر (type != کلید_UNSPEC &&
	    sshkey_type_plain(type) != sshkey_type_plain(pubkey->type)) {
		r = SSH_ERR_کلید_TYPE_MISMATCH;
		جاؤ برآمد;
	}

	/* success */
	r = 0;
	اگر (keyp != تہی) {
		*keyp = pubkey;
		pubkey = تہی;
	}
 برآمد:
	sshbuf_free(decoded);
	sshkey_free(pubkey);
	واپس r;
}

#اگر_تعریف_شدہ WITH_OPENSSL
/* convert SSH v2 key to PEM or PKCS#8 format */
ساکن صحیح
sshkey_نجی_مقصد_blob_pem_pkcs8(ساخت sshkey *کلید, ساخت sshbuf *buf,
    صحیح format, ثابت حرف *_passphrase, ثابت حرف *comment)
{
	صحیح was_shielded = sshkey_is_shielded(کلید);
	صحیح success, r;
	صحیح blen, len = لڑی_لمبائی(_passphrase);
	u_char *passphrase = (len > 0) ? (u_char *)_passphrase : تہی;
	ثابت EVP_CIPHER *cipher = (len > 0) ? EVP_aes_128_cbc() : تہی;
	حرف *bptr;
	BIO *bio = تہی;
	ساخت sshbuf *blob;
	EVP_PKEY *pkey = تہی;

	اگر (len > 0 && len <= 4)
		واپس SSH_ERR_PASSPHRASE_TOO_SHORT;
	اگر ((blob = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((bio = BIO_new(BIO_s_mem())) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshkey_unshield_نجی(کلید)) != 0)
		جاؤ برآمد;

	انتخاب (کلید->type) {
	حالت کلید_ECDSA:
		اگر (format == SSHKEY_نجی_PEM) {
			success = PEM_write_bio_ECPrivate_کلید(bio,
			    EVP_PKEY_get0_EC_کلید(کلید->pkey),
			    cipher, passphrase, len, تہی, تہی);
		} ورنہ {
			pkey = کلید->pkey;
			EVP_PKEY_اوپر_ref(کلید->pkey);
			success = 1;
		}
		توڑو;
	حالت کلید_RSA:
		اگر (format == SSHKEY_نجی_PEM) {
			success = PEM_write_bio_RSAPrivate_کلید(bio,
			    EVP_PKEY_get0_RSA(کلید->pkey),
			    cipher, passphrase, len, تہی, تہی);
		} ورنہ {
			pkey = کلید->pkey;
			EVP_PKEY_اوپر_ref(کلید->pkey);
			success = 1;
		}
		توڑو;
#اگر_تعریف_شدہ OPENSSL_HAS_ED25519
	حالت کلید_ED25519:
		اگر (format == SSHKEY_نجی_PEM) {
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		} ورنہ {
			pkey = EVP_PKEY_new_raw_نجی_کلید(EVP_PKEY_ED25519,
			    تہی, کلید->ed25519_sk,
			    ED25519_SK_SZ - ED25519_PK_SZ);
			success = pkey != تہی;
		}
		توڑو;
#اگر_ختم
	طےشدہ:
		success = 0;
		توڑو;
	}
	اگر (success == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	اگر (format == SSHKEY_نجی_PKCS8) {
		اگر ((success = PEM_write_bio_نجی_کلید(bio, pkey, cipher,
		    passphrase, len, تہی, تہی)) == 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			جاؤ برآمد;
		}
	}
	اگر ((blen = BIO_get_mem_ڈیٹا(bio, &bptr)) <= 0) {
		r = SSH_ERR_اندرونی_ERROR;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put(blob, bptr, blen)) != 0)
		جاؤ برآمد;
	r = 0;
 برآمد:
	اگر (was_shielded)
		r = sshkey_shield_نجی(کلید);
	اگر (r == 0)
		r = sshbuf_putb(buf, blob);

	EVP_PKEY_free(pkey);
	sshbuf_free(blob);
	BIO_free(bio);
	واپس r;
}
#اگر_ختم /* WITH_OPENSSL */

/* Serialise "key" to buffer "blob" */
صحیح
sshkey_نجی_مقصد_fileblob(ساخت sshkey *کلید, ساخت sshbuf *blob,
    ثابت حرف *passphrase, ثابت حرف *comment,
    صحیح format, ثابت حرف *openssh_format_cipher, صحیح openssh_format_دور)
{
	انتخاب (کلید->type) {
#اگر_تعریف_شدہ WITH_OPENSSL
	حالت کلید_ECDSA:
	حالت کلید_RSA:
	حالت کلید_ED25519:
		توڑو; /* see below */
#ورنہ /* WITH_OPENSSL */
	حالت کلید_ED25519:
#اگر_ختم /* WITH_OPENSSL */
	حالت کلید_ED25519_SK:
#اگر_تعریف_شدہ WITH_OPENSSL
	حالت کلید_ECDSA_SK:
#اگر_ختم /* WITH_OPENSSL */
	حالت کلید_MLDSA44_ED25519:
		واپس sshkey_نجی_مقصد_blob2(کلید, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_دور);
	طےشدہ:
		واپس SSH_ERR_کلید_TYPE_UNKNOWN;
	}

#اگر_تعریف_شدہ WITH_OPENSSL
	انتخاب (format) {
	حالت SSHKEY_نجی_OPENSSH:
		واپس sshkey_نجی_مقصد_blob2(کلید, blob, passphrase,
		    comment, openssh_format_cipher, openssh_format_دور);
	حالت SSHKEY_نجی_PEM:
	حالت SSHKEY_نجی_PKCS8:
		واپس sshkey_نجی_مقصد_blob_pem_pkcs8(کلید, blob,
		    format, passphrase, comment);
	طےشدہ:
		واپس SSH_ERR_INVALID_دلیل;
	}
#اگر_ختم /* WITH_OPENSSL */
}

#اگر_تعریف_شدہ WITH_OPENSSL
ساکن صحیح
translate_libcrypto_error(غیرعلامتی طویل pem_err)
{
	صحیح pem_reason = ERR_GET_REASON(pem_err);

	انتخاب (ERR_GET_LIB(pem_err)) {
	حالت ERR_LIB_PEM:
		انتخاب (pem_reason) {
		حالت PEM_R_BAD_PASSWORD_READ:
#اگر_تعریف_شدہ PEM_R_PROBLEMS_GETTING_PASSWORD
		حالت PEM_R_PROBLEMS_GETTING_PASSWORD:
#اگر_ختم
#اگر_تعریف_شدہ PEM_R_BAD_DECRYPT
		حالت PEM_R_BAD_DECRYPT:
#اگر_ختم
			واپس SSH_ERR_کلید_WRONG_PASSPHRASE;
		طےشدہ:
			واپس SSH_ERR_INVALID_FORMAT;
		}
	حالت ERR_LIB_EVP:
		انتخاب (pem_reason) {
#اگر_تعریف_شدہ EVP_R_BAD_DECRYPT
		حالت EVP_R_BAD_DECRYPT:
			واپس SSH_ERR_کلید_WRONG_PASSPHRASE;
#اگر_ختم
#اگر_تعریف_شدہ EVP_R_BN_DECODE_ERROR
		حالت EVP_R_BN_DECODE_ERROR:
#اگر_ختم
		حالت EVP_R_DECODE_ERROR:
#اگر_تعریف_شدہ EVP_R_نجی_کلید_DECODE_ERROR
		حالت EVP_R_نجی_کلید_DECODE_ERROR:
#اگر_ختم
			واپس SSH_ERR_INVALID_FORMAT;
		طےشدہ:
			واپس SSH_ERR_LIBCRYPTO_ERROR;
		}
	حالت ERR_LIB_ASN1:
#اگر_تعریف_شدہ ERR_LIB_OSSL_DECODER
	حالت ERR_LIB_OSSL_DECODER:
#اگر_ختم
		واپس SSH_ERR_INVALID_FORMAT;
	}
	واپس SSH_ERR_LIBCRYPTO_ERROR;
}

ساکن خالی
clear_libcrypto_errors(خالی)
{
	جب (ERR_get_error() != 0)
		;
}

/*
 * Translate OpenSSL error codes to determine whether
 * passphrase is required/incorrect.
 */
ساکن صحیح
convert_libcrypto_error(خالی)
{
	/*
	 * Some password errors are reported at the beginning
	 * of the error queue.
	 */
	اگر (translate_libcrypto_error(ERR_peek_error()) ==
	    SSH_ERR_کلید_WRONG_PASSPHRASE)
		واپس SSH_ERR_کلید_WRONG_PASSPHRASE;
	واپس translate_libcrypto_error(ERR_peek_آخری_error());
}

ساکن صحیح
pem_passphrase_cb(حرف *buf, صحیح سائز, صحیح rwflag, خالی *u)
{
	حرف *p = (حرف *)u;
	سائز_t len;

	اگر (p == تہی || (len = لڑی_لمبائی(p)) == 0)
		واپس -1;
	اگر (سائز < 0 || len > (سائز_t)سائز)
		واپس -1;
	حافظہ_نقل(buf, p, len);
	واپس (صحیح)len;
}

ساکن صحیح
sshkey_parse_نجی_pem_fileblob(ساخت sshbuf *blob, صحیح type,
    ثابت حرف *passphrase, ساخت sshkey **keyp)
{
	EVP_PKEY *pk = تہی;
	ساخت sshkey *prv = تہی;
	BIO *bio = تہی;
	صحیح r;
	RSA *rsa = تہی;
	EC_کلید *ecdsa = تہی;

	اگر (keyp != تہی)
		*keyp = تہی;

	اگر ((bio = BIO_new(BIO_s_mem())) == تہی || sshbuf_len(blob) > زیادہ_سے_زیادہ_عدد)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر (BIO_write(bio, sshbuf_ptr(blob), sshbuf_len(blob)) !=
	    (صحیح)sshbuf_len(blob)) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}

	clear_libcrypto_errors();
	اگر ((pk = PEM_read_bio_نجی_کلید(bio, تہی, pem_passphrase_cb,
	    (حرف *)passphrase)) == تہی) {
		/*
		 * libcrypto may return various ASN.1 errors when attempting
		 * to parse a key with an incorrect passphrase.
		 * Treat all format errors as "incorrect passphrase" if a
		 * passphrase was supplied.
		 */
		اگر (passphrase != تہی && *passphrase != '\0')
			r = SSH_ERR_کلید_WRONG_PASSPHRASE;
		ورنہ
			r = convert_libcrypto_error();
		جاؤ برآمد;
	}
	اگر (EVP_PKEY_بنیاد_id(pk) == EVP_PKEY_RSA &&
	    (type == کلید_UNSPEC || type == کلید_RSA)) {
		اگر ((prv = sshkey_new(کلید_UNSPEC)) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		اگر ((rsa = EVP_PKEY_get1_RSA(pk)) == تہی) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			جاؤ برآمد;
		}
		prv->type = کلید_RSA;
#اگر_تعریف_شدہ DEBUG_PK
		RSA_print_fp(stderr, rsa, 8);
#اگر_ختم
		اگر (RSA_blinding_on(rsa, تہی) != 1 ||
		    EVP_PKEY_set1_RSA(pk, rsa) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			جاؤ برآمد;
		}
		EVP_PKEY_اوپر_ref(pk);
		prv->pkey = pk;
		اگر ((r = sshkey_check_rsa_لمبائی(prv, 0)) != 0)
			جاؤ برآمد;
	} ورنہ اگر (EVP_PKEY_بنیاد_id(pk) == EVP_PKEY_EC &&
	    (type == کلید_UNSPEC || type == کلید_ECDSA)) {
		اگر ((prv = sshkey_new(کلید_UNSPEC)) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		اگر ((prv->ecdsa_nid = sshkey_ecdsa_fixup_گروہ(pk)) == -1 ||
		    (ecdsa = EVP_PKEY_get1_EC_کلید(pk)) == تہی) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			جاؤ برآمد;
		}
		prv->type = کلید_ECDSA;
		اگر (sshkey_خم_nid_مقصد_name(prv->ecdsa_nid) == تہی ||
		    sshkey_ec_validate_عوامی(EC_کلید_get0_گروہ(ecdsa),
		    EC_کلید_get0_عوامی_کلید(ecdsa)) != 0 ||
		    sshkey_ec_validate_نجی(ecdsa) != 0) {
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		EVP_PKEY_اوپر_ref(pk);
		prv->pkey = pk;
#اگر_تعریف_شدہ DEBUG_PK
		اگر (prv != تہی && prv->pkey != تہی)
			sshkey_dump_ec_کلید(EVP_PKEY_get0_EC_کلید(prv->pkey));
#اگر_ختم
#اگر_تعریف_شدہ OPENSSL_HAS_ED25519
	} ورنہ اگر (EVP_PKEY_بنیاد_id(pk) == EVP_PKEY_ED25519 &&
	    (type == کلید_UNSPEC || type == کلید_ED25519)) {
		سائز_t len;

		اگر ((prv = sshkey_new(کلید_UNSPEC)) == تہی ||
		    (prv->ed25519_sk = صفر_حافظہ_دو(1, ED25519_SK_SZ)) == تہی ||
		    (prv->ed25519_pk = صفر_حافظہ_دو(1, ED25519_PK_SZ)) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		prv->type = کلید_ED25519;
		len = ED25519_PK_SZ;
		اگر (!EVP_PKEY_get_raw_عوامی_کلید(pk, prv->ed25519_pk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			جاؤ برآمد;
		}
		اگر (len != ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		len = ED25519_SK_SZ - ED25519_PK_SZ;
		اگر (!EVP_PKEY_get_raw_نجی_کلید(pk, prv->ed25519_sk, &len)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			جاؤ برآمد;
		}
		اگر (len != ED25519_SK_SZ - ED25519_PK_SZ) {
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		/* Append the public key to our private key */
		حافظہ_نقل(prv->ed25519_sk + (ED25519_SK_SZ - ED25519_PK_SZ),
		    prv->ed25519_pk, ED25519_PK_SZ);
#اگر_تعریف_شدہ DEBUG_PK
		sshbuf_dump_ڈیٹا(prv->ed25519_sk, ED25519_SK_SZ, stderr);
#اگر_ختم
#اگر_ختم /* OPENSSL_HAS_ED25519 */
	} ورنہ {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	r = 0;
	اگر (keyp != تہی) {
		*keyp = prv;
		prv = تہی;
	}
 برآمد:
	BIO_free(bio);
	EVP_PKEY_free(pk);
	RSA_free(rsa);
	EC_کلید_free(ecdsa);
	sshkey_free(prv);
	واپس r;
}
#اگر_ختم /* WITH_OPENSSL */

صحیح
sshkey_parse_نجی_fileblob_type(ساخت sshbuf *blob, صحیح type,
    ثابت حرف *passphrase, ساخت sshkey **keyp, حرف **commentp)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;

	اگر (keyp != تہی)
		*keyp = تہی;
	اگر (commentp != تہی)
		*commentp = تہی;

	r = sshkey_parse_private2(blob, type, passphrase, keyp, commentp);
	/* Only fallback to PEM parser if a format error occurred. */
	اگر (r != SSH_ERR_INVALID_FORMAT)
		واپس r;
#اگر_تعریف_شدہ WITH_OPENSSL
	واپس sshkey_parse_نجی_pem_fileblob(blob, type,
	    passphrase, keyp);
#ورنہ
	واپس SSH_ERR_INVALID_FORMAT;
#اگر_ختم /* WITH_OPENSSL */
}

صحیح
sshkey_parse_نجی_fileblob(ساخت sshbuf *بفر, ثابت حرف *passphrase,
    ساخت sshkey **keyp, حرف **commentp)
{
	اگر (keyp != تہی)
		*keyp = تہی;
	اگر (commentp != تہی)
		*commentp = تہی;

	واپس sshkey_parse_نجی_fileblob_type(بفر, کلید_UNSPEC,
	    passphrase, keyp, commentp);
}

خالی
sshkey_sig_details_free(ساخت sshkey_sig_details *details)
{
	freezero(details, حجم(*details));
}

صحیح
sshkey_parse_pubkey_from_نجی_fileblob_type(ساخت sshbuf *blob, صحیح type,
    ساخت sshkey **pubkeyp)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;

	اگر (pubkeyp != تہی)
		*pubkeyp = تہی;
	/* only new-format private keys bundle a public key inside */
	اگر ((r = sshkey_parse_private2_pubkey(blob, type, pubkeyp)) != 0)
		واپس r;
	واپس 0;
}
