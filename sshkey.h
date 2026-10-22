/* $OpenBSD: sshkey.h,v 1.75 2026/09/16 00:31:27 djm Exp $ */

/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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
#اگر_غیر_تعریف_شدہ SSHKEY_H
#تعریف_کرو SSHKEY_H

#شامل <sys/types.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/rsa.h>
#شامل <openssl/ec.h>
#شامل <openssl/ecdsa.h>
#شامل <openssl/evp.h>
#تعریف_کرو SSH_OPENSSL_نسخہ Open_SSL_نسخہ(OPENSSL_نسخہ)
#ورنہ /* OPENSSL */
#تعریف_کرو BIGNUM		خالی
#تعریف_کرو RSA		خالی
#تعریف_کرو EC_کلید		خالی
#تعریف_کرو EC_گروہ	خالی
#تعریف_کرو EC_نقطہ	خالی
#تعریف_کرو EVP_PKEY	خالی
#تعریف_کرو SSH_OPENSSL_نسخہ "without OpenSSL"
#اگر_ختم /* WITH_OPENSSL */

#تعریف_کرو SSH_RSA_MINIMUM_MODULUS_سائز	1024
#تعریف_کرو SSH_کلید_MAX_SIGN_ڈیٹا_سائز	(1 << 20)

ساخت sshbuf;

/* Key types */
شمار sshkey_types {
	کلید_RSA,
	کلید_ECDSA,
	کلید_ED25519,
	کلید_RSA_CERT,
	کلید_ECDSA_CERT,
	کلید_ED25519_CERT,
	کلید_ECDSA_SK,
	کلید_ECDSA_SK_CERT,
	کلید_ED25519_SK,
	کلید_ED25519_SK_CERT,
	کلید_MLDSA44_ED25519,
	کلید_MLDSA44_ED25519_CERT,
	کلید_UNSPEC
};

/* Default fingerprint hash */
#تعریف_کرو SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
شمار sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
شمار sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
شمار sshkey_نجی_format {
	SSHKEY_نجی_OPENSSH = 0,
	SSHKEY_نجی_PEM = 1,
	SSHKEY_نجی_PKCS8 = 2,
};

/* key is stored in external hardware */
#تعریف_کرو SSHKEY_FLAG_EXT		0x0001

#تعریف_کرو SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
ساخت sshkey_cert {
	ساخت sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	حرف		*کلید_id;
	u_int		 nprincipals;
	حرف		**principals;
	uint64_t	 valid_after, valid_before;
	ساخت sshbuf	*critical;
	ساخت sshbuf	*extensions;
	ساخت sshkey	*signature_کلید;
	حرف		*signature_type;
};

/* XXX opacify? */
ساخت sshkey {
	صحیح	 type;
	صحیح	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	صحیح	 ecdsa_nid;	/* NID of curve */
	/* libcrypto-backed keys */
	EVP_PKEY *pkey;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_MLDSA44_ED25519 */
	u_char	*mldsa_ed25519_sk;
	u_char	*mldsa_ed25519_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	حرف	*sk_application;
	uint8_t	sk_flags;
	ساخت sshbuf *sk_کلید_handle;
	ساخت sshbuf *sk_reserved;
	/* Certificates */
	ساخت sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_نجی;
	سائز_t	shielded_len;
	u_char	*shield_prekey;
	سائز_t	shield_prekey_len;
};

#تعریف_کرو	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#تعریف_کرو	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
ساخت sshkey_sig_details {
	uint32_t sk_شمار;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

ساخت sshkey_impl_funcs {
	u_int (*سائز)(ثابت ساخت sshkey *);	/* optional */
	صحیح (*alloc)(ساخت sshkey *);		/* optional */
	خالی (*cleanup)(ساخت sshkey *);	/* optional */
	صحیح (*equal)(ثابت ساخت sshkey *, ثابت ساخت sshkey *);
	صحیح (*serialize_عوامی)(ثابت ساخت sshkey *, ساخت sshbuf *,
	    شمار sshkey_serialize_rep);
	صحیح (*deserialize_عوامی)(ثابت حرف *, ساخت sshbuf *,
	    ساخت sshkey *);
	صحیح (*serialize_نجی)(ثابت ساخت sshkey *, ساخت sshbuf *,
	    شمار sshkey_serialize_rep);
	صحیح (*deserialize_نجی)(ثابت حرف *, ساخت sshbuf *,
	    ساخت sshkey *);
	صحیح (*generate)(ساخت sshkey *, صحیح);	/* optional */
	صحیح (*copy_عوامی)(ثابت ساخت sshkey *, ساخت sshkey *);
	صحیح (*sign)(ساخت sshkey *, u_char **, سائز_t *,
	    ثابت u_char *, سائز_t, ثابت حرف *,
	    ثابت حرف *, ثابت حرف *, u_int); /* optional */
	صحیح (*verify)(ثابت ساخت sshkey *, ثابت u_char *, سائز_t,
	    ثابت u_char *, سائز_t, ثابت حرف *, u_int,
	    ساخت sshkey_sig_details **);
};

ساخت sshkey_impl {
	ثابت حرف *name;
	ثابت حرف *shortname;
	ثابت حرف *sigalg;
	صحیح type;
	صحیح nid;
	صحیح cert;
	صحیح sigonly;
	صحیح keybits;
	ثابت ساخت sshkey_impl_funcs *funcs;
};

ساخت sshkey	*sshkey_new(صحیح);
خالی		 sshkey_free(ساخت sshkey *);
صحیح		 sshkey_equal_عوامی(ثابت ساخت sshkey *,
    ثابت ساخت sshkey *);
صحیح		 sshkey_equal(ثابت ساخت sshkey *, ثابت ساخت sshkey *);
حرف		*sshkey_fingerprint(ثابت ساخت sshkey *,
    صحیح, شمار sshkey_fp_rep);
صحیح		 sshkey_fingerprint_raw(ثابت ساخت sshkey *k,
    صحیح, u_char **retp, سائز_t *lenp);
ثابت حرف	*sshkey_type(ثابت ساخت sshkey *);
ثابت حرف	*sshkey_cert_type(ثابت ساخت sshkey *);
صحیح		 sshkey_format_متن(ثابت ساخت sshkey *, ساخت sshbuf *);
صحیح		 sshkey_write(ثابت ساخت sshkey *, FILE *);
صحیح		 sshkey_read(ساخت sshkey *, حرف **);
u_int		 sshkey_سائز(ثابت ساخت sshkey *);

صحیح		 sshkey_generate(صحیح type, u_int بٹ, ساخت sshkey **keyp);
صحیح		 sshkey_from_نجی(ثابت ساخت sshkey *, ساخت sshkey **);

صحیح		 sshkey_is_shielded(ساخت sshkey *);
صحیح		 sshkey_shield_نجی(ساخت sshkey *);
صحیح		 sshkey_unshield_نجی(ساخت sshkey *);

صحیح	 sshkey_type_from_name(ثابت حرف *);
صحیح	 sshkey_type_from_shortname(ثابت حرف *);
صحیح	 sshkey_is_cert(ثابت ساخت sshkey *);
صحیح	 sshkey_is_sk(ثابت ساخت sshkey *);
صحیح	 sshkey_type_is_cert(صحیح);
صحیح	 sshkey_type_plain(صحیح);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
صحیح	 sshkey_مطابقت_keyname_مقصد_sigalgs(ثابت حرف *, ثابت حرف *);

صحیح	 sshkey_مقصد_certified(ساخت sshkey *);
صحیح	 sshkey_drop_cert(ساخت sshkey *);
صحیح	 sshkey_cert_copy(ثابت ساخت sshkey *, ساخت sshkey *);
صحیح	 sshkey_cert_check_authority(ثابت ساخت sshkey *, صحیح, صحیح,
    uint64_t, ثابت حرف *, ثابت حرف **);
صحیح	 sshkey_cert_check_authority_now(ثابت ساخت sshkey *, صحیح, صحیح,
    ثابت حرف *, ثابت حرف **);
صحیح	 sshkey_cert_check_host(ثابت ساخت sshkey *, ثابت حرف *,
    ثابت حرف *, ثابت حرف **);
سائز_t	 sshkey_format_cert_validity(ثابت ساخت sshkey_cert *,
    حرف *, سائز_t) __attribute__((__bounded__(__string__, 2, 3)));
صحیح	 sshkey_check_cert_sigtype(ثابت ساخت sshkey *, ثابت حرف *);

صحیح	 sshkey_certify(ساخت sshkey *, ساخت sshkey *,
    ثابت حرف *, ثابت حرف *, ثابت حرف *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
قسمتعریف صحیح sshkey_certify_signer(ساخت sshkey *, u_char **, سائز_t *,
    ثابت u_char *, سائز_t, ثابت حرف *, ثابت حرف *, ثابت حرف *,
    u_int, خالی *);
صحیح	 sshkey_certify_custom(ساخت sshkey *, ساخت sshkey *, ثابت حرف *,
    ثابت حرف *, ثابت حرف *, sshkey_certify_signer *, خالی *);

صحیح		 sshkey_ecdsa_nid_from_name(ثابت حرف *);
صحیح		 sshkey_خم_name_مقصد_nid(ثابت حرف *);
ثابت حرف *	 sshkey_خم_nid_مقصد_name(صحیح);
u_int		 sshkey_خم_nid_مقصد_بٹ(صحیح);
صحیح		 sshkey_ecdsa_بٹ_مقصد_nid(صحیح);
صحیح		 sshkey_ecdsa_کلید_مقصد_nid(ثابت EC_کلید *);
صحیح		 sshkey_ecdsa_pkey_مقصد_nid(EVP_PKEY *);
صحیح		 sshkey_ec_nid_مقصد_hash_alg(صحیح nid);
صحیح		 sshkey_ec_validate_عوامی(ثابت EC_گروہ *, ثابت EC_نقطہ *);
صحیح		 sshkey_ec_validate_نجی(ثابت EC_کلید *);
ثابت حرف	*sshkey_ssh_name(ثابت ساخت sshkey *);
ثابت حرف	*sshkey_ssh_name_plain(ثابت ساخت sshkey *);
صحیح		 sshkey_نام_valid2(ثابت حرف *, صحیح, صحیح);
حرف		*sshkey_alg_list(صحیح, صحیح, صحیح, حرف);

صحیح	 sshkey_from_blob(ثابت u_char *, سائز_t, ساخت sshkey **);
صحیح	 sshkey_fromb(ساخت sshbuf *, ساخت sshkey **);
صحیح	 sshkey_fromb_allowlist(ساخت sshbuf *, ساخت sshkey **,
    ثابت حرف *, ثابت حرف *);
صحیح	 sshkey_froms(ساخت sshbuf *, ساخت sshkey **);
صحیح	 sshkey_مقصد_blob(ثابت ساخت sshkey *, u_char **, سائز_t *);
صحیح	 sshkey_مقصد_base64(ثابت ساخت sshkey *, حرف **);
صحیح	 sshkey_putb(ثابت ساخت sshkey *, ساخت sshbuf *);
صحیح	 sshkey_puts(ثابت ساخت sshkey *, ساخت sshbuf *);
صحیح	 sshkey_plain_مقصد_blob(ثابت ساخت sshkey *, u_char **, سائز_t *);
صحیح	 sshkey_putb_plain(ثابت ساخت sshkey *, ساخت sshbuf *);
صحیح	 sshkey_puts_plain(ثابت ساخت sshkey *, ساخت sshbuf *);

صحیح	 sshkey_sign(ساخت sshkey *, u_char **, سائز_t *,
    ثابت u_char *, سائز_t, ثابت حرف *, ثابت حرف *, ثابت حرف *, u_int);
صحیح	 sshkey_verify(ثابت ساخت sshkey *, ثابت u_char *, سائز_t,
    ثابت u_char *, سائز_t, ثابت حرف *, u_int, ساخت sshkey_sig_details **);
صحیح	 sshkey_check_sigtype(ثابت u_char *, سائز_t, ثابت حرف *);
ثابت حرف *sshkey_sigalg_by_name(ثابت حرف *);
صحیح	 sshkey_get_sigtype(ثابت u_char *, سائز_t, حرف **);

/* Signing and verification backend for libcrypto-backed keys */
صحیح	sshkey_pkey_digest_sign(EVP_PKEY*, صحیح, u_char **,
    سائز_t *, ثابت u_char *, سائز_t);
صحیح	sshkey_pkey_digest_verify(EVP_PKEY *, صحیح, ثابت u_char *,
    سائز_t, u_char *, سائز_t);

/* for debug */
خالی	sshkey_dump_ec_نقطہ(ثابت EC_گروہ *, ثابت EC_نقطہ *);
خالی	sshkey_dump_ec_کلید(ثابت EC_کلید *);

/* private key parsing and serialisation */
صحیح	sshkey_نجی_serialize(ساخت sshkey *کلید, ساخت sshbuf *buf);
صحیح	sshkey_نجی_deserialize(ساخت sshbuf *buf,  ساخت sshkey **keyp);

/* private key file format parsing and serialisation */
صحیح	sshkey_نجی_مقصد_fileblob(ساخت sshkey *کلید, ساخت sshbuf *blob,
    ثابت حرف *passphrase, ثابت حرف *comment,
    صحیح format, ثابت حرف *openssh_format_cipher, صحیح openssh_format_دور);
صحیح	sshkey_parse_نجی_fileblob(ساخت sshbuf *بفر,
    ثابت حرف *passphrase, ساخت sshkey **keyp, حرف **commentp);
صحیح	sshkey_parse_نجی_fileblob_type(ساخت sshbuf *blob, صحیح type,
    ثابت حرف *passphrase, ساخت sshkey **keyp, حرف **commentp);
صحیح	sshkey_parse_pubkey_from_نجی_fileblob_type(ساخت sshbuf *blob,
    صحیح type, ساخت sshkey **pubkeyp);

صحیح sshkey_check_rsa_لمبائی(ثابت ساخت sshkey *, صحیح);
صحیح	ssh_rsa_hash_id_from_keyname(ثابت حرف *);
ثابت حرف *ssh_rsa_hash_alg_ident(صحیح);
صحیح	ssh_rsa_encode_store_sig(صحیح, ثابت u_char *, سائز_t,
	    u_char **, سائز_t *);
صحیح	ssh_ecdsa_encode_store_sig(ثابت ساخت sshkey *,
	    ثابت BIGNUM *, ثابت BIGNUM *, u_char **, سائز_t *);
صحیح	ssh_ed25519_encode_store_sig(ثابت u_char *, سائز_t,
	    u_char **, سائز_t *);
/* XXX should be internal, but used by ssh-keygen */
صحیح ssh_rsa_complete_crt_parameters(ثابت BIGNUM *, ثابت BIGNUM *,
    ثابت BIGNUM *, ثابت BIGNUM *, BIGNUM **, BIGNUM **);

خالی	 sshkey_sig_details_free(ساخت sshkey_sig_details *);

#اگر_تعریف_شدہ WITH_OPENSSL
صحیح	sshkey_ecdsa_fixup_گروہ(EVP_PKEY *k); /* ssh-ecdsa.c */
#اگر_ختم

#اگر_تعریف_شدہ SSHKEY_اندرونی
صحیح	sshkey_sk_fields_equal(ثابت ساخت sshkey *a, ثابت ساخت sshkey *b);
خالی	sshkey_sk_cleanup(ساخت sshkey *k);
صحیح	sshkey_serialize_sk(ثابت ساخت sshkey *کلید, ساخت sshbuf *b);
صحیح	sshkey_copy_عوامی_sk(ثابت ساخت sshkey *from, ساخت sshkey *مقصد);
صحیح	sshkey_deserialize_sk(ساخت sshbuf *b, ساخت sshkey *کلید);
صحیح	sshkey_serialize_نجی_sk(ثابت ساخت sshkey *کلید,
    ساخت sshbuf *buf);
صحیح	sshkey_نجی_deserialize_sk(ساخت sshbuf *buf, ساخت sshkey *k);
#اگر_تعریف_شدہ WITH_OPENSSL
صحیح	check_rsa_لمبائی(ثابت RSA *rsa); /* XXX remove */
#اگر_ختم
#اگر_ختم

#اگر_غیر_تعریف_شدہ WITH_OPENSSL
#تعریف_منسوخ RSA
#تعریف_منسوخ EC_کلید
#تعریف_منسوخ EC_گروہ
#تعریف_منسوخ EC_نقطہ
#تعریف_منسوخ EVP_PKEY
#اگر_ختم /* WITH_OPENSSL */

#اگر_ختم /* SSHKEY_H */
