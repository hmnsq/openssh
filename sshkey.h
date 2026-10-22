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
#که_نه_تعریف_شوی SSHKEY_H
#تعریف_کړه SSHKEY_H

#ضمن <sys/types.h>

#که_تعریف_شوی WITH_OPENSSL
#ضمن <openssl/rsa.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/evp.h>
#تعریف_کړه SSH_OPENSSL_نسخه Open_SSL_نسخه(OPENSSL_نسخه)
#وإلا /* OPENSSL */
#تعریف_کړه BIGNUM		فراغ
#تعریف_کړه RSA		فراغ
#تعریف_کړه EC_کلی		فراغ
#تعریف_کړه EC_ډله	فراغ
#تعریف_کړه EC_ټکی	فراغ
#تعریف_کړه EVP_PKEY	فراغ
#تعریف_کړه SSH_OPENSSL_نسخه "without OpenSSL"
#د_که_پای /* WITH_OPENSSL */

#تعریف_کړه SSH_RSA_MINIMUM_MODULUS_اندازه	1024
#تعریف_کړه SSH_کلی_MAX_SIGN_معلومات_اندازه	(1 << 20)

بنية sshbuf;

/* Key types */
تعداد sshkey_types {
	کلی_RSA,
	کلی_ECDSA,
	کلی_ED25519,
	کلی_RSA_CERT,
	کلی_ECDSA_CERT,
	کلی_ED25519_CERT,
	کلی_ECDSA_SK,
	کلی_ECDSA_SK_CERT,
	کلی_ED25519_SK,
	کلی_ED25519_SK_CERT,
	کلی_MLDSA44_ED25519,
	کلی_MLDSA44_ED25519_CERT,
	کلی_UNSPEC
};

/* Default fingerprint hash */
#تعریف_کړه SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
تعداد sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
تعداد sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
تعداد sshkey_شخصي_format {
	SSHKEY_شخصي_OPENSSH = 0,
	SSHKEY_شخصي_PEM = 1,
	SSHKEY_شخصي_PKCS8 = 2,
};

/* key is stored in external hardware */
#تعریف_کړه SSHKEY_FLAG_EXT		0x0001

#تعریف_کړه SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
بنية sshkey_cert {
	بنية sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	حرف		*کلی_id;
	u_int		 nprincipals;
	حرف		**principals;
	uint64_t	 valid_after, valid_before;
	بنية sshbuf	*critical;
	بنية sshbuf	*extensions;
	بنية sshkey	*signature_کلی;
	حرف		*signature_type;
};

/* XXX opacify? */
بنية sshkey {
	صحيح	 type;
	صحيح	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	صحيح	 ecdsa_nid;	/* NID of curve */
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
	بنية sshbuf *sk_کلی_handle;
	بنية sshbuf *sk_reserved;
	/* Certificates */
	بنية sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_شخصي;
	اندازه_t	shielded_len;
	u_char	*shield_prekey;
	اندازه_t	shield_prekey_len;
};

#تعریف_کړه	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#تعریف_کړه	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
بنية sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

بنية sshkey_impl_funcs {
	u_int (*اندازه)(ثابت بنية sshkey *);	/* optional */
	صحيح (*alloc)(بنية sshkey *);		/* optional */
	فراغ (*cleanup)(بنية sshkey *);	/* optional */
	صحيح (*equal)(ثابت بنية sshkey *, ثابت بنية sshkey *);
	صحيح (*serialize_عامه)(ثابت بنية sshkey *, بنية sshbuf *,
	    تعداد sshkey_serialize_rep);
	صحيح (*deserialize_عامه)(ثابت حرف *, بنية sshbuf *,
	    بنية sshkey *);
	صحيح (*serialize_شخصي)(ثابت بنية sshkey *, بنية sshbuf *,
	    تعداد sshkey_serialize_rep);
	صحيح (*deserialize_شخصي)(ثابت حرف *, بنية sshbuf *,
	    بنية sshkey *);
	صحيح (*generate)(بنية sshkey *, صحيح);	/* optional */
	صحيح (*copy_عامه)(ثابت بنية sshkey *, بنية sshkey *);
	صحيح (*sign)(بنية sshkey *, u_char **, اندازه_t *,
	    ثابت u_char *, اندازه_t, ثابت حرف *,
	    ثابت حرف *, ثابت حرف *, u_int); /* optional */
	صحيح (*verify)(ثابت بنية sshkey *, ثابت u_char *, اندازه_t,
	    ثابت u_char *, اندازه_t, ثابت حرف *, u_int,
	    بنية sshkey_sig_details **);
};

بنية sshkey_impl {
	ثابت حرف *name;
	ثابت حرف *shortname;
	ثابت حرف *sigalg;
	صحيح type;
	صحيح nid;
	صحيح cert;
	صحيح sigonly;
	صحيح keybits;
	ثابت بنية sshkey_impl_funcs *funcs;
};

بنية sshkey	*sshkey_new(صحيح);
فراغ		 sshkey_free(بنية sshkey *);
صحيح		 sshkey_equal_عامه(ثابت بنية sshkey *,
    ثابت بنية sshkey *);
صحيح		 sshkey_equal(ثابت بنية sshkey *, ثابت بنية sshkey *);
حرف		*sshkey_fingerprint(ثابت بنية sshkey *,
    صحيح, تعداد sshkey_fp_rep);
صحيح		 sshkey_fingerprint_raw(ثابت بنية sshkey *k,
    صحيح, u_char **retp, اندازه_t *lenp);
ثابت حرف	*sshkey_type(ثابت بنية sshkey *);
ثابت حرف	*sshkey_cert_type(ثابت بنية sshkey *);
صحيح		 sshkey_format_متن(ثابت بنية sshkey *, بنية sshbuf *);
صحيح		 sshkey_write(ثابت بنية sshkey *, FILE *);
صحيح		 sshkey_read(بنية sshkey *, حرف **);
u_int		 sshkey_اندازه(ثابت بنية sshkey *);

صحيح		 sshkey_generate(صحيح type, u_int بټونه, بنية sshkey **keyp);
صحيح		 sshkey_from_شخصي(ثابت بنية sshkey *, بنية sshkey **);

صحيح		 sshkey_is_shielded(بنية sshkey *);
صحيح		 sshkey_shield_شخصي(بنية sshkey *);
صحيح		 sshkey_unshield_شخصي(بنية sshkey *);

صحيح	 sshkey_type_from_name(ثابت حرف *);
صحيح	 sshkey_type_from_shortname(ثابت حرف *);
صحيح	 sshkey_is_cert(ثابت بنية sshkey *);
صحيح	 sshkey_is_sk(ثابت بنية sshkey *);
صحيح	 sshkey_type_is_cert(صحيح);
صحيح	 sshkey_type_plain(صحيح);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
صحيح	 sshkey_سمون_keyname_منزل_sigalgs(ثابت حرف *, ثابت حرف *);

صحيح	 sshkey_منزل_certified(بنية sshkey *);
صحيح	 sshkey_drop_cert(بنية sshkey *);
صحيح	 sshkey_cert_copy(ثابت بنية sshkey *, بنية sshkey *);
صحيح	 sshkey_cert_check_authority(ثابت بنية sshkey *, صحيح, صحيح,
    uint64_t, ثابت حرف *, ثابت حرف **);
صحيح	 sshkey_cert_check_authority_now(ثابت بنية sshkey *, صحيح, صحيح,
    ثابت حرف *, ثابت حرف **);
صحيح	 sshkey_cert_check_host(ثابت بنية sshkey *, ثابت حرف *,
    ثابت حرف *, ثابت حرف **);
اندازه_t	 sshkey_format_cert_validity(ثابت بنية sshkey_cert *,
    حرف *, اندازه_t) __attribute__((__bounded__(__string__, 2, 3)));
صحيح	 sshkey_check_cert_sigtype(ثابت بنية sshkey *, ثابت حرف *);

صحيح	 sshkey_certify(بنية sshkey *, بنية sshkey *,
    ثابت حرف *, ثابت حرف *, ثابت حرف *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
تعريفنوع صحيح sshkey_certify_signer(بنية sshkey *, u_char **, اندازه_t *,
    ثابت u_char *, اندازه_t, ثابت حرف *, ثابت حرف *, ثابت حرف *,
    u_int, فراغ *);
صحيح	 sshkey_certify_custom(بنية sshkey *, بنية sshkey *, ثابت حرف *,
    ثابت حرف *, ثابت حرف *, sshkey_certify_signer *, فراغ *);

صحيح		 sshkey_ecdsa_nid_from_name(ثابت حرف *);
صحيح		 sshkey_منحني_name_منزل_nid(ثابت حرف *);
ثابت حرف *	 sshkey_منحني_nid_منزل_name(صحيح);
u_int		 sshkey_منحني_nid_منزل_بټونه(صحيح);
صحيح		 sshkey_ecdsa_بټونه_منزل_nid(صحيح);
صحيح		 sshkey_ecdsa_کلی_منزل_nid(ثابت EC_کلی *);
صحيح		 sshkey_ecdsa_pkey_منزل_nid(EVP_PKEY *);
صحيح		 sshkey_ec_nid_منزل_hash_alg(صحيح nid);
صحيح		 sshkey_ec_validate_عامه(ثابت EC_ډله *, ثابت EC_ټکی *);
صحيح		 sshkey_ec_validate_شخصي(ثابت EC_کلی *);
ثابت حرف	*sshkey_ssh_name(ثابت بنية sshkey *);
ثابت حرف	*sshkey_ssh_name_plain(ثابت بنية sshkey *);
صحيح		 sshkey_نومونه_valid2(ثابت حرف *, صحيح, صحيح);
حرف		*sshkey_alg_list(صحيح, صحيح, صحيح, حرف);

صحيح	 sshkey_from_blob(ثابت u_char *, اندازه_t, بنية sshkey **);
صحيح	 sshkey_fromb(بنية sshbuf *, بنية sshkey **);
صحيح	 sshkey_fromb_allowlist(بنية sshbuf *, بنية sshkey **,
    ثابت حرف *, ثابت حرف *);
صحيح	 sshkey_froms(بنية sshbuf *, بنية sshkey **);
صحيح	 sshkey_منزل_blob(ثابت بنية sshkey *, u_char **, اندازه_t *);
صحيح	 sshkey_منزل_base64(ثابت بنية sshkey *, حرف **);
صحيح	 sshkey_putb(ثابت بنية sshkey *, بنية sshbuf *);
صحيح	 sshkey_puts(ثابت بنية sshkey *, بنية sshbuf *);
صحيح	 sshkey_plain_منزل_blob(ثابت بنية sshkey *, u_char **, اندازه_t *);
صحيح	 sshkey_putb_plain(ثابت بنية sshkey *, بنية sshbuf *);
صحيح	 sshkey_puts_plain(ثابت بنية sshkey *, بنية sshbuf *);

صحيح	 sshkey_sign(بنية sshkey *, u_char **, اندازه_t *,
    ثابت u_char *, اندازه_t, ثابت حرف *, ثابت حرف *, ثابت حرف *, u_int);
صحيح	 sshkey_verify(ثابت بنية sshkey *, ثابت u_char *, اندازه_t,
    ثابت u_char *, اندازه_t, ثابت حرف *, u_int, بنية sshkey_sig_details **);
صحيح	 sshkey_check_sigtype(ثابت u_char *, اندازه_t, ثابت حرف *);
ثابت حرف *sshkey_sigalg_by_name(ثابت حرف *);
صحيح	 sshkey_get_sigtype(ثابت u_char *, اندازه_t, حرف **);

/* Signing and verification backend for libcrypto-backed keys */
صحيح	sshkey_pkey_digest_sign(EVP_PKEY*, صحيح, u_char **,
    اندازه_t *, ثابت u_char *, اندازه_t);
صحيح	sshkey_pkey_digest_verify(EVP_PKEY *, صحيح, ثابت u_char *,
    اندازه_t, u_char *, اندازه_t);

/* for debug */
فراغ	sshkey_dump_ec_ټکی(ثابت EC_ډله *, ثابت EC_ټکی *);
فراغ	sshkey_dump_ec_کلی(ثابت EC_کلی *);

/* private key parsing and serialisation */
صحيح	sshkey_شخصي_serialize(بنية sshkey *کلی, بنية sshbuf *buf);
صحيح	sshkey_شخصي_deserialize(بنية sshbuf *buf,  بنية sshkey **keyp);

/* private key file format parsing and serialisation */
صحيح	sshkey_شخصي_منزل_fileblob(بنية sshkey *کلی, بنية sshbuf *blob,
    ثابت حرف *passphrase, ثابت حرف *comment,
    صحيح format, ثابت حرف *openssh_format_cipher, صحيح openssh_format_پړاوونه);
صحيح	sshkey_parse_شخصي_fileblob(بنية sshbuf *بفر,
    ثابت حرف *passphrase, بنية sshkey **keyp, حرف **commentp);
صحيح	sshkey_parse_شخصي_fileblob_type(بنية sshbuf *blob, صحيح type,
    ثابت حرف *passphrase, بنية sshkey **keyp, حرف **commentp);
صحيح	sshkey_parse_pubkey_from_شخصي_fileblob_type(بنية sshbuf *blob,
    صحيح type, بنية sshkey **pubkeyp);

صحيح sshkey_check_rsa_اوږدتیا(ثابت بنية sshkey *, صحيح);
صحيح	ssh_rsa_hash_id_from_keyname(ثابت حرف *);
ثابت حرف *ssh_rsa_hash_alg_ident(صحيح);
صحيح	ssh_rsa_encode_store_sig(صحيح, ثابت u_char *, اندازه_t,
	    u_char **, اندازه_t *);
صحيح	ssh_ecdsa_encode_store_sig(ثابت بنية sshkey *,
	    ثابت BIGNUM *, ثابت BIGNUM *, u_char **, اندازه_t *);
صحيح	ssh_ed25519_encode_store_sig(ثابت u_char *, اندازه_t,
	    u_char **, اندازه_t *);
/* XXX should be internal, but used by ssh-keygen */
صحيح ssh_rsa_complete_crt_parameters(ثابت BIGNUM *, ثابت BIGNUM *,
    ثابت BIGNUM *, ثابت BIGNUM *, BIGNUM **, BIGNUM **);

فراغ	 sshkey_sig_details_free(بنية sshkey_sig_details *);

#که_تعریف_شوی WITH_OPENSSL
صحيح	sshkey_ecdsa_fixup_ډله(EVP_PKEY *k); /* ssh-ecdsa.c */
#د_که_پای

#که_تعریف_شوی SSHKEY_دننی
صحيح	sshkey_sk_fields_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b);
فراغ	sshkey_sk_cleanup(بنية sshkey *k);
صحيح	sshkey_serialize_sk(ثابت بنية sshkey *کلی, بنية sshbuf *b);
صحيح	sshkey_copy_عامه_sk(ثابت بنية sshkey *from, بنية sshkey *منزل);
صحيح	sshkey_deserialize_sk(بنية sshbuf *b, بنية sshkey *کلی);
صحيح	sshkey_serialize_شخصي_sk(ثابت بنية sshkey *کلی,
    بنية sshbuf *buf);
صحيح	sshkey_شخصي_deserialize_sk(بنية sshbuf *buf, بنية sshkey *k);
#که_تعریف_شوی WITH_OPENSSL
صحيح	check_rsa_اوږدتیا(ثابت RSA *rsa); /* XXX remove */
#د_که_پای
#د_که_پای

#که_نه_تعریف_شوی WITH_OPENSSL
#تعریف_لغوه RSA
#تعریف_لغوه EC_کلی
#تعریف_لغوه EC_ډله
#تعریف_لغوه EC_ټکی
#تعریف_لغوه EVP_PKEY
#د_که_پای /* WITH_OPENSSL */

#د_که_پای /* SSHKEY_H */
