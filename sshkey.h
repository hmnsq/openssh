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
#جيڪڏهن_وصف_نه_ٿيل SSHKEY_H
#وصف_ڪريو SSHKEY_H

#ضمن <sys/types.h>

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن <openssl/rsa.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/evp.h>
#وصف_ڪريو SSH_OPENSSL_نسخو Open_SSL_نسخو(OPENSSL_نسخو)
#وإلا /* OPENSSL */
#وصف_ڪريو BIGNUM		فراغ
#وصف_ڪريو RSA		فراغ
#وصف_ڪريو EC_ڪنجي		فراغ
#وصف_ڪريو EC_گروهه	فراغ
#وصف_ڪريو EC_نقطو	فراغ
#وصف_ڪريو EVP_PKEY	فراغ
#وصف_ڪريو SSH_OPENSSL_نسخو "without OpenSSL"
#جيڪڏهن_پورو /* WITH_OPENSSL */

#وصف_ڪريو SSH_RSA_MINIMUM_MODULUS_سائيز	1024
#وصف_ڪريو SSH_ڪنجي_MAX_SIGN_معلومات_سائيز	(1 << 20)

بنية sshbuf;

/* Key types */
تعداد sshkey_types {
	ڪنجي_RSA,
	ڪنجي_ECDSA,
	ڪنجي_ED25519,
	ڪنجي_RSA_CERT,
	ڪنجي_ECDSA_CERT,
	ڪنجي_ED25519_CERT,
	ڪنجي_ECDSA_SK,
	ڪنجي_ECDSA_SK_CERT,
	ڪنجي_ED25519_SK,
	ڪنجي_ED25519_SK_CERT,
	ڪنجي_MLDSA44_ED25519,
	ڪنجي_MLDSA44_ED25519_CERT,
	ڪنجي_UNSPEC
};

/* Default fingerprint hash */
#وصف_ڪريو SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

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
تعداد sshkey_ذاتي_format {
	SSHKEY_ذاتي_OPENSSH = 0,
	SSHKEY_ذاتي_PEM = 1,
	SSHKEY_ذاتي_PKCS8 = 2,
};

/* key is stored in external hardware */
#وصف_ڪريو SSHKEY_FLAG_EXT		0x0001

#وصف_ڪريو SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
بنية sshkey_cert {
	بنية sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	حرف		*ڪنجي_id;
	u_int		 nprincipals;
	حرف		**principals;
	uint64_t	 valid_after, valid_before;
	بنية sshbuf	*critical;
	بنية sshbuf	*extensions;
	بنية sshkey	*signature_ڪنجي;
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
	بنية sshbuf *sk_ڪنجي_handle;
	بنية sshbuf *sk_reserved;
	/* Certificates */
	بنية sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_ذاتي;
	سائيز_t	shielded_len;
	u_char	*shield_prekey;
	سائيز_t	shield_prekey_len;
};

#وصف_ڪريو	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#وصف_ڪريو	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
بنية sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

بنية sshkey_impl_funcs {
	u_int (*سائيز)(ثابت بنية sshkey *);	/* optional */
	صحيح (*alloc)(بنية sshkey *);		/* optional */
	فراغ (*cleanup)(بنية sshkey *);	/* optional */
	صحيح (*equal)(ثابت بنية sshkey *, ثابت بنية sshkey *);
	صحيح (*serialize_عوامي)(ثابت بنية sshkey *, بنية sshbuf *,
	    تعداد sshkey_serialize_rep);
	صحيح (*deserialize_عوامي)(ثابت حرف *, بنية sshbuf *,
	    بنية sshkey *);
	صحيح (*serialize_ذاتي)(ثابت بنية sshkey *, بنية sshbuf *,
	    تعداد sshkey_serialize_rep);
	صحيح (*deserialize_ذاتي)(ثابت حرف *, بنية sshbuf *,
	    بنية sshkey *);
	صحيح (*generate)(بنية sshkey *, صحيح);	/* optional */
	صحيح (*copy_عوامي)(ثابت بنية sshkey *, بنية sshkey *);
	صحيح (*sign)(بنية sshkey *, u_char **, سائيز_t *,
	    ثابت u_char *, سائيز_t, ثابت حرف *,
	    ثابت حرف *, ثابت حرف *, u_int); /* optional */
	صحيح (*verify)(ثابت بنية sshkey *, ثابت u_char *, سائيز_t,
	    ثابت u_char *, سائيز_t, ثابت حرف *, u_int,
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
صحيح		 sshkey_equal_عوامي(ثابت بنية sshkey *,
    ثابت بنية sshkey *);
صحيح		 sshkey_equal(ثابت بنية sshkey *, ثابت بنية sshkey *);
حرف		*sshkey_fingerprint(ثابت بنية sshkey *,
    صحيح, تعداد sshkey_fp_rep);
صحيح		 sshkey_fingerprint_raw(ثابت بنية sshkey *k,
    صحيح, u_char **retp, سائيز_t *lenp);
ثابت حرف	*sshkey_type(ثابت بنية sshkey *);
ثابت حرف	*sshkey_cert_type(ثابت بنية sshkey *);
صحيح		 sshkey_format_متن(ثابت بنية sshkey *, بنية sshbuf *);
صحيح		 sshkey_write(ثابت بنية sshkey *, FILE *);
صحيح		 sshkey_read(بنية sshkey *, حرف **);
u_int		 sshkey_سائيز(ثابت بنية sshkey *);

صحيح		 sshkey_generate(صحيح type, u_int بٽ, بنية sshkey **keyp);
صحيح		 sshkey_from_ذاتي(ثابت بنية sshkey *, بنية sshkey **);

صحيح		 sshkey_is_shielded(بنية sshkey *);
صحيح		 sshkey_shield_ذاتي(بنية sshkey *);
صحيح		 sshkey_unshield_ذاتي(بنية sshkey *);

صحيح	 sshkey_type_from_name(ثابت حرف *);
صحيح	 sshkey_type_from_shortname(ثابت حرف *);
صحيح	 sshkey_is_cert(ثابت بنية sshkey *);
صحيح	 sshkey_is_sk(ثابت بنية sshkey *);
صحيح	 sshkey_type_is_cert(صحيح);
صحيح	 sshkey_type_plain(صحيح);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
صحيح	 sshkey_ميلاپ_keyname_منزل_sigalgs(ثابت حرف *, ثابت حرف *);

صحيح	 sshkey_منزل_certified(بنية sshkey *);
صحيح	 sshkey_drop_cert(بنية sshkey *);
صحيح	 sshkey_cert_copy(ثابت بنية sshkey *, بنية sshkey *);
صحيح	 sshkey_cert_check_authority(ثابت بنية sshkey *, صحيح, صحيح,
    uint64_t, ثابت حرف *, ثابت حرف **);
صحيح	 sshkey_cert_check_authority_now(ثابت بنية sshkey *, صحيح, صحيح,
    ثابت حرف *, ثابت حرف **);
صحيح	 sshkey_cert_check_host(ثابت بنية sshkey *, ثابت حرف *,
    ثابت حرف *, ثابت حرف **);
سائيز_t	 sshkey_format_cert_validity(ثابت بنية sshkey_cert *,
    حرف *, سائيز_t) __attribute__((__bounded__(__string__, 2, 3)));
صحيح	 sshkey_check_cert_sigtype(ثابت بنية sshkey *, ثابت حرف *);

صحيح	 sshkey_certify(بنية sshkey *, بنية sshkey *,
    ثابت حرف *, ثابت حرف *, ثابت حرف *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
تعريفنوع صحيح sshkey_certify_signer(بنية sshkey *, u_char **, سائيز_t *,
    ثابت u_char *, سائيز_t, ثابت حرف *, ثابت حرف *, ثابت حرف *,
    u_int, فراغ *);
صحيح	 sshkey_certify_custom(بنية sshkey *, بنية sshkey *, ثابت حرف *,
    ثابت حرف *, ثابت حرف *, sshkey_certify_signer *, فراغ *);

صحيح		 sshkey_ecdsa_nid_from_name(ثابت حرف *);
صحيح		 sshkey_وڪر_name_منزل_nid(ثابت حرف *);
ثابت حرف *	 sshkey_وڪر_nid_منزل_name(صحيح);
u_int		 sshkey_وڪر_nid_منزل_بٽ(صحيح);
صحيح		 sshkey_ecdsa_بٽ_منزل_nid(صحيح);
صحيح		 sshkey_ecdsa_ڪنجي_منزل_nid(ثابت EC_ڪنجي *);
صحيح		 sshkey_ecdsa_pkey_منزل_nid(EVP_PKEY *);
صحيح		 sshkey_ec_nid_منزل_hash_alg(صحيح nid);
صحيح		 sshkey_ec_validate_عوامي(ثابت EC_گروهه *, ثابت EC_نقطو *);
صحيح		 sshkey_ec_validate_ذاتي(ثابت EC_ڪنجي *);
ثابت حرف	*sshkey_ssh_name(ثابت بنية sshkey *);
ثابت حرف	*sshkey_ssh_name_plain(ثابت بنية sshkey *);
صحيح		 sshkey_نالا_valid2(ثابت حرف *, صحيح, صحيح);
حرف		*sshkey_alg_list(صحيح, صحيح, صحيح, حرف);

صحيح	 sshkey_from_blob(ثابت u_char *, سائيز_t, بنية sshkey **);
صحيح	 sshkey_fromb(بنية sshbuf *, بنية sshkey **);
صحيح	 sshkey_fromb_allowlist(بنية sshbuf *, بنية sshkey **,
    ثابت حرف *, ثابت حرف *);
صحيح	 sshkey_froms(بنية sshbuf *, بنية sshkey **);
صحيح	 sshkey_منزل_blob(ثابت بنية sshkey *, u_char **, سائيز_t *);
صحيح	 sshkey_منزل_base64(ثابت بنية sshkey *, حرف **);
صحيح	 sshkey_putb(ثابت بنية sshkey *, بنية sshbuf *);
صحيح	 sshkey_puts(ثابت بنية sshkey *, بنية sshbuf *);
صحيح	 sshkey_plain_منزل_blob(ثابت بنية sshkey *, u_char **, سائيز_t *);
صحيح	 sshkey_putb_plain(ثابت بنية sshkey *, بنية sshbuf *);
صحيح	 sshkey_puts_plain(ثابت بنية sshkey *, بنية sshbuf *);

صحيح	 sshkey_sign(بنية sshkey *, u_char **, سائيز_t *,
    ثابت u_char *, سائيز_t, ثابت حرف *, ثابت حرف *, ثابت حرف *, u_int);
صحيح	 sshkey_verify(ثابت بنية sshkey *, ثابت u_char *, سائيز_t,
    ثابت u_char *, سائيز_t, ثابت حرف *, u_int, بنية sshkey_sig_details **);
صحيح	 sshkey_check_sigtype(ثابت u_char *, سائيز_t, ثابت حرف *);
ثابت حرف *sshkey_sigalg_by_name(ثابت حرف *);
صحيح	 sshkey_get_sigtype(ثابت u_char *, سائيز_t, حرف **);

/* Signing and verification backend for libcrypto-backed keys */
صحيح	sshkey_pkey_digest_sign(EVP_PKEY*, صحيح, u_char **,
    سائيز_t *, ثابت u_char *, سائيز_t);
صحيح	sshkey_pkey_digest_verify(EVP_PKEY *, صحيح, ثابت u_char *,
    سائيز_t, u_char *, سائيز_t);

/* for debug */
فراغ	sshkey_dump_ec_نقطو(ثابت EC_گروهه *, ثابت EC_نقطو *);
فراغ	sshkey_dump_ec_ڪنجي(ثابت EC_ڪنجي *);

/* private key parsing and serialisation */
صحيح	sshkey_ذاتي_serialize(بنية sshkey *ڪنجي, بنية sshbuf *buf);
صحيح	sshkey_ذاتي_deserialize(بنية sshbuf *buf,  بنية sshkey **keyp);

/* private key file format parsing and serialisation */
صحيح	sshkey_ذاتي_منزل_fileblob(بنية sshkey *ڪنجي, بنية sshbuf *blob,
    ثابت حرف *passphrase, ثابت حرف *comment,
    صحيح format, ثابت حرف *openssh_format_cipher, صحيح openssh_format_ڦيرا);
صحيح	sshkey_parse_ذاتي_fileblob(بنية sshbuf *بفر,
    ثابت حرف *passphrase, بنية sshkey **keyp, حرف **commentp);
صحيح	sshkey_parse_ذاتي_fileblob_type(بنية sshbuf *blob, صحيح type,
    ثابت حرف *passphrase, بنية sshkey **keyp, حرف **commentp);
صحيح	sshkey_parse_pubkey_from_ذاتي_fileblob_type(بنية sshbuf *blob,
    صحيح type, بنية sshkey **pubkeyp);

صحيح sshkey_check_rsa_ڊيگهائي(ثابت بنية sshkey *, صحيح);
صحيح	ssh_rsa_hash_id_from_keyname(ثابت حرف *);
ثابت حرف *ssh_rsa_hash_alg_ident(صحيح);
صحيح	ssh_rsa_encode_store_sig(صحيح, ثابت u_char *, سائيز_t,
	    u_char **, سائيز_t *);
صحيح	ssh_ecdsa_encode_store_sig(ثابت بنية sshkey *,
	    ثابت BIGNUM *, ثابت BIGNUM *, u_char **, سائيز_t *);
صحيح	ssh_ed25519_encode_store_sig(ثابت u_char *, سائيز_t,
	    u_char **, سائيز_t *);
/* XXX should be internal, but used by ssh-keygen */
صحيح ssh_rsa_complete_crt_parameters(ثابت BIGNUM *, ثابت BIGNUM *,
    ثابت BIGNUM *, ثابت BIGNUM *, BIGNUM **, BIGNUM **);

فراغ	 sshkey_sig_details_free(بنية sshkey_sig_details *);

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
صحيح	sshkey_ecdsa_fixup_گروهه(EVP_PKEY *k); /* ssh-ecdsa.c */
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل SSHKEY_اندروني
صحيح	sshkey_sk_fields_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b);
فراغ	sshkey_sk_cleanup(بنية sshkey *k);
صحيح	sshkey_serialize_sk(ثابت بنية sshkey *ڪنجي, بنية sshbuf *b);
صحيح	sshkey_copy_عوامي_sk(ثابت بنية sshkey *from, بنية sshkey *منزل);
صحيح	sshkey_deserialize_sk(بنية sshbuf *b, بنية sshkey *ڪنجي);
صحيح	sshkey_serialize_ذاتي_sk(ثابت بنية sshkey *ڪنجي,
    بنية sshbuf *buf);
صحيح	sshkey_ذاتي_deserialize_sk(بنية sshbuf *buf, بنية sshkey *k);
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
صحيح	check_rsa_ڊيگهائي(ثابت RSA *rsa); /* XXX remove */
#جيڪڏهن_پورو
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل WITH_OPENSSL
#وصف_رد RSA
#وصف_رد EC_ڪنجي
#وصف_رد EC_گروهه
#وصف_رد EC_نقطو
#وصف_رد EVP_PKEY
#جيڪڏهن_پورو /* WITH_OPENSSL */

#جيڪڏهن_پورو /* SSHKEY_H */
