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
#ifndef SSHKEY_H
#define SSHKEY_H

#شامل <sys/types.h>

#ifdef WITH_OPENSSL
#شامل <openssl/rsa.h>
#شامل <openssl/ec.h>
#شامل <openssl/ecdsa.h>
#شامل <openssl/evp.h>
#define SSH_OPENSSL_VERSION OpenSSL_version(OPENSSL_VERSION)
#وگرنه /* OPENSSL */
#define BIGNUM		تهی
#define RSA		تهی
#define EC_کلید		تهی
#define EC_GROUP	تهی
#define EC_POINT	تهی
#define EVP_PKEY	تهی
#define SSH_OPENSSL_VERSION "without OpenSSL"
#endif /* WITH_OPENSSL */

#define SSH_RSA_MINIMUM_MODULUS_SIZE	1024
#define SSH_کلید_MAX_SIGN_DATA_SIZE	(1 << 20)

ساختار sshbuf;

/* Key types */
شمارش sshkey_types {
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
#define SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
شمارش sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
شمارش sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
شمارش sshkey_private_format {
	SSHKEY_PRIVATE_OPENSSH = 0,
	SSHKEY_PRIVATE_PEM = 1,
	SSHKEY_PRIVATE_PKCS8 = 2,
};

/* key is stored in external hardware */
#define SSHKEY_FLAG_EXT		0x0001

#define SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
ساختار sshkey_cert {
	ساختار sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	نویسه		*کلید_id;
	u_int		 nprincipals;
	نویسه		**principals;
	uint64_t	 valid_after, valid_before;
	ساختار sshbuf	*critical;
	ساختار sshbuf	*extensions;
	ساختار sshkey	*signature_کلید;
	نویسه		*signature_type;
};

/* XXX opacify? */
ساختار sshkey {
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
	نویسه	*sk_application;
	uint8_t	sk_flags;
	ساختار sshbuf *sk_کلید_handle;
	ساختار sshbuf *sk_reserved;
	/* Certificates */
	ساختار sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	size_t	shielded_len;
	u_char	*shield_prekey;
	size_t	shield_prekey_len;
};

#define	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#define	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
ساختار sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

ساختار sshkey_impl_funcs {
	u_int (*size)(ثابت ساختار sshkey *);	/* optional */
	صحیح (*alloc)(ساختار sshkey *);		/* optional */
	تهی (*cleanup)(ساختار sshkey *);	/* optional */
	صحیح (*equal)(ثابت ساختار sshkey *, ثابت ساختار sshkey *);
	صحیح (*serialize_public)(ثابت ساختار sshkey *, ساختار sshbuf *,
	    شمارش sshkey_serialize_rep);
	صحیح (*deserialize_public)(ثابت نویسه *, ساختار sshbuf *,
	    ساختار sshkey *);
	صحیح (*serialize_private)(ثابت ساختار sshkey *, ساختار sshbuf *,
	    شمارش sshkey_serialize_rep);
	صحیح (*deserialize_private)(ثابت نویسه *, ساختار sshbuf *,
	    ساختار sshkey *);
	صحیح (*generate)(ساختار sshkey *, صحیح);	/* optional */
	صحیح (*copy_public)(ثابت ساختار sshkey *, ساختار sshkey *);
	صحیح (*sign)(ساختار sshkey *, u_char **, size_t *,
	    ثابت u_char *, size_t, ثابت نویسه *,
	    ثابت نویسه *, ثابت نویسه *, u_int); /* optional */
	صحیح (*verify)(ثابت ساختار sshkey *, ثابت u_char *, size_t,
	    ثابت u_char *, size_t, ثابت نویسه *, u_int,
	    ساختار sshkey_sig_details **);
};

ساختار sshkey_impl {
	ثابت نویسه *name;
	ثابت نویسه *shortname;
	ثابت نویسه *sigalg;
	صحیح type;
	صحیح nid;
	صحیح cert;
	صحیح sigonly;
	صحیح keybits;
	ثابت ساختار sshkey_impl_funcs *funcs;
};

ساختار sshkey	*sshkey_new(صحیح);
تهی		 sshkey_free(ساختار sshkey *);
صحیح		 sshkey_equal_public(ثابت ساختار sshkey *,
    ثابت ساختار sshkey *);
صحیح		 sshkey_equal(ثابت ساختار sshkey *, ثابت ساختار sshkey *);
نویسه		*sshkey_fingerprint(ثابت ساختار sshkey *,
    صحیح, شمارش sshkey_fp_rep);
صحیح		 sshkey_fingerprint_raw(ثابت ساختار sshkey *k,
    صحیح, u_char **retp, size_t *lenp);
ثابت نویسه	*sshkey_type(ثابت ساختار sshkey *);
ثابت نویسه	*sshkey_cert_type(ثابت ساختار sshkey *);
صحیح		 sshkey_format_text(ثابت ساختار sshkey *, ساختار sshbuf *);
صحیح		 sshkey_write(ثابت ساختار sshkey *, FILE *);
صحیح		 sshkey_read(ساختار sshkey *, نویسه **);
u_int		 sshkey_size(ثابت ساختار sshkey *);

صحیح		 sshkey_generate(صحیح type, u_int bits, ساختار sshkey **keyp);
صحیح		 sshkey_from_private(ثابت ساختار sshkey *, ساختار sshkey **);

صحیح		 sshkey_is_shielded(ساختار sshkey *);
صحیح		 sshkey_shield_private(ساختار sshkey *);
صحیح		 sshkey_unshield_private(ساختار sshkey *);

صحیح	 sshkey_type_from_name(ثابت نویسه *);
صحیح	 sshkey_type_from_shortname(ثابت نویسه *);
صحیح	 sshkey_is_cert(ثابت ساختار sshkey *);
صحیح	 sshkey_is_sk(ثابت ساختار sshkey *);
صحیح	 sshkey_type_is_cert(صحیح);
صحیح	 sshkey_type_plain(صحیح);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
صحیح	 sshkey_match_keyname_to_sigalgs(ثابت نویسه *, ثابت نویسه *);

صحیح	 sshkey_to_certified(ساختار sshkey *);
صحیح	 sshkey_drop_cert(ساختار sshkey *);
صحیح	 sshkey_cert_copy(ثابت ساختار sshkey *, ساختار sshkey *);
صحیح	 sshkey_cert_check_authority(ثابت ساختار sshkey *, صحیح, صحیح,
    uint64_t, ثابت نویسه *, ثابت نویسه **);
صحیح	 sshkey_cert_check_authority_now(ثابت ساختار sshkey *, صحیح, صحیح,
    ثابت نویسه *, ثابت نویسه **);
صحیح	 sshkey_cert_check_host(ثابت ساختار sshkey *, ثابت نویسه *,
    ثابت نویسه *, ثابت نویسه **);
size_t	 sshkey_format_cert_validity(ثابت ساختار sshkey_cert *,
    نویسه *, size_t) __attribute__((__bounded__(__string__, 2, 3)));
صحیح	 sshkey_check_cert_sigtype(ثابت ساختار sshkey *, ثابت نویسه *);

صحیح	 sshkey_certify(ساختار sshkey *, ساختار sshkey *,
    ثابت نویسه *, ثابت نویسه *, ثابت نویسه *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
تعریفنوع صحیح sshkey_certify_signer(ساختار sshkey *, u_char **, size_t *,
    ثابت u_char *, size_t, ثابت نویسه *, ثابت نویسه *, ثابت نویسه *,
    u_int, تهی *);
صحیح	 sshkey_certify_custom(ساختار sshkey *, ساختار sshkey *, ثابت نویسه *,
    ثابت نویسه *, ثابت نویسه *, sshkey_certify_signer *, تهی *);

صحیح		 sshkey_ecdsa_nid_from_name(ثابت نویسه *);
صحیح		 sshkey_curve_name_to_nid(ثابت نویسه *);
ثابت نویسه *	 sshkey_curve_nid_to_name(صحیح);
u_int		 sshkey_curve_nid_to_bits(صحیح);
صحیح		 sshkey_ecdsa_bits_to_nid(صحیح);
صحیح		 sshkey_ecdsa_کلید_to_nid(ثابت EC_کلید *);
صحیح		 sshkey_ecdsa_pkey_to_nid(EVP_PKEY *);
صحیح		 sshkey_ec_nid_to_hash_alg(صحیح nid);
صحیح		 sshkey_ec_validate_public(ثابت EC_GROUP *, ثابت EC_POINT *);
صحیح		 sshkey_ec_validate_private(ثابت EC_کلید *);
ثابت نویسه	*sshkey_ssh_name(ثابت ساختار sshkey *);
ثابت نویسه	*sshkey_ssh_name_plain(ثابت ساختار sshkey *);
صحیح		 sshkey_names_valid2(ثابت نویسه *, صحیح, صحیح);
نویسه		*sshkey_alg_list(صحیح, صحیح, صحیح, نویسه);

صحیح	 sshkey_from_blob(ثابت u_char *, size_t, ساختار sshkey **);
صحیح	 sshkey_fromb(ساختار sshbuf *, ساختار sshkey **);
صحیح	 sshkey_fromb_allowlist(ساختار sshbuf *, ساختار sshkey **,
    ثابت نویسه *, ثابت نویسه *);
صحیح	 sshkey_froms(ساختار sshbuf *, ساختار sshkey **);
صحیح	 sshkey_to_blob(ثابت ساختار sshkey *, u_char **, size_t *);
صحیح	 sshkey_to_base64(ثابت ساختار sshkey *, نویسه **);
صحیح	 sshkey_putb(ثابت ساختار sshkey *, ساختار sshbuf *);
صحیح	 sshkey_puts(ثابت ساختار sshkey *, ساختار sshbuf *);
صحیح	 sshkey_plain_to_blob(ثابت ساختار sshkey *, u_char **, size_t *);
صحیح	 sshkey_putb_plain(ثابت ساختار sshkey *, ساختار sshbuf *);
صحیح	 sshkey_puts_plain(ثابت ساختار sshkey *, ساختار sshbuf *);

صحیح	 sshkey_sign(ساختار sshkey *, u_char **, size_t *,
    ثابت u_char *, size_t, ثابت نویسه *, ثابت نویسه *, ثابت نویسه *, u_int);
صحیح	 sshkey_verify(ثابت ساختار sshkey *, ثابت u_char *, size_t,
    ثابت u_char *, size_t, ثابت نویسه *, u_int, ساختار sshkey_sig_details **);
صحیح	 sshkey_check_sigtype(ثابت u_char *, size_t, ثابت نویسه *);
ثابت نویسه *sshkey_sigalg_by_name(ثابت نویسه *);
صحیح	 sshkey_get_sigtype(ثابت u_char *, size_t, نویسه **);

/* Signing and verification backend for libcrypto-backed keys */
صحیح	sshkey_pkey_digest_sign(EVP_PKEY*, صحیح, u_char **,
    size_t *, ثابت u_char *, size_t);
صحیح	sshkey_pkey_digest_verify(EVP_PKEY *, صحیح, ثابت u_char *,
    size_t, u_char *, size_t);

/* for debug */
تهی	sshkey_dump_ec_point(ثابت EC_GROUP *, ثابت EC_POINT *);
تهی	sshkey_dump_ec_کلید(ثابت EC_کلید *);

/* private key parsing and serialisation */
صحیح	sshkey_private_serialize(ساختار sshkey *کلید, ساختار sshbuf *buf);
صحیح	sshkey_private_deserialize(ساختار sshbuf *buf,  ساختار sshkey **keyp);

/* private key file format parsing and serialisation */
صحیح	sshkey_private_to_fileblob(ساختار sshkey *کلید, ساختار sshbuf *blob,
    ثابت نویسه *passphrase, ثابت نویسه *comment,
    صحیح format, ثابت نویسه *openssh_format_cipher, صحیح openssh_format_rounds);
صحیح	sshkey_parse_private_fileblob(ساختار sshbuf *buffer,
    ثابت نویسه *passphrase, ساختار sshkey **keyp, نویسه **commentp);
صحیح	sshkey_parse_private_fileblob_type(ساختار sshbuf *blob, صحیح type,
    ثابت نویسه *passphrase, ساختار sshkey **keyp, نویسه **commentp);
صحیح	sshkey_parse_pubkey_from_private_fileblob_type(ساختار sshbuf *blob,
    صحیح type, ساختار sshkey **pubkeyp);

صحیح sshkey_check_rsa_length(ثابت ساختار sshkey *, صحیح);
صحیح	ssh_rsa_hash_id_from_keyname(ثابت نویسه *);
ثابت نویسه *ssh_rsa_hash_alg_ident(صحیح);
صحیح	ssh_rsa_encode_store_sig(صحیح, ثابت u_char *, size_t,
	    u_char **, size_t *);
صحیح	ssh_ecdsa_encode_store_sig(ثابت ساختار sshkey *,
	    ثابت BIGNUM *, ثابت BIGNUM *, u_char **, size_t *);
صحیح	ssh_ed25519_encode_store_sig(ثابت u_char *, size_t,
	    u_char **, size_t *);
/* XXX should be internal, but used by ssh-keygen */
صحیح ssh_rsa_complete_crt_parameters(ثابت BIGNUM *, ثابت BIGNUM *,
    ثابت BIGNUM *, ثابت BIGNUM *, BIGNUM **, BIGNUM **);

تهی	 sshkey_sig_details_free(ساختار sshkey_sig_details *);

#ifdef WITH_OPENSSL
صحیح	sshkey_ecdsa_fixup_group(EVP_PKEY *k); /* ssh-ecdsa.c */
#endif

#ifdef SSHKEY_INTERNAL
صحیح	sshkey_sk_fields_equal(ثابت ساختار sshkey *a, ثابت ساختار sshkey *b);
تهی	sshkey_sk_cleanup(ساختار sshkey *k);
صحیح	sshkey_serialize_sk(ثابت ساختار sshkey *کلید, ساختار sshbuf *b);
صحیح	sshkey_copy_public_sk(ثابت ساختار sshkey *from, ساختار sshkey *to);
صحیح	sshkey_deserialize_sk(ساختار sshbuf *b, ساختار sshkey *کلید);
صحیح	sshkey_serialize_private_sk(ثابت ساختار sshkey *کلید,
    ساختار sshbuf *buf);
صحیح	sshkey_private_deserialize_sk(ساختار sshbuf *buf, ساختار sshkey *k);
#ifdef WITH_OPENSSL
صحیح	check_rsa_length(ثابت RSA *rsa); /* XXX remove */
#endif
#endif

#ifndef WITH_OPENSSL
#undef RSA
#undef EC_کلید
#undef EC_GROUP
#undef EC_POINT
#undef EVP_PKEY
#endif /* WITH_OPENSSL */

#endif /* SSHKEY_H */
