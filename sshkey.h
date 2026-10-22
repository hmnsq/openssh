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

#अन्तर्भाव <sys/types.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/rsa.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/ecdsa.h>
#अन्तर्भाव <openssl/evp.h>
#define SSH_OPENSSL_VERSION OpenSSL_version(OPENSSL_VERSION)
#अन्यथा /* OPENSSL */
#define BIGNUM		शून्य
#define RSA		शून्य
#define EC_किल्ली		शून्य
#define EC_GROUP	शून्य
#define EC_POINT	शून्य
#define EVP_PKEY	शून्य
#define SSH_OPENSSL_VERSION "without OpenSSL"
#endif /* WITH_OPENSSL */

#define SSH_RSA_MINIMUM_MODULUS_SIZE	1024
#define SSH_किल्ली_MAX_SIGN_DATA_SIZE	(1 << 20)

संरचना sshbuf;

/* Key types */
गणना sshkey_types {
	किल्ली_RSA,
	किल्ली_ECDSA,
	किल्ली_ED25519,
	किल्ली_RSA_CERT,
	किल्ली_ECDSA_CERT,
	किल्ली_ED25519_CERT,
	किल्ली_ECDSA_SK,
	किल्ली_ECDSA_SK_CERT,
	किल्ली_ED25519_SK,
	किल्ली_ED25519_SK_CERT,
	किल्ली_MLDSA44_ED25519,
	किल्ली_MLDSA44_ED25519_CERT,
	किल्ली_UNSPEC
};

/* Default fingerprint hash */
#define SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
गणना sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
गणना sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
गणना sshkey_private_format {
	SSHKEY_PRIVATE_OPENSSH = 0,
	SSHKEY_PRIVATE_PEM = 1,
	SSHKEY_PRIVATE_PKCS8 = 2,
};

/* key is stored in external hardware */
#define SSHKEY_FLAG_EXT		0x0001

#define SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
संरचना sshkey_cert {
	संरचना sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	अक्षर		*किल्ली_id;
	u_int		 nprincipals;
	अक्षर		**principals;
	uint64_t	 valid_after, valid_before;
	संरचना sshbuf	*critical;
	संरचना sshbuf	*extensions;
	संरचना sshkey	*signature_किल्ली;
	अक्षर		*signature_type;
};

/* XXX opacify? */
संरचना sshkey {
	पूर्णांक	 type;
	पूर्णांक	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	पूर्णांक	 ecdsa_nid;	/* NID of curve */
	/* libcrypto-backed keys */
	EVP_PKEY *pkey;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_MLDSA44_ED25519 */
	u_char	*mldsa_ed25519_sk;
	u_char	*mldsa_ed25519_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	अक्षर	*sk_application;
	uint8_t	sk_flags;
	संरचना sshbuf *sk_किल्ली_handle;
	संरचना sshbuf *sk_reserved;
	/* Certificates */
	संरचना sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	माप_प्रकार	shielded_len;
	u_char	*shield_prekey;
	माप_प्रकार	shield_prekey_len;
};

#define	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#define	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
संरचना sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

संरचना sshkey_impl_funcs {
	u_int (*size)(स्थिरांक संरचना sshkey *);	/* optional */
	पूर्णांक (*alloc)(संरचना sshkey *);		/* optional */
	शून्य (*cleanup)(संरचना sshkey *);	/* optional */
	पूर्णांक (*equal)(स्थिरांक संरचना sshkey *, स्थिरांक संरचना sshkey *);
	पूर्णांक (*serialize_public)(स्थिरांक संरचना sshkey *, संरचना sshbuf *,
	    गणना sshkey_serialize_rep);
	पूर्णांक (*deserialize_public)(स्थिरांक अक्षर *, संरचना sshbuf *,
	    संरचना sshkey *);
	पूर्णांक (*serialize_private)(स्थिरांक संरचना sshkey *, संरचना sshbuf *,
	    गणना sshkey_serialize_rep);
	पूर्णांक (*deserialize_private)(स्थिरांक अक्षर *, संरचना sshbuf *,
	    संरचना sshkey *);
	पूर्णांक (*generate)(संरचना sshkey *, पूर्णांक);	/* optional */
	पूर्णांक (*copy_public)(स्थिरांक संरचना sshkey *, संरचना sshkey *);
	पूर्णांक (*sign)(संरचना sshkey *, u_char **, माप_प्रकार *,
	    स्थिरांक u_char *, माप_प्रकार, स्थिरांक अक्षर *,
	    स्थिरांक अक्षर *, स्थिरांक अक्षर *, u_int); /* optional */
	पूर्णांक (*verify)(स्थिरांक संरचना sshkey *, स्थिरांक u_char *, माप_प्रकार,
	    स्थिरांक u_char *, माप_प्रकार, स्थिरांक अक्षर *, u_int,
	    संरचना sshkey_sig_details **);
};

संरचना sshkey_impl {
	स्थिरांक अक्षर *name;
	स्थिरांक अक्षर *shortname;
	स्थिरांक अक्षर *sigalg;
	पूर्णांक type;
	पूर्णांक nid;
	पूर्णांक cert;
	पूर्णांक sigonly;
	पूर्णांक keybits;
	स्थिरांक संरचना sshkey_impl_funcs *funcs;
};

संरचना sshkey	*sshkey_new(पूर्णांक);
शून्य		 sshkey_free(संरचना sshkey *);
पूर्णांक		 sshkey_equal_public(स्थिरांक संरचना sshkey *,
    स्थिरांक संरचना sshkey *);
पूर्णांक		 sshkey_equal(स्थिरांक संरचना sshkey *, स्थिरांक संरचना sshkey *);
अक्षर		*sshkey_fingerprint(स्थिरांक संरचना sshkey *,
    पूर्णांक, गणना sshkey_fp_rep);
पूर्णांक		 sshkey_fingerprint_raw(स्थिरांक संरचना sshkey *k,
    पूर्णांक, u_char **retp, माप_प्रकार *lenp);
स्थिरांक अक्षर	*sshkey_type(स्थिरांक संरचना sshkey *);
स्थिरांक अक्षर	*sshkey_cert_type(स्थिरांक संरचना sshkey *);
पूर्णांक		 sshkey_format_text(स्थिरांक संरचना sshkey *, संरचना sshbuf *);
पूर्णांक		 sshkey_write(स्थिरांक संरचना sshkey *, खाता *);
पूर्णांक		 sshkey_read(संरचना sshkey *, अक्षर **);
u_int		 sshkey_size(स्थिरांक संरचना sshkey *);

पूर्णांक		 sshkey_generate(पूर्णांक type, u_int bits, संरचना sshkey **keyp);
पूर्णांक		 sshkey_from_private(स्थिरांक संरचना sshkey *, संरचना sshkey **);

पूर्णांक		 sshkey_is_shielded(संरचना sshkey *);
पूर्णांक		 sshkey_shield_private(संरचना sshkey *);
पूर्णांक		 sshkey_unshield_private(संरचना sshkey *);

पूर्णांक	 sshkey_type_from_name(स्थिरांक अक्षर *);
पूर्णांक	 sshkey_type_from_shortname(स्थिरांक अक्षर *);
पूर्णांक	 sshkey_is_cert(स्थिरांक संरचना sshkey *);
पूर्णांक	 sshkey_is_sk(स्थिरांक संरचना sshkey *);
पूर्णांक	 sshkey_type_is_cert(पूर्णांक);
पूर्णांक	 sshkey_type_plain(पूर्णांक);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
पूर्णांक	 sshkey_match_keyname_to_sigalgs(स्थिरांक अक्षर *, स्थिरांक अक्षर *);

पूर्णांक	 sshkey_to_certified(संरचना sshkey *);
पूर्णांक	 sshkey_drop_cert(संरचना sshkey *);
पूर्णांक	 sshkey_cert_copy(स्थिरांक संरचना sshkey *, संरचना sshkey *);
पूर्णांक	 sshkey_cert_check_authority(स्थिरांक संरचना sshkey *, पूर्णांक, पूर्णांक,
    uint64_t, स्थिरांक अक्षर *, स्थिरांक अक्षर **);
पूर्णांक	 sshkey_cert_check_authority_now(स्थिरांक संरचना sshkey *, पूर्णांक, पूर्णांक,
    स्थिरांक अक्षर *, स्थिरांक अक्षर **);
पूर्णांक	 sshkey_cert_check_host(स्थिरांक संरचना sshkey *, स्थिरांक अक्षर *,
    स्थिरांक अक्षर *, स्थिरांक अक्षर **);
माप_प्रकार	 sshkey_format_cert_validity(स्थिरांक संरचना sshkey_cert *,
    अक्षर *, माप_प्रकार) __attribute__((__bounded__(__string__, 2, 3)));
पूर्णांक	 sshkey_check_cert_sigtype(स्थिरांक संरचना sshkey *, स्थिरांक अक्षर *);

पूर्णांक	 sshkey_certify(संरचना sshkey *, संरचना sshkey *,
    स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
प्रकारव्याख्या पूर्णांक sshkey_certify_signer(संरचना sshkey *, u_char **, माप_प्रकार *,
    स्थिरांक u_char *, माप_प्रकार, स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *,
    u_int, शून्य *);
पूर्णांक	 sshkey_certify_custom(संरचना sshkey *, संरचना sshkey *, स्थिरांक अक्षर *,
    स्थिरांक अक्षर *, स्थिरांक अक्षर *, sshkey_certify_signer *, शून्य *);

पूर्णांक		 sshkey_ecdsa_nid_from_name(स्थिरांक अक्षर *);
पूर्णांक		 sshkey_curve_name_to_nid(स्थिरांक अक्षर *);
स्थिरांक अक्षर *	 sshkey_curve_nid_to_name(पूर्णांक);
u_int		 sshkey_curve_nid_to_bits(पूर्णांक);
पूर्णांक		 sshkey_ecdsa_bits_to_nid(पूर्णांक);
पूर्णांक		 sshkey_ecdsa_किल्ली_to_nid(स्थिरांक EC_किल्ली *);
पूर्णांक		 sshkey_ecdsa_pkey_to_nid(EVP_PKEY *);
पूर्णांक		 sshkey_ec_nid_to_hash_alg(पूर्णांक nid);
पूर्णांक		 sshkey_ec_validate_public(स्थिरांक EC_GROUP *, स्थिरांक EC_POINT *);
पूर्णांक		 sshkey_ec_validate_private(स्थिरांक EC_किल्ली *);
स्थिरांक अक्षर	*sshkey_ssh_name(स्थिरांक संरचना sshkey *);
स्थिरांक अक्षर	*sshkey_ssh_name_plain(स्थिरांक संरचना sshkey *);
पूर्णांक		 sshkey_names_valid2(स्थिरांक अक्षर *, पूर्णांक, पूर्णांक);
अक्षर		*sshkey_alg_list(पूर्णांक, पूर्णांक, पूर्णांक, अक्षर);

पूर्णांक	 sshkey_from_blob(स्थिरांक u_char *, माप_प्रकार, संरचना sshkey **);
पूर्णांक	 sshkey_fromb(संरचना sshbuf *, संरचना sshkey **);
पूर्णांक	 sshkey_fromb_allowlist(संरचना sshbuf *, संरचना sshkey **,
    स्थिरांक अक्षर *, स्थिरांक अक्षर *);
पूर्णांक	 sshkey_froms(संरचना sshbuf *, संरचना sshkey **);
पूर्णांक	 sshkey_to_blob(स्थिरांक संरचना sshkey *, u_char **, माप_प्रकार *);
पूर्णांक	 sshkey_to_base64(स्थिरांक संरचना sshkey *, अक्षर **);
पूर्णांक	 sshkey_putb(स्थिरांक संरचना sshkey *, संरचना sshbuf *);
पूर्णांक	 sshkey_puts(स्थिरांक संरचना sshkey *, संरचना sshbuf *);
पूर्णांक	 sshkey_plain_to_blob(स्थिरांक संरचना sshkey *, u_char **, माप_प्रकार *);
पूर्णांक	 sshkey_putb_plain(स्थिरांक संरचना sshkey *, संरचना sshbuf *);
पूर्णांक	 sshkey_puts_plain(स्थिरांक संरचना sshkey *, संरचना sshbuf *);

पूर्णांक	 sshkey_sign(संरचना sshkey *, u_char **, माप_प्रकार *,
    स्थिरांक u_char *, माप_प्रकार, स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *, u_int);
पूर्णांक	 sshkey_verify(स्थिरांक संरचना sshkey *, स्थिरांक u_char *, माप_प्रकार,
    स्थिरांक u_char *, माप_प्रकार, स्थिरांक अक्षर *, u_int, संरचना sshkey_sig_details **);
पूर्णांक	 sshkey_check_sigtype(स्थिरांक u_char *, माप_प्रकार, स्थिरांक अक्षर *);
स्थिरांक अक्षर *sshkey_sigalg_by_name(स्थिरांक अक्षर *);
पूर्णांक	 sshkey_get_sigtype(स्थिरांक u_char *, माप_प्रकार, अक्षर **);

/* Signing and verification backend for libcrypto-backed keys */
पूर्णांक	sshkey_pkey_digest_sign(EVP_PKEY*, पूर्णांक, u_char **,
    माप_प्रकार *, स्थिरांक u_char *, माप_प्रकार);
पूर्णांक	sshkey_pkey_digest_verify(EVP_PKEY *, पूर्णांक, स्थिरांक u_char *,
    माप_प्रकार, u_char *, माप_प्रकार);

/* for debug */
शून्य	sshkey_dump_ec_point(स्थिरांक EC_GROUP *, स्थिरांक EC_POINT *);
शून्य	sshkey_dump_ec_किल्ली(स्थिरांक EC_किल्ली *);

/* private key parsing and serialisation */
पूर्णांक	sshkey_private_serialize(संरचना sshkey *किल्ली, संरचना sshbuf *buf);
पूर्णांक	sshkey_private_deserialize(संरचना sshbuf *buf,  संरचना sshkey **keyp);

/* private key file format parsing and serialisation */
पूर्णांक	sshkey_private_to_fileblob(संरचना sshkey *किल्ली, संरचना sshbuf *blob,
    स्थिरांक अक्षर *passphrase, स्थिरांक अक्षर *comment,
    पूर्णांक format, स्थिरांक अक्षर *openssh_format_cipher, पूर्णांक openssh_format_rounds);
पूर्णांक	sshkey_parse_private_fileblob(संरचना sshbuf *buffer,
    स्थिरांक अक्षर *passphrase, संरचना sshkey **keyp, अक्षर **commentp);
पूर्णांक	sshkey_parse_private_fileblob_type(संरचना sshbuf *blob, पूर्णांक type,
    स्थिरांक अक्षर *passphrase, संरचना sshkey **keyp, अक्षर **commentp);
पूर्णांक	sshkey_parse_pubkey_from_private_fileblob_type(संरचना sshbuf *blob,
    पूर्णांक type, संरचना sshkey **pubkeyp);

पूर्णांक sshkey_check_rsa_length(स्थिरांक संरचना sshkey *, पूर्णांक);
पूर्णांक	ssh_rsa_hash_id_from_keyname(स्थिरांक अक्षर *);
स्थिरांक अक्षर *ssh_rsa_hash_alg_ident(पूर्णांक);
पूर्णांक	ssh_rsa_encode_store_sig(पूर्णांक, स्थिरांक u_char *, माप_प्रकार,
	    u_char **, माप_प्रकार *);
पूर्णांक	ssh_ecdsa_encode_store_sig(स्थिरांक संरचना sshkey *,
	    स्थिरांक BIGNUM *, स्थिरांक BIGNUM *, u_char **, माप_प्रकार *);
पूर्णांक	ssh_ed25519_encode_store_sig(स्थिरांक u_char *, माप_प्रकार,
	    u_char **, माप_प्रकार *);
/* XXX should be internal, but used by ssh-keygen */
पूर्णांक ssh_rsa_complete_crt_parameters(स्थिरांक BIGNUM *, स्थिरांक BIGNUM *,
    स्थिरांक BIGNUM *, स्थिरांक BIGNUM *, BIGNUM **, BIGNUM **);

शून्य	 sshkey_sig_details_free(संरचना sshkey_sig_details *);

#ifdef WITH_OPENSSL
पूर्णांक	sshkey_ecdsa_fixup_group(EVP_PKEY *k); /* ssh-ecdsa.c */
#endif

#ifdef SSHKEY_INTERNAL
पूर्णांक	sshkey_sk_fields_equal(स्थिरांक संरचना sshkey *a, स्थिरांक संरचना sshkey *b);
शून्य	sshkey_sk_cleanup(संरचना sshkey *k);
पूर्णांक	sshkey_serialize_sk(स्थिरांक संरचना sshkey *किल्ली, संरचना sshbuf *b);
पूर्णांक	sshkey_copy_public_sk(स्थिरांक संरचना sshkey *from, संरचना sshkey *to);
पूर्णांक	sshkey_deserialize_sk(संरचना sshbuf *b, संरचना sshkey *किल्ली);
पूर्णांक	sshkey_serialize_private_sk(स्थिरांक संरचना sshkey *किल्ली,
    संरचना sshbuf *buf);
पूर्णांक	sshkey_private_deserialize_sk(संरचना sshbuf *buf, संरचना sshkey *k);
#ifdef WITH_OPENSSL
पूर्णांक	check_rsa_length(स्थिरांक RSA *rsa); /* XXX remove */
#endif
#endif

#ifndef WITH_OPENSSL
#undef RSA
#undef EC_किल्ली
#undef EC_GROUP
#undef EC_POINT
#undef EVP_PKEY
#endif /* WITH_OPENSSL */

#endif /* SSHKEY_H */
