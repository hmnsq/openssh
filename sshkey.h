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
#अगर_अघोषित SSHKEY_H
#घोषणा SSHKEY_H

#समावेश <sys/types.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/rsa.h>
#समावेश <openssl/ec.h>
#समावेश <openssl/ecdsa.h>
#समावेश <openssl/evp.h>
#घोषणा SSH_OPENSSL_VERSION OpenSSL_version(OPENSSL_VERSION)
#अन्यथा /* OPENSSL */
#घोषणा BIGNUM		व्योम
#घोषणा RSA		व्योम
#घोषणा EC_कुंजी		व्योम
#घोषणा EC_GROUP	व्योम
#घोषणा EC_POINT	व्योम
#घोषणा EVP_PKEY	व्योम
#घोषणा SSH_OPENSSL_VERSION "without OpenSSL"
#पूर्ण_अगर /* WITH_OPENSSL */

#घोषणा SSH_RSA_MINIMUM_MODULUS_आकार	1024
#घोषणा SSH_कुंजी_MAX_SIGN_तथ्य_आकार	(1 << 20)

काष्ठा sshbuf;

/* Key types */
क्रमागत sshkey_types {
	कुंजी_RSA,
	कुंजी_ECDSA,
	कुंजी_ED25519,
	कुंजी_RSA_CERT,
	कुंजी_ECDSA_CERT,
	कुंजी_ED25519_CERT,
	कुंजी_ECDSA_SK,
	कुंजी_ECDSA_SK_CERT,
	कुंजी_ED25519_SK,
	कुंजी_ED25519_SK_CERT,
	कुंजी_MLDSA44_ED25519,
	कुंजी_MLDSA44_ED25519_CERT,
	कुंजी_UNSPEC
};

/* Default fingerprint hash */
#घोषणा SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
क्रमागत sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
क्रमागत sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
क्रमागत sshkey_private_format {
	SSHKEY_PRIVATE_OPENSSH = 0,
	SSHKEY_PRIVATE_PEM = 1,
	SSHKEY_PRIVATE_PKCS8 = 2,
};

/* key is stored in external hardware */
#घोषणा SSHKEY_FLAG_EXT		0x0001

#घोषणा SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
काष्ठा sshkey_cert {
	काष्ठा sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	अक्षर		*कुंजी_id;
	u_int		 nprincipals;
	अक्षर		**principals;
	uint64_t	 valid_after, valid_before;
	काष्ठा sshbuf	*critical;
	काष्ठा sshbuf	*extensions;
	काष्ठा sshkey	*signature_कुंजी;
	अक्षर		*signature_type;
};

/* XXX opacify? */
काष्ठा sshkey {
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
	काष्ठा sshbuf *sk_कुंजी_handle;
	काष्ठा sshbuf *sk_reserved;
	/* Certificates */
	काष्ठा sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	माप_प्रकार	shielded_len;
	u_char	*shield_prekey;
	माप_प्रकार	shield_prekey_len;
};

#घोषणा	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#घोषणा	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
काष्ठा sshkey_sig_details {
	uint32_t sk_गणक;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

काष्ठा sshkey_impl_funcs {
	u_int (*आकार)(स्थिर काष्ठा sshkey *);	/* optional */
	पूर्णांक (*alloc)(काष्ठा sshkey *);		/* optional */
	व्योम (*cleanup)(काष्ठा sshkey *);	/* optional */
	पूर्णांक (*equal)(स्थिर काष्ठा sshkey *, स्थिर काष्ठा sshkey *);
	पूर्णांक (*serialize_public)(स्थिर काष्ठा sshkey *, काष्ठा sshbuf *,
	    क्रमागत sshkey_serialize_rep);
	पूर्णांक (*deserialize_public)(स्थिर अक्षर *, काष्ठा sshbuf *,
	    काष्ठा sshkey *);
	पूर्णांक (*serialize_private)(स्थिर काष्ठा sshkey *, काष्ठा sshbuf *,
	    क्रमागत sshkey_serialize_rep);
	पूर्णांक (*deserialize_private)(स्थिर अक्षर *, काष्ठा sshbuf *,
	    काष्ठा sshkey *);
	पूर्णांक (*generate)(काष्ठा sshkey *, पूर्णांक);	/* optional */
	पूर्णांक (*copy_public)(स्थिर काष्ठा sshkey *, काष्ठा sshkey *);
	पूर्णांक (*sign)(काष्ठा sshkey *, u_char **, माप_प्रकार *,
	    स्थिर u_char *, माप_प्रकार, स्थिर अक्षर *,
	    स्थिर अक्षर *, स्थिर अक्षर *, u_int); /* optional */
	पूर्णांक (*verify)(स्थिर काष्ठा sshkey *, स्थिर u_char *, माप_प्रकार,
	    स्थिर u_char *, माप_प्रकार, स्थिर अक्षर *, u_int,
	    काष्ठा sshkey_sig_details **);
};

काष्ठा sshkey_impl {
	स्थिर अक्षर *name;
	स्थिर अक्षर *shortname;
	स्थिर अक्षर *sigalg;
	पूर्णांक type;
	पूर्णांक nid;
	पूर्णांक cert;
	पूर्णांक sigonly;
	पूर्णांक keybits;
	स्थिर काष्ठा sshkey_impl_funcs *funcs;
};

काष्ठा sshkey	*sshkey_new(पूर्णांक);
व्योम		 sshkey_free(काष्ठा sshkey *);
पूर्णांक		 sshkey_equal_public(स्थिर काष्ठा sshkey *,
    स्थिर काष्ठा sshkey *);
पूर्णांक		 sshkey_equal(स्थिर काष्ठा sshkey *, स्थिर काष्ठा sshkey *);
अक्षर		*sshkey_fingerprint(स्थिर काष्ठा sshkey *,
    पूर्णांक, क्रमागत sshkey_fp_rep);
पूर्णांक		 sshkey_fingerprint_raw(स्थिर काष्ठा sshkey *k,
    पूर्णांक, u_char **retp, माप_प्रकार *lenp);
स्थिर अक्षर	*sshkey_type(स्थिर काष्ठा sshkey *);
स्थिर अक्षर	*sshkey_cert_type(स्थिर काष्ठा sshkey *);
पूर्णांक		 sshkey_format_text(स्थिर काष्ठा sshkey *, काष्ठा sshbuf *);
पूर्णांक		 sshkey_write(स्थिर काष्ठा sshkey *, खाता *);
पूर्णांक		 sshkey_read(काष्ठा sshkey *, अक्षर **);
u_int		 sshkey_आकार(स्थिर काष्ठा sshkey *);

पूर्णांक		 sshkey_generate(पूर्णांक type, u_int bits, काष्ठा sshkey **keyp);
पूर्णांक		 sshkey_from_private(स्थिर काष्ठा sshkey *, काष्ठा sshkey **);

पूर्णांक		 sshkey_is_shielded(काष्ठा sshkey *);
पूर्णांक		 sshkey_shield_private(काष्ठा sshkey *);
पूर्णांक		 sshkey_unshield_private(काष्ठा sshkey *);

पूर्णांक	 sshkey_type_from_name(स्थिर अक्षर *);
पूर्णांक	 sshkey_type_from_shortname(स्थिर अक्षर *);
पूर्णांक	 sshkey_is_cert(स्थिर काष्ठा sshkey *);
पूर्णांक	 sshkey_is_sk(स्थिर काष्ठा sshkey *);
पूर्णांक	 sshkey_type_is_cert(पूर्णांक);
पूर्णांक	 sshkey_type_plain(पूर्णांक);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
पूर्णांक	 sshkey_match_keyname_to_sigalgs(स्थिर अक्षर *, स्थिर अक्षर *);

पूर्णांक	 sshkey_to_certified(काष्ठा sshkey *);
पूर्णांक	 sshkey_drop_cert(काष्ठा sshkey *);
पूर्णांक	 sshkey_cert_copy(स्थिर काष्ठा sshkey *, काष्ठा sshkey *);
पूर्णांक	 sshkey_cert_check_authority(स्थिर काष्ठा sshkey *, पूर्णांक, पूर्णांक,
    uint64_t, स्थिर अक्षर *, स्थिर अक्षर **);
पूर्णांक	 sshkey_cert_check_authority_now(स्थिर काष्ठा sshkey *, पूर्णांक, पूर्णांक,
    स्थिर अक्षर *, स्थिर अक्षर **);
पूर्णांक	 sshkey_cert_check_host(स्थिर काष्ठा sshkey *, स्थिर अक्षर *,
    स्थिर अक्षर *, स्थिर अक्षर **);
माप_प्रकार	 sshkey_format_cert_validity(स्थिर काष्ठा sshkey_cert *,
    अक्षर *, माप_प्रकार) __attribute__((__bounded__(__string__, 2, 3)));
पूर्णांक	 sshkey_check_cert_sigtype(स्थिर काष्ठा sshkey *, स्थिर अक्षर *);

पूर्णांक	 sshkey_certify(काष्ठा sshkey *, काष्ठा sshkey *,
    स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
प्रकार पूर्णांक sshkey_certify_signer(काष्ठा sshkey *, u_char **, माप_प्रकार *,
    स्थिर u_char *, माप_प्रकार, स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *,
    u_int, व्योम *);
पूर्णांक	 sshkey_certify_custom(काष्ठा sshkey *, काष्ठा sshkey *, स्थिर अक्षर *,
    स्थिर अक्षर *, स्थिर अक्षर *, sshkey_certify_signer *, व्योम *);

पूर्णांक		 sshkey_ecdsa_nid_from_name(स्थिर अक्षर *);
पूर्णांक		 sshkey_curve_name_to_nid(स्थिर अक्षर *);
स्थिर अक्षर *	 sshkey_curve_nid_to_name(पूर्णांक);
u_int		 sshkey_curve_nid_to_bits(पूर्णांक);
पूर्णांक		 sshkey_ecdsa_bits_to_nid(पूर्णांक);
पूर्णांक		 sshkey_ecdsa_कुंजी_to_nid(स्थिर EC_कुंजी *);
पूर्णांक		 sshkey_ecdsa_pkey_to_nid(EVP_PKEY *);
पूर्णांक		 sshkey_ec_nid_to_hash_alg(पूर्णांक nid);
पूर्णांक		 sshkey_ec_validate_public(स्थिर EC_GROUP *, स्थिर EC_POINT *);
पूर्णांक		 sshkey_ec_validate_private(स्थिर EC_कुंजी *);
स्थिर अक्षर	*sshkey_ssh_name(स्थिर काष्ठा sshkey *);
स्थिर अक्षर	*sshkey_ssh_name_plain(स्थिर काष्ठा sshkey *);
पूर्णांक		 sshkey_names_valid2(स्थिर अक्षर *, पूर्णांक, पूर्णांक);
अक्षर		*sshkey_alg_list(पूर्णांक, पूर्णांक, पूर्णांक, अक्षर);

पूर्णांक	 sshkey_from_blob(स्थिर u_char *, माप_प्रकार, काष्ठा sshkey **);
पूर्णांक	 sshkey_fromb(काष्ठा sshbuf *, काष्ठा sshkey **);
पूर्णांक	 sshkey_fromb_allowlist(काष्ठा sshbuf *, काष्ठा sshkey **,
    स्थिर अक्षर *, स्थिर अक्षर *);
पूर्णांक	 sshkey_froms(काष्ठा sshbuf *, काष्ठा sshkey **);
पूर्णांक	 sshkey_to_blob(स्थिर काष्ठा sshkey *, u_char **, माप_प्रकार *);
पूर्णांक	 sshkey_to_base64(स्थिर काष्ठा sshkey *, अक्षर **);
पूर्णांक	 sshkey_putb(स्थिर काष्ठा sshkey *, काष्ठा sshbuf *);
पूर्णांक	 sshkey_puts(स्थिर काष्ठा sshkey *, काष्ठा sshbuf *);
पूर्णांक	 sshkey_plain_to_blob(स्थिर काष्ठा sshkey *, u_char **, माप_प्रकार *);
पूर्णांक	 sshkey_putb_plain(स्थिर काष्ठा sshkey *, काष्ठा sshbuf *);
पूर्णांक	 sshkey_puts_plain(स्थिर काष्ठा sshkey *, काष्ठा sshbuf *);

पूर्णांक	 sshkey_sign(काष्ठा sshkey *, u_char **, माप_प्रकार *,
    स्थिर u_char *, माप_प्रकार, स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *, u_int);
पूर्णांक	 sshkey_verify(स्थिर काष्ठा sshkey *, स्थिर u_char *, माप_प्रकार,
    स्थिर u_char *, माप_प्रकार, स्थिर अक्षर *, u_int, काष्ठा sshkey_sig_details **);
पूर्णांक	 sshkey_check_sigtype(स्थिर u_char *, माप_प्रकार, स्थिर अक्षर *);
स्थिर अक्षर *sshkey_sigalg_by_name(स्थिर अक्षर *);
पूर्णांक	 sshkey_get_sigtype(स्थिर u_char *, माप_प्रकार, अक्षर **);

/* Signing and verification backend for libcrypto-backed keys */
पूर्णांक	sshkey_pkey_digest_sign(EVP_PKEY*, पूर्णांक, u_char **,
    माप_प्रकार *, स्थिर u_char *, माप_प्रकार);
पूर्णांक	sshkey_pkey_digest_verify(EVP_PKEY *, पूर्णांक, स्थिर u_char *,
    माप_प्रकार, u_char *, माप_प्रकार);

/* for debug */
व्योम	sshkey_dump_ec_point(स्थिर EC_GROUP *, स्थिर EC_POINT *);
व्योम	sshkey_dump_ec_कुंजी(स्थिर EC_कुंजी *);

/* private key parsing and serialisation */
पूर्णांक	sshkey_private_serialize(काष्ठा sshkey *कुंजी, काष्ठा sshbuf *buf);
पूर्णांक	sshkey_private_deserialize(काष्ठा sshbuf *buf,  काष्ठा sshkey **keyp);

/* private key file format parsing and serialisation */
पूर्णांक	sshkey_private_to_fileblob(काष्ठा sshkey *कुंजी, काष्ठा sshbuf *blob,
    स्थिर अक्षर *passphrase, स्थिर अक्षर *comment,
    पूर्णांक format, स्थिर अक्षर *openssh_format_cipher, पूर्णांक openssh_format_rounds);
पूर्णांक	sshkey_parse_private_fileblob(काष्ठा sshbuf *बफर,
    स्थिर अक्षर *passphrase, काष्ठा sshkey **keyp, अक्षर **commentp);
पूर्णांक	sshkey_parse_private_fileblob_type(काष्ठा sshbuf *blob, पूर्णांक type,
    स्थिर अक्षर *passphrase, काष्ठा sshkey **keyp, अक्षर **commentp);
पूर्णांक	sshkey_parse_pubkey_from_private_fileblob_type(काष्ठा sshbuf *blob,
    पूर्णांक type, काष्ठा sshkey **pubkeyp);

पूर्णांक sshkey_check_rsa_लंबाई(स्थिर काष्ठा sshkey *, पूर्णांक);
पूर्णांक	ssh_rsa_hash_id_from_keyname(स्थिर अक्षर *);
स्थिर अक्षर *ssh_rsa_hash_alg_ident(पूर्णांक);
पूर्णांक	ssh_rsa_encode_store_sig(पूर्णांक, स्थिर u_char *, माप_प्रकार,
	    u_char **, माप_प्रकार *);
पूर्णांक	ssh_ecdsa_encode_store_sig(स्थिर काष्ठा sshkey *,
	    स्थिर BIGNUM *, स्थिर BIGNUM *, u_char **, माप_प्रकार *);
पूर्णांक	ssh_ed25519_encode_store_sig(स्थिर u_char *, माप_प्रकार,
	    u_char **, माप_प्रकार *);
/* XXX should be internal, but used by ssh-keygen */
पूर्णांक ssh_rsa_complete_crt_parameters(स्थिर BIGNUM *, स्थिर BIGNUM *,
    स्थिर BIGNUM *, स्थिर BIGNUM *, BIGNUM **, BIGNUM **);

व्योम	 sshkey_sig_details_free(काष्ठा sshkey_sig_details *);

#अगर_घोषित WITH_OPENSSL
पूर्णांक	sshkey_ecdsa_fixup_group(EVP_PKEY *k); /* ssh-ecdsa.c */
#पूर्ण_अगर

#अगर_घोषित SSHKEY_INTERNAL
पूर्णांक	sshkey_sk_fields_equal(स्थिर काष्ठा sshkey *a, स्थिर काष्ठा sshkey *b);
व्योम	sshkey_sk_cleanup(काष्ठा sshkey *k);
पूर्णांक	sshkey_serialize_sk(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b);
पूर्णांक	sshkey_copy_public_sk(स्थिर काष्ठा sshkey *from, काष्ठा sshkey *to);
पूर्णांक	sshkey_deserialize_sk(काष्ठा sshbuf *b, काष्ठा sshkey *कुंजी);
पूर्णांक	sshkey_serialize_private_sk(स्थिर काष्ठा sshkey *कुंजी,
    काष्ठा sshbuf *buf);
पूर्णांक	sshkey_private_deserialize_sk(काष्ठा sshbuf *buf, काष्ठा sshkey *k);
#अगर_घोषित WITH_OPENSSL
पूर्णांक	check_rsa_लंबाई(स्थिर RSA *rsa); /* XXX remove */
#पूर्ण_अगर
#पूर्ण_अगर

#अगर_अघोषित WITH_OPENSSL
#अघोषित RSA
#अघोषित EC_कुंजी
#अघोषित EC_GROUP
#अघोषित EC_POINT
#अघोषित EVP_PKEY
#पूर्ण_अगर /* WITH_OPENSSL */

#पूर्ण_अगर /* SSHKEY_H */
