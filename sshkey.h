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

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/rsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#define SSH_OPENSSL_VERSION OpenSSL_version(OPENSSL_VERSION)
#ಅನ್ಯಥಾ /* OPENSSL */
#define BIGNUM		ಶೂನ್ಯ
#define RSA		ಶೂನ್ಯ
#define EC_ಕೀಲಿ		ಶೂನ್ಯ
#define EC_GROUP	ಶೂನ್ಯ
#define EC_POINT	ಶೂನ್ಯ
#define EVP_PKEY	ಶೂನ್ಯ
#define SSH_OPENSSL_VERSION "without OpenSSL"
#endif /* WITH_OPENSSL */

#define SSH_RSA_MINIMUM_MODULUS_SIZE	1024
#define SSH_ಕೀಲಿ_MAX_SIGN_DATA_SIZE	(1 << 20)

ಸಂರಚನಾ sshbuf;

/* Key types */
ಗಣನಾ sshkey_types {
	ಕೀಲಿ_RSA,
	ಕೀಲಿ_ECDSA,
	ಕೀಲಿ_ED25519,
	ಕೀಲಿ_RSA_CERT,
	ಕೀಲಿ_ECDSA_CERT,
	ಕೀಲಿ_ED25519_CERT,
	ಕೀಲಿ_ECDSA_SK,
	ಕೀಲಿ_ECDSA_SK_CERT,
	ಕೀಲಿ_ED25519_SK,
	ಕೀಲಿ_ED25519_SK_CERT,
	ಕೀಲಿ_MLDSA44_ED25519,
	ಕೀಲಿ_MLDSA44_ED25519_CERT,
	ಕೀಲಿ_UNSPEC
};

/* Default fingerprint hash */
#define SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
ಗಣನಾ sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
ಗಣನಾ sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
ಗಣನಾ sshkey_private_format {
	SSHKEY_PRIVATE_OPENSSH = 0,
	SSHKEY_PRIVATE_PEM = 1,
	SSHKEY_PRIVATE_PKCS8 = 2,
};

/* key is stored in external hardware */
#define SSHKEY_FLAG_EXT		0x0001

#define SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
ಸಂರಚನಾ sshkey_cert {
	ಸಂರಚನಾ sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	ವರ್ಣ		*ಕೀಲಿ_id;
	u_int		 nprincipals;
	ವರ್ಣ		**principals;
	uint64_t	 valid_after, valid_before;
	ಸಂರಚನಾ sshbuf	*critical;
	ಸಂರಚನಾ sshbuf	*extensions;
	ಸಂರಚನಾ sshkey	*signature_ಕೀಲಿ;
	ವರ್ಣ		*signature_type;
};

/* XXX opacify? */
ಸಂರಚನಾ sshkey {
	ಪೂರ್ಣಾಙ್ಕ	 type;
	ಪೂರ್ಣಾಙ್ಕ	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	ಪೂರ್ಣಾಙ್ಕ	 ecdsa_nid;	/* NID of curve */
	/* libcrypto-backed keys */
	EVP_PKEY *pkey;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_MLDSA44_ED25519 */
	u_char	*mldsa_ed25519_sk;
	u_char	*mldsa_ed25519_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	ವರ್ಣ	*sk_application;
	uint8_t	sk_flags;
	ಸಂರಚನಾ sshbuf *sk_ಕೀಲಿ_handle;
	ಸಂರಚನಾ sshbuf *sk_reserved;
	/* Certificates */
	ಸಂರಚನಾ sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	size_t	shielded_len;
	u_char	*shield_prekey;
	size_t	shield_prekey_len;
};

#define	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#define	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
ಸಂರಚನಾ sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

ಸಂರಚನಾ sshkey_impl_funcs {
	u_int (*size)(ಧ್ರುವ ಸಂರಚನಾ sshkey *);	/* optional */
	ಪೂರ್ಣಾಙ್ಕ (*alloc)(ಸಂರಚನಾ sshkey *);		/* optional */
	ಶೂನ್ಯ (*cleanup)(ಸಂರಚನಾ sshkey *);	/* optional */
	ಪೂರ್ಣಾಙ್ಕ (*equal)(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಧ್ರುವ ಸಂರಚನಾ sshkey *);
	ಪೂರ್ಣಾಙ್ಕ (*serialize_public)(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ sshbuf *,
	    ಗಣನಾ sshkey_serialize_rep);
	ಪೂರ್ಣಾಙ್ಕ (*deserialize_public)(ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ sshbuf *,
	    ಸಂರಚನಾ sshkey *);
	ಪೂರ್ಣಾಙ್ಕ (*serialize_private)(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ sshbuf *,
	    ಗಣನಾ sshkey_serialize_rep);
	ಪೂರ್ಣಾಙ್ಕ (*deserialize_private)(ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ sshbuf *,
	    ಸಂರಚನಾ sshkey *);
	ಪೂರ್ಣಾಙ್ಕ (*generate)(ಸಂರಚನಾ sshkey *, ಪೂರ್ಣಾಙ್ಕ);	/* optional */
	ಪೂರ್ಣಾಙ್ಕ (*copy_public)(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ sshkey *);
	ಪೂರ್ಣಾಙ್ಕ (*sign)(ಸಂರಚನಾ sshkey *, u_char **, size_t *,
	    ಧ್ರುವ u_char *, size_t, ಧ್ರುವ ವರ್ಣ *,
	    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, u_int); /* optional */
	ಪೂರ್ಣಾಙ್ಕ (*verify)(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಧ್ರುವ u_char *, size_t,
	    ಧ್ರುವ u_char *, size_t, ಧ್ರುವ ವರ್ಣ *, u_int,
	    ಸಂರಚನಾ sshkey_sig_details **);
};

ಸಂರಚನಾ sshkey_impl {
	ಧ್ರುವ ವರ್ಣ *name;
	ಧ್ರುವ ವರ್ಣ *shortname;
	ಧ್ರುವ ವರ್ಣ *sigalg;
	ಪೂರ್ಣಾಙ್ಕ type;
	ಪೂರ್ಣಾಙ್ಕ nid;
	ಪೂರ್ಣಾಙ್ಕ cert;
	ಪೂರ್ಣಾಙ್ಕ sigonly;
	ಪೂರ್ಣಾಙ್ಕ keybits;
	ಧ್ರುವ ಸಂರಚನಾ sshkey_impl_funcs *funcs;
};

ಸಂರಚನಾ sshkey	*sshkey_new(ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ		 sshkey_free(ಸಂರಚನಾ sshkey *);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_equal_public(ಧ್ರುವ ಸಂರಚನಾ sshkey *,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_equal(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಧ್ರುವ ಸಂರಚನಾ sshkey *);
ವರ್ಣ		*sshkey_fingerprint(ಧ್ರುವ ಸಂರಚನಾ sshkey *,
    ಪೂರ್ಣಾಙ್ಕ, ಗಣನಾ sshkey_fp_rep);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_fingerprint_raw(ಧ್ರುವ ಸಂರಚನಾ sshkey *k,
    ಪೂರ್ಣಾಙ್ಕ, u_char **retp, size_t *lenp);
ಧ್ರುವ ವರ್ಣ	*sshkey_type(ಧ್ರುವ ಸಂರಚನಾ sshkey *);
ಧ್ರುವ ವರ್ಣ	*sshkey_cert_type(ಧ್ರುವ ಸಂರಚನಾ sshkey *);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_format_text(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_write(ಧ್ರುವ ಸಂರಚನಾ sshkey *, FILE *);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_read(ಸಂರಚನಾ sshkey *, ವರ್ಣ **);
u_int		 sshkey_size(ಧ್ರುವ ಸಂರಚನಾ sshkey *);

ಪೂರ್ಣಾಙ್ಕ		 sshkey_generate(ಪೂರ್ಣಾಙ್ಕ type, u_int bits, ಸಂರಚನಾ sshkey **keyp);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_from_private(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ sshkey **);

ಪೂರ್ಣಾಙ್ಕ		 sshkey_is_shielded(ಸಂರಚನಾ sshkey *);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_shield_private(ಸಂರಚನಾ sshkey *);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_unshield_private(ಸಂರಚನಾ sshkey *);

ಪೂರ್ಣಾಙ್ಕ	 sshkey_type_from_name(ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_type_from_shortname(ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_is_cert(ಧ್ರುವ ಸಂರಚನಾ sshkey *);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_is_sk(ಧ್ರುವ ಸಂರಚನಾ sshkey *);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_type_is_cert(ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_type_plain(ಪೂರ್ಣಾಙ್ಕ);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
ಪೂರ್ಣಾಙ್ಕ	 sshkey_match_keyname_to_sigalgs(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);

ಪೂರ್ಣಾಙ್ಕ	 sshkey_to_certified(ಸಂರಚನಾ sshkey *);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_drop_cert(ಸಂರಚನಾ sshkey *);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_cert_copy(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ sshkey *);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_cert_check_authority(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ,
    uint64_t, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ **);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_cert_check_authority_now(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ,
    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ **);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_cert_check_host(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ **);
size_t	 sshkey_format_cert_validity(ಧ್ರುವ ಸಂರಚನಾ sshkey_cert *,
    ವರ್ಣ *, size_t) __attribute__((__bounded__(__string__, 2, 3)));
ಪೂರ್ಣಾಙ್ಕ	 sshkey_check_cert_sigtype(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಧ್ರುವ ವರ್ಣ *);

ಪೂರ್ಣಾಙ್ಕ	 sshkey_certify(ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ sshkey *,
    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
ಪ್ರಕಾರನಿರ್ದೇಶ ಪೂರ್ಣಾಙ್ಕ sshkey_certify_signer(ಸಂರಚನಾ sshkey *, u_char **, size_t *,
    ಧ್ರುವ u_char *, size_t, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *,
    u_int, ಶೂನ್ಯ *);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_certify_custom(ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ sshkey *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, sshkey_certify_signer *, ಶೂನ್ಯ *);

ಪೂರ್ಣಾಙ್ಕ		 sshkey_ecdsa_nid_from_name(ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_curve_name_to_nid(ಧ್ರುವ ವರ್ಣ *);
ಧ್ರುವ ವರ್ಣ *	 sshkey_curve_nid_to_name(ಪೂರ್ಣಾಙ್ಕ);
u_int		 sshkey_curve_nid_to_bits(ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_ecdsa_bits_to_nid(ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_ecdsa_ಕೀಲಿ_to_nid(ಧ್ರುವ EC_ಕೀಲಿ *);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_ecdsa_pkey_to_nid(EVP_PKEY *);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_ec_nid_to_hash_alg(ಪೂರ್ಣಾಙ್ಕ nid);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_ec_validate_public(ಧ್ರುವ EC_GROUP *, ಧ್ರುವ EC_POINT *);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_ec_validate_private(ಧ್ರುವ EC_ಕೀಲಿ *);
ಧ್ರುವ ವರ್ಣ	*sshkey_ssh_name(ಧ್ರುವ ಸಂರಚನಾ sshkey *);
ಧ್ರುವ ವರ್ಣ	*sshkey_ssh_name_plain(ಧ್ರುವ ಸಂರಚನಾ sshkey *);
ಪೂರ್ಣಾಙ್ಕ		 sshkey_names_valid2(ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ವರ್ಣ		*sshkey_alg_list(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ);

ಪೂರ್ಣಾಙ್ಕ	 sshkey_from_blob(ಧ್ರುವ u_char *, size_t, ಸಂರಚನಾ sshkey **);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_fromb(ಸಂರಚನಾ sshbuf *, ಸಂರಚನಾ sshkey **);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_fromb_allowlist(ಸಂರಚನಾ sshbuf *, ಸಂರಚನಾ sshkey **,
    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_froms(ಸಂರಚನಾ sshbuf *, ಸಂರಚನಾ sshkey **);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_to_blob(ಧ್ರುವ ಸಂರಚನಾ sshkey *, u_char **, size_t *);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_to_base64(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ವರ್ಣ **);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_putb(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_puts(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_plain_to_blob(ಧ್ರುವ ಸಂರಚನಾ sshkey *, u_char **, size_t *);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_putb_plain(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_puts_plain(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ sshbuf *);

ಪೂರ್ಣಾಙ್ಕ	 sshkey_sign(ಸಂರಚನಾ sshkey *, u_char **, size_t *,
    ಧ್ರುವ u_char *, size_t, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, u_int);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_verify(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಧ್ರುವ u_char *, size_t,
    ಧ್ರುವ u_char *, size_t, ಧ್ರುವ ವರ್ಣ *, u_int, ಸಂರಚನಾ sshkey_sig_details **);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_check_sigtype(ಧ್ರುವ u_char *, size_t, ಧ್ರುವ ವರ್ಣ *);
ಧ್ರುವ ವರ್ಣ *sshkey_sigalg_by_name(ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 sshkey_get_sigtype(ಧ್ರುವ u_char *, size_t, ವರ್ಣ **);

/* Signing and verification backend for libcrypto-backed keys */
ಪೂರ್ಣಾಙ್ಕ	sshkey_pkey_digest_sign(EVP_PKEY*, ಪೂರ್ಣಾಙ್ಕ, u_char **,
    size_t *, ಧ್ರುವ u_char *, size_t);
ಪೂರ್ಣಾಙ್ಕ	sshkey_pkey_digest_verify(EVP_PKEY *, ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ u_char *,
    size_t, u_char *, size_t);

/* for debug */
ಶೂನ್ಯ	sshkey_dump_ec_point(ಧ್ರುವ EC_GROUP *, ಧ್ರುವ EC_POINT *);
ಶೂನ್ಯ	sshkey_dump_ec_ಕೀಲಿ(ಧ್ರುವ EC_ಕೀಲಿ *);

/* private key parsing and serialisation */
ಪೂರ್ಣಾಙ್ಕ	sshkey_private_serialize(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *buf);
ಪೂರ್ಣಾಙ್ಕ	sshkey_private_deserialize(ಸಂರಚನಾ sshbuf *buf,  ಸಂರಚನಾ sshkey **keyp);

/* private key file format parsing and serialisation */
ಪೂರ್ಣಾಙ್ಕ	sshkey_private_to_fileblob(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *blob,
    ಧ್ರುವ ವರ್ಣ *passphrase, ಧ್ರುವ ವರ್ಣ *comment,
    ಪೂರ್ಣಾಙ್ಕ format, ಧ್ರುವ ವರ್ಣ *openssh_format_cipher, ಪೂರ್ಣಾಙ್ಕ openssh_format_rounds);
ಪೂರ್ಣಾಙ್ಕ	sshkey_parse_private_fileblob(ಸಂರಚನಾ sshbuf *buffer,
    ಧ್ರುವ ವರ್ಣ *passphrase, ಸಂರಚನಾ sshkey **keyp, ವರ್ಣ **commentp);
ಪೂರ್ಣಾಙ್ಕ	sshkey_parse_private_fileblob_type(ಸಂರಚನಾ sshbuf *blob, ಪೂರ್ಣಾಙ್ಕ type,
    ಧ್ರುವ ವರ್ಣ *passphrase, ಸಂರಚನಾ sshkey **keyp, ವರ್ಣ **commentp);
ಪೂರ್ಣಾಙ್ಕ	sshkey_parse_pubkey_from_private_fileblob_type(ಸಂರಚನಾ sshbuf *blob,
    ಪೂರ್ಣಾಙ್ಕ type, ಸಂರಚನಾ sshkey **pubkeyp);

ಪೂರ್ಣಾಙ್ಕ sshkey_check_rsa_length(ಧ್ರುವ ಸಂರಚನಾ sshkey *, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	ssh_rsa_hash_id_from_keyname(ಧ್ರುವ ವರ್ಣ *);
ಧ್ರುವ ವರ್ಣ *ssh_rsa_hash_alg_ident(ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	ssh_rsa_encode_store_sig(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ u_char *, size_t,
	    u_char **, size_t *);
ಪೂರ್ಣಾಙ್ಕ	ssh_ecdsa_encode_store_sig(ಧ್ರುವ ಸಂರಚನಾ sshkey *,
	    ಧ್ರುವ BIGNUM *, ಧ್ರುವ BIGNUM *, u_char **, size_t *);
ಪೂರ್ಣಾಙ್ಕ	ssh_ed25519_encode_store_sig(ಧ್ರುವ u_char *, size_t,
	    u_char **, size_t *);
/* XXX should be internal, but used by ssh-keygen */
ಪೂರ್ಣಾಙ್ಕ ssh_rsa_complete_crt_parameters(ಧ್ರುವ BIGNUM *, ಧ್ರುವ BIGNUM *,
    ಧ್ರುವ BIGNUM *, ಧ್ರುವ BIGNUM *, BIGNUM **, BIGNUM **);

ಶೂನ್ಯ	 sshkey_sig_details_free(ಸಂರಚನಾ sshkey_sig_details *);

#ifdef WITH_OPENSSL
ಪೂರ್ಣಾಙ್ಕ	sshkey_ecdsa_fixup_group(EVP_PKEY *k); /* ssh-ecdsa.c */
#endif

#ifdef SSHKEY_INTERNAL
ಪೂರ್ಣಾಙ್ಕ	sshkey_sk_fields_equal(ಧ್ರುವ ಸಂರಚನಾ sshkey *a, ಧ್ರುವ ಸಂರಚನಾ sshkey *b);
ಶೂನ್ಯ	sshkey_sk_cleanup(ಸಂರಚನಾ sshkey *k);
ಪೂರ್ಣಾಙ್ಕ	sshkey_serialize_sk(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b);
ಪೂರ್ಣಾಙ್ಕ	sshkey_copy_public_sk(ಧ್ರುವ ಸಂರಚನಾ sshkey *from, ಸಂರಚನಾ sshkey *to);
ಪೂರ್ಣಾಙ್ಕ	sshkey_deserialize_sk(ಸಂರಚನಾ sshbuf *b, ಸಂರಚನಾ sshkey *ಕೀಲಿ);
ಪೂರ್ಣಾಙ್ಕ	sshkey_serialize_private_sk(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಸಂರಚನಾ sshbuf *buf);
ಪೂರ್ಣಾಙ್ಕ	sshkey_private_deserialize_sk(ಸಂರಚನಾ sshbuf *buf, ಸಂರಚನಾ sshkey *k);
#ifdef WITH_OPENSSL
ಪೂರ್ಣಾಙ್ಕ	check_rsa_length(ಧ್ರುವ RSA *rsa); /* XXX remove */
#endif
#endif

#ifndef WITH_OPENSSL
#undef RSA
#undef EC_ಕೀಲಿ
#undef EC_GROUP
#undef EC_POINT
#undef EVP_PKEY
#endif /* WITH_OPENSSL */

#endif /* SSHKEY_H */
