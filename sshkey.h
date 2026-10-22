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
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SSHKEY_H
#ವ್ಯಾಖ್ಯಾನಿಸು SSHKEY_H

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/rsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_OPENSSL_ಆವೃತ್ತಿ Open_SSL_ಆವೃತ್ತಿ(OPENSSL_ಆವೃತ್ತಿ)
#ಇಲ್ಲದಿದ್ದರೆ /* OPENSSL */
#ವ್ಯಾಖ್ಯಾನಿಸು BIGNUM		ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು RSA		ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು EC_ಕೀಲಿ		ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು EC_ಗುಂಪು	ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು EC_ಬಿಂದು	ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು EVP_PKEY	ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_OPENSSL_ಆವೃತ್ತಿ "without OpenSSL"
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_RSA_MINIMUM_MODULUS_ಗಾತ್ರ	1024
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ಕೀಲಿ_MAX_SIGN_ದತ್ತಾಂಶ_ಗಾತ್ರ	(1 << 20)

ರಚನೆ sshbuf;

/* Key types */
ಎಣಿಕೆ sshkey_types {
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
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
ಎಣಿಕೆ sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
ಎಣಿಕೆ sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
ಎಣಿಕೆ sshkey_ಖಾಸಗಿ_format {
	SSHKEY_ಖಾಸಗಿ_OPENSSH = 0,
	SSHKEY_ಖಾಸಗಿ_PEM = 1,
	SSHKEY_ಖಾಸಗಿ_PKCS8 = 2,
};

/* key is stored in external hardware */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHKEY_FLAG_EXT		0x0001

#ವ್ಯಾಖ್ಯಾನಿಸು SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
ರಚನೆ sshkey_cert {
	ರಚನೆ sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	ಅಕ್ಷರ		*ಕೀಲಿ_id;
	u_int		 nprincipals;
	ಅಕ್ಷರ		**principals;
	uint64_t	 valid_after, valid_before;
	ರಚನೆ sshbuf	*critical;
	ರಚನೆ sshbuf	*extensions;
	ರಚನೆ sshkey	*signature_ಕೀಲಿ;
	ಅಕ್ಷರ		*signature_type;
};

/* XXX opacify? */
ರಚನೆ sshkey {
	ಪೂರ್ಣಾಂಕ	 type;
	ಪೂರ್ಣಾಂಕ	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	ಪೂರ್ಣಾಂಕ	 ecdsa_nid;	/* NID of curve */
	/* libcrypto-backed keys */
	EVP_PKEY *pkey;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_MLDSA44_ED25519 */
	u_char	*mldsa_ed25519_sk;
	u_char	*mldsa_ed25519_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	ಅಕ್ಷರ	*sk_application;
	uint8_t	sk_flags;
	ರಚನೆ sshbuf *sk_ಕೀಲಿ_handle;
	ರಚನೆ sshbuf *sk_reserved;
	/* Certificates */
	ರಚನೆ sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_ಖಾಸಗಿ;
	ಗಾತ್ರ_t	shielded_len;
	u_char	*shield_prekey;
	ಗಾತ್ರ_t	shield_prekey_len;
};

#ವ್ಯಾಖ್ಯಾನಿಸು	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#ವ್ಯಾಖ್ಯಾನಿಸು	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
ರಚನೆ sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

ರಚನೆ sshkey_impl_funcs {
	u_int (*ಗಾತ್ರ_2)(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *);	/* optional */
	ಪೂರ್ಣಾಂಕ (*alloc)(ರಚನೆ sshkey *);		/* optional */
	ಶೂನ್ಯ (*cleanup)(ರಚನೆ sshkey *);	/* optional */
	ಪೂರ್ಣಾಂಕ (*equal)(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *);
	ಪೂರ್ಣಾಂಕ (*serialize_ಬಹಿರಂಗ)(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ರಚನೆ sshbuf *,
	    ಎಣಿಕೆ sshkey_serialize_rep);
	ಪೂರ್ಣಾಂಕ (*deserialize_ಬಹಿರಂಗ)(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sshbuf *,
	    ರಚನೆ sshkey *);
	ಪೂರ್ಣಾಂಕ (*serialize_ಖಾಸಗಿ)(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ರಚನೆ sshbuf *,
	    ಎಣಿಕೆ sshkey_serialize_rep);
	ಪೂರ್ಣಾಂಕ (*deserialize_ಖಾಸಗಿ)(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sshbuf *,
	    ರಚನೆ sshkey *);
	ಪೂರ್ಣಾಂಕ (*generate)(ರಚನೆ sshkey *, ಪೂರ್ಣಾಂಕ);	/* optional */
	ಪೂರ್ಣಾಂಕ (*copy_ಬಹಿರಂಗ)(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ರಚನೆ sshkey *);
	ಪೂರ್ಣಾಂಕ (*sign)(ರಚನೆ sshkey *, u_char **, ಗಾತ್ರ_t *,
	    ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, u_int); /* optional */
	ಪೂರ್ಣಾಂಕ (*verify)(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t,
	    ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, u_int,
	    ರಚನೆ sshkey_sig_details **);
};

ರಚನೆ sshkey_impl {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *shortname;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sigalg;
	ಪೂರ್ಣಾಂಕ type;
	ಪೂರ್ಣಾಂಕ nid;
	ಪೂರ್ಣಾಂಕ cert;
	ಪೂರ್ಣಾಂಕ sigonly;
	ಪೂರ್ಣಾಂಕ keybits;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl_funcs *funcs;
};

ರಚನೆ sshkey	*sshkey_new(ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ		 sshkey_free(ರಚನೆ sshkey *);
ಪೂರ್ಣಾಂಕ		 sshkey_equal_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *);
ಪೂರ್ಣಾಂಕ		 sshkey_equal(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *);
ಅಕ್ಷರ		*sshkey_fingerprint(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *,
    ಪೂರ್ಣಾಂಕ, ಎಣಿಕೆ sshkey_fp_rep);
ಪೂರ್ಣಾಂಕ		 sshkey_fingerprint_raw(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *k,
    ಪೂರ್ಣಾಂಕ, u_char **retp, ಗಾತ್ರ_t *lenp);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ	*sshkey_type(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ	*sshkey_cert_type(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *);
ಪೂರ್ಣಾಂಕ		 sshkey_format_ಪಠ್ಯ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ		 sshkey_write(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, FILE *);
ಪೂರ್ಣಾಂಕ		 sshkey_read(ರಚನೆ sshkey *, ಅಕ್ಷರ **);
u_int		 sshkey_ಗಾತ್ರ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *);

ಪೂರ್ಣಾಂಕ		 sshkey_generate(ಪೂರ್ಣಾಂಕ type, u_int ಬಿಟ್ಟುಗಳು, ರಚನೆ sshkey **keyp);
ಪೂರ್ಣಾಂಕ		 sshkey_from_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ರಚನೆ sshkey **);

ಪೂರ್ಣಾಂಕ		 sshkey_is_shielded(ರಚನೆ sshkey *);
ಪೂರ್ಣಾಂಕ		 sshkey_shield_ಖಾಸಗಿ(ರಚನೆ sshkey *);
ಪೂರ್ಣಾಂಕ		 sshkey_unshield_ಖಾಸಗಿ(ರಚನೆ sshkey *);

ಪೂರ್ಣಾಂಕ	 sshkey_type_from_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 sshkey_type_from_shortname(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 sshkey_is_cert(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *);
ಪೂರ್ಣಾಂಕ	 sshkey_is_sk(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *);
ಪೂರ್ಣಾಂಕ	 sshkey_type_is_cert(ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 sshkey_type_plain(ಪೂರ್ಣಾಂಕ);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
ಪೂರ್ಣಾಂಕ	 sshkey_ಹೊಂದಿಕೆ_keyname_ಗಮ್ಯ_sigalgs(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ಪೂರ್ಣಾಂಕ	 sshkey_ಗಮ್ಯ_certified(ರಚನೆ sshkey *);
ಪೂರ್ಣಾಂಕ	 sshkey_drop_cert(ರಚನೆ sshkey *);
ಪೂರ್ಣಾಂಕ	 sshkey_cert_copy(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ರಚನೆ sshkey *);
ಪೂರ್ಣಾಂಕ	 sshkey_cert_check_authority(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ,
    uint64_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **);
ಪೂರ್ಣಾಂಕ	 sshkey_cert_check_authority_now(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **);
ಪೂರ್ಣಾಂಕ	 sshkey_cert_check_host(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **);
ಗಾತ್ರ_t	 sshkey_format_cert_validity(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_cert *,
    ಅಕ್ಷರ *, ಗಾತ್ರ_t) __attribute__((__bounded__(__string__, 2, 3)));
ಪೂರ್ಣಾಂಕ	 sshkey_check_cert_sigtype(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ಪೂರ್ಣಾಂಕ	 sshkey_certify(ರಚನೆ sshkey *, ರಚನೆ sshkey *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಪೂರ್ಣಾಂಕ sshkey_certify_signer(ರಚನೆ sshkey *, u_char **, ಗಾತ್ರ_t *,
    ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    u_int, ಶೂನ್ಯ *);
ಪೂರ್ಣಾಂಕ	 sshkey_certify_custom(ರಚನೆ sshkey *, ರಚನೆ sshkey *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, sshkey_certify_signer *, ಶೂನ್ಯ *);

ಪೂರ್ಣಾಂಕ		 sshkey_ecdsa_nid_from_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ		 sshkey_ವಕ್ರ_name_ಗಮ್ಯ_nid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *	 sshkey_ವಕ್ರ_nid_ಗಮ್ಯ_name(ಪೂರ್ಣಾಂಕ);
u_int		 sshkey_ವಕ್ರ_nid_ಗಮ್ಯ_ಬಿಟ್ಟುಗಳು(ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ		 sshkey_ecdsa_ಬಿಟ್ಟುಗಳು_ಗಮ್ಯ_nid(ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ		 sshkey_ecdsa_ಕೀಲಿ_ಗಮ್ಯ_nid(ಸ್ಥಿರಾಂಕ EC_ಕೀಲಿ *);
ಪೂರ್ಣಾಂಕ		 sshkey_ecdsa_pkey_ಗಮ್ಯ_nid(EVP_PKEY *);
ಪೂರ್ಣಾಂಕ		 sshkey_ec_nid_ಗಮ್ಯ_hash_alg(ಪೂರ್ಣಾಂಕ nid);
ಪೂರ್ಣಾಂಕ		 sshkey_ec_validate_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *, ಸ್ಥಿರಾಂಕ EC_ಬಿಂದು *);
ಪೂರ್ಣಾಂಕ		 sshkey_ec_validate_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ EC_ಕೀಲಿ *);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ	*sshkey_ssh_name(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ	*sshkey_ssh_name_plain(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *);
ಪೂರ್ಣಾಂಕ		 sshkey_ಹೆಸರುಗಳು_valid2(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಅಕ್ಷರ		*sshkey_alg_list(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ);

ಪೂರ್ಣಾಂಕ	 sshkey_from_blob(ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t, ರಚನೆ sshkey **);
ಪೂರ್ಣಾಂಕ	 sshkey_fromb(ರಚನೆ sshbuf *, ರಚನೆ sshkey **);
ಪೂರ್ಣಾಂಕ	 sshkey_fromb_allowlist(ರಚನೆ sshbuf *, ರಚನೆ sshkey **,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 sshkey_froms(ರಚನೆ sshbuf *, ರಚನೆ sshkey **);
ಪೂರ್ಣಾಂಕ	 sshkey_ಗಮ್ಯ_blob(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, u_char **, ಗಾತ್ರ_t *);
ಪೂರ್ಣಾಂಕ	 sshkey_ಗಮ್ಯ_base64(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ಅಕ್ಷರ **);
ಪೂರ್ಣಾಂಕ	 sshkey_putb(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ	 sshkey_puts(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ	 sshkey_plain_ಗಮ್ಯ_blob(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, u_char **, ಗಾತ್ರ_t *);
ಪೂರ್ಣಾಂಕ	 sshkey_putb_plain(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ	 sshkey_puts_plain(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ರಚನೆ sshbuf *);

ಪೂರ್ಣಾಂಕ	 sshkey_sign(ರಚನೆ sshkey *, u_char **, ಗಾತ್ರ_t *,
    ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, u_int);
ಪೂರ್ಣಾಂಕ	 sshkey_verify(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t,
    ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, u_int, ರಚನೆ sshkey_sig_details **);
ಪೂರ್ಣಾಂಕ	 sshkey_check_sigtype(ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sshkey_sigalg_by_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 sshkey_get_sigtype(ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t, ಅಕ್ಷರ **);

/* Signing and verification backend for libcrypto-backed keys */
ಪೂರ್ಣಾಂಕ	sshkey_pkey_digest_sign(EVP_PKEY*, ಪೂರ್ಣಾಂಕ, u_char **,
    ಗಾತ್ರ_t *, ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t);
ಪೂರ್ಣಾಂಕ	sshkey_pkey_digest_verify(EVP_PKEY *, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ u_char *,
    ಗಾತ್ರ_t, u_char *, ಗಾತ್ರ_t);

/* for debug */
ಶೂನ್ಯ	sshkey_dump_ec_ಬಿಂದು(ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *, ಸ್ಥಿರಾಂಕ EC_ಬಿಂದು *);
ಶೂನ್ಯ	sshkey_dump_ec_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ EC_ಕೀಲಿ *);

/* private key parsing and serialisation */
ಪೂರ್ಣಾಂಕ	sshkey_ಖಾಸಗಿ_serialize(ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *buf);
ಪೂರ್ಣಾಂಕ	sshkey_ಖಾಸಗಿ_deserialize(ರಚನೆ sshbuf *buf,  ರಚನೆ sshkey **keyp);

/* private key file format parsing and serialisation */
ಪೂರ್ಣಾಂಕ	sshkey_ಖಾಸಗಿ_ಗಮ್ಯ_fileblob(ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *blob,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comment,
    ಪೂರ್ಣಾಂಕ format, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *openssh_format_cipher, ಪೂರ್ಣಾಂಕ openssh_format_ಸುತ್ತುಗಳು);
ಪೂರ್ಣಾಂಕ	sshkey_parse_ಖಾಸಗಿ_fileblob(ರಚನೆ sshbuf *ಬಫರ್,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase, ರಚನೆ sshkey **keyp, ಅಕ್ಷರ **commentp);
ಪೂರ್ಣಾಂಕ	sshkey_parse_ಖಾಸಗಿ_fileblob_type(ರಚನೆ sshbuf *blob, ಪೂರ್ಣಾಂಕ type,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase, ರಚನೆ sshkey **keyp, ಅಕ್ಷರ **commentp);
ಪೂರ್ಣಾಂಕ	sshkey_parse_pubkey_from_ಖಾಸಗಿ_fileblob_type(ರಚನೆ sshbuf *blob,
    ಪೂರ್ಣಾಂಕ type, ರಚನೆ sshkey **pubkeyp);

ಪೂರ್ಣಾಂಕ sshkey_check_rsa_ಉದ್ದಳತೆ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	ssh_rsa_hash_id_from_keyname(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ssh_rsa_hash_alg_ident(ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	ssh_rsa_encode_store_sig(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t,
	    u_char **, ಗಾತ್ರ_t *);
ಪೂರ್ಣಾಂಕ	ssh_ecdsa_encode_store_sig(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *,
	    ಸ್ಥಿರಾಂಕ BIGNUM *, ಸ್ಥಿರಾಂಕ BIGNUM *, u_char **, ಗಾತ್ರ_t *);
ಪೂರ್ಣಾಂಕ	ssh_ed25519_encode_store_sig(ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t,
	    u_char **, ಗಾತ್ರ_t *);
/* XXX should be internal, but used by ssh-keygen */
ಪೂರ್ಣಾಂಕ ssh_rsa_complete_crt_parameters(ಸ್ಥಿರಾಂಕ BIGNUM *, ಸ್ಥಿರಾಂಕ BIGNUM *,
    ಸ್ಥಿರಾಂಕ BIGNUM *, ಸ್ಥಿರಾಂಕ BIGNUM *, BIGNUM **, BIGNUM **);

ಶೂನ್ಯ	 sshkey_sig_details_free(ರಚನೆ sshkey_sig_details *);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಪೂರ್ಣಾಂಕ	sshkey_ecdsa_fixup_ಗುಂಪು(EVP_PKEY *k); /* ssh-ecdsa.c */
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSHKEY_ಆಂತರಿಕ
ಪೂರ್ಣಾಂಕ	sshkey_sk_fields_equal(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *a, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *b);
ಶೂನ್ಯ	sshkey_sk_cleanup(ರಚನೆ sshkey *k);
ಪೂರ್ಣಾಂಕ	sshkey_serialize_sk(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b);
ಪೂರ್ಣಾಂಕ	sshkey_copy_ಬಹಿರಂಗ_sk(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *from, ರಚನೆ sshkey *ಗಮ್ಯ);
ಪೂರ್ಣಾಂಕ	sshkey_deserialize_sk(ರಚನೆ sshbuf *b, ರಚನೆ sshkey *ಕೀಲಿ);
ಪೂರ್ಣಾಂಕ	sshkey_serialize_ಖಾಸಗಿ_sk(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ರಚನೆ sshbuf *buf);
ಪೂರ್ಣಾಂಕ	sshkey_ಖಾಸಗಿ_deserialize_sk(ರಚನೆ sshbuf *buf, ರಚನೆ sshkey *k);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಪೂರ್ಣಾಂಕ	check_rsa_ಉದ್ದಳತೆ(ಸ್ಥಿರಾಂಕ RSA *rsa); /* XXX remove */
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ WITH_OPENSSL
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು RSA
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು EC_ಕೀಲಿ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು EC_ಗುಂಪು
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು EC_ಬಿಂದು
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು EVP_PKEY
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

#ಆದರೆ_ಅಂತ್ಯ /* SSHKEY_H */
