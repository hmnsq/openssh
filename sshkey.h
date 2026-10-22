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

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/rsa.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ec.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ecdsa.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#define SSH_OPENSSL_VERSION OpenSSL_version(OPENSSL_VERSION)
#ଅନ୍ୟଥା /* OPENSSL */
#define BIGNUM		ଶୂନ୍ୟ
#define RSA		ଶୂନ୍ୟ
#define EC_ଚାବି		ଶୂନ୍ୟ
#define EC_GROUP	ଶୂନ୍ୟ
#define EC_POINT	ଶୂନ୍ୟ
#define EVP_PKEY	ଶୂନ୍ୟ
#define SSH_OPENSSL_VERSION "without OpenSSL"
#endif /* WITH_OPENSSL */

#define SSH_RSA_MINIMUM_MODULUS_SIZE	1024
#define SSH_ଚାବି_MAX_SIGN_DATA_SIZE	(1 << 20)

ସଂରଚନା sshbuf;

/* Key types */
ଗଣନା sshkey_types {
	ଚାବି_RSA,
	ଚାବି_ECDSA,
	ଚାବି_ED25519,
	ଚାବି_RSA_CERT,
	ଚାବି_ECDSA_CERT,
	ଚାବି_ED25519_CERT,
	ଚାବି_ECDSA_SK,
	ଚାବି_ECDSA_SK_CERT,
	ଚାବି_ED25519_SK,
	ଚାବି_ED25519_SK_CERT,
	ଚାବି_MLDSA44_ED25519,
	ଚାବି_MLDSA44_ED25519_CERT,
	ଚାବି_UNSPEC
};

/* Default fingerprint hash */
#define SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
ଗଣନା sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
ଗଣନା sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
ଗଣନା sshkey_private_format {
	SSHKEY_PRIVATE_OPENSSH = 0,
	SSHKEY_PRIVATE_PEM = 1,
	SSHKEY_PRIVATE_PKCS8 = 2,
};

/* key is stored in external hardware */
#define SSHKEY_FLAG_EXT		0x0001

#define SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
ସଂରଚନା sshkey_cert {
	ସଂରଚନା sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	ଅକ୍ଷର		*ଚାବି_id;
	u_int		 nprincipals;
	ଅକ୍ଷର		**principals;
	uint64_t	 valid_after, valid_before;
	ସଂରଚନା sshbuf	*critical;
	ସଂରଚନା sshbuf	*extensions;
	ସଂରଚନା sshkey	*signature_ଚାବି;
	ଅକ୍ଷର		*signature_type;
};

/* XXX opacify? */
ସଂରଚନା sshkey {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ecdsa_nid;	/* NID of curve */
	/* libcrypto-backed keys */
	EVP_PKEY *pkey;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_MLDSA44_ED25519 */
	u_char	*mldsa_ed25519_sk;
	u_char	*mldsa_ed25519_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	ଅକ୍ଷର	*sk_application;
	uint8_t	sk_flags;
	ସଂରଚନା sshbuf *sk_ଚାବି_handle;
	ସଂରଚନା sshbuf *sk_reserved;
	/* Certificates */
	ସଂରଚନା sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	size_t	shielded_len;
	u_char	*shield_prekey;
	size_t	shield_prekey_len;
};

#define	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#define	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
ସଂରଚନା sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

ସଂରଚନା sshkey_impl_funcs {
	u_int (*size)(ଅଚଳ ସଂରଚନା sshkey *);	/* optional */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*alloc)(ସଂରଚନା sshkey *);		/* optional */
	ଶୂନ୍ୟ (*cleanup)(ସଂରଚନା sshkey *);	/* optional */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*equal)(ଅଚଳ ସଂରଚନା sshkey *, ଅଚଳ ସଂରଚନା sshkey *);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*serialize_public)(ଅଚଳ ସଂରଚନା sshkey *, ସଂରଚନା sshbuf *,
	    ଗଣନା sshkey_serialize_rep);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*deserialize_public)(ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା sshbuf *,
	    ସଂରଚନା sshkey *);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*serialize_private)(ଅଚଳ ସଂରଚନା sshkey *, ସଂରଚନା sshbuf *,
	    ଗଣନା sshkey_serialize_rep);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*deserialize_private)(ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା sshbuf *,
	    ସଂରଚନା sshkey *);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*generate)(ସଂରଚନା sshkey *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);	/* optional */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*copy_public)(ଅଚଳ ସଂରଚନା sshkey *, ସଂରଚନା sshkey *);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*sign)(ସଂରଚନା sshkey *, u_char **, size_t *,
	    ଅଚଳ u_char *, size_t, ଅଚଳ ଅକ୍ଷର *,
	    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, u_int); /* optional */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*verify)(ଅଚଳ ସଂରଚନା sshkey *, ଅଚଳ u_char *, size_t,
	    ଅଚଳ u_char *, size_t, ଅଚଳ ଅକ୍ଷର *, u_int,
	    ସଂରଚନା sshkey_sig_details **);
};

ସଂରଚନା sshkey_impl {
	ଅଚଳ ଅକ୍ଷର *name;
	ଅଚଳ ଅକ୍ଷର *shortname;
	ଅଚଳ ଅକ୍ଷର *sigalg;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା cert;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sigonly;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା keybits;
	ଅଚଳ ସଂରଚନା sshkey_impl_funcs *funcs;
};

ସଂରଚନା sshkey	*sshkey_new(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ		 sshkey_free(ସଂରଚନା sshkey *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_equal_public(ଅଚଳ ସଂରଚନା sshkey *,
    ଅଚଳ ସଂରଚନା sshkey *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_equal(ଅଚଳ ସଂରଚନା sshkey *, ଅଚଳ ସଂରଚନା sshkey *);
ଅକ୍ଷର		*sshkey_fingerprint(ଅଚଳ ସଂରଚନା sshkey *,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଗଣନା sshkey_fp_rep);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_fingerprint_raw(ଅଚଳ ସଂରଚନା sshkey *k,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା, u_char **retp, size_t *lenp);
ଅଚଳ ଅକ୍ଷର	*sshkey_type(ଅଚଳ ସଂରଚନା sshkey *);
ଅଚଳ ଅକ୍ଷର	*sshkey_cert_type(ଅଚଳ ସଂରଚନା sshkey *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_format_text(ଅଚଳ ସଂରଚନା sshkey *, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_write(ଅଚଳ ସଂରଚନା sshkey *, FILE *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_read(ସଂରଚନା sshkey *, ଅକ୍ଷର **);
u_int		 sshkey_size(ଅଚଳ ସଂରଚନା sshkey *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_generate(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, u_int bits, ସଂରଚନା sshkey **keyp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_from_private(ଅଚଳ ସଂରଚନା sshkey *, ସଂରଚନା sshkey **);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_is_shielded(ସଂରଚନା sshkey *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_shield_private(ସଂରଚନା sshkey *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_unshield_private(ସଂରଚନା sshkey *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_type_from_name(ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_type_from_shortname(ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_is_cert(ଅଚଳ ସଂରଚନା sshkey *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_is_sk(ଅଚଳ ସଂରଚନା sshkey *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_type_is_cert(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_type_plain(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_match_keyname_to_sigalgs(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_to_certified(ସଂରଚନା sshkey *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_drop_cert(ସଂରଚନା sshkey *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_cert_copy(ଅଚଳ ସଂରଚନା sshkey *, ସଂରଚନା sshkey *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_cert_check_authority(ଅଚଳ ସଂରଚନା sshkey *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
    uint64_t, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_cert_check_authority_now(ଅଚଳ ସଂରଚନା sshkey *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_cert_check_host(ଅଚଳ ସଂରଚନା sshkey *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର **);
size_t	 sshkey_format_cert_validity(ଅଚଳ ସଂରଚନା sshkey_cert *,
    ଅକ୍ଷର *, size_t) __attribute__((__bounded__(__string__, 2, 3)));
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_check_cert_sigtype(ଅଚଳ ସଂରଚନା sshkey *, ଅଚଳ ଅକ୍ଷର *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_certify(ସଂରଚନା sshkey *, ସଂରଚନା sshkey *,
    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
ପ୍ରକାରବ୍ୟାଖ୍ୟା ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshkey_certify_signer(ସଂରଚନା sshkey *, u_char **, size_t *,
    ଅଚଳ u_char *, size_t, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *,
    u_int, ଶୂନ୍ୟ *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_certify_custom(ସଂରଚନା sshkey *, ସଂରଚନା sshkey *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, sshkey_certify_signer *, ଶୂନ୍ୟ *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_ecdsa_nid_from_name(ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_curve_name_to_nid(ଅଚଳ ଅକ୍ଷର *);
ଅଚଳ ଅକ୍ଷର *	 sshkey_curve_nid_to_name(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
u_int		 sshkey_curve_nid_to_bits(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_ecdsa_bits_to_nid(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_ecdsa_ଚାବି_to_nid(ଅଚଳ EC_ଚାବି *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_ecdsa_pkey_to_nid(EVP_PKEY *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_ec_nid_to_hash_alg(ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_ec_validate_public(ଅଚଳ EC_GROUP *, ଅଚଳ EC_POINT *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_ec_validate_private(ଅଚଳ EC_ଚାବି *);
ଅଚଳ ଅକ୍ଷର	*sshkey_ssh_name(ଅଚଳ ସଂରଚନା sshkey *);
ଅଚଳ ଅକ୍ଷର	*sshkey_ssh_name_plain(ଅଚଳ ସଂରଚନା sshkey *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା		 sshkey_names_valid2(ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଅକ୍ଷର		*sshkey_alg_list(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_from_blob(ଅଚଳ u_char *, size_t, ସଂରଚନା sshkey **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_fromb(ସଂରଚନା sshbuf *, ସଂରଚନା sshkey **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_fromb_allowlist(ସଂରଚନା sshbuf *, ସଂରଚନା sshkey **,
    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_froms(ସଂରଚନା sshbuf *, ସଂରଚନା sshkey **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_to_blob(ଅଚଳ ସଂରଚନା sshkey *, u_char **, size_t *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_to_base64(ଅଚଳ ସଂରଚନା sshkey *, ଅକ୍ଷର **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_putb(ଅଚଳ ସଂରଚନା sshkey *, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_puts(ଅଚଳ ସଂରଚନା sshkey *, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_plain_to_blob(ଅଚଳ ସଂରଚନା sshkey *, u_char **, size_t *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_putb_plain(ଅଚଳ ସଂରଚନା sshkey *, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_puts_plain(ଅଚଳ ସଂରଚନା sshkey *, ସଂରଚନା sshbuf *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_sign(ସଂରଚନା sshkey *, u_char **, size_t *,
    ଅଚଳ u_char *, size_t, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, u_int);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_verify(ଅଚଳ ସଂରଚନା sshkey *, ଅଚଳ u_char *, size_t,
    ଅଚଳ u_char *, size_t, ଅଚଳ ଅକ୍ଷର *, u_int, ସଂରଚନା sshkey_sig_details **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_check_sigtype(ଅଚଳ u_char *, size_t, ଅଚଳ ଅକ୍ଷର *);
ଅଚଳ ଅକ୍ଷର *sshkey_sigalg_by_name(ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 sshkey_get_sigtype(ଅଚଳ u_char *, size_t, ଅକ୍ଷର **);

/* Signing and verification backend for libcrypto-backed keys */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshkey_pkey_digest_sign(EVP_PKEY*, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, u_char **,
    size_t *, ଅଚଳ u_char *, size_t);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshkey_pkey_digest_verify(EVP_PKEY *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ u_char *,
    size_t, u_char *, size_t);

/* for debug */
ଶୂନ୍ୟ	sshkey_dump_ec_point(ଅଚଳ EC_GROUP *, ଅଚଳ EC_POINT *);
ଶୂନ୍ୟ	sshkey_dump_ec_ଚାବି(ଅଚଳ EC_ଚାବି *);

/* private key parsing and serialisation */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshkey_private_serialize(ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *buf);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshkey_private_deserialize(ସଂରଚନା sshbuf *buf,  ସଂରଚନା sshkey **keyp);

/* private key file format parsing and serialisation */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshkey_private_to_fileblob(ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *blob,
    ଅଚଳ ଅକ୍ଷର *passphrase, ଅଚଳ ଅକ୍ଷର *comment,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା format, ଅଚଳ ଅକ୍ଷର *openssh_format_cipher, ପୂର୍ଣ୍ଣସଂଖ୍ୟା openssh_format_rounds);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshkey_parse_private_fileblob(ସଂରଚନା sshbuf *buffer,
    ଅଚଳ ଅକ୍ଷର *passphrase, ସଂରଚନା sshkey **keyp, ଅକ୍ଷର **commentp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshkey_parse_private_fileblob_type(ସଂରଚନା sshbuf *blob, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type,
    ଅଚଳ ଅକ୍ଷର *passphrase, ସଂରଚନା sshkey **keyp, ଅକ୍ଷର **commentp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshkey_parse_pubkey_from_private_fileblob_type(ସଂରଚନା sshbuf *blob,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ସଂରଚନା sshkey **pubkeyp);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshkey_check_rsa_length(ଅଚଳ ସଂରଚନା sshkey *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_rsa_hash_id_from_keyname(ଅଚଳ ଅକ୍ଷର *);
ଅଚଳ ଅକ୍ଷର *ssh_rsa_hash_alg_ident(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_rsa_encode_store_sig(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ u_char *, size_t,
	    u_char **, size_t *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_ecdsa_encode_store_sig(ଅଚଳ ସଂରଚନା sshkey *,
	    ଅଚଳ BIGNUM *, ଅଚଳ BIGNUM *, u_char **, size_t *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_ed25519_encode_store_sig(ଅଚଳ u_char *, size_t,
	    u_char **, size_t *);
/* XXX should be internal, but used by ssh-keygen */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_rsa_complete_crt_parameters(ଅଚଳ BIGNUM *, ଅଚଳ BIGNUM *,
    ଅଚଳ BIGNUM *, ଅଚଳ BIGNUM *, BIGNUM **, BIGNUM **);

ଶୂନ୍ୟ	 sshkey_sig_details_free(ସଂରଚନା sshkey_sig_details *);

#ifdef WITH_OPENSSL
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshkey_ecdsa_fixup_group(EVP_PKEY *k); /* ssh-ecdsa.c */
#endif

#ifdef SSHKEY_INTERNAL
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshkey_sk_fields_equal(ଅଚଳ ସଂରଚନା sshkey *a, ଅଚଳ ସଂରଚନା sshkey *b);
ଶୂନ୍ୟ	sshkey_sk_cleanup(ସଂରଚନା sshkey *k);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshkey_serialize_sk(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshkey_copy_public_sk(ଅଚଳ ସଂରଚନା sshkey *from, ସଂରଚନା sshkey *to);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshkey_deserialize_sk(ସଂରଚନା sshbuf *b, ସଂରଚନା sshkey *ଚାବି);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshkey_serialize_private_sk(ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ସଂରଚନା sshbuf *buf);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshkey_private_deserialize_sk(ସଂରଚନା sshbuf *buf, ସଂରଚନା sshkey *k);
#ifdef WITH_OPENSSL
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	check_rsa_length(ଅଚଳ RSA *rsa); /* XXX remove */
#endif
#endif

#ifndef WITH_OPENSSL
#undef RSA
#undef EC_ଚାବି
#undef EC_GROUP
#undef EC_POINT
#undef EVP_PKEY
#endif /* WITH_OPENSSL */

#endif /* SSHKEY_H */
