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

#অন্তর্ভাৱ <sys/types.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাৱ <openssl/rsa.h>
#অন্তর্ভাৱ <openssl/ec.h>
#অন্তর্ভাৱ <openssl/ecdsa.h>
#অন্তর্ভাৱ <openssl/evp.h>
#define SSH_OPENSSL_VERSION OpenSSL_version(OPENSSL_VERSION)
#অন্যথা /* OPENSSL */
#define BIGNUM		শূন্য
#define RSA		শূন্য
#define EC_চাবি		শূন্য
#define EC_GROUP	শূন্য
#define EC_POINT	শূন্য
#define EVP_PKEY	শূন্য
#define SSH_OPENSSL_VERSION "without OpenSSL"
#endif /* WITH_OPENSSL */

#define SSH_RSA_MINIMUM_MODULUS_SIZE	1024
#define SSH_চাবি_MAX_SIGN_DATA_SIZE	(1 << 20)

সংরচনা sshbuf;

/* Key types */
গণনা sshkey_types {
	চাবি_RSA,
	চাবি_ECDSA,
	চাবি_ED25519,
	চাবি_RSA_CERT,
	চাবি_ECDSA_CERT,
	চাবি_ED25519_CERT,
	চাবি_ECDSA_SK,
	চাবি_ECDSA_SK_CERT,
	চাবি_ED25519_SK,
	চাবি_ED25519_SK_CERT,
	চাবি_MLDSA44_ED25519,
	চাবি_MLDSA44_ED25519_CERT,
	চাবি_UNSPEC
};

/* Default fingerprint hash */
#define SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
গণনা sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
গণনা sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
গণনা sshkey_private_format {
	SSHKEY_PRIVATE_OPENSSH = 0,
	SSHKEY_PRIVATE_PEM = 1,
	SSHKEY_PRIVATE_PKCS8 = 2,
};

/* key is stored in external hardware */
#define SSHKEY_FLAG_EXT		0x0001

#define SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
সংরচনা sshkey_cert {
	সংরচনা sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	ৱর্ণ		*চাবি_id;
	u_int		 nprincipals;
	ৱর্ণ		**principals;
	uint64_t	 valid_after, valid_before;
	সংরচনা sshbuf	*critical;
	সংরচনা sshbuf	*extensions;
	সংরচনা sshkey	*signature_চাবি;
	ৱর্ণ		*signature_type;
};

/* XXX opacify? */
সংরচনা sshkey {
	পূর্ণাঙ্ক	 type;
	পূর্ণাঙ্ক	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	পূর্ণাঙ্ক	 ecdsa_nid;	/* NID of curve */
	/* libcrypto-backed keys */
	EVP_PKEY *pkey;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_MLDSA44_ED25519 */
	u_char	*mldsa_ed25519_sk;
	u_char	*mldsa_ed25519_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	ৱর্ণ	*sk_application;
	uint8_t	sk_flags;
	সংরচনা sshbuf *sk_চাবি_handle;
	সংরচনা sshbuf *sk_reserved;
	/* Certificates */
	সংরচনা sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	size_t	shielded_len;
	u_char	*shield_prekey;
	size_t	shield_prekey_len;
};

#define	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#define	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
সংরচনা sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

সংরচনা sshkey_impl_funcs {
	u_int (*size)(ধ্রুৱ সংরচনা sshkey *);	/* optional */
	পূর্ণাঙ্ক (*alloc)(সংরচনা sshkey *);		/* optional */
	শূন্য (*cleanup)(সংরচনা sshkey *);	/* optional */
	পূর্ণাঙ্ক (*equal)(ধ্রুৱ সংরচনা sshkey *, ধ্রুৱ সংরচনা sshkey *);
	পূর্ণাঙ্ক (*serialize_public)(ধ্রুৱ সংরচনা sshkey *, সংরচনা sshbuf *,
	    গণনা sshkey_serialize_rep);
	পূর্ণাঙ্ক (*deserialize_public)(ধ্রুৱ ৱর্ণ *, সংরচনা sshbuf *,
	    সংরচনা sshkey *);
	পূর্ণাঙ্ক (*serialize_private)(ধ্রুৱ সংরচনা sshkey *, সংরচনা sshbuf *,
	    গণনা sshkey_serialize_rep);
	পূর্ণাঙ্ক (*deserialize_private)(ধ্রুৱ ৱর্ণ *, সংরচনা sshbuf *,
	    সংরচনা sshkey *);
	পূর্ণাঙ্ক (*generate)(সংরচনা sshkey *, পূর্ণাঙ্ক);	/* optional */
	পূর্ণাঙ্ক (*copy_public)(ধ্রুৱ সংরচনা sshkey *, সংরচনা sshkey *);
	পূর্ণাঙ্ক (*sign)(সংরচনা sshkey *, u_char **, size_t *,
	    ধ্রুৱ u_char *, size_t, ধ্রুৱ ৱর্ণ *,
	    ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, u_int); /* optional */
	পূর্ণাঙ্ক (*verify)(ধ্রুৱ সংরচনা sshkey *, ধ্রুৱ u_char *, size_t,
	    ধ্রুৱ u_char *, size_t, ধ্রুৱ ৱর্ণ *, u_int,
	    সংরচনা sshkey_sig_details **);
};

সংরচনা sshkey_impl {
	ধ্রুৱ ৱর্ণ *name;
	ধ্রুৱ ৱর্ণ *shortname;
	ধ্রুৱ ৱর্ণ *sigalg;
	পূর্ণাঙ্ক type;
	পূর্ণাঙ্ক nid;
	পূর্ণাঙ্ক cert;
	পূর্ণাঙ্ক sigonly;
	পূর্ণাঙ্ক keybits;
	ধ্রুৱ সংরচনা sshkey_impl_funcs *funcs;
};

সংরচনা sshkey	*sshkey_new(পূর্ণাঙ্ক);
শূন্য		 sshkey_free(সংরচনা sshkey *);
পূর্ণাঙ্ক		 sshkey_equal_public(ধ্রুৱ সংরচনা sshkey *,
    ধ্রুৱ সংরচনা sshkey *);
পূর্ণাঙ্ক		 sshkey_equal(ধ্রুৱ সংরচনা sshkey *, ধ্রুৱ সংরচনা sshkey *);
ৱর্ণ		*sshkey_fingerprint(ধ্রুৱ সংরচনা sshkey *,
    পূর্ণাঙ্ক, গণনা sshkey_fp_rep);
পূর্ণাঙ্ক		 sshkey_fingerprint_raw(ধ্রুৱ সংরচনা sshkey *k,
    পূর্ণাঙ্ক, u_char **retp, size_t *lenp);
ধ্রুৱ ৱর্ণ	*sshkey_type(ধ্রুৱ সংরচনা sshkey *);
ধ্রুৱ ৱর্ণ	*sshkey_cert_type(ধ্রুৱ সংরচনা sshkey *);
পূর্ণাঙ্ক		 sshkey_format_text(ধ্রুৱ সংরচনা sshkey *, সংরচনা sshbuf *);
পূর্ণাঙ্ক		 sshkey_write(ধ্রুৱ সংরচনা sshkey *, FILE *);
পূর্ণাঙ্ক		 sshkey_read(সংরচনা sshkey *, ৱর্ণ **);
u_int		 sshkey_size(ধ্রুৱ সংরচনা sshkey *);

পূর্ণাঙ্ক		 sshkey_generate(পূর্ণাঙ্ক type, u_int bits, সংরচনা sshkey **keyp);
পূর্ণাঙ্ক		 sshkey_from_private(ধ্রুৱ সংরচনা sshkey *, সংরচনা sshkey **);

পূর্ণাঙ্ক		 sshkey_is_shielded(সংরচনা sshkey *);
পূর্ণাঙ্ক		 sshkey_shield_private(সংরচনা sshkey *);
পূর্ণাঙ্ক		 sshkey_unshield_private(সংরচনা sshkey *);

পূর্ণাঙ্ক	 sshkey_type_from_name(ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 sshkey_type_from_shortname(ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 sshkey_is_cert(ধ্রুৱ সংরচনা sshkey *);
পূর্ণাঙ্ক	 sshkey_is_sk(ধ্রুৱ সংরচনা sshkey *);
পূর্ণাঙ্ক	 sshkey_type_is_cert(পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 sshkey_type_plain(পূর্ণাঙ্ক);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
পূর্ণাঙ্ক	 sshkey_match_keyname_to_sigalgs(ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *);

পূর্ণাঙ্ক	 sshkey_to_certified(সংরচনা sshkey *);
পূর্ণাঙ্ক	 sshkey_drop_cert(সংরচনা sshkey *);
পূর্ণাঙ্ক	 sshkey_cert_copy(ধ্রুৱ সংরচনা sshkey *, সংরচনা sshkey *);
পূর্ণাঙ্ক	 sshkey_cert_check_authority(ধ্রুৱ সংরচনা sshkey *, পূর্ণাঙ্ক, পূর্ণাঙ্ক,
    uint64_t, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ **);
পূর্ণাঙ্ক	 sshkey_cert_check_authority_now(ধ্রুৱ সংরচনা sshkey *, পূর্ণাঙ্ক, পূর্ণাঙ্ক,
    ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ **);
পূর্ণাঙ্ক	 sshkey_cert_check_host(ধ্রুৱ সংরচনা sshkey *, ধ্রুৱ ৱর্ণ *,
    ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ **);
size_t	 sshkey_format_cert_validity(ধ্রুৱ সংরচনা sshkey_cert *,
    ৱর্ণ *, size_t) __attribute__((__bounded__(__string__, 2, 3)));
পূর্ণাঙ্ক	 sshkey_check_cert_sigtype(ধ্রুৱ সংরচনা sshkey *, ধ্রুৱ ৱর্ণ *);

পূর্ণাঙ্ক	 sshkey_certify(সংরচনা sshkey *, সংরচনা sshkey *,
    ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
প্রকারনির্দেশ পূর্ণাঙ্ক sshkey_certify_signer(সংরচনা sshkey *, u_char **, size_t *,
    ধ্রুৱ u_char *, size_t, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *,
    u_int, শূন্য *);
পূর্ণাঙ্ক	 sshkey_certify_custom(সংরচনা sshkey *, সংরচনা sshkey *, ধ্রুৱ ৱর্ণ *,
    ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, sshkey_certify_signer *, শূন্য *);

পূর্ণাঙ্ক		 sshkey_ecdsa_nid_from_name(ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক		 sshkey_curve_name_to_nid(ধ্রুৱ ৱর্ণ *);
ধ্রুৱ ৱর্ণ *	 sshkey_curve_nid_to_name(পূর্ণাঙ্ক);
u_int		 sshkey_curve_nid_to_bits(পূর্ণাঙ্ক);
পূর্ণাঙ্ক		 sshkey_ecdsa_bits_to_nid(পূর্ণাঙ্ক);
পূর্ণাঙ্ক		 sshkey_ecdsa_চাবি_to_nid(ধ্রুৱ EC_চাবি *);
পূর্ণাঙ্ক		 sshkey_ecdsa_pkey_to_nid(EVP_PKEY *);
পূর্ণাঙ্ক		 sshkey_ec_nid_to_hash_alg(পূর্ণাঙ্ক nid);
পূর্ণাঙ্ক		 sshkey_ec_validate_public(ধ্রুৱ EC_GROUP *, ধ্রুৱ EC_POINT *);
পূর্ণাঙ্ক		 sshkey_ec_validate_private(ধ্রুৱ EC_চাবি *);
ধ্রুৱ ৱর্ণ	*sshkey_ssh_name(ধ্রুৱ সংরচনা sshkey *);
ধ্রুৱ ৱর্ণ	*sshkey_ssh_name_plain(ধ্রুৱ সংরচনা sshkey *);
পূর্ণাঙ্ক		 sshkey_names_valid2(ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক, পূর্ণাঙ্ক);
ৱর্ণ		*sshkey_alg_list(পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক, ৱর্ণ);

পূর্ণাঙ্ক	 sshkey_from_blob(ধ্রুৱ u_char *, size_t, সংরচনা sshkey **);
পূর্ণাঙ্ক	 sshkey_fromb(সংরচনা sshbuf *, সংরচনা sshkey **);
পূর্ণাঙ্ক	 sshkey_fromb_allowlist(সংরচনা sshbuf *, সংরচনা sshkey **,
    ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 sshkey_froms(সংরচনা sshbuf *, সংরচনা sshkey **);
পূর্ণাঙ্ক	 sshkey_to_blob(ধ্রুৱ সংরচনা sshkey *, u_char **, size_t *);
পূর্ণাঙ্ক	 sshkey_to_base64(ধ্রুৱ সংরচনা sshkey *, ৱর্ণ **);
পূর্ণাঙ্ক	 sshkey_putb(ধ্রুৱ সংরচনা sshkey *, সংরচনা sshbuf *);
পূর্ণাঙ্ক	 sshkey_puts(ধ্রুৱ সংরচনা sshkey *, সংরচনা sshbuf *);
পূর্ণাঙ্ক	 sshkey_plain_to_blob(ধ্রুৱ সংরচনা sshkey *, u_char **, size_t *);
পূর্ণাঙ্ক	 sshkey_putb_plain(ধ্রুৱ সংরচনা sshkey *, সংরচনা sshbuf *);
পূর্ণাঙ্ক	 sshkey_puts_plain(ধ্রুৱ সংরচনা sshkey *, সংরচনা sshbuf *);

পূর্ণাঙ্ক	 sshkey_sign(সংরচনা sshkey *, u_char **, size_t *,
    ধ্রুৱ u_char *, size_t, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, u_int);
পূর্ণাঙ্ক	 sshkey_verify(ধ্রুৱ সংরচনা sshkey *, ধ্রুৱ u_char *, size_t,
    ধ্রুৱ u_char *, size_t, ধ্রুৱ ৱর্ণ *, u_int, সংরচনা sshkey_sig_details **);
পূর্ণাঙ্ক	 sshkey_check_sigtype(ধ্রুৱ u_char *, size_t, ধ্রুৱ ৱর্ণ *);
ধ্রুৱ ৱর্ণ *sshkey_sigalg_by_name(ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 sshkey_get_sigtype(ধ্রুৱ u_char *, size_t, ৱর্ণ **);

/* Signing and verification backend for libcrypto-backed keys */
পূর্ণাঙ্ক	sshkey_pkey_digest_sign(EVP_PKEY*, পূর্ণাঙ্ক, u_char **,
    size_t *, ধ্রুৱ u_char *, size_t);
পূর্ণাঙ্ক	sshkey_pkey_digest_verify(EVP_PKEY *, পূর্ণাঙ্ক, ধ্রুৱ u_char *,
    size_t, u_char *, size_t);

/* for debug */
শূন্য	sshkey_dump_ec_point(ধ্রুৱ EC_GROUP *, ধ্রুৱ EC_POINT *);
শূন্য	sshkey_dump_ec_চাবি(ধ্রুৱ EC_চাবি *);

/* private key parsing and serialisation */
পূর্ণাঙ্ক	sshkey_private_serialize(সংরচনা sshkey *চাবি, সংরচনা sshbuf *buf);
পূর্ণাঙ্ক	sshkey_private_deserialize(সংরচনা sshbuf *buf,  সংরচনা sshkey **keyp);

/* private key file format parsing and serialisation */
পূর্ণাঙ্ক	sshkey_private_to_fileblob(সংরচনা sshkey *চাবি, সংরচনা sshbuf *blob,
    ধ্রুৱ ৱর্ণ *passphrase, ধ্রুৱ ৱর্ণ *comment,
    পূর্ণাঙ্ক format, ধ্রুৱ ৱর্ণ *openssh_format_cipher, পূর্ণাঙ্ক openssh_format_rounds);
পূর্ণাঙ্ক	sshkey_parse_private_fileblob(সংরচনা sshbuf *buffer,
    ধ্রুৱ ৱর্ণ *passphrase, সংরচনা sshkey **keyp, ৱর্ণ **commentp);
পূর্ণাঙ্ক	sshkey_parse_private_fileblob_type(সংরচনা sshbuf *blob, পূর্ণাঙ্ক type,
    ধ্রুৱ ৱর্ণ *passphrase, সংরচনা sshkey **keyp, ৱর্ণ **commentp);
পূর্ণাঙ্ক	sshkey_parse_pubkey_from_private_fileblob_type(সংরচনা sshbuf *blob,
    পূর্ণাঙ্ক type, সংরচনা sshkey **pubkeyp);

পূর্ণাঙ্ক sshkey_check_rsa_length(ধ্রুৱ সংরচনা sshkey *, পূর্ণাঙ্ক);
পূর্ণাঙ্ক	ssh_rsa_hash_id_from_keyname(ধ্রুৱ ৱর্ণ *);
ধ্রুৱ ৱর্ণ *ssh_rsa_hash_alg_ident(পূর্ণাঙ্ক);
পূর্ণাঙ্ক	ssh_rsa_encode_store_sig(পূর্ণাঙ্ক, ধ্রুৱ u_char *, size_t,
	    u_char **, size_t *);
পূর্ণাঙ্ক	ssh_ecdsa_encode_store_sig(ধ্রুৱ সংরচনা sshkey *,
	    ধ্রুৱ BIGNUM *, ধ্রুৱ BIGNUM *, u_char **, size_t *);
পূর্ণাঙ্ক	ssh_ed25519_encode_store_sig(ধ্রুৱ u_char *, size_t,
	    u_char **, size_t *);
/* XXX should be internal, but used by ssh-keygen */
পূর্ণাঙ্ক ssh_rsa_complete_crt_parameters(ধ্রুৱ BIGNUM *, ধ্রুৱ BIGNUM *,
    ধ্রুৱ BIGNUM *, ধ্রুৱ BIGNUM *, BIGNUM **, BIGNUM **);

শূন্য	 sshkey_sig_details_free(সংরচনা sshkey_sig_details *);

#ifdef WITH_OPENSSL
পূর্ণাঙ্ক	sshkey_ecdsa_fixup_group(EVP_PKEY *k); /* ssh-ecdsa.c */
#endif

#ifdef SSHKEY_INTERNAL
পূর্ণাঙ্ক	sshkey_sk_fields_equal(ধ্রুৱ সংরচনা sshkey *a, ধ্রুৱ সংরচনা sshkey *b);
শূন্য	sshkey_sk_cleanup(সংরচনা sshkey *k);
পূর্ণাঙ্ক	sshkey_serialize_sk(ধ্রুৱ সংরচনা sshkey *চাবি, সংরচনা sshbuf *b);
পূর্ণাঙ্ক	sshkey_copy_public_sk(ধ্রুৱ সংরচনা sshkey *from, সংরচনা sshkey *to);
পূর্ণাঙ্ক	sshkey_deserialize_sk(সংরচনা sshbuf *b, সংরচনা sshkey *চাবি);
পূর্ণাঙ্ক	sshkey_serialize_private_sk(ধ্রুৱ সংরচনা sshkey *চাবি,
    সংরচনা sshbuf *buf);
পূর্ণাঙ্ক	sshkey_private_deserialize_sk(সংরচনা sshbuf *buf, সংরচনা sshkey *k);
#ifdef WITH_OPENSSL
পূর্ণাঙ্ক	check_rsa_length(ধ্রুৱ RSA *rsa); /* XXX remove */
#endif
#endif

#ifndef WITH_OPENSSL
#undef RSA
#undef EC_চাবি
#undef EC_GROUP
#undef EC_POINT
#undef EVP_PKEY
#endif /* WITH_OPENSSL */

#endif /* SSHKEY_H */
