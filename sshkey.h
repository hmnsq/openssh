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

#অন্তর্ভাব <sys/types.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/rsa.h>
#অন্তর্ভাব <openssl/ec.h>
#অন্তর্ভাব <openssl/ecdsa.h>
#অন্তর্ভাব <openssl/evp.h>
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

#define SSH_RSA_MINIMUM_MODULUS_আকার	1024
#define SSH_চাবি_MAX_SIGN_তথ্য_আকার	(1 << 20)

কাঠামো sshbuf;

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
কাঠামো sshkey_cert {
	কাঠামো sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	অক্ষর		*চাবি_id;
	u_int		 nprincipals;
	অক্ষর		**principals;
	uint64_t	 valid_after, valid_before;
	কাঠামো sshbuf	*critical;
	কাঠামো sshbuf	*extensions;
	কাঠামো sshkey	*signature_চাবি;
	অক্ষর		*signature_type;
};

/* XXX opacify? */
কাঠামো sshkey {
	পূর্ণসংখ্যা	 type;
	পূর্ণসংখ্যা	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	পূর্ণসংখ্যা	 ecdsa_nid;	/* NID of curve */
	/* libcrypto-backed keys */
	EVP_PKEY *pkey;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_MLDSA44_ED25519 */
	u_char	*mldsa_ed25519_sk;
	u_char	*mldsa_ed25519_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	অক্ষর	*sk_application;
	uint8_t	sk_flags;
	কাঠামো sshbuf *sk_চাবি_handle;
	কাঠামো sshbuf *sk_reserved;
	/* Certificates */
	কাঠামো sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	আকার_t	shielded_len;
	u_char	*shield_prekey;
	আকার_t	shield_prekey_len;
};

#define	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#define	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
কাঠামো sshkey_sig_details {
	uint32_t sk_গণক;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

কাঠামো sshkey_impl_funcs {
	u_int (*আকার_2)(ধ্রুবক কাঠামো sshkey *);	/* optional */
	পূর্ণসংখ্যা (*alloc)(কাঠামো sshkey *);		/* optional */
	শূন্য (*cleanup)(কাঠামো sshkey *);	/* optional */
	পূর্ণসংখ্যা (*equal)(ধ্রুবক কাঠামো sshkey *, ধ্রুবক কাঠামো sshkey *);
	পূর্ণসংখ্যা (*serialize_public)(ধ্রুবক কাঠামো sshkey *, কাঠামো sshbuf *,
	    গণনা sshkey_serialize_rep);
	পূর্ণসংখ্যা (*deserialize_public)(ধ্রুবক অক্ষর *, কাঠামো sshbuf *,
	    কাঠামো sshkey *);
	পূর্ণসংখ্যা (*serialize_private)(ধ্রুবক কাঠামো sshkey *, কাঠামো sshbuf *,
	    গণনা sshkey_serialize_rep);
	পূর্ণসংখ্যা (*deserialize_private)(ধ্রুবক অক্ষর *, কাঠামো sshbuf *,
	    কাঠামো sshkey *);
	পূর্ণসংখ্যা (*generate)(কাঠামো sshkey *, পূর্ণসংখ্যা);	/* optional */
	পূর্ণসংখ্যা (*copy_public)(ধ্রুবক কাঠামো sshkey *, কাঠামো sshkey *);
	পূর্ণসংখ্যা (*sign)(কাঠামো sshkey *, u_char **, আকার_t *,
	    ধ্রুবক u_char *, আকার_t, ধ্রুবক অক্ষর *,
	    ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, u_int); /* optional */
	পূর্ণসংখ্যা (*verify)(ধ্রুবক কাঠামো sshkey *, ধ্রুবক u_char *, আকার_t,
	    ধ্রুবক u_char *, আকার_t, ধ্রুবক অক্ষর *, u_int,
	    কাঠামো sshkey_sig_details **);
};

কাঠামো sshkey_impl {
	ধ্রুবক অক্ষর *name;
	ধ্রুবক অক্ষর *shortname;
	ধ্রুবক অক্ষর *sigalg;
	পূর্ণসংখ্যা type;
	পূর্ণসংখ্যা nid;
	পূর্ণসংখ্যা cert;
	পূর্ণসংখ্যা sigonly;
	পূর্ণসংখ্যা keybits;
	ধ্রুবক কাঠামো sshkey_impl_funcs *funcs;
};

কাঠামো sshkey	*sshkey_new(পূর্ণসংখ্যা);
শূন্য		 sshkey_free(কাঠামো sshkey *);
পূর্ণসংখ্যা		 sshkey_equal_public(ধ্রুবক কাঠামো sshkey *,
    ধ্রুবক কাঠামো sshkey *);
পূর্ণসংখ্যা		 sshkey_equal(ধ্রুবক কাঠামো sshkey *, ধ্রুবক কাঠামো sshkey *);
অক্ষর		*sshkey_fingerprint(ধ্রুবক কাঠামো sshkey *,
    পূর্ণসংখ্যা, গণনা sshkey_fp_rep);
পূর্ণসংখ্যা		 sshkey_fingerprint_raw(ধ্রুবক কাঠামো sshkey *k,
    পূর্ণসংখ্যা, u_char **retp, আকার_t *lenp);
ধ্রুবক অক্ষর	*sshkey_type(ধ্রুবক কাঠামো sshkey *);
ধ্রুবক অক্ষর	*sshkey_cert_type(ধ্রুবক কাঠামো sshkey *);
পূর্ণসংখ্যা		 sshkey_format_text(ধ্রুবক কাঠামো sshkey *, কাঠামো sshbuf *);
পূর্ণসংখ্যা		 sshkey_write(ধ্রুবক কাঠামো sshkey *, FILE *);
পূর্ণসংখ্যা		 sshkey_read(কাঠামো sshkey *, অক্ষর **);
u_int		 sshkey_আকার(ধ্রুবক কাঠামো sshkey *);

পূর্ণসংখ্যা		 sshkey_generate(পূর্ণসংখ্যা type, u_int bits, কাঠামো sshkey **keyp);
পূর্ণসংখ্যা		 sshkey_from_private(ধ্রুবক কাঠামো sshkey *, কাঠামো sshkey **);

পূর্ণসংখ্যা		 sshkey_is_shielded(কাঠামো sshkey *);
পূর্ণসংখ্যা		 sshkey_shield_private(কাঠামো sshkey *);
পূর্ণসংখ্যা		 sshkey_unshield_private(কাঠামো sshkey *);

পূর্ণসংখ্যা	 sshkey_type_from_name(ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 sshkey_type_from_shortname(ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 sshkey_is_cert(ধ্রুবক কাঠামো sshkey *);
পূর্ণসংখ্যা	 sshkey_is_sk(ধ্রুবক কাঠামো sshkey *);
পূর্ণসংখ্যা	 sshkey_type_is_cert(পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 sshkey_type_plain(পূর্ণসংখ্যা);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
পূর্ণসংখ্যা	 sshkey_match_keyname_to_sigalgs(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);

পূর্ণসংখ্যা	 sshkey_to_certified(কাঠামো sshkey *);
পূর্ণসংখ্যা	 sshkey_drop_cert(কাঠামো sshkey *);
পূর্ণসংখ্যা	 sshkey_cert_copy(ধ্রুবক কাঠামো sshkey *, কাঠামো sshkey *);
পূর্ণসংখ্যা	 sshkey_cert_check_authority(ধ্রুবক কাঠামো sshkey *, পূর্ণসংখ্যা, পূর্ণসংখ্যা,
    uint64_t, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর **);
পূর্ণসংখ্যা	 sshkey_cert_check_authority_now(ধ্রুবক কাঠামো sshkey *, পূর্ণসংখ্যা, পূর্ণসংখ্যা,
    ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর **);
পূর্ণসংখ্যা	 sshkey_cert_check_host(ধ্রুবক কাঠামো sshkey *, ধ্রুবক অক্ষর *,
    ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর **);
আকার_t	 sshkey_format_cert_validity(ধ্রুবক কাঠামো sshkey_cert *,
    অক্ষর *, আকার_t) __attribute__((__bounded__(__string__, 2, 3)));
পূর্ণসংখ্যা	 sshkey_check_cert_sigtype(ধ্রুবক কাঠামো sshkey *, ধ্রুবক অক্ষর *);

পূর্ণসংখ্যা	 sshkey_certify(কাঠামো sshkey *, কাঠামো sshkey *,
    ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
প্রকারলেখ পূর্ণসংখ্যা sshkey_certify_signer(কাঠামো sshkey *, u_char **, আকার_t *,
    ধ্রুবক u_char *, আকার_t, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *,
    u_int, শূন্য *);
পূর্ণসংখ্যা	 sshkey_certify_custom(কাঠামো sshkey *, কাঠামো sshkey *, ধ্রুবক অক্ষর *,
    ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, sshkey_certify_signer *, শূন্য *);

পূর্ণসংখ্যা		 sshkey_ecdsa_nid_from_name(ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা		 sshkey_curve_name_to_nid(ধ্রুবক অক্ষর *);
ধ্রুবক অক্ষর *	 sshkey_curve_nid_to_name(পূর্ণসংখ্যা);
u_int		 sshkey_curve_nid_to_bits(পূর্ণসংখ্যা);
পূর্ণসংখ্যা		 sshkey_ecdsa_bits_to_nid(পূর্ণসংখ্যা);
পূর্ণসংখ্যা		 sshkey_ecdsa_চাবি_to_nid(ধ্রুবক EC_চাবি *);
পূর্ণসংখ্যা		 sshkey_ecdsa_pkey_to_nid(EVP_PKEY *);
পূর্ণসংখ্যা		 sshkey_ec_nid_to_hash_alg(পূর্ণসংখ্যা nid);
পূর্ণসংখ্যা		 sshkey_ec_validate_public(ধ্রুবক EC_GROUP *, ধ্রুবক EC_POINT *);
পূর্ণসংখ্যা		 sshkey_ec_validate_private(ধ্রুবক EC_চাবি *);
ধ্রুবক অক্ষর	*sshkey_ssh_name(ধ্রুবক কাঠামো sshkey *);
ধ্রুবক অক্ষর	*sshkey_ssh_name_plain(ধ্রুবক কাঠামো sshkey *);
পূর্ণসংখ্যা		 sshkey_names_valid2(ধ্রুবক অক্ষর *, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
অক্ষর		*sshkey_alg_list(পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা, অক্ষর);

পূর্ণসংখ্যা	 sshkey_from_blob(ধ্রুবক u_char *, আকার_t, কাঠামো sshkey **);
পূর্ণসংখ্যা	 sshkey_fromb(কাঠামো sshbuf *, কাঠামো sshkey **);
পূর্ণসংখ্যা	 sshkey_fromb_allowlist(কাঠামো sshbuf *, কাঠামো sshkey **,
    ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 sshkey_froms(কাঠামো sshbuf *, কাঠামো sshkey **);
পূর্ণসংখ্যা	 sshkey_to_blob(ধ্রুবক কাঠামো sshkey *, u_char **, আকার_t *);
পূর্ণসংখ্যা	 sshkey_to_base64(ধ্রুবক কাঠামো sshkey *, অক্ষর **);
পূর্ণসংখ্যা	 sshkey_putb(ধ্রুবক কাঠামো sshkey *, কাঠামো sshbuf *);
পূর্ণসংখ্যা	 sshkey_puts(ধ্রুবক কাঠামো sshkey *, কাঠামো sshbuf *);
পূর্ণসংখ্যা	 sshkey_plain_to_blob(ধ্রুবক কাঠামো sshkey *, u_char **, আকার_t *);
পূর্ণসংখ্যা	 sshkey_putb_plain(ধ্রুবক কাঠামো sshkey *, কাঠামো sshbuf *);
পূর্ণসংখ্যা	 sshkey_puts_plain(ধ্রুবক কাঠামো sshkey *, কাঠামো sshbuf *);

পূর্ণসংখ্যা	 sshkey_sign(কাঠামো sshkey *, u_char **, আকার_t *,
    ধ্রুবক u_char *, আকার_t, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, u_int);
পূর্ণসংখ্যা	 sshkey_verify(ধ্রুবক কাঠামো sshkey *, ধ্রুবক u_char *, আকার_t,
    ধ্রুবক u_char *, আকার_t, ধ্রুবক অক্ষর *, u_int, কাঠামো sshkey_sig_details **);
পূর্ণসংখ্যা	 sshkey_check_sigtype(ধ্রুবক u_char *, আকার_t, ধ্রুবক অক্ষর *);
ধ্রুবক অক্ষর *sshkey_sigalg_by_name(ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 sshkey_get_sigtype(ধ্রুবক u_char *, আকার_t, অক্ষর **);

/* Signing and verification backend for libcrypto-backed keys */
পূর্ণসংখ্যা	sshkey_pkey_digest_sign(EVP_PKEY*, পূর্ণসংখ্যা, u_char **,
    আকার_t *, ধ্রুবক u_char *, আকার_t);
পূর্ণসংখ্যা	sshkey_pkey_digest_verify(EVP_PKEY *, পূর্ণসংখ্যা, ধ্রুবক u_char *,
    আকার_t, u_char *, আকার_t);

/* for debug */
শূন্য	sshkey_dump_ec_point(ধ্রুবক EC_GROUP *, ধ্রুবক EC_POINT *);
শূন্য	sshkey_dump_ec_চাবি(ধ্রুবক EC_চাবি *);

/* private key parsing and serialisation */
পূর্ণসংখ্যা	sshkey_private_serialize(কাঠামো sshkey *চাবি, কাঠামো sshbuf *buf);
পূর্ণসংখ্যা	sshkey_private_deserialize(কাঠামো sshbuf *buf,  কাঠামো sshkey **keyp);

/* private key file format parsing and serialisation */
পূর্ণসংখ্যা	sshkey_private_to_fileblob(কাঠামো sshkey *চাবি, কাঠামো sshbuf *blob,
    ধ্রুবক অক্ষর *passphrase, ধ্রুবক অক্ষর *comment,
    পূর্ণসংখ্যা format, ধ্রুবক অক্ষর *openssh_format_cipher, পূর্ণসংখ্যা openssh_format_rounds);
পূর্ণসংখ্যা	sshkey_parse_private_fileblob(কাঠামো sshbuf *বাফার,
    ধ্রুবক অক্ষর *passphrase, কাঠামো sshkey **keyp, অক্ষর **commentp);
পূর্ণসংখ্যা	sshkey_parse_private_fileblob_type(কাঠামো sshbuf *blob, পূর্ণসংখ্যা type,
    ধ্রুবক অক্ষর *passphrase, কাঠামো sshkey **keyp, অক্ষর **commentp);
পূর্ণসংখ্যা	sshkey_parse_pubkey_from_private_fileblob_type(কাঠামো sshbuf *blob,
    পূর্ণসংখ্যা type, কাঠামো sshkey **pubkeyp);

পূর্ণসংখ্যা sshkey_check_rsa_দৈর্ঘ্য(ধ্রুবক কাঠামো sshkey *, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	ssh_rsa_hash_id_from_keyname(ধ্রুবক অক্ষর *);
ধ্রুবক অক্ষর *ssh_rsa_hash_alg_ident(পূর্ণসংখ্যা);
পূর্ণসংখ্যা	ssh_rsa_encode_store_sig(পূর্ণসংখ্যা, ধ্রুবক u_char *, আকার_t,
	    u_char **, আকার_t *);
পূর্ণসংখ্যা	ssh_ecdsa_encode_store_sig(ধ্রুবক কাঠামো sshkey *,
	    ধ্রুবক BIGNUM *, ধ্রুবক BIGNUM *, u_char **, আকার_t *);
পূর্ণসংখ্যা	ssh_ed25519_encode_store_sig(ধ্রুবক u_char *, আকার_t,
	    u_char **, আকার_t *);
/* XXX should be internal, but used by ssh-keygen */
পূর্ণসংখ্যা ssh_rsa_complete_crt_parameters(ধ্রুবক BIGNUM *, ধ্রুবক BIGNUM *,
    ধ্রুবক BIGNUM *, ধ্রুবক BIGNUM *, BIGNUM **, BIGNUM **);

শূন্য	 sshkey_sig_details_free(কাঠামো sshkey_sig_details *);

#ifdef WITH_OPENSSL
পূর্ণসংখ্যা	sshkey_ecdsa_fixup_group(EVP_PKEY *k); /* ssh-ecdsa.c */
#endif

#ifdef SSHKEY_INTERNAL
পূর্ণসংখ্যা	sshkey_sk_fields_equal(ধ্রুবক কাঠামো sshkey *a, ধ্রুবক কাঠামো sshkey *b);
শূন্য	sshkey_sk_cleanup(কাঠামো sshkey *k);
পূর্ণসংখ্যা	sshkey_serialize_sk(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b);
পূর্ণসংখ্যা	sshkey_copy_public_sk(ধ্রুবক কাঠামো sshkey *from, কাঠামো sshkey *to);
পূর্ণসংখ্যা	sshkey_deserialize_sk(কাঠামো sshbuf *b, কাঠামো sshkey *চাবি);
পূর্ণসংখ্যা	sshkey_serialize_private_sk(ধ্রুবক কাঠামো sshkey *চাবি,
    কাঠামো sshbuf *buf);
পূর্ণসংখ্যা	sshkey_private_deserialize_sk(কাঠামো sshbuf *buf, কাঠামো sshkey *k);
#ifdef WITH_OPENSSL
পূর্ণসংখ্যা	check_rsa_দৈর্ঘ্য(ধ্রুবক RSA *rsa); /* XXX remove */
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
