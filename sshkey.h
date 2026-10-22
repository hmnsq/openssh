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

#include <sys/types.h>

#ifdef WITH_OPENSSL
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#define SSH_OPENSSL_VERSION OpenSSL_version(OPENSSL_VERSION)
#ບໍ່ດັ່ງນັ້ນ /* OPENSSL */
#define BIGNUM		void
#define RSA		void
#define EC_KEY		void
#define EC_GROUP	void
#define EC_POINT	void
#define EVP_PKEY	void
#define SSH_OPENSSL_VERSION "without OpenSSL"
#endif /* WITH_OPENSSL */

#define SSH_RSA_MINIMUM_MODULUS_SIZE	1024
#define SSH_KEY_MAX_SIGN_DATA_SIZE	(1 << 20)

sa_nracanaa sshbuf;

/* Key types */
ga_nanaa sshkey_types {
	KEY_RSA,
	KEY_ECDSA,
	KEY_ED25519,
	KEY_RSA_CERT,
	KEY_ECDSA_CERT,
	KEY_ED25519_CERT,
	KEY_ECDSA_SK,
	KEY_ECDSA_SK_CERT,
	KEY_ED25519_SK,
	KEY_ED25519_SK_CERT,
	KEY_MLDSA44_ED25519,
	KEY_MLDSA44_ED25519_CERT,
	KEY_UNSPEC
};

/* Default fingerprint hash */
#define SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
ga_nanaa sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
ga_nanaa sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
ga_nanaa sshkey_private_format {
	SSHKEY_PRIVATE_OPENSSH = 0,
	SSHKEY_PRIVATE_PEM = 1,
	SSHKEY_PRIVATE_PKCS8 = 2,
};

/* key is stored in external hardware */
#define SSHKEY_FLAG_EXT		0x0001

#define SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
sa_nracanaa sshkey_cert {
	sa_nracanaa sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	var_na		*key_id;
	u_int		 nprincipals;
	var_na		**principals;
	uint64_t	 valid_after, valid_before;
	sa_nracanaa sshbuf	*critical;
	sa_nracanaa sshbuf	*extensions;
	sa_nracanaa sshkey	*signature_key;
	var_na		*signature_type;
};

/* XXX opacify? */
sa_nracanaa sshkey {
	ຈຳນວນເຕັມ	 type;
	ຈຳນວນເຕັມ	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	ຈຳນວນເຕັມ	 ecdsa_nid;	/* NID of curve */
	/* libcrypto-backed keys */
	EVP_PKEY *pkey;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_MLDSA44_ED25519 */
	u_char	*mldsa_ed25519_sk;
	u_char	*mldsa_ed25519_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	var_na	*sk_application;
	uint8_t	sk_flags;
	sa_nracanaa sshbuf *sk_key_handle;
	sa_nracanaa sshbuf *sk_reserved;
	/* Certificates */
	sa_nracanaa sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	size_t	shielded_len;
	u_char	*shield_prekey;
	size_t	shield_prekey_len;
};

#define	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#define	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
sa_nracanaa sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

sa_nracanaa sshkey_impl_funcs {
	u_int (*size)(const sa_nracanaa sshkey *);	/* optional */
	ຈຳນວນເຕັມ (*alloc)(sa_nracanaa sshkey *);		/* optional */
	void (*cleanup)(sa_nracanaa sshkey *);	/* optional */
	ຈຳນວນເຕັມ (*equal)(const sa_nracanaa sshkey *, const sa_nracanaa sshkey *);
	ຈຳນວນເຕັມ (*serialize_public)(const sa_nracanaa sshkey *, sa_nracanaa sshbuf *,
	    ga_nanaa sshkey_serialize_rep);
	ຈຳນວນເຕັມ (*deserialize_public)(const var_na *, sa_nracanaa sshbuf *,
	    sa_nracanaa sshkey *);
	ຈຳນວນເຕັມ (*serialize_private)(const sa_nracanaa sshkey *, sa_nracanaa sshbuf *,
	    ga_nanaa sshkey_serialize_rep);
	ຈຳນວນເຕັມ (*deserialize_private)(const var_na *, sa_nracanaa sshbuf *,
	    sa_nracanaa sshkey *);
	ຈຳນວນເຕັມ (*generate)(sa_nracanaa sshkey *, ຈຳນວນເຕັມ);	/* optional */
	ຈຳນວນເຕັມ (*copy_public)(const sa_nracanaa sshkey *, sa_nracanaa sshkey *);
	ຈຳນວນເຕັມ (*sign)(sa_nracanaa sshkey *, u_char **, size_t *,
	    const u_char *, size_t, const var_na *,
	    const var_na *, const var_na *, u_int); /* optional */
	ຈຳນວນເຕັມ (*verify)(const sa_nracanaa sshkey *, const u_char *, size_t,
	    const u_char *, size_t, const var_na *, u_int,
	    sa_nracanaa sshkey_sig_details **);
};

sa_nracanaa sshkey_impl {
	const var_na *name;
	const var_na *shortname;
	const var_na *sigalg;
	ຈຳນວນເຕັມ type;
	ຈຳນວນເຕັມ nid;
	ຈຳນວນເຕັມ cert;
	ຈຳນວນເຕັມ sigonly;
	ຈຳນວນເຕັມ keybits;
	const sa_nracanaa sshkey_impl_funcs *funcs;
};

sa_nracanaa sshkey	*sshkey_new(ຈຳນວນເຕັມ);
void		 sshkey_free(sa_nracanaa sshkey *);
ຈຳນວນເຕັມ		 sshkey_equal_public(const sa_nracanaa sshkey *,
    const sa_nracanaa sshkey *);
ຈຳນວນເຕັມ		 sshkey_equal(const sa_nracanaa sshkey *, const sa_nracanaa sshkey *);
var_na		*sshkey_fingerprint(const sa_nracanaa sshkey *,
    ຈຳນວນເຕັມ, ga_nanaa sshkey_fp_rep);
ຈຳນວນເຕັມ		 sshkey_fingerprint_raw(const sa_nracanaa sshkey *k,
    ຈຳນວນເຕັມ, u_char **retp, size_t *lenp);
const var_na	*sshkey_type(const sa_nracanaa sshkey *);
const var_na	*sshkey_cert_type(const sa_nracanaa sshkey *);
ຈຳນວນເຕັມ		 sshkey_format_text(const sa_nracanaa sshkey *, sa_nracanaa sshbuf *);
ຈຳນວນເຕັມ		 sshkey_write(const sa_nracanaa sshkey *, FILE *);
ຈຳນວນເຕັມ		 sshkey_read(sa_nracanaa sshkey *, var_na **);
u_int		 sshkey_size(const sa_nracanaa sshkey *);

ຈຳນວນເຕັມ		 sshkey_generate(ຈຳນວນເຕັມ type, u_int bits, sa_nracanaa sshkey **keyp);
ຈຳນວນເຕັມ		 sshkey_from_private(const sa_nracanaa sshkey *, sa_nracanaa sshkey **);

ຈຳນວນເຕັມ		 sshkey_is_shielded(sa_nracanaa sshkey *);
ຈຳນວນເຕັມ		 sshkey_shield_private(sa_nracanaa sshkey *);
ຈຳນວນເຕັມ		 sshkey_unshield_private(sa_nracanaa sshkey *);

ຈຳນວນເຕັມ	 sshkey_type_from_name(const var_na *);
ຈຳນວນເຕັມ	 sshkey_type_from_shortname(const var_na *);
ຈຳນວນເຕັມ	 sshkey_is_cert(const sa_nracanaa sshkey *);
ຈຳນວນເຕັມ	 sshkey_is_sk(const sa_nracanaa sshkey *);
ຈຳນວນເຕັມ	 sshkey_type_is_cert(ຈຳນວນເຕັມ);
ຈຳນວນເຕັມ	 sshkey_type_plain(ຈຳນວນເຕັມ);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
ຈຳນວນເຕັມ	 sshkey_match_keyname_to_sigalgs(const var_na *, const var_na *);

ຈຳນວນເຕັມ	 sshkey_to_certified(sa_nracanaa sshkey *);
ຈຳນວນເຕັມ	 sshkey_drop_cert(sa_nracanaa sshkey *);
ຈຳນວນເຕັມ	 sshkey_cert_copy(const sa_nracanaa sshkey *, sa_nracanaa sshkey *);
ຈຳນວນເຕັມ	 sshkey_cert_check_authority(const sa_nracanaa sshkey *, ຈຳນວນເຕັມ, ຈຳນວນເຕັມ,
    uint64_t, const var_na *, const var_na **);
ຈຳນວນເຕັມ	 sshkey_cert_check_authority_now(const sa_nracanaa sshkey *, ຈຳນວນເຕັມ, ຈຳນວນເຕັມ,
    const var_na *, const var_na **);
ຈຳນວນເຕັມ	 sshkey_cert_check_host(const sa_nracanaa sshkey *, const var_na *,
    const var_na *, const var_na **);
size_t	 sshkey_format_cert_validity(const sa_nracanaa sshkey_cert *,
    var_na *, size_t) __attribute__((__bounded__(__string__, 2, 3)));
ຈຳນວນເຕັມ	 sshkey_check_cert_sigtype(const sa_nracanaa sshkey *, const var_na *);

ຈຳນວນເຕັມ	 sshkey_certify(sa_nracanaa sshkey *, sa_nracanaa sshkey *,
    const var_na *, const var_na *, const var_na *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
typedef ຈຳນວນເຕັມ sshkey_certify_signer(sa_nracanaa sshkey *, u_char **, size_t *,
    const u_char *, size_t, const var_na *, const var_na *, const var_na *,
    u_int, void *);
ຈຳນວນເຕັມ	 sshkey_certify_custom(sa_nracanaa sshkey *, sa_nracanaa sshkey *, const var_na *,
    const var_na *, const var_na *, sshkey_certify_signer *, void *);

ຈຳນວນເຕັມ		 sshkey_ecdsa_nid_from_name(const var_na *);
ຈຳນວນເຕັມ		 sshkey_curve_name_to_nid(const var_na *);
const var_na *	 sshkey_curve_nid_to_name(ຈຳນວນເຕັມ);
u_int		 sshkey_curve_nid_to_bits(ຈຳນວນເຕັມ);
ຈຳນວນເຕັມ		 sshkey_ecdsa_bits_to_nid(ຈຳນວນເຕັມ);
ຈຳນວນເຕັມ		 sshkey_ecdsa_key_to_nid(const EC_KEY *);
ຈຳນວນເຕັມ		 sshkey_ecdsa_pkey_to_nid(EVP_PKEY *);
ຈຳນວນເຕັມ		 sshkey_ec_nid_to_hash_alg(ຈຳນວນເຕັມ nid);
ຈຳນວນເຕັມ		 sshkey_ec_validate_public(const EC_GROUP *, const EC_POINT *);
ຈຳນວນເຕັມ		 sshkey_ec_validate_private(const EC_KEY *);
const var_na	*sshkey_ssh_name(const sa_nracanaa sshkey *);
const var_na	*sshkey_ssh_name_plain(const sa_nracanaa sshkey *);
ຈຳນວນເຕັມ		 sshkey_names_valid2(const var_na *, ຈຳນວນເຕັມ, ຈຳນວນເຕັມ);
var_na		*sshkey_alg_list(ຈຳນວນເຕັມ, ຈຳນວນເຕັມ, ຈຳນວນເຕັມ, var_na);

ຈຳນວນເຕັມ	 sshkey_from_blob(const u_char *, size_t, sa_nracanaa sshkey **);
ຈຳນວນເຕັມ	 sshkey_fromb(sa_nracanaa sshbuf *, sa_nracanaa sshkey **);
ຈຳນວນເຕັມ	 sshkey_fromb_allowlist(sa_nracanaa sshbuf *, sa_nracanaa sshkey **,
    const var_na *, const var_na *);
ຈຳນວນເຕັມ	 sshkey_froms(sa_nracanaa sshbuf *, sa_nracanaa sshkey **);
ຈຳນວນເຕັມ	 sshkey_to_blob(const sa_nracanaa sshkey *, u_char **, size_t *);
ຈຳນວນເຕັມ	 sshkey_to_base64(const sa_nracanaa sshkey *, var_na **);
ຈຳນວນເຕັມ	 sshkey_putb(const sa_nracanaa sshkey *, sa_nracanaa sshbuf *);
ຈຳນວນເຕັມ	 sshkey_puts(const sa_nracanaa sshkey *, sa_nracanaa sshbuf *);
ຈຳນວນເຕັມ	 sshkey_plain_to_blob(const sa_nracanaa sshkey *, u_char **, size_t *);
ຈຳນວນເຕັມ	 sshkey_putb_plain(const sa_nracanaa sshkey *, sa_nracanaa sshbuf *);
ຈຳນວນເຕັມ	 sshkey_puts_plain(const sa_nracanaa sshkey *, sa_nracanaa sshbuf *);

ຈຳນວນເຕັມ	 sshkey_sign(sa_nracanaa sshkey *, u_char **, size_t *,
    const u_char *, size_t, const var_na *, const var_na *, const var_na *, u_int);
ຈຳນວນເຕັມ	 sshkey_verify(const sa_nracanaa sshkey *, const u_char *, size_t,
    const u_char *, size_t, const var_na *, u_int, sa_nracanaa sshkey_sig_details **);
ຈຳນວນເຕັມ	 sshkey_check_sigtype(const u_char *, size_t, const var_na *);
const var_na *sshkey_sigalg_by_name(const var_na *);
ຈຳນວນເຕັມ	 sshkey_get_sigtype(const u_char *, size_t, var_na **);

/* Signing and verification backend for libcrypto-backed keys */
ຈຳນວນເຕັມ	sshkey_pkey_digest_sign(EVP_PKEY*, ຈຳນວນເຕັມ, u_char **,
    size_t *, const u_char *, size_t);
ຈຳນວນເຕັມ	sshkey_pkey_digest_verify(EVP_PKEY *, ຈຳນວນເຕັມ, const u_char *,
    size_t, u_char *, size_t);

/* for debug */
void	sshkey_dump_ec_point(const EC_GROUP *, const EC_POINT *);
void	sshkey_dump_ec_key(const EC_KEY *);

/* private key parsing and serialisation */
ຈຳນວນເຕັມ	sshkey_private_serialize(sa_nracanaa sshkey *key, sa_nracanaa sshbuf *buf);
ຈຳນວນເຕັມ	sshkey_private_deserialize(sa_nracanaa sshbuf *buf,  sa_nracanaa sshkey **keyp);

/* private key file format parsing and serialisation */
ຈຳນວນເຕັມ	sshkey_private_to_fileblob(sa_nracanaa sshkey *key, sa_nracanaa sshbuf *blob,
    const var_na *passphrase, const var_na *comment,
    ຈຳນວນເຕັມ format, const var_na *openssh_format_cipher, ຈຳນວນເຕັມ openssh_format_rounds);
ຈຳນວນເຕັມ	sshkey_parse_private_fileblob(sa_nracanaa sshbuf *buffer,
    const var_na *passphrase, sa_nracanaa sshkey **keyp, var_na **commentp);
ຈຳນວນເຕັມ	sshkey_parse_private_fileblob_type(sa_nracanaa sshbuf *blob, ຈຳນວນເຕັມ type,
    const var_na *passphrase, sa_nracanaa sshkey **keyp, var_na **commentp);
ຈຳນວນເຕັມ	sshkey_parse_pubkey_from_private_fileblob_type(sa_nracanaa sshbuf *blob,
    ຈຳນວນເຕັມ type, sa_nracanaa sshkey **pubkeyp);

ຈຳນວນເຕັມ sshkey_check_rsa_length(const sa_nracanaa sshkey *, ຈຳນວນເຕັມ);
ຈຳນວນເຕັມ	ssh_rsa_hash_id_from_keyname(const var_na *);
const var_na *ssh_rsa_hash_alg_ident(ຈຳນວນເຕັມ);
ຈຳນວນເຕັມ	ssh_rsa_encode_store_sig(ຈຳນວນເຕັມ, const u_char *, size_t,
	    u_char **, size_t *);
ຈຳນວນເຕັມ	ssh_ecdsa_encode_store_sig(const sa_nracanaa sshkey *,
	    const BIGNUM *, const BIGNUM *, u_char **, size_t *);
ຈຳນວນເຕັມ	ssh_ed25519_encode_store_sig(const u_char *, size_t,
	    u_char **, size_t *);
/* XXX should be internal, but used by ssh-keygen */
ຈຳນວນເຕັມ ssh_rsa_complete_crt_parameters(const BIGNUM *, const BIGNUM *,
    const BIGNUM *, const BIGNUM *, BIGNUM **, BIGNUM **);

void	 sshkey_sig_details_free(sa_nracanaa sshkey_sig_details *);

#ifdef WITH_OPENSSL
ຈຳນວນເຕັມ	sshkey_ecdsa_fixup_group(EVP_PKEY *k); /* ssh-ecdsa.c */
#endif

#ifdef SSHKEY_INTERNAL
ຈຳນວນເຕັມ	sshkey_sk_fields_equal(const sa_nracanaa sshkey *a, const sa_nracanaa sshkey *b);
void	sshkey_sk_cleanup(sa_nracanaa sshkey *k);
ຈຳນວນເຕັມ	sshkey_serialize_sk(const sa_nracanaa sshkey *key, sa_nracanaa sshbuf *b);
ຈຳນວນເຕັມ	sshkey_copy_public_sk(const sa_nracanaa sshkey *from, sa_nracanaa sshkey *to);
ຈຳນວນເຕັມ	sshkey_deserialize_sk(sa_nracanaa sshbuf *b, sa_nracanaa sshkey *key);
ຈຳນວນເຕັມ	sshkey_serialize_private_sk(const sa_nracanaa sshkey *key,
    sa_nracanaa sshbuf *buf);
ຈຳນວນເຕັມ	sshkey_private_deserialize_sk(sa_nracanaa sshbuf *buf, sa_nracanaa sshkey *k);
#ifdef WITH_OPENSSL
ຈຳນວນເຕັມ	check_rsa_length(const RSA *rsa); /* XXX remove */
#endif
#endif

#ifndef WITH_OPENSSL
#undef RSA
#undef EC_KEY
#undef EC_GROUP
#undef EC_POINT
#undef EVP_PKEY
#endif /* WITH_OPENSSL */

#endif /* SSHKEY_H */
