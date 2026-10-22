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
#инако /* OPENSSL */
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

struct sshbuf;

/* Key types */
enum sshkey_types {
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
enum sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
enum sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
enum sshkey_private_format {
	SSHKEY_PRIVATE_OPENSSH = 0,
	SSHKEY_PRIVATE_PEM = 1,
	SSHKEY_PRIVATE_PKCS8 = 2,
};

/* key is stored in external hardware */
#define SSHKEY_FLAG_EXT		0x0001

#define SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
struct sshkey_cert {
	struct sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	char		*key_id;
	u_int		 nprincipals;
	char		**principals;
	uint64_t	 valid_after, valid_before;
	struct sshbuf	*critical;
	struct sshbuf	*extensions;
	struct sshkey	*signature_key;
	char		*signature_type;
};

/* XXX opacify? */
struct sshkey {
	цео	 type;
	цео	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	цео	 ecdsa_nid;	/* NID of curve */
	/* libcrypto-backed keys */
	EVP_PKEY *pkey;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_MLDSA44_ED25519 */
	u_char	*mldsa_ed25519_sk;
	u_char	*mldsa_ed25519_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	char	*sk_application;
	uint8_t	sk_flags;
	struct sshbuf *sk_key_handle;
	struct sshbuf *sk_reserved;
	/* Certificates */
	struct sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	size_t	shielded_len;
	u_char	*shield_prekey;
	size_t	shield_prekey_len;
};

#define	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#define	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
struct sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

struct sshkey_impl_funcs {
	u_int (*size)(const struct sshkey *);	/* optional */
	цео (*alloc)(struct sshkey *);		/* optional */
	void (*cleanup)(struct sshkey *);	/* optional */
	цео (*equal)(const struct sshkey *, const struct sshkey *);
	цео (*serialize_public)(const struct sshkey *, struct sshbuf *,
	    enum sshkey_serialize_rep);
	цео (*deserialize_public)(const char *, struct sshbuf *,
	    struct sshkey *);
	цео (*serialize_private)(const struct sshkey *, struct sshbuf *,
	    enum sshkey_serialize_rep);
	цео (*deserialize_private)(const char *, struct sshbuf *,
	    struct sshkey *);
	цео (*generate)(struct sshkey *, цео);	/* optional */
	цео (*copy_public)(const struct sshkey *, struct sshkey *);
	цео (*sign)(struct sshkey *, u_char **, size_t *,
	    const u_char *, size_t, const char *,
	    const char *, const char *, u_int); /* optional */
	цео (*verify)(const struct sshkey *, const u_char *, size_t,
	    const u_char *, size_t, const char *, u_int,
	    struct sshkey_sig_details **);
};

struct sshkey_impl {
	const char *name;
	const char *shortname;
	const char *sigalg;
	цео type;
	цео nid;
	цео cert;
	цео sigonly;
	цео keybits;
	const struct sshkey_impl_funcs *funcs;
};

struct sshkey	*sshkey_new(цео);
void		 sshkey_free(struct sshkey *);
цео		 sshkey_equal_public(const struct sshkey *,
    const struct sshkey *);
цео		 sshkey_equal(const struct sshkey *, const struct sshkey *);
char		*sshkey_fingerprint(const struct sshkey *,
    цео, enum sshkey_fp_rep);
цео		 sshkey_fingerprint_raw(const struct sshkey *k,
    цео, u_char **retp, size_t *lenp);
const char	*sshkey_type(const struct sshkey *);
const char	*sshkey_cert_type(const struct sshkey *);
цео		 sshkey_format_text(const struct sshkey *, struct sshbuf *);
цео		 sshkey_write(const struct sshkey *, FILE *);
цео		 sshkey_read(struct sshkey *, char **);
u_int		 sshkey_size(const struct sshkey *);

цео		 sshkey_generate(цео type, u_int bits, struct sshkey **keyp);
цео		 sshkey_from_private(const struct sshkey *, struct sshkey **);

цео		 sshkey_is_shielded(struct sshkey *);
цео		 sshkey_shield_private(struct sshkey *);
цео		 sshkey_unshield_private(struct sshkey *);

цео	 sshkey_type_from_name(const char *);
цео	 sshkey_type_from_shortname(const char *);
цео	 sshkey_is_cert(const struct sshkey *);
цео	 sshkey_is_sk(const struct sshkey *);
цео	 sshkey_type_is_cert(цео);
цео	 sshkey_type_plain(цео);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
цео	 sshkey_match_keyname_to_sigalgs(const char *, const char *);

цео	 sshkey_to_certified(struct sshkey *);
цео	 sshkey_drop_cert(struct sshkey *);
цео	 sshkey_cert_copy(const struct sshkey *, struct sshkey *);
цео	 sshkey_cert_check_authority(const struct sshkey *, цео, цео,
    uint64_t, const char *, const char **);
цео	 sshkey_cert_check_authority_now(const struct sshkey *, цео, цео,
    const char *, const char **);
цео	 sshkey_cert_check_host(const struct sshkey *, const char *,
    const char *, const char **);
size_t	 sshkey_format_cert_validity(const struct sshkey_cert *,
    char *, size_t) __attribute__((__bounded__(__string__, 2, 3)));
цео	 sshkey_check_cert_sigtype(const struct sshkey *, const char *);

цео	 sshkey_certify(struct sshkey *, struct sshkey *,
    const char *, const char *, const char *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
typedef цео sshkey_certify_signer(struct sshkey *, u_char **, size_t *,
    const u_char *, size_t, const char *, const char *, const char *,
    u_int, void *);
цео	 sshkey_certify_custom(struct sshkey *, struct sshkey *, const char *,
    const char *, const char *, sshkey_certify_signer *, void *);

цео		 sshkey_ecdsa_nid_from_name(const char *);
цео		 sshkey_curve_name_to_nid(const char *);
const char *	 sshkey_curve_nid_to_name(цео);
u_int		 sshkey_curve_nid_to_bits(цео);
цео		 sshkey_ecdsa_bits_to_nid(цео);
цео		 sshkey_ecdsa_key_to_nid(const EC_KEY *);
цео		 sshkey_ecdsa_pkey_to_nid(EVP_PKEY *);
цео		 sshkey_ec_nid_to_hash_alg(цео nid);
цео		 sshkey_ec_validate_public(const EC_GROUP *, const EC_POINT *);
цео		 sshkey_ec_validate_private(const EC_KEY *);
const char	*sshkey_ssh_name(const struct sshkey *);
const char	*sshkey_ssh_name_plain(const struct sshkey *);
цео		 sshkey_names_valid2(const char *, цео, цео);
char		*sshkey_alg_list(цео, цео, цео, char);

цео	 sshkey_from_blob(const u_char *, size_t, struct sshkey **);
цео	 sshkey_fromb(struct sshbuf *, struct sshkey **);
цео	 sshkey_fromb_allowlist(struct sshbuf *, struct sshkey **,
    const char *, const char *);
цео	 sshkey_froms(struct sshbuf *, struct sshkey **);
цео	 sshkey_to_blob(const struct sshkey *, u_char **, size_t *);
цео	 sshkey_to_base64(const struct sshkey *, char **);
цео	 sshkey_putb(const struct sshkey *, struct sshbuf *);
цео	 sshkey_puts(const struct sshkey *, struct sshbuf *);
цео	 sshkey_plain_to_blob(const struct sshkey *, u_char **, size_t *);
цео	 sshkey_putb_plain(const struct sshkey *, struct sshbuf *);
цео	 sshkey_puts_plain(const struct sshkey *, struct sshbuf *);

цео	 sshkey_sign(struct sshkey *, u_char **, size_t *,
    const u_char *, size_t, const char *, const char *, const char *, u_int);
цео	 sshkey_verify(const struct sshkey *, const u_char *, size_t,
    const u_char *, size_t, const char *, u_int, struct sshkey_sig_details **);
цео	 sshkey_check_sigtype(const u_char *, size_t, const char *);
const char *sshkey_sigalg_by_name(const char *);
цео	 sshkey_get_sigtype(const u_char *, size_t, char **);

/* Signing and verification backend for libcrypto-backed keys */
цео	sshkey_pkey_digest_sign(EVP_PKEY*, цео, u_char **,
    size_t *, const u_char *, size_t);
цео	sshkey_pkey_digest_verify(EVP_PKEY *, цео, const u_char *,
    size_t, u_char *, size_t);

/* for debug */
void	sshkey_dump_ec_point(const EC_GROUP *, const EC_POINT *);
void	sshkey_dump_ec_key(const EC_KEY *);

/* private key parsing and serialisation */
цео	sshkey_private_serialize(struct sshkey *key, struct sshbuf *buf);
цео	sshkey_private_deserialize(struct sshbuf *buf,  struct sshkey **keyp);

/* private key file format parsing and serialisation */
цео	sshkey_private_to_fileblob(struct sshkey *key, struct sshbuf *blob,
    const char *passphrase, const char *comment,
    цео format, const char *openssh_format_cipher, цео openssh_format_rounds);
цео	sshkey_parse_private_fileblob(struct sshbuf *buffer,
    const char *passphrase, struct sshkey **keyp, char **commentp);
цео	sshkey_parse_private_fileblob_type(struct sshbuf *blob, цео type,
    const char *passphrase, struct sshkey **keyp, char **commentp);
цео	sshkey_parse_pubkey_from_private_fileblob_type(struct sshbuf *blob,
    цео type, struct sshkey **pubkeyp);

цео sshkey_check_rsa_length(const struct sshkey *, цео);
цео	ssh_rsa_hash_id_from_keyname(const char *);
const char *ssh_rsa_hash_alg_ident(цео);
цео	ssh_rsa_encode_store_sig(цео, const u_char *, size_t,
	    u_char **, size_t *);
цео	ssh_ecdsa_encode_store_sig(const struct sshkey *,
	    const BIGNUM *, const BIGNUM *, u_char **, size_t *);
цео	ssh_ed25519_encode_store_sig(const u_char *, size_t,
	    u_char **, size_t *);
/* XXX should be internal, but used by ssh-keygen */
цео ssh_rsa_complete_crt_parameters(const BIGNUM *, const BIGNUM *,
    const BIGNUM *, const BIGNUM *, BIGNUM **, BIGNUM **);

void	 sshkey_sig_details_free(struct sshkey_sig_details *);

#ifdef WITH_OPENSSL
цео	sshkey_ecdsa_fixup_group(EVP_PKEY *k); /* ssh-ecdsa.c */
#endif

#ifdef SSHKEY_INTERNAL
цео	sshkey_sk_fields_equal(const struct sshkey *a, const struct sshkey *b);
void	sshkey_sk_cleanup(struct sshkey *k);
цео	sshkey_serialize_sk(const struct sshkey *key, struct sshbuf *b);
цео	sshkey_copy_public_sk(const struct sshkey *from, struct sshkey *to);
цео	sshkey_deserialize_sk(struct sshbuf *b, struct sshkey *key);
цео	sshkey_serialize_private_sk(const struct sshkey *key,
    struct sshbuf *buf);
цео	sshkey_private_deserialize_sk(struct sshbuf *buf, struct sshkey *k);
#ifdef WITH_OPENSSL
цео	check_rsa_length(const RSA *rsa); /* XXX remove */
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
