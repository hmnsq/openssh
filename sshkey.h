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
#否则 /* OPENSSL */
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
	整数	 type;
	整数	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	整数	 ecdsa_nid;	/* NID of curve */
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
	整数 (*alloc)(struct sshkey *);		/* optional */
	void (*cleanup)(struct sshkey *);	/* optional */
	整数 (*equal)(const struct sshkey *, const struct sshkey *);
	整数 (*serialize_public)(const struct sshkey *, struct sshbuf *,
	    enum sshkey_serialize_rep);
	整数 (*deserialize_public)(const char *, struct sshbuf *,
	    struct sshkey *);
	整数 (*serialize_private)(const struct sshkey *, struct sshbuf *,
	    enum sshkey_serialize_rep);
	整数 (*deserialize_private)(const char *, struct sshbuf *,
	    struct sshkey *);
	整数 (*generate)(struct sshkey *, 整数);	/* optional */
	整数 (*copy_public)(const struct sshkey *, struct sshkey *);
	整数 (*sign)(struct sshkey *, u_char **, size_t *,
	    const u_char *, size_t, const char *,
	    const char *, const char *, u_int); /* optional */
	整数 (*verify)(const struct sshkey *, const u_char *, size_t,
	    const u_char *, size_t, const char *, u_int,
	    struct sshkey_sig_details **);
};

struct sshkey_impl {
	const char *name;
	const char *shortname;
	const char *sigalg;
	整数 type;
	整数 nid;
	整数 cert;
	整数 sigonly;
	整数 keybits;
	const struct sshkey_impl_funcs *funcs;
};

struct sshkey	*sshkey_new(整数);
void		 sshkey_free(struct sshkey *);
整数		 sshkey_equal_public(const struct sshkey *,
    const struct sshkey *);
整数		 sshkey_equal(const struct sshkey *, const struct sshkey *);
char		*sshkey_fingerprint(const struct sshkey *,
    整数, enum sshkey_fp_rep);
整数		 sshkey_fingerprint_raw(const struct sshkey *k,
    整数, u_char **retp, size_t *lenp);
const char	*sshkey_type(const struct sshkey *);
const char	*sshkey_cert_type(const struct sshkey *);
整数		 sshkey_format_text(const struct sshkey *, struct sshbuf *);
整数		 sshkey_write(const struct sshkey *, FILE *);
整数		 sshkey_read(struct sshkey *, char **);
u_int		 sshkey_size(const struct sshkey *);

整数		 sshkey_generate(整数 type, u_int bits, struct sshkey **keyp);
整数		 sshkey_from_private(const struct sshkey *, struct sshkey **);

整数		 sshkey_is_shielded(struct sshkey *);
整数		 sshkey_shield_private(struct sshkey *);
整数		 sshkey_unshield_private(struct sshkey *);

整数	 sshkey_type_from_name(const char *);
整数	 sshkey_type_from_shortname(const char *);
整数	 sshkey_is_cert(const struct sshkey *);
整数	 sshkey_is_sk(const struct sshkey *);
整数	 sshkey_type_is_cert(整数);
整数	 sshkey_type_plain(整数);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
整数	 sshkey_match_keyname_to_sigalgs(const char *, const char *);

整数	 sshkey_to_certified(struct sshkey *);
整数	 sshkey_drop_cert(struct sshkey *);
整数	 sshkey_cert_copy(const struct sshkey *, struct sshkey *);
整数	 sshkey_cert_check_authority(const struct sshkey *, 整数, 整数,
    uint64_t, const char *, const char **);
整数	 sshkey_cert_check_authority_now(const struct sshkey *, 整数, 整数,
    const char *, const char **);
整数	 sshkey_cert_check_host(const struct sshkey *, const char *,
    const char *, const char **);
size_t	 sshkey_format_cert_validity(const struct sshkey_cert *,
    char *, size_t) __attribute__((__bounded__(__string__, 2, 3)));
整数	 sshkey_check_cert_sigtype(const struct sshkey *, const char *);

整数	 sshkey_certify(struct sshkey *, struct sshkey *,
    const char *, const char *, const char *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
typedef 整数 sshkey_certify_signer(struct sshkey *, u_char **, size_t *,
    const u_char *, size_t, const char *, const char *, const char *,
    u_int, void *);
整数	 sshkey_certify_custom(struct sshkey *, struct sshkey *, const char *,
    const char *, const char *, sshkey_certify_signer *, void *);

整数		 sshkey_ecdsa_nid_from_name(const char *);
整数		 sshkey_curve_name_to_nid(const char *);
const char *	 sshkey_curve_nid_to_name(整数);
u_int		 sshkey_curve_nid_to_bits(整数);
整数		 sshkey_ecdsa_bits_to_nid(整数);
整数		 sshkey_ecdsa_key_to_nid(const EC_KEY *);
整数		 sshkey_ecdsa_pkey_to_nid(EVP_PKEY *);
整数		 sshkey_ec_nid_to_hash_alg(整数 nid);
整数		 sshkey_ec_validate_public(const EC_GROUP *, const EC_POINT *);
整数		 sshkey_ec_validate_private(const EC_KEY *);
const char	*sshkey_ssh_name(const struct sshkey *);
const char	*sshkey_ssh_name_plain(const struct sshkey *);
整数		 sshkey_names_valid2(const char *, 整数, 整数);
char		*sshkey_alg_list(整数, 整数, 整数, char);

整数	 sshkey_from_blob(const u_char *, size_t, struct sshkey **);
整数	 sshkey_fromb(struct sshbuf *, struct sshkey **);
整数	 sshkey_fromb_allowlist(struct sshbuf *, struct sshkey **,
    const char *, const char *);
整数	 sshkey_froms(struct sshbuf *, struct sshkey **);
整数	 sshkey_to_blob(const struct sshkey *, u_char **, size_t *);
整数	 sshkey_to_base64(const struct sshkey *, char **);
整数	 sshkey_putb(const struct sshkey *, struct sshbuf *);
整数	 sshkey_puts(const struct sshkey *, struct sshbuf *);
整数	 sshkey_plain_to_blob(const struct sshkey *, u_char **, size_t *);
整数	 sshkey_putb_plain(const struct sshkey *, struct sshbuf *);
整数	 sshkey_puts_plain(const struct sshkey *, struct sshbuf *);

整数	 sshkey_sign(struct sshkey *, u_char **, size_t *,
    const u_char *, size_t, const char *, const char *, const char *, u_int);
整数	 sshkey_verify(const struct sshkey *, const u_char *, size_t,
    const u_char *, size_t, const char *, u_int, struct sshkey_sig_details **);
整数	 sshkey_check_sigtype(const u_char *, size_t, const char *);
const char *sshkey_sigalg_by_name(const char *);
整数	 sshkey_get_sigtype(const u_char *, size_t, char **);

/* Signing and verification backend for libcrypto-backed keys */
整数	sshkey_pkey_digest_sign(EVP_PKEY*, 整数, u_char **,
    size_t *, const u_char *, size_t);
整数	sshkey_pkey_digest_verify(EVP_PKEY *, 整数, const u_char *,
    size_t, u_char *, size_t);

/* for debug */
void	sshkey_dump_ec_point(const EC_GROUP *, const EC_POINT *);
void	sshkey_dump_ec_key(const EC_KEY *);

/* private key parsing and serialisation */
整数	sshkey_private_serialize(struct sshkey *key, struct sshbuf *buf);
整数	sshkey_private_deserialize(struct sshbuf *buf,  struct sshkey **keyp);

/* private key file format parsing and serialisation */
整数	sshkey_private_to_fileblob(struct sshkey *key, struct sshbuf *blob,
    const char *passphrase, const char *comment,
    整数 format, const char *openssh_format_cipher, 整数 openssh_format_rounds);
整数	sshkey_parse_private_fileblob(struct sshbuf *buffer,
    const char *passphrase, struct sshkey **keyp, char **commentp);
整数	sshkey_parse_private_fileblob_type(struct sshbuf *blob, 整数 type,
    const char *passphrase, struct sshkey **keyp, char **commentp);
整数	sshkey_parse_pubkey_from_private_fileblob_type(struct sshbuf *blob,
    整数 type, struct sshkey **pubkeyp);

整数 sshkey_check_rsa_length(const struct sshkey *, 整数);
整数	ssh_rsa_hash_id_from_keyname(const char *);
const char *ssh_rsa_hash_alg_ident(整数);
整数	ssh_rsa_encode_store_sig(整数, const u_char *, size_t,
	    u_char **, size_t *);
整数	ssh_ecdsa_encode_store_sig(const struct sshkey *,
	    const BIGNUM *, const BIGNUM *, u_char **, size_t *);
整数	ssh_ed25519_encode_store_sig(const u_char *, size_t,
	    u_char **, size_t *);
/* XXX should be internal, but used by ssh-keygen */
整数 ssh_rsa_complete_crt_parameters(const BIGNUM *, const BIGNUM *,
    const BIGNUM *, const BIGNUM *, BIGNUM **, BIGNUM **);

void	 sshkey_sig_details_free(struct sshkey_sig_details *);

#ifdef WITH_OPENSSL
整数	sshkey_ecdsa_fixup_group(EVP_PKEY *k); /* ssh-ecdsa.c */
#endif

#ifdef SSHKEY_INTERNAL
整数	sshkey_sk_fields_equal(const struct sshkey *a, const struct sshkey *b);
void	sshkey_sk_cleanup(struct sshkey *k);
整数	sshkey_serialize_sk(const struct sshkey *key, struct sshbuf *b);
整数	sshkey_copy_public_sk(const struct sshkey *from, struct sshkey *to);
整数	sshkey_deserialize_sk(struct sshbuf *b, struct sshkey *key);
整数	sshkey_serialize_private_sk(const struct sshkey *key,
    struct sshbuf *buf);
整数	sshkey_private_deserialize_sk(struct sshbuf *buf, struct sshkey *k);
#ifdef WITH_OPENSSL
整数	check_rsa_length(const RSA *rsa); /* XXX remove */
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
