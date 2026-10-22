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

#અન્તર્ભાવ <sys/types.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/rsa.h>
#અન્તર્ભાવ <openssl/ec.h>
#અન્તર્ભાવ <openssl/ecdsa.h>
#અન્તર્ભાવ <openssl/evp.h>
#define SSH_OPENSSL_VERSION OpenSSL_version(OPENSSL_VERSION)
#નહીંતર /* OPENSSL */
#define BIGNUM		શૂન્ય
#define RSA		શૂન્ય
#define EC_ચાવી		શૂન્ય
#define EC_GROUP	શૂન્ય
#define EC_POINT	શૂન્ય
#define EVP_PKEY	શૂન્ય
#define SSH_OPENSSL_VERSION "without OpenSSL"
#endif /* WITH_OPENSSL */

#define SSH_RSA_MINIMUM_MODULUS_SIZE	1024
#define SSH_ચાવી_MAX_SIGN_DATA_SIZE	(1 << 20)

સંરચના sshbuf;

/* Key types */
ગણના sshkey_types {
	ચાવી_RSA,
	ચાવી_ECDSA,
	ચાવી_ED25519,
	ચાવી_RSA_CERT,
	ચાવી_ECDSA_CERT,
	ચાવી_ED25519_CERT,
	ચાવી_ECDSA_SK,
	ચાવી_ECDSA_SK_CERT,
	ચાવી_ED25519_SK,
	ચાવી_ED25519_SK_CERT,
	ચાવી_MLDSA44_ED25519,
	ચાવી_MLDSA44_ED25519_CERT,
	ચાવી_UNSPEC
};

/* Default fingerprint hash */
#define SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
ગણના sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
ગણના sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
ગણના sshkey_private_format {
	SSHKEY_PRIVATE_OPENSSH = 0,
	SSHKEY_PRIVATE_PEM = 1,
	SSHKEY_PRIVATE_PKCS8 = 2,
};

/* key is stored in external hardware */
#define SSHKEY_FLAG_EXT		0x0001

#define SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
સંરચના sshkey_cert {
	સંરચના sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	અક્ષર		*ચાવી_id;
	u_int		 nprincipals;
	અક્ષર		**principals;
	uint64_t	 valid_after, valid_before;
	સંરચના sshbuf	*critical;
	સંરચના sshbuf	*extensions;
	સંરચના sshkey	*signature_ચાવી;
	અક્ષર		*signature_type;
};

/* XXX opacify? */
સંરચના sshkey {
	પૂર્ણાંક	 type;
	પૂર્ણાંક	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	પૂર્ણાંક	 ecdsa_nid;	/* NID of curve */
	/* libcrypto-backed keys */
	EVP_PKEY *pkey;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_MLDSA44_ED25519 */
	u_char	*mldsa_ed25519_sk;
	u_char	*mldsa_ed25519_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	અક્ષર	*sk_application;
	uint8_t	sk_flags;
	સંરચના sshbuf *sk_ચાવી_handle;
	સંરચના sshbuf *sk_reserved;
	/* Certificates */
	સંરચના sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	size_t	shielded_len;
	u_char	*shield_prekey;
	size_t	shield_prekey_len;
};

#define	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#define	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
સંરચના sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

સંરચના sshkey_impl_funcs {
	u_int (*size)(અચલ સંરચના sshkey *);	/* optional */
	પૂર્ણાંક (*alloc)(સંરચના sshkey *);		/* optional */
	શૂન્ય (*cleanup)(સંરચના sshkey *);	/* optional */
	પૂર્ણાંક (*equal)(અચલ સંરચના sshkey *, અચલ સંરચના sshkey *);
	પૂર્ણાંક (*serialize_public)(અચલ સંરચના sshkey *, સંરચના sshbuf *,
	    ગણના sshkey_serialize_rep);
	પૂર્ણાંક (*deserialize_public)(અચલ અક્ષર *, સંરચના sshbuf *,
	    સંરચના sshkey *);
	પૂર્ણાંક (*serialize_private)(અચલ સંરચના sshkey *, સંરચના sshbuf *,
	    ગણના sshkey_serialize_rep);
	પૂર્ણાંક (*deserialize_private)(અચલ અક્ષર *, સંરચના sshbuf *,
	    સંરચના sshkey *);
	પૂર્ણાંક (*generate)(સંરચના sshkey *, પૂર્ણાંક);	/* optional */
	પૂર્ણાંક (*copy_public)(અચલ સંરચના sshkey *, સંરચના sshkey *);
	પૂર્ણાંક (*sign)(સંરચના sshkey *, u_char **, size_t *,
	    અચલ u_char *, size_t, અચલ અક્ષર *,
	    અચલ અક્ષર *, અચલ અક્ષર *, u_int); /* optional */
	પૂર્ણાંક (*verify)(અચલ સંરચના sshkey *, અચલ u_char *, size_t,
	    અચલ u_char *, size_t, અચલ અક્ષર *, u_int,
	    સંરચના sshkey_sig_details **);
};

સંરચના sshkey_impl {
	અચલ અક્ષર *name;
	અચલ અક્ષર *shortname;
	અચલ અક્ષર *sigalg;
	પૂર્ણાંક type;
	પૂર્ણાંક nid;
	પૂર્ણાંક cert;
	પૂર્ણાંક sigonly;
	પૂર્ણાંક keybits;
	અચલ સંરચના sshkey_impl_funcs *funcs;
};

સંરચના sshkey	*sshkey_new(પૂર્ણાંક);
શૂન્ય		 sshkey_free(સંરચના sshkey *);
પૂર્ણાંક		 sshkey_equal_public(અચલ સંરચના sshkey *,
    અચલ સંરચના sshkey *);
પૂર્ણાંક		 sshkey_equal(અચલ સંરચના sshkey *, અચલ સંરચના sshkey *);
અક્ષર		*sshkey_fingerprint(અચલ સંરચના sshkey *,
    પૂર્ણાંક, ગણના sshkey_fp_rep);
પૂર્ણાંક		 sshkey_fingerprint_raw(અચલ સંરચના sshkey *k,
    પૂર્ણાંક, u_char **retp, size_t *lenp);
અચલ અક્ષર	*sshkey_type(અચલ સંરચના sshkey *);
અચલ અક્ષર	*sshkey_cert_type(અચલ સંરચના sshkey *);
પૂર્ણાંક		 sshkey_format_text(અચલ સંરચના sshkey *, સંરચના sshbuf *);
પૂર્ણાંક		 sshkey_write(અચલ સંરચના sshkey *, FILE *);
પૂર્ણાંક		 sshkey_read(સંરચના sshkey *, અક્ષર **);
u_int		 sshkey_size(અચલ સંરચના sshkey *);

પૂર્ણાંક		 sshkey_generate(પૂર્ણાંક type, u_int bits, સંરચના sshkey **keyp);
પૂર્ણાંક		 sshkey_from_private(અચલ સંરચના sshkey *, સંરચના sshkey **);

પૂર્ણાંક		 sshkey_is_shielded(સંરચના sshkey *);
પૂર્ણાંક		 sshkey_shield_private(સંરચના sshkey *);
પૂર્ણાંક		 sshkey_unshield_private(સંરચના sshkey *);

પૂર્ણાંક	 sshkey_type_from_name(અચલ અક્ષર *);
પૂર્ણાંક	 sshkey_type_from_shortname(અચલ અક્ષર *);
પૂર્ણાંક	 sshkey_is_cert(અચલ સંરચના sshkey *);
પૂર્ણાંક	 sshkey_is_sk(અચલ સંરચના sshkey *);
પૂર્ણાંક	 sshkey_type_is_cert(પૂર્ણાંક);
પૂર્ણાંક	 sshkey_type_plain(પૂર્ણાંક);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
પૂર્ણાંક	 sshkey_match_keyname_to_sigalgs(અચલ અક્ષર *, અચલ અક્ષર *);

પૂર્ણાંક	 sshkey_to_certified(સંરચના sshkey *);
પૂર્ણાંક	 sshkey_drop_cert(સંરચના sshkey *);
પૂર્ણાંક	 sshkey_cert_copy(અચલ સંરચના sshkey *, સંરચના sshkey *);
પૂર્ણાંક	 sshkey_cert_check_authority(અચલ સંરચના sshkey *, પૂર્ણાંક, પૂર્ણાંક,
    uint64_t, અચલ અક્ષર *, અચલ અક્ષર **);
પૂર્ણાંક	 sshkey_cert_check_authority_now(અચલ સંરચના sshkey *, પૂર્ણાંક, પૂર્ણાંક,
    અચલ અક્ષર *, અચલ અક્ષર **);
પૂર્ણાંક	 sshkey_cert_check_host(અચલ સંરચના sshkey *, અચલ અક્ષર *,
    અચલ અક્ષર *, અચલ અક્ષર **);
size_t	 sshkey_format_cert_validity(અચલ સંરચના sshkey_cert *,
    અક્ષર *, size_t) __attribute__((__bounded__(__string__, 2, 3)));
પૂર્ણાંક	 sshkey_check_cert_sigtype(અચલ સંરચના sshkey *, અચલ અક્ષર *);

પૂર્ણાંક	 sshkey_certify(સંરચના sshkey *, સંરચના sshkey *,
    અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
પ્રકારવ્યાખ્યા પૂર્ણાંક sshkey_certify_signer(સંરચના sshkey *, u_char **, size_t *,
    અચલ u_char *, size_t, અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *,
    u_int, શૂન્ય *);
પૂર્ણાંક	 sshkey_certify_custom(સંરચના sshkey *, સંરચના sshkey *, અચલ અક્ષર *,
    અચલ અક્ષર *, અચલ અક્ષર *, sshkey_certify_signer *, શૂન્ય *);

પૂર્ણાંક		 sshkey_ecdsa_nid_from_name(અચલ અક્ષર *);
પૂર્ણાંક		 sshkey_curve_name_to_nid(અચલ અક્ષર *);
અચલ અક્ષર *	 sshkey_curve_nid_to_name(પૂર્ણાંક);
u_int		 sshkey_curve_nid_to_bits(પૂર્ણાંક);
પૂર્ણાંક		 sshkey_ecdsa_bits_to_nid(પૂર્ણાંક);
પૂર્ણાંક		 sshkey_ecdsa_ચાવી_to_nid(અચલ EC_ચાવી *);
પૂર્ણાંક		 sshkey_ecdsa_pkey_to_nid(EVP_PKEY *);
પૂર્ણાંક		 sshkey_ec_nid_to_hash_alg(પૂર્ણાંક nid);
પૂર્ણાંક		 sshkey_ec_validate_public(અચલ EC_GROUP *, અચલ EC_POINT *);
પૂર્ણાંક		 sshkey_ec_validate_private(અચલ EC_ચાવી *);
અચલ અક્ષર	*sshkey_ssh_name(અચલ સંરચના sshkey *);
અચલ અક્ષર	*sshkey_ssh_name_plain(અચલ સંરચના sshkey *);
પૂર્ણાંક		 sshkey_names_valid2(અચલ અક્ષર *, પૂર્ણાંક, પૂર્ણાંક);
અક્ષર		*sshkey_alg_list(પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક, અક્ષર);

પૂર્ણાંક	 sshkey_from_blob(અચલ u_char *, size_t, સંરચના sshkey **);
પૂર્ણાંક	 sshkey_fromb(સંરચના sshbuf *, સંરચના sshkey **);
પૂર્ણાંક	 sshkey_fromb_allowlist(સંરચના sshbuf *, સંરચના sshkey **,
    અચલ અક્ષર *, અચલ અક્ષર *);
પૂર્ણાંક	 sshkey_froms(સંરચના sshbuf *, સંરચના sshkey **);
પૂર્ણાંક	 sshkey_to_blob(અચલ સંરચના sshkey *, u_char **, size_t *);
પૂર્ણાંક	 sshkey_to_base64(અચલ સંરચના sshkey *, અક્ષર **);
પૂર્ણાંક	 sshkey_putb(અચલ સંરચના sshkey *, સંરચના sshbuf *);
પૂર્ણાંક	 sshkey_puts(અચલ સંરચના sshkey *, સંરચના sshbuf *);
પૂર્ણાંક	 sshkey_plain_to_blob(અચલ સંરચના sshkey *, u_char **, size_t *);
પૂર્ણાંક	 sshkey_putb_plain(અચલ સંરચના sshkey *, સંરચના sshbuf *);
પૂર્ણાંક	 sshkey_puts_plain(અચલ સંરચના sshkey *, સંરચના sshbuf *);

પૂર્ણાંક	 sshkey_sign(સંરચના sshkey *, u_char **, size_t *,
    અચલ u_char *, size_t, અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *, u_int);
પૂર્ણાંક	 sshkey_verify(અચલ સંરચના sshkey *, અચલ u_char *, size_t,
    અચલ u_char *, size_t, અચલ અક્ષર *, u_int, સંરચના sshkey_sig_details **);
પૂર્ણાંક	 sshkey_check_sigtype(અચલ u_char *, size_t, અચલ અક્ષર *);
અચલ અક્ષર *sshkey_sigalg_by_name(અચલ અક્ષર *);
પૂર્ણાંક	 sshkey_get_sigtype(અચલ u_char *, size_t, અક્ષર **);

/* Signing and verification backend for libcrypto-backed keys */
પૂર્ણાંક	sshkey_pkey_digest_sign(EVP_PKEY*, પૂર્ણાંક, u_char **,
    size_t *, અચલ u_char *, size_t);
પૂર્ણાંક	sshkey_pkey_digest_verify(EVP_PKEY *, પૂર્ણાંક, અચલ u_char *,
    size_t, u_char *, size_t);

/* for debug */
શૂન્ય	sshkey_dump_ec_point(અચલ EC_GROUP *, અચલ EC_POINT *);
શૂન્ય	sshkey_dump_ec_ચાવી(અચલ EC_ચાવી *);

/* private key parsing and serialisation */
પૂર્ણાંક	sshkey_private_serialize(સંરચના sshkey *ચાવી, સંરચના sshbuf *buf);
પૂર્ણાંક	sshkey_private_deserialize(સંરચના sshbuf *buf,  સંરચના sshkey **keyp);

/* private key file format parsing and serialisation */
પૂર્ણાંક	sshkey_private_to_fileblob(સંરચના sshkey *ચાવી, સંરચના sshbuf *blob,
    અચલ અક્ષર *passphrase, અચલ અક્ષર *comment,
    પૂર્ણાંક format, અચલ અક્ષર *openssh_format_cipher, પૂર્ણાંક openssh_format_rounds);
પૂર્ણાંક	sshkey_parse_private_fileblob(સંરચના sshbuf *buffer,
    અચલ અક્ષર *passphrase, સંરચના sshkey **keyp, અક્ષર **commentp);
પૂર્ણાંક	sshkey_parse_private_fileblob_type(સંરચના sshbuf *blob, પૂર્ણાંક type,
    અચલ અક્ષર *passphrase, સંરચના sshkey **keyp, અક્ષર **commentp);
પૂર્ણાંક	sshkey_parse_pubkey_from_private_fileblob_type(સંરચના sshbuf *blob,
    પૂર્ણાંક type, સંરચના sshkey **pubkeyp);

પૂર્ણાંક sshkey_check_rsa_length(અચલ સંરચના sshkey *, પૂર્ણાંક);
પૂર્ણાંક	ssh_rsa_hash_id_from_keyname(અચલ અક્ષર *);
અચલ અક્ષર *ssh_rsa_hash_alg_ident(પૂર્ણાંક);
પૂર્ણાંક	ssh_rsa_encode_store_sig(પૂર્ણાંક, અચલ u_char *, size_t,
	    u_char **, size_t *);
પૂર્ણાંક	ssh_ecdsa_encode_store_sig(અચલ સંરચના sshkey *,
	    અચલ BIGNUM *, અચલ BIGNUM *, u_char **, size_t *);
પૂર્ણાંક	ssh_ed25519_encode_store_sig(અચલ u_char *, size_t,
	    u_char **, size_t *);
/* XXX should be internal, but used by ssh-keygen */
પૂર્ણાંક ssh_rsa_complete_crt_parameters(અચલ BIGNUM *, અચલ BIGNUM *,
    અચલ BIGNUM *, અચલ BIGNUM *, BIGNUM **, BIGNUM **);

શૂન્ય	 sshkey_sig_details_free(સંરચના sshkey_sig_details *);

#ifdef WITH_OPENSSL
પૂર્ણાંક	sshkey_ecdsa_fixup_group(EVP_PKEY *k); /* ssh-ecdsa.c */
#endif

#ifdef SSHKEY_INTERNAL
પૂર્ણાંક	sshkey_sk_fields_equal(અચલ સંરચના sshkey *a, અચલ સંરચના sshkey *b);
શૂન્ય	sshkey_sk_cleanup(સંરચના sshkey *k);
પૂર્ણાંક	sshkey_serialize_sk(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b);
પૂર્ણાંક	sshkey_copy_public_sk(અચલ સંરચના sshkey *from, સંરચના sshkey *to);
પૂર્ણાંક	sshkey_deserialize_sk(સંરચના sshbuf *b, સંરચના sshkey *ચાવી);
પૂર્ણાંક	sshkey_serialize_private_sk(અચલ સંરચના sshkey *ચાવી,
    સંરચના sshbuf *buf);
પૂર્ણાંક	sshkey_private_deserialize_sk(સંરચના sshbuf *buf, સંરચના sshkey *k);
#ifdef WITH_OPENSSL
પૂર્ણાંક	check_rsa_length(અચલ RSA *rsa); /* XXX remove */
#endif
#endif

#ifndef WITH_OPENSSL
#undef RSA
#undef EC_ચાવી
#undef EC_GROUP
#undef EC_POINT
#undef EVP_PKEY
#endif /* WITH_OPENSSL */

#endif /* SSHKEY_H */
