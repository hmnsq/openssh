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

#അന്തര്ഭാവ <sys/types.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/rsa.h>
#അന്തര്ഭാവ <openssl/ec.h>
#അന്തര്ഭാവ <openssl/ecdsa.h>
#അന്തര്ഭാവ <openssl/evp.h>
#define SSH_OPENSSL_VERSION OpenSSL_version(OPENSSL_VERSION)
#അല്ലെങ്കിൽ /* OPENSSL */
#define BIGNUM		ശൂന്യം
#define RSA		ശൂന്യം
#define EC_താക്കോൽ		ശൂന്യം
#define EC_GROUP	ശൂന്യം
#define EC_POINT	ശൂന്യം
#define EVP_PKEY	ശൂന്യം
#define SSH_OPENSSL_VERSION "without OpenSSL"
#endif /* WITH_OPENSSL */

#define SSH_RSA_MINIMUM_MODULUS_SIZE	1024
#define SSH_താക്കോൽ_MAX_SIGN_DATA_SIZE	(1 << 20)

ഘടന sshbuf;

/* Key types */
എണ്ണൽ sshkey_types {
	താക്കോൽ_RSA,
	താക്കോൽ_ECDSA,
	താക്കോൽ_ED25519,
	താക്കോൽ_RSA_CERT,
	താക്കോൽ_ECDSA_CERT,
	താക്കോൽ_ED25519_CERT,
	താക്കോൽ_ECDSA_SK,
	താക്കോൽ_ECDSA_SK_CERT,
	താക്കോൽ_ED25519_SK,
	താക്കോൽ_ED25519_SK_CERT,
	താക്കോൽ_MLDSA44_ED25519,
	താക്കോൽ_MLDSA44_ED25519_CERT,
	താക്കോൽ_UNSPEC
};

/* Default fingerprint hash */
#define SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
എണ്ണൽ sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
എണ്ണൽ sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
എണ്ണൽ sshkey_private_format {
	SSHKEY_PRIVATE_OPENSSH = 0,
	SSHKEY_PRIVATE_PEM = 1,
	SSHKEY_PRIVATE_PKCS8 = 2,
};

/* key is stored in external hardware */
#define SSHKEY_FLAG_EXT		0x0001

#define SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
ഘടന sshkey_cert {
	ഘടന sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	അക്ഷരം		*താക്കോൽ_id;
	u_int		 nprincipals;
	അക്ഷരം		**principals;
	uint64_t	 valid_after, valid_before;
	ഘടന sshbuf	*critical;
	ഘടന sshbuf	*extensions;
	ഘടന sshkey	*signature_താക്കോൽ;
	അക്ഷരം		*signature_type;
};

/* XXX opacify? */
ഘടന sshkey {
	പൂർണ്ണസംഖ്യ	 type;
	പൂർണ്ണസംഖ്യ	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	പൂർണ്ണസംഖ്യ	 ecdsa_nid;	/* NID of curve */
	/* libcrypto-backed keys */
	EVP_PKEY *pkey;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_MLDSA44_ED25519 */
	u_char	*mldsa_ed25519_sk;
	u_char	*mldsa_ed25519_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	അക്ഷരം	*sk_application;
	uint8_t	sk_flags;
	ഘടന sshbuf *sk_താക്കോൽ_handle;
	ഘടന sshbuf *sk_reserved;
	/* Certificates */
	ഘടന sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	size_t	shielded_len;
	u_char	*shield_prekey;
	size_t	shield_prekey_len;
};

#define	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#define	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
ഘടന sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

ഘടന sshkey_impl_funcs {
	u_int (*size)(സ്ഥിരം ഘടന sshkey *);	/* optional */
	പൂർണ്ണസംഖ്യ (*alloc)(ഘടന sshkey *);		/* optional */
	ശൂന്യം (*cleanup)(ഘടന sshkey *);	/* optional */
	പൂർണ്ണസംഖ്യ (*equal)(സ്ഥിരം ഘടന sshkey *, സ്ഥിരം ഘടന sshkey *);
	പൂർണ്ണസംഖ്യ (*serialize_public)(സ്ഥിരം ഘടന sshkey *, ഘടന sshbuf *,
	    എണ്ണൽ sshkey_serialize_rep);
	പൂർണ്ണസംഖ്യ (*deserialize_public)(സ്ഥിരം അക്ഷരം *, ഘടന sshbuf *,
	    ഘടന sshkey *);
	പൂർണ്ണസംഖ്യ (*serialize_private)(സ്ഥിരം ഘടന sshkey *, ഘടന sshbuf *,
	    എണ്ണൽ sshkey_serialize_rep);
	പൂർണ്ണസംഖ്യ (*deserialize_private)(സ്ഥിരം അക്ഷരം *, ഘടന sshbuf *,
	    ഘടന sshkey *);
	പൂർണ്ണസംഖ്യ (*generate)(ഘടന sshkey *, പൂർണ്ണസംഖ്യ);	/* optional */
	പൂർണ്ണസംഖ്യ (*copy_public)(സ്ഥിരം ഘടന sshkey *, ഘടന sshkey *);
	പൂർണ്ണസംഖ്യ (*sign)(ഘടന sshkey *, u_char **, size_t *,
	    സ്ഥിരം u_char *, size_t, സ്ഥിരം അക്ഷരം *,
	    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, u_int); /* optional */
	പൂർണ്ണസംഖ്യ (*verify)(സ്ഥിരം ഘടന sshkey *, സ്ഥിരം u_char *, size_t,
	    സ്ഥിരം u_char *, size_t, സ്ഥിരം അക്ഷരം *, u_int,
	    ഘടന sshkey_sig_details **);
};

ഘടന sshkey_impl {
	സ്ഥിരം അക്ഷരം *name;
	സ്ഥിരം അക്ഷരം *shortname;
	സ്ഥിരം അക്ഷരം *sigalg;
	പൂർണ്ണസംഖ്യ type;
	പൂർണ്ണസംഖ്യ nid;
	പൂർണ്ണസംഖ്യ cert;
	പൂർണ്ണസംഖ്യ sigonly;
	പൂർണ്ണസംഖ്യ keybits;
	സ്ഥിരം ഘടന sshkey_impl_funcs *funcs;
};

ഘടന sshkey	*sshkey_new(പൂർണ്ണസംഖ്യ);
ശൂന്യം		 sshkey_free(ഘടന sshkey *);
പൂർണ്ണസംഖ്യ		 sshkey_equal_public(സ്ഥിരം ഘടന sshkey *,
    സ്ഥിരം ഘടന sshkey *);
പൂർണ്ണസംഖ്യ		 sshkey_equal(സ്ഥിരം ഘടന sshkey *, സ്ഥിരം ഘടന sshkey *);
അക്ഷരം		*sshkey_fingerprint(സ്ഥിരം ഘടന sshkey *,
    പൂർണ്ണസംഖ്യ, എണ്ണൽ sshkey_fp_rep);
പൂർണ്ണസംഖ്യ		 sshkey_fingerprint_raw(സ്ഥിരം ഘടന sshkey *k,
    പൂർണ്ണസംഖ്യ, u_char **retp, size_t *lenp);
സ്ഥിരം അക്ഷരം	*sshkey_type(സ്ഥിരം ഘടന sshkey *);
സ്ഥിരം അക്ഷരം	*sshkey_cert_type(സ്ഥിരം ഘടന sshkey *);
പൂർണ്ണസംഖ്യ		 sshkey_format_text(സ്ഥിരം ഘടന sshkey *, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ		 sshkey_write(സ്ഥിരം ഘടന sshkey *, FILE *);
പൂർണ്ണസംഖ്യ		 sshkey_read(ഘടന sshkey *, അക്ഷരം **);
u_int		 sshkey_size(സ്ഥിരം ഘടന sshkey *);

പൂർണ്ണസംഖ്യ		 sshkey_generate(പൂർണ്ണസംഖ്യ type, u_int bits, ഘടന sshkey **keyp);
പൂർണ്ണസംഖ്യ		 sshkey_from_private(സ്ഥിരം ഘടന sshkey *, ഘടന sshkey **);

പൂർണ്ണസംഖ്യ		 sshkey_is_shielded(ഘടന sshkey *);
പൂർണ്ണസംഖ്യ		 sshkey_shield_private(ഘടന sshkey *);
പൂർണ്ണസംഖ്യ		 sshkey_unshield_private(ഘടന sshkey *);

പൂർണ്ണസംഖ്യ	 sshkey_type_from_name(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 sshkey_type_from_shortname(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 sshkey_is_cert(സ്ഥിരം ഘടന sshkey *);
പൂർണ്ണസംഖ്യ	 sshkey_is_sk(സ്ഥിരം ഘടന sshkey *);
പൂർണ്ണസംഖ്യ	 sshkey_type_is_cert(പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	 sshkey_type_plain(പൂർണ്ണസംഖ്യ);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
പൂർണ്ണസംഖ്യ	 sshkey_match_keyname_to_sigalgs(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);

പൂർണ്ണസംഖ്യ	 sshkey_to_certified(ഘടന sshkey *);
പൂർണ്ണസംഖ്യ	 sshkey_drop_cert(ഘടന sshkey *);
പൂർണ്ണസംഖ്യ	 sshkey_cert_copy(സ്ഥിരം ഘടന sshkey *, ഘടന sshkey *);
പൂർണ്ണസംഖ്യ	 sshkey_cert_check_authority(സ്ഥിരം ഘടന sshkey *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ,
    uint64_t, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം **);
പൂർണ്ണസംഖ്യ	 sshkey_cert_check_authority_now(സ്ഥിരം ഘടന sshkey *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ,
    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം **);
പൂർണ്ണസംഖ്യ	 sshkey_cert_check_host(സ്ഥിരം ഘടന sshkey *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം **);
size_t	 sshkey_format_cert_validity(സ്ഥിരം ഘടന sshkey_cert *,
    അക്ഷരം *, size_t) __attribute__((__bounded__(__string__, 2, 3)));
പൂർണ്ണസംഖ്യ	 sshkey_check_cert_sigtype(സ്ഥിരം ഘടന sshkey *, സ്ഥിരം അക്ഷരം *);

പൂർണ്ണസംഖ്യ	 sshkey_certify(ഘടന sshkey *, ഘടന sshkey *,
    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
തരനിർവചനം പൂർണ്ണസംഖ്യ sshkey_certify_signer(ഘടന sshkey *, u_char **, size_t *,
    സ്ഥിരം u_char *, size_t, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *,
    u_int, ശൂന്യം *);
പൂർണ്ണസംഖ്യ	 sshkey_certify_custom(ഘടന sshkey *, ഘടന sshkey *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, sshkey_certify_signer *, ശൂന്യം *);

പൂർണ്ണസംഖ്യ		 sshkey_ecdsa_nid_from_name(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ		 sshkey_curve_name_to_nid(സ്ഥിരം അക്ഷരം *);
സ്ഥിരം അക്ഷരം *	 sshkey_curve_nid_to_name(പൂർണ്ണസംഖ്യ);
u_int		 sshkey_curve_nid_to_bits(പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ		 sshkey_ecdsa_bits_to_nid(പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ		 sshkey_ecdsa_താക്കോൽ_to_nid(സ്ഥിരം EC_താക്കോൽ *);
പൂർണ്ണസംഖ്യ		 sshkey_ecdsa_pkey_to_nid(EVP_PKEY *);
പൂർണ്ണസംഖ്യ		 sshkey_ec_nid_to_hash_alg(പൂർണ്ണസംഖ്യ nid);
പൂർണ്ണസംഖ്യ		 sshkey_ec_validate_public(സ്ഥിരം EC_GROUP *, സ്ഥിരം EC_POINT *);
പൂർണ്ണസംഖ്യ		 sshkey_ec_validate_private(സ്ഥിരം EC_താക്കോൽ *);
സ്ഥിരം അക്ഷരം	*sshkey_ssh_name(സ്ഥിരം ഘടന sshkey *);
സ്ഥിരം അക്ഷരം	*sshkey_ssh_name_plain(സ്ഥിരം ഘടന sshkey *);
പൂർണ്ണസംഖ്യ		 sshkey_names_valid2(സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
അക്ഷരം		*sshkey_alg_list(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, അക്ഷരം);

പൂർണ്ണസംഖ്യ	 sshkey_from_blob(സ്ഥിരം u_char *, size_t, ഘടന sshkey **);
പൂർണ്ണസംഖ്യ	 sshkey_fromb(ഘടന sshbuf *, ഘടന sshkey **);
പൂർണ്ണസംഖ്യ	 sshkey_fromb_allowlist(ഘടന sshbuf *, ഘടന sshkey **,
    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 sshkey_froms(ഘടന sshbuf *, ഘടന sshkey **);
പൂർണ്ണസംഖ്യ	 sshkey_to_blob(സ്ഥിരം ഘടന sshkey *, u_char **, size_t *);
പൂർണ്ണസംഖ്യ	 sshkey_to_base64(സ്ഥിരം ഘടന sshkey *, അക്ഷരം **);
പൂർണ്ണസംഖ്യ	 sshkey_putb(സ്ഥിരം ഘടന sshkey *, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ	 sshkey_puts(സ്ഥിരം ഘടന sshkey *, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ	 sshkey_plain_to_blob(സ്ഥിരം ഘടന sshkey *, u_char **, size_t *);
പൂർണ്ണസംഖ്യ	 sshkey_putb_plain(സ്ഥിരം ഘടന sshkey *, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ	 sshkey_puts_plain(സ്ഥിരം ഘടന sshkey *, ഘടന sshbuf *);

പൂർണ്ണസംഖ്യ	 sshkey_sign(ഘടന sshkey *, u_char **, size_t *,
    സ്ഥിരം u_char *, size_t, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, u_int);
പൂർണ്ണസംഖ്യ	 sshkey_verify(സ്ഥിരം ഘടന sshkey *, സ്ഥിരം u_char *, size_t,
    സ്ഥിരം u_char *, size_t, സ്ഥിരം അക്ഷരം *, u_int, ഘടന sshkey_sig_details **);
പൂർണ്ണസംഖ്യ	 sshkey_check_sigtype(സ്ഥിരം u_char *, size_t, സ്ഥിരം അക്ഷരം *);
സ്ഥിരം അക്ഷരം *sshkey_sigalg_by_name(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 sshkey_get_sigtype(സ്ഥിരം u_char *, size_t, അക്ഷരം **);

/* Signing and verification backend for libcrypto-backed keys */
പൂർണ്ണസംഖ്യ	sshkey_pkey_digest_sign(EVP_PKEY*, പൂർണ്ണസംഖ്യ, u_char **,
    size_t *, സ്ഥിരം u_char *, size_t);
പൂർണ്ണസംഖ്യ	sshkey_pkey_digest_verify(EVP_PKEY *, പൂർണ്ണസംഖ്യ, സ്ഥിരം u_char *,
    size_t, u_char *, size_t);

/* for debug */
ശൂന്യം	sshkey_dump_ec_point(സ്ഥിരം EC_GROUP *, സ്ഥിരം EC_POINT *);
ശൂന്യം	sshkey_dump_ec_താക്കോൽ(സ്ഥിരം EC_താക്കോൽ *);

/* private key parsing and serialisation */
പൂർണ്ണസംഖ്യ	sshkey_private_serialize(ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *buf);
പൂർണ്ണസംഖ്യ	sshkey_private_deserialize(ഘടന sshbuf *buf,  ഘടന sshkey **keyp);

/* private key file format parsing and serialisation */
പൂർണ്ണസംഖ്യ	sshkey_private_to_fileblob(ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *blob,
    സ്ഥിരം അക്ഷരം *passphrase, സ്ഥിരം അക്ഷരം *comment,
    പൂർണ്ണസംഖ്യ format, സ്ഥിരം അക്ഷരം *openssh_format_cipher, പൂർണ്ണസംഖ്യ openssh_format_rounds);
പൂർണ്ണസംഖ്യ	sshkey_parse_private_fileblob(ഘടന sshbuf *buffer,
    സ്ഥിരം അക്ഷരം *passphrase, ഘടന sshkey **keyp, അക്ഷരം **commentp);
പൂർണ്ണസംഖ്യ	sshkey_parse_private_fileblob_type(ഘടന sshbuf *blob, പൂർണ്ണസംഖ്യ type,
    സ്ഥിരം അക്ഷരം *passphrase, ഘടന sshkey **keyp, അക്ഷരം **commentp);
പൂർണ്ണസംഖ്യ	sshkey_parse_pubkey_from_private_fileblob_type(ഘടന sshbuf *blob,
    പൂർണ്ണസംഖ്യ type, ഘടന sshkey **pubkeyp);

പൂർണ്ണസംഖ്യ sshkey_check_rsa_length(സ്ഥിരം ഘടന sshkey *, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	ssh_rsa_hash_id_from_keyname(സ്ഥിരം അക്ഷരം *);
സ്ഥിരം അക്ഷരം *ssh_rsa_hash_alg_ident(പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ	ssh_rsa_encode_store_sig(പൂർണ്ണസംഖ്യ, സ്ഥിരം u_char *, size_t,
	    u_char **, size_t *);
പൂർണ്ണസംഖ്യ	ssh_ecdsa_encode_store_sig(സ്ഥിരം ഘടന sshkey *,
	    സ്ഥിരം BIGNUM *, സ്ഥിരം BIGNUM *, u_char **, size_t *);
പൂർണ്ണസംഖ്യ	ssh_ed25519_encode_store_sig(സ്ഥിരം u_char *, size_t,
	    u_char **, size_t *);
/* XXX should be internal, but used by ssh-keygen */
പൂർണ്ണസംഖ്യ ssh_rsa_complete_crt_parameters(സ്ഥിരം BIGNUM *, സ്ഥിരം BIGNUM *,
    സ്ഥിരം BIGNUM *, സ്ഥിരം BIGNUM *, BIGNUM **, BIGNUM **);

ശൂന്യം	 sshkey_sig_details_free(ഘടന sshkey_sig_details *);

#ifdef WITH_OPENSSL
പൂർണ്ണസംഖ്യ	sshkey_ecdsa_fixup_group(EVP_PKEY *k); /* ssh-ecdsa.c */
#endif

#ifdef SSHKEY_INTERNAL
പൂർണ്ണസംഖ്യ	sshkey_sk_fields_equal(സ്ഥിരം ഘടന sshkey *a, സ്ഥിരം ഘടന sshkey *b);
ശൂന്യം	sshkey_sk_cleanup(ഘടന sshkey *k);
പൂർണ്ണസംഖ്യ	sshkey_serialize_sk(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b);
പൂർണ്ണസംഖ്യ	sshkey_copy_public_sk(സ്ഥിരം ഘടന sshkey *from, ഘടന sshkey *to);
പൂർണ്ണസംഖ്യ	sshkey_deserialize_sk(ഘടന sshbuf *b, ഘടന sshkey *താക്കോൽ);
പൂർണ്ണസംഖ്യ	sshkey_serialize_private_sk(സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    ഘടന sshbuf *buf);
പൂർണ്ണസംഖ്യ	sshkey_private_deserialize_sk(ഘടന sshbuf *buf, ഘടന sshkey *k);
#ifdef WITH_OPENSSL
പൂർണ്ണസംഖ്യ	check_rsa_length(സ്ഥിരം RSA *rsa); /* XXX remove */
#endif
#endif

#ifndef WITH_OPENSSL
#undef RSA
#undef EC_താക്കോൽ
#undef EC_GROUP
#undef EC_POINT
#undef EVP_PKEY
#endif /* WITH_OPENSSL */

#endif /* SSHKEY_H */
