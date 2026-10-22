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

#அந்தர்பாவ <sys/types.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/rsa.h>
#அந்தர்பாவ <openssl/ec.h>
#அந்தர்பாவ <openssl/ecdsa.h>
#அந்தர்பாவ <openssl/evp.h>
#define SSH_OPENSSL_VERSION OpenSSL_version(OPENSSL_VERSION)
#இல்லையெனில் /* OPENSSL */
#define BIGNUM		வெறுமை
#define RSA		வெறுமை
#define EC_சாவி		வெறுமை
#define EC_GROUP	வெறுமை
#define EC_POINT	வெறுமை
#define EVP_PKEY	வெறுமை
#define SSH_OPENSSL_VERSION "without OpenSSL"
#endif /* WITH_OPENSSL */

#define SSH_RSA_MINIMUM_MODULUS_SIZE	1024
#define SSH_சாவி_MAX_SIGN_DATA_SIZE	(1 << 20)

கட்டமைப்பு sshbuf;

/* Key types */
எண்ணிக்கை sshkey_types {
	சாவி_RSA,
	சாவி_ECDSA,
	சாவி_ED25519,
	சாவி_RSA_CERT,
	சாவி_ECDSA_CERT,
	சாவி_ED25519_CERT,
	சாவி_ECDSA_SK,
	சாவி_ECDSA_SK_CERT,
	சாவி_ED25519_SK,
	சாவி_ED25519_SK_CERT,
	சாவி_MLDSA44_ED25519,
	சாவி_MLDSA44_ED25519_CERT,
	சாவி_UNSPEC
};

/* Default fingerprint hash */
#define SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
எண்ணிக்கை sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
எண்ணிக்கை sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
எண்ணிக்கை sshkey_private_format {
	SSHKEY_PRIVATE_OPENSSH = 0,
	SSHKEY_PRIVATE_PEM = 1,
	SSHKEY_PRIVATE_PKCS8 = 2,
};

/* key is stored in external hardware */
#define SSHKEY_FLAG_EXT		0x0001

#define SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
கட்டமைப்பு sshkey_cert {
	கட்டமைப்பு sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	எழுத்து		*சாவி_id;
	u_int		 nprincipals;
	எழுத்து		**principals;
	uint64_t	 valid_after, valid_before;
	கட்டமைப்பு sshbuf	*critical;
	கட்டமைப்பு sshbuf	*extensions;
	கட்டமைப்பு sshkey	*signature_சாவி;
	எழுத்து		*signature_type;
};

/* XXX opacify? */
கட்டமைப்பு sshkey {
	முழு	 type;
	முழு	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	முழு	 ecdsa_nid;	/* NID of curve */
	/* libcrypto-backed keys */
	EVP_PKEY *pkey;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_MLDSA44_ED25519 */
	u_char	*mldsa_ed25519_sk;
	u_char	*mldsa_ed25519_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	எழுத்து	*sk_application;
	uint8_t	sk_flags;
	கட்டமைப்பு sshbuf *sk_சாவி_handle;
	கட்டமைப்பு sshbuf *sk_reserved;
	/* Certificates */
	கட்டமைப்பு sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	size_t	shielded_len;
	u_char	*shield_prekey;
	size_t	shield_prekey_len;
};

#define	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#define	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
கட்டமைப்பு sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

கட்டமைப்பு sshkey_impl_funcs {
	u_int (*size)(மாறிலி கட்டமைப்பு sshkey *);	/* optional */
	முழு (*alloc)(கட்டமைப்பு sshkey *);		/* optional */
	வெறுமை (*cleanup)(கட்டமைப்பு sshkey *);	/* optional */
	முழு (*equal)(மாறிலி கட்டமைப்பு sshkey *, மாறிலி கட்டமைப்பு sshkey *);
	முழு (*serialize_public)(மாறிலி கட்டமைப்பு sshkey *, கட்டமைப்பு sshbuf *,
	    எண்ணிக்கை sshkey_serialize_rep);
	முழு (*deserialize_public)(மாறிலி எழுத்து *, கட்டமைப்பு sshbuf *,
	    கட்டமைப்பு sshkey *);
	முழு (*serialize_private)(மாறிலி கட்டமைப்பு sshkey *, கட்டமைப்பு sshbuf *,
	    எண்ணிக்கை sshkey_serialize_rep);
	முழு (*deserialize_private)(மாறிலி எழுத்து *, கட்டமைப்பு sshbuf *,
	    கட்டமைப்பு sshkey *);
	முழு (*generate)(கட்டமைப்பு sshkey *, முழு);	/* optional */
	முழு (*copy_public)(மாறிலி கட்டமைப்பு sshkey *, கட்டமைப்பு sshkey *);
	முழு (*sign)(கட்டமைப்பு sshkey *, u_char **, size_t *,
	    மாறிலி u_char *, size_t, மாறிலி எழுத்து *,
	    மாறிலி எழுத்து *, மாறிலி எழுத்து *, u_int); /* optional */
	முழு (*verify)(மாறிலி கட்டமைப்பு sshkey *, மாறிலி u_char *, size_t,
	    மாறிலி u_char *, size_t, மாறிலி எழுத்து *, u_int,
	    கட்டமைப்பு sshkey_sig_details **);
};

கட்டமைப்பு sshkey_impl {
	மாறிலி எழுத்து *name;
	மாறிலி எழுத்து *shortname;
	மாறிலி எழுத்து *sigalg;
	முழு type;
	முழு nid;
	முழு cert;
	முழு sigonly;
	முழு keybits;
	மாறிலி கட்டமைப்பு sshkey_impl_funcs *funcs;
};

கட்டமைப்பு sshkey	*sshkey_new(முழு);
வெறுமை		 sshkey_free(கட்டமைப்பு sshkey *);
முழு		 sshkey_equal_public(மாறிலி கட்டமைப்பு sshkey *,
    மாறிலி கட்டமைப்பு sshkey *);
முழு		 sshkey_equal(மாறிலி கட்டமைப்பு sshkey *, மாறிலி கட்டமைப்பு sshkey *);
எழுத்து		*sshkey_fingerprint(மாறிலி கட்டமைப்பு sshkey *,
    முழு, எண்ணிக்கை sshkey_fp_rep);
முழு		 sshkey_fingerprint_raw(மாறிலி கட்டமைப்பு sshkey *k,
    முழு, u_char **retp, size_t *lenp);
மாறிலி எழுத்து	*sshkey_type(மாறிலி கட்டமைப்பு sshkey *);
மாறிலி எழுத்து	*sshkey_cert_type(மாறிலி கட்டமைப்பு sshkey *);
முழு		 sshkey_format_text(மாறிலி கட்டமைப்பு sshkey *, கட்டமைப்பு sshbuf *);
முழு		 sshkey_write(மாறிலி கட்டமைப்பு sshkey *, FILE *);
முழு		 sshkey_read(கட்டமைப்பு sshkey *, எழுத்து **);
u_int		 sshkey_size(மாறிலி கட்டமைப்பு sshkey *);

முழு		 sshkey_generate(முழு type, u_int bits, கட்டமைப்பு sshkey **keyp);
முழு		 sshkey_from_private(மாறிலி கட்டமைப்பு sshkey *, கட்டமைப்பு sshkey **);

முழு		 sshkey_is_shielded(கட்டமைப்பு sshkey *);
முழு		 sshkey_shield_private(கட்டமைப்பு sshkey *);
முழு		 sshkey_unshield_private(கட்டமைப்பு sshkey *);

முழு	 sshkey_type_from_name(மாறிலி எழுத்து *);
முழு	 sshkey_type_from_shortname(மாறிலி எழுத்து *);
முழு	 sshkey_is_cert(மாறிலி கட்டமைப்பு sshkey *);
முழு	 sshkey_is_sk(மாறிலி கட்டமைப்பு sshkey *);
முழு	 sshkey_type_is_cert(முழு);
முழு	 sshkey_type_plain(முழு);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
முழு	 sshkey_match_keyname_to_sigalgs(மாறிலி எழுத்து *, மாறிலி எழுத்து *);

முழு	 sshkey_to_certified(கட்டமைப்பு sshkey *);
முழு	 sshkey_drop_cert(கட்டமைப்பு sshkey *);
முழு	 sshkey_cert_copy(மாறிலி கட்டமைப்பு sshkey *, கட்டமைப்பு sshkey *);
முழு	 sshkey_cert_check_authority(மாறிலி கட்டமைப்பு sshkey *, முழு, முழு,
    uint64_t, மாறிலி எழுத்து *, மாறிலி எழுத்து **);
முழு	 sshkey_cert_check_authority_now(மாறிலி கட்டமைப்பு sshkey *, முழு, முழு,
    மாறிலி எழுத்து *, மாறிலி எழுத்து **);
முழு	 sshkey_cert_check_host(மாறிலி கட்டமைப்பு sshkey *, மாறிலி எழுத்து *,
    மாறிலி எழுத்து *, மாறிலி எழுத்து **);
size_t	 sshkey_format_cert_validity(மாறிலி கட்டமைப்பு sshkey_cert *,
    எழுத்து *, size_t) __attribute__((__bounded__(__string__, 2, 3)));
முழு	 sshkey_check_cert_sigtype(மாறிலி கட்டமைப்பு sshkey *, மாறிலி எழுத்து *);

முழு	 sshkey_certify(கட்டமைப்பு sshkey *, கட்டமைப்பு sshkey *,
    மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
வகைவரை முழு sshkey_certify_signer(கட்டமைப்பு sshkey *, u_char **, size_t *,
    மாறிலி u_char *, size_t, மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *,
    u_int, வெறுமை *);
முழு	 sshkey_certify_custom(கட்டமைப்பு sshkey *, கட்டமைப்பு sshkey *, மாறிலி எழுத்து *,
    மாறிலி எழுத்து *, மாறிலி எழுத்து *, sshkey_certify_signer *, வெறுமை *);

முழு		 sshkey_ecdsa_nid_from_name(மாறிலி எழுத்து *);
முழு		 sshkey_curve_name_to_nid(மாறிலி எழுத்து *);
மாறிலி எழுத்து *	 sshkey_curve_nid_to_name(முழு);
u_int		 sshkey_curve_nid_to_bits(முழு);
முழு		 sshkey_ecdsa_bits_to_nid(முழு);
முழு		 sshkey_ecdsa_சாவி_to_nid(மாறிலி EC_சாவி *);
முழு		 sshkey_ecdsa_pkey_to_nid(EVP_PKEY *);
முழு		 sshkey_ec_nid_to_hash_alg(முழு nid);
முழு		 sshkey_ec_validate_public(மாறிலி EC_GROUP *, மாறிலி EC_POINT *);
முழு		 sshkey_ec_validate_private(மாறிலி EC_சாவி *);
மாறிலி எழுத்து	*sshkey_ssh_name(மாறிலி கட்டமைப்பு sshkey *);
மாறிலி எழுத்து	*sshkey_ssh_name_plain(மாறிலி கட்டமைப்பு sshkey *);
முழு		 sshkey_names_valid2(மாறிலி எழுத்து *, முழு, முழு);
எழுத்து		*sshkey_alg_list(முழு, முழு, முழு, எழுத்து);

முழு	 sshkey_from_blob(மாறிலி u_char *, size_t, கட்டமைப்பு sshkey **);
முழு	 sshkey_fromb(கட்டமைப்பு sshbuf *, கட்டமைப்பு sshkey **);
முழு	 sshkey_fromb_allowlist(கட்டமைப்பு sshbuf *, கட்டமைப்பு sshkey **,
    மாறிலி எழுத்து *, மாறிலி எழுத்து *);
முழு	 sshkey_froms(கட்டமைப்பு sshbuf *, கட்டமைப்பு sshkey **);
முழு	 sshkey_to_blob(மாறிலி கட்டமைப்பு sshkey *, u_char **, size_t *);
முழு	 sshkey_to_base64(மாறிலி கட்டமைப்பு sshkey *, எழுத்து **);
முழு	 sshkey_putb(மாறிலி கட்டமைப்பு sshkey *, கட்டமைப்பு sshbuf *);
முழு	 sshkey_puts(மாறிலி கட்டமைப்பு sshkey *, கட்டமைப்பு sshbuf *);
முழு	 sshkey_plain_to_blob(மாறிலி கட்டமைப்பு sshkey *, u_char **, size_t *);
முழு	 sshkey_putb_plain(மாறிலி கட்டமைப்பு sshkey *, கட்டமைப்பு sshbuf *);
முழு	 sshkey_puts_plain(மாறிலி கட்டமைப்பு sshkey *, கட்டமைப்பு sshbuf *);

முழு	 sshkey_sign(கட்டமைப்பு sshkey *, u_char **, size_t *,
    மாறிலி u_char *, size_t, மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *, u_int);
முழு	 sshkey_verify(மாறிலி கட்டமைப்பு sshkey *, மாறிலி u_char *, size_t,
    மாறிலி u_char *, size_t, மாறிலி எழுத்து *, u_int, கட்டமைப்பு sshkey_sig_details **);
முழு	 sshkey_check_sigtype(மாறிலி u_char *, size_t, மாறிலி எழுத்து *);
மாறிலி எழுத்து *sshkey_sigalg_by_name(மாறிலி எழுத்து *);
முழு	 sshkey_get_sigtype(மாறிலி u_char *, size_t, எழுத்து **);

/* Signing and verification backend for libcrypto-backed keys */
முழு	sshkey_pkey_digest_sign(EVP_PKEY*, முழு, u_char **,
    size_t *, மாறிலி u_char *, size_t);
முழு	sshkey_pkey_digest_verify(EVP_PKEY *, முழு, மாறிலி u_char *,
    size_t, u_char *, size_t);

/* for debug */
வெறுமை	sshkey_dump_ec_point(மாறிலி EC_GROUP *, மாறிலி EC_POINT *);
வெறுமை	sshkey_dump_ec_சாவி(மாறிலி EC_சாவி *);

/* private key parsing and serialisation */
முழு	sshkey_private_serialize(கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *buf);
முழு	sshkey_private_deserialize(கட்டமைப்பு sshbuf *buf,  கட்டமைப்பு sshkey **keyp);

/* private key file format parsing and serialisation */
முழு	sshkey_private_to_fileblob(கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *blob,
    மாறிலி எழுத்து *passphrase, மாறிலி எழுத்து *comment,
    முழு format, மாறிலி எழுத்து *openssh_format_cipher, முழு openssh_format_rounds);
முழு	sshkey_parse_private_fileblob(கட்டமைப்பு sshbuf *buffer,
    மாறிலி எழுத்து *passphrase, கட்டமைப்பு sshkey **keyp, எழுத்து **commentp);
முழு	sshkey_parse_private_fileblob_type(கட்டமைப்பு sshbuf *blob, முழு type,
    மாறிலி எழுத்து *passphrase, கட்டமைப்பு sshkey **keyp, எழுத்து **commentp);
முழு	sshkey_parse_pubkey_from_private_fileblob_type(கட்டமைப்பு sshbuf *blob,
    முழு type, கட்டமைப்பு sshkey **pubkeyp);

முழு sshkey_check_rsa_length(மாறிலி கட்டமைப்பு sshkey *, முழு);
முழு	ssh_rsa_hash_id_from_keyname(மாறிலி எழுத்து *);
மாறிலி எழுத்து *ssh_rsa_hash_alg_ident(முழு);
முழு	ssh_rsa_encode_store_sig(முழு, மாறிலி u_char *, size_t,
	    u_char **, size_t *);
முழு	ssh_ecdsa_encode_store_sig(மாறிலி கட்டமைப்பு sshkey *,
	    மாறிலி BIGNUM *, மாறிலி BIGNUM *, u_char **, size_t *);
முழு	ssh_ed25519_encode_store_sig(மாறிலி u_char *, size_t,
	    u_char **, size_t *);
/* XXX should be internal, but used by ssh-keygen */
முழு ssh_rsa_complete_crt_parameters(மாறிலி BIGNUM *, மாறிலி BIGNUM *,
    மாறிலி BIGNUM *, மாறிலி BIGNUM *, BIGNUM **, BIGNUM **);

வெறுமை	 sshkey_sig_details_free(கட்டமைப்பு sshkey_sig_details *);

#ifdef WITH_OPENSSL
முழு	sshkey_ecdsa_fixup_group(EVP_PKEY *k); /* ssh-ecdsa.c */
#endif

#ifdef SSHKEY_INTERNAL
முழு	sshkey_sk_fields_equal(மாறிலி கட்டமைப்பு sshkey *a, மாறிலி கட்டமைப்பு sshkey *b);
வெறுமை	sshkey_sk_cleanup(கட்டமைப்பு sshkey *k);
முழு	sshkey_serialize_sk(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b);
முழு	sshkey_copy_public_sk(மாறிலி கட்டமைப்பு sshkey *from, கட்டமைப்பு sshkey *to);
முழு	sshkey_deserialize_sk(கட்டமைப்பு sshbuf *b, கட்டமைப்பு sshkey *சாவி);
முழு	sshkey_serialize_private_sk(மாறிலி கட்டமைப்பு sshkey *சாவி,
    கட்டமைப்பு sshbuf *buf);
முழு	sshkey_private_deserialize_sk(கட்டமைப்பு sshbuf *buf, கட்டமைப்பு sshkey *k);
#ifdef WITH_OPENSSL
முழு	check_rsa_length(மாறிலி RSA *rsa); /* XXX remove */
#endif
#endif

#ifndef WITH_OPENSSL
#undef RSA
#undef EC_சாவி
#undef EC_GROUP
#undef EC_POINT
#undef EVP_PKEY
#endif /* WITH_OPENSSL */

#endif /* SSHKEY_H */
