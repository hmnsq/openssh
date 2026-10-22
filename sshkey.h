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
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SSHKEY_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHKEY_H

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/rsa.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ec.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ecdsa.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_OPENSSL_ਸੰਸਕਰਣ Open_SSL_ਸੰਸਕਰਣ(OPENSSL_ਸੰਸਕਰਣ)
#ਨਹੀਂਤਾਂ /* OPENSSL */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BIGNUM		ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RSA		ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EC_ਕੁੰਜੀ		ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EC_ਸਮੂਹ	ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EC_ਬਿੰਦੂ	ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EVP_PKEY	ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_OPENSSL_ਸੰਸਕਰਣ "without OpenSSL"
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_RSA_MINIMUM_MODULUS_ਮਾਪ	1024
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ਕੁੰਜੀ_MAX_SIGN_ਅੰਕੜੇ_ਮਾਪ	(1 << 20)

ਬਣਤਰ sshbuf;

/* Key types */
ਗਿਣਤੀ sshkey_types {
	ਕੁੰਜੀ_RSA,
	ਕੁੰਜੀ_ECDSA,
	ਕੁੰਜੀ_ED25519,
	ਕੁੰਜੀ_RSA_CERT,
	ਕੁੰਜੀ_ECDSA_CERT,
	ਕੁੰਜੀ_ED25519_CERT,
	ਕੁੰਜੀ_ECDSA_SK,
	ਕੁੰਜੀ_ECDSA_SK_CERT,
	ਕੁੰਜੀ_ED25519_SK,
	ਕੁੰਜੀ_ED25519_SK_CERT,
	ਕੁੰਜੀ_MLDSA44_ED25519,
	ਕੁੰਜੀ_MLDSA44_ED25519_CERT,
	ਕੁੰਜੀ_UNSPEC
};

/* Default fingerprint hash */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
ਗਿਣਤੀ sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
ਗਿਣਤੀ sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
ਗਿਣਤੀ sshkey_ਨਿੱਜੀ_format {
	SSHKEY_ਨਿੱਜੀ_OPENSSH = 0,
	SSHKEY_ਨਿੱਜੀ_PEM = 1,
	SSHKEY_ਨਿੱਜੀ_PKCS8 = 2,
};

/* key is stored in external hardware */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHKEY_FLAG_EXT		0x0001

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
ਬਣਤਰ sshkey_cert {
	ਬਣਤਰ sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	ਅੱਖਰ		*ਕੁੰਜੀ_id;
	u_int		 nprincipals;
	ਅੱਖਰ		**principals;
	uint64_t	 valid_after, valid_before;
	ਬਣਤਰ sshbuf	*critical;
	ਬਣਤਰ sshbuf	*extensions;
	ਬਣਤਰ sshkey	*signature_ਕੁੰਜੀ;
	ਅੱਖਰ		*signature_type;
};

/* XXX opacify? */
ਬਣਤਰ sshkey {
	ਪੂਰਨ	 type;
	ਪੂਰਨ	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	ਪੂਰਨ	 ecdsa_nid;	/* NID of curve */
	/* libcrypto-backed keys */
	EVP_PKEY *pkey;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_MLDSA44_ED25519 */
	u_char	*mldsa_ed25519_sk;
	u_char	*mldsa_ed25519_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	ਅੱਖਰ	*sk_application;
	uint8_t	sk_flags;
	ਬਣਤਰ sshbuf *sk_ਕੁੰਜੀ_handle;
	ਬਣਤਰ sshbuf *sk_reserved;
	/* Certificates */
	ਬਣਤਰ sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_ਨਿੱਜੀ;
	ਮਾਪ_t	shielded_len;
	u_char	*shield_prekey;
	ਮਾਪ_t	shield_prekey_len;
};

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
ਬਣਤਰ sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

ਬਣਤਰ sshkey_impl_funcs {
	u_int (*ਮਾਪ)(ਅਚਲ ਬਣਤਰ sshkey *);	/* optional */
	ਪੂਰਨ (*alloc)(ਬਣਤਰ sshkey *);		/* optional */
	ਖਾਲੀ (*cleanup)(ਬਣਤਰ sshkey *);	/* optional */
	ਪੂਰਨ (*equal)(ਅਚਲ ਬਣਤਰ sshkey *, ਅਚਲ ਬਣਤਰ sshkey *);
	ਪੂਰਨ (*serialize_ਜਨਤਕ)(ਅਚਲ ਬਣਤਰ sshkey *, ਬਣਤਰ sshbuf *,
	    ਗਿਣਤੀ sshkey_serialize_rep);
	ਪੂਰਨ (*deserialize_ਜਨਤਕ)(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sshbuf *,
	    ਬਣਤਰ sshkey *);
	ਪੂਰਨ (*serialize_ਨਿੱਜੀ)(ਅਚਲ ਬਣਤਰ sshkey *, ਬਣਤਰ sshbuf *,
	    ਗਿਣਤੀ sshkey_serialize_rep);
	ਪੂਰਨ (*deserialize_ਨਿੱਜੀ)(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sshbuf *,
	    ਬਣਤਰ sshkey *);
	ਪੂਰਨ (*generate)(ਬਣਤਰ sshkey *, ਪੂਰਨ);	/* optional */
	ਪੂਰਨ (*copy_ਜਨਤਕ)(ਅਚਲ ਬਣਤਰ sshkey *, ਬਣਤਰ sshkey *);
	ਪੂਰਨ (*sign)(ਬਣਤਰ sshkey *, u_char **, ਮਾਪ_t *,
	    ਅਚਲ u_char *, ਮਾਪ_t, ਅਚਲ ਅੱਖਰ *,
	    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, u_int); /* optional */
	ਪੂਰਨ (*verify)(ਅਚਲ ਬਣਤਰ sshkey *, ਅਚਲ u_char *, ਮਾਪ_t,
	    ਅਚਲ u_char *, ਮਾਪ_t, ਅਚਲ ਅੱਖਰ *, u_int,
	    ਬਣਤਰ sshkey_sig_details **);
};

ਬਣਤਰ sshkey_impl {
	ਅਚਲ ਅੱਖਰ *name;
	ਅਚਲ ਅੱਖਰ *shortname;
	ਅਚਲ ਅੱਖਰ *sigalg;
	ਪੂਰਨ type;
	ਪੂਰਨ nid;
	ਪੂਰਨ cert;
	ਪੂਰਨ sigonly;
	ਪੂਰਨ keybits;
	ਅਚਲ ਬਣਤਰ sshkey_impl_funcs *funcs;
};

ਬਣਤਰ sshkey	*sshkey_new(ਪੂਰਨ);
ਖਾਲੀ		 sshkey_free(ਬਣਤਰ sshkey *);
ਪੂਰਨ		 sshkey_equal_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *,
    ਅਚਲ ਬਣਤਰ sshkey *);
ਪੂਰਨ		 sshkey_equal(ਅਚਲ ਬਣਤਰ sshkey *, ਅਚਲ ਬਣਤਰ sshkey *);
ਅੱਖਰ		*sshkey_fingerprint(ਅਚਲ ਬਣਤਰ sshkey *,
    ਪੂਰਨ, ਗਿਣਤੀ sshkey_fp_rep);
ਪੂਰਨ		 sshkey_fingerprint_raw(ਅਚਲ ਬਣਤਰ sshkey *k,
    ਪੂਰਨ, u_char **retp, ਮਾਪ_t *lenp);
ਅਚਲ ਅੱਖਰ	*sshkey_type(ਅਚਲ ਬਣਤਰ sshkey *);
ਅਚਲ ਅੱਖਰ	*sshkey_cert_type(ਅਚਲ ਬਣਤਰ sshkey *);
ਪੂਰਨ		 sshkey_format_ਪਾਠ(ਅਚਲ ਬਣਤਰ sshkey *, ਬਣਤਰ sshbuf *);
ਪੂਰਨ		 sshkey_write(ਅਚਲ ਬਣਤਰ sshkey *, FILE *);
ਪੂਰਨ		 sshkey_read(ਬਣਤਰ sshkey *, ਅੱਖਰ **);
u_int		 sshkey_ਮਾਪ(ਅਚਲ ਬਣਤਰ sshkey *);

ਪੂਰਨ		 sshkey_generate(ਪੂਰਨ type, u_int ਬਿੱਟ, ਬਣਤਰ sshkey **keyp);
ਪੂਰਨ		 sshkey_from_ਨਿੱਜੀ(ਅਚਲ ਬਣਤਰ sshkey *, ਬਣਤਰ sshkey **);

ਪੂਰਨ		 sshkey_is_shielded(ਬਣਤਰ sshkey *);
ਪੂਰਨ		 sshkey_shield_ਨਿੱਜੀ(ਬਣਤਰ sshkey *);
ਪੂਰਨ		 sshkey_unshield_ਨਿੱਜੀ(ਬਣਤਰ sshkey *);

ਪੂਰਨ	 sshkey_type_from_name(ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 sshkey_type_from_shortname(ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 sshkey_is_cert(ਅਚਲ ਬਣਤਰ sshkey *);
ਪੂਰਨ	 sshkey_is_sk(ਅਚਲ ਬਣਤਰ sshkey *);
ਪੂਰਨ	 sshkey_type_is_cert(ਪੂਰਨ);
ਪੂਰਨ	 sshkey_type_plain(ਪੂਰਨ);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
ਪੂਰਨ	 sshkey_ਮੇਲ_keyname_ਮੰਜ਼ਿਲ_sigalgs(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

ਪੂਰਨ	 sshkey_ਮੰਜ਼ਿਲ_certified(ਬਣਤਰ sshkey *);
ਪੂਰਨ	 sshkey_drop_cert(ਬਣਤਰ sshkey *);
ਪੂਰਨ	 sshkey_cert_copy(ਅਚਲ ਬਣਤਰ sshkey *, ਬਣਤਰ sshkey *);
ਪੂਰਨ	 sshkey_cert_check_authority(ਅਚਲ ਬਣਤਰ sshkey *, ਪੂਰਨ, ਪੂਰਨ,
    uint64_t, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ **);
ਪੂਰਨ	 sshkey_cert_check_authority_now(ਅਚਲ ਬਣਤਰ sshkey *, ਪੂਰਨ, ਪੂਰਨ,
    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ **);
ਪੂਰਨ	 sshkey_cert_check_host(ਅਚਲ ਬਣਤਰ sshkey *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ **);
ਮਾਪ_t	 sshkey_format_cert_validity(ਅਚਲ ਬਣਤਰ sshkey_cert *,
    ਅੱਖਰ *, ਮਾਪ_t) __attribute__((__bounded__(__string__, 2, 3)));
ਪੂਰਨ	 sshkey_check_cert_sigtype(ਅਚਲ ਬਣਤਰ sshkey *, ਅਚਲ ਅੱਖਰ *);

ਪੂਰਨ	 sshkey_certify(ਬਣਤਰ sshkey *, ਬਣਤਰ sshkey *,
    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਪੂਰਨ sshkey_certify_signer(ਬਣਤਰ sshkey *, u_char **, ਮਾਪ_t *,
    ਅਚਲ u_char *, ਮਾਪ_t, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
    u_int, ਖਾਲੀ *);
ਪੂਰਨ	 sshkey_certify_custom(ਬਣਤਰ sshkey *, ਬਣਤਰ sshkey *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, sshkey_certify_signer *, ਖਾਲੀ *);

ਪੂਰਨ		 sshkey_ecdsa_nid_from_name(ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ		 sshkey_ਵਕਰ_name_ਮੰਜ਼ਿਲ_nid(ਅਚਲ ਅੱਖਰ *);
ਅਚਲ ਅੱਖਰ *	 sshkey_ਵਕਰ_nid_ਮੰਜ਼ਿਲ_name(ਪੂਰਨ);
u_int		 sshkey_ਵਕਰ_nid_ਮੰਜ਼ਿਲ_ਬਿੱਟ(ਪੂਰਨ);
ਪੂਰਨ		 sshkey_ecdsa_ਬਿੱਟ_ਮੰਜ਼ਿਲ_nid(ਪੂਰਨ);
ਪੂਰਨ		 sshkey_ecdsa_ਕੁੰਜੀ_ਮੰਜ਼ਿਲ_nid(ਅਚਲ EC_ਕੁੰਜੀ *);
ਪੂਰਨ		 sshkey_ecdsa_pkey_ਮੰਜ਼ਿਲ_nid(EVP_PKEY *);
ਪੂਰਨ		 sshkey_ec_nid_ਮੰਜ਼ਿਲ_hash_alg(ਪੂਰਨ nid);
ਪੂਰਨ		 sshkey_ec_validate_ਜਨਤਕ(ਅਚਲ EC_ਸਮੂਹ *, ਅਚਲ EC_ਬਿੰਦੂ *);
ਪੂਰਨ		 sshkey_ec_validate_ਨਿੱਜੀ(ਅਚਲ EC_ਕੁੰਜੀ *);
ਅਚਲ ਅੱਖਰ	*sshkey_ssh_name(ਅਚਲ ਬਣਤਰ sshkey *);
ਅਚਲ ਅੱਖਰ	*sshkey_ssh_name_plain(ਅਚਲ ਬਣਤਰ sshkey *);
ਪੂਰਨ		 sshkey_ਨਾਂ_valid2(ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ, ਪੂਰਨ);
ਅੱਖਰ		*sshkey_alg_list(ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ, ਅੱਖਰ);

ਪੂਰਨ	 sshkey_from_blob(ਅਚਲ u_char *, ਮਾਪ_t, ਬਣਤਰ sshkey **);
ਪੂਰਨ	 sshkey_fromb(ਬਣਤਰ sshbuf *, ਬਣਤਰ sshkey **);
ਪੂਰਨ	 sshkey_fromb_allowlist(ਬਣਤਰ sshbuf *, ਬਣਤਰ sshkey **,
    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 sshkey_froms(ਬਣਤਰ sshbuf *, ਬਣਤਰ sshkey **);
ਪੂਰਨ	 sshkey_ਮੰਜ਼ਿਲ_blob(ਅਚਲ ਬਣਤਰ sshkey *, u_char **, ਮਾਪ_t *);
ਪੂਰਨ	 sshkey_ਮੰਜ਼ਿਲ_base64(ਅਚਲ ਬਣਤਰ sshkey *, ਅੱਖਰ **);
ਪੂਰਨ	 sshkey_putb(ਅਚਲ ਬਣਤਰ sshkey *, ਬਣਤਰ sshbuf *);
ਪੂਰਨ	 sshkey_puts(ਅਚਲ ਬਣਤਰ sshkey *, ਬਣਤਰ sshbuf *);
ਪੂਰਨ	 sshkey_plain_ਮੰਜ਼ਿਲ_blob(ਅਚਲ ਬਣਤਰ sshkey *, u_char **, ਮਾਪ_t *);
ਪੂਰਨ	 sshkey_putb_plain(ਅਚਲ ਬਣਤਰ sshkey *, ਬਣਤਰ sshbuf *);
ਪੂਰਨ	 sshkey_puts_plain(ਅਚਲ ਬਣਤਰ sshkey *, ਬਣਤਰ sshbuf *);

ਪੂਰਨ	 sshkey_sign(ਬਣਤਰ sshkey *, u_char **, ਮਾਪ_t *,
    ਅਚਲ u_char *, ਮਾਪ_t, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, u_int);
ਪੂਰਨ	 sshkey_verify(ਅਚਲ ਬਣਤਰ sshkey *, ਅਚਲ u_char *, ਮਾਪ_t,
    ਅਚਲ u_char *, ਮਾਪ_t, ਅਚਲ ਅੱਖਰ *, u_int, ਬਣਤਰ sshkey_sig_details **);
ਪੂਰਨ	 sshkey_check_sigtype(ਅਚਲ u_char *, ਮਾਪ_t, ਅਚਲ ਅੱਖਰ *);
ਅਚਲ ਅੱਖਰ *sshkey_sigalg_by_name(ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 sshkey_get_sigtype(ਅਚਲ u_char *, ਮਾਪ_t, ਅੱਖਰ **);

/* Signing and verification backend for libcrypto-backed keys */
ਪੂਰਨ	sshkey_pkey_digest_sign(EVP_PKEY*, ਪੂਰਨ, u_char **,
    ਮਾਪ_t *, ਅਚਲ u_char *, ਮਾਪ_t);
ਪੂਰਨ	sshkey_pkey_digest_verify(EVP_PKEY *, ਪੂਰਨ, ਅਚਲ u_char *,
    ਮਾਪ_t, u_char *, ਮਾਪ_t);

/* for debug */
ਖਾਲੀ	sshkey_dump_ec_ਬਿੰਦੂ(ਅਚਲ EC_ਸਮੂਹ *, ਅਚਲ EC_ਬਿੰਦੂ *);
ਖਾਲੀ	sshkey_dump_ec_ਕੁੰਜੀ(ਅਚਲ EC_ਕੁੰਜੀ *);

/* private key parsing and serialisation */
ਪੂਰਨ	sshkey_ਨਿੱਜੀ_serialize(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *buf);
ਪੂਰਨ	sshkey_ਨਿੱਜੀ_deserialize(ਬਣਤਰ sshbuf *buf,  ਬਣਤਰ sshkey **keyp);

/* private key file format parsing and serialisation */
ਪੂਰਨ	sshkey_ਨਿੱਜੀ_ਮੰਜ਼ਿਲ_fileblob(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *blob,
    ਅਚਲ ਅੱਖਰ *passphrase, ਅਚਲ ਅੱਖਰ *comment,
    ਪੂਰਨ format, ਅਚਲ ਅੱਖਰ *openssh_format_cipher, ਪੂਰਨ openssh_format_ਗੇੜ);
ਪੂਰਨ	sshkey_parse_ਨਿੱਜੀ_fileblob(ਬਣਤਰ sshbuf *ਬਫਰ,
    ਅਚਲ ਅੱਖਰ *passphrase, ਬਣਤਰ sshkey **keyp, ਅੱਖਰ **commentp);
ਪੂਰਨ	sshkey_parse_ਨਿੱਜੀ_fileblob_type(ਬਣਤਰ sshbuf *blob, ਪੂਰਨ type,
    ਅਚਲ ਅੱਖਰ *passphrase, ਬਣਤਰ sshkey **keyp, ਅੱਖਰ **commentp);
ਪੂਰਨ	sshkey_parse_pubkey_from_ਨਿੱਜੀ_fileblob_type(ਬਣਤਰ sshbuf *blob,
    ਪੂਰਨ type, ਬਣਤਰ sshkey **pubkeyp);

ਪੂਰਨ sshkey_check_rsa_ਲੰਮਾਈ(ਅਚਲ ਬਣਤਰ sshkey *, ਪੂਰਨ);
ਪੂਰਨ	ssh_rsa_hash_id_from_keyname(ਅਚਲ ਅੱਖਰ *);
ਅਚਲ ਅੱਖਰ *ssh_rsa_hash_alg_ident(ਪੂਰਨ);
ਪੂਰਨ	ssh_rsa_encode_store_sig(ਪੂਰਨ, ਅਚਲ u_char *, ਮਾਪ_t,
	    u_char **, ਮਾਪ_t *);
ਪੂਰਨ	ssh_ecdsa_encode_store_sig(ਅਚਲ ਬਣਤਰ sshkey *,
	    ਅਚਲ BIGNUM *, ਅਚਲ BIGNUM *, u_char **, ਮਾਪ_t *);
ਪੂਰਨ	ssh_ed25519_encode_store_sig(ਅਚਲ u_char *, ਮਾਪ_t,
	    u_char **, ਮਾਪ_t *);
/* XXX should be internal, but used by ssh-keygen */
ਪੂਰਨ ssh_rsa_complete_crt_parameters(ਅਚਲ BIGNUM *, ਅਚਲ BIGNUM *,
    ਅਚਲ BIGNUM *, ਅਚਲ BIGNUM *, BIGNUM **, BIGNUM **);

ਖਾਲੀ	 sshkey_sig_details_free(ਬਣਤਰ sshkey_sig_details *);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਪੂਰਨ	sshkey_ecdsa_fixup_ਸਮੂਹ(EVP_PKEY *k); /* ssh-ecdsa.c */
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSHKEY_ਅੰਦਰੂਨੀ
ਪੂਰਨ	sshkey_sk_fields_equal(ਅਚਲ ਬਣਤਰ sshkey *a, ਅਚਲ ਬਣਤਰ sshkey *b);
ਖਾਲੀ	sshkey_sk_cleanup(ਬਣਤਰ sshkey *k);
ਪੂਰਨ	sshkey_serialize_sk(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b);
ਪੂਰਨ	sshkey_copy_ਜਨਤਕ_sk(ਅਚਲ ਬਣਤਰ sshkey *from, ਬਣਤਰ sshkey *ਮੰਜ਼ਿਲ);
ਪੂਰਨ	sshkey_deserialize_sk(ਬਣਤਰ sshbuf *b, ਬਣਤਰ sshkey *ਕੁੰਜੀ);
ਪੂਰਨ	sshkey_serialize_ਨਿੱਜੀ_sk(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਬਣਤਰ sshbuf *buf);
ਪੂਰਨ	sshkey_ਨਿੱਜੀ_deserialize_sk(ਬਣਤਰ sshbuf *buf, ਬਣਤਰ sshkey *k);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਪੂਰਨ	check_rsa_ਲੰਮਾਈ(ਅਚਲ RSA *rsa); /* XXX remove */
#ਜੇ_ਅੰਤ
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ RSA
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ EC_ਕੁੰਜੀ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ EC_ਸਮੂਹ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ EC_ਬਿੰਦੂ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ EVP_PKEY
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

#ਜੇ_ਅੰਤ /* SSHKEY_H */
