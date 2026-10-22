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

#अन्तर्भाव <sys/types.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/rsa.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/ecdsa.h>
#अन्तर्भाव <openssl/evp.h>
#define SSH_OPENSSL_VERSION OpenSSL_version(OPENSSL_VERSION)
#अन्यथा /* OPENSSL */
#define BIGNUM		शून्य
#define RSA		शून्य
#define EC_साँचो		शून्य
#define EC_GROUP	शून्य
#define EC_POINT	शून्य
#define EVP_PKEY	शून्य
#define SSH_OPENSSL_VERSION "without OpenSSL"
#endif /* WITH_OPENSSL */

#define SSH_RSA_MINIMUM_MODULUS_SIZE	1024
#define SSH_साँचो_MAX_SIGN_DATA_SIZE	(1 << 20)

संरचना sshbuf;

/* Key types */
गणना sshkey_types {
	साँचो_RSA,
	साँचो_ECDSA,
	साँचो_ED25519,
	साँचो_RSA_CERT,
	साँचो_ECDSA_CERT,
	साँचो_ED25519_CERT,
	साँचो_ECDSA_SK,
	साँचो_ECDSA_SK_CERT,
	साँचो_ED25519_SK,
	साँचो_ED25519_SK_CERT,
	साँचो_MLDSA44_ED25519,
	साँचो_MLDSA44_ED25519_CERT,
	साँचो_UNSPEC
};

/* Default fingerprint hash */
#define SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
गणना sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
गणना sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
गणना sshkey_private_format {
	SSHKEY_PRIVATE_OPENSSH = 0,
	SSHKEY_PRIVATE_PEM = 1,
	SSHKEY_PRIVATE_PKCS8 = 2,
};

/* key is stored in external hardware */
#define SSHKEY_FLAG_EXT		0x0001

#define SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
संरचना sshkey_cert {
	संरचना sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	वर्ण		*साँचो_id;
	u_int		 nprincipals;
	वर्ण		**principals;
	uint64_t	 valid_after, valid_before;
	संरचना sshbuf	*critical;
	संरचना sshbuf	*extensions;
	संरचना sshkey	*signature_साँचो;
	वर्ण		*signature_type;
};

/* XXX opacify? */
संरचना sshkey {
	पूर्णाङ्क	 type;
	पूर्णाङ्क	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	पूर्णाङ्क	 ecdsa_nid;	/* NID of curve */
	/* libcrypto-backed keys */
	EVP_PKEY *pkey;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_MLDSA44_ED25519 */
	u_char	*mldsa_ed25519_sk;
	u_char	*mldsa_ed25519_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	वर्ण	*sk_application;
	uint8_t	sk_flags;
	संरचना sshbuf *sk_साँचो_handle;
	संरचना sshbuf *sk_reserved;
	/* Certificates */
	संरचना sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_private;
	माप_प्रकार	shielded_len;
	u_char	*shield_prekey;
	माप_प्रकार	shield_prekey_len;
};

#define	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#define	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
संरचना sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

संरचना sshkey_impl_funcs {
	u_int (*size)(अचर संरचना sshkey *);	/* optional */
	पूर्णाङ्क (*alloc)(संरचना sshkey *);		/* optional */
	शून्य (*cleanup)(संरचना sshkey *);	/* optional */
	पूर्णाङ्क (*equal)(अचर संरचना sshkey *, अचर संरचना sshkey *);
	पूर्णाङ्क (*serialize_public)(अचर संरचना sshkey *, संरचना sshbuf *,
	    गणना sshkey_serialize_rep);
	पूर्णाङ्क (*deserialize_public)(अचर वर्ण *, संरचना sshbuf *,
	    संरचना sshkey *);
	पूर्णाङ्क (*serialize_private)(अचर संरचना sshkey *, संरचना sshbuf *,
	    गणना sshkey_serialize_rep);
	पूर्णाङ्क (*deserialize_private)(अचर वर्ण *, संरचना sshbuf *,
	    संरचना sshkey *);
	पूर्णाङ्क (*generate)(संरचना sshkey *, पूर्णाङ्क);	/* optional */
	पूर्णाङ्क (*copy_public)(अचर संरचना sshkey *, संरचना sshkey *);
	पूर्णाङ्क (*sign)(संरचना sshkey *, u_char **, माप_प्रकार *,
	    अचर u_char *, माप_प्रकार, अचर वर्ण *,
	    अचर वर्ण *, अचर वर्ण *, u_int); /* optional */
	पूर्णाङ्क (*verify)(अचर संरचना sshkey *, अचर u_char *, माप_प्रकार,
	    अचर u_char *, माप_प्रकार, अचर वर्ण *, u_int,
	    संरचना sshkey_sig_details **);
};

संरचना sshkey_impl {
	अचर वर्ण *name;
	अचर वर्ण *shortname;
	अचर वर्ण *sigalg;
	पूर्णाङ्क type;
	पूर्णाङ्क nid;
	पूर्णाङ्क cert;
	पूर्णाङ्क sigonly;
	पूर्णाङ्क keybits;
	अचर संरचना sshkey_impl_funcs *funcs;
};

संरचना sshkey	*sshkey_new(पूर्णाङ्क);
शून्य		 sshkey_free(संरचना sshkey *);
पूर्णाङ्क		 sshkey_equal_public(अचर संरचना sshkey *,
    अचर संरचना sshkey *);
पूर्णाङ्क		 sshkey_equal(अचर संरचना sshkey *, अचर संरचना sshkey *);
वर्ण		*sshkey_fingerprint(अचर संरचना sshkey *,
    पूर्णाङ्क, गणना sshkey_fp_rep);
पूर्णाङ्क		 sshkey_fingerprint_raw(अचर संरचना sshkey *k,
    पूर्णाङ्क, u_char **retp, माप_प्रकार *lenp);
अचर वर्ण	*sshkey_type(अचर संरचना sshkey *);
अचर वर्ण	*sshkey_cert_type(अचर संरचना sshkey *);
पूर्णाङ्क		 sshkey_format_text(अचर संरचना sshkey *, संरचना sshbuf *);
पूर्णाङ्क		 sshkey_write(अचर संरचना sshkey *, खाता *);
पूर्णाङ्क		 sshkey_read(संरचना sshkey *, वर्ण **);
u_int		 sshkey_size(अचर संरचना sshkey *);

पूर्णाङ्क		 sshkey_generate(पूर्णाङ्क type, u_int bits, संरचना sshkey **keyp);
पूर्णाङ्क		 sshkey_from_private(अचर संरचना sshkey *, संरचना sshkey **);

पूर्णाङ्क		 sshkey_is_shielded(संरचना sshkey *);
पूर्णाङ्क		 sshkey_shield_private(संरचना sshkey *);
पूर्णाङ्क		 sshkey_unshield_private(संरचना sshkey *);

पूर्णाङ्क	 sshkey_type_from_name(अचर वर्ण *);
पूर्णाङ्क	 sshkey_type_from_shortname(अचर वर्ण *);
पूर्णाङ्क	 sshkey_is_cert(अचर संरचना sshkey *);
पूर्णाङ्क	 sshkey_is_sk(अचर संरचना sshkey *);
पूर्णाङ्क	 sshkey_type_is_cert(पूर्णाङ्क);
पूर्णाङ्क	 sshkey_type_plain(पूर्णाङ्क);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
पूर्णाङ्क	 sshkey_match_keyname_to_sigalgs(अचर वर्ण *, अचर वर्ण *);

पूर्णाङ्क	 sshkey_to_certified(संरचना sshkey *);
पूर्णाङ्क	 sshkey_drop_cert(संरचना sshkey *);
पूर्णाङ्क	 sshkey_cert_copy(अचर संरचना sshkey *, संरचना sshkey *);
पूर्णाङ्क	 sshkey_cert_check_authority(अचर संरचना sshkey *, पूर्णाङ्क, पूर्णाङ्क,
    uint64_t, अचर वर्ण *, अचर वर्ण **);
पूर्णाङ्क	 sshkey_cert_check_authority_now(अचर संरचना sshkey *, पूर्णाङ्क, पूर्णाङ्क,
    अचर वर्ण *, अचर वर्ण **);
पूर्णाङ्क	 sshkey_cert_check_host(अचर संरचना sshkey *, अचर वर्ण *,
    अचर वर्ण *, अचर वर्ण **);
माप_प्रकार	 sshkey_format_cert_validity(अचर संरचना sshkey_cert *,
    वर्ण *, माप_प्रकार) __attribute__((__bounded__(__string__, 2, 3)));
पूर्णाङ्क	 sshkey_check_cert_sigtype(अचर संरचना sshkey *, अचर वर्ण *);

पूर्णाङ्क	 sshkey_certify(संरचना sshkey *, संरचना sshkey *,
    अचर वर्ण *, अचर वर्ण *, अचर वर्ण *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
प्रकारनिर्देश पूर्णाङ्क sshkey_certify_signer(संरचना sshkey *, u_char **, माप_प्रकार *,
    अचर u_char *, माप_प्रकार, अचर वर्ण *, अचर वर्ण *, अचर वर्ण *,
    u_int, शून्य *);
पूर्णाङ्क	 sshkey_certify_custom(संरचना sshkey *, संरचना sshkey *, अचर वर्ण *,
    अचर वर्ण *, अचर वर्ण *, sshkey_certify_signer *, शून्य *);

पूर्णाङ्क		 sshkey_ecdsa_nid_from_name(अचर वर्ण *);
पूर्णाङ्क		 sshkey_curve_name_to_nid(अचर वर्ण *);
अचर वर्ण *	 sshkey_curve_nid_to_name(पूर्णाङ्क);
u_int		 sshkey_curve_nid_to_bits(पूर्णाङ्क);
पूर्णाङ्क		 sshkey_ecdsa_bits_to_nid(पूर्णाङ्क);
पूर्णाङ्क		 sshkey_ecdsa_साँचो_to_nid(अचर EC_साँचो *);
पूर्णाङ्क		 sshkey_ecdsa_pkey_to_nid(EVP_PKEY *);
पूर्णाङ्क		 sshkey_ec_nid_to_hash_alg(पूर्णाङ्क nid);
पूर्णाङ्क		 sshkey_ec_validate_public(अचर EC_GROUP *, अचर EC_POINT *);
पूर्णाङ्क		 sshkey_ec_validate_private(अचर EC_साँचो *);
अचर वर्ण	*sshkey_ssh_name(अचर संरचना sshkey *);
अचर वर्ण	*sshkey_ssh_name_plain(अचर संरचना sshkey *);
पूर्णाङ्क		 sshkey_names_valid2(अचर वर्ण *, पूर्णाङ्क, पूर्णाङ्क);
वर्ण		*sshkey_alg_list(पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क, वर्ण);

पूर्णाङ्क	 sshkey_from_blob(अचर u_char *, माप_प्रकार, संरचना sshkey **);
पूर्णाङ्क	 sshkey_fromb(संरचना sshbuf *, संरचना sshkey **);
पूर्णाङ्क	 sshkey_fromb_allowlist(संरचना sshbuf *, संरचना sshkey **,
    अचर वर्ण *, अचर वर्ण *);
पूर्णाङ्क	 sshkey_froms(संरचना sshbuf *, संरचना sshkey **);
पूर्णाङ्क	 sshkey_to_blob(अचर संरचना sshkey *, u_char **, माप_प्रकार *);
पूर्णाङ्क	 sshkey_to_base64(अचर संरचना sshkey *, वर्ण **);
पूर्णाङ्क	 sshkey_putb(अचर संरचना sshkey *, संरचना sshbuf *);
पूर्णाङ्क	 sshkey_puts(अचर संरचना sshkey *, संरचना sshbuf *);
पूर्णाङ्क	 sshkey_plain_to_blob(अचर संरचना sshkey *, u_char **, माप_प्रकार *);
पूर्णाङ्क	 sshkey_putb_plain(अचर संरचना sshkey *, संरचना sshbuf *);
पूर्णाङ्क	 sshkey_puts_plain(अचर संरचना sshkey *, संरचना sshbuf *);

पूर्णाङ्क	 sshkey_sign(संरचना sshkey *, u_char **, माप_प्रकार *,
    अचर u_char *, माप_प्रकार, अचर वर्ण *, अचर वर्ण *, अचर वर्ण *, u_int);
पूर्णाङ्क	 sshkey_verify(अचर संरचना sshkey *, अचर u_char *, माप_प्रकार,
    अचर u_char *, माप_प्रकार, अचर वर्ण *, u_int, संरचना sshkey_sig_details **);
पूर्णाङ्क	 sshkey_check_sigtype(अचर u_char *, माप_प्रकार, अचर वर्ण *);
अचर वर्ण *sshkey_sigalg_by_name(अचर वर्ण *);
पूर्णाङ्क	 sshkey_get_sigtype(अचर u_char *, माप_प्रकार, वर्ण **);

/* Signing and verification backend for libcrypto-backed keys */
पूर्णाङ्क	sshkey_pkey_digest_sign(EVP_PKEY*, पूर्णाङ्क, u_char **,
    माप_प्रकार *, अचर u_char *, माप_प्रकार);
पूर्णाङ्क	sshkey_pkey_digest_verify(EVP_PKEY *, पूर्णाङ्क, अचर u_char *,
    माप_प्रकार, u_char *, माप_प्रकार);

/* for debug */
शून्य	sshkey_dump_ec_point(अचर EC_GROUP *, अचर EC_POINT *);
शून्य	sshkey_dump_ec_साँचो(अचर EC_साँचो *);

/* private key parsing and serialisation */
पूर्णाङ्क	sshkey_private_serialize(संरचना sshkey *साँचो, संरचना sshbuf *buf);
पूर्णाङ्क	sshkey_private_deserialize(संरचना sshbuf *buf,  संरचना sshkey **keyp);

/* private key file format parsing and serialisation */
पूर्णाङ्क	sshkey_private_to_fileblob(संरचना sshkey *साँचो, संरचना sshbuf *blob,
    अचर वर्ण *passphrase, अचर वर्ण *comment,
    पूर्णाङ्क format, अचर वर्ण *openssh_format_cipher, पूर्णाङ्क openssh_format_rounds);
पूर्णाङ्क	sshkey_parse_private_fileblob(संरचना sshbuf *buffer,
    अचर वर्ण *passphrase, संरचना sshkey **keyp, वर्ण **commentp);
पूर्णाङ्क	sshkey_parse_private_fileblob_type(संरचना sshbuf *blob, पूर्णाङ्क type,
    अचर वर्ण *passphrase, संरचना sshkey **keyp, वर्ण **commentp);
पूर्णाङ्क	sshkey_parse_pubkey_from_private_fileblob_type(संरचना sshbuf *blob,
    पूर्णाङ्क type, संरचना sshkey **pubkeyp);

पूर्णाङ्क sshkey_check_rsa_length(अचर संरचना sshkey *, पूर्णाङ्क);
पूर्णाङ्क	ssh_rsa_hash_id_from_keyname(अचर वर्ण *);
अचर वर्ण *ssh_rsa_hash_alg_ident(पूर्णाङ्क);
पूर्णाङ्क	ssh_rsa_encode_store_sig(पूर्णाङ्क, अचर u_char *, माप_प्रकार,
	    u_char **, माप_प्रकार *);
पूर्णाङ्क	ssh_ecdsa_encode_store_sig(अचर संरचना sshkey *,
	    अचर BIGNUM *, अचर BIGNUM *, u_char **, माप_प्रकार *);
पूर्णाङ्क	ssh_ed25519_encode_store_sig(अचर u_char *, माप_प्रकार,
	    u_char **, माप_प्रकार *);
/* XXX should be internal, but used by ssh-keygen */
पूर्णाङ्क ssh_rsa_complete_crt_parameters(अचर BIGNUM *, अचर BIGNUM *,
    अचर BIGNUM *, अचर BIGNUM *, BIGNUM **, BIGNUM **);

शून्य	 sshkey_sig_details_free(संरचना sshkey_sig_details *);

#ifdef WITH_OPENSSL
पूर्णाङ्क	sshkey_ecdsa_fixup_group(EVP_PKEY *k); /* ssh-ecdsa.c */
#endif

#ifdef SSHKEY_INTERNAL
पूर्णाङ्क	sshkey_sk_fields_equal(अचर संरचना sshkey *a, अचर संरचना sshkey *b);
शून्य	sshkey_sk_cleanup(संरचना sshkey *k);
पूर्णाङ्क	sshkey_serialize_sk(अचर संरचना sshkey *साँचो, संरचना sshbuf *b);
पूर्णाङ्क	sshkey_copy_public_sk(अचर संरचना sshkey *from, संरचना sshkey *to);
पूर्णाङ्क	sshkey_deserialize_sk(संरचना sshbuf *b, संरचना sshkey *साँचो);
पूर्णाङ्क	sshkey_serialize_private_sk(अचर संरचना sshkey *साँचो,
    संरचना sshbuf *buf);
पूर्णाङ्क	sshkey_private_deserialize_sk(संरचना sshbuf *buf, संरचना sshkey *k);
#ifdef WITH_OPENSSL
पूर्णाङ्क	check_rsa_length(अचर RSA *rsa); /* XXX remove */
#endif
#endif

#ifndef WITH_OPENSSL
#undef RSA
#undef EC_साँचो
#undef EC_GROUP
#undef EC_POINT
#undef EVP_PKEY
#endif /* WITH_OPENSSL */

#endif /* SSHKEY_H */
