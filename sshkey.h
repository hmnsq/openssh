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
#నిర్వచితం_కాకపోతే SSHKEY_H
#నిర్వచించు SSHKEY_H

#అన్తర్భావ <sys/types.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/rsa.h>
#అన్తర్భావ <openssl/ec.h>
#అన్తర్భావ <openssl/ecdsa.h>
#అన్తర్భావ <openssl/evp.h>
#నిర్వచించు SSH_OPENSSL_సంస్కరణ Open_SSL_సంస్కరణ(OPENSSL_సంస్కరణ)
#లేకపోతే /* OPENSSL */
#నిర్వచించు BIGNUM		శూన్య
#నిర్వచించు RSA		శూన్య
#నిర్వచించు EC_కీలకం		శూన్య
#నిర్వచించు EC_సమూహం	శూన్య
#నిర్వచించు EC_బిందువు	శూన్య
#నిర్వచించు EVP_PKEY	శూన్య
#నిర్వచించు SSH_OPENSSL_సంస్కరణ "without OpenSSL"
#అయితే_ముగింపు /* WITH_OPENSSL */

#నిర్వచించు SSH_RSA_MINIMUM_MODULUS_కొలత	1024
#నిర్వచించు SSH_కీలకం_MAX_SIGN_దత్తాంశం_కొలత	(1 << 20)

నిర్మాణం sshbuf;

/* Key types */
గణన sshkey_types {
	కీలకం_RSA,
	కీలకం_ECDSA,
	కీలకం_ED25519,
	కీలకం_RSA_CERT,
	కీలకం_ECDSA_CERT,
	కీలకం_ED25519_CERT,
	కీలకం_ECDSA_SK,
	కీలకం_ECDSA_SK_CERT,
	కీలకం_ED25519_SK,
	కీలకం_ED25519_SK_CERT,
	కీలకం_MLDSA44_ED25519,
	కీలకం_MLDSA44_ED25519_CERT,
	కీలకం_UNSPEC
};

/* Default fingerprint hash */
#నిర్వచించు SSH_FP_HASH_DEFAULT	SSH_DIGEST_SHA256

/* Fingerprint representation formats */
గణన sshkey_fp_rep {
	SSH_FP_DEFAULT = 0,
	SSH_FP_HEX,
	SSH_FP_BASE64,
	SSH_FP_BUBBLEBABBLE,
	SSH_FP_RANDOMART
};

/* Private key serialisation formats, used on the wire */
గణన sshkey_serialize_rep {
	SSHKEY_SERIALIZE_DEFAULT = 0,
};

/* Private key disk formats */
గణన sshkey_వ్యక్తిగత_format {
	SSHKEY_వ్యక్తిగత_OPENSSH = 0,
	SSHKEY_వ్యక్తిగత_PEM = 1,
	SSHKEY_వ్యక్తిగత_PKCS8 = 2,
};

/* key is stored in external hardware */
#నిర్వచించు SSHKEY_FLAG_EXT		0x0001

#నిర్వచించు SSHKEY_CERT_MAX_PRINCIPALS	256
/* XXX opacify? */
నిర్మాణం sshkey_cert {
	నిర్మాణం sshbuf	*certblob; /* Kept around for use on wire */
	u_int		 type; /* SSH2_CERT_TYPE_USER or SSH2_CERT_TYPE_HOST */
	uint64_t	 serial;
	అక్షరం		*కీలకం_id;
	u_int		 nprincipals;
	అక్షరం		**principals;
	uint64_t	 valid_after, valid_before;
	నిర్మాణం sshbuf	*critical;
	నిర్మాణం sshbuf	*extensions;
	నిర్మాణం sshkey	*signature_కీలకం;
	అక్షరం		*signature_type;
};

/* XXX opacify? */
నిర్మాణం sshkey {
	పూర్ణాంకం	 type;
	పూర్ణాంకం	 flags;
	/* KEY_ECDSA and KEY_ECDSA_SK */
	పూర్ణాంకం	 ecdsa_nid;	/* NID of curve */
	/* libcrypto-backed keys */
	EVP_PKEY *pkey;
	/* KEY_ED25519 and KEY_ED25519_SK */
	u_char	*ed25519_sk;
	u_char	*ed25519_pk;
	/* KEY_MLDSA44_ED25519 */
	u_char	*mldsa_ed25519_sk;
	u_char	*mldsa_ed25519_pk;
	/* KEY_ECDSA_SK and KEY_ED25519_SK */
	అక్షరం	*sk_application;
	uint8_t	sk_flags;
	నిర్మాణం sshbuf *sk_కీలకం_handle;
	నిర్మాణం sshbuf *sk_reserved;
	/* Certificates */
	నిర్మాణం sshkey_cert *cert;
	/* Private key shielding */
	u_char	*shielded_వ్యక్తిగత;
	కొలత_t	shielded_len;
	u_char	*shield_prekey;
	కొలత_t	shield_prekey_len;
};

#నిర్వచించు	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#నిర్వచించు	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES

/* Additional fields contained in signature */
నిర్మాణం sshkey_sig_details {
	uint32_t sk_counter;	/* U2F signature counter */
	uint8_t sk_flags;	/* U2F signature flags; see ssh-sk.h */
};

నిర్మాణం sshkey_impl_funcs {
	u_int (*కొలత)(స్థిరరాశి నిర్మాణం sshkey *);	/* optional */
	పూర్ణాంకం (*alloc)(నిర్మాణం sshkey *);		/* optional */
	శూన్య (*cleanup)(నిర్మాణం sshkey *);	/* optional */
	పూర్ణాంకం (*equal)(స్థిరరాశి నిర్మాణం sshkey *, స్థిరరాశి నిర్మాణం sshkey *);
	పూర్ణాంకం (*serialize_ప్రజా)(స్థిరరాశి నిర్మాణం sshkey *, నిర్మాణం sshbuf *,
	    గణన sshkey_serialize_rep);
	పూర్ణాంకం (*deserialize_ప్రజా)(స్థిరరాశి అక్షరం *, నిర్మాణం sshbuf *,
	    నిర్మాణం sshkey *);
	పూర్ణాంకం (*serialize_వ్యక్తిగత)(స్థిరరాశి నిర్మాణం sshkey *, నిర్మాణం sshbuf *,
	    గణన sshkey_serialize_rep);
	పూర్ణాంకం (*deserialize_వ్యక్తిగత)(స్థిరరాశి అక్షరం *, నిర్మాణం sshbuf *,
	    నిర్మాణం sshkey *);
	పూర్ణాంకం (*generate)(నిర్మాణం sshkey *, పూర్ణాంకం);	/* optional */
	పూర్ణాంకం (*copy_ప్రజా)(స్థిరరాశి నిర్మాణం sshkey *, నిర్మాణం sshkey *);
	పూర్ణాంకం (*sign)(నిర్మాణం sshkey *, u_char **, కొలత_t *,
	    స్థిరరాశి u_char *, కొలత_t, స్థిరరాశి అక్షరం *,
	    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, u_int); /* optional */
	పూర్ణాంకం (*verify)(స్థిరరాశి నిర్మాణం sshkey *, స్థిరరాశి u_char *, కొలత_t,
	    స్థిరరాశి u_char *, కొలత_t, స్థిరరాశి అక్షరం *, u_int,
	    నిర్మాణం sshkey_sig_details **);
};

నిర్మాణం sshkey_impl {
	స్థిరరాశి అక్షరం *name;
	స్థిరరాశి అక్షరం *shortname;
	స్థిరరాశి అక్షరం *sigalg;
	పూర్ణాంకం type;
	పూర్ణాంకం nid;
	పూర్ణాంకం cert;
	పూర్ణాంకం sigonly;
	పూర్ణాంకం keybits;
	స్థిరరాశి నిర్మాణం sshkey_impl_funcs *funcs;
};

నిర్మాణం sshkey	*sshkey_new(పూర్ణాంకం);
శూన్య		 sshkey_free(నిర్మాణం sshkey *);
పూర్ణాంకం		 sshkey_equal_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *,
    స్థిరరాశి నిర్మాణం sshkey *);
పూర్ణాంకం		 sshkey_equal(స్థిరరాశి నిర్మాణం sshkey *, స్థిరరాశి నిర్మాణం sshkey *);
అక్షరం		*sshkey_fingerprint(స్థిరరాశి నిర్మాణం sshkey *,
    పూర్ణాంకం, గణన sshkey_fp_rep);
పూర్ణాంకం		 sshkey_fingerprint_raw(స్థిరరాశి నిర్మాణం sshkey *k,
    పూర్ణాంకం, u_char **retp, కొలత_t *lenp);
స్థిరరాశి అక్షరం	*sshkey_type(స్థిరరాశి నిర్మాణం sshkey *);
స్థిరరాశి అక్షరం	*sshkey_cert_type(స్థిరరాశి నిర్మాణం sshkey *);
పూర్ణాంకం		 sshkey_format_పాఠ్యం(స్థిరరాశి నిర్మాణం sshkey *, నిర్మాణం sshbuf *);
పూర్ణాంకం		 sshkey_write(స్థిరరాశి నిర్మాణం sshkey *, FILE *);
పూర్ణాంకం		 sshkey_read(నిర్మాణం sshkey *, అక్షరం **);
u_int		 sshkey_కొలత(స్థిరరాశి నిర్మాణం sshkey *);

పూర్ణాంకం		 sshkey_generate(పూర్ణాంకం type, u_int బిట్లు, నిర్మాణం sshkey **keyp);
పూర్ణాంకం		 sshkey_from_వ్యక్తిగత(స్థిరరాశి నిర్మాణం sshkey *, నిర్మాణం sshkey **);

పూర్ణాంకం		 sshkey_is_shielded(నిర్మాణం sshkey *);
పూర్ణాంకం		 sshkey_shield_వ్యక్తిగత(నిర్మాణం sshkey *);
పూర్ణాంకం		 sshkey_unshield_వ్యక్తిగత(నిర్మాణం sshkey *);

పూర్ణాంకం	 sshkey_type_from_name(స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 sshkey_type_from_shortname(స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 sshkey_is_cert(స్థిరరాశి నిర్మాణం sshkey *);
పూర్ణాంకం	 sshkey_is_sk(స్థిరరాశి నిర్మాణం sshkey *);
పూర్ణాంకం	 sshkey_type_is_cert(పూర్ణాంకం);
పూర్ణాంకం	 sshkey_type_plain(పూర్ణాంకం);

/* Returns non-zero if key name match sigalgs pattern list. (handles RSA) */
పూర్ణాంకం	 sshkey_సరిపోలిక_keyname_గమ్యం_sigalgs(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

పూర్ణాంకం	 sshkey_గమ్యం_certified(నిర్మాణం sshkey *);
పూర్ణాంకం	 sshkey_drop_cert(నిర్మాణం sshkey *);
పూర్ణాంకం	 sshkey_cert_copy(స్థిరరాశి నిర్మాణం sshkey *, నిర్మాణం sshkey *);
పూర్ణాంకం	 sshkey_cert_check_authority(స్థిరరాశి నిర్మాణం sshkey *, పూర్ణాంకం, పూర్ణాంకం,
    uint64_t, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం **);
పూర్ణాంకం	 sshkey_cert_check_authority_now(స్థిరరాశి నిర్మాణం sshkey *, పూర్ణాంకం, పూర్ణాంకం,
    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం **);
పూర్ణాంకం	 sshkey_cert_check_host(స్థిరరాశి నిర్మాణం sshkey *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం **);
కొలత_t	 sshkey_format_cert_validity(స్థిరరాశి నిర్మాణం sshkey_cert *,
    అక్షరం *, కొలత_t) __attribute__((__bounded__(__string__, 2, 3)));
పూర్ణాంకం	 sshkey_check_cert_sigtype(స్థిరరాశి నిర్మాణం sshkey *, స్థిరరాశి అక్షరం *);

పూర్ణాంకం	 sshkey_certify(నిర్మాణం sshkey *, నిర్మాణం sshkey *,
    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
/* Variant allowing use of a custom signature function (e.g. for ssh-agent) */
రకనిర్వచనం పూర్ణాంకం sshkey_certify_signer(నిర్మాణం sshkey *, u_char **, కొలత_t *,
    స్థిరరాశి u_char *, కొలత_t, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
    u_int, శూన్య *);
పూర్ణాంకం	 sshkey_certify_custom(నిర్మాణం sshkey *, నిర్మాణం sshkey *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, sshkey_certify_signer *, శూన్య *);

పూర్ణాంకం		 sshkey_ecdsa_nid_from_name(స్థిరరాశి అక్షరం *);
పూర్ణాంకం		 sshkey_వక్రం_name_గమ్యం_nid(స్థిరరాశి అక్షరం *);
స్థిరరాశి అక్షరం *	 sshkey_వక్రం_nid_గమ్యం_name(పూర్ణాంకం);
u_int		 sshkey_వక్రం_nid_గమ్యం_బిట్లు(పూర్ణాంకం);
పూర్ణాంకం		 sshkey_ecdsa_బిట్లు_గమ్యం_nid(పూర్ణాంకం);
పూర్ణాంకం		 sshkey_ecdsa_కీలకం_గమ్యం_nid(స్థిరరాశి EC_కీలకం *);
పూర్ణాంకం		 sshkey_ecdsa_pkey_గమ్యం_nid(EVP_PKEY *);
పూర్ణాంకం		 sshkey_ec_nid_గమ్యం_hash_alg(పూర్ణాంకం nid);
పూర్ణాంకం		 sshkey_ec_validate_ప్రజా(స్థిరరాశి EC_సమూహం *, స్థిరరాశి EC_బిందువు *);
పూర్ణాంకం		 sshkey_ec_validate_వ్యక్తిగత(స్థిరరాశి EC_కీలకం *);
స్థిరరాశి అక్షరం	*sshkey_ssh_name(స్థిరరాశి నిర్మాణం sshkey *);
స్థిరరాశి అక్షరం	*sshkey_ssh_name_plain(స్థిరరాశి నిర్మాణం sshkey *);
పూర్ణాంకం		 sshkey_పేర్లు_valid2(స్థిరరాశి అక్షరం *, పూర్ణాంకం, పూర్ణాంకం);
అక్షరం		*sshkey_alg_list(పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం, అక్షరం);

పూర్ణాంకం	 sshkey_from_blob(స్థిరరాశి u_char *, కొలత_t, నిర్మాణం sshkey **);
పూర్ణాంకం	 sshkey_fromb(నిర్మాణం sshbuf *, నిర్మాణం sshkey **);
పూర్ణాంకం	 sshkey_fromb_allowlist(నిర్మాణం sshbuf *, నిర్మాణం sshkey **,
    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 sshkey_froms(నిర్మాణం sshbuf *, నిర్మాణం sshkey **);
పూర్ణాంకం	 sshkey_గమ్యం_blob(స్థిరరాశి నిర్మాణం sshkey *, u_char **, కొలత_t *);
పూర్ణాంకం	 sshkey_గమ్యం_base64(స్థిరరాశి నిర్మాణం sshkey *, అక్షరం **);
పూర్ణాంకం	 sshkey_putb(స్థిరరాశి నిర్మాణం sshkey *, నిర్మాణం sshbuf *);
పూర్ణాంకం	 sshkey_puts(స్థిరరాశి నిర్మాణం sshkey *, నిర్మాణం sshbuf *);
పూర్ణాంకం	 sshkey_plain_గమ్యం_blob(స్థిరరాశి నిర్మాణం sshkey *, u_char **, కొలత_t *);
పూర్ణాంకం	 sshkey_putb_plain(స్థిరరాశి నిర్మాణం sshkey *, నిర్మాణం sshbuf *);
పూర్ణాంకం	 sshkey_puts_plain(స్థిరరాశి నిర్మాణం sshkey *, నిర్మాణం sshbuf *);

పూర్ణాంకం	 sshkey_sign(నిర్మాణం sshkey *, u_char **, కొలత_t *,
    స్థిరరాశి u_char *, కొలత_t, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, u_int);
పూర్ణాంకం	 sshkey_verify(స్థిరరాశి నిర్మాణం sshkey *, స్థిరరాశి u_char *, కొలత_t,
    స్థిరరాశి u_char *, కొలత_t, స్థిరరాశి అక్షరం *, u_int, నిర్మాణం sshkey_sig_details **);
పూర్ణాంకం	 sshkey_check_sigtype(స్థిరరాశి u_char *, కొలత_t, స్థిరరాశి అక్షరం *);
స్థిరరాశి అక్షరం *sshkey_sigalg_by_name(స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 sshkey_get_sigtype(స్థిరరాశి u_char *, కొలత_t, అక్షరం **);

/* Signing and verification backend for libcrypto-backed keys */
పూర్ణాంకం	sshkey_pkey_digest_sign(EVP_PKEY*, పూర్ణాంకం, u_char **,
    కొలత_t *, స్థిరరాశి u_char *, కొలత_t);
పూర్ణాంకం	sshkey_pkey_digest_verify(EVP_PKEY *, పూర్ణాంకం, స్థిరరాశి u_char *,
    కొలత_t, u_char *, కొలత_t);

/* for debug */
శూన్య	sshkey_dump_ec_బిందువు(స్థిరరాశి EC_సమూహం *, స్థిరరాశి EC_బిందువు *);
శూన్య	sshkey_dump_ec_కీలకం(స్థిరరాశి EC_కీలకం *);

/* private key parsing and serialisation */
పూర్ణాంకం	sshkey_వ్యక్తిగత_serialize(నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *buf);
పూర్ణాంకం	sshkey_వ్యక్తిగత_deserialize(నిర్మాణం sshbuf *buf,  నిర్మాణం sshkey **keyp);

/* private key file format parsing and serialisation */
పూర్ణాంకం	sshkey_వ్యక్తిగత_గమ్యం_fileblob(నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *blob,
    స్థిరరాశి అక్షరం *passphrase, స్థిరరాశి అక్షరం *comment,
    పూర్ణాంకం format, స్థిరరాశి అక్షరం *openssh_format_cipher, పూర్ణాంకం openssh_format_విడతలు);
పూర్ణాంకం	sshkey_parse_వ్యక్తిగత_fileblob(నిర్మాణం sshbuf *బఫరు,
    స్థిరరాశి అక్షరం *passphrase, నిర్మాణం sshkey **keyp, అక్షరం **commentp);
పూర్ణాంకం	sshkey_parse_వ్యక్తిగత_fileblob_type(నిర్మాణం sshbuf *blob, పూర్ణాంకం type,
    స్థిరరాశి అక్షరం *passphrase, నిర్మాణం sshkey **keyp, అక్షరం **commentp);
పూర్ణాంకం	sshkey_parse_pubkey_from_వ్యక్తిగత_fileblob_type(నిర్మాణం sshbuf *blob,
    పూర్ణాంకం type, నిర్మాణం sshkey **pubkeyp);

పూర్ణాంకం sshkey_check_rsa_నిడివి(స్థిరరాశి నిర్మాణం sshkey *, పూర్ణాంకం);
పూర్ణాంకం	ssh_rsa_hash_id_from_keyname(స్థిరరాశి అక్షరం *);
స్థిరరాశి అక్షరం *ssh_rsa_hash_alg_ident(పూర్ణాంకం);
పూర్ణాంకం	ssh_rsa_encode_store_sig(పూర్ణాంకం, స్థిరరాశి u_char *, కొలత_t,
	    u_char **, కొలత_t *);
పూర్ణాంకం	ssh_ecdsa_encode_store_sig(స్థిరరాశి నిర్మాణం sshkey *,
	    స్థిరరాశి BIGNUM *, స్థిరరాశి BIGNUM *, u_char **, కొలత_t *);
పూర్ణాంకం	ssh_ed25519_encode_store_sig(స్థిరరాశి u_char *, కొలత_t,
	    u_char **, కొలత_t *);
/* XXX should be internal, but used by ssh-keygen */
పూర్ణాంకం ssh_rsa_complete_crt_parameters(స్థిరరాశి BIGNUM *, స్థిరరాశి BIGNUM *,
    స్థిరరాశి BIGNUM *, స్థిరరాశి BIGNUM *, BIGNUM **, BIGNUM **);

శూన్య	 sshkey_sig_details_free(నిర్మాణం sshkey_sig_details *);

#నిర్వచితమైతే WITH_OPENSSL
పూర్ణాంకం	sshkey_ecdsa_fixup_సమూహం(EVP_PKEY *k); /* ssh-ecdsa.c */
#అయితే_ముగింపు

#నిర్వచితమైతే SSHKEY_అంతర్గత
పూర్ణాంకం	sshkey_sk_fields_equal(స్థిరరాశి నిర్మాణం sshkey *a, స్థిరరాశి నిర్మాణం sshkey *b);
శూన్య	sshkey_sk_cleanup(నిర్మాణం sshkey *k);
పూర్ణాంకం	sshkey_serialize_sk(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b);
పూర్ణాంకం	sshkey_copy_ప్రజా_sk(స్థిరరాశి నిర్మాణం sshkey *from, నిర్మాణం sshkey *గమ్యం);
పూర్ణాంకం	sshkey_deserialize_sk(నిర్మాణం sshbuf *b, నిర్మాణం sshkey *కీలకం);
పూర్ణాంకం	sshkey_serialize_వ్యక్తిగత_sk(స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    నిర్మాణం sshbuf *buf);
పూర్ణాంకం	sshkey_వ్యక్తిగత_deserialize_sk(నిర్మాణం sshbuf *buf, నిర్మాణం sshkey *k);
#నిర్వచితమైతే WITH_OPENSSL
పూర్ణాంకం	check_rsa_నిడివి(స్థిరరాశి RSA *rsa); /* XXX remove */
#అయితే_ముగింపు
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే WITH_OPENSSL
#నిర్వచనం_రద్దు RSA
#నిర్వచనం_రద్దు EC_కీలకం
#నిర్వచనం_రద్దు EC_సమూహం
#నిర్వచనం_రద్దు EC_బిందువు
#నిర్వచనం_రద్దు EVP_PKEY
#అయితే_ముగింపు /* WITH_OPENSSL */

#అయితే_ముగింపు /* SSHKEY_H */
