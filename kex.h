/* $OpenBSD: kex.h,v 1.135 2026/09/16 00:29:44 djm Exp $ */

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
#ifndef KEX_H
#define KEX_H

#अन्तर्भाव "mac.h"
#अन्तर्भाव "crypto_api.h"

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/dh.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/ecdsa.h>
#अन्यथा /* OPENSSL */
#define BIGNUM		शून्य
#define DH		शून्य
#define EC_किल्ली		शून्य
#define EC_GROUP	शून्य
#endif /* WITH_OPENSSL */

#define KEX_COOKIE_LEN	16

#define	KEX_DH1				"diffie-hellman-group1-sha1"
#define	KEX_DH14_SHA1			"diffie-hellman-group14-sha1"
#define	KEX_DH14_SHA256			"diffie-hellman-group14-sha256"
#define	KEX_DH16_SHA512			"diffie-hellman-group16-sha512"
#define	KEX_DH18_SHA512			"diffie-hellman-group18-sha512"
#define	KEX_DHGEX_SHA1			"diffie-hellman-group-exchange-sha1"
#define	KEX_DHGEX_SHA256		"diffie-hellman-group-exchange-sha256"
#define	KEX_ECDH_SHA2_NISTP256		"ecdh-sha2-nistp256"
#define	KEX_ECDH_SHA2_NISTP384		"ecdh-sha2-nistp384"
#define	KEX_ECDH_SHA2_NISTP521		"ecdh-sha2-nistp521"
#define	KEX_CURVE25519_SHA256		"curve25519-sha256"
#define	KEX_CURVE25519_SHA256_OLD	"curve25519-sha256@libssh.org"
#define	KEX_SNTRUP761X25519_SHA512	"sntrup761x25519-sha512"
#define	KEX_SNTRUP761X25519_SHA512_OLD	"sntrup761x25519-sha512@openssh.com"
#define	KEX_MLKEM768X25519_SHA256	"mlkem768x25519-sha256"
#define	KEX_MLKEM768NISTP256_SHA256	"mlkem768nistp256-sha256"

#define COMP_NONE	0
#define COMP_DELAYED	2

#define CURVE25519_SIZE 32

गणना kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_किल्ली_ALGS,
	PROPOSAL_ENC_ALGS_CTOS,
	PROPOSAL_ENC_ALGS_STOC,
	PROPOSAL_MAC_ALGS_CTOS,
	PROPOSAL_MAC_ALGS_STOC,
	PROPOSAL_COMP_ALGS_CTOS,
	PROPOSAL_COMP_ALGS_STOC,
	PROPOSAL_LANG_CTOS,
	PROPOSAL_LANG_STOC,
	PROPOSAL_MAX
};

गणना kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};

गणना kex_exchange {
	KEX_DH_GRP1_SHA1 = 1,
	KEX_DH_GRP14_SHA1,
	KEX_DH_GRP14_SHA256,
	KEX_DH_GRP16_SHA512,
	KEX_DH_GRP18_SHA512,
	KEX_DH_GEX_SHA1,
	KEX_DH_GEX_SHA256,
	KEX_ECDH_SHA2,
	KEX_C25519_SHA256,
	KEX_KEM_SNTRUP761X25519_SHA512,
	KEX_KEM_MLKEM768X25519_SHA256,
	KEX_KEM_MLKEM768ECDH_SHA256,
	KEX_MAX
};

/* kex->flags */
#define KEX_INIT_SENT			0x0001
#define KEX_INITIAL			0x0002
#define KEX_HAS_PUBKEY_HOSTBOUND	0x0004
#define KEX_RSA_SHA2_256_SUPPORTED	0x0008 /* only set in server for now */
#define KEX_RSA_SHA2_512_SUPPORTED	0x0010 /* only set in server for now */
#define KEX_HAS_PING			0x0020
#define KEX_HAS_EXT_INFO_IN_AUTH	0x0040
#define KEX_HAS_NEWAGENT		0x0080 /* only set in client */
#define KEX_INIT_RECVD			0x0100

/* kex->pq */
#define KEX_NOT_PQ			0
#define KEX_IS_PQ			1

संरचना sshenc {
	अक्षर	*name;
	स्थिरांक संरचना sshcipher *cipher;
	पूर्णांक	enabled;
	u_int	किल्ली_len;
	u_int	iv_len;
	u_int	block_size;
	u_char	*किल्ली;
	u_char	*iv;
};
संरचना sshcomp {
	u_int	type;
	पूर्णांक	enabled;
	अक्षर	*name;
};
संरचना newkeys {
	संरचना sshenc	enc;
	संरचना sshmac	mac;
	संरचना sshcomp  comp;
};

संरचना ssh;
संरचना sshbuf;

संरचना kex {
	संरचना newkeys	*newkeys[MODE_MAX];
	u_int	we_need;
	u_int	dh_need;
	पूर्णांक	server;
	अक्षर	*name;
	अक्षर	*hostkey_alg;
	पूर्णांक	hostkey_type;
	पूर्णांक	hostkey_nid;
	u_int	kex_type;
	अक्षर	*server_sig_algs;
	पूर्णांक	ext_info_c;
	पूर्णांक	ext_info_s;
	पूर्णांक	kex_strict;
	पूर्णांक	ext_info_received;
	संरचना sshbuf *my;
	संरचना sshbuf *peer;
	संरचना sshbuf *client_version;
	संरचना sshbuf *server_version;
	संरचना sshbuf *session_id;
	संरचना sshbuf *initial_sig;
	संरचना sshkey *initial_hostkey;
	संक_पूर्ण_प्रकार done;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	पूर्णांक	hash_alg;
	पूर्णांक	ec_nid;
	अक्षर	*failed_choice;
	पूर्णांक	(*verify_host_किल्ली)(संरचना sshkey *, संरचना ssh *);
	संरचना sshkey *(*load_host_public_किल्ली)(पूर्णांक, पूर्णांक, संरचना ssh *);
	संरचना sshkey *(*load_host_private_किल्ली)(पूर्णांक, पूर्णांक, संरचना ssh *);
	पूर्णांक	(*host_किल्ली_index)(संरचना sshkey *, पूर्णांक, संरचना ssh *);
	पूर्णांक	(*sign)(संरचना ssh *, संरचना sshkey *, संरचना sshkey *,
	    u_char **, माप_प्रकार *, स्थिरांक u_char *, माप_प्रकार, स्थिरांक अक्षर *);
	पूर्णांक	(*kex[KEX_MAX])(संरचना ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_किल्ली	*ec_client_किल्ली;		/* ECDH */
	स्थिरांक EC_GROUP *ec_group;	/* ECDH */
	u_char c25519_client_किल्ली[CURVE25519_SIZE]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_SIZE]; /* 25519 */
	u_char sntrup761_client_किल्ली[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_किल्ली[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	संरचना sshbuf *client_pub;
};

पूर्णांक	 kex_name_valid(स्थिरांक अक्षर *);
u_int	 kex_type_from_name(स्थिरांक अक्षर *);
पूर्णांक	 kex_hash_from_name(स्थिरांक अक्षर *);
पूर्णांक	 kex_nid_from_name(स्थिरांक अक्षर *);
पूर्णांक	 kex_is_pq_from_name(स्थिरांक अक्षर *);
पूर्णांक	 kex_names_valid(स्थिरांक अक्षर *);
अक्षर	*kex_alg_list(अक्षर);
अक्षर	*kex_names_cat(स्थिरांक अक्षर *, स्थिरांक अक्षर *);
पूर्णांक	 kex_has_any_alg(स्थिरांक अक्षर *, स्थिरांक अक्षर *);
पूर्णांक	 kex_assemble_names(अक्षर **, स्थिरांक अक्षर *, स्थिरांक अक्षर *);
शून्य	 kex_proposal_populate_entries(संरचना ssh *, अक्षर *prop[PROPOSAL_MAX],
    स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *);
शून्य	 kex_proposal_free_entries(अक्षर *prop[PROPOSAL_MAX]);

पूर्णांक	 kex_exchange_identification(संरचना ssh *, पूर्णांक, स्थिरांक अक्षर *);

संरचना kex *kex_new(शून्य);
पूर्णांक	 kex_ready(संरचना ssh *, अक्षर *[PROPOSAL_MAX]);
पूर्णांक	 kex_setup(संरचना ssh *, अक्षर *[PROPOSAL_MAX]);
शून्य	 kex_free_newkeys(संरचना newkeys *);
शून्य	 kex_free(संरचना kex *);

पूर्णांक	 kex_buf2prop(संरचना sshbuf *, पूर्णांक *, अक्षर ***);
पूर्णांक	 kex_prop2buf(संरचना sshbuf *, अक्षर *proposal[PROPOSAL_MAX]);
शून्य	 kex_prop_free(अक्षर **);
पूर्णांक	 kex_load_hostkey(संरचना ssh *, संरचना sshkey **, संरचना sshkey **);
पूर्णांक	 kex_verify_host_किल्ली(संरचना ssh *, संरचना sshkey *);

पूर्णांक	 kex_send_kexinit(संरचना ssh *);
पूर्णांक	 kex_आदान_kexinit(पूर्णांक, uint32_t, संरचना ssh *);
पूर्णांक	 kex_आदान_ext_info(पूर्णांक, uint32_t, संरचना ssh *);
पूर्णांक	 kex_protocol_error(पूर्णांक, uint32_t, संरचना ssh *);
पूर्णांक	 kex_derive_किल्ल्या(संरचना ssh *, u_char *, u_int, स्थिरांक संरचना sshbuf *);
पूर्णांक	 kex_send_newkeys(संरचना ssh *);
पूर्णांक	 kex_start_rekex(संरचना ssh *);
पूर्णांक	 kex_server_update_ext_info(संरचना ssh *);
शून्य	 kex_set_server_sig_algs(संरचना ssh *, स्थिरांक अक्षर *);
शून्य	 kex_set_warn_weak_crypto(संरचना ssh *, पूर्णांक);
शून्य	 kex_check_warn_weak_crypto(संरचना ssh *);

पूर्णांक	 kexgex_client(संरचना ssh *);
पूर्णांक	 kexgex_server(संरचना ssh *);
पूर्णांक	 kex_gen_client(संरचना ssh *);
पूर्णांक	 kex_gen_server(संरचना ssh *);

पूर्णांक	 kex_dh_keypair(संरचना kex *);
पूर्णांक	 kex_dh_enc(संरचना kex *, स्थिरांक संरचना sshbuf *, संरचना sshbuf **,
    संरचना sshbuf **);
पूर्णांक	 kex_dh_dec(संरचना kex *, स्थिरांक संरचना sshbuf *, संरचना sshbuf **);

पूर्णांक	 kex_ecdh_dec_किल्ली_group(संरचना kex *, स्थिरांक संरचना sshbuf *, EC_किल्ली *किल्ली,
	    स्थिरांक EC_GROUP *, पूर्णांक, संरचना sshbuf **);

पूर्णांक	 kex_ecdh_keypair(संरचना kex *);
पूर्णांक	 kex_ecdh_enc(संरचना kex *, स्थिरांक संरचना sshbuf *, संरचना sshbuf **,
    संरचना sshbuf **);
पूर्णांक	 kex_ecdh_dec(संरचना kex *, स्थिरांक संरचना sshbuf *, संरचना sshbuf **);

पूर्णांक	 kex_c25519_keypair(संरचना kex *);
पूर्णांक	 kex_c25519_enc(संरचना kex *, स्थिरांक संरचना sshbuf *, संरचना sshbuf **,
    संरचना sshbuf **);
पूर्णांक	 kex_c25519_dec(संरचना kex *, स्थिरांक संरचना sshbuf *, संरचना sshbuf **);

पूर्णांक	 kex_kem_sntrup761x25519_keypair(संरचना kex *);
पूर्णांक	 kex_kem_sntrup761x25519_enc(संरचना kex *, स्थिरांक संरचना sshbuf *,
    संरचना sshbuf **, संरचना sshbuf **);
पूर्णांक	 kex_kem_sntrup761x25519_dec(संरचना kex *, स्थिरांक संरचना sshbuf *,
    संरचना sshbuf **);

पूर्णांक	 kex_kem_mlkem768x25519_keypair(संरचना kex *);
पूर्णांक	 kex_kem_mlkem768x25519_enc(संरचना kex *, स्थिरांक संरचना sshbuf *,
    संरचना sshbuf **, संरचना sshbuf **);
पूर्णांक	 kex_kem_mlkem768x25519_dec(संरचना kex *, स्थिरांक संरचना sshbuf *,
    संरचना sshbuf **);

पूर्णांक	 kex_kem_mlkem768ecdh_keypair(संरचना kex *);
पूर्णांक	 kex_kem_mlkem768ecdh_enc(संरचना kex *, स्थिरांक संरचना sshbuf *,
    संरचना sshbuf **, संरचना sshbuf **);
पूर्णांक	 kex_kem_mlkem768ecdh_dec(संरचना kex *, स्थिरांक संरचना sshbuf *,
    संरचना sshbuf **);

पूर्णांक	 kex_dh_keygen(संरचना kex *);
पूर्णांक	 kex_dh_compute_किल्ली(संरचना kex *, BIGNUM *, संरचना sshbuf *);

पूर्णांक	 kexgex_hash(पूर्णांक, स्थिरांक संरचना sshbuf *, स्थिरांक संरचना sshbuf *,
    स्थिरांक संरचना sshbuf *, स्थिरांक संरचना sshbuf *, स्थिरांक संरचना sshbuf *,
    पूर्णांक, पूर्णांक, पूर्णांक,
    स्थिरांक BIGNUM *, स्थिरांक BIGNUM *, स्थिरांक BIGNUM *,
    स्थिरांक BIGNUM *, स्थिरांक u_char *, माप_प्रकार,
    u_char *, माप_प्रकार *);

शून्य	kexc25519_keygen(u_char किल्ली[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
पूर्णांक	kexc25519_shared_किल्ली(स्थिरांक u_char किल्ली[CURVE25519_SIZE],
    स्थिरांक u_char pub[CURVE25519_SIZE], संरचना sshbuf *out)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
पूर्णांक	kexc25519_shared_किल्ली_ext(स्थिरांक u_char किल्ली[CURVE25519_SIZE],
    स्थिरांक u_char pub[CURVE25519_SIZE], संरचना sshbuf *out, पूर्णांक)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));

#जर defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
शून्य	dump_digest(स्थिरांक अक्षर *, स्थिरांक u_char *, पूर्णांक);
#endif

#endif
