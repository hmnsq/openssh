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
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ KEX_H
#ವ್ಯಾಖ್ಯಾನಿಸು KEX_H

#ಅನ್ತರ್ಭಾವ "mac.h"
#ಅನ್ತರ್ಭಾವ "crypto_api.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/dh.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಇಲ್ಲದಿದ್ದರೆ /* OPENSSL */
#ವ್ಯಾಖ್ಯಾನಿಸು BIGNUM		ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು DH		ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು EC_ಕೀಲಿ		ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು EC_ಗುಂಪು	ಶೂನ್ಯ
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

#ವ್ಯಾಖ್ಯಾನಿಸು KEX_COOKIE_LEN	16

#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_DH1				"diffie-hellman-group1-sha1"
#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_DH14_SHA1			"diffie-hellman-group14-sha1"
#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_DH14_SHA256			"diffie-hellman-group14-sha256"
#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_DH16_SHA512			"diffie-hellman-group16-sha512"
#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_DH18_SHA512			"diffie-hellman-group18-sha512"
#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_DHGEX_SHA1			"diffie-hellman-group-exchange-sha1"
#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_DHGEX_SHA256		"diffie-hellman-group-exchange-sha256"
#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_ECDH_SHA2_NISTP256		"ecdh-sha2-nistp256"
#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_ECDH_SHA2_NISTP384		"ecdh-sha2-nistp384"
#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_ECDH_SHA2_NISTP521		"ecdh-sha2-nistp521"
#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_CURVE25519_SHA256		"curve25519-sha256"
#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_CURVE25519_SHA256_OLD	"curve25519-sha256@libssh.org"
#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_SNTRUP761X25519_SHA512	"sntrup761x25519-sha512"
#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_SNTRUP761X25519_SHA512_OLD	"sntrup761x25519-sha512@openssh.com"
#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_MLKEM768X25519_SHA256	"mlkem768x25519-sha256"
#ವ್ಯಾಖ್ಯಾನಿಸು	KEX_MLKEM768NISTP256_SHA256	"mlkem768nistp256-sha256"

#ವ್ಯಾಖ್ಯಾನಿಸು COMP_NONE	0
#ವ್ಯಾಖ್ಯಾನಿಸು COMP_DELAYED	2

#ವ್ಯಾಖ್ಯಾನಿಸು CURVE25519_ಗಾತ್ರ 32

ಎಣಿಕೆ kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS,
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

ಎಣಿಕೆ kex_modes {
	ಬಹುಲಕ_ಒಳ,
	ಬಹುಲಕ_ಹೊರಹೋಗು,
	ಬಹುಲಕ_MAX
};

ಎಣಿಕೆ kex_exchange {
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
#ವ್ಯಾಖ್ಯಾನಿಸು KEX_INIT_ಕಳುಹಿಸಿದ			0x0001
#ವ್ಯಾಖ್ಯಾನಿಸು KEX_INITIAL			0x0002
#ವ್ಯಾಖ್ಯಾನಿಸು KEX_HAS_PUBKEY_HOSTBOUND	0x0004
#ವ್ಯಾಖ್ಯಾನಿಸು KEX_RSA_SHA2_256_SUPPORTED	0x0008 /* only set in server for now */
#ವ್ಯಾಖ್ಯಾನಿಸು KEX_RSA_SHA2_512_SUPPORTED	0x0010 /* only set in server for now */
#ವ್ಯಾಖ್ಯಾನಿಸು KEX_HAS_PING			0x0020
#ವ್ಯಾಖ್ಯಾನಿಸು KEX_HAS_EXT_INFO_ಒಳ_AUTH	0x0040
#ವ್ಯಾಖ್ಯಾನಿಸು KEX_HAS_NEWAGENT		0x0080 /* only set in client */
#ವ್ಯಾಖ್ಯಾನಿಸು KEX_INIT_RECVD			0x0100

/* kex->pq */
#ವ್ಯಾಖ್ಯಾನಿಸು KEX_NOT_PQ			0
#ವ್ಯಾಖ್ಯಾನಿಸು KEX_IS_PQ			1

ರಚನೆ sshenc {
	ಅಕ್ಷರ	*name;
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *cipher;
	ಪೂರ್ಣಾಂಕ	enabled;
	u_int	ಕೀಲಿ_len;
	u_int	iv_len;
	u_int	ಖಂಡ_ಗಾತ್ರ;
	u_char	*ಕೀಲಿ;
	u_char	*iv;
};
ರಚನೆ sshcomp {
	u_int	type;
	ಪೂರ್ಣಾಂಕ	enabled;
	ಅಕ್ಷರ	*name;
};
ರಚನೆ newkeys {
	ರಚನೆ sshenc	enc;
	ರಚನೆ sshmac	mac;
	ರಚನೆ sshcomp  comp;
};

ರಚನೆ ssh;
ರಚನೆ sshbuf;

ರಚನೆ kex {
	ರಚನೆ newkeys	*newkeys[ಬಹುಲಕ_MAX];
	u_int	we_need;
	u_int	dh_need;
	ಪೂರ್ಣಾಂಕ	server;
	ಅಕ್ಷರ	*name;
	ಅಕ್ಷರ	*hostkey_alg;
	ಪೂರ್ಣಾಂಕ	hostkey_type;
	ಪೂರ್ಣಾಂಕ	hostkey_nid;
	u_int	kex_type;
	ಅಕ್ಷರ	*server_sig_algs;
	ಪೂರ್ಣಾಂಕ	ext_info_c;
	ಪೂರ್ಣಾಂಕ	ext_info_s;
	ಪೂರ್ಣಾಂಕ	kex_strict;
	ಪೂರ್ಣಾಂಕ	ext_info_received;
	ರಚನೆ sshbuf *my;
	ರಚನೆ sshbuf *peer;
	ರಚನೆ sshbuf *client_ಆವೃತ್ತಿ;
	ರಚನೆ sshbuf *server_ಆವೃತ್ತಿ;
	ರಚನೆ sshbuf *session_id;
	ರಚನೆ sshbuf *initial_sig;
	ರಚನೆ sshkey *initial_hostkey;
	sig_atomic_t ಮುಗಿದ;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	ಪೂರ್ಣಾಂಕ	hash_alg;
	ಪೂರ್ಣಾಂಕ	ec_nid;
	ಅಕ್ಷರ	*failed_choice;
	ಪೂರ್ಣಾಂಕ	(*verify_host_ಕೀಲಿ)(ರಚನೆ sshkey *, ರಚನೆ ssh *);
	ರಚನೆ sshkey *(*ತುಂಬು_host_ಬಹಿರಂಗ_ಕೀಲಿ)(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ರಚನೆ ssh *);
	ರಚನೆ sshkey *(*ತುಂಬು_host_ಖಾಸಗಿ_ಕೀಲಿ)(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ರಚನೆ ssh *);
	ಪೂರ್ಣಾಂಕ	(*host_ಕೀಲಿ_ಸೂಚ್ಯಂಕ)(ರಚನೆ sshkey *, ಪೂರ್ಣಾಂಕ, ರಚನೆ ssh *);
	ಪೂರ್ಣಾಂಕ	(*sign)(ರಚನೆ ssh *, ರಚನೆ sshkey *, ರಚನೆ sshkey *,
	    u_char **, ಗಾತ್ರ_t *, ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
	ಪೂರ್ಣಾಂಕ	(*kex[KEX_MAX])(ರಚನೆ ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_ಕೀಲಿ	*ec_client_ಕೀಲಿ;		/* ECDH */
	ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *ec_ಗುಂಪು;	/* ECDH */
	u_char c25519_client_ಕೀಲಿ[CURVE25519_ಗಾತ್ರ]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_ಗಾತ್ರ]; /* 25519 */
	u_char sntrup761_client_ಕೀಲಿ[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_ಕೀಲಿ[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	ರಚನೆ sshbuf *client_pub;
};

ಪೂರ್ಣಾಂಕ	 kex_name_valid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
u_int	 kex_type_from_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 kex_hash_from_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 kex_nid_from_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 kex_is_pq_from_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 kex_ಹೆಸರುಗಳು_valid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಅಕ್ಷರ	*kex_alg_list(ಅಕ್ಷರ);
ಅಕ್ಷರ	*kex_ಹೆಸರುಗಳು_cat(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 kex_has_any_alg(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 kex_assemble_ಹೆಸರುಗಳು(ಅಕ್ಷರ **, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ	 kex_proposal_populate_entries(ರಚನೆ ssh *, ಅಕ್ಷರ *prop[PROPOSAL_MAX],
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ	 kex_proposal_free_entries(ಅಕ್ಷರ *prop[PROPOSAL_MAX]);

ಪೂರ್ಣಾಂಕ	 kex_exchange_identification(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ರಚನೆ kex *kex_new(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ	 kex_ready(ರಚನೆ ssh *, ಅಕ್ಷರ *[PROPOSAL_MAX]);
ಪೂರ್ಣಾಂಕ	 kex_ಸಿದ್ಧತೆ(ರಚನೆ ssh *, ಅಕ್ಷರ *[PROPOSAL_MAX]);
ಶೂನ್ಯ	 kex_free_newkeys(ರಚನೆ newkeys *);
ಶೂನ್ಯ	 kex_free(ರಚನೆ kex *);

ಪೂರ್ಣಾಂಕ	 kex_buf2prop(ರಚನೆ sshbuf *, ಪೂರ್ಣಾಂಕ *, ಅಕ್ಷರ ***);
ಪೂರ್ಣಾಂಕ	 kex_prop2buf(ರಚನೆ sshbuf *, ಅಕ್ಷರ *proposal[PROPOSAL_MAX]);
ಶೂನ್ಯ	 kex_prop_free(ಅಕ್ಷರ **);
ಪೂರ್ಣಾಂಕ	 kex_ತುಂಬು_hostkey(ರಚನೆ ssh *, ರಚನೆ sshkey **, ರಚನೆ sshkey **);
ಪೂರ್ಣಾಂಕ	 kex_verify_host_ಕೀಲಿ(ರಚನೆ ssh *, ರಚನೆ sshkey *);

ಪೂರ್ಣಾಂಕ	 kex_send_kexinit(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 kex_ಒಳಹರಿವು_kexinit(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 kex_ಒಳಹರಿವು_ext_info(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 kex_protocol_error(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 kex_derive_ಕೀಲಿಗಳು(ರಚನೆ ssh *, u_char *, u_int, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ	 kex_send_newkeys(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 kex_ಆರಂಭ_rekex(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 kex_server_update_ext_info(ರಚನೆ ssh *);
ಶೂನ್ಯ	 kex_ಗಣ_server_sig_algs(ರಚನೆ ssh *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ	 kex_ಗಣ_warn_weak_crypto(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ	 kex_check_warn_weak_crypto(ರಚನೆ ssh *);

ಪೂರ್ಣಾಂಕ	 kexgex_client(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 kexgex_server(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 kex_gen_client(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	 kex_gen_server(ರಚನೆ ssh *);

ಪೂರ್ಣಾಂಕ	 kex_dh_keypair(ರಚನೆ kex *);
ಪೂರ್ಣಾಂಕ	 kex_dh_enc(ರಚನೆ kex *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *, ರಚನೆ sshbuf **,
    ರಚನೆ sshbuf **);
ಪೂರ್ಣಾಂಕ	 kex_dh_dec(ರಚನೆ kex *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *, ರಚನೆ sshbuf **);

ಪೂರ್ಣಾಂಕ	 kex_ecdh_dec_ಕೀಲಿ_ಗುಂಪು(ರಚನೆ kex *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *, EC_ಕೀಲಿ *ಕೀಲಿ,
	    ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *, ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf **);

ಪೂರ್ಣಾಂಕ	 kex_ecdh_keypair(ರಚನೆ kex *);
ಪೂರ್ಣಾಂಕ	 kex_ecdh_enc(ರಚನೆ kex *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *, ರಚನೆ sshbuf **,
    ರಚನೆ sshbuf **);
ಪೂರ್ಣಾಂಕ	 kex_ecdh_dec(ರಚನೆ kex *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *, ರಚನೆ sshbuf **);

ಪೂರ್ಣಾಂಕ	 kex_c25519_keypair(ರಚನೆ kex *);
ಪೂರ್ಣಾಂಕ	 kex_c25519_enc(ರಚನೆ kex *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *, ರಚನೆ sshbuf **,
    ರಚನೆ sshbuf **);
ಪೂರ್ಣಾಂಕ	 kex_c25519_dec(ರಚನೆ kex *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *, ರಚನೆ sshbuf **);

ಪೂರ್ಣಾಂಕ	 kex_kem_sntrup761x25519_keypair(ರಚನೆ kex *);
ಪೂರ್ಣಾಂಕ	 kex_kem_sntrup761x25519_enc(ರಚನೆ kex *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *,
    ರಚನೆ sshbuf **, ರಚನೆ sshbuf **);
ಪೂರ್ಣಾಂಕ	 kex_kem_sntrup761x25519_dec(ರಚನೆ kex *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *,
    ರಚನೆ sshbuf **);

ಪೂರ್ಣಾಂಕ	 kex_kem_mlkem768x25519_keypair(ರಚನೆ kex *);
ಪೂರ್ಣಾಂಕ	 kex_kem_mlkem768x25519_enc(ರಚನೆ kex *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *,
    ರಚನೆ sshbuf **, ರಚನೆ sshbuf **);
ಪೂರ್ಣಾಂಕ	 kex_kem_mlkem768x25519_dec(ರಚನೆ kex *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *,
    ರಚನೆ sshbuf **);

ಪೂರ್ಣಾಂಕ	 kex_kem_mlkem768ecdh_keypair(ರಚನೆ kex *);
ಪೂರ್ಣಾಂಕ	 kex_kem_mlkem768ecdh_enc(ರಚನೆ kex *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *,
    ರಚನೆ sshbuf **, ರಚನೆ sshbuf **);
ಪೂರ್ಣಾಂಕ	 kex_kem_mlkem768ecdh_dec(ರಚನೆ kex *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *,
    ರಚನೆ sshbuf **);

ಪೂರ್ಣಾಂಕ	 kex_dh_keygen(ರಚನೆ kex *);
ಪೂರ್ಣಾಂಕ	 kex_dh_compute_ಕೀಲಿ(ರಚನೆ kex *, BIGNUM *, ರಚನೆ sshbuf *);

ಪೂರ್ಣಾಂಕ	 kexgex_hash(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *,
    ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ,
    ಸ್ಥಿರಾಂಕ BIGNUM *, ಸ್ಥಿರಾಂಕ BIGNUM *, ಸ್ಥಿರಾಂಕ BIGNUM *,
    ಸ್ಥಿರಾಂಕ BIGNUM *, ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t,
    u_char *, ಗಾತ್ರ_t *);

ಶೂನ್ಯ	kexc25519_keygen(u_char ಕೀಲಿ[CURVE25519_ಗಾತ್ರ], u_char pub[CURVE25519_ಗಾತ್ರ])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_ಗಾತ್ರ)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_ಗಾತ್ರ)));
ಪೂರ್ಣಾಂಕ	kexc25519_shared_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ u_char ಕೀಲಿ[CURVE25519_ಗಾತ್ರ],
    ಸ್ಥಿರಾಂಕ u_char pub[CURVE25519_ಗಾತ್ರ], ರಚನೆ sshbuf *ಹೊರಹೋಗು)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_ಗಾತ್ರ)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_ಗಾತ್ರ)));
ಪೂರ್ಣಾಂಕ	kexc25519_shared_ಕೀಲಿ_ext(ಸ್ಥಿರಾಂಕ u_char ಕೀಲಿ[CURVE25519_ಗಾತ್ರ],
    ಸ್ಥಿರಾಂಕ u_char pub[CURVE25519_ಗಾತ್ರ], ರಚನೆ sshbuf *ಹೊರಹೋಗು, ಪೂರ್ಣಾಂಕ)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_ಗಾತ್ರ)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_ಗಾತ್ರ)));

#ಆದರೆ defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
ಶೂನ್ಯ	dump_digest(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ u_char *, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ
