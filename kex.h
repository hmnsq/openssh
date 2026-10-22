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

#ଅନ୍ତର୍ଭାଵ "mac.h"
#ଅନ୍ତର୍ଭାଵ "crypto_api.h"

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/dh.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ec.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ecdsa.h>
#ଅନ୍ୟଥା /* OPENSSL */
#define BIGNUM		ଶୂନ୍ୟ
#define DH		ଶୂନ୍ୟ
#define EC_ଚାବି		ଶୂନ୍ୟ
#define EC_GROUP	ଶୂନ୍ୟ
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

ଗଣନା kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_ଚାବି_ALGS,
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

ଗଣନା kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};

ଗଣନା kex_exchange {
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

ସଂରଚନା sshenc {
	ଅକ୍ଷର	*name;
	ଅଚଳ ସଂରଚନା sshcipher *cipher;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	enabled;
	u_int	ଚାବି_len;
	u_int	iv_len;
	u_int	block_size;
	u_char	*ଚାବି;
	u_char	*iv;
};
ସଂରଚନା sshcomp {
	u_int	type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	enabled;
	ଅକ୍ଷର	*name;
};
ସଂରଚନା newkeys {
	ସଂରଚନା sshenc	enc;
	ସଂରଚନା sshmac	mac;
	ସଂରଚନା sshcomp  comp;
};

ସଂରଚନା ssh;
ସଂରଚନା sshbuf;

ସଂରଚନା kex {
	ସଂରଚନା newkeys	*newkeys[MODE_MAX];
	u_int	we_need;
	u_int	dh_need;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	server;
	ଅକ୍ଷର	*name;
	ଅକ୍ଷର	*hostkey_alg;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	hostkey_type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	hostkey_nid;
	u_int	kex_type;
	ଅକ୍ଷର	*server_sig_algs;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ext_info_c;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ext_info_s;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	kex_strict;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ext_info_received;
	ସଂରଚନା sshbuf *my;
	ସଂରଚନା sshbuf *peer;
	ସଂରଚନା sshbuf *client_version;
	ସଂରଚନା sshbuf *server_version;
	ସଂରଚନା sshbuf *session_id;
	ସଂରଚନା sshbuf *initial_sig;
	ସଂରଚନା sshkey *initial_hostkey;
	sig_atomic_t done;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	hash_alg;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ec_nid;
	ଅକ୍ଷର	*failed_choice;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	(*verify_host_ଚାବି)(ସଂରଚନା sshkey *, ସଂରଚନା ssh *);
	ସଂରଚନା sshkey *(*load_host_public_ଚାବି)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା ssh *);
	ସଂରଚନା sshkey *(*load_host_private_ଚାବି)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା ssh *);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	(*host_ଚାବି_index)(ସଂରଚନା sshkey *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା ssh *);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	(*sign)(ସଂରଚନା ssh *, ସଂରଚନା sshkey *, ସଂରଚନା sshkey *,
	    u_char **, size_t *, ଅଚଳ u_char *, size_t, ଅଚଳ ଅକ୍ଷର *);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	(*kex[KEX_MAX])(ସଂରଚନା ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_ଚାବି	*ec_client_ଚାବି;		/* ECDH */
	ଅଚଳ EC_GROUP *ec_group;	/* ECDH */
	u_char c25519_client_ଚାବି[CURVE25519_SIZE]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_SIZE]; /* 25519 */
	u_char sntrup761_client_ଚାବି[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_ଚାବି[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	ସଂରଚନା sshbuf *client_pub;
};

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_name_valid(ଅଚଳ ଅକ୍ଷର *);
u_int	 kex_type_from_name(ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_hash_from_name(ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_nid_from_name(ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_is_pq_from_name(ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_names_valid(ଅଚଳ ଅକ୍ଷର *);
ଅକ୍ଷର	*kex_alg_list(ଅକ୍ଷର);
ଅକ୍ଷର	*kex_names_cat(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_has_any_alg(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_assemble_names(ଅକ୍ଷର **, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ଶୂନ୍ୟ	 kex_proposal_populate_entries(ସଂରଚନା ssh *, ଅକ୍ଷର *prop[PROPOSAL_MAX],
    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);
ଶୂନ୍ୟ	 kex_proposal_free_entries(ଅକ୍ଷର *prop[PROPOSAL_MAX]);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_exchange_identification(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର *);

ସଂରଚନା kex *kex_new(ଶୂନ୍ୟ);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_ready(ସଂରଚନା ssh *, ଅକ୍ଷର *[PROPOSAL_MAX]);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_setup(ସଂରଚନା ssh *, ଅକ୍ଷର *[PROPOSAL_MAX]);
ଶୂନ୍ୟ	 kex_free_newkeys(ସଂରଚନା newkeys *);
ଶୂନ୍ୟ	 kex_free(ସଂରଚନା kex *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_buf2prop(ସଂରଚନା sshbuf *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ଅକ୍ଷର ***);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_prop2buf(ସଂରଚନା sshbuf *, ଅକ୍ଷର *proposal[PROPOSAL_MAX]);
ଶୂନ୍ୟ	 kex_prop_free(ଅକ୍ଷର **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_load_hostkey(ସଂରଚନା ssh *, ସଂରଚନା sshkey **, ସଂରଚନା sshkey **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_verify_host_ଚାବି(ସଂରଚନା ssh *, ସଂରଚନା sshkey *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_send_kexinit(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_ନିବେଶ_kexinit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_ନିବେଶ_ext_info(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_protocol_error(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_derive_ଚାବିଗୁଡ଼ିକ(ସଂରଚନା ssh *, u_char *, u_int, ଅଚଳ ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_send_newkeys(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_start_rekex(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_server_update_ext_info(ସଂରଚନା ssh *);
ଶୂନ୍ୟ	 kex_set_server_sig_algs(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *);
ଶୂନ୍ୟ	 kex_set_warn_weak_crypto(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 kex_check_warn_weak_crypto(ସଂରଚନା ssh *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kexgex_client(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kexgex_server(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_gen_client(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_gen_server(ସଂରଚନା ssh *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_dh_keypair(ସଂରଚନା kex *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_dh_enc(ସଂରଚନା kex *, ଅଚଳ ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf **,
    ସଂରଚନା sshbuf **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_dh_dec(ସଂରଚନା kex *, ଅଚଳ ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf **);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_ecdh_dec_ଚାବି_group(ସଂରଚନା kex *, ଅଚଳ ସଂରଚନା sshbuf *, EC_ଚାବି *ଚାବି,
	    ଅଚଳ EC_GROUP *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf **);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_ecdh_keypair(ସଂରଚନା kex *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_ecdh_enc(ସଂରଚନା kex *, ଅଚଳ ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf **,
    ସଂରଚନା sshbuf **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_ecdh_dec(ସଂରଚନା kex *, ଅଚଳ ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf **);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_c25519_keypair(ସଂରଚନା kex *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_c25519_enc(ସଂରଚନା kex *, ଅଚଳ ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf **,
    ସଂରଚନା sshbuf **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_c25519_dec(ସଂରଚନା kex *, ଅଚଳ ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf **);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_kem_sntrup761x25519_keypair(ସଂରଚନା kex *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_kem_sntrup761x25519_enc(ସଂରଚନା kex *, ଅଚଳ ସଂରଚନା sshbuf *,
    ସଂରଚନା sshbuf **, ସଂରଚନା sshbuf **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_kem_sntrup761x25519_dec(ସଂରଚନା kex *, ଅଚଳ ସଂରଚନା sshbuf *,
    ସଂରଚନା sshbuf **);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_kem_mlkem768x25519_keypair(ସଂରଚନା kex *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_kem_mlkem768x25519_enc(ସଂରଚନା kex *, ଅଚଳ ସଂରଚନା sshbuf *,
    ସଂରଚନା sshbuf **, ସଂରଚନା sshbuf **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_kem_mlkem768x25519_dec(ସଂରଚନା kex *, ଅଚଳ ସଂରଚନା sshbuf *,
    ସଂରଚନା sshbuf **);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_kem_mlkem768ecdh_keypair(ସଂରଚନା kex *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_kem_mlkem768ecdh_enc(ସଂରଚନା kex *, ଅଚଳ ସଂରଚନା sshbuf *,
    ସଂରଚନା sshbuf **, ସଂରଚନା sshbuf **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_kem_mlkem768ecdh_dec(ସଂରଚନା kex *, ଅଚଳ ସଂରଚନା sshbuf *,
    ସଂରଚନା sshbuf **);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_dh_keygen(ସଂରଚନା kex *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kex_dh_compute_ଚାବି(ସଂରଚନା kex *, BIGNUM *, ସଂରଚନା sshbuf *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 kexgex_hash(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ସଂରଚନା sshbuf *, ଅଚଳ ସଂରଚନା sshbuf *,
    ଅଚଳ ସଂରଚନା sshbuf *, ଅଚଳ ସଂରଚନା sshbuf *, ଅଚଳ ସଂରଚନା sshbuf *,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
    ଅଚଳ BIGNUM *, ଅଚଳ BIGNUM *, ଅଚଳ BIGNUM *,
    ଅଚଳ BIGNUM *, ଅଚଳ u_char *, size_t,
    u_char *, size_t *);

ଶୂନ୍ୟ	kexc25519_keygen(u_char ଚାବି[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	kexc25519_shared_ଚାବି(ଅଚଳ u_char ଚାବି[CURVE25519_SIZE],
    ଅଚଳ u_char pub[CURVE25519_SIZE], ସଂରଚନା sshbuf *out)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	kexc25519_shared_ଚାବି_ext(ଅଚଳ u_char ଚାବି[CURVE25519_SIZE],
    ଅଚଳ u_char pub[CURVE25519_SIZE], ସଂରଚନା sshbuf *out, ପୂର୍ଣ୍ଣସଂଖ୍ୟା)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));

#ଯଦି defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
ଶୂନ୍ୟ	dump_digest(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ u_char *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#endif

#endif
