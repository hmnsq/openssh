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

#অন্তর্ভাৱ "mac.h"
#অন্তর্ভাৱ "crypto_api.h"

#ifdef WITH_OPENSSL
#অন্তর্ভাৱ <openssl/bn.h>
#অন্তর্ভাৱ <openssl/dh.h>
#অন্তর্ভাৱ <openssl/ec.h>
#অন্তর্ভাৱ <openssl/ecdsa.h>
#অন্যথা /* OPENSSL */
#define BIGNUM		শূন্য
#define DH		শূন্য
#define EC_চাবি		শূন্য
#define EC_GROUP	শূন্য
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

গণনা kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_চাবি_ALGS,
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

গণনা kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};

গণনা kex_exchange {
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

সংরচনা sshenc {
	ৱর্ণ	*name;
	ধ্রুৱ সংরচনা sshcipher *cipher;
	পূর্ণাঙ্ক	enabled;
	u_int	চাবি_len;
	u_int	iv_len;
	u_int	block_size;
	u_char	*চাবি;
	u_char	*iv;
};
সংরচনা sshcomp {
	u_int	type;
	পূর্ণাঙ্ক	enabled;
	ৱর্ণ	*name;
};
সংরচনা newkeys {
	সংরচনা sshenc	enc;
	সংরচনা sshmac	mac;
	সংরচনা sshcomp  comp;
};

সংরচনা ssh;
সংরচনা sshbuf;

সংরচনা kex {
	সংরচনা newkeys	*newkeys[MODE_MAX];
	u_int	we_need;
	u_int	dh_need;
	পূর্ণাঙ্ক	server;
	ৱর্ণ	*name;
	ৱর্ণ	*hostkey_alg;
	পূর্ণাঙ্ক	hostkey_type;
	পূর্ণাঙ্ক	hostkey_nid;
	u_int	kex_type;
	ৱর্ণ	*server_sig_algs;
	পূর্ণাঙ্ক	ext_info_c;
	পূর্ণাঙ্ক	ext_info_s;
	পূর্ণাঙ্ক	kex_strict;
	পূর্ণাঙ্ক	ext_info_received;
	সংরচনা sshbuf *my;
	সংরচনা sshbuf *peer;
	সংরচনা sshbuf *client_version;
	সংরচনা sshbuf *server_version;
	সংরচনা sshbuf *session_id;
	সংরচনা sshbuf *initial_sig;
	সংরচনা sshkey *initial_hostkey;
	sig_atomic_t done;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	পূর্ণাঙ্ক	hash_alg;
	পূর্ণাঙ্ক	ec_nid;
	ৱর্ণ	*failed_choice;
	পূর্ণাঙ্ক	(*verify_host_চাবি)(সংরচনা sshkey *, সংরচনা ssh *);
	সংরচনা sshkey *(*load_host_public_চাবি)(পূর্ণাঙ্ক, পূর্ণাঙ্ক, সংরচনা ssh *);
	সংরচনা sshkey *(*load_host_private_চাবি)(পূর্ণাঙ্ক, পূর্ণাঙ্ক, সংরচনা ssh *);
	পূর্ণাঙ্ক	(*host_চাবি_index)(সংরচনা sshkey *, পূর্ণাঙ্ক, সংরচনা ssh *);
	পূর্ণাঙ্ক	(*sign)(সংরচনা ssh *, সংরচনা sshkey *, সংরচনা sshkey *,
	    u_char **, size_t *, ধ্রুৱ u_char *, size_t, ধ্রুৱ ৱর্ণ *);
	পূর্ণাঙ্ক	(*kex[KEX_MAX])(সংরচনা ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_চাবি	*ec_client_চাবি;		/* ECDH */
	ধ্রুৱ EC_GROUP *ec_group;	/* ECDH */
	u_char c25519_client_চাবি[CURVE25519_SIZE]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_SIZE]; /* 25519 */
	u_char sntrup761_client_চাবি[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_চাবি[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	সংরচনা sshbuf *client_pub;
};

পূর্ণাঙ্ক	 kex_name_valid(ধ্রুৱ ৱর্ণ *);
u_int	 kex_type_from_name(ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 kex_hash_from_name(ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 kex_nid_from_name(ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 kex_is_pq_from_name(ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 kex_names_valid(ধ্রুৱ ৱর্ণ *);
ৱর্ণ	*kex_alg_list(ৱর্ণ);
ৱর্ণ	*kex_names_cat(ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 kex_has_any_alg(ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *);
পূর্ণাঙ্ক	 kex_assemble_names(ৱর্ণ **, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *);
শূন্য	 kex_proposal_populate_entries(সংরচনা ssh *, ৱর্ণ *prop[PROPOSAL_MAX],
    ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *);
শূন্য	 kex_proposal_free_entries(ৱর্ণ *prop[PROPOSAL_MAX]);

পূর্ণাঙ্ক	 kex_exchange_identification(সংরচনা ssh *, পূর্ণাঙ্ক, ধ্রুৱ ৱর্ণ *);

সংরচনা kex *kex_new(শূন্য);
পূর্ণাঙ্ক	 kex_ready(সংরচনা ssh *, ৱর্ণ *[PROPOSAL_MAX]);
পূর্ণাঙ্ক	 kex_setup(সংরচনা ssh *, ৱর্ণ *[PROPOSAL_MAX]);
শূন্য	 kex_free_newkeys(সংরচনা newkeys *);
শূন্য	 kex_free(সংরচনা kex *);

পূর্ণাঙ্ক	 kex_buf2prop(সংরচনা sshbuf *, পূর্ণাঙ্ক *, ৱর্ণ ***);
পূর্ণাঙ্ক	 kex_prop2buf(সংরচনা sshbuf *, ৱর্ণ *proposal[PROPOSAL_MAX]);
শূন্য	 kex_prop_free(ৱর্ণ **);
পূর্ণাঙ্ক	 kex_load_hostkey(সংরচনা ssh *, সংরচনা sshkey **, সংরচনা sshkey **);
পূর্ণাঙ্ক	 kex_verify_host_চাবি(সংরচনা ssh *, সংরচনা sshkey *);

পূর্ণাঙ্ক	 kex_send_kexinit(সংরচনা ssh *);
পূর্ণাঙ্ক	 kex_প্ৰবেশ_kexinit(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);
পূর্ণাঙ্ক	 kex_প্ৰবেশ_ext_info(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);
পূর্ণাঙ্ক	 kex_protocol_error(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);
পূর্ণাঙ্ক	 kex_derive_চাবিগুলি(সংরচনা ssh *, u_char *, u_int, ধ্রুৱ সংরচনা sshbuf *);
পূর্ণাঙ্ক	 kex_send_newkeys(সংরচনা ssh *);
পূর্ণাঙ্ক	 kex_start_rekex(সংরচনা ssh *);
পূর্ণাঙ্ক	 kex_server_update_ext_info(সংরচনা ssh *);
শূন্য	 kex_set_server_sig_algs(সংরচনা ssh *, ধ্রুৱ ৱর্ণ *);
শূন্য	 kex_set_warn_weak_crypto(সংরচনা ssh *, পূর্ণাঙ্ক);
শূন্য	 kex_check_warn_weak_crypto(সংরচনা ssh *);

পূর্ণাঙ্ক	 kexgex_client(সংরচনা ssh *);
পূর্ণাঙ্ক	 kexgex_server(সংরচনা ssh *);
পূর্ণাঙ্ক	 kex_gen_client(সংরচনা ssh *);
পূর্ণাঙ্ক	 kex_gen_server(সংরচনা ssh *);

পূর্ণাঙ্ক	 kex_dh_keypair(সংরচনা kex *);
পূর্ণাঙ্ক	 kex_dh_enc(সংরচনা kex *, ধ্রুৱ সংরচনা sshbuf *, সংরচনা sshbuf **,
    সংরচনা sshbuf **);
পূর্ণাঙ্ক	 kex_dh_dec(সংরচনা kex *, ধ্রুৱ সংরচনা sshbuf *, সংরচনা sshbuf **);

পূর্ণাঙ্ক	 kex_ecdh_dec_চাবি_group(সংরচনা kex *, ধ্রুৱ সংরচনা sshbuf *, EC_চাবি *চাবি,
	    ধ্রুৱ EC_GROUP *, পূর্ণাঙ্ক, সংরচনা sshbuf **);

পূর্ণাঙ্ক	 kex_ecdh_keypair(সংরচনা kex *);
পূর্ণাঙ্ক	 kex_ecdh_enc(সংরচনা kex *, ধ্রুৱ সংরচনা sshbuf *, সংরচনা sshbuf **,
    সংরচনা sshbuf **);
পূর্ণাঙ্ক	 kex_ecdh_dec(সংরচনা kex *, ধ্রুৱ সংরচনা sshbuf *, সংরচনা sshbuf **);

পূর্ণাঙ্ক	 kex_c25519_keypair(সংরচনা kex *);
পূর্ণাঙ্ক	 kex_c25519_enc(সংরচনা kex *, ধ্রুৱ সংরচনা sshbuf *, সংরচনা sshbuf **,
    সংরচনা sshbuf **);
পূর্ণাঙ্ক	 kex_c25519_dec(সংরচনা kex *, ধ্রুৱ সংরচনা sshbuf *, সংরচনা sshbuf **);

পূর্ণাঙ্ক	 kex_kem_sntrup761x25519_keypair(সংরচনা kex *);
পূর্ণাঙ্ক	 kex_kem_sntrup761x25519_enc(সংরচনা kex *, ধ্রুৱ সংরচনা sshbuf *,
    সংরচনা sshbuf **, সংরচনা sshbuf **);
পূর্ণাঙ্ক	 kex_kem_sntrup761x25519_dec(সংরচনা kex *, ধ্রুৱ সংরচনা sshbuf *,
    সংরচনা sshbuf **);

পূর্ণাঙ্ক	 kex_kem_mlkem768x25519_keypair(সংরচনা kex *);
পূর্ণাঙ্ক	 kex_kem_mlkem768x25519_enc(সংরচনা kex *, ধ্রুৱ সংরচনা sshbuf *,
    সংরচনা sshbuf **, সংরচনা sshbuf **);
পূর্ণাঙ্ক	 kex_kem_mlkem768x25519_dec(সংরচনা kex *, ধ্রুৱ সংরচনা sshbuf *,
    সংরচনা sshbuf **);

পূর্ণাঙ্ক	 kex_kem_mlkem768ecdh_keypair(সংরচনা kex *);
পূর্ণাঙ্ক	 kex_kem_mlkem768ecdh_enc(সংরচনা kex *, ধ্রুৱ সংরচনা sshbuf *,
    সংরচনা sshbuf **, সংরচনা sshbuf **);
পূর্ণাঙ্ক	 kex_kem_mlkem768ecdh_dec(সংরচনা kex *, ধ্রুৱ সংরচনা sshbuf *,
    সংরচনা sshbuf **);

পূর্ণাঙ্ক	 kex_dh_keygen(সংরচনা kex *);
পূর্ণাঙ্ক	 kex_dh_compute_চাবি(সংরচনা kex *, BIGNUM *, সংরচনা sshbuf *);

পূর্ণাঙ্ক	 kexgex_hash(পূর্ণাঙ্ক, ধ্রুৱ সংরচনা sshbuf *, ধ্রুৱ সংরচনা sshbuf *,
    ধ্রুৱ সংরচনা sshbuf *, ধ্রুৱ সংরচনা sshbuf *, ধ্রুৱ সংরচনা sshbuf *,
    পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক,
    ধ্রুৱ BIGNUM *, ধ্রুৱ BIGNUM *, ধ্রুৱ BIGNUM *,
    ধ্রুৱ BIGNUM *, ধ্রুৱ u_char *, size_t,
    u_char *, size_t *);

শূন্য	kexc25519_keygen(u_char চাবি[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
পূর্ণাঙ্ক	kexc25519_shared_চাবি(ধ্রুৱ u_char চাবি[CURVE25519_SIZE],
    ধ্রুৱ u_char pub[CURVE25519_SIZE], সংরচনা sshbuf *out)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
পূর্ণাঙ্ক	kexc25519_shared_চাবি_ext(ধ্রুৱ u_char চাবি[CURVE25519_SIZE],
    ধ্রুৱ u_char pub[CURVE25519_SIZE], সংরচনা sshbuf *out, পূর্ণাঙ্ক)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));

#যদি defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
শূন্য	dump_digest(ধ্রুৱ ৱর্ণ *, ধ্রুৱ u_char *, পূর্ণাঙ্ক);
#endif

#endif
