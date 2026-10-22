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

#અન્તર્ભાવ "mac.h"
#અન્તર્ભાવ "crypto_api.h"

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/dh.h>
#અન્તર્ભાવ <openssl/ec.h>
#અન્તર્ભાવ <openssl/ecdsa.h>
#નહીંતર /* OPENSSL */
#define BIGNUM		શૂન્ય
#define DH		શૂન્ય
#define EC_ચાવી		શૂન્ય
#define EC_GROUP	શૂન્ય
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

ગણના kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_ચાવી_ALGS,
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

ગણના kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};

ગણના kex_exchange {
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

સંરચના sshenc {
	અક્ષર	*name;
	અચલ સંરચના sshcipher *cipher;
	પૂર્ણાંક	enabled;
	u_int	ચાવી_len;
	u_int	iv_len;
	u_int	block_size;
	u_char	*ચાવી;
	u_char	*iv;
};
સંરચના sshcomp {
	u_int	type;
	પૂર્ણાંક	enabled;
	અક્ષર	*name;
};
સંરચના newkeys {
	સંરચના sshenc	enc;
	સંરચના sshmac	mac;
	સંરચના sshcomp  comp;
};

સંરચના ssh;
સંરચના sshbuf;

સંરચના kex {
	સંરચના newkeys	*newkeys[MODE_MAX];
	u_int	we_need;
	u_int	dh_need;
	પૂર્ણાંક	server;
	અક્ષર	*name;
	અક્ષર	*hostkey_alg;
	પૂર્ણાંક	hostkey_type;
	પૂર્ણાંક	hostkey_nid;
	u_int	kex_type;
	અક્ષર	*server_sig_algs;
	પૂર્ણાંક	ext_info_c;
	પૂર્ણાંક	ext_info_s;
	પૂર્ણાંક	kex_strict;
	પૂર્ણાંક	ext_info_received;
	સંરચના sshbuf *my;
	સંરચના sshbuf *peer;
	સંરચના sshbuf *client_version;
	સંરચના sshbuf *server_version;
	સંરચના sshbuf *session_id;
	સંરચના sshbuf *initial_sig;
	સંરચના sshkey *initial_hostkey;
	sig_atomic_t done;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	પૂર્ણાંક	hash_alg;
	પૂર્ણાંક	ec_nid;
	અક્ષર	*failed_choice;
	પૂર્ણાંક	(*verify_host_ચાવી)(સંરચના sshkey *, સંરચના ssh *);
	સંરચના sshkey *(*load_host_public_ચાવી)(પૂર્ણાંક, પૂર્ણાંક, સંરચના ssh *);
	સંરચના sshkey *(*load_host_private_ચાવી)(પૂર્ણાંક, પૂર્ણાંક, સંરચના ssh *);
	પૂર્ણાંક	(*host_ચાવી_index)(સંરચના sshkey *, પૂર્ણાંક, સંરચના ssh *);
	પૂર્ણાંક	(*sign)(સંરચના ssh *, સંરચના sshkey *, સંરચના sshkey *,
	    u_char **, size_t *, અચલ u_char *, size_t, અચલ અક્ષર *);
	પૂર્ણાંક	(*kex[KEX_MAX])(સંરચના ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_ચાવી	*ec_client_ચાવી;		/* ECDH */
	અચલ EC_GROUP *ec_group;	/* ECDH */
	u_char c25519_client_ચાવી[CURVE25519_SIZE]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_SIZE]; /* 25519 */
	u_char sntrup761_client_ચાવી[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_ચાવી[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	સંરચના sshbuf *client_pub;
};

પૂર્ણાંક	 kex_name_valid(અચલ અક્ષર *);
u_int	 kex_type_from_name(અચલ અક્ષર *);
પૂર્ણાંક	 kex_hash_from_name(અચલ અક્ષર *);
પૂર્ણાંક	 kex_nid_from_name(અચલ અક્ષર *);
પૂર્ણાંક	 kex_is_pq_from_name(અચલ અક્ષર *);
પૂર્ણાંક	 kex_names_valid(અચલ અક્ષર *);
અક્ષર	*kex_alg_list(અક્ષર);
અક્ષર	*kex_names_cat(અચલ અક્ષર *, અચલ અક્ષર *);
પૂર્ણાંક	 kex_has_any_alg(અચલ અક્ષર *, અચલ અક્ષર *);
પૂર્ણાંક	 kex_assemble_names(અક્ષર **, અચલ અક્ષર *, અચલ અક્ષર *);
શૂન્ય	 kex_proposal_populate_entries(સંરચના ssh *, અક્ષર *prop[PROPOSAL_MAX],
    અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *);
શૂન્ય	 kex_proposal_free_entries(અક્ષર *prop[PROPOSAL_MAX]);

પૂર્ણાંક	 kex_exchange_identification(સંરચના ssh *, પૂર્ણાંક, અચલ અક્ષર *);

સંરચના kex *kex_new(શૂન્ય);
પૂર્ણાંક	 kex_ready(સંરચના ssh *, અક્ષર *[PROPOSAL_MAX]);
પૂર્ણાંક	 kex_setup(સંરચના ssh *, અક્ષર *[PROPOSAL_MAX]);
શૂન્ય	 kex_free_newkeys(સંરચના newkeys *);
શૂન્ય	 kex_free(સંરચના kex *);

પૂર્ણાંક	 kex_buf2prop(સંરચના sshbuf *, પૂર્ણાંક *, અક્ષર ***);
પૂર્ણાંક	 kex_prop2buf(સંરચના sshbuf *, અક્ષર *proposal[PROPOSAL_MAX]);
શૂન્ય	 kex_prop_free(અક્ષર **);
પૂર્ણાંક	 kex_load_hostkey(સંરચના ssh *, સંરચના sshkey **, સંરચના sshkey **);
પૂર્ણાંક	 kex_verify_host_ચાવી(સંરચના ssh *, સંરચના sshkey *);

પૂર્ણાંક	 kex_send_kexinit(સંરચના ssh *);
પૂર્ણાંક	 kex_આગત_kexinit(પૂર્ણાંક, uint32_t, સંરચના ssh *);
પૂર્ણાંક	 kex_આગત_ext_info(પૂર્ણાંક, uint32_t, સંરચના ssh *);
પૂર્ણાંક	 kex_protocol_error(પૂર્ણાંક, uint32_t, સંરચના ssh *);
પૂર્ણાંક	 kex_derive_ચાવીઓ(સંરચના ssh *, u_char *, u_int, અચલ સંરચના sshbuf *);
પૂર્ણાંક	 kex_send_newkeys(સંરચના ssh *);
પૂર્ણાંક	 kex_start_rekex(સંરચના ssh *);
પૂર્ણાંક	 kex_server_update_ext_info(સંરચના ssh *);
શૂન્ય	 kex_set_server_sig_algs(સંરચના ssh *, અચલ અક્ષર *);
શૂન્ય	 kex_set_warn_weak_crypto(સંરચના ssh *, પૂર્ણાંક);
શૂન્ય	 kex_check_warn_weak_crypto(સંરચના ssh *);

પૂર્ણાંક	 kexgex_client(સંરચના ssh *);
પૂર્ણાંક	 kexgex_server(સંરચના ssh *);
પૂર્ણાંક	 kex_gen_client(સંરચના ssh *);
પૂર્ણાંક	 kex_gen_server(સંરચના ssh *);

પૂર્ણાંક	 kex_dh_keypair(સંરચના kex *);
પૂર્ણાંક	 kex_dh_enc(સંરચના kex *, અચલ સંરચના sshbuf *, સંરચના sshbuf **,
    સંરચના sshbuf **);
પૂર્ણાંક	 kex_dh_dec(સંરચના kex *, અચલ સંરચના sshbuf *, સંરચના sshbuf **);

પૂર્ણાંક	 kex_ecdh_dec_ચાવી_group(સંરચના kex *, અચલ સંરચના sshbuf *, EC_ચાવી *ચાવી,
	    અચલ EC_GROUP *, પૂર્ણાંક, સંરચના sshbuf **);

પૂર્ણાંક	 kex_ecdh_keypair(સંરચના kex *);
પૂર્ણાંક	 kex_ecdh_enc(સંરચના kex *, અચલ સંરચના sshbuf *, સંરચના sshbuf **,
    સંરચના sshbuf **);
પૂર્ણાંક	 kex_ecdh_dec(સંરચના kex *, અચલ સંરચના sshbuf *, સંરચના sshbuf **);

પૂર્ણાંક	 kex_c25519_keypair(સંરચના kex *);
પૂર્ણાંક	 kex_c25519_enc(સંરચના kex *, અચલ સંરચના sshbuf *, સંરચના sshbuf **,
    સંરચના sshbuf **);
પૂર્ણાંક	 kex_c25519_dec(સંરચના kex *, અચલ સંરચના sshbuf *, સંરચના sshbuf **);

પૂર્ણાંક	 kex_kem_sntrup761x25519_keypair(સંરચના kex *);
પૂર્ણાંક	 kex_kem_sntrup761x25519_enc(સંરચના kex *, અચલ સંરચના sshbuf *,
    સંરચના sshbuf **, સંરચના sshbuf **);
પૂર્ણાંક	 kex_kem_sntrup761x25519_dec(સંરચના kex *, અચલ સંરચના sshbuf *,
    સંરચના sshbuf **);

પૂર્ણાંક	 kex_kem_mlkem768x25519_keypair(સંરચના kex *);
પૂર્ણાંક	 kex_kem_mlkem768x25519_enc(સંરચના kex *, અચલ સંરચના sshbuf *,
    સંરચના sshbuf **, સંરચના sshbuf **);
પૂર્ણાંક	 kex_kem_mlkem768x25519_dec(સંરચના kex *, અચલ સંરચના sshbuf *,
    સંરચના sshbuf **);

પૂર્ણાંક	 kex_kem_mlkem768ecdh_keypair(સંરચના kex *);
પૂર્ણાંક	 kex_kem_mlkem768ecdh_enc(સંરચના kex *, અચલ સંરચના sshbuf *,
    સંરચના sshbuf **, સંરચના sshbuf **);
પૂર્ણાંક	 kex_kem_mlkem768ecdh_dec(સંરચના kex *, અચલ સંરચના sshbuf *,
    સંરચના sshbuf **);

પૂર્ણાંક	 kex_dh_keygen(સંરચના kex *);
પૂર્ણાંક	 kex_dh_compute_ચાવી(સંરચના kex *, BIGNUM *, સંરચના sshbuf *);

પૂર્ણાંક	 kexgex_hash(પૂર્ણાંક, અચલ સંરચના sshbuf *, અચલ સંરચના sshbuf *,
    અચલ સંરચના sshbuf *, અચલ સંરચના sshbuf *, અચલ સંરચના sshbuf *,
    પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક,
    અચલ BIGNUM *, અચલ BIGNUM *, અચલ BIGNUM *,
    અચલ BIGNUM *, અચલ u_char *, size_t,
    u_char *, size_t *);

શૂન્ય	kexc25519_keygen(u_char ચાવી[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
પૂર્ણાંક	kexc25519_shared_ચાવી(અચલ u_char ચાવી[CURVE25519_SIZE],
    અચલ u_char pub[CURVE25519_SIZE], સંરચના sshbuf *out)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
પૂર્ણાંક	kexc25519_shared_ચાવી_ext(અચલ u_char ચાવી[CURVE25519_SIZE],
    અચલ u_char pub[CURVE25519_SIZE], સંરચના sshbuf *out, પૂર્ણાંક)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));

#જો defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
શૂન્ય	dump_digest(અચલ અક્ષર *, અચલ u_char *, પૂર્ણાંક);
#endif

#endif
