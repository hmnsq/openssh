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
#నిర్వచితం_కాకపోతే KEX_H
#నిర్వచించు KEX_H

#అన్తర్భావ "mac.h"
#అన్తర్భావ "crypto_api.h"

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/dh.h>
#అన్తర్భావ <openssl/ec.h>
#అన్తర్భావ <openssl/ecdsa.h>
#లేకపోతే /* OPENSSL */
#నిర్వచించు BIGNUM		శూన్య
#నిర్వచించు DH		శూన్య
#నిర్వచించు EC_కీలకం		శూన్య
#నిర్వచించు EC_సమూహం	శూన్య
#అయితే_ముగింపు /* WITH_OPENSSL */

#నిర్వచించు KEX_COOKIE_LEN	16

#నిర్వచించు	KEX_DH1				"diffie-hellman-group1-sha1"
#నిర్వచించు	KEX_DH14_SHA1			"diffie-hellman-group14-sha1"
#నిర్వచించు	KEX_DH14_SHA256			"diffie-hellman-group14-sha256"
#నిర్వచించు	KEX_DH16_SHA512			"diffie-hellman-group16-sha512"
#నిర్వచించు	KEX_DH18_SHA512			"diffie-hellman-group18-sha512"
#నిర్వచించు	KEX_DHGEX_SHA1			"diffie-hellman-group-exchange-sha1"
#నిర్వచించు	KEX_DHGEX_SHA256		"diffie-hellman-group-exchange-sha256"
#నిర్వచించు	KEX_ECDH_SHA2_NISTP256		"ecdh-sha2-nistp256"
#నిర్వచించు	KEX_ECDH_SHA2_NISTP384		"ecdh-sha2-nistp384"
#నిర్వచించు	KEX_ECDH_SHA2_NISTP521		"ecdh-sha2-nistp521"
#నిర్వచించు	KEX_CURVE25519_SHA256		"curve25519-sha256"
#నిర్వచించు	KEX_CURVE25519_SHA256_OLD	"curve25519-sha256@libssh.org"
#నిర్వచించు	KEX_SNTRUP761X25519_SHA512	"sntrup761x25519-sha512"
#నిర్వచించు	KEX_SNTRUP761X25519_SHA512_OLD	"sntrup761x25519-sha512@openssh.com"
#నిర్వచించు	KEX_MLKEM768X25519_SHA256	"mlkem768x25519-sha256"
#నిర్వచించు	KEX_MLKEM768NISTP256_SHA256	"mlkem768nistp256-sha256"

#నిర్వచించు COMP_NONE	0
#నిర్వచించు COMP_DELAYED	2

#నిర్వచించు CURVE25519_కొలత 32

గణన kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_కీలకం_ALGS,
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

గణన kex_modes {
	బహుళకం_లోపల,
	బహుళకం_బహిర్గతం,
	బహుళకం_MAX
};

గణన kex_exchange {
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
#నిర్వచించు KEX_INIT_పంపిన			0x0001
#నిర్వచించు KEX_INITIAL			0x0002
#నిర్వచించు KEX_HAS_PUBKEY_HOSTBOUND	0x0004
#నిర్వచించు KEX_RSA_SHA2_256_SUPPORTED	0x0008 /* only set in server for now */
#నిర్వచించు KEX_RSA_SHA2_512_SUPPORTED	0x0010 /* only set in server for now */
#నిర్వచించు KEX_HAS_PING			0x0020
#నిర్వచించు KEX_HAS_EXT_INFO_లోపల_AUTH	0x0040
#నిర్వచించు KEX_HAS_NEWAGENT		0x0080 /* only set in client */
#నిర్వచించు KEX_INIT_RECVD			0x0100

/* kex->pq */
#నిర్వచించు KEX_NOT_PQ			0
#నిర్వచించు KEX_IS_PQ			1

నిర్మాణం sshenc {
	అక్షరం	*name;
	స్థిరరాశి నిర్మాణం sshcipher *cipher;
	పూర్ణాంకం	enabled;
	u_int	కీలకం_len;
	u_int	iv_len;
	u_int	ఖండం_కొలత;
	u_char	*కీలకం;
	u_char	*iv;
};
నిర్మాణం sshcomp {
	u_int	type;
	పూర్ణాంకం	enabled;
	అక్షరం	*name;
};
నిర్మాణం newkeys {
	నిర్మాణం sshenc	enc;
	నిర్మాణం sshmac	mac;
	నిర్మాణం sshcomp  comp;
};

నిర్మాణం ssh;
నిర్మాణం sshbuf;

నిర్మాణం kex {
	నిర్మాణం newkeys	*newkeys[బహుళకం_MAX];
	u_int	we_need;
	u_int	dh_need;
	పూర్ణాంకం	server;
	అక్షరం	*name;
	అక్షరం	*hostkey_alg;
	పూర్ణాంకం	hostkey_type;
	పూర్ణాంకం	hostkey_nid;
	u_int	kex_type;
	అక్షరం	*server_sig_algs;
	పూర్ణాంకం	ext_info_c;
	పూర్ణాంకం	ext_info_s;
	పూర్ణాంకం	kex_strict;
	పూర్ణాంకం	ext_info_received;
	నిర్మాణం sshbuf *my;
	నిర్మాణం sshbuf *peer;
	నిర్మాణం sshbuf *client_సంస్కరణ;
	నిర్మాణం sshbuf *server_సంస్కరణ;
	నిర్మాణం sshbuf *session_id;
	నిర్మాణం sshbuf *initial_sig;
	నిర్మాణం sshkey *initial_hostkey;
	sig_atomic_t పూర్తి;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	పూర్ణాంకం	hash_alg;
	పూర్ణాంకం	ec_nid;
	అక్షరం	*failed_choice;
	పూర్ణాంకం	(*verify_host_కీలకం)(నిర్మాణం sshkey *, నిర్మాణం ssh *);
	నిర్మాణం sshkey *(*ఎక్కించు_host_ప్రజా_కీలకం)(పూర్ణాంకం, పూర్ణాంకం, నిర్మాణం ssh *);
	నిర్మాణం sshkey *(*ఎక్కించు_host_వ్యక్తిగత_కీలకం)(పూర్ణాంకం, పూర్ణాంకం, నిర్మాణం ssh *);
	పూర్ణాంకం	(*host_కీలకం_సూచీ)(నిర్మాణం sshkey *, పూర్ణాంకం, నిర్మాణం ssh *);
	పూర్ణాంకం	(*sign)(నిర్మాణం ssh *, నిర్మాణం sshkey *, నిర్మాణం sshkey *,
	    u_char **, కొలత_t *, స్థిరరాశి u_char *, కొలత_t, స్థిరరాశి అక్షరం *);
	పూర్ణాంకం	(*kex[KEX_MAX])(నిర్మాణం ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_కీలకం	*ec_client_కీలకం;		/* ECDH */
	స్థిరరాశి EC_సమూహం *ec_సమూహం;	/* ECDH */
	u_char c25519_client_కీలకం[CURVE25519_కొలత]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_కొలత]; /* 25519 */
	u_char sntrup761_client_కీలకం[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_కీలకం[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	నిర్మాణం sshbuf *client_pub;
};

పూర్ణాంకం	 kex_name_valid(స్థిరరాశి అక్షరం *);
u_int	 kex_type_from_name(స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 kex_hash_from_name(స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 kex_nid_from_name(స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 kex_is_pq_from_name(స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 kex_పేర్లు_valid(స్థిరరాశి అక్షరం *);
అక్షరం	*kex_alg_list(అక్షరం);
అక్షరం	*kex_పేర్లు_cat(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 kex_has_any_alg(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	 kex_assemble_పేర్లు(అక్షరం **, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
శూన్య	 kex_proposal_populate_entries(నిర్మాణం ssh *, అక్షరం *prop[PROPOSAL_MAX],
    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);
శూన్య	 kex_proposal_free_entries(అక్షరం *prop[PROPOSAL_MAX]);

పూర్ణాంకం	 kex_exchange_identification(నిర్మాణం ssh *, పూర్ణాంకం, స్థిరరాశి అక్షరం *);

నిర్మాణం kex *kex_new(శూన్య);
పూర్ణాంకం	 kex_ready(నిర్మాణం ssh *, అక్షరం *[PROPOSAL_MAX]);
పూర్ణాంకం	 kex_అమరిక(నిర్మాణం ssh *, అక్షరం *[PROPOSAL_MAX]);
శూన్య	 kex_free_newkeys(నిర్మాణం newkeys *);
శూన్య	 kex_free(నిర్మాణం kex *);

పూర్ణాంకం	 kex_buf2prop(నిర్మాణం sshbuf *, పూర్ణాంకం *, అక్షరం ***);
పూర్ణాంకం	 kex_prop2buf(నిర్మాణం sshbuf *, అక్షరం *proposal[PROPOSAL_MAX]);
శూన్య	 kex_prop_free(అక్షరం **);
పూర్ణాంకం	 kex_ఎక్కించు_hostkey(నిర్మాణం ssh *, నిర్మాణం sshkey **, నిర్మాణం sshkey **);
పూర్ణాంకం	 kex_verify_host_కీలకం(నిర్మాణం ssh *, నిర్మాణం sshkey *);

పూర్ణాంకం	 kex_send_kexinit(నిర్మాణం ssh *);
పూర్ణాంకం	 kex_ఆదానం_kexinit(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
పూర్ణాంకం	 kex_ఆదానం_ext_info(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
పూర్ణాంకం	 kex_protocol_error(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
పూర్ణాంకం	 kex_derive_కీలకాలు(నిర్మాణం ssh *, u_char *, u_int, స్థిరరాశి నిర్మాణం sshbuf *);
పూర్ణాంకం	 kex_send_newkeys(నిర్మాణం ssh *);
పూర్ణాంకం	 kex_ప్రారంభం_rekex(నిర్మాణం ssh *);
పూర్ణాంకం	 kex_server_update_ext_info(నిర్మాణం ssh *);
శూన్య	 kex_సమితి_server_sig_algs(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *);
శూన్య	 kex_సమితి_warn_weak_crypto(నిర్మాణం ssh *, పూర్ణాంకం);
శూన్య	 kex_check_warn_weak_crypto(నిర్మాణం ssh *);

పూర్ణాంకం	 kexgex_client(నిర్మాణం ssh *);
పూర్ణాంకం	 kexgex_server(నిర్మాణం ssh *);
పూర్ణాంకం	 kex_gen_client(నిర్మాణం ssh *);
పూర్ణాంకం	 kex_gen_server(నిర్మాణం ssh *);

పూర్ణాంకం	 kex_dh_keypair(నిర్మాణం kex *);
పూర్ణాంకం	 kex_dh_enc(నిర్మాణం kex *, స్థిరరాశి నిర్మాణం sshbuf *, నిర్మాణం sshbuf **,
    నిర్మాణం sshbuf **);
పూర్ణాంకం	 kex_dh_dec(నిర్మాణం kex *, స్థిరరాశి నిర్మాణం sshbuf *, నిర్మాణం sshbuf **);

పూర్ణాంకం	 kex_ecdh_dec_కీలకం_సమూహం(నిర్మాణం kex *, స్థిరరాశి నిర్మాణం sshbuf *, EC_కీలకం *కీలకం,
	    స్థిరరాశి EC_సమూహం *, పూర్ణాంకం, నిర్మాణం sshbuf **);

పూర్ణాంకం	 kex_ecdh_keypair(నిర్మాణం kex *);
పూర్ణాంకం	 kex_ecdh_enc(నిర్మాణం kex *, స్థిరరాశి నిర్మాణం sshbuf *, నిర్మాణం sshbuf **,
    నిర్మాణం sshbuf **);
పూర్ణాంకం	 kex_ecdh_dec(నిర్మాణం kex *, స్థిరరాశి నిర్మాణం sshbuf *, నిర్మాణం sshbuf **);

పూర్ణాంకం	 kex_c25519_keypair(నిర్మాణం kex *);
పూర్ణాంకం	 kex_c25519_enc(నిర్మాణం kex *, స్థిరరాశి నిర్మాణం sshbuf *, నిర్మాణం sshbuf **,
    నిర్మాణం sshbuf **);
పూర్ణాంకం	 kex_c25519_dec(నిర్మాణం kex *, స్థిరరాశి నిర్మాణం sshbuf *, నిర్మాణం sshbuf **);

పూర్ణాంకం	 kex_kem_sntrup761x25519_keypair(నిర్మాణం kex *);
పూర్ణాంకం	 kex_kem_sntrup761x25519_enc(నిర్మాణం kex *, స్థిరరాశి నిర్మాణం sshbuf *,
    నిర్మాణం sshbuf **, నిర్మాణం sshbuf **);
పూర్ణాంకం	 kex_kem_sntrup761x25519_dec(నిర్మాణం kex *, స్థిరరాశి నిర్మాణం sshbuf *,
    నిర్మాణం sshbuf **);

పూర్ణాంకం	 kex_kem_mlkem768x25519_keypair(నిర్మాణం kex *);
పూర్ణాంకం	 kex_kem_mlkem768x25519_enc(నిర్మాణం kex *, స్థిరరాశి నిర్మాణం sshbuf *,
    నిర్మాణం sshbuf **, నిర్మాణం sshbuf **);
పూర్ణాంకం	 kex_kem_mlkem768x25519_dec(నిర్మాణం kex *, స్థిరరాశి నిర్మాణం sshbuf *,
    నిర్మాణం sshbuf **);

పూర్ణాంకం	 kex_kem_mlkem768ecdh_keypair(నిర్మాణం kex *);
పూర్ణాంకం	 kex_kem_mlkem768ecdh_enc(నిర్మాణం kex *, స్థిరరాశి నిర్మాణం sshbuf *,
    నిర్మాణం sshbuf **, నిర్మాణం sshbuf **);
పూర్ణాంకం	 kex_kem_mlkem768ecdh_dec(నిర్మాణం kex *, స్థిరరాశి నిర్మాణం sshbuf *,
    నిర్మాణం sshbuf **);

పూర్ణాంకం	 kex_dh_keygen(నిర్మాణం kex *);
పూర్ణాంకం	 kex_dh_compute_కీలకం(నిర్మాణం kex *, BIGNUM *, నిర్మాణం sshbuf *);

పూర్ణాంకం	 kexgex_hash(పూర్ణాంకం, స్థిరరాశి నిర్మాణం sshbuf *, స్థిరరాశి నిర్మాణం sshbuf *,
    స్థిరరాశి నిర్మాణం sshbuf *, స్థిరరాశి నిర్మాణం sshbuf *, స్థిరరాశి నిర్మాణం sshbuf *,
    పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం,
    స్థిరరాశి BIGNUM *, స్థిరరాశి BIGNUM *, స్థిరరాశి BIGNUM *,
    స్థిరరాశి BIGNUM *, స్థిరరాశి u_char *, కొలత_t,
    u_char *, కొలత_t *);

శూన్య	kexc25519_keygen(u_char కీలకం[CURVE25519_కొలత], u_char pub[CURVE25519_కొలత])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_కొలత)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_కొలత)));
పూర్ణాంకం	kexc25519_shared_కీలకం(స్థిరరాశి u_char కీలకం[CURVE25519_కొలత],
    స్థిరరాశి u_char pub[CURVE25519_కొలత], నిర్మాణం sshbuf *బహిర్గతం)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_కొలత)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_కొలత)));
పూర్ణాంకం	kexc25519_shared_కీలకం_ext(స్థిరరాశి u_char కీలకం[CURVE25519_కొలత],
    స్థిరరాశి u_char pub[CURVE25519_కొలత], నిర్మాణం sshbuf *బహిర్గతం, పూర్ణాంకం)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_కొలత)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_కొలత)));

#ఒకవేళ defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
శూన్య	dump_digest(స్థిరరాశి అక్షరం *, స్థిరరాశి u_char *, పూర్ణాంకం);
#అయితే_ముగింపు

#అయితే_ముగింపు
