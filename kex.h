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
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ KEX_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KEX_H

#ਅਨ੍ਤਰ੍ਭਾਵ "mac.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/dh.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ec.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ecdsa.h>
#ਨਹੀਂਤਾਂ /* OPENSSL */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BIGNUM		ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DH		ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EC_ਕੁੰਜੀ		ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EC_ਸਮੂਹ	ਖਾਲੀ
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KEX_COOKIE_LEN	16

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_DH1				"diffie-hellman-group1-sha1"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_DH14_SHA1			"diffie-hellman-group14-sha1"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_DH14_SHA256			"diffie-hellman-group14-sha256"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_DH16_SHA512			"diffie-hellman-group16-sha512"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_DH18_SHA512			"diffie-hellman-group18-sha512"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_DHGEX_SHA1			"diffie-hellman-group-exchange-sha1"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_DHGEX_SHA256		"diffie-hellman-group-exchange-sha256"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_ECDH_SHA2_NISTP256		"ecdh-sha2-nistp256"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_ECDH_SHA2_NISTP384		"ecdh-sha2-nistp384"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_ECDH_SHA2_NISTP521		"ecdh-sha2-nistp521"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_CURVE25519_SHA256		"curve25519-sha256"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_CURVE25519_SHA256_OLD	"curve25519-sha256@libssh.org"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_SNTRUP761X25519_SHA512	"sntrup761x25519-sha512"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_SNTRUP761X25519_SHA512_OLD	"sntrup761x25519-sha512@openssh.com"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_MLKEM768X25519_SHA256	"mlkem768x25519-sha256"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	KEX_MLKEM768NISTP256_SHA256	"mlkem768nistp256-sha256"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ COMP_NONE	0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ COMP_DELAYED	2

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CURVE25519_ਮਾਪ 32

ਗਿਣਤੀ kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS,
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

ਗਿਣਤੀ kex_modes {
	ਬਹੁਲਕ_ਵਿੱਚ,
	ਬਹੁਲਕ_ਬਾਹਰਲਾ,
	ਬਹੁਲਕ_MAX
};

ਗਿਣਤੀ kex_exchange {
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
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KEX_INIT_ਭੇਜਿਆ			0x0001
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KEX_INITIAL			0x0002
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KEX_HAS_PUBKEY_HOSTBOUND	0x0004
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KEX_RSA_SHA2_256_SUPPORTED	0x0008 /* only set in server for now */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KEX_RSA_SHA2_512_SUPPORTED	0x0010 /* only set in server for now */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KEX_HAS_PING			0x0020
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KEX_HAS_EXT_INFO_ਵਿੱਚ_AUTH	0x0040
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KEX_HAS_NEWAGENT		0x0080 /* only set in client */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KEX_INIT_RECVD			0x0100

/* kex->pq */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KEX_NOT_PQ			0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KEX_IS_PQ			1

ਬਣਤਰ sshenc {
	ਅੱਖਰ	*name;
	ਅਚਲ ਬਣਤਰ sshcipher *cipher;
	ਪੂਰਨ	enabled;
	u_int	ਕੁੰਜੀ_len;
	u_int	iv_len;
	u_int	ਖੰਡ_ਮਾਪ;
	u_char	*ਕੁੰਜੀ;
	u_char	*iv;
};
ਬਣਤਰ sshcomp {
	u_int	type;
	ਪੂਰਨ	enabled;
	ਅੱਖਰ	*name;
};
ਬਣਤਰ newkeys {
	ਬਣਤਰ sshenc	enc;
	ਬਣਤਰ sshmac	mac;
	ਬਣਤਰ sshcomp  comp;
};

ਬਣਤਰ ssh;
ਬਣਤਰ sshbuf;

ਬਣਤਰ kex {
	ਬਣਤਰ newkeys	*newkeys[ਬਹੁਲਕ_MAX];
	u_int	we_need;
	u_int	dh_need;
	ਪੂਰਨ	server;
	ਅੱਖਰ	*name;
	ਅੱਖਰ	*hostkey_alg;
	ਪੂਰਨ	hostkey_type;
	ਪੂਰਨ	hostkey_nid;
	u_int	kex_type;
	ਅੱਖਰ	*server_sig_algs;
	ਪੂਰਨ	ext_info_c;
	ਪੂਰਨ	ext_info_s;
	ਪੂਰਨ	kex_strict;
	ਪੂਰਨ	ext_info_received;
	ਬਣਤਰ sshbuf *my;
	ਬਣਤਰ sshbuf *peer;
	ਬਣਤਰ sshbuf *client_ਸੰਸਕਰਣ;
	ਬਣਤਰ sshbuf *server_ਸੰਸਕਰਣ;
	ਬਣਤਰ sshbuf *session_id;
	ਬਣਤਰ sshbuf *initial_sig;
	ਬਣਤਰ sshkey *initial_hostkey;
	sig_atomic_t ਪੂਰਾ;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	ਪੂਰਨ	hash_alg;
	ਪੂਰਨ	ec_nid;
	ਅੱਖਰ	*failed_choice;
	ਪੂਰਨ	(*verify_host_ਕੁੰਜੀ)(ਬਣਤਰ sshkey *, ਬਣਤਰ ssh *);
	ਬਣਤਰ sshkey *(*ਲੱਦੋ_host_ਜਨਤਕ_ਕੁੰਜੀ)(ਪੂਰਨ, ਪੂਰਨ, ਬਣਤਰ ssh *);
	ਬਣਤਰ sshkey *(*ਲੱਦੋ_host_ਨਿੱਜੀ_ਕੁੰਜੀ)(ਪੂਰਨ, ਪੂਰਨ, ਬਣਤਰ ssh *);
	ਪੂਰਨ	(*host_ਕੁੰਜੀ_ਸੂਚਕਾਂਕ)(ਬਣਤਰ sshkey *, ਪੂਰਨ, ਬਣਤਰ ssh *);
	ਪੂਰਨ	(*sign)(ਬਣਤਰ ssh *, ਬਣਤਰ sshkey *, ਬਣਤਰ sshkey *,
	    u_char **, ਮਾਪ_t *, ਅਚਲ u_char *, ਮਾਪ_t, ਅਚਲ ਅੱਖਰ *);
	ਪੂਰਨ	(*kex[KEX_MAX])(ਬਣਤਰ ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_ਕੁੰਜੀ	*ec_client_ਕੁੰਜੀ;		/* ECDH */
	ਅਚਲ EC_ਸਮੂਹ *ec_ਸਮੂਹ;	/* ECDH */
	u_char c25519_client_ਕੁੰਜੀ[CURVE25519_ਮਾਪ]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_ਮਾਪ]; /* 25519 */
	u_char sntrup761_client_ਕੁੰਜੀ[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_ਕੁੰਜੀ[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	ਬਣਤਰ sshbuf *client_pub;
};

ਪੂਰਨ	 kex_name_valid(ਅਚਲ ਅੱਖਰ *);
u_int	 kex_type_from_name(ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 kex_hash_from_name(ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 kex_nid_from_name(ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 kex_is_pq_from_name(ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 kex_ਨਾਂ_valid(ਅਚਲ ਅੱਖਰ *);
ਅੱਖਰ	*kex_alg_list(ਅੱਖਰ);
ਅੱਖਰ	*kex_ਨਾਂ_cat(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 kex_has_any_alg(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ	 kex_assemble_ਨਾਂ(ਅੱਖਰ **, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ	 kex_proposal_populate_entries(ਬਣਤਰ ssh *, ਅੱਖਰ *prop[PROPOSAL_MAX],
    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ	 kex_proposal_free_entries(ਅੱਖਰ *prop[PROPOSAL_MAX]);

ਪੂਰਨ	 kex_exchange_identification(ਬਣਤਰ ssh *, ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *);

ਬਣਤਰ kex *kex_new(ਖਾਲੀ);
ਪੂਰਨ	 kex_ready(ਬਣਤਰ ssh *, ਅੱਖਰ *[PROPOSAL_MAX]);
ਪੂਰਨ	 kex_ਤਿਆਰੀ(ਬਣਤਰ ssh *, ਅੱਖਰ *[PROPOSAL_MAX]);
ਖਾਲੀ	 kex_free_newkeys(ਬਣਤਰ newkeys *);
ਖਾਲੀ	 kex_free(ਬਣਤਰ kex *);

ਪੂਰਨ	 kex_buf2prop(ਬਣਤਰ sshbuf *, ਪੂਰਨ *, ਅੱਖਰ ***);
ਪੂਰਨ	 kex_prop2buf(ਬਣਤਰ sshbuf *, ਅੱਖਰ *proposal[PROPOSAL_MAX]);
ਖਾਲੀ	 kex_prop_free(ਅੱਖਰ **);
ਪੂਰਨ	 kex_ਲੱਦੋ_hostkey(ਬਣਤਰ ssh *, ਬਣਤਰ sshkey **, ਬਣਤਰ sshkey **);
ਪੂਰਨ	 kex_verify_host_ਕੁੰਜੀ(ਬਣਤਰ ssh *, ਬਣਤਰ sshkey *);

ਪੂਰਨ	 kex_send_kexinit(ਬਣਤਰ ssh *);
ਪੂਰਨ	 kex_ਨਿਵੇਸ਼_kexinit(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਪੂਰਨ	 kex_ਨਿਵੇਸ਼_ext_info(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਪੂਰਨ	 kex_protocol_error(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਪੂਰਨ	 kex_derive_ਕੁੰਜੀਆਂ(ਬਣਤਰ ssh *, u_char *, u_int, ਅਚਲ ਬਣਤਰ sshbuf *);
ਪੂਰਨ	 kex_send_newkeys(ਬਣਤਰ ssh *);
ਪੂਰਨ	 kex_ਸ਼ੁਰੂ_rekex(ਬਣਤਰ ssh *);
ਪੂਰਨ	 kex_server_update_ext_info(ਬਣਤਰ ssh *);
ਖਾਲੀ	 kex_ਸੈੱਟ_server_sig_algs(ਬਣਤਰ ssh *, ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ	 kex_ਸੈੱਟ_warn_weak_crypto(ਬਣਤਰ ssh *, ਪੂਰਨ);
ਖਾਲੀ	 kex_check_warn_weak_crypto(ਬਣਤਰ ssh *);

ਪੂਰਨ	 kexgex_client(ਬਣਤਰ ssh *);
ਪੂਰਨ	 kexgex_server(ਬਣਤਰ ssh *);
ਪੂਰਨ	 kex_gen_client(ਬਣਤਰ ssh *);
ਪੂਰਨ	 kex_gen_server(ਬਣਤਰ ssh *);

ਪੂਰਨ	 kex_dh_keypair(ਬਣਤਰ kex *);
ਪੂਰਨ	 kex_dh_enc(ਬਣਤਰ kex *, ਅਚਲ ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf **,
    ਬਣਤਰ sshbuf **);
ਪੂਰਨ	 kex_dh_dec(ਬਣਤਰ kex *, ਅਚਲ ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf **);

ਪੂਰਨ	 kex_ecdh_dec_ਕੁੰਜੀ_ਸਮੂਹ(ਬਣਤਰ kex *, ਅਚਲ ਬਣਤਰ sshbuf *, EC_ਕੁੰਜੀ *ਕੁੰਜੀ,
	    ਅਚਲ EC_ਸਮੂਹ *, ਪੂਰਨ, ਬਣਤਰ sshbuf **);

ਪੂਰਨ	 kex_ecdh_keypair(ਬਣਤਰ kex *);
ਪੂਰਨ	 kex_ecdh_enc(ਬਣਤਰ kex *, ਅਚਲ ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf **,
    ਬਣਤਰ sshbuf **);
ਪੂਰਨ	 kex_ecdh_dec(ਬਣਤਰ kex *, ਅਚਲ ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf **);

ਪੂਰਨ	 kex_c25519_keypair(ਬਣਤਰ kex *);
ਪੂਰਨ	 kex_c25519_enc(ਬਣਤਰ kex *, ਅਚਲ ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf **,
    ਬਣਤਰ sshbuf **);
ਪੂਰਨ	 kex_c25519_dec(ਬਣਤਰ kex *, ਅਚਲ ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf **);

ਪੂਰਨ	 kex_kem_sntrup761x25519_keypair(ਬਣਤਰ kex *);
ਪੂਰਨ	 kex_kem_sntrup761x25519_enc(ਬਣਤਰ kex *, ਅਚਲ ਬਣਤਰ sshbuf *,
    ਬਣਤਰ sshbuf **, ਬਣਤਰ sshbuf **);
ਪੂਰਨ	 kex_kem_sntrup761x25519_dec(ਬਣਤਰ kex *, ਅਚਲ ਬਣਤਰ sshbuf *,
    ਬਣਤਰ sshbuf **);

ਪੂਰਨ	 kex_kem_mlkem768x25519_keypair(ਬਣਤਰ kex *);
ਪੂਰਨ	 kex_kem_mlkem768x25519_enc(ਬਣਤਰ kex *, ਅਚਲ ਬਣਤਰ sshbuf *,
    ਬਣਤਰ sshbuf **, ਬਣਤਰ sshbuf **);
ਪੂਰਨ	 kex_kem_mlkem768x25519_dec(ਬਣਤਰ kex *, ਅਚਲ ਬਣਤਰ sshbuf *,
    ਬਣਤਰ sshbuf **);

ਪੂਰਨ	 kex_kem_mlkem768ecdh_keypair(ਬਣਤਰ kex *);
ਪੂਰਨ	 kex_kem_mlkem768ecdh_enc(ਬਣਤਰ kex *, ਅਚਲ ਬਣਤਰ sshbuf *,
    ਬਣਤਰ sshbuf **, ਬਣਤਰ sshbuf **);
ਪੂਰਨ	 kex_kem_mlkem768ecdh_dec(ਬਣਤਰ kex *, ਅਚਲ ਬਣਤਰ sshbuf *,
    ਬਣਤਰ sshbuf **);

ਪੂਰਨ	 kex_dh_keygen(ਬਣਤਰ kex *);
ਪੂਰਨ	 kex_dh_compute_ਕੁੰਜੀ(ਬਣਤਰ kex *, BIGNUM *, ਬਣਤਰ sshbuf *);

ਪੂਰਨ	 kexgex_hash(ਪੂਰਨ, ਅਚਲ ਬਣਤਰ sshbuf *, ਅਚਲ ਬਣਤਰ sshbuf *,
    ਅਚਲ ਬਣਤਰ sshbuf *, ਅਚਲ ਬਣਤਰ sshbuf *, ਅਚਲ ਬਣਤਰ sshbuf *,
    ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ,
    ਅਚਲ BIGNUM *, ਅਚਲ BIGNUM *, ਅਚਲ BIGNUM *,
    ਅਚਲ BIGNUM *, ਅਚਲ u_char *, ਮਾਪ_t,
    u_char *, ਮਾਪ_t *);

ਖਾਲੀ	kexc25519_keygen(u_char ਕੁੰਜੀ[CURVE25519_ਮਾਪ], u_char pub[CURVE25519_ਮਾਪ])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_ਮਾਪ)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_ਮਾਪ)));
ਪੂਰਨ	kexc25519_shared_ਕੁੰਜੀ(ਅਚਲ u_char ਕੁੰਜੀ[CURVE25519_ਮਾਪ],
    ਅਚਲ u_char pub[CURVE25519_ਮਾਪ], ਬਣਤਰ sshbuf *ਬਾਹਰਲਾ)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_ਮਾਪ)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_ਮਾਪ)));
ਪੂਰਨ	kexc25519_shared_ਕੁੰਜੀ_ext(ਅਚਲ u_char ਕੁੰਜੀ[CURVE25519_ਮਾਪ],
    ਅਚਲ u_char pub[CURVE25519_ਮਾਪ], ਬਣਤਰ sshbuf *ਬਾਹਰਲਾ, ਪੂਰਨ)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_ਮਾਪ)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_ਮਾਪ)));

#ਜੇ defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
ਖਾਲੀ	dump_digest(ਅਚਲ ਅੱਖਰ *, ਅਚਲ u_char *, ਪੂਰਨ);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ
