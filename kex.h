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

#include "mac.h"
#include "crypto_api.h"

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#དེ་མིན /* OPENSSL */
#define BIGNUM		void
#define DH		void
#define EC_KEY		void
#define EC_GROUP	void
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

ga_nanaa kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_KEY_ALGS,
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

ga_nanaa kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};

ga_nanaa kex_exchange {
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

sa_nracanaa sshenc {
	var_na	*name;
	const sa_nracanaa sshcipher *cipher;
	ཧྲིལ	enabled;
	u_int	key_len;
	u_int	iv_len;
	u_int	block_size;
	u_char	*key;
	u_char	*iv;
};
sa_nracanaa sshcomp {
	u_int	type;
	ཧྲིལ	enabled;
	var_na	*name;
};
sa_nracanaa newkeys {
	sa_nracanaa sshenc	enc;
	sa_nracanaa sshmac	mac;
	sa_nracanaa sshcomp  comp;
};

sa_nracanaa ssh;
sa_nracanaa sshbuf;

sa_nracanaa kex {
	sa_nracanaa newkeys	*newkeys[MODE_MAX];
	u_int	we_need;
	u_int	dh_need;
	ཧྲིལ	server;
	var_na	*name;
	var_na	*hostkey_alg;
	ཧྲིལ	hostkey_type;
	ཧྲིལ	hostkey_nid;
	u_int	kex_type;
	var_na	*server_sig_algs;
	ཧྲིལ	ext_info_c;
	ཧྲིལ	ext_info_s;
	ཧྲིལ	kex_strict;
	ཧྲིལ	ext_info_received;
	sa_nracanaa sshbuf *my;
	sa_nracanaa sshbuf *peer;
	sa_nracanaa sshbuf *client_version;
	sa_nracanaa sshbuf *server_version;
	sa_nracanaa sshbuf *session_id;
	sa_nracanaa sshbuf *initial_sig;
	sa_nracanaa sshkey *initial_hostkey;
	sig_atomic_t done;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	ཧྲིལ	hash_alg;
	ཧྲིལ	ec_nid;
	var_na	*failed_choice;
	ཧྲིལ	(*verify_host_key)(sa_nracanaa sshkey *, sa_nracanaa ssh *);
	sa_nracanaa sshkey *(*load_host_public_key)(ཧྲིལ, ཧྲིལ, sa_nracanaa ssh *);
	sa_nracanaa sshkey *(*load_host_private_key)(ཧྲིལ, ཧྲིལ, sa_nracanaa ssh *);
	ཧྲིལ	(*host_key_index)(sa_nracanaa sshkey *, ཧྲིལ, sa_nracanaa ssh *);
	ཧྲིལ	(*sign)(sa_nracanaa ssh *, sa_nracanaa sshkey *, sa_nracanaa sshkey *,
	    u_char **, size_t *, const u_char *, size_t, const var_na *);
	ཧྲིལ	(*kex[KEX_MAX])(sa_nracanaa ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_KEY	*ec_client_key;		/* ECDH */
	const EC_GROUP *ec_group;	/* ECDH */
	u_char c25519_client_key[CURVE25519_SIZE]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_SIZE]; /* 25519 */
	u_char sntrup761_client_key[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_key[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	sa_nracanaa sshbuf *client_pub;
};

ཧྲིལ	 kex_name_valid(const var_na *);
u_int	 kex_type_from_name(const var_na *);
ཧྲིལ	 kex_hash_from_name(const var_na *);
ཧྲིལ	 kex_nid_from_name(const var_na *);
ཧྲིལ	 kex_is_pq_from_name(const var_na *);
ཧྲིལ	 kex_names_valid(const var_na *);
var_na	*kex_alg_list(var_na);
var_na	*kex_names_cat(const var_na *, const var_na *);
ཧྲིལ	 kex_has_any_alg(const var_na *, const var_na *);
ཧྲིལ	 kex_assemble_names(var_na **, const var_na *, const var_na *);
void	 kex_proposal_populate_entries(sa_nracanaa ssh *, var_na *prop[PROPOSAL_MAX],
    const var_na *, const var_na *, const var_na *, const var_na *, const var_na *);
void	 kex_proposal_free_entries(var_na *prop[PROPOSAL_MAX]);

ཧྲིལ	 kex_exchange_identification(sa_nracanaa ssh *, ཧྲིལ, const var_na *);

sa_nracanaa kex *kex_new(void);
ཧྲིལ	 kex_ready(sa_nracanaa ssh *, var_na *[PROPOSAL_MAX]);
ཧྲིལ	 kex_setup(sa_nracanaa ssh *, var_na *[PROPOSAL_MAX]);
void	 kex_free_newkeys(sa_nracanaa newkeys *);
void	 kex_free(sa_nracanaa kex *);

ཧྲིལ	 kex_buf2prop(sa_nracanaa sshbuf *, ཧྲིལ *, var_na ***);
ཧྲིལ	 kex_prop2buf(sa_nracanaa sshbuf *, var_na *proposal[PROPOSAL_MAX]);
void	 kex_prop_free(var_na **);
ཧྲིལ	 kex_load_hostkey(sa_nracanaa ssh *, sa_nracanaa sshkey **, sa_nracanaa sshkey **);
ཧྲིལ	 kex_verify_host_key(sa_nracanaa ssh *, sa_nracanaa sshkey *);

ཧྲིལ	 kex_send_kexinit(sa_nracanaa ssh *);
ཧྲིལ	 kex_input_kexinit(ཧྲིལ, uint32_t, sa_nracanaa ssh *);
ཧྲིལ	 kex_input_ext_info(ཧྲིལ, uint32_t, sa_nracanaa ssh *);
ཧྲིལ	 kex_protocol_error(ཧྲིལ, uint32_t, sa_nracanaa ssh *);
ཧྲིལ	 kex_derive_keys(sa_nracanaa ssh *, u_char *, u_int, const sa_nracanaa sshbuf *);
ཧྲིལ	 kex_send_newkeys(sa_nracanaa ssh *);
ཧྲིལ	 kex_start_rekex(sa_nracanaa ssh *);
ཧྲིལ	 kex_server_update_ext_info(sa_nracanaa ssh *);
void	 kex_set_server_sig_algs(sa_nracanaa ssh *, const var_na *);
void	 kex_set_warn_weak_crypto(sa_nracanaa ssh *, ཧྲིལ);
void	 kex_check_warn_weak_crypto(sa_nracanaa ssh *);

ཧྲིལ	 kexgex_client(sa_nracanaa ssh *);
ཧྲིལ	 kexgex_server(sa_nracanaa ssh *);
ཧྲིལ	 kex_gen_client(sa_nracanaa ssh *);
ཧྲིལ	 kex_gen_server(sa_nracanaa ssh *);

ཧྲིལ	 kex_dh_keypair(sa_nracanaa kex *);
ཧྲིལ	 kex_dh_enc(sa_nracanaa kex *, const sa_nracanaa sshbuf *, sa_nracanaa sshbuf **,
    sa_nracanaa sshbuf **);
ཧྲིལ	 kex_dh_dec(sa_nracanaa kex *, const sa_nracanaa sshbuf *, sa_nracanaa sshbuf **);

ཧྲིལ	 kex_ecdh_dec_key_group(sa_nracanaa kex *, const sa_nracanaa sshbuf *, EC_KEY *key,
	    const EC_GROUP *, ཧྲིལ, sa_nracanaa sshbuf **);

ཧྲིལ	 kex_ecdh_keypair(sa_nracanaa kex *);
ཧྲིལ	 kex_ecdh_enc(sa_nracanaa kex *, const sa_nracanaa sshbuf *, sa_nracanaa sshbuf **,
    sa_nracanaa sshbuf **);
ཧྲིལ	 kex_ecdh_dec(sa_nracanaa kex *, const sa_nracanaa sshbuf *, sa_nracanaa sshbuf **);

ཧྲིལ	 kex_c25519_keypair(sa_nracanaa kex *);
ཧྲིལ	 kex_c25519_enc(sa_nracanaa kex *, const sa_nracanaa sshbuf *, sa_nracanaa sshbuf **,
    sa_nracanaa sshbuf **);
ཧྲིལ	 kex_c25519_dec(sa_nracanaa kex *, const sa_nracanaa sshbuf *, sa_nracanaa sshbuf **);

ཧྲིལ	 kex_kem_sntrup761x25519_keypair(sa_nracanaa kex *);
ཧྲིལ	 kex_kem_sntrup761x25519_enc(sa_nracanaa kex *, const sa_nracanaa sshbuf *,
    sa_nracanaa sshbuf **, sa_nracanaa sshbuf **);
ཧྲིལ	 kex_kem_sntrup761x25519_dec(sa_nracanaa kex *, const sa_nracanaa sshbuf *,
    sa_nracanaa sshbuf **);

ཧྲིལ	 kex_kem_mlkem768x25519_keypair(sa_nracanaa kex *);
ཧྲིལ	 kex_kem_mlkem768x25519_enc(sa_nracanaa kex *, const sa_nracanaa sshbuf *,
    sa_nracanaa sshbuf **, sa_nracanaa sshbuf **);
ཧྲིལ	 kex_kem_mlkem768x25519_dec(sa_nracanaa kex *, const sa_nracanaa sshbuf *,
    sa_nracanaa sshbuf **);

ཧྲིལ	 kex_kem_mlkem768ecdh_keypair(sa_nracanaa kex *);
ཧྲིལ	 kex_kem_mlkem768ecdh_enc(sa_nracanaa kex *, const sa_nracanaa sshbuf *,
    sa_nracanaa sshbuf **, sa_nracanaa sshbuf **);
ཧྲིལ	 kex_kem_mlkem768ecdh_dec(sa_nracanaa kex *, const sa_nracanaa sshbuf *,
    sa_nracanaa sshbuf **);

ཧྲིལ	 kex_dh_keygen(sa_nracanaa kex *);
ཧྲིལ	 kex_dh_compute_key(sa_nracanaa kex *, BIGNUM *, sa_nracanaa sshbuf *);

ཧྲིལ	 kexgex_hash(ཧྲིལ, const sa_nracanaa sshbuf *, const sa_nracanaa sshbuf *,
    const sa_nracanaa sshbuf *, const sa_nracanaa sshbuf *, const sa_nracanaa sshbuf *,
    ཧྲིལ, ཧྲིལ, ཧྲིལ,
    const BIGNUM *, const BIGNUM *, const BIGNUM *,
    const BIGNUM *, const u_char *, size_t,
    u_char *, size_t *);

void	kexc25519_keygen(u_char key[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
ཧྲིལ	kexc25519_shared_key(const u_char key[CURVE25519_SIZE],
    const u_char pub[CURVE25519_SIZE], sa_nracanaa sshbuf *out)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
ཧྲིལ	kexc25519_shared_key_ext(const u_char key[CURVE25519_SIZE],
    const u_char pub[CURVE25519_SIZE], sa_nracanaa sshbuf *out, ཧྲིལ)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));

#གལ་ཏེ defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
void	dump_digest(const var_na *, const u_char *, ཧྲིལ);
#endif

#endif
