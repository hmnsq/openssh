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

#അന്തര്ഭാവ "mac.h"
#അന്തര്ഭാവ "crypto_api.h"

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/dh.h>
#അന്തര്ഭാവ <openssl/ec.h>
#അന്തര്ഭാവ <openssl/ecdsa.h>
#അല്ലെങ്കിൽ /* OPENSSL */
#define BIGNUM		ശൂന്യം
#define DH		ശൂന്യം
#define EC_താക്കോൽ		ശൂന്യം
#define EC_GROUP	ശൂന്യം
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

എണ്ണൽ kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS,
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

എണ്ണൽ kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};

എണ്ണൽ kex_exchange {
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

ഘടന sshenc {
	അക്ഷരം	*name;
	സ്ഥിരം ഘടന sshcipher *cipher;
	പൂർണ്ണസംഖ്യ	enabled;
	u_int	താക്കോൽ_len;
	u_int	iv_len;
	u_int	block_size;
	u_char	*താക്കോൽ;
	u_char	*iv;
};
ഘടന sshcomp {
	u_int	type;
	പൂർണ്ണസംഖ്യ	enabled;
	അക്ഷരം	*name;
};
ഘടന newkeys {
	ഘടന sshenc	enc;
	ഘടന sshmac	mac;
	ഘടന sshcomp  comp;
};

ഘടന ssh;
ഘടന sshbuf;

ഘടന kex {
	ഘടന newkeys	*newkeys[MODE_MAX];
	u_int	we_need;
	u_int	dh_need;
	പൂർണ്ണസംഖ്യ	server;
	അക്ഷരം	*name;
	അക്ഷരം	*hostkey_alg;
	പൂർണ്ണസംഖ്യ	hostkey_type;
	പൂർണ്ണസംഖ്യ	hostkey_nid;
	u_int	kex_type;
	അക്ഷരം	*server_sig_algs;
	പൂർണ്ണസംഖ്യ	ext_info_c;
	പൂർണ്ണസംഖ്യ	ext_info_s;
	പൂർണ്ണസംഖ്യ	kex_strict;
	പൂർണ്ണസംഖ്യ	ext_info_received;
	ഘടന sshbuf *my;
	ഘടന sshbuf *peer;
	ഘടന sshbuf *client_version;
	ഘടന sshbuf *server_version;
	ഘടന sshbuf *session_id;
	ഘടന sshbuf *initial_sig;
	ഘടന sshkey *initial_hostkey;
	sig_atomic_t done;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	പൂർണ്ണസംഖ്യ	hash_alg;
	പൂർണ്ണസംഖ്യ	ec_nid;
	അക്ഷരം	*failed_choice;
	പൂർണ്ണസംഖ്യ	(*verify_host_താക്കോൽ)(ഘടന sshkey *, ഘടന ssh *);
	ഘടന sshkey *(*load_host_public_താക്കോൽ)(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, ഘടന ssh *);
	ഘടന sshkey *(*load_host_private_താക്കോൽ)(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, ഘടന ssh *);
	പൂർണ്ണസംഖ്യ	(*host_താക്കോൽ_index)(ഘടന sshkey *, പൂർണ്ണസംഖ്യ, ഘടന ssh *);
	പൂർണ്ണസംഖ്യ	(*sign)(ഘടന ssh *, ഘടന sshkey *, ഘടന sshkey *,
	    u_char **, size_t *, സ്ഥിരം u_char *, size_t, സ്ഥിരം അക്ഷരം *);
	പൂർണ്ണസംഖ്യ	(*kex[KEX_MAX])(ഘടന ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_താക്കോൽ	*ec_client_താക്കോൽ;		/* ECDH */
	സ്ഥിരം EC_GROUP *ec_group;	/* ECDH */
	u_char c25519_client_താക്കോൽ[CURVE25519_SIZE]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_SIZE]; /* 25519 */
	u_char sntrup761_client_താക്കോൽ[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_താക്കോൽ[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	ഘടന sshbuf *client_pub;
};

പൂർണ്ണസംഖ്യ	 kex_name_valid(സ്ഥിരം അക്ഷരം *);
u_int	 kex_type_from_name(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 kex_hash_from_name(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 kex_nid_from_name(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 kex_is_pq_from_name(സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 kex_names_valid(സ്ഥിരം അക്ഷരം *);
അക്ഷരം	*kex_alg_list(അക്ഷരം);
അക്ഷരം	*kex_names_cat(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 kex_has_any_alg(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 kex_assemble_names(അക്ഷരം **, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
ശൂന്യം	 kex_proposal_populate_entries(ഘടന ssh *, അക്ഷരം *prop[PROPOSAL_MAX],
    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *);
ശൂന്യം	 kex_proposal_free_entries(അക്ഷരം *prop[PROPOSAL_MAX]);

പൂർണ്ണസംഖ്യ	 kex_exchange_identification(ഘടന ssh *, പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *);

ഘടന kex *kex_new(ശൂന്യം);
പൂർണ്ണസംഖ്യ	 kex_ready(ഘടന ssh *, അക്ഷരം *[PROPOSAL_MAX]);
പൂർണ്ണസംഖ്യ	 kex_setup(ഘടന ssh *, അക്ഷരം *[PROPOSAL_MAX]);
ശൂന്യം	 kex_free_newkeys(ഘടന newkeys *);
ശൂന്യം	 kex_free(ഘടന kex *);

പൂർണ്ണസംഖ്യ	 kex_buf2prop(ഘടന sshbuf *, പൂർണ്ണസംഖ്യ *, അക്ഷരം ***);
പൂർണ്ണസംഖ്യ	 kex_prop2buf(ഘടന sshbuf *, അക്ഷരം *proposal[PROPOSAL_MAX]);
ശൂന്യം	 kex_prop_free(അക്ഷരം **);
പൂർണ്ണസംഖ്യ	 kex_load_hostkey(ഘടന ssh *, ഘടന sshkey **, ഘടന sshkey **);
പൂർണ്ണസംഖ്യ	 kex_verify_host_താക്കോൽ(ഘടന ssh *, ഘടന sshkey *);

പൂർണ്ണസംഖ്യ	 kex_send_kexinit(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 kex_നിവേശം_kexinit(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 kex_നിവേശം_ext_info(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 kex_protocol_error(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 kex_derive_താക്കോലുകൾ(ഘടന ssh *, u_char *, u_int, സ്ഥിരം ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ	 kex_send_newkeys(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 kex_start_rekex(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 kex_server_update_ext_info(ഘടന ssh *);
ശൂന്യം	 kex_set_server_sig_algs(ഘടന ssh *, സ്ഥിരം അക്ഷരം *);
ശൂന്യം	 kex_set_warn_weak_crypto(ഘടന ssh *, പൂർണ്ണസംഖ്യ);
ശൂന്യം	 kex_check_warn_weak_crypto(ഘടന ssh *);

പൂർണ്ണസംഖ്യ	 kexgex_client(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 kexgex_server(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 kex_gen_client(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	 kex_gen_server(ഘടന ssh *);

പൂർണ്ണസംഖ്യ	 kex_dh_keypair(ഘടന kex *);
പൂർണ്ണസംഖ്യ	 kex_dh_enc(ഘടന kex *, സ്ഥിരം ഘടന sshbuf *, ഘടന sshbuf **,
    ഘടന sshbuf **);
പൂർണ്ണസംഖ്യ	 kex_dh_dec(ഘടന kex *, സ്ഥിരം ഘടന sshbuf *, ഘടന sshbuf **);

പൂർണ്ണസംഖ്യ	 kex_ecdh_dec_താക്കോൽ_group(ഘടന kex *, സ്ഥിരം ഘടന sshbuf *, EC_താക്കോൽ *താക്കോൽ,
	    സ്ഥിരം EC_GROUP *, പൂർണ്ണസംഖ്യ, ഘടന sshbuf **);

പൂർണ്ണസംഖ്യ	 kex_ecdh_keypair(ഘടന kex *);
പൂർണ്ണസംഖ്യ	 kex_ecdh_enc(ഘടന kex *, സ്ഥിരം ഘടന sshbuf *, ഘടന sshbuf **,
    ഘടന sshbuf **);
പൂർണ്ണസംഖ്യ	 kex_ecdh_dec(ഘടന kex *, സ്ഥിരം ഘടന sshbuf *, ഘടന sshbuf **);

പൂർണ്ണസംഖ്യ	 kex_c25519_keypair(ഘടന kex *);
പൂർണ്ണസംഖ്യ	 kex_c25519_enc(ഘടന kex *, സ്ഥിരം ഘടന sshbuf *, ഘടന sshbuf **,
    ഘടന sshbuf **);
പൂർണ്ണസംഖ്യ	 kex_c25519_dec(ഘടന kex *, സ്ഥിരം ഘടന sshbuf *, ഘടന sshbuf **);

പൂർണ്ണസംഖ്യ	 kex_kem_sntrup761x25519_keypair(ഘടന kex *);
പൂർണ്ണസംഖ്യ	 kex_kem_sntrup761x25519_enc(ഘടന kex *, സ്ഥിരം ഘടന sshbuf *,
    ഘടന sshbuf **, ഘടന sshbuf **);
പൂർണ്ണസംഖ്യ	 kex_kem_sntrup761x25519_dec(ഘടന kex *, സ്ഥിരം ഘടന sshbuf *,
    ഘടന sshbuf **);

പൂർണ്ണസംഖ്യ	 kex_kem_mlkem768x25519_keypair(ഘടന kex *);
പൂർണ്ണസംഖ്യ	 kex_kem_mlkem768x25519_enc(ഘടന kex *, സ്ഥിരം ഘടന sshbuf *,
    ഘടന sshbuf **, ഘടന sshbuf **);
പൂർണ്ണസംഖ്യ	 kex_kem_mlkem768x25519_dec(ഘടന kex *, സ്ഥിരം ഘടന sshbuf *,
    ഘടന sshbuf **);

പൂർണ്ണസംഖ്യ	 kex_kem_mlkem768ecdh_keypair(ഘടന kex *);
പൂർണ്ണസംഖ്യ	 kex_kem_mlkem768ecdh_enc(ഘടന kex *, സ്ഥിരം ഘടന sshbuf *,
    ഘടന sshbuf **, ഘടന sshbuf **);
പൂർണ്ണസംഖ്യ	 kex_kem_mlkem768ecdh_dec(ഘടന kex *, സ്ഥിരം ഘടന sshbuf *,
    ഘടന sshbuf **);

പൂർണ്ണസംഖ്യ	 kex_dh_keygen(ഘടന kex *);
പൂർണ്ണസംഖ്യ	 kex_dh_compute_താക്കോൽ(ഘടന kex *, BIGNUM *, ഘടന sshbuf *);

പൂർണ്ണസംഖ്യ	 kexgex_hash(പൂർണ്ണസംഖ്യ, സ്ഥിരം ഘടന sshbuf *, സ്ഥിരം ഘടന sshbuf *,
    സ്ഥിരം ഘടന sshbuf *, സ്ഥിരം ഘടന sshbuf *, സ്ഥിരം ഘടന sshbuf *,
    പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ,
    സ്ഥിരം BIGNUM *, സ്ഥിരം BIGNUM *, സ്ഥിരം BIGNUM *,
    സ്ഥിരം BIGNUM *, സ്ഥിരം u_char *, size_t,
    u_char *, size_t *);

ശൂന്യം	kexc25519_keygen(u_char താക്കോൽ[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
പൂർണ്ണസംഖ്യ	kexc25519_shared_താക്കോൽ(സ്ഥിരം u_char താക്കോൽ[CURVE25519_SIZE],
    സ്ഥിരം u_char pub[CURVE25519_SIZE], ഘടന sshbuf *out)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
പൂർണ്ണസംഖ്യ	kexc25519_shared_താക്കോൽ_ext(സ്ഥിരം u_char താക്കോൽ[CURVE25519_SIZE],
    സ്ഥിരം u_char pub[CURVE25519_SIZE], ഘടന sshbuf *out, പൂർണ്ണസംഖ്യ)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));

#എങ്കിൽ defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
ശൂന്യം	dump_digest(സ്ഥിരം അക്ഷരം *, സ്ഥിരം u_char *, പൂർണ്ണസംഖ്യ);
#endif

#endif
