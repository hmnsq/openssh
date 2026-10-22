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

#شامل "mac.h"
#شامل "crypto_api.h"

#ifdef WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/dh.h>
#شامل <openssl/ec.h>
#شامل <openssl/ecdsa.h>
#وگرنه /* OPENSSL */
#define BIGNUM		تهی
#define DH		تهی
#define EC_کلید		تهی
#define EC_GROUP	تهی
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

شمارش kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_کلید_ALGS,
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

شمارش kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};

شمارش kex_exchange {
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

ساختار sshenc {
	نویسه	*name;
	ثابت ساختار sshcipher *cipher;
	صحیح	enabled;
	u_int	کلید_len;
	u_int	iv_len;
	u_int	block_size;
	u_char	*کلید;
	u_char	*iv;
};
ساختار sshcomp {
	u_int	type;
	صحیح	enabled;
	نویسه	*name;
};
ساختار newkeys {
	ساختار sshenc	enc;
	ساختار sshmac	mac;
	ساختار sshcomp  comp;
};

ساختار ssh;
ساختار sshbuf;

ساختار kex {
	ساختار newkeys	*newkeys[MODE_MAX];
	u_int	we_need;
	u_int	dh_need;
	صحیح	server;
	نویسه	*name;
	نویسه	*hostkey_alg;
	صحیح	hostkey_type;
	صحیح	hostkey_nid;
	u_int	kex_type;
	نویسه	*server_sig_algs;
	صحیح	ext_info_c;
	صحیح	ext_info_s;
	صحیح	kex_strict;
	صحیح	ext_info_received;
	ساختار sshbuf *my;
	ساختار sshbuf *peer;
	ساختار sshbuf *client_version;
	ساختار sshbuf *server_version;
	ساختار sshbuf *session_id;
	ساختار sshbuf *initial_sig;
	ساختار sshkey *initial_hostkey;
	sig_atomic_t done;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	صحیح	hash_alg;
	صحیح	ec_nid;
	نویسه	*failed_choice;
	صحیح	(*verify_host_کلید)(ساختار sshkey *, ساختار ssh *);
	ساختار sshkey *(*load_host_public_کلید)(صحیح, صحیح, ساختار ssh *);
	ساختار sshkey *(*load_host_private_کلید)(صحیح, صحیح, ساختار ssh *);
	صحیح	(*host_کلید_index)(ساختار sshkey *, صحیح, ساختار ssh *);
	صحیح	(*sign)(ساختار ssh *, ساختار sshkey *, ساختار sshkey *,
	    u_char **, size_t *, ثابت u_char *, size_t, ثابت نویسه *);
	صحیح	(*kex[KEX_MAX])(ساختار ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_کلید	*ec_client_کلید;		/* ECDH */
	ثابت EC_GROUP *ec_group;	/* ECDH */
	u_char c25519_client_کلید[CURVE25519_SIZE]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_SIZE]; /* 25519 */
	u_char sntrup761_client_کلید[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_کلید[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	ساختار sshbuf *client_pub;
};

صحیح	 kex_name_valid(ثابت نویسه *);
u_int	 kex_type_from_name(ثابت نویسه *);
صحیح	 kex_hash_from_name(ثابت نویسه *);
صحیح	 kex_nid_from_name(ثابت نویسه *);
صحیح	 kex_is_pq_from_name(ثابت نویسه *);
صحیح	 kex_names_valid(ثابت نویسه *);
نویسه	*kex_alg_list(نویسه);
نویسه	*kex_names_cat(ثابت نویسه *, ثابت نویسه *);
صحیح	 kex_has_any_alg(ثابت نویسه *, ثابت نویسه *);
صحیح	 kex_assemble_names(نویسه **, ثابت نویسه *, ثابت نویسه *);
تهی	 kex_proposal_populate_entries(ساختار ssh *, نویسه *prop[PROPOSAL_MAX],
    ثابت نویسه *, ثابت نویسه *, ثابت نویسه *, ثابت نویسه *, ثابت نویسه *);
تهی	 kex_proposal_free_entries(نویسه *prop[PROPOSAL_MAX]);

صحیح	 kex_exchange_identification(ساختار ssh *, صحیح, ثابت نویسه *);

ساختار kex *kex_new(تهی);
صحیح	 kex_ready(ساختار ssh *, نویسه *[PROPOSAL_MAX]);
صحیح	 kex_setup(ساختار ssh *, نویسه *[PROPOSAL_MAX]);
تهی	 kex_free_newkeys(ساختار newkeys *);
تهی	 kex_free(ساختار kex *);

صحیح	 kex_buf2prop(ساختار sshbuf *, صحیح *, نویسه ***);
صحیح	 kex_prop2buf(ساختار sshbuf *, نویسه *proposal[PROPOSAL_MAX]);
تهی	 kex_prop_free(نویسه **);
صحیح	 kex_load_hostkey(ساختار ssh *, ساختار sshkey **, ساختار sshkey **);
صحیح	 kex_verify_host_کلید(ساختار ssh *, ساختار sshkey *);

صحیح	 kex_send_kexinit(ساختار ssh *);
صحیح	 kex_درون_داد_kexinit(صحیح, uint32_t, ساختار ssh *);
صحیح	 kex_درون_داد_ext_info(صحیح, uint32_t, ساختار ssh *);
صحیح	 kex_protocol_error(صحیح, uint32_t, ساختار ssh *);
صحیح	 kex_derive_کلیدها(ساختار ssh *, u_char *, u_int, ثابت ساختار sshbuf *);
صحیح	 kex_send_newkeys(ساختار ssh *);
صحیح	 kex_start_rekex(ساختار ssh *);
صحیح	 kex_server_update_ext_info(ساختار ssh *);
تهی	 kex_set_server_sig_algs(ساختار ssh *, ثابت نویسه *);
تهی	 kex_set_warn_weak_crypto(ساختار ssh *, صحیح);
تهی	 kex_check_warn_weak_crypto(ساختار ssh *);

صحیح	 kexgex_client(ساختار ssh *);
صحیح	 kexgex_server(ساختار ssh *);
صحیح	 kex_gen_client(ساختار ssh *);
صحیح	 kex_gen_server(ساختار ssh *);

صحیح	 kex_dh_keypair(ساختار kex *);
صحیح	 kex_dh_enc(ساختار kex *, ثابت ساختار sshbuf *, ساختار sshbuf **,
    ساختار sshbuf **);
صحیح	 kex_dh_dec(ساختار kex *, ثابت ساختار sshbuf *, ساختار sshbuf **);

صحیح	 kex_ecdh_dec_کلید_group(ساختار kex *, ثابت ساختار sshbuf *, EC_کلید *کلید,
	    ثابت EC_GROUP *, صحیح, ساختار sshbuf **);

صحیح	 kex_ecdh_keypair(ساختار kex *);
صحیح	 kex_ecdh_enc(ساختار kex *, ثابت ساختار sshbuf *, ساختار sshbuf **,
    ساختار sshbuf **);
صحیح	 kex_ecdh_dec(ساختار kex *, ثابت ساختار sshbuf *, ساختار sshbuf **);

صحیح	 kex_c25519_keypair(ساختار kex *);
صحیح	 kex_c25519_enc(ساختار kex *, ثابت ساختار sshbuf *, ساختار sshbuf **,
    ساختار sshbuf **);
صحیح	 kex_c25519_dec(ساختار kex *, ثابت ساختار sshbuf *, ساختار sshbuf **);

صحیح	 kex_kem_sntrup761x25519_keypair(ساختار kex *);
صحیح	 kex_kem_sntrup761x25519_enc(ساختار kex *, ثابت ساختار sshbuf *,
    ساختار sshbuf **, ساختار sshbuf **);
صحیح	 kex_kem_sntrup761x25519_dec(ساختار kex *, ثابت ساختار sshbuf *,
    ساختار sshbuf **);

صحیح	 kex_kem_mlkem768x25519_keypair(ساختار kex *);
صحیح	 kex_kem_mlkem768x25519_enc(ساختار kex *, ثابت ساختار sshbuf *,
    ساختار sshbuf **, ساختار sshbuf **);
صحیح	 kex_kem_mlkem768x25519_dec(ساختار kex *, ثابت ساختار sshbuf *,
    ساختار sshbuf **);

صحیح	 kex_kem_mlkem768ecdh_keypair(ساختار kex *);
صحیح	 kex_kem_mlkem768ecdh_enc(ساختار kex *, ثابت ساختار sshbuf *,
    ساختار sshbuf **, ساختار sshbuf **);
صحیح	 kex_kem_mlkem768ecdh_dec(ساختار kex *, ثابت ساختار sshbuf *,
    ساختار sshbuf **);

صحیح	 kex_dh_keygen(ساختار kex *);
صحیح	 kex_dh_compute_کلید(ساختار kex *, BIGNUM *, ساختار sshbuf *);

صحیح	 kexgex_hash(صحیح, ثابت ساختار sshbuf *, ثابت ساختار sshbuf *,
    ثابت ساختار sshbuf *, ثابت ساختار sshbuf *, ثابت ساختار sshbuf *,
    صحیح, صحیح, صحیح,
    ثابت BIGNUM *, ثابت BIGNUM *, ثابت BIGNUM *,
    ثابت BIGNUM *, ثابت u_char *, size_t,
    u_char *, size_t *);

تهی	kexc25519_keygen(u_char کلید[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
صحیح	kexc25519_shared_کلید(ثابت u_char کلید[CURVE25519_SIZE],
    ثابت u_char pub[CURVE25519_SIZE], ساختار sshbuf *out)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
صحیح	kexc25519_shared_کلید_ext(ثابت u_char کلید[CURVE25519_SIZE],
    ثابت u_char pub[CURVE25519_SIZE], ساختار sshbuf *out, صحیح)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));

#اگر defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
تهی	dump_digest(ثابت نویسه *, ثابت u_char *, صحیح);
#endif

#endif
