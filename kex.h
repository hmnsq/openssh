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

#அந்தர்பாவ "mac.h"
#அந்தர்பாவ "crypto_api.h"

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/dh.h>
#அந்தர்பாவ <openssl/ec.h>
#அந்தர்பாவ <openssl/ecdsa.h>
#இல்லையெனில் /* OPENSSL */
#define BIGNUM		வெறுமை
#define DH		வெறுமை
#define EC_சாவி		வெறுமை
#define EC_GROUP	வெறுமை
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

எண்ணிக்கை kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_சாவி_ALGS,
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

எண்ணிக்கை kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};

எண்ணிக்கை kex_exchange {
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

கட்டமைப்பு sshenc {
	எழுத்து	*name;
	மாறிலி கட்டமைப்பு sshcipher *cipher;
	முழு	enabled;
	u_int	சாவி_len;
	u_int	iv_len;
	u_int	block_size;
	u_char	*சாவி;
	u_char	*iv;
};
கட்டமைப்பு sshcomp {
	u_int	type;
	முழு	enabled;
	எழுத்து	*name;
};
கட்டமைப்பு newkeys {
	கட்டமைப்பு sshenc	enc;
	கட்டமைப்பு sshmac	mac;
	கட்டமைப்பு sshcomp  comp;
};

கட்டமைப்பு ssh;
கட்டமைப்பு sshbuf;

கட்டமைப்பு kex {
	கட்டமைப்பு newkeys	*newkeys[MODE_MAX];
	u_int	we_need;
	u_int	dh_need;
	முழு	server;
	எழுத்து	*name;
	எழுத்து	*hostkey_alg;
	முழு	hostkey_type;
	முழு	hostkey_nid;
	u_int	kex_type;
	எழுத்து	*server_sig_algs;
	முழு	ext_info_c;
	முழு	ext_info_s;
	முழு	kex_strict;
	முழு	ext_info_received;
	கட்டமைப்பு sshbuf *my;
	கட்டமைப்பு sshbuf *peer;
	கட்டமைப்பு sshbuf *client_version;
	கட்டமைப்பு sshbuf *server_version;
	கட்டமைப்பு sshbuf *session_id;
	கட்டமைப்பு sshbuf *initial_sig;
	கட்டமைப்பு sshkey *initial_hostkey;
	sig_atomic_t done;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	முழு	hash_alg;
	முழு	ec_nid;
	எழுத்து	*failed_choice;
	முழு	(*verify_host_சாவி)(கட்டமைப்பு sshkey *, கட்டமைப்பு ssh *);
	கட்டமைப்பு sshkey *(*load_host_public_சாவி)(முழு, முழு, கட்டமைப்பு ssh *);
	கட்டமைப்பு sshkey *(*load_host_private_சாவி)(முழு, முழு, கட்டமைப்பு ssh *);
	முழு	(*host_சாவி_index)(கட்டமைப்பு sshkey *, முழு, கட்டமைப்பு ssh *);
	முழு	(*sign)(கட்டமைப்பு ssh *, கட்டமைப்பு sshkey *, கட்டமைப்பு sshkey *,
	    u_char **, size_t *, மாறிலி u_char *, size_t, மாறிலி எழுத்து *);
	முழு	(*kex[KEX_MAX])(கட்டமைப்பு ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_சாவி	*ec_client_சாவி;		/* ECDH */
	மாறிலி EC_GROUP *ec_group;	/* ECDH */
	u_char c25519_client_சாவி[CURVE25519_SIZE]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_SIZE]; /* 25519 */
	u_char sntrup761_client_சாவி[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_சாவி[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	கட்டமைப்பு sshbuf *client_pub;
};

முழு	 kex_name_valid(மாறிலி எழுத்து *);
u_int	 kex_type_from_name(மாறிலி எழுத்து *);
முழு	 kex_hash_from_name(மாறிலி எழுத்து *);
முழு	 kex_nid_from_name(மாறிலி எழுத்து *);
முழு	 kex_is_pq_from_name(மாறிலி எழுத்து *);
முழு	 kex_names_valid(மாறிலி எழுத்து *);
எழுத்து	*kex_alg_list(எழுத்து);
எழுத்து	*kex_names_cat(மாறிலி எழுத்து *, மாறிலி எழுத்து *);
முழு	 kex_has_any_alg(மாறிலி எழுத்து *, மாறிலி எழுத்து *);
முழு	 kex_assemble_names(எழுத்து **, மாறிலி எழுத்து *, மாறிலி எழுத்து *);
வெறுமை	 kex_proposal_populate_entries(கட்டமைப்பு ssh *, எழுத்து *prop[PROPOSAL_MAX],
    மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *);
வெறுமை	 kex_proposal_free_entries(எழுத்து *prop[PROPOSAL_MAX]);

முழு	 kex_exchange_identification(கட்டமைப்பு ssh *, முழு, மாறிலி எழுத்து *);

கட்டமைப்பு kex *kex_new(வெறுமை);
முழு	 kex_ready(கட்டமைப்பு ssh *, எழுத்து *[PROPOSAL_MAX]);
முழு	 kex_setup(கட்டமைப்பு ssh *, எழுத்து *[PROPOSAL_MAX]);
வெறுமை	 kex_free_newkeys(கட்டமைப்பு newkeys *);
வெறுமை	 kex_free(கட்டமைப்பு kex *);

முழு	 kex_buf2prop(கட்டமைப்பு sshbuf *, முழு *, எழுத்து ***);
முழு	 kex_prop2buf(கட்டமைப்பு sshbuf *, எழுத்து *proposal[PROPOSAL_MAX]);
வெறுமை	 kex_prop_free(எழுத்து **);
முழு	 kex_load_hostkey(கட்டமைப்பு ssh *, கட்டமைப்பு sshkey **, கட்டமைப்பு sshkey **);
முழு	 kex_verify_host_சாவி(கட்டமைப்பு ssh *, கட்டமைப்பு sshkey *);

முழு	 kex_send_kexinit(கட்டமைப்பு ssh *);
முழு	 kex_உள்ளீடு_kexinit(முழு, uint32_t, கட்டமைப்பு ssh *);
முழு	 kex_உள்ளீடு_ext_info(முழு, uint32_t, கட்டமைப்பு ssh *);
முழு	 kex_protocol_error(முழு, uint32_t, கட்டமைப்பு ssh *);
முழு	 kex_derive_சாவிகள்(கட்டமைப்பு ssh *, u_char *, u_int, மாறிலி கட்டமைப்பு sshbuf *);
முழு	 kex_send_newkeys(கட்டமைப்பு ssh *);
முழு	 kex_start_rekex(கட்டமைப்பு ssh *);
முழு	 kex_server_update_ext_info(கட்டமைப்பு ssh *);
வெறுமை	 kex_set_server_sig_algs(கட்டமைப்பு ssh *, மாறிலி எழுத்து *);
வெறுமை	 kex_set_warn_weak_crypto(கட்டமைப்பு ssh *, முழு);
வெறுமை	 kex_check_warn_weak_crypto(கட்டமைப்பு ssh *);

முழு	 kexgex_client(கட்டமைப்பு ssh *);
முழு	 kexgex_server(கட்டமைப்பு ssh *);
முழு	 kex_gen_client(கட்டமைப்பு ssh *);
முழு	 kex_gen_server(கட்டமைப்பு ssh *);

முழு	 kex_dh_keypair(கட்டமைப்பு kex *);
முழு	 kex_dh_enc(கட்டமைப்பு kex *, மாறிலி கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf **,
    கட்டமைப்பு sshbuf **);
முழு	 kex_dh_dec(கட்டமைப்பு kex *, மாறிலி கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf **);

முழு	 kex_ecdh_dec_சாவி_group(கட்டமைப்பு kex *, மாறிலி கட்டமைப்பு sshbuf *, EC_சாவி *சாவி,
	    மாறிலி EC_GROUP *, முழு, கட்டமைப்பு sshbuf **);

முழு	 kex_ecdh_keypair(கட்டமைப்பு kex *);
முழு	 kex_ecdh_enc(கட்டமைப்பு kex *, மாறிலி கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf **,
    கட்டமைப்பு sshbuf **);
முழு	 kex_ecdh_dec(கட்டமைப்பு kex *, மாறிலி கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf **);

முழு	 kex_c25519_keypair(கட்டமைப்பு kex *);
முழு	 kex_c25519_enc(கட்டமைப்பு kex *, மாறிலி கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf **,
    கட்டமைப்பு sshbuf **);
முழு	 kex_c25519_dec(கட்டமைப்பு kex *, மாறிலி கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf **);

முழு	 kex_kem_sntrup761x25519_keypair(கட்டமைப்பு kex *);
முழு	 kex_kem_sntrup761x25519_enc(கட்டமைப்பு kex *, மாறிலி கட்டமைப்பு sshbuf *,
    கட்டமைப்பு sshbuf **, கட்டமைப்பு sshbuf **);
முழு	 kex_kem_sntrup761x25519_dec(கட்டமைப்பு kex *, மாறிலி கட்டமைப்பு sshbuf *,
    கட்டமைப்பு sshbuf **);

முழு	 kex_kem_mlkem768x25519_keypair(கட்டமைப்பு kex *);
முழு	 kex_kem_mlkem768x25519_enc(கட்டமைப்பு kex *, மாறிலி கட்டமைப்பு sshbuf *,
    கட்டமைப்பு sshbuf **, கட்டமைப்பு sshbuf **);
முழு	 kex_kem_mlkem768x25519_dec(கட்டமைப்பு kex *, மாறிலி கட்டமைப்பு sshbuf *,
    கட்டமைப்பு sshbuf **);

முழு	 kex_kem_mlkem768ecdh_keypair(கட்டமைப்பு kex *);
முழு	 kex_kem_mlkem768ecdh_enc(கட்டமைப்பு kex *, மாறிலி கட்டமைப்பு sshbuf *,
    கட்டமைப்பு sshbuf **, கட்டமைப்பு sshbuf **);
முழு	 kex_kem_mlkem768ecdh_dec(கட்டமைப்பு kex *, மாறிலி கட்டமைப்பு sshbuf *,
    கட்டமைப்பு sshbuf **);

முழு	 kex_dh_keygen(கட்டமைப்பு kex *);
முழு	 kex_dh_compute_சாவி(கட்டமைப்பு kex *, BIGNUM *, கட்டமைப்பு sshbuf *);

முழு	 kexgex_hash(முழு, மாறிலி கட்டமைப்பு sshbuf *, மாறிலி கட்டமைப்பு sshbuf *,
    மாறிலி கட்டமைப்பு sshbuf *, மாறிலி கட்டமைப்பு sshbuf *, மாறிலி கட்டமைப்பு sshbuf *,
    முழு, முழு, முழு,
    மாறிலி BIGNUM *, மாறிலி BIGNUM *, மாறிலி BIGNUM *,
    மாறிலி BIGNUM *, மாறிலி u_char *, size_t,
    u_char *, size_t *);

வெறுமை	kexc25519_keygen(u_char சாவி[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
முழு	kexc25519_shared_சாவி(மாறிலி u_char சாவி[CURVE25519_SIZE],
    மாறிலி u_char pub[CURVE25519_SIZE], கட்டமைப்பு sshbuf *out)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
முழு	kexc25519_shared_சாவி_ext(மாறிலி u_char சாவி[CURVE25519_SIZE],
    மாறிலி u_char pub[CURVE25519_SIZE], கட்டமைப்பு sshbuf *out, முழு)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));

#எனில் defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
வெறுமை	dump_digest(மாறிலி எழுத்து *, மாறிலி u_char *, முழு);
#endif

#endif
