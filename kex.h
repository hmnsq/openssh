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

#অন্তর্ভাব "mac.h"
#অন্তর্ভাব "crypto_api.h"

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/dh.h>
#অন্তর্ভাব <openssl/ec.h>
#অন্তর্ভাব <openssl/ecdsa.h>
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

#define CURVE25519_আকার 32

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

কাঠামো sshenc {
	অক্ষর	*name;
	ধ্রুবক কাঠামো sshcipher *cipher;
	পূর্ণসংখ্যা	enabled;
	u_int	চাবি_len;
	u_int	iv_len;
	u_int	block_আকার;
	u_char	*চাবি;
	u_char	*iv;
};
কাঠামো sshcomp {
	u_int	type;
	পূর্ণসংখ্যা	enabled;
	অক্ষর	*name;
};
কাঠামো newkeys {
	কাঠামো sshenc	enc;
	কাঠামো sshmac	mac;
	কাঠামো sshcomp  comp;
};

কাঠামো ssh;
কাঠামো sshbuf;

কাঠামো kex {
	কাঠামো newkeys	*newkeys[MODE_MAX];
	u_int	we_need;
	u_int	dh_need;
	পূর্ণসংখ্যা	server;
	অক্ষর	*name;
	অক্ষর	*hostkey_alg;
	পূর্ণসংখ্যা	hostkey_type;
	পূর্ণসংখ্যা	hostkey_nid;
	u_int	kex_type;
	অক্ষর	*server_sig_algs;
	পূর্ণসংখ্যা	ext_info_c;
	পূর্ণসংখ্যা	ext_info_s;
	পূর্ণসংখ্যা	kex_strict;
	পূর্ণসংখ্যা	ext_info_received;
	কাঠামো sshbuf *my;
	কাঠামো sshbuf *peer;
	কাঠামো sshbuf *client_version;
	কাঠামো sshbuf *server_version;
	কাঠামো sshbuf *session_id;
	কাঠামো sshbuf *initial_sig;
	কাঠামো sshkey *initial_hostkey;
	sig_atomic_t done;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	পূর্ণসংখ্যা	hash_alg;
	পূর্ণসংখ্যা	ec_nid;
	অক্ষর	*failed_choice;
	পূর্ণসংখ্যা	(*verify_host_চাবি)(কাঠামো sshkey *, কাঠামো ssh *);
	কাঠামো sshkey *(*load_host_public_চাবি)(পূর্ণসংখ্যা, পূর্ণসংখ্যা, কাঠামো ssh *);
	কাঠামো sshkey *(*load_host_private_চাবি)(পূর্ণসংখ্যা, পূর্ণসংখ্যা, কাঠামো ssh *);
	পূর্ণসংখ্যা	(*host_চাবি_সূচক)(কাঠামো sshkey *, পূর্ণসংখ্যা, কাঠামো ssh *);
	পূর্ণসংখ্যা	(*sign)(কাঠামো ssh *, কাঠামো sshkey *, কাঠামো sshkey *,
	    u_char **, আকার_t *, ধ্রুবক u_char *, আকার_t, ধ্রুবক অক্ষর *);
	পূর্ণসংখ্যা	(*kex[KEX_MAX])(কাঠামো ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_চাবি	*ec_client_চাবি;		/* ECDH */
	ধ্রুবক EC_GROUP *ec_group;	/* ECDH */
	u_char c25519_client_চাবি[CURVE25519_আকার]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_আকার]; /* 25519 */
	u_char sntrup761_client_চাবি[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_চাবি[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	কাঠামো sshbuf *client_pub;
};

পূর্ণসংখ্যা	 kex_name_valid(ধ্রুবক অক্ষর *);
u_int	 kex_type_from_name(ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 kex_hash_from_name(ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 kex_nid_from_name(ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 kex_is_pq_from_name(ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 kex_names_valid(ধ্রুবক অক্ষর *);
অক্ষর	*kex_alg_list(অক্ষর);
অক্ষর	*kex_names_cat(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 kex_has_any_alg(ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা	 kex_assemble_names(অক্ষর **, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
শূন্য	 kex_proposal_populate_entries(কাঠামো ssh *, অক্ষর *prop[PROPOSAL_MAX],
    ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);
শূন্য	 kex_proposal_free_entries(অক্ষর *prop[PROPOSAL_MAX]);

পূর্ণসংখ্যা	 kex_exchange_identification(কাঠামো ssh *, পূর্ণসংখ্যা, ধ্রুবক অক্ষর *);

কাঠামো kex *kex_new(শূন্য);
পূর্ণসংখ্যা	 kex_ready(কাঠামো ssh *, অক্ষর *[PROPOSAL_MAX]);
পূর্ণসংখ্যা	 kex_setup(কাঠামো ssh *, অক্ষর *[PROPOSAL_MAX]);
শূন্য	 kex_free_newkeys(কাঠামো newkeys *);
শূন্য	 kex_free(কাঠামো kex *);

পূর্ণসংখ্যা	 kex_buf2prop(কাঠামো sshbuf *, পূর্ণসংখ্যা *, অক্ষর ***);
পূর্ণসংখ্যা	 kex_prop2buf(কাঠামো sshbuf *, অক্ষর *proposal[PROPOSAL_MAX]);
শূন্য	 kex_prop_free(অক্ষর **);
পূর্ণসংখ্যা	 kex_load_hostkey(কাঠামো ssh *, কাঠামো sshkey **, কাঠামো sshkey **);
পূর্ণসংখ্যা	 kex_verify_host_চাবি(কাঠামো ssh *, কাঠামো sshkey *);

পূর্ণসংখ্যা	 kex_send_kexinit(কাঠামো ssh *);
পূর্ণসংখ্যা	 kex_প্রবেশ_kexinit(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
পূর্ণসংখ্যা	 kex_প্রবেশ_ext_info(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
পূর্ণসংখ্যা	 kex_protocol_error(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
পূর্ণসংখ্যা	 kex_derive_চাবিগুলি(কাঠামো ssh *, u_char *, u_int, ধ্রুবক কাঠামো sshbuf *);
পূর্ণসংখ্যা	 kex_send_newkeys(কাঠামো ssh *);
পূর্ণসংখ্যা	 kex_start_rekex(কাঠামো ssh *);
পূর্ণসংখ্যা	 kex_server_update_ext_info(কাঠামো ssh *);
শূন্য	 kex_set_server_sig_algs(কাঠামো ssh *, ধ্রুবক অক্ষর *);
শূন্য	 kex_set_warn_weak_crypto(কাঠামো ssh *, পূর্ণসংখ্যা);
শূন্য	 kex_check_warn_weak_crypto(কাঠামো ssh *);

পূর্ণসংখ্যা	 kexgex_client(কাঠামো ssh *);
পূর্ণসংখ্যা	 kexgex_server(কাঠামো ssh *);
পূর্ণসংখ্যা	 kex_gen_client(কাঠামো ssh *);
পূর্ণসংখ্যা	 kex_gen_server(কাঠামো ssh *);

পূর্ণসংখ্যা	 kex_dh_keypair(কাঠামো kex *);
পূর্ণসংখ্যা	 kex_dh_enc(কাঠামো kex *, ধ্রুবক কাঠামো sshbuf *, কাঠামো sshbuf **,
    কাঠামো sshbuf **);
পূর্ণসংখ্যা	 kex_dh_dec(কাঠামো kex *, ধ্রুবক কাঠামো sshbuf *, কাঠামো sshbuf **);

পূর্ণসংখ্যা	 kex_ecdh_dec_চাবি_group(কাঠামো kex *, ধ্রুবক কাঠামো sshbuf *, EC_চাবি *চাবি,
	    ধ্রুবক EC_GROUP *, পূর্ণসংখ্যা, কাঠামো sshbuf **);

পূর্ণসংখ্যা	 kex_ecdh_keypair(কাঠামো kex *);
পূর্ণসংখ্যা	 kex_ecdh_enc(কাঠামো kex *, ধ্রুবক কাঠামো sshbuf *, কাঠামো sshbuf **,
    কাঠামো sshbuf **);
পূর্ণসংখ্যা	 kex_ecdh_dec(কাঠামো kex *, ধ্রুবক কাঠামো sshbuf *, কাঠামো sshbuf **);

পূর্ণসংখ্যা	 kex_c25519_keypair(কাঠামো kex *);
পূর্ণসংখ্যা	 kex_c25519_enc(কাঠামো kex *, ধ্রুবক কাঠামো sshbuf *, কাঠামো sshbuf **,
    কাঠামো sshbuf **);
পূর্ণসংখ্যা	 kex_c25519_dec(কাঠামো kex *, ধ্রুবক কাঠামো sshbuf *, কাঠামো sshbuf **);

পূর্ণসংখ্যা	 kex_kem_sntrup761x25519_keypair(কাঠামো kex *);
পূর্ণসংখ্যা	 kex_kem_sntrup761x25519_enc(কাঠামো kex *, ধ্রুবক কাঠামো sshbuf *,
    কাঠামো sshbuf **, কাঠামো sshbuf **);
পূর্ণসংখ্যা	 kex_kem_sntrup761x25519_dec(কাঠামো kex *, ধ্রুবক কাঠামো sshbuf *,
    কাঠামো sshbuf **);

পূর্ণসংখ্যা	 kex_kem_mlkem768x25519_keypair(কাঠামো kex *);
পূর্ণসংখ্যা	 kex_kem_mlkem768x25519_enc(কাঠামো kex *, ধ্রুবক কাঠামো sshbuf *,
    কাঠামো sshbuf **, কাঠামো sshbuf **);
পূর্ণসংখ্যা	 kex_kem_mlkem768x25519_dec(কাঠামো kex *, ধ্রুবক কাঠামো sshbuf *,
    কাঠামো sshbuf **);

পূর্ণসংখ্যা	 kex_kem_mlkem768ecdh_keypair(কাঠামো kex *);
পূর্ণসংখ্যা	 kex_kem_mlkem768ecdh_enc(কাঠামো kex *, ধ্রুবক কাঠামো sshbuf *,
    কাঠামো sshbuf **, কাঠামো sshbuf **);
পূর্ণসংখ্যা	 kex_kem_mlkem768ecdh_dec(কাঠামো kex *, ধ্রুবক কাঠামো sshbuf *,
    কাঠামো sshbuf **);

পূর্ণসংখ্যা	 kex_dh_keygen(কাঠামো kex *);
পূর্ণসংখ্যা	 kex_dh_compute_চাবি(কাঠামো kex *, BIGNUM *, কাঠামো sshbuf *);

পূর্ণসংখ্যা	 kexgex_hash(পূর্ণসংখ্যা, ধ্রুবক কাঠামো sshbuf *, ধ্রুবক কাঠামো sshbuf *,
    ধ্রুবক কাঠামো sshbuf *, ধ্রুবক কাঠামো sshbuf *, ধ্রুবক কাঠামো sshbuf *,
    পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা,
    ধ্রুবক BIGNUM *, ধ্রুবক BIGNUM *, ধ্রুবক BIGNUM *,
    ধ্রুবক BIGNUM *, ধ্রুবক u_char *, আকার_t,
    u_char *, আকার_t *);

শূন্য	kexc25519_keygen(u_char চাবি[CURVE25519_আকার], u_char pub[CURVE25519_আকার])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_আকার)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_আকার)));
পূর্ণসংখ্যা	kexc25519_shared_চাবি(ধ্রুবক u_char চাবি[CURVE25519_আকার],
    ধ্রুবক u_char pub[CURVE25519_আকার], কাঠামো sshbuf *out)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_আকার)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_আকার)));
পূর্ণসংখ্যা	kexc25519_shared_চাবি_ext(ধ্রুবক u_char চাবি[CURVE25519_আকার],
    ধ্রুবক u_char pub[CURVE25519_আকার], কাঠামো sshbuf *out, পূর্ণসংখ্যা)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_আকার)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_আকার)));

#যদি defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
শূন্য	dump_digest(ধ্রুবক অক্ষর *, ধ্রুবক u_char *, পূর্ণসংখ্যা);
#endif

#endif
