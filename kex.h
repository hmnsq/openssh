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
#अगर_अघोषित KEX_H
#घोषणा KEX_H

#समावेश "mac.h"
#समावेश "crypto_api.h"

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/bn.h>
#समावेश <openssl/dh.h>
#समावेश <openssl/ec.h>
#समावेश <openssl/ecdsa.h>
#अन्यथा /* OPENSSL */
#घोषणा BIGNUM		व्योम
#घोषणा DH		व्योम
#घोषणा EC_कुंजी		व्योम
#घोषणा EC_GROUP	व्योम
#पूर्ण_अगर /* WITH_OPENSSL */

#घोषणा KEX_COOKIE_LEN	16

#घोषणा	KEX_DH1				"diffie-hellman-group1-sha1"
#घोषणा	KEX_DH14_SHA1			"diffie-hellman-group14-sha1"
#घोषणा	KEX_DH14_SHA256			"diffie-hellman-group14-sha256"
#घोषणा	KEX_DH16_SHA512			"diffie-hellman-group16-sha512"
#घोषणा	KEX_DH18_SHA512			"diffie-hellman-group18-sha512"
#घोषणा	KEX_DHGEX_SHA1			"diffie-hellman-group-exchange-sha1"
#घोषणा	KEX_DHGEX_SHA256		"diffie-hellman-group-exchange-sha256"
#घोषणा	KEX_ECDH_SHA2_NISTP256		"ecdh-sha2-nistp256"
#घोषणा	KEX_ECDH_SHA2_NISTP384		"ecdh-sha2-nistp384"
#घोषणा	KEX_ECDH_SHA2_NISTP521		"ecdh-sha2-nistp521"
#घोषणा	KEX_CURVE25519_SHA256		"curve25519-sha256"
#घोषणा	KEX_CURVE25519_SHA256_OLD	"curve25519-sha256@libssh.org"
#घोषणा	KEX_SNTRUP761X25519_SHA512	"sntrup761x25519-sha512"
#घोषणा	KEX_SNTRUP761X25519_SHA512_OLD	"sntrup761x25519-sha512@openssh.com"
#घोषणा	KEX_MLKEM768X25519_SHA256	"mlkem768x25519-sha256"
#घोषणा	KEX_MLKEM768NISTP256_SHA256	"mlkem768nistp256-sha256"

#घोषणा COMP_NONE	0
#घोषणा COMP_DELAYED	2

#घोषणा CURVE25519_आकार 32

क्रमागत kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_कुंजी_ALGS,
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

क्रमागत kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};

क्रमागत kex_exchange {
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
#घोषणा KEX_INIT_SENT			0x0001
#घोषणा KEX_INITIAL			0x0002
#घोषणा KEX_HAS_PUBKEY_HOSTBOUND	0x0004
#घोषणा KEX_RSA_SHA2_256_SUPPORTED	0x0008 /* only set in server for now */
#घोषणा KEX_RSA_SHA2_512_SUPPORTED	0x0010 /* only set in server for now */
#घोषणा KEX_HAS_PING			0x0020
#घोषणा KEX_HAS_EXT_INFO_IN_AUTH	0x0040
#घोषणा KEX_HAS_NEWAGENT		0x0080 /* only set in client */
#घोषणा KEX_INIT_RECVD			0x0100

/* kex->pq */
#घोषणा KEX_NOT_PQ			0
#घोषणा KEX_IS_PQ			1

काष्ठा sshenc {
	अक्षर	*name;
	स्थिर काष्ठा sshcipher *cipher;
	पूर्णांक	enabled;
	u_int	कुंजी_len;
	u_int	iv_len;
	u_int	block_आकार;
	u_char	*कुंजी;
	u_char	*iv;
};
काष्ठा sshcomp {
	u_int	type;
	पूर्णांक	enabled;
	अक्षर	*name;
};
काष्ठा newkeys {
	काष्ठा sshenc	enc;
	काष्ठा sshmac	mac;
	काष्ठा sshcomp  comp;
};

काष्ठा ssh;
काष्ठा sshbuf;

काष्ठा kex {
	काष्ठा newkeys	*newkeys[MODE_MAX];
	u_int	we_need;
	u_int	dh_need;
	पूर्णांक	server;
	अक्षर	*name;
	अक्षर	*hostkey_alg;
	पूर्णांक	hostkey_type;
	पूर्णांक	hostkey_nid;
	u_int	kex_type;
	अक्षर	*server_sig_algs;
	पूर्णांक	ext_info_c;
	पूर्णांक	ext_info_s;
	पूर्णांक	kex_strict;
	पूर्णांक	ext_info_received;
	काष्ठा sshbuf *my;
	काष्ठा sshbuf *peer;
	काष्ठा sshbuf *client_version;
	काष्ठा sshbuf *server_version;
	काष्ठा sshbuf *session_id;
	काष्ठा sshbuf *initial_sig;
	काष्ठा sshkey *initial_hostkey;
	संक_पूर्ण_प्रकार done;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	पूर्णांक	hash_alg;
	पूर्णांक	ec_nid;
	अक्षर	*failed_choice;
	पूर्णांक	(*verify_host_कुंजी)(काष्ठा sshkey *, काष्ठा ssh *);
	काष्ठा sshkey *(*load_host_public_कुंजी)(पूर्णांक, पूर्णांक, काष्ठा ssh *);
	काष्ठा sshkey *(*load_host_private_कुंजी)(पूर्णांक, पूर्णांक, काष्ठा ssh *);
	पूर्णांक	(*host_कुंजी_सूचकांक)(काष्ठा sshkey *, पूर्णांक, काष्ठा ssh *);
	पूर्णांक	(*sign)(काष्ठा ssh *, काष्ठा sshkey *, काष्ठा sshkey *,
	    u_char **, माप_प्रकार *, स्थिर u_char *, माप_प्रकार, स्थिर अक्षर *);
	पूर्णांक	(*kex[KEX_MAX])(काष्ठा ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_कुंजी	*ec_client_कुंजी;		/* ECDH */
	स्थिर EC_GROUP *ec_group;	/* ECDH */
	u_char c25519_client_कुंजी[CURVE25519_आकार]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_आकार]; /* 25519 */
	u_char sntrup761_client_कुंजी[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_कुंजी[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	काष्ठा sshbuf *client_pub;
};

पूर्णांक	 kex_name_valid(स्थिर अक्षर *);
u_int	 kex_type_from_name(स्थिर अक्षर *);
पूर्णांक	 kex_hash_from_name(स्थिर अक्षर *);
पूर्णांक	 kex_nid_from_name(स्थिर अक्षर *);
पूर्णांक	 kex_is_pq_from_name(स्थिर अक्षर *);
पूर्णांक	 kex_names_valid(स्थिर अक्षर *);
अक्षर	*kex_alg_list(अक्षर);
अक्षर	*kex_names_cat(स्थिर अक्षर *, स्थिर अक्षर *);
पूर्णांक	 kex_has_any_alg(स्थिर अक्षर *, स्थिर अक्षर *);
पूर्णांक	 kex_assemble_names(अक्षर **, स्थिर अक्षर *, स्थिर अक्षर *);
व्योम	 kex_proposal_populate_entries(काष्ठा ssh *, अक्षर *prop[PROPOSAL_MAX],
    स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *);
व्योम	 kex_proposal_free_entries(अक्षर *prop[PROPOSAL_MAX]);

पूर्णांक	 kex_exchange_identification(काष्ठा ssh *, पूर्णांक, स्थिर अक्षर *);

काष्ठा kex *kex_new(व्योम);
पूर्णांक	 kex_ready(काष्ठा ssh *, अक्षर *[PROPOSAL_MAX]);
पूर्णांक	 kex_setup(काष्ठा ssh *, अक्षर *[PROPOSAL_MAX]);
व्योम	 kex_free_newkeys(काष्ठा newkeys *);
व्योम	 kex_free(काष्ठा kex *);

पूर्णांक	 kex_buf2prop(काष्ठा sshbuf *, पूर्णांक *, अक्षर ***);
पूर्णांक	 kex_prop2buf(काष्ठा sshbuf *, अक्षर *proposal[PROPOSAL_MAX]);
व्योम	 kex_prop_free(अक्षर **);
पूर्णांक	 kex_load_hostkey(काष्ठा ssh *, काष्ठा sshkey **, काष्ठा sshkey **);
पूर्णांक	 kex_verify_host_कुंजी(काष्ठा ssh *, काष्ठा sshkey *);

पूर्णांक	 kex_send_kexinit(काष्ठा ssh *);
पूर्णांक	 kex_निवेश_kexinit(पूर्णांक, uint32_t, काष्ठा ssh *);
पूर्णांक	 kex_निवेश_ext_info(पूर्णांक, uint32_t, काष्ठा ssh *);
पूर्णांक	 kex_protocol_error(पूर्णांक, uint32_t, काष्ठा ssh *);
पूर्णांक	 kex_derive_कुंजियाँ(काष्ठा ssh *, u_char *, u_int, स्थिर काष्ठा sshbuf *);
पूर्णांक	 kex_send_newkeys(काष्ठा ssh *);
पूर्णांक	 kex_start_rekex(काष्ठा ssh *);
पूर्णांक	 kex_server_update_ext_info(काष्ठा ssh *);
व्योम	 kex_set_server_sig_algs(काष्ठा ssh *, स्थिर अक्षर *);
व्योम	 kex_set_warn_weak_crypto(काष्ठा ssh *, पूर्णांक);
व्योम	 kex_check_warn_weak_crypto(काष्ठा ssh *);

पूर्णांक	 kexgex_client(काष्ठा ssh *);
पूर्णांक	 kexgex_server(काष्ठा ssh *);
पूर्णांक	 kex_gen_client(काष्ठा ssh *);
पूर्णांक	 kex_gen_server(काष्ठा ssh *);

पूर्णांक	 kex_dh_keypair(काष्ठा kex *);
पूर्णांक	 kex_dh_enc(काष्ठा kex *, स्थिर काष्ठा sshbuf *, काष्ठा sshbuf **,
    काष्ठा sshbuf **);
पूर्णांक	 kex_dh_dec(काष्ठा kex *, स्थिर काष्ठा sshbuf *, काष्ठा sshbuf **);

पूर्णांक	 kex_ecdh_dec_कुंजी_group(काष्ठा kex *, स्थिर काष्ठा sshbuf *, EC_कुंजी *कुंजी,
	    स्थिर EC_GROUP *, पूर्णांक, काष्ठा sshbuf **);

पूर्णांक	 kex_ecdh_keypair(काष्ठा kex *);
पूर्णांक	 kex_ecdh_enc(काष्ठा kex *, स्थिर काष्ठा sshbuf *, काष्ठा sshbuf **,
    काष्ठा sshbuf **);
पूर्णांक	 kex_ecdh_dec(काष्ठा kex *, स्थिर काष्ठा sshbuf *, काष्ठा sshbuf **);

पूर्णांक	 kex_c25519_keypair(काष्ठा kex *);
पूर्णांक	 kex_c25519_enc(काष्ठा kex *, स्थिर काष्ठा sshbuf *, काष्ठा sshbuf **,
    काष्ठा sshbuf **);
पूर्णांक	 kex_c25519_dec(काष्ठा kex *, स्थिर काष्ठा sshbuf *, काष्ठा sshbuf **);

पूर्णांक	 kex_kem_sntrup761x25519_keypair(काष्ठा kex *);
पूर्णांक	 kex_kem_sntrup761x25519_enc(काष्ठा kex *, स्थिर काष्ठा sshbuf *,
    काष्ठा sshbuf **, काष्ठा sshbuf **);
पूर्णांक	 kex_kem_sntrup761x25519_dec(काष्ठा kex *, स्थिर काष्ठा sshbuf *,
    काष्ठा sshbuf **);

पूर्णांक	 kex_kem_mlkem768x25519_keypair(काष्ठा kex *);
पूर्णांक	 kex_kem_mlkem768x25519_enc(काष्ठा kex *, स्थिर काष्ठा sshbuf *,
    काष्ठा sshbuf **, काष्ठा sshbuf **);
पूर्णांक	 kex_kem_mlkem768x25519_dec(काष्ठा kex *, स्थिर काष्ठा sshbuf *,
    काष्ठा sshbuf **);

पूर्णांक	 kex_kem_mlkem768ecdh_keypair(काष्ठा kex *);
पूर्णांक	 kex_kem_mlkem768ecdh_enc(काष्ठा kex *, स्थिर काष्ठा sshbuf *,
    काष्ठा sshbuf **, काष्ठा sshbuf **);
पूर्णांक	 kex_kem_mlkem768ecdh_dec(काष्ठा kex *, स्थिर काष्ठा sshbuf *,
    काष्ठा sshbuf **);

पूर्णांक	 kex_dh_keygen(काष्ठा kex *);
पूर्णांक	 kex_dh_compute_कुंजी(काष्ठा kex *, BIGNUM *, काष्ठा sshbuf *);

पूर्णांक	 kexgex_hash(पूर्णांक, स्थिर काष्ठा sshbuf *, स्थिर काष्ठा sshbuf *,
    स्थिर काष्ठा sshbuf *, स्थिर काष्ठा sshbuf *, स्थिर काष्ठा sshbuf *,
    पूर्णांक, पूर्णांक, पूर्णांक,
    स्थिर BIGNUM *, स्थिर BIGNUM *, स्थिर BIGNUM *,
    स्थिर BIGNUM *, स्थिर u_char *, माप_प्रकार,
    u_char *, माप_प्रकार *);

व्योम	kexc25519_keygen(u_char कुंजी[CURVE25519_आकार], u_char pub[CURVE25519_आकार])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_आकार)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_आकार)));
पूर्णांक	kexc25519_shared_कुंजी(स्थिर u_char कुंजी[CURVE25519_आकार],
    स्थिर u_char pub[CURVE25519_आकार], काष्ठा sshbuf *out)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_आकार)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_आकार)));
पूर्णांक	kexc25519_shared_कुंजी_ext(स्थिर u_char कुंजी[CURVE25519_आकार],
    स्थिर u_char pub[CURVE25519_आकार], काष्ठा sshbuf *out, पूर्णांक)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_आकार)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_आकार)));

#अगर defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
व्योम	dump_digest(स्थिर अक्षर *, स्थिर u_char *, पूर्णांक);
#पूर्ण_अगर

#पूर्ण_अगर
