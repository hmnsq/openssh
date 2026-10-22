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
#यदि_अपरिभाषितम् KEX_H
#परिभाषय KEX_H

#अन्तर्भाव "mac.h"
#अन्तर्भाव "crypto_api.h"

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/dh.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/ecdsa.h>
#अन्यथा /* OPENSSL */
#परिभाषय BIGNUM		शून्य
#परिभाषय DH		शून्य
#परिभाषय EC_कुञ्चिका		शून्य
#परिभाषय EC_गणः	शून्य
#यदि_अन्तः /* WITH_OPENSSL */

#परिभाषय KEX_COOKIE_LEN	16

#परिभाषय	KEX_DH1				"diffie-hellman-group1-sha1"
#परिभाषय	KEX_DH14_SHA1			"diffie-hellman-group14-sha1"
#परिभाषय	KEX_DH14_SHA256			"diffie-hellman-group14-sha256"
#परिभाषय	KEX_DH16_SHA512			"diffie-hellman-group16-sha512"
#परिभाषय	KEX_DH18_SHA512			"diffie-hellman-group18-sha512"
#परिभाषय	KEX_DHGEX_SHA1			"diffie-hellman-group-exchange-sha1"
#परिभाषय	KEX_DHGEX_SHA256		"diffie-hellman-group-exchange-sha256"
#परिभाषय	KEX_ECDH_SHA2_NISTP256		"ecdh-sha2-nistp256"
#परिभाषय	KEX_ECDH_SHA2_NISTP384		"ecdh-sha2-nistp384"
#परिभाषय	KEX_ECDH_SHA2_NISTP521		"ecdh-sha2-nistp521"
#परिभाषय	KEX_CURVE25519_SHA256		"curve25519-sha256"
#परिभाषय	KEX_CURVE25519_SHA256_OLD	"curve25519-sha256@libssh.org"
#परिभाषय	KEX_SNTRUP761X25519_SHA512	"sntrup761x25519-sha512"
#परिभाषय	KEX_SNTRUP761X25519_SHA512_OLD	"sntrup761x25519-sha512@openssh.com"
#परिभाषय	KEX_MLKEM768X25519_SHA256	"mlkem768x25519-sha256"
#परिभाषय	KEX_MLKEM768NISTP256_SHA256	"mlkem768nistp256-sha256"

#परिभाषय COMP_NONE	0
#परिभाषय COMP_DELAYED	2

#परिभाषय CURVE25519_आकार 32

गणना kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS,
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

गणना kex_modes {
	बहुलकम्_अन्तर्,
	बहुलकम्_बहिर्गमनम्,
	बहुलकम्_MAX
};

गणना kex_exchange {
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
#परिभाषय KEX_INIT_प्रेषितम्			0x0001
#परिभाषय KEX_INITIAL			0x0002
#परिभाषय KEX_HAS_PUBKEY_HOSTBOUND	0x0004
#परिभाषय KEX_RSA_SHA2_256_SUPPORTED	0x0008 /* only set in server for now */
#परिभाषय KEX_RSA_SHA2_512_SUPPORTED	0x0010 /* only set in server for now */
#परिभाषय KEX_HAS_PING			0x0020
#परिभाषय KEX_HAS_EXT_INFO_अन्तर्_AUTH	0x0040
#परिभाषय KEX_HAS_NEWAGENT		0x0080 /* only set in client */
#परिभाषय KEX_INIT_RECVD			0x0100

/* kex->pq */
#परिभाषय KEX_NOT_PQ			0
#परिभाषय KEX_IS_PQ			1

संरचना sshenc {
	वर्ण	*name;
	ध्रुव संरचना sshcipher *cipher;
	पूर्णाङ्क	enabled;
	u_int	कुञ्चिका_len;
	u_int	iv_len;
	u_int	खण्डम्_आकार;
	u_char	*कुञ्चिका;
	u_char	*iv;
};
संरचना sshcomp {
	u_int	type;
	पूर्णाङ्क	enabled;
	वर्ण	*name;
};
संरचना newkeys {
	संरचना sshenc	enc;
	संरचना sshmac	mac;
	संरचना sshcomp  comp;
};

संरचना ssh;
संरचना sshbuf;

संरचना kex {
	संरचना newkeys	*newkeys[बहुलकम्_MAX];
	u_int	we_need;
	u_int	dh_need;
	पूर्णाङ्क	server;
	वर्ण	*name;
	वर्ण	*hostkey_alg;
	पूर्णाङ्क	hostkey_type;
	पूर्णाङ्क	hostkey_nid;
	u_int	kex_type;
	वर्ण	*server_sig_algs;
	पूर्णाङ्क	ext_info_c;
	पूर्णाङ्क	ext_info_s;
	पूर्णाङ्क	kex_strict;
	पूर्णाङ्क	ext_info_received;
	संरचना sshbuf *my;
	संरचना sshbuf *peer;
	संरचना sshbuf *client_संस्करणम्;
	संरचना sshbuf *server_संस्करणम्;
	संरचना sshbuf *session_id;
	संरचना sshbuf *initial_sig;
	संरचना sshkey *initial_hostkey;
	sig_atomic_t समाप्तम्;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	पूर्णाङ्क	hash_alg;
	पूर्णाङ्क	ec_nid;
	वर्ण	*failed_choice;
	पूर्णाङ्क	(*verify_host_कुञ्चिका)(संरचना sshkey *, संरचना ssh *);
	संरचना sshkey *(*आरोपय_host_लौकिकम्_कुञ्चिका)(पूर्णाङ्क, पूर्णाङ्क, संरचना ssh *);
	संरचना sshkey *(*आरोपय_host_वैयक्तिकम्_कुञ्चिका)(पूर्णाङ्क, पूर्णाङ्क, संरचना ssh *);
	पूर्णाङ्क	(*host_कुञ्चिका_सूचकांक)(संरचना sshkey *, पूर्णाङ्क, संरचना ssh *);
	पूर्णाङ्क	(*sign)(संरचना ssh *, संरचना sshkey *, संरचना sshkey *,
	    u_char **, आकार_t *, ध्रुव u_char *, आकार_t, ध्रुव वर्ण *);
	पूर्णाङ्क	(*kex[KEX_MAX])(संरचना ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_कुञ्चिका	*ec_client_कुञ्चिका;		/* ECDH */
	ध्रुव EC_गणः *ec_गणः;	/* ECDH */
	u_char c25519_client_कुञ्चिका[CURVE25519_आकार]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_आकार]; /* 25519 */
	u_char sntrup761_client_कुञ्चिका[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_कुञ्चिका[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	संरचना sshbuf *client_pub;
};

पूर्णाङ्क	 kex_name_valid(ध्रुव वर्ण *);
u_int	 kex_type_from_name(ध्रुव वर्ण *);
पूर्णाङ्क	 kex_hash_from_name(ध्रुव वर्ण *);
पूर्णाङ्क	 kex_nid_from_name(ध्रुव वर्ण *);
पूर्णाङ्क	 kex_is_pq_from_name(ध्रुव वर्ण *);
पूर्णाङ्क	 kex_नामानि_valid(ध्रुव वर्ण *);
वर्ण	*kex_alg_list(वर्ण);
वर्ण	*kex_नामानि_cat(ध्रुव वर्ण *, ध्रुव वर्ण *);
पूर्णाङ्क	 kex_has_any_alg(ध्रुव वर्ण *, ध्रुव वर्ण *);
पूर्णाङ्क	 kex_assemble_नामानि(वर्ण **, ध्रुव वर्ण *, ध्रुव वर्ण *);
शून्य	 kex_proposal_populate_entries(संरचना ssh *, वर्ण *prop[PROPOSAL_MAX],
    ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *);
शून्य	 kex_proposal_free_entries(वर्ण *prop[PROPOSAL_MAX]);

पूर्णाङ्क	 kex_exchange_identification(संरचना ssh *, पूर्णाङ्क, ध्रुव वर्ण *);

संरचना kex *kex_new(शून्य);
पूर्णाङ्क	 kex_ready(संरचना ssh *, वर्ण *[PROPOSAL_MAX]);
पूर्णाङ्क	 kex_सज्जता(संरचना ssh *, वर्ण *[PROPOSAL_MAX]);
शून्य	 kex_free_newkeys(संरचना newkeys *);
शून्य	 kex_free(संरचना kex *);

पूर्णाङ्क	 kex_buf2prop(संरचना sshbuf *, पूर्णाङ्क *, वर्ण ***);
पूर्णाङ्क	 kex_prop2buf(संरचना sshbuf *, वर्ण *proposal[PROPOSAL_MAX]);
शून्य	 kex_prop_free(वर्ण **);
पूर्णाङ्क	 kex_आरोपय_hostkey(संरचना ssh *, संरचना sshkey **, संरचना sshkey **);
पूर्णाङ्क	 kex_verify_host_कुञ्चिका(संरचना ssh *, संरचना sshkey *);

पूर्णाङ्क	 kex_send_kexinit(संरचना ssh *);
पूर्णाङ्क	 kex_निवेशः_kexinit(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 kex_निवेशः_ext_info(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 kex_protocol_error(पूर्णाङ्क, uint32_t, संरचना ssh *);
पूर्णाङ्क	 kex_derive_कुञ्चिकाः(संरचना ssh *, u_char *, u_int, ध्रुव संरचना sshbuf *);
पूर्णाङ्क	 kex_send_newkeys(संरचना ssh *);
पूर्णाङ्क	 kex_start_rekex(संरचना ssh *);
पूर्णाङ्क	 kex_server_update_ext_info(संरचना ssh *);
शून्य	 kex_समुच्चयः_server_sig_algs(संरचना ssh *, ध्रुव वर्ण *);
शून्य	 kex_समुच्चयः_warn_weak_crypto(संरचना ssh *, पूर्णाङ्क);
शून्य	 kex_check_warn_weak_crypto(संरचना ssh *);

पूर्णाङ्क	 kexgex_client(संरचना ssh *);
पूर्णाङ्क	 kexgex_server(संरचना ssh *);
पूर्णाङ्क	 kex_gen_client(संरचना ssh *);
पूर्णाङ्क	 kex_gen_server(संरचना ssh *);

पूर्णाङ्क	 kex_dh_keypair(संरचना kex *);
पूर्णाङ्क	 kex_dh_enc(संरचना kex *, ध्रुव संरचना sshbuf *, संरचना sshbuf **,
    संरचना sshbuf **);
पूर्णाङ्क	 kex_dh_dec(संरचना kex *, ध्रुव संरचना sshbuf *, संरचना sshbuf **);

पूर्णाङ्क	 kex_ecdh_dec_कुञ्चिका_गणः(संरचना kex *, ध्रुव संरचना sshbuf *, EC_कुञ्चिका *कुञ्चिका,
	    ध्रुव EC_गणः *, पूर्णाङ्क, संरचना sshbuf **);

पूर्णाङ्क	 kex_ecdh_keypair(संरचना kex *);
पूर्णाङ्क	 kex_ecdh_enc(संरचना kex *, ध्रुव संरचना sshbuf *, संरचना sshbuf **,
    संरचना sshbuf **);
पूर्णाङ्क	 kex_ecdh_dec(संरचना kex *, ध्रुव संरचना sshbuf *, संरचना sshbuf **);

पूर्णाङ्क	 kex_c25519_keypair(संरचना kex *);
पूर्णाङ्क	 kex_c25519_enc(संरचना kex *, ध्रुव संरचना sshbuf *, संरचना sshbuf **,
    संरचना sshbuf **);
पूर्णाङ्क	 kex_c25519_dec(संरचना kex *, ध्रुव संरचना sshbuf *, संरचना sshbuf **);

पूर्णाङ्क	 kex_kem_sntrup761x25519_keypair(संरचना kex *);
पूर्णाङ्क	 kex_kem_sntrup761x25519_enc(संरचना kex *, ध्रुव संरचना sshbuf *,
    संरचना sshbuf **, संरचना sshbuf **);
पूर्णाङ्क	 kex_kem_sntrup761x25519_dec(संरचना kex *, ध्रुव संरचना sshbuf *,
    संरचना sshbuf **);

पूर्णाङ्क	 kex_kem_mlkem768x25519_keypair(संरचना kex *);
पूर्णाङ्क	 kex_kem_mlkem768x25519_enc(संरचना kex *, ध्रुव संरचना sshbuf *,
    संरचना sshbuf **, संरचना sshbuf **);
पूर्णाङ्क	 kex_kem_mlkem768x25519_dec(संरचना kex *, ध्रुव संरचना sshbuf *,
    संरचना sshbuf **);

पूर्णाङ्क	 kex_kem_mlkem768ecdh_keypair(संरचना kex *);
पूर्णाङ्क	 kex_kem_mlkem768ecdh_enc(संरचना kex *, ध्रुव संरचना sshbuf *,
    संरचना sshbuf **, संरचना sshbuf **);
पूर्णाङ्क	 kex_kem_mlkem768ecdh_dec(संरचना kex *, ध्रुव संरचना sshbuf *,
    संरचना sshbuf **);

पूर्णाङ्क	 kex_dh_keygen(संरचना kex *);
पूर्णाङ्क	 kex_dh_compute_कुञ्चिका(संरचना kex *, BIGNUM *, संरचना sshbuf *);

पूर्णाङ्क	 kexgex_hash(पूर्णाङ्क, ध्रुव संरचना sshbuf *, ध्रुव संरचना sshbuf *,
    ध्रुव संरचना sshbuf *, ध्रुव संरचना sshbuf *, ध्रुव संरचना sshbuf *,
    पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क,
    ध्रुव BIGNUM *, ध्रुव BIGNUM *, ध्रुव BIGNUM *,
    ध्रुव BIGNUM *, ध्रुव u_char *, आकार_t,
    u_char *, आकार_t *);

शून्य	kexc25519_keygen(u_char कुञ्चिका[CURVE25519_आकार], u_char pub[CURVE25519_आकार])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_आकार)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_आकार)));
पूर्णाङ्क	kexc25519_shared_कुञ्चिका(ध्रुव u_char कुञ्चिका[CURVE25519_आकार],
    ध्रुव u_char pub[CURVE25519_आकार], संरचना sshbuf *बहिर्गमनम्)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_आकार)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_आकार)));
पूर्णाङ्क	kexc25519_shared_कुञ्चिका_ext(ध्रुव u_char कुञ्चिका[CURVE25519_आकार],
    ध्रुव u_char pub[CURVE25519_आकार], संरचना sshbuf *बहिर्गमनम्, पूर्णाङ्क)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_आकार)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_आकार)));

#यदि defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
शून्य	dump_digest(ध्रुव वर्ण *, ध्रुव u_char *, पूर्णाङ्क);
#यदि_अन्तः

#यदि_अन्तः
