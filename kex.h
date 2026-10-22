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
#اگر_غیر_تعریف_شدہ KEX_H
#تعریف_کرو KEX_H

#شامل "mac.h"
#شامل "crypto_api.h"

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/dh.h>
#شامل <openssl/ec.h>
#شامل <openssl/ecdsa.h>
#ورنہ /* OPENSSL */
#تعریف_کرو BIGNUM		خالی
#تعریف_کرو DH		خالی
#تعریف_کرو EC_کلید		خالی
#تعریف_کرو EC_گروہ	خالی
#اگر_ختم /* WITH_OPENSSL */

#تعریف_کرو KEX_COOKIE_LEN	16

#تعریف_کرو	KEX_DH1				"diffie-hellman-group1-sha1"
#تعریف_کرو	KEX_DH14_SHA1			"diffie-hellman-group14-sha1"
#تعریف_کرو	KEX_DH14_SHA256			"diffie-hellman-group14-sha256"
#تعریف_کرو	KEX_DH16_SHA512			"diffie-hellman-group16-sha512"
#تعریف_کرو	KEX_DH18_SHA512			"diffie-hellman-group18-sha512"
#تعریف_کرو	KEX_DHGEX_SHA1			"diffie-hellman-group-exchange-sha1"
#تعریف_کرو	KEX_DHGEX_SHA256		"diffie-hellman-group-exchange-sha256"
#تعریف_کرو	KEX_ECDH_SHA2_NISTP256		"ecdh-sha2-nistp256"
#تعریف_کرو	KEX_ECDH_SHA2_NISTP384		"ecdh-sha2-nistp384"
#تعریف_کرو	KEX_ECDH_SHA2_NISTP521		"ecdh-sha2-nistp521"
#تعریف_کرو	KEX_CURVE25519_SHA256		"curve25519-sha256"
#تعریف_کرو	KEX_CURVE25519_SHA256_OLD	"curve25519-sha256@libssh.org"
#تعریف_کرو	KEX_SNTRUP761X25519_SHA512	"sntrup761x25519-sha512"
#تعریف_کرو	KEX_SNTRUP761X25519_SHA512_OLD	"sntrup761x25519-sha512@openssh.com"
#تعریف_کرو	KEX_MLKEM768X25519_SHA256	"mlkem768x25519-sha256"
#تعریف_کرو	KEX_MLKEM768NISTP256_SHA256	"mlkem768nistp256-sha256"

#تعریف_کرو COMP_NONE	0
#تعریف_کرو COMP_DELAYED	2

#تعریف_کرو CURVE25519_سائز 32

شمار kex_init_proposals {
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

شمار kex_modes {
	منوال_اندر,
	منوال_برآمد,
	منوال_MAX
};

شمار kex_exchange {
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
#تعریف_کرو KEX_INIT_بھیجا			0x0001
#تعریف_کرو KEX_INITIAL			0x0002
#تعریف_کرو KEX_HAS_PUBKEY_HOSTBOUND	0x0004
#تعریف_کرو KEX_RSA_SHA2_256_SUPPORTED	0x0008 /* only set in server for now */
#تعریف_کرو KEX_RSA_SHA2_512_SUPPORTED	0x0010 /* only set in server for now */
#تعریف_کرو KEX_HAS_PING			0x0020
#تعریف_کرو KEX_HAS_EXT_INFO_اندر_AUTH	0x0040
#تعریف_کرو KEX_HAS_NEWAGENT		0x0080 /* only set in client */
#تعریف_کرو KEX_INIT_RECVD			0x0100

/* kex->pq */
#تعریف_کرو KEX_NOT_PQ			0
#تعریف_کرو KEX_IS_PQ			1

ساخت sshenc {
	حرف	*name;
	ثابت ساخت sshcipher *cipher;
	صحیح	enabled;
	u_int	کلید_len;
	u_int	iv_len;
	u_int	بلاک_سائز;
	u_char	*کلید;
	u_char	*iv;
};
ساخت sshcomp {
	u_int	type;
	صحیح	enabled;
	حرف	*name;
};
ساخت newkeys {
	ساخت sshenc	enc;
	ساخت sshmac	mac;
	ساخت sshcomp  comp;
};

ساخت ssh;
ساخت sshbuf;

ساخت kex {
	ساخت newkeys	*newkeys[منوال_MAX];
	u_int	we_need;
	u_int	dh_need;
	صحیح	server;
	حرف	*name;
	حرف	*hostkey_alg;
	صحیح	hostkey_type;
	صحیح	hostkey_nid;
	u_int	kex_type;
	حرف	*server_sig_algs;
	صحیح	ext_info_c;
	صحیح	ext_info_s;
	صحیح	kex_strict;
	صحیح	ext_info_received;
	ساخت sshbuf *my;
	ساخت sshbuf *peer;
	ساخت sshbuf *client_نسخہ;
	ساخت sshbuf *server_نسخہ;
	ساخت sshbuf *session_id;
	ساخت sshbuf *initial_sig;
	ساخت sshkey *initial_hostkey;
	sig_atomic_t مکمل;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	صحیح	hash_alg;
	صحیح	ec_nid;
	حرف	*failed_choice;
	صحیح	(*verify_host_کلید)(ساخت sshkey *, ساخت ssh *);
	ساخت sshkey *(*بھرو_host_عوامی_کلید)(صحیح, صحیح, ساخت ssh *);
	ساخت sshkey *(*بھرو_host_نجی_کلید)(صحیح, صحیح, ساخت ssh *);
	صحیح	(*host_کلید_اشاریہ)(ساخت sshkey *, صحیح, ساخت ssh *);
	صحیح	(*sign)(ساخت ssh *, ساخت sshkey *, ساخت sshkey *,
	    u_char **, سائز_t *, ثابت u_char *, سائز_t, ثابت حرف *);
	صحیح	(*kex[KEX_MAX])(ساخت ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_کلید	*ec_client_کلید;		/* ECDH */
	ثابت EC_گروہ *ec_گروہ;	/* ECDH */
	u_char c25519_client_کلید[CURVE25519_سائز]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_سائز]; /* 25519 */
	u_char sntrup761_client_کلید[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_کلید[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	ساخت sshbuf *client_pub;
};

صحیح	 kex_name_valid(ثابت حرف *);
u_int	 kex_type_from_name(ثابت حرف *);
صحیح	 kex_hash_from_name(ثابت حرف *);
صحیح	 kex_nid_from_name(ثابت حرف *);
صحیح	 kex_is_pq_from_name(ثابت حرف *);
صحیح	 kex_نام_valid(ثابت حرف *);
حرف	*kex_alg_list(حرف);
حرف	*kex_نام_cat(ثابت حرف *, ثابت حرف *);
صحیح	 kex_has_any_alg(ثابت حرف *, ثابت حرف *);
صحیح	 kex_assemble_نام(حرف **, ثابت حرف *, ثابت حرف *);
خالی	 kex_proposal_populate_entries(ساخت ssh *, حرف *prop[PROPOSAL_MAX],
    ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);
خالی	 kex_proposal_free_entries(حرف *prop[PROPOSAL_MAX]);

صحیح	 kex_exchange_identification(ساخت ssh *, صحیح, ثابت حرف *);

ساخت kex *kex_new(خالی);
صحیح	 kex_ready(ساخت ssh *, حرف *[PROPOSAL_MAX]);
صحیح	 kex_تیاری(ساخت ssh *, حرف *[PROPOSAL_MAX]);
خالی	 kex_free_newkeys(ساخت newkeys *);
خالی	 kex_free(ساخت kex *);

صحیح	 kex_buf2prop(ساخت sshbuf *, صحیح *, حرف ***);
صحیح	 kex_prop2buf(ساخت sshbuf *, حرف *proposal[PROPOSAL_MAX]);
خالی	 kex_prop_free(حرف **);
صحیح	 kex_بھرو_hostkey(ساخت ssh *, ساخت sshkey **, ساخت sshkey **);
صحیح	 kex_verify_host_کلید(ساخت ssh *, ساخت sshkey *);

صحیح	 kex_send_kexinit(ساخت ssh *);
صحیح	 kex_داخلہ_kexinit(صحیح, uint32_t, ساخت ssh *);
صحیح	 kex_داخلہ_ext_info(صحیح, uint32_t, ساخت ssh *);
صحیح	 kex_protocol_error(صحیح, uint32_t, ساخت ssh *);
صحیح	 kex_derive_کلیدیں(ساخت ssh *, u_char *, u_int, ثابت ساخت sshbuf *);
صحیح	 kex_send_newkeys(ساخت ssh *);
صحیح	 kex_آغاز_rekex(ساخت ssh *);
صحیح	 kex_server_update_ext_info(ساخت ssh *);
خالی	 kex_سیٹ_server_sig_algs(ساخت ssh *, ثابت حرف *);
خالی	 kex_سیٹ_warn_weak_crypto(ساخت ssh *, صحیح);
خالی	 kex_check_warn_weak_crypto(ساخت ssh *);

صحیح	 kexgex_client(ساخت ssh *);
صحیح	 kexgex_server(ساخت ssh *);
صحیح	 kex_gen_client(ساخت ssh *);
صحیح	 kex_gen_server(ساخت ssh *);

صحیح	 kex_dh_keypair(ساخت kex *);
صحیح	 kex_dh_enc(ساخت kex *, ثابت ساخت sshbuf *, ساخت sshbuf **,
    ساخت sshbuf **);
صحیح	 kex_dh_dec(ساخت kex *, ثابت ساخت sshbuf *, ساخت sshbuf **);

صحیح	 kex_ecdh_dec_کلید_گروہ(ساخت kex *, ثابت ساخت sshbuf *, EC_کلید *کلید,
	    ثابت EC_گروہ *, صحیح, ساخت sshbuf **);

صحیح	 kex_ecdh_keypair(ساخت kex *);
صحیح	 kex_ecdh_enc(ساخت kex *, ثابت ساخت sshbuf *, ساخت sshbuf **,
    ساخت sshbuf **);
صحیح	 kex_ecdh_dec(ساخت kex *, ثابت ساخت sshbuf *, ساخت sshbuf **);

صحیح	 kex_c25519_keypair(ساخت kex *);
صحیح	 kex_c25519_enc(ساخت kex *, ثابت ساخت sshbuf *, ساخت sshbuf **,
    ساخت sshbuf **);
صحیح	 kex_c25519_dec(ساخت kex *, ثابت ساخت sshbuf *, ساخت sshbuf **);

صحیح	 kex_kem_sntrup761x25519_keypair(ساخت kex *);
صحیح	 kex_kem_sntrup761x25519_enc(ساخت kex *, ثابت ساخت sshbuf *,
    ساخت sshbuf **, ساخت sshbuf **);
صحیح	 kex_kem_sntrup761x25519_dec(ساخت kex *, ثابت ساخت sshbuf *,
    ساخت sshbuf **);

صحیح	 kex_kem_mlkem768x25519_keypair(ساخت kex *);
صحیح	 kex_kem_mlkem768x25519_enc(ساخت kex *, ثابت ساخت sshbuf *,
    ساخت sshbuf **, ساخت sshbuf **);
صحیح	 kex_kem_mlkem768x25519_dec(ساخت kex *, ثابت ساخت sshbuf *,
    ساخت sshbuf **);

صحیح	 kex_kem_mlkem768ecdh_keypair(ساخت kex *);
صحیح	 kex_kem_mlkem768ecdh_enc(ساخت kex *, ثابت ساخت sshbuf *,
    ساخت sshbuf **, ساخت sshbuf **);
صحیح	 kex_kem_mlkem768ecdh_dec(ساخت kex *, ثابت ساخت sshbuf *,
    ساخت sshbuf **);

صحیح	 kex_dh_keygen(ساخت kex *);
صحیح	 kex_dh_compute_کلید(ساخت kex *, BIGNUM *, ساخت sshbuf *);

صحیح	 kexgex_hash(صحیح, ثابت ساخت sshbuf *, ثابت ساخت sshbuf *,
    ثابت ساخت sshbuf *, ثابت ساخت sshbuf *, ثابت ساخت sshbuf *,
    صحیح, صحیح, صحیح,
    ثابت BIGNUM *, ثابت BIGNUM *, ثابت BIGNUM *,
    ثابت BIGNUM *, ثابت u_char *, سائز_t,
    u_char *, سائز_t *);

خالی	kexc25519_keygen(u_char کلید[CURVE25519_سائز], u_char pub[CURVE25519_سائز])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_سائز)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_سائز)));
صحیح	kexc25519_shared_کلید(ثابت u_char کلید[CURVE25519_سائز],
    ثابت u_char pub[CURVE25519_سائز], ساخت sshbuf *برآمد)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_سائز)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_سائز)));
صحیح	kexc25519_shared_کلید_ext(ثابت u_char کلید[CURVE25519_سائز],
    ثابت u_char pub[CURVE25519_سائز], ساخت sshbuf *برآمد, صحیح)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_سائز)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_سائز)));

#اگر defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
خالی	dump_digest(ثابت حرف *, ثابت u_char *, صحیح);
#اگر_ختم

#اگر_ختم
