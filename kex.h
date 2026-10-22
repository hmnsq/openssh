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
#جے_بنا_تعریف KEX_H
#تعریف_کرو KEX_H

#ضمن "mac.h"
#ضمن "crypto_api.h"

#جے_تعریف_شدہ WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/dh.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/ecdsa.h>
#وإلا /* OPENSSL */
#تعریف_کرو BIGNUM		فراغ
#تعریف_کرو DH		فراغ
#تعریف_کرو EC_کلید		فراغ
#تعریف_کرو EC_گروہ	فراغ
#جے_انت /* WITH_OPENSSL */

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

#تعریف_کرو CURVE25519_ناپ 32

تعداد kex_init_proposals {
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

تعداد kex_modes {
	منوال_وچ,
	منوال_باہرلا,
	منوال_MAX
};

تعداد kex_exchange {
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
#تعریف_کرو KEX_INIT_گھلیا			0x0001
#تعریف_کرو KEX_INITIAL			0x0002
#تعریف_کرو KEX_HAS_PUBKEY_HOSTBOUND	0x0004
#تعریف_کرو KEX_RSA_SHA2_256_SUPPORTED	0x0008 /* only set in server for now */
#تعریف_کرو KEX_RSA_SHA2_512_SUPPORTED	0x0010 /* only set in server for now */
#تعریف_کرو KEX_HAS_PING			0x0020
#تعریف_کرو KEX_HAS_EXT_INFO_وچ_AUTH	0x0040
#تعریف_کرو KEX_HAS_NEWAGENT		0x0080 /* only set in client */
#تعریف_کرو KEX_INIT_RECVD			0x0100

/* kex->pq */
#تعریف_کرو KEX_NOT_PQ			0
#تعریف_کرو KEX_IS_PQ			1

بنية sshenc {
	حرف	*name;
	ثابت بنية sshcipher *cipher;
	صحيح	enabled;
	u_int	کلید_len;
	u_int	iv_len;
	u_int	بلاک_ناپ;
	u_char	*کلید;
	u_char	*iv;
};
بنية sshcomp {
	u_int	type;
	صحيح	enabled;
	حرف	*name;
};
بنية newkeys {
	بنية sshenc	enc;
	بنية sshmac	mac;
	بنية sshcomp  comp;
};

بنية ssh;
بنية sshbuf;

بنية kex {
	بنية newkeys	*newkeys[منوال_MAX];
	u_int	we_need;
	u_int	dh_need;
	صحيح	server;
	حرف	*name;
	حرف	*hostkey_alg;
	صحيح	hostkey_type;
	صحيح	hostkey_nid;
	u_int	kex_type;
	حرف	*server_sig_algs;
	صحيح	ext_info_c;
	صحيح	ext_info_s;
	صحيح	kex_strict;
	صحيح	ext_info_received;
	بنية sshbuf *my;
	بنية sshbuf *peer;
	بنية sshbuf *client_نسخہ;
	بنية sshbuf *server_نسخہ;
	بنية sshbuf *session_id;
	بنية sshbuf *initial_sig;
	بنية sshkey *initial_hostkey;
	sig_atomic_t پورا;
	u_int	flags;
	u_int	warn_weak_crypto;
	u_int	pq_kex_negotiated;
	u_int	non_pq_kex_warned;
	صحيح	hash_alg;
	صحيح	ec_nid;
	حرف	*failed_choice;
	صحيح	(*verify_host_کلید)(بنية sshkey *, بنية ssh *);
	بنية sshkey *(*لدو_host_عوامی_کلید)(صحيح, صحيح, بنية ssh *);
	بنية sshkey *(*لدو_host_نجی_کلید)(صحيح, صحيح, بنية ssh *);
	صحيح	(*host_کلید_اشاریہ)(بنية sshkey *, صحيح, بنية ssh *);
	صحيح	(*sign)(بنية ssh *, بنية sshkey *, بنية sshkey *,
	    u_char **, ناپ_t *, ثابت u_char *, ناپ_t, ثابت حرف *);
	صحيح	(*kex[KEX_MAX])(بنية ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_کلید	*ec_client_کلید;		/* ECDH */
	ثابت EC_گروہ *ec_گروہ;	/* ECDH */
	u_char c25519_client_کلید[CURVE25519_ناپ]; /* 25519 + KEM */
	u_char c25519_client_pubkey[CURVE25519_ناپ]; /* 25519 */
	u_char sntrup761_client_کلید[crypto_kem_sntrup761_SECRETKEYBYTES]; /* KEM */
	u_char mlkem768_client_کلید[crypto_kem_mlkem768_SECRETKEYBYTES]; /* KEM */
	بنية sshbuf *client_pub;
};

صحيح	 kex_name_valid(ثابت حرف *);
u_int	 kex_type_from_name(ثابت حرف *);
صحيح	 kex_hash_from_name(ثابت حرف *);
صحيح	 kex_nid_from_name(ثابت حرف *);
صحيح	 kex_is_pq_from_name(ثابت حرف *);
صحيح	 kex_ناں_valid(ثابت حرف *);
حرف	*kex_alg_list(حرف);
حرف	*kex_ناں_cat(ثابت حرف *, ثابت حرف *);
صحيح	 kex_has_any_alg(ثابت حرف *, ثابت حرف *);
صحيح	 kex_assemble_ناں(حرف **, ثابت حرف *, ثابت حرف *);
فراغ	 kex_proposal_populate_entries(بنية ssh *, حرف *prop[PROPOSAL_MAX],
    ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *, ثابت حرف *);
فراغ	 kex_proposal_free_entries(حرف *prop[PROPOSAL_MAX]);

صحيح	 kex_exchange_identification(بنية ssh *, صحيح, ثابت حرف *);

بنية kex *kex_new(فراغ);
صحيح	 kex_ready(بنية ssh *, حرف *[PROPOSAL_MAX]);
صحيح	 kex_تیاری(بنية ssh *, حرف *[PROPOSAL_MAX]);
فراغ	 kex_free_newkeys(بنية newkeys *);
فراغ	 kex_free(بنية kex *);

صحيح	 kex_buf2prop(بنية sshbuf *, صحيح *, حرف ***);
صحيح	 kex_prop2buf(بنية sshbuf *, حرف *proposal[PROPOSAL_MAX]);
فراغ	 kex_prop_free(حرف **);
صحيح	 kex_لدو_hostkey(بنية ssh *, بنية sshkey **, بنية sshkey **);
صحيح	 kex_verify_host_کلید(بنية ssh *, بنية sshkey *);

صحيح	 kex_send_kexinit(بنية ssh *);
صحيح	 kex_داخلہ_kexinit(صحيح, uint32_t, بنية ssh *);
صحيح	 kex_داخلہ_ext_info(صحيح, uint32_t, بنية ssh *);
صحيح	 kex_protocol_error(صحيح, uint32_t, بنية ssh *);
صحيح	 kex_derive_کلیدیں(بنية ssh *, u_char *, u_int, ثابت بنية sshbuf *);
صحيح	 kex_send_newkeys(بنية ssh *);
صحيح	 kex_شروع_rekex(بنية ssh *);
صحيح	 kex_server_update_ext_info(بنية ssh *);
فراغ	 kex_سیٹ_server_sig_algs(بنية ssh *, ثابت حرف *);
فراغ	 kex_سیٹ_warn_weak_crypto(بنية ssh *, صحيح);
فراغ	 kex_check_warn_weak_crypto(بنية ssh *);

صحيح	 kexgex_client(بنية ssh *);
صحيح	 kexgex_server(بنية ssh *);
صحيح	 kex_gen_client(بنية ssh *);
صحيح	 kex_gen_server(بنية ssh *);

صحيح	 kex_dh_keypair(بنية kex *);
صحيح	 kex_dh_enc(بنية kex *, ثابت بنية sshbuf *, بنية sshbuf **,
    بنية sshbuf **);
صحيح	 kex_dh_dec(بنية kex *, ثابت بنية sshbuf *, بنية sshbuf **);

صحيح	 kex_ecdh_dec_کلید_گروہ(بنية kex *, ثابت بنية sshbuf *, EC_کلید *کلید,
	    ثابت EC_گروہ *, صحيح, بنية sshbuf **);

صحيح	 kex_ecdh_keypair(بنية kex *);
صحيح	 kex_ecdh_enc(بنية kex *, ثابت بنية sshbuf *, بنية sshbuf **,
    بنية sshbuf **);
صحيح	 kex_ecdh_dec(بنية kex *, ثابت بنية sshbuf *, بنية sshbuf **);

صحيح	 kex_c25519_keypair(بنية kex *);
صحيح	 kex_c25519_enc(بنية kex *, ثابت بنية sshbuf *, بنية sshbuf **,
    بنية sshbuf **);
صحيح	 kex_c25519_dec(بنية kex *, ثابت بنية sshbuf *, بنية sshbuf **);

صحيح	 kex_kem_sntrup761x25519_keypair(بنية kex *);
صحيح	 kex_kem_sntrup761x25519_enc(بنية kex *, ثابت بنية sshbuf *,
    بنية sshbuf **, بنية sshbuf **);
صحيح	 kex_kem_sntrup761x25519_dec(بنية kex *, ثابت بنية sshbuf *,
    بنية sshbuf **);

صحيح	 kex_kem_mlkem768x25519_keypair(بنية kex *);
صحيح	 kex_kem_mlkem768x25519_enc(بنية kex *, ثابت بنية sshbuf *,
    بنية sshbuf **, بنية sshbuf **);
صحيح	 kex_kem_mlkem768x25519_dec(بنية kex *, ثابت بنية sshbuf *,
    بنية sshbuf **);

صحيح	 kex_kem_mlkem768ecdh_keypair(بنية kex *);
صحيح	 kex_kem_mlkem768ecdh_enc(بنية kex *, ثابت بنية sshbuf *,
    بنية sshbuf **, بنية sshbuf **);
صحيح	 kex_kem_mlkem768ecdh_dec(بنية kex *, ثابت بنية sshbuf *,
    بنية sshbuf **);

صحيح	 kex_dh_keygen(بنية kex *);
صحيح	 kex_dh_compute_کلید(بنية kex *, BIGNUM *, بنية sshbuf *);

صحيح	 kexgex_hash(صحيح, ثابت بنية sshbuf *, ثابت بنية sshbuf *,
    ثابت بنية sshbuf *, ثابت بنية sshbuf *, ثابت بنية sshbuf *,
    صحيح, صحيح, صحيح,
    ثابت BIGNUM *, ثابت BIGNUM *, ثابت BIGNUM *,
    ثابت BIGNUM *, ثابت u_char *, ناپ_t,
    u_char *, ناپ_t *);

فراغ	kexc25519_keygen(u_char کلید[CURVE25519_ناپ], u_char pub[CURVE25519_ناپ])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_ناپ)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_ناپ)));
صحيح	kexc25519_shared_کلید(ثابت u_char کلید[CURVE25519_ناپ],
    ثابت u_char pub[CURVE25519_ناپ], بنية sshbuf *باہرلا)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_ناپ)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_ناپ)));
صحيح	kexc25519_shared_کلید_ext(ثابت u_char کلید[CURVE25519_ناپ],
    ثابت u_char pub[CURVE25519_ناپ], بنية sshbuf *باہرلا, صحيح)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_ناپ)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_ناپ)));

#إذا defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
فراغ	dump_digest(ثابت حرف *, ثابت u_char *, صحيح);
#جے_انت

#جے_انت
