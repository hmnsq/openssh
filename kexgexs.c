/* $OpenBSD: kexgexs.c,v 1.51 2026/03/03 09:57:25 dtucker Exp $ */
/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <signal.h>

#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/dh.h>

#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "dh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ifdef GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#endif
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "dispatch.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_kex_dh_gex_request(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_kex_dh_gex_init(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);

ಪೂರ್ಣಾಙ್ಕ
kexgex_server(ಸಂರಚನಾ ssh *ssh)
{
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_REQUEST,
	    &ಒಳಹರಿವು_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_kex_dh_gex_request(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int min = 0, max = 0, nbits = 0;
	ಧ್ರುವ BIGNUM *dh_p, *dh_g;

	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	ಯದಿ ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ಗಚ್ಛ out;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = MAXIMUM(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = MAXIMUM(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	ಯದಿ (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		ಗಚ್ಛ out;
	}

	/* Contact privileged parent */
	kex->dh = mm_choose_dh(min, nbits, max);
	ಯದಿ (kex->dh == ರಿಕ್ತ) {
		(ಶೂನ್ಯ)sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	DH_get0_pqg(kex->dh, &dh_p, ರಿಕ್ತ, &dh_g);
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_GROUP)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಗಚ್ಛ out;

	/* Compute our exchange value in parallel with the client */
	ಯದಿ ((r = dh_gen_ಕೀಲಿ(kex->dh, kex->we_need * 8)) != 0)
		ಗಚ್ಛ out;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_INIT, &ಒಳಹರಿವು_kex_dh_gex_init);
	r = 0;
 out:
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_kex_dh_gex_init(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;
	BIGNUM *dh_client_pub = ರಿಕ್ತ;
	ಧ್ರುವ BIGNUM *pub_ಕೀಲಿ, *dh_p, *dh_g;
	ಸಂರಚನಾ sshbuf *shared_secret = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *server_host_ಕೀಲಿ_blob = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *server_host_public, *server_host_private;
	u_char *signature = ರಿಕ್ತ;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_INIT, &kex_protocol_error);

	ಯದಿ ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		ಗಚ್ಛ out;

	/* key, cert */
	ಯದಿ ((r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((shared_secret = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = kex_dh_compute_ಕೀಲಿ(kex, dh_client_pub, shared_secret)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((server_host_ಕೀಲಿ_blob = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshkey_putb(server_host_public, server_host_ಕೀಲಿ_blob)) != 0)
		ಗಚ್ಛ out;

	/* calc H */
	DH_get0_ಕೀಲಿ(kex->dh, &pub_ಕೀಲಿ, ರಿಕ್ತ);
	DH_get0_pqg(kex->dh, &dh_p, ರಿಕ್ತ, &dh_g);
	hashlen = ಪರಿಮಾಣ(hash);
	ಯದಿ ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_ಕೀಲಿ_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    dh_client_pub,
	    pub_ಕೀಲಿ,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		ಗಚ್ಛ out;

	/* sign H */
	ಯದಿ ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		ಗಚ್ಛ out;

	/* send server hostkey, DH pubkey 'f' and signed H */
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_ಕೀಲಿ_blob)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_ಕೀಲಿ)) != 0 ||     /* f */
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ ((r = kex_derive_ಕೀಲಿಗಳು(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ಗಚ್ಛ out;

	/* retain copy of hostkey used at initial KEX */
	ಯದಿ (kex->initial_hostkey == ರಿಕ್ತ &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		ಗಚ್ಛ out;
	/* success */
 out:
	explicit_bzero(hash, ಪರಿಮಾಣ(hash));
	DH_free(kex->dh);
	kex->dh = ರಿಕ್ತ;
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_ಕೀಲಿ_blob);
	ಮುಕ್ತ(signature);
	ಪ್ರತ್ಯಾಗಮ r;
}
#endif /* WITH_OPENSSL */
