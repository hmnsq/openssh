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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
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
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "dispatch.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_kex_dh_gex_request(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_kex_dh_gex_init(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);

ಪೂರ್ಣಾಂಕ
kexgex_server(ರಚನೆ ssh *ssh)
{
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_REQUEST,
	    &ಒಳಹರಿವು_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_kex_dh_gex_request(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ರಚನೆ kex *kex = ssh->kex;
	ಪೂರ್ಣಾಂಕ r;
	u_int min = 0, max = 0, nbits = 0;
	ಸ್ಥಿರಾಂಕ BIGNUM *dh_p, *dh_g;

	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	ಆದರೆ ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = ಗರಿಷ್ಠ(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = ಗರಿಷ್ಠ(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	ಆದರೆ (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_ಹೊರಹೋಗು_ದ_RANGE;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Contact privileged parent */
	kex->dh = mm_ಆರಿಸು_dh(min, nbits, max);
	ಆದರೆ (kex->dh == ಖಾಲಿ) {
		(ಶೂನ್ಯ)sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	DH_get0_pqg(kex->dh, &dh_p, ಖಾಲಿ, &dh_g);
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_ಗುಂಪು)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Compute our exchange value in parallel with the client */
	ಆದರೆ ((r = dh_gen_ಕೀಲಿ(kex->dh, kex->we_need * 8)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_INIT, &ಒಳಹರಿವು_kex_dh_gex_init);
	r = 0;
 ಹೊರಹೋಗು:
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_kex_dh_gex_init(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ರಚನೆ kex *kex = ssh->kex;
	BIGNUM *dh_client_pub = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ BIGNUM *pub_ಕೀಲಿ, *dh_p, *dh_g;
	ರಚನೆ sshbuf *shared_secret = ಖಾಲಿ;
	ರಚನೆ sshbuf *server_host_ಕೀಲಿ_blob = ಖಾಲಿ;
	ರಚನೆ sshkey *server_host_ಬಹಿರಂಗ, *server_host_ಖಾಸಗಿ;
	u_char *signature = ಖಾಲಿ;
	u_char hash[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];
	ಗಾತ್ರ_t slen, hashlen;
	ಪೂರ್ಣಾಂಕ r;

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_INIT, &kex_protocol_error);

	ಆದರೆ ((r = kex_ತುಂಬು_hostkey(ssh, &server_host_ಖಾಸಗಿ,
	    &server_host_ಬಹಿರಂಗ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* key, cert */
	ಆದರೆ ((r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((shared_secret = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = kex_dh_compute_ಕೀಲಿ(kex, dh_client_pub, shared_secret)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((server_host_ಕೀಲಿ_blob = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshkey_putb(server_host_ಬಹಿರಂಗ, server_host_ಕೀಲಿ_blob)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* calc H */
	DH_get0_ಕೀಲಿ(kex->dh, &pub_ಕೀಲಿ, ಖಾಲಿ);
	DH_get0_pqg(kex->dh, &dh_p, ಖಾಲಿ, &dh_g);
	hashlen = ಗಾತ್ರ(hash);
	ಆದರೆ ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_ಆವೃತ್ತಿ,
	    kex->server_ಆವೃತ್ತಿ,
	    kex->peer,
	    kex->my,
	    server_host_ಕೀಲಿ_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    dh_client_pub,
	    pub_ಕೀಲಿ,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* sign H */
	ಆದರೆ ((r = kex->sign(ssh, server_host_ಖಾಸಗಿ, server_host_ಬಹಿರಂಗ,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* send server hostkey, DH pubkey 'f' and signed H */
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_ಉತ್ತರ)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_ಕೀಲಿ_blob)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_ಕೀಲಿ)) != 0 ||     /* f */
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((r = kex_derive_ಕೀಲಿಗಳು(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* retain copy of hostkey used at initial KEX */
	ಆದರೆ (kex->initial_hostkey == ಖಾಲಿ &&
	    (r = sshkey_from_ಖಾಸಗಿ(server_host_ಬಹಿರಂಗ,
	    &kex->initial_hostkey)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
 ಹೊರಹೋಗು:
	explicit_bzero(hash, ಗಾತ್ರ(hash));
	DH_free(kex->dh);
	kex->dh = ಖಾಲಿ;
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_ಕೀಲಿ_blob);
	ಬಿಡುಗಡೆ(signature);
	ಹಿಂತಿರುಗಿ r;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
