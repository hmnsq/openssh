/* $OpenBSD: kexgexc.c,v 1.43 2026/09/16 00:31:27 djm Exp $ */
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

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/dh.h>

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <signal.h>

#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "dh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "dispatch.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_kex_dh_gex_ಗುಂಪು(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_kex_dh_gex_ಉತ್ತರ(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);

ಪೂರ್ಣಾಂಕ
kexgex_client(ರಚನೆ ssh *ssh)
{
	ರಚನೆ kex *kex = ssh->kex;
	ಪೂರ್ಣಾಂಕ r;
	u_int nbits;

	nbits = dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	ಆದರೆ (ssh->compat & SSH_BUG_DHGEX_LARGE)
		kex->nbits = MINIMUM(kex->nbits, 4096);
	/* New GEX request */
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->min)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->nbits)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->max)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
	    kex->min, kex->nbits, kex->max);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d\n",
	    kex->min, kex->nbits, kex->max);
#ಆದರೆ_ಅಂತ್ಯ
	debug("expecting SSH2_MSG_KEX_DH_GEX_GROUP");
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_ಗುಂಪು,
	    &ಒಳಹರಿವು_kex_dh_gex_ಗುಂಪು);
	r = 0;
 ಹೊರಹೋಗು:
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_kex_dh_gex_ಗುಂಪು(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ರಚನೆ kex *kex = ssh->kex;
	BIGNUM *p = ಖಾಲಿ, *g = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ BIGNUM *pub_ಕೀಲಿ;
	ಪೂರ್ಣಾಂಕ r, ಬಿಟ್ಟುಗಳು;

	debug("SSH2_MSG_KEX_DH_GEX_GROUP received");
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_ಗುಂಪು, &kex_protocol_error);

	ಆದರೆ ((r = sshpkt_get_bignum2(ssh, &p)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, &g)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((ಬಿಟ್ಟುಗಳು = BN_ಅಂಕೆ_ಬಿಟ್ಟುಗಳು(p)) < 0 ||
	    (u_int)ಬಿಟ್ಟುಗಳು < kex->min || (u_int)ಬಿಟ್ಟುಗಳು > kex->max) {
		r = SSH_ERR_DH_GEX_ಹೊರಹೋಗು_ದ_RANGE;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((kex->dh = dh_new_ಗುಂಪು(g, p)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	p = g = ಖಾಲಿ; /* belong to kex->dh now */

	/* generate and send 'e', client DH public key */
	ಆದರೆ ((r = dh_gen_ಕೀಲಿ(kex->dh, kex->we_need * 8)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	DH_get0_ಕೀಲಿ(kex->dh, &pub_ಕೀಲಿ, ಖಾಲಿ);
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_INIT)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_ಕೀಲಿ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_ಕೀಲಿ);
	fprintf(stderr, "\n");
#ಆದರೆ_ಅಂತ್ಯ
	debug("expecting SSH2_MSG_KEX_DH_GEX_REPLY");
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_ಉತ್ತರ, &ಒಳಹರಿವು_kex_dh_gex_ಉತ್ತರ);
	r = 0;
ಹೊರಹೋಗು:
	BN_clear_free(p);
	BN_clear_free(g);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_kex_dh_gex_ಉತ್ತರ(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ರಚನೆ kex *kex = ssh->kex;
	BIGNUM *dh_server_pub = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ BIGNUM *pub_ಕೀಲಿ, *dh_p, *dh_g;
	ರಚನೆ sshbuf *shared_secret = ಖಾಲಿ;
	ರಚನೆ sshbuf *tmp = ಖಾಲಿ, *server_host_ಕೀಲಿ_blob = ಖಾಲಿ;
	ರಚನೆ sshkey *server_host_ಕೀಲಿ = ಖಾಲಿ;
	u_char *signature = ಖಾಲಿ;
	u_char hash[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];
	ಗಾತ್ರ_t slen, hashlen;
	ಪೂರ್ಣಾಂಕ r;

	debug("SSH2_MSG_KEX_DH_GEX_REPLY received");
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_ಉತ್ತರ, &kex_protocol_error);

	/* key, cert */
	ಆದರೆ ((r = sshpkt_getb_froms(ssh, &server_host_ಕೀಲಿ_blob)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	ಆದರೆ ((tmp = sshbuf_fromb(server_host_ಕೀಲಿ_blob)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshkey_fromb_allowlist(tmp, &server_host_ಕೀಲಿ,
	    kex->hostkey_alg, ಖಾಲಿ)) != 0 ||
	    (r = kex_verify_host_ಕೀಲಿ(ssh, server_host_ಕೀಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* DH parameter f, server public DH key, signed H */
	ಆದರೆ ((r = sshpkt_get_bignum2(ssh, &dh_server_pub)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((shared_secret = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = kex_dh_compute_ಕೀಲಿ(kex, dh_server_pub, shared_secret)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (ssh->compat & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	/* calc and verify H */
	DH_get0_ಕೀಲಿ(kex->dh, &pub_ಕೀಲಿ, ಖಾಲಿ);
	DH_get0_pqg(kex->dh, &dh_p, ಖಾಲಿ, &dh_g);
	hashlen = ಗಾತ್ರ(hash);
	ಆದರೆ ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_ಆವೃತ್ತಿ,
	    kex->server_ಆವೃತ್ತಿ,
	    kex->my,
	    kex->peer,
	    server_host_ಕೀಲಿ_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    pub_ಕೀಲಿ,
	    dh_server_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((r = sshkey_verify(server_host_ಕೀಲಿ, signature, slen, hash,
	    hashlen, kex->hostkey_alg, ssh->compat, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((r = kex_derive_ಕೀಲಿಗಳು(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* save initial signature and hostkey */
	ಆದರೆ ((kex->flags & KEX_INITIAL) != 0) {
		ಆದರೆ (kex->initial_hostkey != ಖಾಲಿ || kex->initial_sig != ಖಾಲಿ) {
			r = SSH_ERR_ಆಂತರಿಕ_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((kex->initial_sig = sshbuf_new()) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		kex->initial_hostkey = server_host_ಕೀಲಿ;
		server_host_ಕೀಲಿ = ಖಾಲಿ;
	}
	/* success */
 ಹೊರಹೋಗು:
	explicit_bzero(hash, ಗಾತ್ರ(hash));
	DH_free(kex->dh);
	kex->dh = ಖಾಲಿ;
	BN_clear_free(dh_server_pub);
	sshbuf_free(shared_secret);
	sshkey_free(server_host_ಕೀಲಿ);
	sshbuf_free(tmp);
	sshbuf_free(server_host_ಕೀಲಿ_blob);
	ಬಿಡುಗಡೆ(signature);
	ಹಿಂತಿರುಗಿ r;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
