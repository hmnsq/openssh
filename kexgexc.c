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

#ifdef WITH_OPENSSL
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

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_kex_dh_gex_group(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_kex_dh_gex_reply(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);

ಪೂರ್ಣಾಙ್ಕ
kexgex_client(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int nbits;

	nbits = dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	ಯದಿ (ssh->compat & SSH_BUG_DHGEX_LARGE)
		kex->nbits = MINIMUM(kex->nbits, 4096);
	/* New GEX request */
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->min)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->nbits)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->max)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಗಚ್ಛ out;
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
	    kex->min, kex->nbits, kex->max);
#ifdef DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d\n",
	    kex->min, kex->nbits, kex->max);
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_GROUP");
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_GROUP,
	    &ಒಳಹರಿವು_kex_dh_gex_group);
	r = 0;
 out:
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_kex_dh_gex_group(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;
	BIGNUM *p = ರಿಕ್ತ, *g = ರಿಕ್ತ;
	ಧ್ರುವ BIGNUM *pub_ಕೀಲಿ;
	ಪೂರ್ಣಾಙ್ಕ r, bits;

	debug("SSH2_MSG_KEX_DH_GEX_GROUP received");
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_GROUP, &kex_protocol_error);

	ಯದಿ ((r = sshpkt_get_bignum2(ssh, &p)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, &g)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((bits = BN_ಅಂಕೆ_bits(p)) < 0 ||
	    (u_int)bits < kex->min || (u_int)bits > kex->max) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((kex->dh = dh_new_group(g, p)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	p = g = ರಿಕ್ತ; /* belong to kex->dh now */

	/* generate and send 'e', client DH public key */
	ಯದಿ ((r = dh_gen_ಕೀಲಿ(kex->dh, kex->we_need * 8)) != 0)
		ಗಚ್ಛ out;
	DH_get0_ಕೀಲಿ(kex->dh, &pub_ಕೀಲಿ, ರಿಕ್ತ);
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_INIT)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_ಕೀಲಿ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಗಚ್ಛ out;
	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_ಕೀಲಿ);
	fprintf(stderr, "\n");
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_REPLY");
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_REPLY, &ಒಳಹರಿವು_kex_dh_gex_reply);
	r = 0;
out:
	BN_clear_free(p);
	BN_clear_free(g);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_kex_dh_gex_reply(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;
	BIGNUM *dh_server_pub = ರಿಕ್ತ;
	ಧ್ರುವ BIGNUM *pub_ಕೀಲಿ, *dh_p, *dh_g;
	ಸಂರಚನಾ sshbuf *shared_secret = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *tmp = ರಿಕ್ತ, *server_host_ಕೀಲಿ_blob = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *server_host_ಕೀಲಿ = ರಿಕ್ತ;
	u_char *signature = ರಿಕ್ತ;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug("SSH2_MSG_KEX_DH_GEX_REPLY received");
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEX_DH_GEX_REPLY, &kex_protocol_error);

	/* key, cert */
	ಯದಿ ((r = sshpkt_getb_froms(ssh, &server_host_ಕೀಲಿ_blob)) != 0)
		ಗಚ್ಛ out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	ಯದಿ ((tmp = sshbuf_fromb(server_host_ಕೀಲಿ_blob)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshkey_fromb_allowlist(tmp, &server_host_ಕೀಲಿ,
	    kex->hostkey_alg, ರಿಕ್ತ)) != 0 ||
	    (r = kex_verify_host_ಕೀಲಿ(ssh, server_host_ಕೀಲಿ)) != 0)
		ಗಚ್ಛ out;
	/* DH parameter f, server public DH key, signed H */
	ಯದಿ ((r = sshpkt_get_bignum2(ssh, &dh_server_pub)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((shared_secret = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = kex_dh_compute_ಕೀಲಿ(kex, dh_server_pub, shared_secret)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (ssh->compat & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	/* calc and verify H */
	DH_get0_ಕೀಲಿ(kex->dh, &pub_ಕೀಲಿ, ರಿಕ್ತ);
	DH_get0_pqg(kex->dh, &dh_p, ರಿಕ್ತ, &dh_g);
	hashlen = ಪರಿಮಾಣ(hash);
	ಯದಿ ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_ಕೀಲಿ_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    pub_ಕೀಲಿ,
	    dh_server_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ ((r = sshkey_verify(server_host_ಕೀಲಿ, signature, slen, hash,
	    hashlen, kex->hostkey_alg, ssh->compat, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ ((r = kex_derive_ಕೀಲಿಗಳು(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ಗಚ್ಛ out;

	/* save initial signature and hostkey */
	ಯದಿ ((kex->flags & KEX_INITIAL) != 0) {
		ಯದಿ (kex->initial_hostkey != ರಿಕ್ತ || kex->initial_sig != ರಿಕ್ತ) {
			r = SSH_ERR_INTERNAL_ERROR;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((kex->initial_sig = sshbuf_new()) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			ಗಚ್ಛ out;
		kex->initial_hostkey = server_host_ಕೀಲಿ;
		server_host_ಕೀಲಿ = ರಿಕ್ತ;
	}
	/* success */
 out:
	explicit_bzero(hash, ಪರಿಮಾಣ(hash));
	DH_free(kex->dh);
	kex->dh = ರಿಕ್ತ;
	BN_clear_free(dh_server_pub);
	sshbuf_free(shared_secret);
	sshkey_free(server_host_ಕೀಲಿ);
	sshbuf_free(tmp);
	sshbuf_free(server_host_ಕೀಲಿ_blob);
	ಮುಕ್ತ(signature);
	ಪ್ರತ್ಯಾಗಮ r;
}
#endif /* WITH_OPENSSL */
