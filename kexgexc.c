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

#અન્તર્ભાવ "includes.h"

#ifdef WITH_OPENSSL
#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/dh.h>

#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <signal.h>

#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "dh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "dispatch.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "misc.h"

સ્થિર પૂર્ણાંક આગત_kex_dh_gex_group(પૂર્ણાંક, uint32_t, સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_kex_dh_gex_reply(પૂર્ણાંક, uint32_t, સંરચના ssh *);

પૂર્ણાંક
kexgex_client(સંરચના ssh *ssh)
{
	સંરચના kex *kex = ssh->kex;
	પૂર્ણાંક r;
	u_int nbits;

	nbits = dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	જો (ssh->compat & SSH_BUG_DHGEX_LARGE)
		kex->nbits = MINIMUM(kex->nbits, 4096);
	/* New GEX request */
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_KEX_DH_GEX_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->min)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->nbits)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->max)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		જાઓ out;
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
	    kex->min, kex->nbits, kex->max);
#ifdef DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d\n",
	    kex->min, kex->nbits, kex->max);
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_GROUP");
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEX_DH_GEX_GROUP,
	    &આગત_kex_dh_gex_group);
	r = 0;
 out:
	પાછા r;
}

સ્થિર પૂર્ણાંક
આગત_kex_dh_gex_group(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	સંરચના kex *kex = ssh->kex;
	BIGNUM *p = ખાલી, *g = ખાલી;
	અચલ BIGNUM *pub_ચાવી;
	પૂર્ણાંક r, bits;

	debug("SSH2_MSG_KEX_DH_GEX_GROUP received");
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEX_DH_GEX_GROUP, &kex_protocol_error);

	જો ((r = sshpkt_get_bignum2(ssh, &p)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, &g)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		જાઓ out;
	જો ((bits = BN_અંક_bits(p)) < 0 ||
	    (u_int)bits < kex->min || (u_int)bits > kex->max) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		જાઓ out;
	}
	જો ((kex->dh = dh_new_group(g, p)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	p = g = ખાલી; /* belong to kex->dh now */

	/* generate and send 'e', client DH public key */
	જો ((r = dh_gen_ચાવી(kex->dh, kex->we_need * 8)) != 0)
		જાઓ out;
	DH_get0_ચાવી(kex->dh, &pub_ચાવી, ખાલી);
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_KEX_DH_GEX_INIT)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_ચાવી)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		જાઓ out;
	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_ચાવી);
	fprintf(stderr, "\n");
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_REPLY");
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEX_DH_GEX_REPLY, &આગત_kex_dh_gex_reply);
	r = 0;
out:
	BN_clear_free(p);
	BN_clear_free(g);
	પાછા r;
}

સ્થિર પૂર્ણાંક
આગત_kex_dh_gex_reply(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	સંરચના kex *kex = ssh->kex;
	BIGNUM *dh_server_pub = ખાલી;
	અચલ BIGNUM *pub_ચાવી, *dh_p, *dh_g;
	સંરચના sshbuf *shared_secret = ખાલી;
	સંરચના sshbuf *tmp = ખાલી, *server_host_ચાવી_blob = ખાલી;
	સંરચના sshkey *server_host_ચાવી = ખાલી;
	u_char *signature = ખાલી;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	પૂર્ણાંક r;

	debug("SSH2_MSG_KEX_DH_GEX_REPLY received");
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEX_DH_GEX_REPLY, &kex_protocol_error);

	/* key, cert */
	જો ((r = sshpkt_getb_froms(ssh, &server_host_ચાવી_blob)) != 0)
		જાઓ out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	જો ((tmp = sshbuf_fromb(server_host_ચાવી_blob)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshkey_fromb_allowlist(tmp, &server_host_ચાવી,
	    kex->hostkey_alg, ખાલી)) != 0 ||
	    (r = kex_verify_host_ચાવી(ssh, server_host_ચાવી)) != 0)
		જાઓ out;
	/* DH parameter f, server public DH key, signed H */
	જો ((r = sshpkt_get_bignum2(ssh, &dh_server_pub)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		જાઓ out;
	જો ((shared_secret = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = kex_dh_compute_ચાવી(kex, dh_server_pub, shared_secret)) != 0)
		જાઓ out;
	જો (ssh->compat & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	/* calc and verify H */
	DH_get0_ચાવી(kex->dh, &pub_ચાવી, ખાલી);
	DH_get0_pqg(kex->dh, &dh_p, ખાલી, &dh_g);
	hashlen = કદ(hash);
	જો ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_ચાવી_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    pub_ચાવી,
	    dh_server_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		જાઓ out;

	જો ((r = sshkey_verify(server_host_ચાવી, signature, slen, hash,
	    hashlen, kex->hostkey_alg, ssh->compat, ખાલી)) != 0)
		જાઓ out;

	જો ((r = kex_derive_ચાવીઓ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		જાઓ out;

	/* save initial signature and hostkey */
	જો ((kex->flags & KEX_INITIAL) != 0) {
		જો (kex->initial_hostkey != ખાલી || kex->initial_sig != ખાલી) {
			r = SSH_ERR_INTERNAL_ERROR;
			જાઓ out;
		}
		જો ((kex->initial_sig = sshbuf_new()) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		જો ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			જાઓ out;
		kex->initial_hostkey = server_host_ચાવી;
		server_host_ચાવી = ખાલી;
	}
	/* success */
 out:
	explicit_bzero(hash, કદ(hash));
	DH_free(kex->dh);
	kex->dh = ખાલી;
	BN_clear_free(dh_server_pub);
	sshbuf_free(shared_secret);
	sshkey_free(server_host_ચાવી);
	sshbuf_free(tmp);
	sshbuf_free(server_host_ચાવી_blob);
	મુક્ત(signature);
	પાછા r;
}
#endif /* WITH_OPENSSL */
