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

#અન્તર્ભાવ "includes.h"

#ifdef WITH_OPENSSL
#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <signal.h>

#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/dh.h>

#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "dh.h"
#અન્તર્ભાવ "ssh2.h"
#ifdef GSSAPI
#અન્તર્ભાવ "ssh-gss.h"
#endif
#અન્તર્ભાવ "monitor_wrap.h"
#અન્તર્ભાવ "dispatch.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "misc.h"

સ્થિર પૂર્ણાંક આગત_kex_dh_gex_request(પૂર્ણાંક, uint32_t, સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_kex_dh_gex_init(પૂર્ણાંક, uint32_t, સંરચના ssh *);

પૂર્ણાંક
kexgex_server(સંરચના ssh *ssh)
{
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEX_DH_GEX_REQUEST,
	    &આગત_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	પાછા 0;
}

સ્થિર પૂર્ણાંક
આગત_kex_dh_gex_request(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	સંરચના kex *kex = ssh->kex;
	પૂર્ણાંક r;
	u_int min = 0, max = 0, nbits = 0;
	અચલ BIGNUM *dh_p, *dh_g;

	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	જો ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		જાઓ out;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = MAXIMUM(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = MAXIMUM(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	જો (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		જાઓ out;
	}

	/* Contact privileged parent */
	kex->dh = mm_choose_dh(min, nbits, max);
	જો (kex->dh == ખાલી) {
		(શૂન્ય)sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	DH_get0_pqg(kex->dh, &dh_p, ખાલી, &dh_g);
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_KEX_DH_GEX_GROUP)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		જાઓ out;

	/* Compute our exchange value in parallel with the client */
	જો ((r = dh_gen_ચાવી(kex->dh, kex->we_need * 8)) != 0)
		જાઓ out;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEX_DH_GEX_INIT, &આગત_kex_dh_gex_init);
	r = 0;
 out:
	પાછા r;
}

સ્થિર પૂર્ણાંક
આગત_kex_dh_gex_init(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	સંરચના kex *kex = ssh->kex;
	BIGNUM *dh_client_pub = ખાલી;
	અચલ BIGNUM *pub_ચાવી, *dh_p, *dh_g;
	સંરચના sshbuf *shared_secret = ખાલી;
	સંરચના sshbuf *server_host_ચાવી_blob = ખાલી;
	સંરચના sshkey *server_host_public, *server_host_private;
	u_char *signature = ખાલી;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	પૂર્ણાંક r;

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEX_DH_GEX_INIT, &kex_protocol_error);

	જો ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		જાઓ out;

	/* key, cert */
	જો ((r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		જાઓ out;
	જો ((shared_secret = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = kex_dh_compute_ચાવી(kex, dh_client_pub, shared_secret)) != 0)
		જાઓ out;
	જો ((server_host_ચાવી_blob = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshkey_putb(server_host_public, server_host_ચાવી_blob)) != 0)
		જાઓ out;

	/* calc H */
	DH_get0_ચાવી(kex->dh, &pub_ચાવી, ખાલી);
	DH_get0_pqg(kex->dh, &dh_p, ખાલી, &dh_g);
	hashlen = કદ(hash);
	જો ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_ચાવી_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    dh_client_pub,
	    pub_ચાવી,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		જાઓ out;

	/* sign H */
	જો ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		જાઓ out;

	/* send server hostkey, DH pubkey 'f' and signed H */
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_KEX_DH_GEX_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_ચાવી_blob)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_ચાવી)) != 0 ||     /* f */
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		જાઓ out;

	જો ((r = kex_derive_ચાવીઓ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		જાઓ out;

	/* retain copy of hostkey used at initial KEX */
	જો (kex->initial_hostkey == ખાલી &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		જાઓ out;
	/* success */
 out:
	explicit_bzero(hash, કદ(hash));
	DH_free(kex->dh);
	kex->dh = ખાલી;
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_ચાવી_blob);
	મુક્ત(signature);
	પાછા r;
}
#endif /* WITH_OPENSSL */
