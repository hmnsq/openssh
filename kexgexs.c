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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>

#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/dh.h>

#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "cipher.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "dh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ifdef GSSAPI
#ଅନ୍ତର୍ଭାଵ "ssh-gss.h"
#endif
#ଅନ୍ତର୍ଭାଵ "monitor_wrap.h"
#ଅନ୍ତର୍ଭାଵ "dispatch.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_kex_dh_gex_request(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_kex_dh_gex_init(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kexgex_server(ସଂରଚନା ssh *ssh)
{
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_KEX_DH_GEX_REQUEST,
	    &ନିବେଶ_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_kex_dh_gex_request(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା kex *kex = ssh->kex;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int min = 0, max = 0, nbits = 0;
	ଅଚଳ BIGNUM *dh_p, *dh_g;

	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	ଯଦି ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ଯାଅ out;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = MAXIMUM(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = MAXIMUM(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	ଯଦି (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		ଯାଅ out;
	}

	/* Contact privileged parent */
	kex->dh = mm_choose_dh(min, nbits, max);
	ଯଦି (kex->dh == ଖାଲି) {
		(ଶୂନ୍ୟ)sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	DH_get0_pqg(kex->dh, &dh_p, ଖାଲି, &dh_g);
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_KEX_DH_GEX_GROUP)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ଯାଅ out;

	/* Compute our exchange value in parallel with the client */
	ଯଦି ((r = dh_gen_ଚାବି(kex->dh, kex->we_need * 8)) != 0)
		ଯାଅ out;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_KEX_DH_GEX_INIT, &ନିବେଶ_kex_dh_gex_init);
	r = 0;
 out:
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_kex_dh_gex_init(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା kex *kex = ssh->kex;
	BIGNUM *dh_client_pub = ଖାଲି;
	ଅଚଳ BIGNUM *pub_ଚାବି, *dh_p, *dh_g;
	ସଂରଚନା sshbuf *shared_secret = ଖାଲି;
	ସଂରଚନା sshbuf *server_host_ଚାବି_blob = ଖାଲି;
	ସଂରଚନା sshkey *server_host_public, *server_host_private;
	u_char *signature = ଖାଲି;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_KEX_DH_GEX_INIT, &kex_protocol_error);

	ଯଦି ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		ଯାଅ out;

	/* key, cert */
	ଯଦି ((r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ଯାଅ out;
	ଯଦି ((shared_secret = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = kex_dh_compute_ଚାବି(kex, dh_client_pub, shared_secret)) != 0)
		ଯାଅ out;
	ଯଦି ((server_host_ଚାବି_blob = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshkey_putb(server_host_public, server_host_ଚାବି_blob)) != 0)
		ଯାଅ out;

	/* calc H */
	DH_get0_ଚାବି(kex->dh, &pub_ଚାବି, ଖାଲି);
	DH_get0_pqg(kex->dh, &dh_p, ଖାଲି, &dh_g);
	hashlen = ଆକାର(hash);
	ଯଦି ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_ଚାବି_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    dh_client_pub,
	    pub_ଚାବି,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		ଯାଅ out;

	/* sign H */
	ଯଦି ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		ଯାଅ out;

	/* send server hostkey, DH pubkey 'f' and signed H */
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_KEX_DH_GEX_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_ଚାବି_blob)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_ଚାବି)) != 0 ||     /* f */
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ଯାଅ out;

	ଯଦି ((r = kex_derive_ଚାବିଗୁଡ଼ିକ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ଯାଅ out;

	/* retain copy of hostkey used at initial KEX */
	ଯଦି (kex->initial_hostkey == ଖାଲି &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		ଯାଅ out;
	/* success */
 out:
	explicit_bzero(hash, ଆକାର(hash));
	DH_free(kex->dh);
	kex->dh = ଖାଲି;
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_ଚାବି_blob);
	ମୁକ୍ତ(signature);
	ଫେରନ୍ତୁ r;
}
#endif /* WITH_OPENSSL */
