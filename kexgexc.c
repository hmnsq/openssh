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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/dh.h>

#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>

#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "dh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "dispatch.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_kex_dh_gex_group(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_kex_dh_gex_reply(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kexgex_client(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା kex *kex = ssh->kex;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int nbits;

	nbits = dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	ଯଦି (ssh->compat & SSH_BUG_DHGEX_LARGE)
		kex->nbits = MINIMUM(kex->nbits, 4096);
	/* New GEX request */
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_KEX_DH_GEX_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->min)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->nbits)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->max)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ଯାଅ out;
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
	    kex->min, kex->nbits, kex->max);
#ifdef DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d\n",
	    kex->min, kex->nbits, kex->max);
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_GROUP");
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_KEX_DH_GEX_GROUP,
	    &ନିବେଶ_kex_dh_gex_group);
	r = 0;
 out:
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_kex_dh_gex_group(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା kex *kex = ssh->kex;
	BIGNUM *p = ଖାଲି, *g = ଖାଲି;
	ଅଚଳ BIGNUM *pub_ଚାବି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, bits;

	debug("SSH2_MSG_KEX_DH_GEX_GROUP received");
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_KEX_DH_GEX_GROUP, &kex_protocol_error);

	ଯଦି ((r = sshpkt_get_bignum2(ssh, &p)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, &g)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ଯାଅ out;
	ଯଦି ((bits = BN_ଅଙ୍କ_bits(p)) < 0 ||
	    (u_int)bits < kex->min || (u_int)bits > kex->max) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		ଯାଅ out;
	}
	ଯଦି ((kex->dh = dh_new_group(g, p)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	p = g = ଖାଲି; /* belong to kex->dh now */

	/* generate and send 'e', client DH public key */
	ଯଦି ((r = dh_gen_ଚାବି(kex->dh, kex->we_need * 8)) != 0)
		ଯାଅ out;
	DH_get0_ଚାବି(kex->dh, &pub_ଚାବି, ଖାଲି);
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_KEX_DH_GEX_INIT)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_ଚାବି)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ଯାଅ out;
	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_ଚାବି);
	fprintf(stderr, "\n");
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_REPLY");
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_KEX_DH_GEX_REPLY, &ନିବେଶ_kex_dh_gex_reply);
	r = 0;
out:
	BN_clear_free(p);
	BN_clear_free(g);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_kex_dh_gex_reply(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା kex *kex = ssh->kex;
	BIGNUM *dh_server_pub = ଖାଲି;
	ଅଚଳ BIGNUM *pub_ଚାବି, *dh_p, *dh_g;
	ସଂରଚନା sshbuf *shared_secret = ଖାଲି;
	ସଂରଚନା sshbuf *tmp = ଖାଲି, *server_host_ଚାବି_blob = ଖାଲି;
	ସଂରଚନା sshkey *server_host_ଚାବି = ଖାଲି;
	u_char *signature = ଖାଲି;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug("SSH2_MSG_KEX_DH_GEX_REPLY received");
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_KEX_DH_GEX_REPLY, &kex_protocol_error);

	/* key, cert */
	ଯଦି ((r = sshpkt_getb_froms(ssh, &server_host_ଚାବି_blob)) != 0)
		ଯାଅ out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	ଯଦି ((tmp = sshbuf_fromb(server_host_ଚାବି_blob)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshkey_fromb_allowlist(tmp, &server_host_ଚାବି,
	    kex->hostkey_alg, ଖାଲି)) != 0 ||
	    (r = kex_verify_host_ଚାବି(ssh, server_host_ଚାବି)) != 0)
		ଯାଅ out;
	/* DH parameter f, server public DH key, signed H */
	ଯଦି ((r = sshpkt_get_bignum2(ssh, &dh_server_pub)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ଯାଅ out;
	ଯଦି ((shared_secret = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = kex_dh_compute_ଚାବି(kex, dh_server_pub, shared_secret)) != 0)
		ଯାଅ out;
	ଯଦି (ssh->compat & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	/* calc and verify H */
	DH_get0_ଚାବି(kex->dh, &pub_ଚାବି, ଖାଲି);
	DH_get0_pqg(kex->dh, &dh_p, ଖାଲି, &dh_g);
	hashlen = ଆକାର(hash);
	ଯଦି ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_ଚାବି_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    pub_ଚାବି,
	    dh_server_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		ଯାଅ out;

	ଯଦି ((r = sshkey_verify(server_host_ଚାବି, signature, slen, hash,
	    hashlen, kex->hostkey_alg, ssh->compat, ଖାଲି)) != 0)
		ଯାଅ out;

	ଯଦି ((r = kex_derive_ଚାବିଗୁଡ଼ିକ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ଯାଅ out;

	/* save initial signature and hostkey */
	ଯଦି ((kex->flags & KEX_INITIAL) != 0) {
		ଯଦି (kex->initial_hostkey != ଖାଲି || kex->initial_sig != ଖାଲି) {
			r = SSH_ERR_INTERNAL_ERROR;
			ଯାଅ out;
		}
		ଯଦି ((kex->initial_sig = sshbuf_new()) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			ଯାଅ out;
		kex->initial_hostkey = server_host_ଚାବି;
		server_host_ଚାବି = ଖାଲି;
	}
	/* success */
 out:
	explicit_bzero(hash, ଆକାର(hash));
	DH_free(kex->dh);
	kex->dh = ଖାଲି;
	BN_clear_free(dh_server_pub);
	sshbuf_free(shared_secret);
	sshkey_free(server_host_ଚାବି);
	sshbuf_free(tmp);
	sshbuf_free(server_host_ଚାବି_blob);
	ମୁକ୍ତ(signature);
	ଫେରନ୍ତୁ r;
}
#endif /* WITH_OPENSSL */
