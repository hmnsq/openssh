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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ "openbsd-compat/openssl-compat.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/dh.h>

#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <signal.h>

#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "dh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "dispatch.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "misc.h"

స్థిర పూర్ణాంకం ఆదానం_kex_dh_gex_సమూహం(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_kex_dh_gex_జవాబు(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);

పూర్ణాంకం
kexgex_client(నిర్మాణం ssh *ssh)
{
	నిర్మాణం kex *kex = ssh->kex;
	పూర్ణాంకం r;
	u_int nbits;

	nbits = dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	ఒకవేళ (ssh->compat & SSH_BUG_DHGEX_LARGE)
		kex->nbits = MINIMUM(kex->nbits, 4096);
	/* New GEX request */
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_KEX_DH_GEX_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->min)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->nbits)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->max)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		వెళ్ళు బహిర్గతం;
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
	    kex->min, kex->nbits, kex->max);
#నిర్వచితమైతే DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d\n",
	    kex->min, kex->nbits, kex->max);
#అయితే_ముగింపు
	debug("expecting SSH2_MSG_KEX_DH_GEX_GROUP");
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEX_DH_GEX_సమూహం,
	    &ఆదానం_kex_dh_gex_సమూహం);
	r = 0;
 బహిర్గతం:
	తిరిగి r;
}

స్థిర పూర్ణాంకం
ఆదానం_kex_dh_gex_సమూహం(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	నిర్మాణం kex *kex = ssh->kex;
	BIGNUM *p = ఖాళీ, *g = ఖాళీ;
	స్థిరరాశి BIGNUM *pub_కీలకం;
	పూర్ణాంకం r, బిట్లు;

	debug("SSH2_MSG_KEX_DH_GEX_GROUP received");
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEX_DH_GEX_సమూహం, &kex_protocol_error);

	ఒకవేళ ((r = sshpkt_get_bignum2(ssh, &p)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, &g)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((బిట్లు = BN_అంకె_బిట్లు(p)) < 0 ||
	    (u_int)బిట్లు < kex->min || (u_int)బిట్లు > kex->max) {
		r = SSH_ERR_DH_GEX_బహిర్గతం_యొక్క_RANGE;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((kex->dh = dh_new_సమూహం(g, p)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	p = g = ఖాళీ; /* belong to kex->dh now */

	/* generate and send 'e', client DH public key */
	ఒకవేళ ((r = dh_gen_కీలకం(kex->dh, kex->we_need * 8)) != 0)
		వెళ్ళు బహిర్గతం;
	DH_get0_కీలకం(kex->dh, &pub_కీలకం, ఖాళీ);
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_KEX_DH_GEX_INIT)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_కీలకం)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		వెళ్ళు బహిర్గతం;
	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
#నిర్వచితమైతే DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_కీలకం);
	fprintf(stderr, "\n");
#అయితే_ముగింపు
	debug("expecting SSH2_MSG_KEX_DH_GEX_REPLY");
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEX_DH_GEX_జవాబు, &ఆదానం_kex_dh_gex_జవాబు);
	r = 0;
బహిర్గతం:
	BN_clear_free(p);
	BN_clear_free(g);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
ఆదానం_kex_dh_gex_జవాబు(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	నిర్మాణం kex *kex = ssh->kex;
	BIGNUM *dh_server_pub = ఖాళీ;
	స్థిరరాశి BIGNUM *pub_కీలకం, *dh_p, *dh_g;
	నిర్మాణం sshbuf *shared_secret = ఖాళీ;
	నిర్మాణం sshbuf *tmp = ఖాళీ, *server_host_కీలకం_blob = ఖాళీ;
	నిర్మాణం sshkey *server_host_కీలకం = ఖాళీ;
	u_char *signature = ఖాళీ;
	u_char hash[SSH_DIGEST_MAX_నిడివి];
	కొలత_t slen, hashlen;
	పూర్ణాంకం r;

	debug("SSH2_MSG_KEX_DH_GEX_REPLY received");
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEX_DH_GEX_జవాబు, &kex_protocol_error);

	/* key, cert */
	ఒకవేళ ((r = sshpkt_getb_froms(ssh, &server_host_కీలకం_blob)) != 0)
		వెళ్ళు బహిర్గతం;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	ఒకవేళ ((tmp = sshbuf_fromb(server_host_కీలకం_blob)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshkey_fromb_allowlist(tmp, &server_host_కీలకం,
	    kex->hostkey_alg, ఖాళీ)) != 0 ||
	    (r = kex_verify_host_కీలకం(ssh, server_host_కీలకం)) != 0)
		వెళ్ళు బహిర్గతం;
	/* DH parameter f, server public DH key, signed H */
	ఒకవేళ ((r = sshpkt_get_bignum2(ssh, &dh_server_pub)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((shared_secret = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = kex_dh_compute_కీలకం(kex, dh_server_pub, shared_secret)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (ssh->compat & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	/* calc and verify H */
	DH_get0_కీలకం(kex->dh, &pub_కీలకం, ఖాళీ);
	DH_get0_pqg(kex->dh, &dh_p, ఖాళీ, &dh_g);
	hashlen = పరిమాణం(hash);
	ఒకవేళ ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_సంస్కరణ,
	    kex->server_సంస్కరణ,
	    kex->my,
	    kex->peer,
	    server_host_కీలకం_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    pub_కీలకం,
	    dh_server_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((r = sshkey_verify(server_host_కీలకం, signature, slen, hash,
	    hashlen, kex->hostkey_alg, ssh->compat, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((r = kex_derive_కీలకాలు(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		వెళ్ళు బహిర్గతం;

	/* save initial signature and hostkey */
	ఒకవేళ ((kex->flags & KEX_INITIAL) != 0) {
		ఒకవేళ (kex->initial_hostkey != ఖాళీ || kex->initial_sig != ఖాళీ) {
			r = SSH_ERR_అంతర్గత_ERROR;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((kex->initial_sig = sshbuf_new()) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			వెళ్ళు బహిర్గతం;
		kex->initial_hostkey = server_host_కీలకం;
		server_host_కీలకం = ఖాళీ;
	}
	/* success */
 బహిర్గతం:
	explicit_bzero(hash, పరిమాణం(hash));
	DH_free(kex->dh);
	kex->dh = ఖాళీ;
	BN_clear_free(dh_server_pub);
	sshbuf_free(shared_secret);
	sshkey_free(server_host_కీలకం);
	sshbuf_free(tmp);
	sshbuf_free(server_host_కీలకం_blob);
	విడుదల(signature);
	తిరిగి r;
}
#అయితే_ముగింపు /* WITH_OPENSSL */
