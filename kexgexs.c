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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ "openbsd-compat/openssl-compat.h"

#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <signal.h>

#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/dh.h>

#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "cipher.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "dh.h"
#అన్తర్భావ "ssh2.h"
#నిర్వచితమైతే GSSAPI
#అన్తర్భావ "ssh-gss.h"
#అయితే_ముగింపు
#అన్తర్భావ "monitor_wrap.h"
#అన్తర్భావ "dispatch.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "misc.h"

స్థిర పూర్ణాంకం ఆదానం_kex_dh_gex_request(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_kex_dh_gex_init(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);

పూర్ణాంకం
kexgex_server(నిర్మాణం ssh *ssh)
{
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEX_DH_GEX_REQUEST,
	    &ఆదానం_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ఆదానం_kex_dh_gex_request(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	నిర్మాణం kex *kex = ssh->kex;
	పూర్ణాంకం r;
	u_int min = 0, max = 0, nbits = 0;
	స్థిరరాశి BIGNUM *dh_p, *dh_g;

	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	ఒకవేళ ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		వెళ్ళు బహిర్గతం;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = గరిష్ఠ(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = గరిష్ఠ(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	ఒకవేళ (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_బహిర్గతం_యొక్క_RANGE;
		వెళ్ళు బహిర్గతం;
	}

	/* Contact privileged parent */
	kex->dh = mm_ఎంచుకో_dh(min, nbits, max);
	ఒకవేళ (kex->dh == ఖాళీ) {
		(శూన్య)sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	DH_get0_pqg(kex->dh, &dh_p, ఖాళీ, &dh_g);
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_KEX_DH_GEX_సమూహం)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Compute our exchange value in parallel with the client */
	ఒకవేళ ((r = dh_gen_కీలకం(kex->dh, kex->we_need * 8)) != 0)
		వెళ్ళు బహిర్గతం;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEX_DH_GEX_INIT, &ఆదానం_kex_dh_gex_init);
	r = 0;
 బహిర్గతం:
	తిరిగి r;
}

స్థిర పూర్ణాంకం
ఆదానం_kex_dh_gex_init(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	నిర్మాణం kex *kex = ssh->kex;
	BIGNUM *dh_client_pub = ఖాళీ;
	స్థిరరాశి BIGNUM *pub_కీలకం, *dh_p, *dh_g;
	నిర్మాణం sshbuf *shared_secret = ఖాళీ;
	నిర్మాణం sshbuf *server_host_కీలకం_blob = ఖాళీ;
	నిర్మాణం sshkey *server_host_ప్రజా, *server_host_వ్యక్తిగత;
	u_char *signature = ఖాళీ;
	u_char hash[SSH_DIGEST_MAX_నిడివి];
	కొలత_t slen, hashlen;
	పూర్ణాంకం r;

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEX_DH_GEX_INIT, &kex_protocol_error);

	ఒకవేళ ((r = kex_ఎక్కించు_hostkey(ssh, &server_host_వ్యక్తిగత,
	    &server_host_ప్రజా)) != 0)
		వెళ్ళు బహిర్గతం;

	/* key, cert */
	ఒకవేళ ((r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((shared_secret = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = kex_dh_compute_కీలకం(kex, dh_client_pub, shared_secret)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((server_host_కీలకం_blob = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshkey_putb(server_host_ప్రజా, server_host_కీలకం_blob)) != 0)
		వెళ్ళు బహిర్గతం;

	/* calc H */
	DH_get0_కీలకం(kex->dh, &pub_కీలకం, ఖాళీ);
	DH_get0_pqg(kex->dh, &dh_p, ఖాళీ, &dh_g);
	hashlen = పరిమాణం(hash);
	ఒకవేళ ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_సంస్కరణ,
	    kex->server_సంస్కరణ,
	    kex->peer,
	    kex->my,
	    server_host_కీలకం_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    dh_client_pub,
	    pub_కీలకం,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		వెళ్ళు బహిర్గతం;

	/* sign H */
	ఒకవేళ ((r = kex->sign(ssh, server_host_వ్యక్తిగత, server_host_ప్రజా,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		వెళ్ళు బహిర్గతం;

	/* send server hostkey, DH pubkey 'f' and signed H */
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_KEX_DH_GEX_జవాబు)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_కీలకం_blob)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_కీలకం)) != 0 ||     /* f */
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((r = kex_derive_కీలకాలు(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		వెళ్ళు బహిర్గతం;

	/* retain copy of hostkey used at initial KEX */
	ఒకవేళ (kex->initial_hostkey == ఖాళీ &&
	    (r = sshkey_from_వ్యక్తిగత(server_host_ప్రజా,
	    &kex->initial_hostkey)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
 బహిర్గతం:
	explicit_bzero(hash, పరిమాణం(hash));
	DH_free(kex->dh);
	kex->dh = ఖాళీ;
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_కీలకం_blob);
	విడుదల(signature);
	తిరిగి r;
}
#అయితే_ముగింపు /* WITH_OPENSSL */
