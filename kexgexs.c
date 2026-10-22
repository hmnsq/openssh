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

#অন্তর্ভাব "includes.h"

#ifdef WITH_OPENSSL
#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <signal.h>

#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/dh.h>

#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "dh.h"
#অন্তর্ভাব "ssh2.h"
#ifdef GSSAPI
#অন্তর্ভাব "ssh-gss.h"
#endif
#অন্তর্ভাব "monitor_wrap.h"
#অন্তর্ভাব "dispatch.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "misc.h"

স্থির পূর্ণসংখ্যা প্রবেশ_kex_dh_gex_request(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
স্থির পূর্ণসংখ্যা প্রবেশ_kex_dh_gex_init(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);

পূর্ণসংখ্যা
kexgex_server(কাঠামো ssh *ssh)
{
	ssh_dispatch_set(ssh, SSH2_বার্তা_KEX_DH_GEX_REQUEST,
	    &প্রবেশ_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
প্রবেশ_kex_dh_gex_request(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	কাঠামো kex *kex = ssh->kex;
	পূর্ণসংখ্যা r;
	u_int min = 0, max = 0, nbits = 0;
	ধ্রুবক BIGNUM *dh_p, *dh_g;

	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_set(ssh, SSH2_বার্তা_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	যদি ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		যাও out;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = MAXIMUM(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = MAXIMUM(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	যদি (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		যাও out;
	}

	/* Contact privileged parent */
	kex->dh = mm_choose_dh(min, nbits, max);
	যদি (kex->dh == ফাঁকা) {
		(শূন্য)sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	DH_get0_pqg(kex->dh, &dh_p, ফাঁকা, &dh_g);
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_KEX_DH_GEX_GROUP)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		যাও out;

	/* Compute our exchange value in parallel with the client */
	যদি ((r = dh_gen_চাবি(kex->dh, kex->we_need * 8)) != 0)
		যাও out;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_set(ssh, SSH2_বার্তা_KEX_DH_GEX_INIT, &প্রবেশ_kex_dh_gex_init);
	r = 0;
 out:
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
প্রবেশ_kex_dh_gex_init(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	কাঠামো kex *kex = ssh->kex;
	BIGNUM *dh_client_pub = ফাঁকা;
	ধ্রুবক BIGNUM *pub_চাবি, *dh_p, *dh_g;
	কাঠামো sshbuf *shared_secret = ফাঁকা;
	কাঠামো sshbuf *server_host_চাবি_blob = ফাঁকা;
	কাঠামো sshkey *server_host_public, *server_host_private;
	u_char *signature = ফাঁকা;
	u_char hash[SSH_DIGEST_MAX_দৈর্ঘ্য];
	আকার_t slen, hashlen;
	পূর্ণসংখ্যা r;

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_set(ssh, SSH2_বার্তা_KEX_DH_GEX_INIT, &kex_protocol_error);

	যদি ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		যাও out;

	/* key, cert */
	যদি ((r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		যাও out;
	যদি ((shared_secret = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = kex_dh_compute_চাবি(kex, dh_client_pub, shared_secret)) != 0)
		যাও out;
	যদি ((server_host_চাবি_blob = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshkey_putb(server_host_public, server_host_চাবি_blob)) != 0)
		যাও out;

	/* calc H */
	DH_get0_চাবি(kex->dh, &pub_চাবি, ফাঁকা);
	DH_get0_pqg(kex->dh, &dh_p, ফাঁকা, &dh_g);
	hashlen = আকার(hash);
	যদি ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_চাবি_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    dh_client_pub,
	    pub_চাবি,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		যাও out;

	/* sign H */
	যদি ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		যাও out;

	/* send server hostkey, DH pubkey 'f' and signed H */
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_KEX_DH_GEX_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_চাবি_blob)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_চাবি)) != 0 ||     /* f */
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		যাও out;

	যদি ((r = kex_derive_চাবিগুলি(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		যাও out;

	/* retain copy of hostkey used at initial KEX */
	যদি (kex->initial_hostkey == ফাঁকা &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		যাও out;
	/* success */
 out:
	explicit_bzero(hash, আকার(hash));
	DH_free(kex->dh);
	kex->dh = ফাঁকা;
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_চাবি_blob);
	মুক্ত(signature);
	ফেরত r;
}
#endif /* WITH_OPENSSL */
