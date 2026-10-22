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

#شامل "includes.h"

#ifdef WITH_OPENSSL
#شامل "openbsd-compat/openssl-compat.h"

#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <signal.h>

#شامل <openssl/bn.h>
#شامل <openssl/dh.h>

#شامل "sshkey.h"
#شامل "cipher.h"
#شامل "digest.h"
#شامل "kex.h"
#شامل "log.h"
#شامل "packet.h"
#شامل "dh.h"
#شامل "ssh2.h"
#ifdef GSSAPI
#شامل "ssh-gss.h"
#endif
#شامل "monitor_wrap.h"
#شامل "dispatch.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "misc.h"

ایستا صحیح درون_داد_kex_dh_gex_request(صحیح, uint32_t, ساختار ssh *);
ایستا صحیح درون_داد_kex_dh_gex_init(صحیح, uint32_t, ساختار ssh *);

صحیح
kexgex_server(ساختار ssh *ssh)
{
	ssh_dispatch_set(ssh, SSH2_پیام_KEX_DH_GEX_REQUEST,
	    &درون_داد_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	بازگشت 0;
}

ایستا صحیح
درون_داد_kex_dh_gex_request(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	ساختار kex *kex = ssh->kex;
	صحیح r;
	u_int min = 0, max = 0, nbits = 0;
	ثابت BIGNUM *dh_p, *dh_g;

	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_set(ssh, SSH2_پیام_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	اگر ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		برو out;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = MAXIMUM(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = MAXIMUM(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	اگر (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		برو out;
	}

	/* Contact privileged parent */
	kex->dh = mm_choose_dh(min, nbits, max);
	اگر (kex->dh == پوچ) {
		(تهی)sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	DH_get0_pqg(kex->dh, &dh_p, پوچ, &dh_g);
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_KEX_DH_GEX_GROUP)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		برو out;

	/* Compute our exchange value in parallel with the client */
	اگر ((r = dh_gen_کلید(kex->dh, kex->we_need * 8)) != 0)
		برو out;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_set(ssh, SSH2_پیام_KEX_DH_GEX_INIT, &درون_داد_kex_dh_gex_init);
	r = 0;
 out:
	بازگشت r;
}

ایستا صحیح
درون_داد_kex_dh_gex_init(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	ساختار kex *kex = ssh->kex;
	BIGNUM *dh_client_pub = پوچ;
	ثابت BIGNUM *pub_کلید, *dh_p, *dh_g;
	ساختار sshbuf *shared_secret = پوچ;
	ساختار sshbuf *server_host_کلید_blob = پوچ;
	ساختار sshkey *server_host_public, *server_host_private;
	u_char *signature = پوچ;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	صحیح r;

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_set(ssh, SSH2_پیام_KEX_DH_GEX_INIT, &kex_protocol_error);

	اگر ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		برو out;

	/* key, cert */
	اگر ((r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		برو out;
	اگر ((shared_secret = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = kex_dh_compute_کلید(kex, dh_client_pub, shared_secret)) != 0)
		برو out;
	اگر ((server_host_کلید_blob = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshkey_putb(server_host_public, server_host_کلید_blob)) != 0)
		برو out;

	/* calc H */
	DH_get0_کلید(kex->dh, &pub_کلید, پوچ);
	DH_get0_pqg(kex->dh, &dh_p, پوچ, &dh_g);
	hashlen = اندازه(hash);
	اگر ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_کلید_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    dh_client_pub,
	    pub_کلید,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		برو out;

	/* sign H */
	اگر ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		برو out;

	/* send server hostkey, DH pubkey 'f' and signed H */
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_KEX_DH_GEX_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_کلید_blob)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_کلید)) != 0 ||     /* f */
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		برو out;

	اگر ((r = kex_derive_کلیدها(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		برو out;

	/* retain copy of hostkey used at initial KEX */
	اگر (kex->initial_hostkey == پوچ &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		برو out;
	/* success */
 out:
	explicit_bzero(hash, اندازه(hash));
	DH_free(kex->dh);
	kex->dh = پوچ;
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_کلید_blob);
	آزاد(signature);
	بازگشت r;
}
#endif /* WITH_OPENSSL */
