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

#அந்தர்பாவ "includes.h"

#ifdef WITH_OPENSSL
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <signal.h>

#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/dh.h>

#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "dh.h"
#அந்தர்பாவ "ssh2.h"
#ifdef GSSAPI
#அந்தர்பாவ "ssh-gss.h"
#endif
#அந்தர்பாவ "monitor_wrap.h"
#அந்தர்பாவ "dispatch.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "misc.h"

நிலையான முழு உள்ளீடு_kex_dh_gex_request(முழு, uint32_t, கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_kex_dh_gex_init(முழு, uint32_t, கட்டமைப்பு ssh *);

முழு
kexgex_server(கட்டமைப்பு ssh *ssh)
{
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEX_DH_GEX_REQUEST,
	    &உள்ளீடு_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	திரும்பு 0;
}

நிலையான முழு
உள்ளீடு_kex_dh_gex_request(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு kex *kex = ssh->kex;
	முழு r;
	u_int min = 0, max = 0, nbits = 0;
	மாறிலி BIGNUM *dh_p, *dh_g;

	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	எனில் ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		செல் out;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = MAXIMUM(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = MAXIMUM(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	எனில் (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		செல் out;
	}

	/* Contact privileged parent */
	kex->dh = mm_choose_dh(min, nbits, max);
	எனில் (kex->dh == வெற்று) {
		(வெறுமை)sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	DH_get0_pqg(kex->dh, &dh_p, வெற்று, &dh_g);
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_KEX_DH_GEX_GROUP)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		செல் out;

	/* Compute our exchange value in parallel with the client */
	எனில் ((r = dh_gen_சாவி(kex->dh, kex->we_need * 8)) != 0)
		செல் out;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEX_DH_GEX_INIT, &உள்ளீடு_kex_dh_gex_init);
	r = 0;
 out:
	திரும்பு r;
}

நிலையான முழு
உள்ளீடு_kex_dh_gex_init(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு kex *kex = ssh->kex;
	BIGNUM *dh_client_pub = வெற்று;
	மாறிலி BIGNUM *pub_சாவி, *dh_p, *dh_g;
	கட்டமைப்பு sshbuf *shared_secret = வெற்று;
	கட்டமைப்பு sshbuf *server_host_சாவி_blob = வெற்று;
	கட்டமைப்பு sshkey *server_host_public, *server_host_private;
	u_char *signature = வெற்று;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	முழு r;

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEX_DH_GEX_INIT, &kex_protocol_error);

	எனில் ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		செல் out;

	/* key, cert */
	எனில் ((r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		செல் out;
	எனில் ((shared_secret = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = kex_dh_compute_சாவி(kex, dh_client_pub, shared_secret)) != 0)
		செல் out;
	எனில் ((server_host_சாவி_blob = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshkey_putb(server_host_public, server_host_சாவி_blob)) != 0)
		செல் out;

	/* calc H */
	DH_get0_சாவி(kex->dh, &pub_சாவி, வெற்று);
	DH_get0_pqg(kex->dh, &dh_p, வெற்று, &dh_g);
	hashlen = அளவு(hash);
	எனில் ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_சாவி_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    dh_client_pub,
	    pub_சாவி,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		செல் out;

	/* sign H */
	எனில் ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		செல் out;

	/* send server hostkey, DH pubkey 'f' and signed H */
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_KEX_DH_GEX_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_சாவி_blob)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_சாவி)) != 0 ||     /* f */
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		செல் out;

	எனில் ((r = kex_derive_சாவிகள்(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		செல் out;

	/* retain copy of hostkey used at initial KEX */
	எனில் (kex->initial_hostkey == வெற்று &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		செல் out;
	/* success */
 out:
	explicit_bzero(hash, அளவு(hash));
	DH_free(kex->dh);
	kex->dh = வெற்று;
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_சாவி_blob);
	விடுவி(signature);
	திரும்பு r;
}
#endif /* WITH_OPENSSL */
