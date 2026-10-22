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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/dh.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_wrap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dispatch.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_kex_dh_gex_request(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_kex_dh_gex_init(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);

ਪੂਰਨ
kexgex_server(ਬਣਤਰ ssh *ssh)
{
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_REQUEST,
	    &ਨਿਵੇਸ਼_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_kex_dh_gex_request(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ kex *kex = ssh->kex;
	ਪੂਰਨ r;
	u_int min = 0, max = 0, nbits = 0;
	ਅਚਲ BIGNUM *dh_p, *dh_g;

	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	ਜੇ ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = ਵੱਧ_ਤੋਂ_ਵੱਧ(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = ਵੱਧ_ਤੋਂ_ਵੱਧ(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	ਜੇ (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_ਬਾਹਰਲਾ_ਦਾ_RANGE;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Contact privileged parent */
	kex->dh = mm_ਚੁਣੋ_dh(min, nbits, max);
	ਜੇ (kex->dh == ਨਿਰਾ) {
		(ਖਾਲੀ)sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	DH_get0_pqg(kex->dh, &dh_p, ਨਿਰਾ, &dh_g);
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_ਸਮੂਹ)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Compute our exchange value in parallel with the client */
	ਜੇ ((r = dh_gen_ਕੁੰਜੀ(kex->dh, kex->we_need * 8)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_INIT, &ਨਿਵੇਸ਼_kex_dh_gex_init);
	r = 0;
 ਬਾਹਰਲਾ:
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_kex_dh_gex_init(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ kex *kex = ssh->kex;
	BIGNUM *dh_client_pub = ਨਿਰਾ;
	ਅਚਲ BIGNUM *pub_ਕੁੰਜੀ, *dh_p, *dh_g;
	ਬਣਤਰ sshbuf *shared_secret = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *server_host_ਕੁੰਜੀ_blob = ਨਿਰਾ;
	ਬਣਤਰ sshkey *server_host_ਜਨਤਕ, *server_host_ਨਿੱਜੀ;
	u_char *signature = ਨਿਰਾ;
	u_char hash[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	ਮਾਪ_t slen, hashlen;
	ਪੂਰਨ r;

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_INIT, &kex_protocol_error);

	ਜੇ ((r = kex_ਲੱਦੋ_hostkey(ssh, &server_host_ਨਿੱਜੀ,
	    &server_host_ਜਨਤਕ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* key, cert */
	ਜੇ ((r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((shared_secret = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = kex_dh_compute_ਕੁੰਜੀ(kex, dh_client_pub, shared_secret)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((server_host_ਕੁੰਜੀ_blob = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshkey_putb(server_host_ਜਨਤਕ, server_host_ਕੁੰਜੀ_blob)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* calc H */
	DH_get0_ਕੁੰਜੀ(kex->dh, &pub_ਕੁੰਜੀ, ਨਿਰਾ);
	DH_get0_pqg(kex->dh, &dh_p, ਨਿਰਾ, &dh_g);
	hashlen = ਆਕਾਰ(hash);
	ਜੇ ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_ਸੰਸਕਰਣ,
	    kex->server_ਸੰਸਕਰਣ,
	    kex->peer,
	    kex->my,
	    server_host_ਕੁੰਜੀ_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    dh_client_pub,
	    pub_ਕੁੰਜੀ,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* sign H */
	ਜੇ ((r = kex->sign(ssh, server_host_ਨਿੱਜੀ, server_host_ਜਨਤਕ,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* send server hostkey, DH pubkey 'f' and signed H */
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_ਜਵਾਬ)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_ਕੁੰਜੀ_blob)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_ਕੁੰਜੀ)) != 0 ||     /* f */
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((r = kex_derive_ਕੁੰਜੀਆਂ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* retain copy of hostkey used at initial KEX */
	ਜੇ (kex->initial_hostkey == ਨਿਰਾ &&
	    (r = sshkey_from_ਨਿੱਜੀ(server_host_ਜਨਤਕ,
	    &kex->initial_hostkey)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
 ਬਾਹਰਲਾ:
	explicit_bzero(hash, ਆਕਾਰ(hash));
	DH_free(kex->dh);
	kex->dh = ਨਿਰਾ;
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_ਕੁੰਜੀ_blob);
	ਮੁਕਤ(signature);
	ਵਾਪਸ r;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
