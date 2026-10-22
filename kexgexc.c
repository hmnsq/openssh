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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/dh.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dispatch.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_kex_dh_gex_ਸਮੂਹ(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_kex_dh_gex_ਜਵਾਬ(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);

ਪੂਰਨ
kexgex_client(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ kex *kex = ssh->kex;
	ਪੂਰਨ r;
	u_int nbits;

	nbits = dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	ਜੇ (ssh->compat & SSH_BUG_DHGEX_LARGE)
		kex->nbits = MINIMUM(kex->nbits, 4096);
	/* New GEX request */
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->min)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->nbits)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->max)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
	    kex->min, kex->nbits, kex->max);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d\n",
	    kex->min, kex->nbits, kex->max);
#ਜੇ_ਅੰਤ
	debug("expecting SSH2_MSG_KEX_DH_GEX_GROUP");
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_ਸਮੂਹ,
	    &ਨਿਵੇਸ਼_kex_dh_gex_ਸਮੂਹ);
	r = 0;
 ਬਾਹਰਲਾ:
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_kex_dh_gex_ਸਮੂਹ(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ kex *kex = ssh->kex;
	BIGNUM *p = ਨਿਰਾ, *g = ਨਿਰਾ;
	ਅਚਲ BIGNUM *pub_ਕੁੰਜੀ;
	ਪੂਰਨ r, ਬਿੱਟ;

	debug("SSH2_MSG_KEX_DH_GEX_GROUP received");
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_ਸਮੂਹ, &kex_protocol_error);

	ਜੇ ((r = sshpkt_get_bignum2(ssh, &p)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, &g)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((ਬਿੱਟ = BN_ਅੰਕ_ਬਿੱਟ(p)) < 0 ||
	    (u_int)ਬਿੱਟ < kex->min || (u_int)ਬਿੱਟ > kex->max) {
		r = SSH_ERR_DH_GEX_ਬਾਹਰਲਾ_ਦਾ_RANGE;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((kex->dh = dh_new_ਸਮੂਹ(g, p)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	p = g = ਨਿਰਾ; /* belong to kex->dh now */

	/* generate and send 'e', client DH public key */
	ਜੇ ((r = dh_gen_ਕੁੰਜੀ(kex->dh, kex->we_need * 8)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	DH_get0_ਕੁੰਜੀ(kex->dh, &pub_ਕੁੰਜੀ, ਨਿਰਾ);
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_INIT)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_ਕੁੰਜੀ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_ਕੁੰਜੀ);
	fprintf(stderr, "\n");
#ਜੇ_ਅੰਤ
	debug("expecting SSH2_MSG_KEX_DH_GEX_REPLY");
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_ਜਵਾਬ, &ਨਿਵੇਸ਼_kex_dh_gex_ਜਵਾਬ);
	r = 0;
ਬਾਹਰਲਾ:
	BN_clear_free(p);
	BN_clear_free(g);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_kex_dh_gex_ਜਵਾਬ(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ kex *kex = ssh->kex;
	BIGNUM *dh_server_pub = ਨਿਰਾ;
	ਅਚਲ BIGNUM *pub_ਕੁੰਜੀ, *dh_p, *dh_g;
	ਬਣਤਰ sshbuf *shared_secret = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *tmp = ਨਿਰਾ, *server_host_ਕੁੰਜੀ_blob = ਨਿਰਾ;
	ਬਣਤਰ sshkey *server_host_ਕੁੰਜੀ = ਨਿਰਾ;
	u_char *signature = ਨਿਰਾ;
	u_char hash[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	ਮਾਪ_t slen, hashlen;
	ਪੂਰਨ r;

	debug("SSH2_MSG_KEX_DH_GEX_REPLY received");
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_ਜਵਾਬ, &kex_protocol_error);

	/* key, cert */
	ਜੇ ((r = sshpkt_getb_froms(ssh, &server_host_ਕੁੰਜੀ_blob)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	ਜੇ ((tmp = sshbuf_fromb(server_host_ਕੁੰਜੀ_blob)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshkey_fromb_allowlist(tmp, &server_host_ਕੁੰਜੀ,
	    kex->hostkey_alg, ਨਿਰਾ)) != 0 ||
	    (r = kex_verify_host_ਕੁੰਜੀ(ssh, server_host_ਕੁੰਜੀ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* DH parameter f, server public DH key, signed H */
	ਜੇ ((r = sshpkt_get_bignum2(ssh, &dh_server_pub)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((shared_secret = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = kex_dh_compute_ਕੁੰਜੀ(kex, dh_server_pub, shared_secret)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (ssh->compat & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	/* calc and verify H */
	DH_get0_ਕੁੰਜੀ(kex->dh, &pub_ਕੁੰਜੀ, ਨਿਰਾ);
	DH_get0_pqg(kex->dh, &dh_p, ਨਿਰਾ, &dh_g);
	hashlen = ਆਕਾਰ(hash);
	ਜੇ ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_ਸੰਸਕਰਣ,
	    kex->server_ਸੰਸਕਰਣ,
	    kex->my,
	    kex->peer,
	    server_host_ਕੁੰਜੀ_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    pub_ਕੁੰਜੀ,
	    dh_server_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((r = sshkey_verify(server_host_ਕੁੰਜੀ, signature, slen, hash,
	    hashlen, kex->hostkey_alg, ssh->compat, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((r = kex_derive_ਕੁੰਜੀਆਂ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* save initial signature and hostkey */
	ਜੇ ((kex->flags & KEX_INITIAL) != 0) {
		ਜੇ (kex->initial_hostkey != ਨਿਰਾ || kex->initial_sig != ਨਿਰਾ) {
			r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((kex->initial_sig = sshbuf_new()) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		kex->initial_hostkey = server_host_ਕੁੰਜੀ;
		server_host_ਕੁੰਜੀ = ਨਿਰਾ;
	}
	/* success */
 ਬਾਹਰਲਾ:
	explicit_bzero(hash, ਆਕਾਰ(hash));
	DH_free(kex->dh);
	kex->dh = ਨਿਰਾ;
	BN_clear_free(dh_server_pub);
	sshbuf_free(shared_secret);
	sshkey_free(server_host_ਕੁੰਜੀ);
	sshbuf_free(tmp);
	sshbuf_free(server_host_ਕੁੰਜੀ_blob);
	ਮੁਕਤ(signature);
	ਵਾਪਸ r;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
