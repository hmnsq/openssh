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

#شامل "includes.h"

#ifdef WITH_OPENSSL
#شامل "openbsd-compat/openssl-compat.h"

#شامل <sys/types.h>

#شامل <openssl/bn.h>
#شامل <openssl/dh.h>

#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <signal.h>

#شامل "sshkey.h"
#شامل "digest.h"
#شامل "kex.h"
#شامل "log.h"
#شامل "packet.h"
#شامل "dh.h"
#شامل "ssh2.h"
#شامل "compat.h"
#شامل "dispatch.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "misc.h"

ایستا صحیح درون_داد_kex_dh_gex_group(صحیح, uint32_t, ساختار ssh *);
ایستا صحیح درون_داد_kex_dh_gex_reply(صحیح, uint32_t, ساختار ssh *);

صحیح
kexgex_client(ساختار ssh *ssh)
{
	ساختار kex *kex = ssh->kex;
	صحیح r;
	u_int nbits;

	nbits = dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	اگر (ssh->compat & SSH_BUG_DHGEX_LARGE)
		kex->nbits = MINIMUM(kex->nbits, 4096);
	/* New GEX request */
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_KEX_DH_GEX_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->min)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->nbits)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->max)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		برو out;
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
	    kex->min, kex->nbits, kex->max);
#ifdef DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d\n",
	    kex->min, kex->nbits, kex->max);
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_GROUP");
	ssh_dispatch_set(ssh, SSH2_پیام_KEX_DH_GEX_GROUP,
	    &درون_داد_kex_dh_gex_group);
	r = 0;
 out:
	بازگشت r;
}

ایستا صحیح
درون_داد_kex_dh_gex_group(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	ساختار kex *kex = ssh->kex;
	BIGNUM *p = پوچ, *g = پوچ;
	ثابت BIGNUM *pub_کلید;
	صحیح r, bits;

	debug("SSH2_MSG_KEX_DH_GEX_GROUP received");
	ssh_dispatch_set(ssh, SSH2_پیام_KEX_DH_GEX_GROUP, &kex_protocol_error);

	اگر ((r = sshpkt_get_bignum2(ssh, &p)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, &g)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		برو out;
	اگر ((bits = BN_رقم_bits(p)) < 0 ||
	    (u_int)bits < kex->min || (u_int)bits > kex->max) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		برو out;
	}
	اگر ((kex->dh = dh_new_group(g, p)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	p = g = پوچ; /* belong to kex->dh now */

	/* generate and send 'e', client DH public key */
	اگر ((r = dh_gen_کلید(kex->dh, kex->we_need * 8)) != 0)
		برو out;
	DH_get0_کلید(kex->dh, &pub_کلید, پوچ);
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_KEX_DH_GEX_INIT)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_کلید)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		برو out;
	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_کلید);
	fprintf(stderr, "\n");
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_REPLY");
	ssh_dispatch_set(ssh, SSH2_پیام_KEX_DH_GEX_REPLY, &درون_داد_kex_dh_gex_reply);
	r = 0;
out:
	BN_clear_free(p);
	BN_clear_free(g);
	بازگشت r;
}

ایستا صحیح
درون_داد_kex_dh_gex_reply(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	ساختار kex *kex = ssh->kex;
	BIGNUM *dh_server_pub = پوچ;
	ثابت BIGNUM *pub_کلید, *dh_p, *dh_g;
	ساختار sshbuf *shared_secret = پوچ;
	ساختار sshbuf *tmp = پوچ, *server_host_کلید_blob = پوچ;
	ساختار sshkey *server_host_کلید = پوچ;
	u_char *signature = پوچ;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	صحیح r;

	debug("SSH2_MSG_KEX_DH_GEX_REPLY received");
	ssh_dispatch_set(ssh, SSH2_پیام_KEX_DH_GEX_REPLY, &kex_protocol_error);

	/* key, cert */
	اگر ((r = sshpkt_getb_froms(ssh, &server_host_کلید_blob)) != 0)
		برو out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	اگر ((tmp = sshbuf_fromb(server_host_کلید_blob)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshkey_fromb_allowlist(tmp, &server_host_کلید,
	    kex->hostkey_alg, پوچ)) != 0 ||
	    (r = kex_verify_host_کلید(ssh, server_host_کلید)) != 0)
		برو out;
	/* DH parameter f, server public DH key, signed H */
	اگر ((r = sshpkt_get_bignum2(ssh, &dh_server_pub)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		برو out;
	اگر ((shared_secret = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = kex_dh_compute_کلید(kex, dh_server_pub, shared_secret)) != 0)
		برو out;
	اگر (ssh->compat & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	/* calc and verify H */
	DH_get0_کلید(kex->dh, &pub_کلید, پوچ);
	DH_get0_pqg(kex->dh, &dh_p, پوچ, &dh_g);
	hashlen = اندازه(hash);
	اگر ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_کلید_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    pub_کلید,
	    dh_server_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		برو out;

	اگر ((r = sshkey_verify(server_host_کلید, signature, slen, hash,
	    hashlen, kex->hostkey_alg, ssh->compat, پوچ)) != 0)
		برو out;

	اگر ((r = kex_derive_کلیدها(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		برو out;

	/* save initial signature and hostkey */
	اگر ((kex->flags & KEX_INITIAL) != 0) {
		اگر (kex->initial_hostkey != پوچ || kex->initial_sig != پوچ) {
			r = SSH_ERR_INTERNAL_ERROR;
			برو out;
		}
		اگر ((kex->initial_sig = sshbuf_new()) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		اگر ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			برو out;
		kex->initial_hostkey = server_host_کلید;
		server_host_کلید = پوچ;
	}
	/* success */
 out:
	explicit_bzero(hash, اندازه(hash));
	DH_free(kex->dh);
	kex->dh = پوچ;
	BN_clear_free(dh_server_pub);
	sshbuf_free(shared_secret);
	sshkey_free(server_host_کلید);
	sshbuf_free(tmp);
	sshbuf_free(server_host_کلید_blob);
	آزاد(signature);
	بازگشت r;
}
#endif /* WITH_OPENSSL */
