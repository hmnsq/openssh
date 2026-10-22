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

#ضمن "includes.h"

#ifdef WITH_OPENSSL
#ضمن "openbsd-compat/openssl-compat.h"

#ضمن <sys/types.h>

#ضمن <openssl/bn.h>
#ضمن <openssl/dh.h>

#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <signal.h>

#ضمن "sshkey.h"
#ضمن "digest.h"
#ضمن "kex.h"
#ضمن "log.h"
#ضمن "packet.h"
#ضمن "dh.h"
#ضمن "ssh2.h"
#ضمن "compat.h"
#ضمن "dispatch.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "misc.h"

ساكن صحيح شغرو_kex_dh_gex_group(صحيح, uint32_t, بنية ssh *);
ساكن صحيح شغرو_kex_dh_gex_reply(صحيح, uint32_t, بنية ssh *);

صحيح
kexgex_client(بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	صحيح r;
	u_int nbits;

	nbits = dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	إذا (ssh->compat & SSH_BUG_DHGEX_LARGE)
		kex->nbits = MINIMUM(kex->nbits, 4096);
	/* New GEX request */
	إذا ((r = sshpkt_start(ssh, SSH2_سكو_KEX_DH_GEX_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->min)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->nbits)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->max)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		اذهب out;
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
	    kex->min, kex->nbits, kex->max);
#ifdef DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d\n",
	    kex->min, kex->nbits, kex->max);
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_GROUP");
	ssh_dispatch_set(ssh, SSH2_سكو_KEX_DH_GEX_GROUP,
	    &شغرو_kex_dh_gex_group);
	r = 0;
 out:
	أرجع r;
}

ساكن صحيح
شغرو_kex_dh_gex_group(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	BIGNUM *p = عدم, *g = عدم;
	ثابت BIGNUM *pub_مبودي;
	صحيح r, bits;

	debug("SSH2_MSG_KEX_DH_GEX_GROUP received");
	ssh_dispatch_set(ssh, SSH2_سكو_KEX_DH_GEX_GROUP, &kex_protocol_error);

	إذا ((r = sshpkt_get_bignum2(ssh, &p)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, &g)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		اذهب out;
	إذا ((bits = BN_لمب_bits(p)) < 0 ||
	    (u_int)bits < kex->min || (u_int)bits > kex->max) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		اذهب out;
	}
	إذا ((kex->dh = dh_new_group(g, p)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	p = g = عدم; /* belong to kex->dh now */

	/* generate and send 'e', client DH public key */
	إذا ((r = dh_gen_مبودي(kex->dh, kex->we_need * 8)) != 0)
		اذهب out;
	DH_get0_مبودي(kex->dh, &pub_مبودي, عدم);
	إذا ((r = sshpkt_start(ssh, SSH2_سكو_KEX_DH_GEX_INIT)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_مبودي)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		اذهب out;
	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
#ifdef DEBUG_KEXDH
	DHparams_بغ_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_بغ_fp(stderr, pub_مبودي);
	fprintf(stderr, "\n");
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_REPLY");
	ssh_dispatch_set(ssh, SSH2_سكو_KEX_DH_GEX_REPLY, &شغرو_kex_dh_gex_reply);
	r = 0;
out:
	BN_clear_free(p);
	BN_clear_free(g);
	أرجع r;
}

ساكن صحيح
شغرو_kex_dh_gex_reply(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	BIGNUM *dh_server_pub = عدم;
	ثابت BIGNUM *pub_مبودي, *dh_p, *dh_g;
	بنية sshbuf *shared_secret = عدم;
	بنية sshbuf *tmp = عدم, *server_host_مبودي_blob = عدم;
	بنية sshkey *server_host_مبودي = عدم;
	u_char *signature = عدم;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	صحيح r;

	debug("SSH2_MSG_KEX_DH_GEX_REPLY received");
	ssh_dispatch_set(ssh, SSH2_سكو_KEX_DH_GEX_REPLY, &kex_protocol_error);

	/* key, cert */
	إذا ((r = sshpkt_getb_froms(ssh, &server_host_مبودي_blob)) != 0)
		اذهب out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	إذا ((tmp = sshbuf_fromb(server_host_مبودي_blob)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = sshkey_fromb_allowlist(tmp, &server_host_مبودي,
	    kex->hostkey_alg, عدم)) != 0 ||
	    (r = kex_verify_host_مبودي(ssh, server_host_مبودي)) != 0)
		اذهب out;
	/* DH parameter f, server public DH key, signed H */
	إذا ((r = sshpkt_get_bignum2(ssh, &dh_server_pub)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		اذهب out;
	إذا ((shared_secret = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = kex_dh_compute_مبودي(kex, dh_server_pub, shared_secret)) != 0)
		اذهب out;
	إذا (ssh->compat & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	/* calc and verify H */
	DH_get0_مبودي(kex->dh, &pub_مبودي, عدم);
	DH_get0_pqg(kex->dh, &dh_p, عدم, &dh_g);
	hashlen = حجم(hash);
	إذا ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_مبودي_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    pub_مبودي,
	    dh_server_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		اذهب out;

	إذا ((r = sshkey_verify(server_host_مبودي, signature, slen, hash,
	    hashlen, kex->hostkey_alg, ssh->compat, عدم)) != 0)
		اذهب out;

	إذا ((r = kex_derive_مبوداي(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		اذهب out;

	/* save initial signature and hostkey */
	إذا ((kex->flags & KEX_INITIAL) != 0) {
		إذا (kex->initial_hostkey != عدم || kex->initial_sig != عدم) {
			r = SSH_ERR_INTERNAL_ERROR;
			اذهب out;
		}
		إذا ((kex->initial_sig = sshbuf_new()) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		إذا ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			اذهب out;
		kex->initial_hostkey = server_host_مبودي;
		server_host_مبودي = عدم;
	}
	/* success */
 out:
	explicit_bzero(hash, حجم(hash));
	DH_free(kex->dh);
	kex->dh = عدم;
	BN_clear_free(dh_server_pub);
	sshbuf_free(shared_secret);
	sshkey_free(server_host_مبودي);
	sshbuf_free(tmp);
	sshbuf_free(server_host_مبودي_blob);
	حرر(signature);
	أرجع r;
}
#endif /* WITH_OPENSSL */
