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

#அந்தர்பாவ "includes.h"

#ifdef WITH_OPENSSL
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/dh.h>

#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <signal.h>

#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "dh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "dispatch.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "misc.h"

நிலையான முழு உள்ளீடு_kex_dh_gex_group(முழு, uint32_t, கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_kex_dh_gex_reply(முழு, uint32_t, கட்டமைப்பு ssh *);

முழு
kexgex_client(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு kex *kex = ssh->kex;
	முழு r;
	u_int nbits;

	nbits = dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	எனில் (ssh->compat & SSH_BUG_DHGEX_LARGE)
		kex->nbits = MINIMUM(kex->nbits, 4096);
	/* New GEX request */
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_KEX_DH_GEX_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->min)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->nbits)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->max)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		செல் out;
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
	    kex->min, kex->nbits, kex->max);
#ifdef DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d\n",
	    kex->min, kex->nbits, kex->max);
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_GROUP");
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEX_DH_GEX_GROUP,
	    &உள்ளீடு_kex_dh_gex_group);
	r = 0;
 out:
	திரும்பு r;
}

நிலையான முழு
உள்ளீடு_kex_dh_gex_group(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு kex *kex = ssh->kex;
	BIGNUM *p = வெற்று, *g = வெற்று;
	மாறிலி BIGNUM *pub_சாவி;
	முழு r, bits;

	debug("SSH2_MSG_KEX_DH_GEX_GROUP received");
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEX_DH_GEX_GROUP, &kex_protocol_error);

	எனில் ((r = sshpkt_get_bignum2(ssh, &p)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, &g)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		செல் out;
	எனில் ((bits = BN_இலக்கம்_bits(p)) < 0 ||
	    (u_int)bits < kex->min || (u_int)bits > kex->max) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		செல் out;
	}
	எனில் ((kex->dh = dh_new_group(g, p)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	p = g = வெற்று; /* belong to kex->dh now */

	/* generate and send 'e', client DH public key */
	எனில் ((r = dh_gen_சாவி(kex->dh, kex->we_need * 8)) != 0)
		செல் out;
	DH_get0_சாவி(kex->dh, &pub_சாவி, வெற்று);
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_KEX_DH_GEX_INIT)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_சாவி)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		செல் out;
	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_சாவி);
	fprintf(stderr, "\n");
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_REPLY");
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEX_DH_GEX_REPLY, &உள்ளீடு_kex_dh_gex_reply);
	r = 0;
out:
	BN_clear_free(p);
	BN_clear_free(g);
	திரும்பு r;
}

நிலையான முழு
உள்ளீடு_kex_dh_gex_reply(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு kex *kex = ssh->kex;
	BIGNUM *dh_server_pub = வெற்று;
	மாறிலி BIGNUM *pub_சாவி, *dh_p, *dh_g;
	கட்டமைப்பு sshbuf *shared_secret = வெற்று;
	கட்டமைப்பு sshbuf *tmp = வெற்று, *server_host_சாவி_blob = வெற்று;
	கட்டமைப்பு sshkey *server_host_சாவி = வெற்று;
	u_char *signature = வெற்று;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	முழு r;

	debug("SSH2_MSG_KEX_DH_GEX_REPLY received");
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEX_DH_GEX_REPLY, &kex_protocol_error);

	/* key, cert */
	எனில் ((r = sshpkt_getb_froms(ssh, &server_host_சாவி_blob)) != 0)
		செல் out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	எனில் ((tmp = sshbuf_fromb(server_host_சாவி_blob)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshkey_fromb_allowlist(tmp, &server_host_சாவி,
	    kex->hostkey_alg, வெற்று)) != 0 ||
	    (r = kex_verify_host_சாவி(ssh, server_host_சாவி)) != 0)
		செல் out;
	/* DH parameter f, server public DH key, signed H */
	எனில் ((r = sshpkt_get_bignum2(ssh, &dh_server_pub)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		செல் out;
	எனில் ((shared_secret = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = kex_dh_compute_சாவி(kex, dh_server_pub, shared_secret)) != 0)
		செல் out;
	எனில் (ssh->compat & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	/* calc and verify H */
	DH_get0_சாவி(kex->dh, &pub_சாவி, வெற்று);
	DH_get0_pqg(kex->dh, &dh_p, வெற்று, &dh_g);
	hashlen = அளவு(hash);
	எனில் ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_சாவி_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    pub_சாவி,
	    dh_server_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		செல் out;

	எனில் ((r = sshkey_verify(server_host_சாவி, signature, slen, hash,
	    hashlen, kex->hostkey_alg, ssh->compat, வெற்று)) != 0)
		செல் out;

	எனில் ((r = kex_derive_சாவிகள்(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		செல் out;

	/* save initial signature and hostkey */
	எனில் ((kex->flags & KEX_INITIAL) != 0) {
		எனில் (kex->initial_hostkey != வெற்று || kex->initial_sig != வெற்று) {
			r = SSH_ERR_INTERNAL_ERROR;
			செல் out;
		}
		எனில் ((kex->initial_sig = sshbuf_new()) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		எனில் ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			செல் out;
		kex->initial_hostkey = server_host_சாவி;
		server_host_சாவி = வெற்று;
	}
	/* success */
 out:
	explicit_bzero(hash, அளவு(hash));
	DH_free(kex->dh);
	kex->dh = வெற்று;
	BN_clear_free(dh_server_pub);
	sshbuf_free(shared_secret);
	sshkey_free(server_host_சாவி);
	sshbuf_free(tmp);
	sshbuf_free(server_host_சாவி_blob);
	விடுவி(signature);
	திரும்பு r;
}
#endif /* WITH_OPENSSL */
