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

#अन्तर्भाव "includes.h"

#ifdef WITH_OPENSSL
#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/dh.h>

#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <signal.h>

#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "dh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "dispatch.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "misc.h"

स्थिर पूर्णाङ्क निवेश_kex_dh_gex_group(पूर्णाङ्क, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क निवेश_kex_dh_gex_reply(पूर्णाङ्क, uint32_t, संरचना ssh *);

पूर्णाङ्क
kexgex_client(संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	पूर्णाङ्क r;
	u_int nbits;

	nbits = dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	यदि (ssh->compat & SSH_BUG_DHGEX_LARGE)
		kex->nbits = MINIMUM(kex->nbits, 4096);
	/* New GEX request */
	यदि ((r = sshpkt_start(ssh, SSH2_संदेश_KEX_DH_GEX_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->min)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->nbits)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->max)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		गच्छ out;
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
	    kex->min, kex->nbits, kex->max);
#ifdef DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d\n",
	    kex->min, kex->nbits, kex->max);
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_GROUP");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_GROUP,
	    &निवेश_kex_dh_gex_group);
	r = 0;
 out:
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
निवेश_kex_dh_gex_group(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	BIGNUM *p = रिक्त, *g = रिक्त;
	ध्रुव BIGNUM *pub_कुंजी;
	पूर्णाङ्क r, bits;

	debug("SSH2_MSG_KEX_DH_GEX_GROUP received");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_GROUP, &kex_protocol_error);

	यदि ((r = sshpkt_get_bignum2(ssh, &p)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, &g)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		गच्छ out;
	यदि ((bits = BN_अंक_bits(p)) < 0 ||
	    (u_int)bits < kex->min || (u_int)bits > kex->max) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		गच्छ out;
	}
	यदि ((kex->dh = dh_new_group(g, p)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	p = g = रिक्त; /* belong to kex->dh now */

	/* generate and send 'e', client DH public key */
	यदि ((r = dh_gen_कुंजी(kex->dh, kex->we_need * 8)) != 0)
		गच्छ out;
	DH_get0_कुंजी(kex->dh, &pub_कुंजी, रिक्त);
	यदि ((r = sshpkt_start(ssh, SSH2_संदेश_KEX_DH_GEX_INIT)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_कुंजी)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		गच्छ out;
	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_कुंजी);
	fprintf(stderr, "\n");
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_REPLY");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_REPLY, &निवेश_kex_dh_gex_reply);
	r = 0;
out:
	BN_clear_free(p);
	BN_clear_free(g);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
निवेश_kex_dh_gex_reply(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	BIGNUM *dh_server_pub = रिक्त;
	ध्रुव BIGNUM *pub_कुंजी, *dh_p, *dh_g;
	संरचना sshbuf *shared_secret = रिक्त;
	संरचना sshbuf *tmp = रिक्त, *server_host_कुंजी_blob = रिक्त;
	संरचना sshkey *server_host_कुंजी = रिक्त;
	u_char *signature = रिक्त;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	पूर्णाङ्क r;

	debug("SSH2_MSG_KEX_DH_GEX_REPLY received");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_REPLY, &kex_protocol_error);

	/* key, cert */
	यदि ((r = sshpkt_getb_froms(ssh, &server_host_कुंजी_blob)) != 0)
		गच्छ out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	यदि ((tmp = sshbuf_fromb(server_host_कुंजी_blob)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshkey_fromb_allowlist(tmp, &server_host_कुंजी,
	    kex->hostkey_alg, रिक्त)) != 0 ||
	    (r = kex_verify_host_कुंजी(ssh, server_host_कुंजी)) != 0)
		गच्छ out;
	/* DH parameter f, server public DH key, signed H */
	यदि ((r = sshpkt_get_bignum2(ssh, &dh_server_pub)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		गच्छ out;
	यदि ((shared_secret = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = kex_dh_compute_कुंजी(kex, dh_server_pub, shared_secret)) != 0)
		गच्छ out;
	यदि (ssh->compat & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	/* calc and verify H */
	DH_get0_कुंजी(kex->dh, &pub_कुंजी, रिक्त);
	DH_get0_pqg(kex->dh, &dh_p, रिक्त, &dh_g);
	hashlen = परिमाण(hash);
	यदि ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_कुंजी_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    pub_कुंजी,
	    dh_server_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		गच्छ out;

	यदि ((r = sshkey_verify(server_host_कुंजी, signature, slen, hash,
	    hashlen, kex->hostkey_alg, ssh->compat, रिक्त)) != 0)
		गच्छ out;

	यदि ((r = kex_derive_कुंजियाँ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		गच्छ out;

	/* save initial signature and hostkey */
	यदि ((kex->flags & KEX_INITIAL) != 0) {
		यदि (kex->initial_hostkey != रिक्त || kex->initial_sig != रिक्त) {
			r = SSH_ERR_INTERNAL_ERROR;
			गच्छ out;
		}
		यदि ((kex->initial_sig = sshbuf_new()) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		यदि ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			गच्छ out;
		kex->initial_hostkey = server_host_कुंजी;
		server_host_कुंजी = रिक्त;
	}
	/* success */
 out:
	explicit_bzero(hash, परिमाण(hash));
	DH_free(kex->dh);
	kex->dh = रिक्त;
	BN_clear_free(dh_server_pub);
	sshbuf_free(shared_secret);
	sshkey_free(server_host_कुंजी);
	sshbuf_free(tmp);
	sshbuf_free(server_host_कुंजी_blob);
	मुक्त(signature);
	प्रत्यागम r;
}
#endif /* WITH_OPENSSL */
