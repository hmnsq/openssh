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

#অন্তর্ভাৱ "includes.h"

#ifdef WITH_OPENSSL
#অন্তর্ভাৱ "openbsd-compat/openssl-compat.h"

#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <openssl/bn.h>
#অন্তর্ভাৱ <openssl/dh.h>

#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <signal.h>

#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "digest.h"
#অন্তর্ভাৱ "kex.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "dh.h"
#অন্তর্ভাৱ "ssh2.h"
#অন্তর্ভাৱ "compat.h"
#অন্তর্ভাৱ "dispatch.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "misc.h"

স্থির পূর্ণাঙ্ক প্ৰবেশ_kex_dh_gex_group(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);
স্থির পূর্ণাঙ্ক প্ৰবেশ_kex_dh_gex_reply(পূর্ণাঙ্ক, uint32_t, সংরচনা ssh *);

পূর্ণাঙ্ক
kexgex_client(সংরচনা ssh *ssh)
{
	সংরচনা kex *kex = ssh->kex;
	পূর্ণাঙ্ক r;
	u_int nbits;

	nbits = dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	যদি (ssh->compat & SSH_BUG_DHGEX_LARGE)
		kex->nbits = MINIMUM(kex->nbits, 4096);
	/* New GEX request */
	যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_KEX_DH_GEX_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->min)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->nbits)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->max)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		গচ্ছ out;
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
	    kex->min, kex->nbits, kex->max);
#ifdef DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d\n",
	    kex->min, kex->nbits, kex->max);
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_GROUP");
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_KEX_DH_GEX_GROUP,
	    &প্ৰবেশ_kex_dh_gex_group);
	r = 0;
 out:
	ঘূৰাই r;
}

স্থির পূর্ণাঙ্ক
প্ৰবেশ_kex_dh_gex_group(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	সংরচনা kex *kex = ssh->kex;
	BIGNUM *p = রিক্ত, *g = রিক্ত;
	ধ্রুৱ BIGNUM *pub_চাবি;
	পূর্ণাঙ্ক r, bits;

	debug("SSH2_MSG_KEX_DH_GEX_GROUP received");
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_KEX_DH_GEX_GROUP, &kex_protocol_error);

	যদি ((r = sshpkt_get_bignum2(ssh, &p)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, &g)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		গচ্ছ out;
	যদি ((bits = BN_অঙ্ক_bits(p)) < 0 ||
	    (u_int)bits < kex->min || (u_int)bits > kex->max) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		গচ্ছ out;
	}
	যদি ((kex->dh = dh_new_group(g, p)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	p = g = রিক্ত; /* belong to kex->dh now */

	/* generate and send 'e', client DH public key */
	যদি ((r = dh_gen_চাবি(kex->dh, kex->we_need * 8)) != 0)
		গচ্ছ out;
	DH_get0_চাবি(kex->dh, &pub_চাবি, রিক্ত);
	যদি ((r = sshpkt_start(ssh, SSH2_বাৰ্তা_KEX_DH_GEX_INIT)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_চাবি)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		গচ্ছ out;
	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_চাবি);
	fprintf(stderr, "\n");
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_REPLY");
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_KEX_DH_GEX_REPLY, &প্ৰবেশ_kex_dh_gex_reply);
	r = 0;
out:
	BN_clear_free(p);
	BN_clear_free(g);
	ঘূৰাই r;
}

স্থির পূর্ণাঙ্ক
প্ৰবেশ_kex_dh_gex_reply(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	সংরচনা kex *kex = ssh->kex;
	BIGNUM *dh_server_pub = রিক্ত;
	ধ্রুৱ BIGNUM *pub_চাবি, *dh_p, *dh_g;
	সংরচনা sshbuf *shared_secret = রিক্ত;
	সংরচনা sshbuf *tmp = রিক্ত, *server_host_চাবি_blob = রিক্ত;
	সংরচনা sshkey *server_host_চাবি = রিক্ত;
	u_char *signature = রিক্ত;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	পূর্ণাঙ্ক r;

	debug("SSH2_MSG_KEX_DH_GEX_REPLY received");
	ssh_dispatch_set(ssh, SSH2_বাৰ্তা_KEX_DH_GEX_REPLY, &kex_protocol_error);

	/* key, cert */
	যদি ((r = sshpkt_getb_froms(ssh, &server_host_চাবি_blob)) != 0)
		গচ্ছ out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	যদি ((tmp = sshbuf_fromb(server_host_চাবি_blob)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = sshkey_fromb_allowlist(tmp, &server_host_চাবি,
	    kex->hostkey_alg, রিক্ত)) != 0 ||
	    (r = kex_verify_host_চাবি(ssh, server_host_চাবি)) != 0)
		গচ্ছ out;
	/* DH parameter f, server public DH key, signed H */
	যদি ((r = sshpkt_get_bignum2(ssh, &dh_server_pub)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		গচ্ছ out;
	যদি ((shared_secret = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = kex_dh_compute_চাবি(kex, dh_server_pub, shared_secret)) != 0)
		গচ্ছ out;
	যদি (ssh->compat & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	/* calc and verify H */
	DH_get0_চাবি(kex->dh, &pub_চাবি, রিক্ত);
	DH_get0_pqg(kex->dh, &dh_p, রিক্ত, &dh_g);
	hashlen = পরিমাণ(hash);
	যদি ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_চাবি_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    pub_চাবি,
	    dh_server_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		গচ্ছ out;

	যদি ((r = sshkey_verify(server_host_চাবি, signature, slen, hash,
	    hashlen, kex->hostkey_alg, ssh->compat, রিক্ত)) != 0)
		গচ্ছ out;

	যদি ((r = kex_derive_চাবিগুলি(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		গচ্ছ out;

	/* save initial signature and hostkey */
	যদি ((kex->flags & KEX_INITIAL) != 0) {
		যদি (kex->initial_hostkey != রিক্ত || kex->initial_sig != রিক্ত) {
			r = SSH_ERR_INTERNAL_ERROR;
			গচ্ছ out;
		}
		যদি ((kex->initial_sig = sshbuf_new()) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		যদি ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			গচ্ছ out;
		kex->initial_hostkey = server_host_চাবি;
		server_host_চাবি = রিক্ত;
	}
	/* success */
 out:
	explicit_bzero(hash, পরিমাণ(hash));
	DH_free(kex->dh);
	kex->dh = রিক্ত;
	BN_clear_free(dh_server_pub);
	sshbuf_free(shared_secret);
	sshkey_free(server_host_চাবি);
	sshbuf_free(tmp);
	sshbuf_free(server_host_চাবি_blob);
	মুক্ত(signature);
	ঘূৰাই r;
}
#endif /* WITH_OPENSSL */
