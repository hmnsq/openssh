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

#അന്തര്ഭാവ "includes.h"

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/dh.h>

#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <signal.h>

#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "dh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "dispatch.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "misc.h"

സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_kex_dh_gex_group(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_kex_dh_gex_reply(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);

പൂർണ്ണസംഖ്യ
kexgex_client(ഘടന ssh *ssh)
{
	ഘടന kex *kex = ssh->kex;
	പൂർണ്ണസംഖ്യ r;
	u_int nbits;

	nbits = dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	എങ്കിൽ (ssh->compat & SSH_BUG_DHGEX_LARGE)
		kex->nbits = MINIMUM(kex->nbits, 4096);
	/* New GEX request */
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_KEX_DH_GEX_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->min)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->nbits)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->max)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		പോകുക out;
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
	    kex->min, kex->nbits, kex->max);
#ifdef DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d\n",
	    kex->min, kex->nbits, kex->max);
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_GROUP");
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEX_DH_GEX_GROUP,
	    &നിവേശം_kex_dh_gex_group);
	r = 0;
 out:
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_kex_dh_gex_group(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	ഘടന kex *kex = ssh->kex;
	BIGNUM *p = ശൂന്യ, *g = ശൂന്യ;
	സ്ഥിരം BIGNUM *pub_താക്കോൽ;
	പൂർണ്ണസംഖ്യ r, bits;

	debug("SSH2_MSG_KEX_DH_GEX_GROUP received");
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEX_DH_GEX_GROUP, &kex_protocol_error);

	എങ്കിൽ ((r = sshpkt_get_bignum2(ssh, &p)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, &g)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		പോകുക out;
	എങ്കിൽ ((bits = BN_അക്കം_bits(p)) < 0 ||
	    (u_int)bits < kex->min || (u_int)bits > kex->max) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		പോകുക out;
	}
	എങ്കിൽ ((kex->dh = dh_new_group(g, p)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	p = g = ശൂന്യ; /* belong to kex->dh now */

	/* generate and send 'e', client DH public key */
	എങ്കിൽ ((r = dh_gen_താക്കോൽ(kex->dh, kex->we_need * 8)) != 0)
		പോകുക out;
	DH_get0_താക്കോൽ(kex->dh, &pub_താക്കോൽ, ശൂന്യ);
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_KEX_DH_GEX_INIT)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_താക്കോൽ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		പോകുക out;
	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_താക്കോൽ);
	fprintf(stderr, "\n");
#endif
	debug("expecting SSH2_MSG_KEX_DH_GEX_REPLY");
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEX_DH_GEX_REPLY, &നിവേശം_kex_dh_gex_reply);
	r = 0;
out:
	BN_clear_free(p);
	BN_clear_free(g);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_kex_dh_gex_reply(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	ഘടന kex *kex = ssh->kex;
	BIGNUM *dh_server_pub = ശൂന്യ;
	സ്ഥിരം BIGNUM *pub_താക്കോൽ, *dh_p, *dh_g;
	ഘടന sshbuf *shared_secret = ശൂന്യ;
	ഘടന sshbuf *tmp = ശൂന്യ, *server_host_താക്കോൽ_blob = ശൂന്യ;
	ഘടന sshkey *server_host_താക്കോൽ = ശൂന്യ;
	u_char *signature = ശൂന്യ;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	പൂർണ്ണസംഖ്യ r;

	debug("SSH2_MSG_KEX_DH_GEX_REPLY received");
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEX_DH_GEX_REPLY, &kex_protocol_error);

	/* key, cert */
	എങ്കിൽ ((r = sshpkt_getb_froms(ssh, &server_host_താക്കോൽ_blob)) != 0)
		പോകുക out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	എങ്കിൽ ((tmp = sshbuf_fromb(server_host_താക്കോൽ_blob)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshkey_fromb_allowlist(tmp, &server_host_താക്കോൽ,
	    kex->hostkey_alg, ശൂന്യ)) != 0 ||
	    (r = kex_verify_host_താക്കോൽ(ssh, server_host_താക്കോൽ)) != 0)
		പോകുക out;
	/* DH parameter f, server public DH key, signed H */
	എങ്കിൽ ((r = sshpkt_get_bignum2(ssh, &dh_server_pub)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		പോകുക out;
	എങ്കിൽ ((shared_secret = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = kex_dh_compute_താക്കോൽ(kex, dh_server_pub, shared_secret)) != 0)
		പോകുക out;
	എങ്കിൽ (ssh->compat & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	/* calc and verify H */
	DH_get0_താക്കോൽ(kex->dh, &pub_താക്കോൽ, ശൂന്യ);
	DH_get0_pqg(kex->dh, &dh_p, ശൂന്യ, &dh_g);
	hashlen = വലുപ്പം(hash);
	എങ്കിൽ ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_താക്കോൽ_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    pub_താക്കോൽ,
	    dh_server_pub,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		പോകുക out;

	എങ്കിൽ ((r = sshkey_verify(server_host_താക്കോൽ, signature, slen, hash,
	    hashlen, kex->hostkey_alg, ssh->compat, ശൂന്യ)) != 0)
		പോകുക out;

	എങ്കിൽ ((r = kex_derive_താക്കോലുകൾ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		പോകുക out;

	/* save initial signature and hostkey */
	എങ്കിൽ ((kex->flags & KEX_INITIAL) != 0) {
		എങ്കിൽ (kex->initial_hostkey != ശൂന്യ || kex->initial_sig != ശൂന്യ) {
			r = SSH_ERR_INTERNAL_ERROR;
			പോകുക out;
		}
		എങ്കിൽ ((kex->initial_sig = sshbuf_new()) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			പോകുക out;
		kex->initial_hostkey = server_host_താക്കോൽ;
		server_host_താക്കോൽ = ശൂന്യ;
	}
	/* success */
 out:
	explicit_bzero(hash, വലുപ്പം(hash));
	DH_free(kex->dh);
	kex->dh = ശൂന്യ;
	BN_clear_free(dh_server_pub);
	sshbuf_free(shared_secret);
	sshkey_free(server_host_താക്കോൽ);
	sshbuf_free(tmp);
	sshbuf_free(server_host_താക്കോൽ_blob);
	സ്വതന്ത്രം(signature);
	തിരികെ r;
}
#endif /* WITH_OPENSSL */
