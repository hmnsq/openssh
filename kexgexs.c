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

#അന്തര്ഭാവ "includes.h"

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <signal.h>

#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/dh.h>

#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "cipher.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "dh.h"
#അന്തര്ഭാവ "ssh2.h"
#ifdef GSSAPI
#അന്തര്ഭാവ "ssh-gss.h"
#endif
#അന്തര്ഭാവ "monitor_wrap.h"
#അന്തര്ഭാവ "dispatch.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "misc.h"

സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_kex_dh_gex_request(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_kex_dh_gex_init(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);

പൂർണ്ണസംഖ്യ
kexgex_server(ഘടന ssh *ssh)
{
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEX_DH_GEX_REQUEST,
	    &നിവേശം_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_kex_dh_gex_request(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	ഘടന kex *kex = ssh->kex;
	പൂർണ്ണസംഖ്യ r;
	u_int min = 0, max = 0, nbits = 0;
	സ്ഥിരം BIGNUM *dh_p, *dh_g;

	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		പോകുക out;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = MAXIMUM(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = MAXIMUM(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	എങ്കിൽ (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		പോകുക out;
	}

	/* Contact privileged parent */
	kex->dh = mm_choose_dh(min, nbits, max);
	എങ്കിൽ (kex->dh == ശൂന്യ) {
		(ശൂന്യം)sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	DH_get0_pqg(kex->dh, &dh_p, ശൂന്യ, &dh_g);
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_KEX_DH_GEX_GROUP)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		പോകുക out;

	/* Compute our exchange value in parallel with the client */
	എങ്കിൽ ((r = dh_gen_താക്കോൽ(kex->dh, kex->we_need * 8)) != 0)
		പോകുക out;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEX_DH_GEX_INIT, &നിവേശം_kex_dh_gex_init);
	r = 0;
 out:
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_kex_dh_gex_init(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	ഘടന kex *kex = ssh->kex;
	BIGNUM *dh_client_pub = ശൂന്യ;
	സ്ഥിരം BIGNUM *pub_താക്കോൽ, *dh_p, *dh_g;
	ഘടന sshbuf *shared_secret = ശൂന്യ;
	ഘടന sshbuf *server_host_താക്കോൽ_blob = ശൂന്യ;
	ഘടന sshkey *server_host_public, *server_host_private;
	u_char *signature = ശൂന്യ;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	പൂർണ്ണസംഖ്യ r;

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEX_DH_GEX_INIT, &kex_protocol_error);

	എങ്കിൽ ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		പോകുക out;

	/* key, cert */
	എങ്കിൽ ((r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		പോകുക out;
	എങ്കിൽ ((shared_secret = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = kex_dh_compute_താക്കോൽ(kex, dh_client_pub, shared_secret)) != 0)
		പോകുക out;
	എങ്കിൽ ((server_host_താക്കോൽ_blob = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshkey_putb(server_host_public, server_host_താക്കോൽ_blob)) != 0)
		പോകുക out;

	/* calc H */
	DH_get0_താക്കോൽ(kex->dh, &pub_താക്കോൽ, ശൂന്യ);
	DH_get0_pqg(kex->dh, &dh_p, ശൂന്യ, &dh_g);
	hashlen = വലുപ്പം(hash);
	എങ്കിൽ ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_താക്കോൽ_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    dh_client_pub,
	    pub_താക്കോൽ,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		പോകുക out;

	/* sign H */
	എങ്കിൽ ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		പോകുക out;

	/* send server hostkey, DH pubkey 'f' and signed H */
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_KEX_DH_GEX_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_താക്കോൽ_blob)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_താക്കോൽ)) != 0 ||     /* f */
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		പോകുക out;

	എങ്കിൽ ((r = kex_derive_താക്കോലുകൾ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		പോകുക out;

	/* retain copy of hostkey used at initial KEX */
	എങ്കിൽ (kex->initial_hostkey == ശൂന്യ &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		പോകുക out;
	/* success */
 out:
	explicit_bzero(hash, വലുപ്പം(hash));
	DH_free(kex->dh);
	kex->dh = ശൂന്യ;
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_താക്കോൽ_blob);
	സ്വതന്ത്രം(signature);
	തിരികെ r;
}
#endif /* WITH_OPENSSL */
