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

#अन्तर्भाव "includes.h"

#ifdef WITH_OPENSSL
#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <signal.h>

#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/dh.h>

#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "dh.h"
#अन्तर्भाव "ssh2.h"
#ifdef GSSAPI
#अन्तर्भाव "ssh-gss.h"
#endif
#अन्तर्भाव "monitor_wrap.h"
#अन्तर्भाव "dispatch.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "misc.h"

स्थिर पूर्णाङ्क निवेश_kex_dh_gex_request(पूर्णाङ्क, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क निवेश_kex_dh_gex_init(पूर्णाङ्क, uint32_t, संरचना ssh *);

पूर्णाङ्क
kexgex_server(संरचना ssh *ssh)
{
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_REQUEST,
	    &निवेश_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
निवेश_kex_dh_gex_request(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	पूर्णाङ्क r;
	u_int min = 0, max = 0, nbits = 0;
	ध्रुव BIGNUM *dh_p, *dh_g;

	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	यदि ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		गच्छ out;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = MAXIMUM(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = MAXIMUM(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	यदि (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		गच्छ out;
	}

	/* Contact privileged parent */
	kex->dh = mm_choose_dh(min, nbits, max);
	यदि (kex->dh == रिक्त) {
		(शून्य)sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	DH_get0_pqg(kex->dh, &dh_p, रिक्त, &dh_g);
	यदि ((r = sshpkt_start(ssh, SSH2_संदेश_KEX_DH_GEX_GROUP)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		गच्छ out;

	/* Compute our exchange value in parallel with the client */
	यदि ((r = dh_gen_कुंजी(kex->dh, kex->we_need * 8)) != 0)
		गच्छ out;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_INIT, &निवेश_kex_dh_gex_init);
	r = 0;
 out:
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
निवेश_kex_dh_gex_init(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	BIGNUM *dh_client_pub = रिक्त;
	ध्रुव BIGNUM *pub_कुंजी, *dh_p, *dh_g;
	संरचना sshbuf *shared_secret = रिक्त;
	संरचना sshbuf *server_host_कुंजी_blob = रिक्त;
	संरचना sshkey *server_host_public, *server_host_private;
	u_char *signature = रिक्त;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	माप_प्रकार slen, hashlen;
	पूर्णाङ्क r;

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_INIT, &kex_protocol_error);

	यदि ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		गच्छ out;

	/* key, cert */
	यदि ((r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		गच्छ out;
	यदि ((shared_secret = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = kex_dh_compute_कुंजी(kex, dh_client_pub, shared_secret)) != 0)
		गच्छ out;
	यदि ((server_host_कुंजी_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshkey_putb(server_host_public, server_host_कुंजी_blob)) != 0)
		गच्छ out;

	/* calc H */
	DH_get0_कुंजी(kex->dh, &pub_कुंजी, रिक्त);
	DH_get0_pqg(kex->dh, &dh_p, रिक्त, &dh_g);
	hashlen = परिमाण(hash);
	यदि ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_कुंजी_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    dh_client_pub,
	    pub_कुंजी,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		गच्छ out;

	/* sign H */
	यदि ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		गच्छ out;

	/* send server hostkey, DH pubkey 'f' and signed H */
	यदि ((r = sshpkt_start(ssh, SSH2_संदेश_KEX_DH_GEX_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_कुंजी_blob)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_कुंजी)) != 0 ||     /* f */
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		गच्छ out;

	यदि ((r = kex_derive_कुंजियाँ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		गच्छ out;

	/* retain copy of hostkey used at initial KEX */
	यदि (kex->initial_hostkey == रिक्त &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		गच्छ out;
	/* success */
 out:
	explicit_bzero(hash, परिमाण(hash));
	DH_free(kex->dh);
	kex->dh = रिक्त;
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_कुंजी_blob);
	मुक्त(signature);
	प्रत्यागम r;
}
#endif /* WITH_OPENSSL */
