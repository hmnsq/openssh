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

#समावेश "includes.h"

#अगर_घोषित WITH_OPENSSL
#समावेश "openbsd-compat/openssl-compat.h"

#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <signal.h>

#समावेश <openssl/bn.h>
#समावेश <openssl/dh.h>

#समावेश "sshkey.h"
#समावेश "cipher.h"
#समावेश "digest.h"
#समावेश "kex.h"
#समावेश "log.h"
#समावेश "packet.h"
#समावेश "dh.h"
#समावेश "ssh2.h"
#अगर_घोषित GSSAPI
#समावेश "ssh-gss.h"
#पूर्ण_अगर
#समावेश "monitor_wrap.h"
#समावेश "dispatch.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "misc.h"

अटल पूर्णांक निवेश_kex_dh_gex_request(पूर्णांक, uint32_t, काष्ठा ssh *);
अटल पूर्णांक निवेश_kex_dh_gex_init(पूर्णांक, uint32_t, काष्ठा ssh *);

पूर्णांक
kexgex_server(काष्ठा ssh *ssh)
{
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_REQUEST,
	    &निवेश_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	वापस 0;
}

अटल पूर्णांक
निवेश_kex_dh_gex_request(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	काष्ठा kex *kex = ssh->kex;
	पूर्णांक r;
	u_int min = 0, max = 0, nbits = 0;
	स्थिर BIGNUM *dh_p, *dh_g;

	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	अगर ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		जाओ out;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = MAXIMUM(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = MAXIMUM(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	अगर (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		जाओ out;
	}

	/* Contact privileged parent */
	kex->dh = mm_choose_dh(min, nbits, max);
	अगर (kex->dh == शून्य) {
		(व्योम)sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	DH_get0_pqg(kex->dh, &dh_p, शून्य, &dh_g);
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_KEX_DH_GEX_GROUP)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		जाओ out;

	/* Compute our exchange value in parallel with the client */
	अगर ((r = dh_gen_कुंजी(kex->dh, kex->we_need * 8)) != 0)
		जाओ out;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_INIT, &निवेश_kex_dh_gex_init);
	r = 0;
 out:
	वापस r;
}

अटल पूर्णांक
निवेश_kex_dh_gex_init(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	काष्ठा kex *kex = ssh->kex;
	BIGNUM *dh_client_pub = शून्य;
	स्थिर BIGNUM *pub_कुंजी, *dh_p, *dh_g;
	काष्ठा sshbuf *shared_secret = शून्य;
	काष्ठा sshbuf *server_host_कुंजी_blob = शून्य;
	काष्ठा sshkey *server_host_public, *server_host_private;
	u_char *signature = शून्य;
	u_char hash[SSH_DIGEST_MAX_लंबाई];
	माप_प्रकार slen, hashlen;
	पूर्णांक r;

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_INIT, &kex_protocol_error);

	अगर ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		जाओ out;

	/* key, cert */
	अगर ((r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		जाओ out;
	अगर ((shared_secret = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = kex_dh_compute_कुंजी(kex, dh_client_pub, shared_secret)) != 0)
		जाओ out;
	अगर ((server_host_कुंजी_blob = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshkey_putb(server_host_public, server_host_कुंजी_blob)) != 0)
		जाओ out;

	/* calc H */
	DH_get0_कुंजी(kex->dh, &pub_कुंजी, शून्य);
	DH_get0_pqg(kex->dh, &dh_p, शून्य, &dh_g);
	hashlen = माप(hash);
	अगर ((r = kexgex_hash(
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
		जाओ out;

	/* sign H */
	अगर ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		जाओ out;

	/* send server hostkey, DH pubkey 'f' and signed H */
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_KEX_DH_GEX_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_कुंजी_blob)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_कुंजी)) != 0 ||     /* f */
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		जाओ out;

	अगर ((r = kex_derive_कुंजियाँ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		जाओ out;

	/* retain copy of hostkey used at initial KEX */
	अगर (kex->initial_hostkey == शून्य &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		जाओ out;
	/* success */
 out:
	explicit_bzero(hash, माप(hash));
	DH_free(kex->dh);
	kex->dh = शून्य;
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_कुंजी_blob);
	मुक्त(signature);
	वापस r;
}
#पूर्ण_अगर /* WITH_OPENSSL */
