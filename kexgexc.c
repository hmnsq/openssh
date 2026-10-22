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

#समावेश "includes.h"

#अगर_घोषित WITH_OPENSSL
#समावेश "openbsd-compat/openssl-compat.h"

#समावेश <sys/types.h>

#समावेश <openssl/bn.h>
#समावेश <openssl/dh.h>

#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <signal.h>

#समावेश "sshkey.h"
#समावेश "digest.h"
#समावेश "kex.h"
#समावेश "log.h"
#समावेश "packet.h"
#समावेश "dh.h"
#समावेश "ssh2.h"
#समावेश "compat.h"
#समावेश "dispatch.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "misc.h"

अटल पूर्णांक निवेश_kex_dh_gex_group(पूर्णांक, uint32_t, काष्ठा ssh *);
अटल पूर्णांक निवेश_kex_dh_gex_reply(पूर्णांक, uint32_t, काष्ठा ssh *);

पूर्णांक
kexgex_client(काष्ठा ssh *ssh)
{
	काष्ठा kex *kex = ssh->kex;
	पूर्णांक r;
	u_int nbits;

	nbits = dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	अगर (ssh->compat & SSH_BUG_DHGEX_LARGE)
		kex->nbits = MINIMUM(kex->nbits, 4096);
	/* New GEX request */
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_KEX_DH_GEX_REQUEST)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->min)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->nbits)) != 0 ||
	    (r = sshpkt_put_u32(ssh, kex->max)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		जाओ out;
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
	    kex->min, kex->nbits, kex->max);
#अगर_घोषित DEBUG_KEXDH
	ख_लिखो(मानक_त्रुटि, "\nmin = %d, nbits = %d, max = %d\n",
	    kex->min, kex->nbits, kex->max);
#पूर्ण_अगर
	debug("expecting SSH2_MSG_KEX_DH_GEX_GROUP");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_GROUP,
	    &निवेश_kex_dh_gex_group);
	r = 0;
 out:
	वापस r;
}

अटल पूर्णांक
निवेश_kex_dh_gex_group(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	काष्ठा kex *kex = ssh->kex;
	BIGNUM *p = शून्य, *g = शून्य;
	स्थिर BIGNUM *pub_कुंजी;
	पूर्णांक r, bits;

	debug("SSH2_MSG_KEX_DH_GEX_GROUP received");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_GROUP, &kex_protocol_error);

	अगर ((r = sshpkt_get_bignum2(ssh, &p)) != 0 ||
	    (r = sshpkt_get_bignum2(ssh, &g)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		जाओ out;
	अगर ((bits = BN_अंक_bits(p)) < 0 ||
	    (u_int)bits < kex->min || (u_int)bits > kex->max) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		जाओ out;
	}
	अगर ((kex->dh = dh_new_group(g, p)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	p = g = शून्य; /* belong to kex->dh now */

	/* generate and send 'e', client DH public key */
	अगर ((r = dh_gen_कुंजी(kex->dh, kex->we_need * 8)) != 0)
		जाओ out;
	DH_get0_कुंजी(kex->dh, &pub_कुंजी, शून्य);
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_KEX_DH_GEX_INIT)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_कुंजी)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		जाओ out;
	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
#अगर_घोषित DEBUG_KEXDH
	DHparams_print_fp(मानक_त्रुटि, kex->dh);
	ख_लिखो(मानक_त्रुटि, "pub= ");
	BN_print_fp(मानक_त्रुटि, pub_कुंजी);
	ख_लिखो(मानक_त्रुटि, "\n");
#पूर्ण_अगर
	debug("expecting SSH2_MSG_KEX_DH_GEX_REPLY");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_REPLY, &निवेश_kex_dh_gex_reply);
	r = 0;
out:
	BN_clear_free(p);
	BN_clear_free(g);
	वापस r;
}

अटल पूर्णांक
निवेश_kex_dh_gex_reply(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	काष्ठा kex *kex = ssh->kex;
	BIGNUM *dh_server_pub = शून्य;
	स्थिर BIGNUM *pub_कुंजी, *dh_p, *dh_g;
	काष्ठा sshbuf *shared_secret = शून्य;
	काष्ठा sshbuf *tmp = शून्य, *server_host_कुंजी_blob = शून्य;
	काष्ठा sshkey *server_host_कुंजी = शून्य;
	u_char *signature = शून्य;
	u_char hash[SSH_DIGEST_MAX_लंबाई];
	माप_प्रकार slen, hashlen;
	पूर्णांक r;

	debug("SSH2_MSG_KEX_DH_GEX_REPLY received");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_DH_GEX_REPLY, &kex_protocol_error);

	/* key, cert */
	अगर ((r = sshpkt_getb_froms(ssh, &server_host_कुंजी_blob)) != 0)
		जाओ out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	अगर ((tmp = sshbuf_fromb(server_host_कुंजी_blob)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshkey_fromb_allowlist(tmp, &server_host_कुंजी,
	    kex->hostkey_alg, शून्य)) != 0 ||
	    (r = kex_verify_host_कुंजी(ssh, server_host_कुंजी)) != 0)
		जाओ out;
	/* DH parameter f, server public DH key, signed H */
	अगर ((r = sshpkt_get_bignum2(ssh, &dh_server_pub)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		जाओ out;
	अगर ((shared_secret = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = kex_dh_compute_कुंजी(kex, dh_server_pub, shared_secret)) != 0)
		जाओ out;
	अगर (ssh->compat & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	/* calc and verify H */
	DH_get0_कुंजी(kex->dh, &pub_कुंजी, शून्य);
	DH_get0_pqg(kex->dh, &dh_p, शून्य, &dh_g);
	hashlen = माप(hash);
	अगर ((r = kexgex_hash(
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
		जाओ out;

	अगर ((r = sshkey_verify(server_host_कुंजी, signature, slen, hash,
	    hashlen, kex->hostkey_alg, ssh->compat, शून्य)) != 0)
		जाओ out;

	अगर ((r = kex_derive_कुंजियाँ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		जाओ out;

	/* save initial signature and hostkey */
	अगर ((kex->flags & KEX_INITIAL) != 0) {
		अगर (kex->initial_hostkey != शून्य || kex->initial_sig != शून्य) {
			r = SSH_ERR_INTERNAL_ERROR;
			जाओ out;
		}
		अगर ((kex->initial_sig = sshbuf_new()) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		अगर ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			जाओ out;
		kex->initial_hostkey = server_host_कुंजी;
		server_host_कुंजी = शून्य;
	}
	/* success */
 out:
	explicit_bzero(hash, माप(hash));
	DH_free(kex->dh);
	kex->dh = शून्य;
	BN_clear_free(dh_server_pub);
	sshbuf_free(shared_secret);
	sshkey_free(server_host_कुंजी);
	sshbuf_free(tmp);
	sshbuf_free(server_host_कुंजी_blob);
	मुक्त(signature);
	वापस r;
}
#पूर्ण_अगर /* WITH_OPENSSL */
