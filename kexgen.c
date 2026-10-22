/* $OpenBSD: kexgen.c,v 1.15 2026/09/16 00:31:27 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
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

#समावेश <sys/types.h>

#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <signal.h>

#समावेश "sshkey.h"
#समावेश "kex.h"
#समावेश "log.h"
#समावेश "packet.h"
#समावेश "ssh2.h"
#समावेश "sshbuf.h"
#समावेश "digest.h"
#समावेश "ssherr.h"

अटल पूर्णांक निवेश_kex_gen_init(पूर्णांक, uint32_t, काष्ठा ssh *);
अटल पूर्णांक निवेश_kex_gen_reply(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh);

अटल पूर्णांक
kex_gen_hash(
    पूर्णांक hash_alg,
    स्थिर काष्ठा sshbuf *client_version,
    स्थिर काष्ठा sshbuf *server_version,
    स्थिर काष्ठा sshbuf *client_kexinit,
    स्थिर काष्ठा sshbuf *server_kexinit,
    स्थिर काष्ठा sshbuf *server_host_कुंजी_blob,
    स्थिर काष्ठा sshbuf *client_pub,
    स्थिर काष्ठा sshbuf *server_pub,
    स्थिर काष्ठा sshbuf *shared_secret,
    u_char *hash, माप_प्रकार *hashlen)
{
	काष्ठा sshbuf *b;
	पूर्णांक r;

	अगर (*hashlen < ssh_digest_bytes(hash_alg))
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((b = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put_stringb(b, client_version)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_संदेश_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_संदेश_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_कुंजी_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		वापस r;
	}
#अगर_घोषित DEBUG_KEX
	sshbuf_dump(b, मानक_त्रुटि);
#पूर्ण_अगर
	अगर (ssh_digest_बफर(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		वापस SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#अगर_घोषित DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#पूर्ण_अगर
	वापस 0;
}

पूर्णांक
kex_gen_client(काष्ठा ssh *ssh)
{
	काष्ठा kex *kex = ssh->kex;
	पूर्णांक r;

	चयन (kex->kex_type) {
#अगर_घोषित WITH_OPENSSL
	हाल KEX_DH_GRP1_SHA1:
	हाल KEX_DH_GRP14_SHA1:
	हाल KEX_DH_GRP14_SHA256:
	हाल KEX_DH_GRP16_SHA512:
	हाल KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		अवरोध;
	हाल KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		अवरोध;
	हाल KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_keypair(kex);
		अवरोध;
#पूर्ण_अगर /* WITH_OPENSSL */
	हाल KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		अवरोध;
	हाल KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		अवरोध;
	हाल KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_keypair(kex);
		अवरोध;
	शेष:
		r = SSH_ERR_INVALID_ARGUMENT;
		अवरोध;
	}
	अगर (r != 0)
		वापस r;
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		वापस r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_ECDH_REPLY, &निवेश_kex_gen_reply);
	वापस 0;
}

अटल पूर्णांक
निवेश_kex_gen_reply(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	काष्ठा kex *kex = ssh->kex;
	काष्ठा sshkey *server_host_कुंजी = शून्य;
	काष्ठा sshbuf *shared_secret = शून्य;
	काष्ठा sshbuf *server_blob = शून्य;
	काष्ठा sshbuf *tmp = शून्य, *server_host_कुंजी_blob = शून्य;
	u_char *signature = शून्य;
	u_char hash[SSH_DIGEST_MAX_लंबाई];
	माप_प्रकार slen, hashlen;
	पूर्णांक r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_ECDH_REPLY, &kex_protocol_error);

	/* hostkey */
	अगर ((r = sshpkt_getb_froms(ssh, &server_host_कुंजी_blob)) != 0)
		जाओ out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	अगर ((tmp = sshbuf_fromb(server_host_कुंजी_blob)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshkey_fromb_allowlist(tmp, &server_host_कुंजी,
	    kex->hostkey_alg, शून्य)) != 0)
		जाओ out;
	अगर ((r = kex_verify_host_कुंजी(ssh, server_host_कुंजी)) != 0)
		जाओ out;

	/* Q_S, server public key */
	/* signed H */
	अगर ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		जाओ out;

	/* compute shared secret */
	चयन (kex->kex_type) {
#अगर_घोषित WITH_OPENSSL
	हाल KEX_DH_GRP1_SHA1:
	हाल KEX_DH_GRP14_SHA1:
	हाल KEX_DH_GRP14_SHA256:
	हाल KEX_DH_GRP16_SHA512:
	हाल KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		अवरोध;
	हाल KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		अवरोध;
	हाल KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_dec(kex, server_blob,
		    &shared_secret);
		अवरोध;
#पूर्ण_अगर /* WITH_OPENSSL */
	हाल KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		अवरोध;
	हाल KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
		    &shared_secret);
		अवरोध;
	हाल KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_dec(kex, server_blob,
		    &shared_secret);
		अवरोध;
	शेष:
		r = SSH_ERR_INVALID_ARGUMENT;
		अवरोध;
	}
	अगर (r !=0 )
		जाओ out;

	/* calc and verify H */
	hashlen = माप(hash);
	अगर ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_कुंजी_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		जाओ out;

	अगर ((r = sshkey_verify(server_host_कुंजी, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, शून्य)) != 0)
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
	explicit_bzero(kex->c25519_client_कुंजी, माप(kex->c25519_client_कुंजी));
	explicit_bzero(kex->sntrup761_client_कुंजी,
	    माप(kex->sntrup761_client_कुंजी));
	explicit_bzero(kex->mlkem768_client_कुंजी,
	    माप(kex->mlkem768_client_कुंजी));
	sshbuf_free(server_host_कुंजी_blob);
	मुक्त(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_कुंजी);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = शून्य;
	वापस r;
}

पूर्णांक
kex_gen_server(काष्ठा ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_ECDH_INIT, &निवेश_kex_gen_init);
	वापस 0;
}

अटल पूर्णांक
निवेश_kex_gen_init(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	काष्ठा kex *kex = ssh->kex;
	काष्ठा sshkey *server_host_private, *server_host_public;
	काष्ठा sshbuf *shared_secret = शून्य;
	काष्ठा sshbuf *server_pubkey = शून्य;
	काष्ठा sshbuf *client_pubkey = शून्य;
	काष्ठा sshbuf *server_host_कुंजी_blob = शून्य;
	u_char *signature = शून्य, hash[SSH_DIGEST_MAX_लंबाई];
	माप_प्रकार slen, hashlen;
	पूर्णांक r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_ECDH_INIT, &kex_protocol_error);

	अगर ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		जाओ out;

	अगर ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		जाओ out;

	/* compute shared secret */
	चयन (kex->kex_type) {
#अगर_घोषित WITH_OPENSSL
	हाल KEX_DH_GRP1_SHA1:
	हाल KEX_DH_GRP14_SHA1:
	हाल KEX_DH_GRP14_SHA256:
	हाल KEX_DH_GRP16_SHA512:
	हाल KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		अवरोध;
	हाल KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		अवरोध;
	हाल KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		अवरोध;
#पूर्ण_अगर /* WITH_OPENSSL */
	हाल KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		अवरोध;
	हाल KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		अवरोध;
	हाल KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		अवरोध;
	शेष:
		r = SSH_ERR_INVALID_ARGUMENT;
		अवरोध;
	}
	अगर (r !=0 )
		जाओ out;

	/* calc H */
	अगर ((server_host_कुंजी_blob = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshkey_putb(server_host_public, server_host_कुंजी_blob)) != 0)
		जाओ out;
	hashlen = माप(hash);
	अगर ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_कुंजी_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		जाओ out;

	/* sign H */
	अगर ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		जाओ out;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_KEX_ECDH_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_कुंजी_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
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
	sshbuf_free(server_host_कुंजी_blob);
	मुक्त(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	वापस r;
}
