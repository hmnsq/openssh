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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <signal.h>

#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "ssherr.h"

स्थिर पूर्णांक आदान_kex_gen_init(पूर्णांक, uint32_t, संरचना ssh *);
स्थिर पूर्णांक आदान_kex_gen_reply(पूर्णांक type, uint32_t seq, संरचना ssh *ssh);

स्थिर पूर्णांक
kex_gen_hash(
    पूर्णांक hash_alg,
    स्थिरांक संरचना sshbuf *client_version,
    स्थिरांक संरचना sshbuf *server_version,
    स्थिरांक संरचना sshbuf *client_kexinit,
    स्थिरांक संरचना sshbuf *server_kexinit,
    स्थिरांक संरचना sshbuf *server_host_किल्ली_blob,
    स्थिरांक संरचना sshbuf *client_pub,
    स्थिरांक संरचना sshbuf *server_pub,
    स्थिरांक संरचना sshbuf *shared_secret,
    u_char *hash, माप_प्रकार *hashlen)
{
	संरचना sshbuf *b;
	पूर्णांक r;

	जर (*hashlen < ssh_digest_bytes(hash_alg))
		परत SSH_ERR_INVALID_ARGUMENT;
	जर ((b = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_put_stringb(b, client_version)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_संदेश_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_संदेश_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_किल्ली_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		परत r;
	}
#ifdef DEBUG_KEX
	sshbuf_dump(b, मानक_त्रुटि);
#endif
	जर (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		परत SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#endif
	परत 0;
}

पूर्णांक
kex_gen_client(संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	पूर्णांक r;

	निवड (kex->kex_type) {
#ifdef WITH_OPENSSL
	स्थिती KEX_DH_GRP1_SHA1:
	स्थिती KEX_DH_GRP14_SHA1:
	स्थिती KEX_DH_GRP14_SHA256:
	स्थिती KEX_DH_GRP16_SHA512:
	स्थिती KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		थांबा;
	स्थिती KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		थांबा;
	स्थिती KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_keypair(kex);
		थांबा;
#endif /* WITH_OPENSSL */
	स्थिती KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		थांबा;
	स्थिती KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		थांबा;
	स्थिती KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_keypair(kex);
		थांबा;
	पूर्वनिर्धारित:
		r = SSH_ERR_INVALID_ARGUMENT;
		थांबा;
	}
	जर (r != 0)
		परत r;
	जर ((r = sshpkt_start(ssh, SSH2_संदेश_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		परत r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_ECDH_REPLY, &आदान_kex_gen_reply);
	परत 0;
}

स्थिर पूर्णांक
आदान_kex_gen_reply(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	संरचना sshkey *server_host_किल्ली = रिक्त;
	संरचना sshbuf *shared_secret = रिक्त;
	संरचना sshbuf *server_blob = रिक्त;
	संरचना sshbuf *tmp = रिक्त, *server_host_किल्ली_blob = रिक्त;
	u_char *signature = रिक्त;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	माप_प्रकार slen, hashlen;
	पूर्णांक r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_ECDH_REPLY, &kex_protocol_error);

	/* hostkey */
	जर ((r = sshpkt_getb_froms(ssh, &server_host_किल्ली_blob)) != 0)
		जा out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	जर ((tmp = sshbuf_fromb(server_host_किल्ली_blob)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshkey_fromb_allowlist(tmp, &server_host_किल्ली,
	    kex->hostkey_alg, रिक्त)) != 0)
		जा out;
	जर ((r = kex_verify_host_किल्ली(ssh, server_host_किल्ली)) != 0)
		जा out;

	/* Q_S, server public key */
	/* signed H */
	जर ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		जा out;

	/* compute shared secret */
	निवड (kex->kex_type) {
#ifdef WITH_OPENSSL
	स्थिती KEX_DH_GRP1_SHA1:
	स्थिती KEX_DH_GRP14_SHA1:
	स्थिती KEX_DH_GRP14_SHA256:
	स्थिती KEX_DH_GRP16_SHA512:
	स्थिती KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		थांबा;
	स्थिती KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		थांबा;
	स्थिती KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_dec(kex, server_blob,
		    &shared_secret);
		थांबा;
#endif /* WITH_OPENSSL */
	स्थिती KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		थांबा;
	स्थिती KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
		    &shared_secret);
		थांबा;
	स्थिती KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_dec(kex, server_blob,
		    &shared_secret);
		थांबा;
	पूर्वनिर्धारित:
		r = SSH_ERR_INVALID_ARGUMENT;
		थांबा;
	}
	जर (r !=0 )
		जा out;

	/* calc and verify H */
	hashlen = आकार(hash);
	जर ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_किल्ली_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		जा out;

	जर ((r = sshkey_verify(server_host_किल्ली, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, रिक्त)) != 0)
		जा out;

	जर ((r = kex_derive_किल्ल्या(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		जा out;

	/* save initial signature and hostkey */
	जर ((kex->flags & KEX_INITIAL) != 0) {
		जर (kex->initial_hostkey != रिक्त || kex->initial_sig != रिक्त) {
			r = SSH_ERR_INTERNAL_ERROR;
			जा out;
		}
		जर ((kex->initial_sig = sshbuf_new()) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			जा out;
		}
		जर ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			जा out;
		kex->initial_hostkey = server_host_किल्ली;
		server_host_किल्ली = रिक्त;
	}
	/* success */
out:
	explicit_bzero(hash, आकार(hash));
	explicit_bzero(kex->c25519_client_किल्ली, आकार(kex->c25519_client_किल्ली));
	explicit_bzero(kex->sntrup761_client_किल्ली,
	    आकार(kex->sntrup761_client_किल्ली));
	explicit_bzero(kex->mlkem768_client_किल्ली,
	    आकार(kex->mlkem768_client_किल्ली));
	sshbuf_free(server_host_किल्ली_blob);
	मुक्त(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_किल्ली);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = रिक्त;
	परत r;
}

पूर्णांक
kex_gen_server(संरचना ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_ECDH_INIT, &आदान_kex_gen_init);
	परत 0;
}

स्थिर पूर्णांक
आदान_kex_gen_init(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	संरचना sshkey *server_host_private, *server_host_public;
	संरचना sshbuf *shared_secret = रिक्त;
	संरचना sshbuf *server_pubkey = रिक्त;
	संरचना sshbuf *client_pubkey = रिक्त;
	संरचना sshbuf *server_host_किल्ली_blob = रिक्त;
	u_char *signature = रिक्त, hash[SSH_DIGEST_MAX_LENGTH];
	माप_प्रकार slen, hashlen;
	पूर्णांक r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_set(ssh, SSH2_संदेश_KEX_ECDH_INIT, &kex_protocol_error);

	जर ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		जा out;

	जर ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		जा out;

	/* compute shared secret */
	निवड (kex->kex_type) {
#ifdef WITH_OPENSSL
	स्थिती KEX_DH_GRP1_SHA1:
	स्थिती KEX_DH_GRP14_SHA1:
	स्थिती KEX_DH_GRP14_SHA256:
	स्थिती KEX_DH_GRP16_SHA512:
	स्थिती KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		थांबा;
	स्थिती KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		थांबा;
	स्थिती KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		थांबा;
#endif /* WITH_OPENSSL */
	स्थिती KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		थांबा;
	स्थिती KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		थांबा;
	स्थिती KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		थांबा;
	पूर्वनिर्धारित:
		r = SSH_ERR_INVALID_ARGUMENT;
		थांबा;
	}
	जर (r !=0 )
		जा out;

	/* calc H */
	जर ((server_host_किल्ली_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshkey_putb(server_host_public, server_host_किल्ली_blob)) != 0)
		जा out;
	hashlen = आकार(hash);
	जर ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_किल्ली_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		जा out;

	/* sign H */
	जर ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		जा out;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	जर ((r = sshpkt_start(ssh, SSH2_संदेश_KEX_ECDH_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_किल्ली_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		जा out;

	जर ((r = kex_derive_किल्ल्या(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		जा out;
	/* retain copy of hostkey used at initial KEX */
	जर (kex->initial_hostkey == रिक्त &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		जा out;
	/* success */
out:
	explicit_bzero(hash, आकार(hash));
	sshbuf_free(server_host_किल्ली_blob);
	मुक्त(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	परत r;
}
