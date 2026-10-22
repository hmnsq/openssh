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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <signal.h>

#شامل "sshkey.h"
#شامل "kex.h"
#شامل "log.h"
#شامل "packet.h"
#شامل "ssh2.h"
#شامل "sshbuf.h"
#شامل "digest.h"
#شامل "ssherr.h"

ایستا صحیح درون_داد_kex_gen_init(صحیح, uint32_t, ساختار ssh *);
ایستا صحیح درون_داد_kex_gen_reply(صحیح type, uint32_t seq, ساختار ssh *ssh);

ایستا صحیح
kex_gen_hash(
    صحیح hash_alg,
    ثابت ساختار sshbuf *client_version,
    ثابت ساختار sshbuf *server_version,
    ثابت ساختار sshbuf *client_kexinit,
    ثابت ساختار sshbuf *server_kexinit,
    ثابت ساختار sshbuf *server_host_کلید_blob,
    ثابت ساختار sshbuf *client_pub,
    ثابت ساختار sshbuf *server_pub,
    ثابت ساختار sshbuf *shared_secret,
    u_char *hash, size_t *hashlen)
{
	ساختار sshbuf *b;
	صحیح r;

	اگر (*hashlen < ssh_digest_bytes(hash_alg))
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((b = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_stringb(b, client_version)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیام_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیام_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_کلید_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		بازگشت r;
	}
#ifdef DEBUG_KEX
	sshbuf_dump(b, stderr);
#endif
	اگر (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		بازگشت SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#endif
	بازگشت 0;
}

صحیح
kex_gen_client(ساختار ssh *ssh)
{
	ساختار kex *kex = ssh->kex;
	صحیح r;

	انتخاب (kex->kex_type) {
#ifdef WITH_OPENSSL
	حالت KEX_DH_GRP1_SHA1:
	حالت KEX_DH_GRP14_SHA1:
	حالت KEX_DH_GRP14_SHA256:
	حالت KEX_DH_GRP16_SHA512:
	حالت KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		بشکن;
	حالت KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		بشکن;
	حالت KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_keypair(kex);
		بشکن;
#endif /* WITH_OPENSSL */
	حالت KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		بشکن;
	حالت KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		بشکن;
	حالت KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_keypair(kex);
		بشکن;
	پیشفرض:
		r = SSH_ERR_INVALID_ARGUMENT;
		بشکن;
	}
	اگر (r != 0)
		بازگشت r;
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		بازگشت r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_پیام_KEX_ECDH_REPLY, &درون_داد_kex_gen_reply);
	بازگشت 0;
}

ایستا صحیح
درون_داد_kex_gen_reply(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	ساختار kex *kex = ssh->kex;
	ساختار sshkey *server_host_کلید = پوچ;
	ساختار sshbuf *shared_secret = پوچ;
	ساختار sshbuf *server_blob = پوچ;
	ساختار sshbuf *tmp = پوچ, *server_host_کلید_blob = پوچ;
	u_char *signature = پوچ;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	صحیح r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_set(ssh, SSH2_پیام_KEX_ECDH_REPLY, &kex_protocol_error);

	/* hostkey */
	اگر ((r = sshpkt_getb_froms(ssh, &server_host_کلید_blob)) != 0)
		برو out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	اگر ((tmp = sshbuf_fromb(server_host_کلید_blob)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshkey_fromb_allowlist(tmp, &server_host_کلید,
	    kex->hostkey_alg, پوچ)) != 0)
		برو out;
	اگر ((r = kex_verify_host_کلید(ssh, server_host_کلید)) != 0)
		برو out;

	/* Q_S, server public key */
	/* signed H */
	اگر ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		برو out;

	/* compute shared secret */
	انتخاب (kex->kex_type) {
#ifdef WITH_OPENSSL
	حالت KEX_DH_GRP1_SHA1:
	حالت KEX_DH_GRP14_SHA1:
	حالت KEX_DH_GRP14_SHA256:
	حالت KEX_DH_GRP16_SHA512:
	حالت KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		بشکن;
	حالت KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		بشکن;
	حالت KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_dec(kex, server_blob,
		    &shared_secret);
		بشکن;
#endif /* WITH_OPENSSL */
	حالت KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		بشکن;
	حالت KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
		    &shared_secret);
		بشکن;
	حالت KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_dec(kex, server_blob,
		    &shared_secret);
		بشکن;
	پیشفرض:
		r = SSH_ERR_INVALID_ARGUMENT;
		بشکن;
	}
	اگر (r !=0 )
		برو out;

	/* calc and verify H */
	hashlen = اندازه(hash);
	اگر ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_کلید_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		برو out;

	اگر ((r = sshkey_verify(server_host_کلید, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, پوچ)) != 0)
		برو out;

	اگر ((r = kex_derive_کلیدها(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		برو out;

	/* save initial signature and hostkey */
	اگر ((kex->flags & KEX_INITIAL) != 0) {
		اگر (kex->initial_hostkey != پوچ || kex->initial_sig != پوچ) {
			r = SSH_ERR_INTERNAL_ERROR;
			برو out;
		}
		اگر ((kex->initial_sig = sshbuf_new()) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		اگر ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			برو out;
		kex->initial_hostkey = server_host_کلید;
		server_host_کلید = پوچ;
	}
	/* success */
out:
	explicit_bzero(hash, اندازه(hash));
	explicit_bzero(kex->c25519_client_کلید, اندازه(kex->c25519_client_کلید));
	explicit_bzero(kex->sntrup761_client_کلید,
	    اندازه(kex->sntrup761_client_کلید));
	explicit_bzero(kex->mlkem768_client_کلید,
	    اندازه(kex->mlkem768_client_کلید));
	sshbuf_free(server_host_کلید_blob);
	آزاد(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_کلید);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = پوچ;
	بازگشت r;
}

صحیح
kex_gen_server(ساختار ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_set(ssh, SSH2_پیام_KEX_ECDH_INIT, &درون_داد_kex_gen_init);
	بازگشت 0;
}

ایستا صحیح
درون_داد_kex_gen_init(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	ساختار kex *kex = ssh->kex;
	ساختار sshkey *server_host_private, *server_host_public;
	ساختار sshbuf *shared_secret = پوچ;
	ساختار sshbuf *server_pubkey = پوچ;
	ساختار sshbuf *client_pubkey = پوچ;
	ساختار sshbuf *server_host_کلید_blob = پوچ;
	u_char *signature = پوچ, hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	صحیح r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_set(ssh, SSH2_پیام_KEX_ECDH_INIT, &kex_protocol_error);

	اگر ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		برو out;

	اگر ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		برو out;

	/* compute shared secret */
	انتخاب (kex->kex_type) {
#ifdef WITH_OPENSSL
	حالت KEX_DH_GRP1_SHA1:
	حالت KEX_DH_GRP14_SHA1:
	حالت KEX_DH_GRP14_SHA256:
	حالت KEX_DH_GRP16_SHA512:
	حالت KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		بشکن;
	حالت KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		بشکن;
	حالت KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		بشکن;
#endif /* WITH_OPENSSL */
	حالت KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		بشکن;
	حالت KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		بشکن;
	حالت KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		بشکن;
	پیشفرض:
		r = SSH_ERR_INVALID_ARGUMENT;
		بشکن;
	}
	اگر (r !=0 )
		برو out;

	/* calc H */
	اگر ((server_host_کلید_blob = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshkey_putb(server_host_public, server_host_کلید_blob)) != 0)
		برو out;
	hashlen = اندازه(hash);
	اگر ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_کلید_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		برو out;

	/* sign H */
	اگر ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		برو out;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	اگر ((r = sshpkt_start(ssh, SSH2_پیام_KEX_ECDH_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_کلید_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		برو out;

	اگر ((r = kex_derive_کلیدها(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		برو out;
	/* retain copy of hostkey used at initial KEX */
	اگر (kex->initial_hostkey == پوچ &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		برو out;
	/* success */
out:
	explicit_bzero(hash, اندازه(hash));
	sshbuf_free(server_host_کلید_blob);
	آزاد(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	بازگشت r;
}
