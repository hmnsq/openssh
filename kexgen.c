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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_kex_gen_init(ਪੂਰਨ, uint32_t, ਬਣਤਰ ssh *);
ਸਥਿਰ ਪੂਰਨ ਨਿਵੇਸ਼_kex_gen_ਜਵਾਬ(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh);

ਸਥਿਰ ਪੂਰਨ
kex_gen_hash(
    ਪੂਰਨ hash_alg,
    ਅਚਲ ਬਣਤਰ sshbuf *client_ਸੰਸਕਰਣ,
    ਅਚਲ ਬਣਤਰ sshbuf *server_ਸੰਸਕਰਣ,
    ਅਚਲ ਬਣਤਰ sshbuf *client_kexinit,
    ਅਚਲ ਬਣਤਰ sshbuf *server_kexinit,
    ਅਚਲ ਬਣਤਰ sshbuf *server_host_ਕੁੰਜੀ_blob,
    ਅਚਲ ਬਣਤਰ sshbuf *client_pub,
    ਅਚਲ ਬਣਤਰ sshbuf *server_pub,
    ਅਚਲ ਬਣਤਰ sshbuf *shared_secret,
    u_char *hash, ਮਾਪ_t *hashlen)
{
	ਬਣਤਰ sshbuf *b;
	ਪੂਰਨ r;

	ਜੇ (*hashlen < ssh_digest_ਬਾਈਟਾਂ(hash_alg))
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put_stringb(b, client_ਸੰਸਕਰਣ)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_ਸੰਸਕਰਣ)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ਸੁਨੇਹਾ_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ਸੁਨੇਹਾ_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_ਕੁੰਜੀ_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		ਵਾਪਸ r;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEX
	sshbuf_dump(b, stderr);
#ਜੇ_ਅੰਤ
	ਜੇ (ssh_digest_ਬਫਰ(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_ਬਾਈਟਾਂ(hash_alg);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#ਜੇ_ਅੰਤ
	ਵਾਪਸ 0;
}

ਪੂਰਨ
kex_gen_client(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ kex *kex = ssh->kex;
	ਪੂਰਨ r;

	ਚੋਣ (kex->kex_type) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਹਾਲਤ KEX_DH_GRP1_SHA1:
	ਹਾਲਤ KEX_DH_GRP14_SHA1:
	ਹਾਲਤ KEX_DH_GRP14_SHA256:
	ਹਾਲਤ KEX_DH_GRP16_SHA512:
	ਹਾਲਤ KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		ਰੋਕੋ;
	ਹਾਲਤ KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		ਰੋਕੋ;
	ਹਾਲਤ KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_keypair(kex);
		ਰੋਕੋ;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਹਾਲਤ KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		ਰੋਕੋ;
	ਹਾਲਤ KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		ਰੋਕੋ;
	ਹਾਲਤ KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_keypair(kex);
		ਰੋਕੋ;
	ਮੂਲ:
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਰੋਕੋ;
	}
	ਜੇ (r != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ਵਾਪਸ r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_ECDH_ਜਵਾਬ, &ਨਿਵੇਸ਼_kex_gen_ਜਵਾਬ);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_kex_gen_ਜਵਾਬ(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ kex *kex = ssh->kex;
	ਬਣਤਰ sshkey *server_host_ਕੁੰਜੀ = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *shared_secret = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *server_blob = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *tmp = ਨਿਰਾ, *server_host_ਕੁੰਜੀ_blob = ਨਿਰਾ;
	u_char *signature = ਨਿਰਾ;
	u_char hash[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	ਮਾਪ_t slen, hashlen;
	ਪੂਰਨ r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_ECDH_ਜਵਾਬ, &kex_protocol_error);

	/* hostkey */
	ਜੇ ((r = sshpkt_getb_froms(ssh, &server_host_ਕੁੰਜੀ_blob)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	ਜੇ ((tmp = sshbuf_fromb(server_host_ਕੁੰਜੀ_blob)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshkey_fromb_allowlist(tmp, &server_host_ਕੁੰਜੀ,
	    kex->hostkey_alg, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = kex_verify_host_ਕੁੰਜੀ(ssh, server_host_ਕੁੰਜੀ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Q_S, server public key */
	/* signed H */
	ਜੇ ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* compute shared secret */
	ਚੋਣ (kex->kex_type) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਹਾਲਤ KEX_DH_GRP1_SHA1:
	ਹਾਲਤ KEX_DH_GRP14_SHA1:
	ਹਾਲਤ KEX_DH_GRP14_SHA256:
	ਹਾਲਤ KEX_DH_GRP16_SHA512:
	ਹਾਲਤ KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		ਰੋਕੋ;
	ਹਾਲਤ KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		ਰੋਕੋ;
	ਹਾਲਤ KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_dec(kex, server_blob,
		    &shared_secret);
		ਰੋਕੋ;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਹਾਲਤ KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		ਰੋਕੋ;
	ਹਾਲਤ KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
		    &shared_secret);
		ਰੋਕੋ;
	ਹਾਲਤ KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_dec(kex, server_blob,
		    &shared_secret);
		ਰੋਕੋ;
	ਮੂਲ:
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਰੋਕੋ;
	}
	ਜੇ (r !=0 )
		ਜਾਓ ਬਾਹਰਲਾ;

	/* calc and verify H */
	hashlen = ਆਕਾਰ(hash);
	ਜੇ ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_ਸੰਸਕਰਣ,
	    kex->server_ਸੰਸਕਰਣ,
	    kex->my,
	    kex->peer,
	    server_host_ਕੁੰਜੀ_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((r = sshkey_verify(server_host_ਕੁੰਜੀ, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((r = kex_derive_ਕੁੰਜੀਆਂ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* save initial signature and hostkey */
	ਜੇ ((kex->flags & KEX_INITIAL) != 0) {
		ਜੇ (kex->initial_hostkey != ਨਿਰਾ || kex->initial_sig != ਨਿਰਾ) {
			r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((kex->initial_sig = sshbuf_new()) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		kex->initial_hostkey = server_host_ਕੁੰਜੀ;
		server_host_ਕੁੰਜੀ = ਨਿਰਾ;
	}
	/* success */
ਬਾਹਰਲਾ:
	explicit_bzero(hash, ਆਕਾਰ(hash));
	explicit_bzero(kex->c25519_client_ਕੁੰਜੀ, ਆਕਾਰ(kex->c25519_client_ਕੁੰਜੀ));
	explicit_bzero(kex->sntrup761_client_ਕੁੰਜੀ,
	    ਆਕਾਰ(kex->sntrup761_client_ਕੁੰਜੀ));
	explicit_bzero(kex->mlkem768_client_ਕੁੰਜੀ,
	    ਆਕਾਰ(kex->mlkem768_client_ਕੁੰਜੀ));
	sshbuf_free(server_host_ਕੁੰਜੀ_blob);
	ਮੁਕਤ(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_ਕੁੰਜੀ);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = ਨਿਰਾ;
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_gen_server(ਬਣਤਰ ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_ECDH_INIT, &ਨਿਵੇਸ਼_kex_gen_init);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_kex_gen_init(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ kex *kex = ssh->kex;
	ਬਣਤਰ sshkey *server_host_ਨਿੱਜੀ, *server_host_ਜਨਤਕ;
	ਬਣਤਰ sshbuf *shared_secret = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *server_pubkey = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *client_pubkey = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *server_host_ਕੁੰਜੀ_blob = ਨਿਰਾ;
	u_char *signature = ਨਿਰਾ, hash[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	ਮਾਪ_t slen, hashlen;
	ਪੂਰਨ r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_ECDH_INIT, &kex_protocol_error);

	ਜੇ ((r = kex_ਲੱਦੋ_hostkey(ssh, &server_host_ਨਿੱਜੀ,
	    &server_host_ਜਨਤਕ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* compute shared secret */
	ਚੋਣ (kex->kex_type) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਹਾਲਤ KEX_DH_GRP1_SHA1:
	ਹਾਲਤ KEX_DH_GRP14_SHA1:
	ਹਾਲਤ KEX_DH_GRP14_SHA256:
	ਹਾਲਤ KEX_DH_GRP16_SHA512:
	ਹਾਲਤ KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		ਰੋਕੋ;
	ਹਾਲਤ KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		ਰੋਕੋ;
	ਹਾਲਤ KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		ਰੋਕੋ;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਹਾਲਤ KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		ਰੋਕੋ;
	ਹਾਲਤ KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		ਰੋਕੋ;
	ਹਾਲਤ KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		ਰੋਕੋ;
	ਮੂਲ:
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਰੋਕੋ;
	}
	ਜੇ (r !=0 )
		ਜਾਓ ਬਾਹਰਲਾ;

	/* calc H */
	ਜੇ ((server_host_ਕੁੰਜੀ_blob = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshkey_putb(server_host_ਜਨਤਕ, server_host_ਕੁੰਜੀ_blob)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	hashlen = ਆਕਾਰ(hash);
	ਜੇ ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_ਸੰਸਕਰਣ,
	    kex->server_ਸੰਸਕਰਣ,
	    kex->peer,
	    kex->my,
	    server_host_ਕੁੰਜੀ_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* sign H */
	ਜੇ ((r = kex->sign(ssh, server_host_ਨਿੱਜੀ, server_host_ਜਨਤਕ,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, SSH2_ਸੁਨੇਹਾ_KEX_ECDH_ਜਵਾਬ)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_ਕੁੰਜੀ_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((r = kex_derive_ਕੁੰਜੀਆਂ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* retain copy of hostkey used at initial KEX */
	ਜੇ (kex->initial_hostkey == ਨਿਰਾ &&
	    (r = sshkey_from_ਨਿੱਜੀ(server_host_ਜਨਤਕ,
	    &kex->initial_hostkey)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
ਬਾਹਰਲਾ:
	explicit_bzero(hash, ਆਕਾਰ(hash));
	sshbuf_free(server_host_ਕੁੰਜੀ_blob);
	ਮੁਕਤ(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	ਵਾਪਸ r;
}
