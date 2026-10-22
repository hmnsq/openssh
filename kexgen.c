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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <signal.h>

#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "ssherr.h"

நிலையான முழு உள்ளீடு_kex_gen_init(முழு, uint32_t, கட்டமைப்பு ssh *);
நிலையான முழு உள்ளீடு_kex_gen_reply(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh);

நிலையான முழு
kex_gen_hash(
    முழு hash_alg,
    மாறிலி கட்டமைப்பு sshbuf *client_version,
    மாறிலி கட்டமைப்பு sshbuf *server_version,
    மாறிலி கட்டமைப்பு sshbuf *client_kexinit,
    மாறிலி கட்டமைப்பு sshbuf *server_kexinit,
    மாறிலி கட்டமைப்பு sshbuf *server_host_சாவி_blob,
    மாறிலி கட்டமைப்பு sshbuf *client_pub,
    மாறிலி கட்டமைப்பு sshbuf *server_pub,
    மாறிலி கட்டமைப்பு sshbuf *shared_secret,
    u_char *hash, size_t *hashlen)
{
	கட்டமைப்பு sshbuf *b;
	முழு r;

	எனில் (*hashlen < ssh_digest_bytes(hash_alg))
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((b = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_put_stringb(b, client_version)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_செய்தி_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_செய்தி_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_சாவி_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		திரும்பு r;
	}
#ifdef DEBUG_KEX
	sshbuf_dump(b, stderr);
#endif
	எனில் (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#endif
	திரும்பு 0;
}

முழு
kex_gen_client(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு kex *kex = ssh->kex;
	முழு r;

	தேர்வு (kex->kex_type) {
#ifdef WITH_OPENSSL
	நிலை KEX_DH_GRP1_SHA1:
	நிலை KEX_DH_GRP14_SHA1:
	நிலை KEX_DH_GRP14_SHA256:
	நிலை KEX_DH_GRP16_SHA512:
	நிலை KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		நிறுத்து;
	நிலை KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		நிறுத்து;
	நிலை KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_keypair(kex);
		நிறுத்து;
#endif /* WITH_OPENSSL */
	நிலை KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		நிறுத்து;
	நிலை KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		நிறுத்து;
	நிலை KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_keypair(kex);
		நிறுத்து;
	இயல்பு:
		r = SSH_ERR_INVALID_ARGUMENT;
		நிறுத்து;
	}
	எனில் (r != 0)
		திரும்பு r;
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		திரும்பு r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEX_ECDH_REPLY, &உள்ளீடு_kex_gen_reply);
	திரும்பு 0;
}

நிலையான முழு
உள்ளீடு_kex_gen_reply(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு kex *kex = ssh->kex;
	கட்டமைப்பு sshkey *server_host_சாவி = வெற்று;
	கட்டமைப்பு sshbuf *shared_secret = வெற்று;
	கட்டமைப்பு sshbuf *server_blob = வெற்று;
	கட்டமைப்பு sshbuf *tmp = வெற்று, *server_host_சாவி_blob = வெற்று;
	u_char *signature = வெற்று;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	முழு r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEX_ECDH_REPLY, &kex_protocol_error);

	/* hostkey */
	எனில் ((r = sshpkt_getb_froms(ssh, &server_host_சாவி_blob)) != 0)
		செல் out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	எனில் ((tmp = sshbuf_fromb(server_host_சாவி_blob)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshkey_fromb_allowlist(tmp, &server_host_சாவி,
	    kex->hostkey_alg, வெற்று)) != 0)
		செல் out;
	எனில் ((r = kex_verify_host_சாவி(ssh, server_host_சாவி)) != 0)
		செல் out;

	/* Q_S, server public key */
	/* signed H */
	எனில் ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		செல் out;

	/* compute shared secret */
	தேர்வு (kex->kex_type) {
#ifdef WITH_OPENSSL
	நிலை KEX_DH_GRP1_SHA1:
	நிலை KEX_DH_GRP14_SHA1:
	நிலை KEX_DH_GRP14_SHA256:
	நிலை KEX_DH_GRP16_SHA512:
	நிலை KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		நிறுத்து;
	நிலை KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		நிறுத்து;
	நிலை KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_dec(kex, server_blob,
		    &shared_secret);
		நிறுத்து;
#endif /* WITH_OPENSSL */
	நிலை KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		நிறுத்து;
	நிலை KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
		    &shared_secret);
		நிறுத்து;
	நிலை KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_dec(kex, server_blob,
		    &shared_secret);
		நிறுத்து;
	இயல்பு:
		r = SSH_ERR_INVALID_ARGUMENT;
		நிறுத்து;
	}
	எனில் (r !=0 )
		செல் out;

	/* calc and verify H */
	hashlen = அளவு(hash);
	எனில் ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_சாவி_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		செல் out;

	எனில் ((r = sshkey_verify(server_host_சாவி, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, வெற்று)) != 0)
		செல் out;

	எனில் ((r = kex_derive_சாவிகள்(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		செல் out;

	/* save initial signature and hostkey */
	எனில் ((kex->flags & KEX_INITIAL) != 0) {
		எனில் (kex->initial_hostkey != வெற்று || kex->initial_sig != வெற்று) {
			r = SSH_ERR_INTERNAL_ERROR;
			செல் out;
		}
		எனில் ((kex->initial_sig = sshbuf_new()) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		எனில் ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			செல் out;
		kex->initial_hostkey = server_host_சாவி;
		server_host_சாவி = வெற்று;
	}
	/* success */
out:
	explicit_bzero(hash, அளவு(hash));
	explicit_bzero(kex->c25519_client_சாவி, அளவு(kex->c25519_client_சாவி));
	explicit_bzero(kex->sntrup761_client_சாவி,
	    அளவு(kex->sntrup761_client_சாவி));
	explicit_bzero(kex->mlkem768_client_சாவி,
	    அளவு(kex->mlkem768_client_சாவி));
	sshbuf_free(server_host_சாவி_blob);
	விடுவி(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_சாவி);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = வெற்று;
	திரும்பு r;
}

முழு
kex_gen_server(கட்டமைப்பு ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEX_ECDH_INIT, &உள்ளீடு_kex_gen_init);
	திரும்பு 0;
}

நிலையான முழு
உள்ளீடு_kex_gen_init(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு kex *kex = ssh->kex;
	கட்டமைப்பு sshkey *server_host_private, *server_host_public;
	கட்டமைப்பு sshbuf *shared_secret = வெற்று;
	கட்டமைப்பு sshbuf *server_pubkey = வெற்று;
	கட்டமைப்பு sshbuf *client_pubkey = வெற்று;
	கட்டமைப்பு sshbuf *server_host_சாவி_blob = வெற்று;
	u_char *signature = வெற்று, hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	முழு r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_set(ssh, SSH2_செய்தி_KEX_ECDH_INIT, &kex_protocol_error);

	எனில் ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		செல் out;

	எனில் ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		செல் out;

	/* compute shared secret */
	தேர்வு (kex->kex_type) {
#ifdef WITH_OPENSSL
	நிலை KEX_DH_GRP1_SHA1:
	நிலை KEX_DH_GRP14_SHA1:
	நிலை KEX_DH_GRP14_SHA256:
	நிலை KEX_DH_GRP16_SHA512:
	நிலை KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		நிறுத்து;
	நிலை KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		நிறுத்து;
	நிலை KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		நிறுத்து;
#endif /* WITH_OPENSSL */
	நிலை KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		நிறுத்து;
	நிலை KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		நிறுத்து;
	நிலை KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		நிறுத்து;
	இயல்பு:
		r = SSH_ERR_INVALID_ARGUMENT;
		நிறுத்து;
	}
	எனில் (r !=0 )
		செல் out;

	/* calc H */
	எனில் ((server_host_சாவி_blob = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshkey_putb(server_host_public, server_host_சாவி_blob)) != 0)
		செல் out;
	hashlen = அளவு(hash);
	எனில் ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_சாவி_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		செல் out;

	/* sign H */
	எனில் ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		செல் out;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	எனில் ((r = sshpkt_start(ssh, SSH2_செய்தி_KEX_ECDH_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_சாவி_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		செல் out;

	எனில் ((r = kex_derive_சாவிகள்(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		செல் out;
	/* retain copy of hostkey used at initial KEX */
	எனில் (kex->initial_hostkey == வெற்று &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		செல் out;
	/* success */
out:
	explicit_bzero(hash, அளவு(hash));
	sshbuf_free(server_host_சாவி_blob);
	விடுவி(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	திரும்பு r;
}
