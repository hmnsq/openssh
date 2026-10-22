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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <signal.h>

#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "ssherr.h"

સ્થિર પૂર્ણાંક આગત_kex_gen_init(પૂર્ણાંક, uint32_t, સંરચના ssh *);
સ્થિર પૂર્ણાંક આગત_kex_gen_reply(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh);

સ્થિર પૂર્ણાંક
kex_gen_hash(
    પૂર્ણાંક hash_alg,
    અચલ સંરચના sshbuf *client_version,
    અચલ સંરચના sshbuf *server_version,
    અચલ સંરચના sshbuf *client_kexinit,
    અચલ સંરચના sshbuf *server_kexinit,
    અચલ સંરચના sshbuf *server_host_ચાવી_blob,
    અચલ સંરચના sshbuf *client_pub,
    અચલ સંરચના sshbuf *server_pub,
    અચલ સંરચના sshbuf *shared_secret,
    u_char *hash, size_t *hashlen)
{
	સંરચના sshbuf *b;
	પૂર્ણાંક r;

	જો (*hashlen < ssh_digest_bytes(hash_alg))
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((b = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put_stringb(b, client_version)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_સંદેશ_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_સંદેશ_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_ચાવી_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		પાછા r;
	}
#ifdef DEBUG_KEX
	sshbuf_dump(b, stderr);
#endif
	જો (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		પાછા SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#endif
	પાછા 0;
}

પૂર્ણાંક
kex_gen_client(સંરચના ssh *ssh)
{
	સંરચના kex *kex = ssh->kex;
	પૂર્ણાંક r;

	પસંદગી (kex->kex_type) {
#ifdef WITH_OPENSSL
	સ્થિતિ KEX_DH_GRP1_SHA1:
	સ્થિતિ KEX_DH_GRP14_SHA1:
	સ્થિતિ KEX_DH_GRP14_SHA256:
	સ્થિતિ KEX_DH_GRP16_SHA512:
	સ્થિતિ KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		તોડો;
	સ્થિતિ KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		તોડો;
	સ્થિતિ KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_keypair(kex);
		તોડો;
#endif /* WITH_OPENSSL */
	સ્થિતિ KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		તોડો;
	સ્થિતિ KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		તોડો;
	સ્થિતિ KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_keypair(kex);
		તોડો;
	મૂળભૂત:
		r = SSH_ERR_INVALID_ARGUMENT;
		તોડો;
	}
	જો (r != 0)
		પાછા r;
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		પાછા r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEX_ECDH_REPLY, &આગત_kex_gen_reply);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
આગત_kex_gen_reply(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	સંરચના kex *kex = ssh->kex;
	સંરચના sshkey *server_host_ચાવી = ખાલી;
	સંરચના sshbuf *shared_secret = ખાલી;
	સંરચના sshbuf *server_blob = ખાલી;
	સંરચના sshbuf *tmp = ખાલી, *server_host_ચાવી_blob = ખાલી;
	u_char *signature = ખાલી;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	પૂર્ણાંક r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEX_ECDH_REPLY, &kex_protocol_error);

	/* hostkey */
	જો ((r = sshpkt_getb_froms(ssh, &server_host_ચાવી_blob)) != 0)
		જાઓ out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	જો ((tmp = sshbuf_fromb(server_host_ચાવી_blob)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshkey_fromb_allowlist(tmp, &server_host_ચાવી,
	    kex->hostkey_alg, ખાલી)) != 0)
		જાઓ out;
	જો ((r = kex_verify_host_ચાવી(ssh, server_host_ચાવી)) != 0)
		જાઓ out;

	/* Q_S, server public key */
	/* signed H */
	જો ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		જાઓ out;

	/* compute shared secret */
	પસંદગી (kex->kex_type) {
#ifdef WITH_OPENSSL
	સ્થિતિ KEX_DH_GRP1_SHA1:
	સ્થિતિ KEX_DH_GRP14_SHA1:
	સ્થિતિ KEX_DH_GRP14_SHA256:
	સ્થિતિ KEX_DH_GRP16_SHA512:
	સ્થિતિ KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		તોડો;
	સ્થિતિ KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		તોડો;
	સ્થિતિ KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_dec(kex, server_blob,
		    &shared_secret);
		તોડો;
#endif /* WITH_OPENSSL */
	સ્થિતિ KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		તોડો;
	સ્થિતિ KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
		    &shared_secret);
		તોડો;
	સ્થિતિ KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_dec(kex, server_blob,
		    &shared_secret);
		તોડો;
	મૂળભૂત:
		r = SSH_ERR_INVALID_ARGUMENT;
		તોડો;
	}
	જો (r !=0 )
		જાઓ out;

	/* calc and verify H */
	hashlen = કદ(hash);
	જો ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_ચાવી_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		જાઓ out;

	જો ((r = sshkey_verify(server_host_ચાવી, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, ખાલી)) != 0)
		જાઓ out;

	જો ((r = kex_derive_ચાવીઓ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		જાઓ out;

	/* save initial signature and hostkey */
	જો ((kex->flags & KEX_INITIAL) != 0) {
		જો (kex->initial_hostkey != ખાલી || kex->initial_sig != ખાલી) {
			r = SSH_ERR_INTERNAL_ERROR;
			જાઓ out;
		}
		જો ((kex->initial_sig = sshbuf_new()) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		જો ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			જાઓ out;
		kex->initial_hostkey = server_host_ચાવી;
		server_host_ચાવી = ખાલી;
	}
	/* success */
out:
	explicit_bzero(hash, કદ(hash));
	explicit_bzero(kex->c25519_client_ચાવી, કદ(kex->c25519_client_ચાવી));
	explicit_bzero(kex->sntrup761_client_ચાવી,
	    કદ(kex->sntrup761_client_ચાવી));
	explicit_bzero(kex->mlkem768_client_ચાવી,
	    કદ(kex->mlkem768_client_ચાવી));
	sshbuf_free(server_host_ચાવી_blob);
	મુક્ત(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_ચાવી);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = ખાલી;
	પાછા r;
}

પૂર્ણાંક
kex_gen_server(સંરચના ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEX_ECDH_INIT, &આગત_kex_gen_init);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
આગત_kex_gen_init(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	સંરચના kex *kex = ssh->kex;
	સંરચના sshkey *server_host_private, *server_host_public;
	સંરચના sshbuf *shared_secret = ખાલી;
	સંરચના sshbuf *server_pubkey = ખાલી;
	સંરચના sshbuf *client_pubkey = ખાલી;
	સંરચના sshbuf *server_host_ચાવી_blob = ખાલી;
	u_char *signature = ખાલી, hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	પૂર્ણાંક r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEX_ECDH_INIT, &kex_protocol_error);

	જો ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		જાઓ out;

	જો ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		જાઓ out;

	/* compute shared secret */
	પસંદગી (kex->kex_type) {
#ifdef WITH_OPENSSL
	સ્થિતિ KEX_DH_GRP1_SHA1:
	સ્થિતિ KEX_DH_GRP14_SHA1:
	સ્થિતિ KEX_DH_GRP14_SHA256:
	સ્થિતિ KEX_DH_GRP16_SHA512:
	સ્થિતિ KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		તોડો;
	સ્થિતિ KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		તોડો;
	સ્થિતિ KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		તોડો;
#endif /* WITH_OPENSSL */
	સ્થિતિ KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		તોડો;
	સ્થિતિ KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		તોડો;
	સ્થિતિ KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		તોડો;
	મૂળભૂત:
		r = SSH_ERR_INVALID_ARGUMENT;
		તોડો;
	}
	જો (r !=0 )
		જાઓ out;

	/* calc H */
	જો ((server_host_ચાવી_blob = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshkey_putb(server_host_public, server_host_ચાવી_blob)) != 0)
		જાઓ out;
	hashlen = કદ(hash);
	જો ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_ચાવી_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		જાઓ out;

	/* sign H */
	જો ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		જાઓ out;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_KEX_ECDH_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_ચાવી_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		જાઓ out;

	જો ((r = kex_derive_ચાવીઓ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		જાઓ out;
	/* retain copy of hostkey used at initial KEX */
	જો (kex->initial_hostkey == ખાલી &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		જાઓ out;
	/* success */
out:
	explicit_bzero(hash, કદ(hash));
	sshbuf_free(server_host_ચાવી_blob);
	મુક્ત(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	પાછા r;
}
