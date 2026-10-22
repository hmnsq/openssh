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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <signal.h>

#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "ssherr.h"

സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_kex_gen_init(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_kex_gen_reply(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh);

സ്ഥിതം പൂർണ്ണസംഖ്യ
kex_gen_hash(
    പൂർണ്ണസംഖ്യ hash_alg,
    സ്ഥിരം ഘടന sshbuf *client_version,
    സ്ഥിരം ഘടന sshbuf *server_version,
    സ്ഥിരം ഘടന sshbuf *client_kexinit,
    സ്ഥിരം ഘടന sshbuf *server_kexinit,
    സ്ഥിരം ഘടന sshbuf *server_host_താക്കോൽ_blob,
    സ്ഥിരം ഘടന sshbuf *client_pub,
    സ്ഥിരം ഘടന sshbuf *server_pub,
    സ്ഥിരം ഘടന sshbuf *shared_secret,
    u_char *hash, size_t *hashlen)
{
	ഘടന sshbuf *b;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (*hashlen < ssh_digest_bytes(hash_alg))
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_put_stringb(b, client_version)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_സന്ദേശം_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_സന്ദേശം_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_താക്കോൽ_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		തിരികെ r;
	}
#ifdef DEBUG_KEX
	sshbuf_dump(b, stderr);
#endif
	എങ്കിൽ (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#endif
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
kex_gen_client(ഘടന ssh *ssh)
{
	ഘടന kex *kex = ssh->kex;
	പൂർണ്ണസംഖ്യ r;

	തിരഞ്ഞെടുപ്പ് (kex->kex_type) {
#ifdef WITH_OPENSSL
	അവസ്ഥ KEX_DH_GRP1_SHA1:
	അവസ്ഥ KEX_DH_GRP14_SHA1:
	അവസ്ഥ KEX_DH_GRP14_SHA256:
	അവസ്ഥ KEX_DH_GRP16_SHA512:
	അവസ്ഥ KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		നിർത്തുക;
	അവസ്ഥ KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		നിർത്തുക;
	അവസ്ഥ KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_keypair(kex);
		നിർത്തുക;
#endif /* WITH_OPENSSL */
	അവസ്ഥ KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		നിർത്തുക;
	അവസ്ഥ KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		നിർത്തുക;
	അവസ്ഥ KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_keypair(kex);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		r = SSH_ERR_INVALID_ARGUMENT;
		നിർത്തുക;
	}
	എങ്കിൽ (r != 0)
		തിരികെ r;
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		തിരികെ r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEX_ECDH_REPLY, &നിവേശം_kex_gen_reply);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_kex_gen_reply(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	ഘടന kex *kex = ssh->kex;
	ഘടന sshkey *server_host_താക്കോൽ = ശൂന്യ;
	ഘടന sshbuf *shared_secret = ശൂന്യ;
	ഘടന sshbuf *server_blob = ശൂന്യ;
	ഘടന sshbuf *tmp = ശൂന്യ, *server_host_താക്കോൽ_blob = ശൂന്യ;
	u_char *signature = ശൂന്യ;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	പൂർണ്ണസംഖ്യ r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEX_ECDH_REPLY, &kex_protocol_error);

	/* hostkey */
	എങ്കിൽ ((r = sshpkt_getb_froms(ssh, &server_host_താക്കോൽ_blob)) != 0)
		പോകുക out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	എങ്കിൽ ((tmp = sshbuf_fromb(server_host_താക്കോൽ_blob)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshkey_fromb_allowlist(tmp, &server_host_താക്കോൽ,
	    kex->hostkey_alg, ശൂന്യ)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = kex_verify_host_താക്കോൽ(ssh, server_host_താക്കോൽ)) != 0)
		പോകുക out;

	/* Q_S, server public key */
	/* signed H */
	എങ്കിൽ ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		പോകുക out;

	/* compute shared secret */
	തിരഞ്ഞെടുപ്പ് (kex->kex_type) {
#ifdef WITH_OPENSSL
	അവസ്ഥ KEX_DH_GRP1_SHA1:
	അവസ്ഥ KEX_DH_GRP14_SHA1:
	അവസ്ഥ KEX_DH_GRP14_SHA256:
	അവസ്ഥ KEX_DH_GRP16_SHA512:
	അവസ്ഥ KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		നിർത്തുക;
	അവസ്ഥ KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		നിർത്തുക;
	അവസ്ഥ KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_dec(kex, server_blob,
		    &shared_secret);
		നിർത്തുക;
#endif /* WITH_OPENSSL */
	അവസ്ഥ KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		നിർത്തുക;
	അവസ്ഥ KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
		    &shared_secret);
		നിർത്തുക;
	അവസ്ഥ KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_dec(kex, server_blob,
		    &shared_secret);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		r = SSH_ERR_INVALID_ARGUMENT;
		നിർത്തുക;
	}
	എങ്കിൽ (r !=0 )
		പോകുക out;

	/* calc and verify H */
	hashlen = വലുപ്പം(hash);
	എങ്കിൽ ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_താക്കോൽ_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		പോകുക out;

	എങ്കിൽ ((r = sshkey_verify(server_host_താക്കോൽ, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, ശൂന്യ)) != 0)
		പോകുക out;

	എങ്കിൽ ((r = kex_derive_താക്കോലുകൾ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		പോകുക out;

	/* save initial signature and hostkey */
	എങ്കിൽ ((kex->flags & KEX_INITIAL) != 0) {
		എങ്കിൽ (kex->initial_hostkey != ശൂന്യ || kex->initial_sig != ശൂന്യ) {
			r = SSH_ERR_INTERNAL_ERROR;
			പോകുക out;
		}
		എങ്കിൽ ((kex->initial_sig = sshbuf_new()) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			പോകുക out;
		kex->initial_hostkey = server_host_താക്കോൽ;
		server_host_താക്കോൽ = ശൂന്യ;
	}
	/* success */
out:
	explicit_bzero(hash, വലുപ്പം(hash));
	explicit_bzero(kex->c25519_client_താക്കോൽ, വലുപ്പം(kex->c25519_client_താക്കോൽ));
	explicit_bzero(kex->sntrup761_client_താക്കോൽ,
	    വലുപ്പം(kex->sntrup761_client_താക്കോൽ));
	explicit_bzero(kex->mlkem768_client_താക്കോൽ,
	    വലുപ്പം(kex->mlkem768_client_താക്കോൽ));
	sshbuf_free(server_host_താക്കോൽ_blob);
	സ്വതന്ത്രം(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_താക്കോൽ);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = ശൂന്യ;
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
kex_gen_server(ഘടന ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEX_ECDH_INIT, &നിവേശം_kex_gen_init);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_kex_gen_init(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	ഘടന kex *kex = ssh->kex;
	ഘടന sshkey *server_host_private, *server_host_public;
	ഘടന sshbuf *shared_secret = ശൂന്യ;
	ഘടന sshbuf *server_pubkey = ശൂന്യ;
	ഘടന sshbuf *client_pubkey = ശൂന്യ;
	ഘടന sshbuf *server_host_താക്കോൽ_blob = ശൂന്യ;
	u_char *signature = ശൂന്യ, hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	പൂർണ്ണസംഖ്യ r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_KEX_ECDH_INIT, &kex_protocol_error);

	എങ്കിൽ ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		പോകുക out;

	എങ്കിൽ ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		പോകുക out;

	/* compute shared secret */
	തിരഞ്ഞെടുപ്പ് (kex->kex_type) {
#ifdef WITH_OPENSSL
	അവസ്ഥ KEX_DH_GRP1_SHA1:
	അവസ്ഥ KEX_DH_GRP14_SHA1:
	അവസ്ഥ KEX_DH_GRP14_SHA256:
	അവസ്ഥ KEX_DH_GRP16_SHA512:
	അവസ്ഥ KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		നിർത്തുക;
	അവസ്ഥ KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		നിർത്തുക;
	അവസ്ഥ KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		നിർത്തുക;
#endif /* WITH_OPENSSL */
	അവസ്ഥ KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		നിർത്തുക;
	അവസ്ഥ KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		നിർത്തുക;
	അവസ്ഥ KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		r = SSH_ERR_INVALID_ARGUMENT;
		നിർത്തുക;
	}
	എങ്കിൽ (r !=0 )
		പോകുക out;

	/* calc H */
	എങ്കിൽ ((server_host_താക്കോൽ_blob = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshkey_putb(server_host_public, server_host_താക്കോൽ_blob)) != 0)
		പോകുക out;
	hashlen = വലുപ്പം(hash);
	എങ്കിൽ ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_താക്കോൽ_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		പോകുക out;

	/* sign H */
	എങ്കിൽ ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		പോകുക out;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_KEX_ECDH_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_താക്കോൽ_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
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
	sshbuf_free(server_host_താക്കോൽ_blob);
	സ്വതന്ത്രം(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	തിരികെ r;
}
