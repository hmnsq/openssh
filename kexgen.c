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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <signal.h>

#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_kex_gen_init(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_kex_gen_reply(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh);

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
kex_gen_hash(
    ಪೂರ್ಣಾಙ್ಕ hash_alg,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *client_version,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *server_version,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *client_kexinit,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *server_kexinit,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *server_host_ಕೀಲಿ_blob,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *client_pub,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *server_pub,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *shared_secret,
    u_char *hash, size_t *hashlen)
{
	ಸಂರಚನಾ sshbuf *b;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (*hashlen < ssh_digest_bytes(hash_alg))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_put_stringb(b, client_version)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ಸಂದೇಶ_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ಸಂದೇಶ_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_ಕೀಲಿ_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		ಪ್ರತ್ಯಾಗಮ r;
	}
#ifdef DEBUG_KEX
	sshbuf_dump(b, stderr);
#endif
	ಯದಿ (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#endif
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
kex_gen_client(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;
	ಪೂರ್ಣಾಙ್ಕ r;

	ವಿಕಲ್ಪ (kex->kex_type) {
#ifdef WITH_OPENSSL
	ಪಕ್ಷ KEX_DH_GRP1_SHA1:
	ಪಕ್ಷ KEX_DH_GRP14_SHA1:
	ಪಕ್ಷ KEX_DH_GRP14_SHA256:
	ಪಕ್ಷ KEX_DH_GRP16_SHA512:
	ಪಕ್ಷ KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		ಭಙ್ಗ;
	ಪಕ್ಷ KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		ಭಙ್ಗ;
	ಪಕ್ಷ KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_keypair(kex);
		ಭಙ್ಗ;
#endif /* WITH_OPENSSL */
	ಪಕ್ಷ KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		ಭಙ್ಗ;
	ಪಕ್ಷ KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		ಭಙ್ಗ;
	ಪಕ್ಷ KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_keypair(kex);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		r = SSH_ERR_INVALID_ARGUMENT;
		ಭಙ್ಗ;
	}
	ಯದಿ (r != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEX_ECDH_REPLY, &ಒಳಹರಿವು_kex_gen_reply);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_kex_gen_reply(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;
	ಸಂರಚನಾ sshkey *server_host_ಕೀಲಿ = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *shared_secret = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *server_blob = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *tmp = ರಿಕ್ತ, *server_host_ಕೀಲಿ_blob = ರಿಕ್ತ;
	u_char *signature = ರಿಕ್ತ;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEX_ECDH_REPLY, &kex_protocol_error);

	/* hostkey */
	ಯದಿ ((r = sshpkt_getb_froms(ssh, &server_host_ಕೀಲಿ_blob)) != 0)
		ಗಚ್ಛ out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	ಯದಿ ((tmp = sshbuf_fromb(server_host_ಕೀಲಿ_blob)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshkey_fromb_allowlist(tmp, &server_host_ಕೀಲಿ,
	    kex->hostkey_alg, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = kex_verify_host_ಕೀಲಿ(ssh, server_host_ಕೀಲಿ)) != 0)
		ಗಚ್ಛ out;

	/* Q_S, server public key */
	/* signed H */
	ಯದಿ ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ಗಚ್ಛ out;

	/* compute shared secret */
	ವಿಕಲ್ಪ (kex->kex_type) {
#ifdef WITH_OPENSSL
	ಪಕ್ಷ KEX_DH_GRP1_SHA1:
	ಪಕ್ಷ KEX_DH_GRP14_SHA1:
	ಪಕ್ಷ KEX_DH_GRP14_SHA256:
	ಪಕ್ಷ KEX_DH_GRP16_SHA512:
	ಪಕ್ಷ KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		ಭಙ್ಗ;
	ಪಕ್ಷ KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		ಭಙ್ಗ;
	ಪಕ್ಷ KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_dec(kex, server_blob,
		    &shared_secret);
		ಭಙ್ಗ;
#endif /* WITH_OPENSSL */
	ಪಕ್ಷ KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		ಭಙ್ಗ;
	ಪಕ್ಷ KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
		    &shared_secret);
		ಭಙ್ಗ;
	ಪಕ್ಷ KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_dec(kex, server_blob,
		    &shared_secret);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		r = SSH_ERR_INVALID_ARGUMENT;
		ಭಙ್ಗ;
	}
	ಯದಿ (r !=0 )
		ಗಚ್ಛ out;

	/* calc and verify H */
	hashlen = ಪರಿಮಾಣ(hash);
	ಯದಿ ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_ಕೀಲಿ_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ ((r = sshkey_verify(server_host_ಕೀಲಿ, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ ((r = kex_derive_ಕೀಲಿಗಳು(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ಗಚ್ಛ out;

	/* save initial signature and hostkey */
	ಯದಿ ((kex->flags & KEX_INITIAL) != 0) {
		ಯದಿ (kex->initial_hostkey != ರಿಕ್ತ || kex->initial_sig != ರಿಕ್ತ) {
			r = SSH_ERR_INTERNAL_ERROR;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((kex->initial_sig = sshbuf_new()) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			ಗಚ್ಛ out;
		kex->initial_hostkey = server_host_ಕೀಲಿ;
		server_host_ಕೀಲಿ = ರಿಕ್ತ;
	}
	/* success */
out:
	explicit_bzero(hash, ಪರಿಮಾಣ(hash));
	explicit_bzero(kex->c25519_client_ಕೀಲಿ, ಪರಿಮಾಣ(kex->c25519_client_ಕೀಲಿ));
	explicit_bzero(kex->sntrup761_client_ಕೀಲಿ,
	    ಪರಿಮಾಣ(kex->sntrup761_client_ಕೀಲಿ));
	explicit_bzero(kex->mlkem768_client_ಕೀಲಿ,
	    ಪರಿಮಾಣ(kex->mlkem768_client_ಕೀಲಿ));
	sshbuf_free(server_host_ಕೀಲಿ_blob);
	ಮುಕ್ತ(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_ಕೀಲಿ);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
kex_gen_server(ಸಂರಚನಾ ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEX_ECDH_INIT, &ಒಳಹರಿವು_kex_gen_init);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_kex_gen_init(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;
	ಸಂರಚನಾ sshkey *server_host_private, *server_host_public;
	ಸಂರಚನಾ sshbuf *shared_secret = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *server_pubkey = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *client_pubkey = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *server_host_ಕೀಲಿ_blob = ರಿಕ್ತ;
	u_char *signature = ರಿಕ್ತ, hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_KEX_ECDH_INIT, &kex_protocol_error);

	ಯದಿ ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ಗಚ್ಛ out;

	/* compute shared secret */
	ವಿಕಲ್ಪ (kex->kex_type) {
#ifdef WITH_OPENSSL
	ಪಕ್ಷ KEX_DH_GRP1_SHA1:
	ಪಕ್ಷ KEX_DH_GRP14_SHA1:
	ಪಕ್ಷ KEX_DH_GRP14_SHA256:
	ಪಕ್ಷ KEX_DH_GRP16_SHA512:
	ಪಕ್ಷ KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		ಭಙ್ಗ;
	ಪಕ್ಷ KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		ಭಙ್ಗ;
	ಪಕ್ಷ KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		ಭಙ್ಗ;
#endif /* WITH_OPENSSL */
	ಪಕ್ಷ KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		ಭಙ್ಗ;
	ಪಕ್ಷ KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		ಭಙ್ಗ;
	ಪಕ್ಷ KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		r = SSH_ERR_INVALID_ARGUMENT;
		ಭಙ್ಗ;
	}
	ಯದಿ (r !=0 )
		ಗಚ್ಛ out;

	/* calc H */
	ಯದಿ ((server_host_ಕೀಲಿ_blob = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshkey_putb(server_host_public, server_host_ಕೀಲಿ_blob)) != 0)
		ಗಚ್ಛ out;
	hashlen = ಪರಿಮಾಣ(hash);
	ಯದಿ ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_ಕೀಲಿ_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		ಗಚ್ಛ out;

	/* sign H */
	ಯದಿ ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		ಗಚ್ಛ out;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_KEX_ECDH_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_ಕೀಲಿ_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಗಚ್ಛ out;

	ಯದಿ ((r = kex_derive_ಕೀಲಿಗಳು(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ಗಚ್ಛ out;
	/* retain copy of hostkey used at initial KEX */
	ಯದಿ (kex->initial_hostkey == ರಿಕ್ತ &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		ಗಚ್ಛ out;
	/* success */
out:
	explicit_bzero(hash, ಪರಿಮಾಣ(hash));
	sshbuf_free(server_host_ಕೀಲಿ_blob);
	ಮುಕ್ತ(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	ಪ್ರತ್ಯಾಗಮ r;
}
