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

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_kex_gen_init(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_kex_gen_ಉತ್ತರ(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh);

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
kex_gen_hash(
    ಪೂರ್ಣಾಂಕ hash_alg,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *client_ಆವೃತ್ತಿ,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *server_ಆವೃತ್ತಿ,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *client_kexinit,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *server_kexinit,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *server_host_ಕೀಲಿ_blob,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *client_pub,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *server_pub,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *shared_secret,
    u_char *hash, ಗಾತ್ರ_t *hashlen)
{
	ರಚನೆ sshbuf *b;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (*hashlen < ssh_digest_ಬೈಟುಗಳು(hash_alg))
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put_stringb(b, client_ಆವೃತ್ತಿ)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_ಆವೃತ್ತಿ)) != 0 ||
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
		ಹಿಂತಿರುಗಿ r;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEX
	sshbuf_dump(b, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (ssh_digest_ಬಫರ್(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_ಬೈಟುಗಳು(hash_alg);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
kex_gen_client(ರಚನೆ ssh *ssh)
{
	ರಚನೆ kex *kex = ssh->kex;
	ಪೂರ್ಣಾಂಕ r;

	ಆಯ್ಕೆ (kex->kex_type) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿತಿ KEX_DH_GRP1_SHA1:
	ಸ್ಥಿತಿ KEX_DH_GRP14_SHA1:
	ಸ್ಥಿತಿ KEX_DH_GRP14_SHA256:
	ಸ್ಥಿತಿ KEX_DH_GRP16_SHA512:
	ಸ್ಥಿತಿ KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_keypair(kex);
		ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಸ್ಥಿತಿ KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_keypair(kex);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		r = SSH_ERR_INVALID_ವಾದ;
		ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (r != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಹಿಂತಿರುಗಿ r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEX_ECDH_ಉತ್ತರ, &ಒಳಹರಿವು_kex_gen_ಉತ್ತರ);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_kex_gen_ಉತ್ತರ(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ರಚನೆ kex *kex = ssh->kex;
	ರಚನೆ sshkey *server_host_ಕೀಲಿ = ಖಾಲಿ;
	ರಚನೆ sshbuf *shared_secret = ಖಾಲಿ;
	ರಚನೆ sshbuf *server_blob = ಖಾಲಿ;
	ರಚನೆ sshbuf *tmp = ಖಾಲಿ, *server_host_ಕೀಲಿ_blob = ಖಾಲಿ;
	u_char *signature = ಖಾಲಿ;
	u_char hash[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];
	ಗಾತ್ರ_t slen, hashlen;
	ಪೂರ್ಣಾಂಕ r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEX_ECDH_ಉತ್ತರ, &kex_protocol_error);

	/* hostkey */
	ಆದರೆ ((r = sshpkt_getb_froms(ssh, &server_host_ಕೀಲಿ_blob)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	ಆದರೆ ((tmp = sshbuf_fromb(server_host_ಕೀಲಿ_blob)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshkey_fromb_allowlist(tmp, &server_host_ಕೀಲಿ,
	    kex->hostkey_alg, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = kex_verify_host_ಕೀಲಿ(ssh, server_host_ಕೀಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Q_S, server public key */
	/* signed H */
	ಆದರೆ ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* compute shared secret */
	ಆಯ್ಕೆ (kex->kex_type) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿತಿ KEX_DH_GRP1_SHA1:
	ಸ್ಥಿತಿ KEX_DH_GRP14_SHA1:
	ಸ್ಥಿತಿ KEX_DH_GRP14_SHA256:
	ಸ್ಥಿತಿ KEX_DH_GRP16_SHA512:
	ಸ್ಥಿತಿ KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_dec(kex, server_blob,
		    &shared_secret);
		ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಸ್ಥಿತಿ KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
		    &shared_secret);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_dec(kex, server_blob,
		    &shared_secret);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		r = SSH_ERR_INVALID_ವಾದ;
		ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (r !=0 )
		ಹೋಗು ಹೊರಹೋಗು;

	/* calc and verify H */
	hashlen = ಗಾತ್ರ(hash);
	ಆದರೆ ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_ಆವೃತ್ತಿ,
	    kex->server_ಆವೃತ್ತಿ,
	    kex->my,
	    kex->peer,
	    server_host_ಕೀಲಿ_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((r = sshkey_verify(server_host_ಕೀಲಿ, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((r = kex_derive_ಕೀಲಿಗಳು(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* save initial signature and hostkey */
	ಆದರೆ ((kex->flags & KEX_INITIAL) != 0) {
		ಆದರೆ (kex->initial_hostkey != ಖಾಲಿ || kex->initial_sig != ಖಾಲಿ) {
			r = SSH_ERR_ಆಂತರಿಕ_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((kex->initial_sig = sshbuf_new()) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		kex->initial_hostkey = server_host_ಕೀಲಿ;
		server_host_ಕೀಲಿ = ಖಾಲಿ;
	}
	/* success */
ಹೊರಹೋಗು:
	explicit_bzero(hash, ಗಾತ್ರ(hash));
	explicit_bzero(kex->c25519_client_ಕೀಲಿ, ಗಾತ್ರ(kex->c25519_client_ಕೀಲಿ));
	explicit_bzero(kex->sntrup761_client_ಕೀಲಿ,
	    ಗಾತ್ರ(kex->sntrup761_client_ಕೀಲಿ));
	explicit_bzero(kex->mlkem768_client_ಕೀಲಿ,
	    ಗಾತ್ರ(kex->mlkem768_client_ಕೀಲಿ));
	sshbuf_free(server_host_ಕೀಲಿ_blob);
	ಬಿಡುಗಡೆ(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_ಕೀಲಿ);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
kex_gen_server(ರಚನೆ ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEX_ECDH_INIT, &ಒಳಹರಿವು_kex_gen_init);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_kex_gen_init(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ರಚನೆ kex *kex = ssh->kex;
	ರಚನೆ sshkey *server_host_ಖಾಸಗಿ, *server_host_ಬಹಿರಂಗ;
	ರಚನೆ sshbuf *shared_secret = ಖಾಲಿ;
	ರಚನೆ sshbuf *server_pubkey = ಖಾಲಿ;
	ರಚನೆ sshbuf *client_pubkey = ಖಾಲಿ;
	ರಚನೆ sshbuf *server_host_ಕೀಲಿ_blob = ಖಾಲಿ;
	u_char *signature = ಖಾಲಿ, hash[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];
	ಗಾತ್ರ_t slen, hashlen;
	ಪೂರ್ಣಾಂಕ r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_KEX_ECDH_INIT, &kex_protocol_error);

	ಆದರೆ ((r = kex_ತುಂಬು_hostkey(ssh, &server_host_ಖಾಸಗಿ,
	    &server_host_ಬಹಿರಂಗ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* compute shared secret */
	ಆಯ್ಕೆ (kex->kex_type) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿತಿ KEX_DH_GRP1_SHA1:
	ಸ್ಥಿತಿ KEX_DH_GRP14_SHA1:
	ಸ್ಥಿತಿ KEX_DH_GRP14_SHA256:
	ಸ್ಥಿತಿ KEX_DH_GRP16_SHA512:
	ಸ್ಥಿತಿ KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಸ್ಥಿತಿ KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		r = SSH_ERR_INVALID_ವಾದ;
		ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (r !=0 )
		ಹೋಗು ಹೊರಹೋಗು;

	/* calc H */
	ಆದರೆ ((server_host_ಕೀಲಿ_blob = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshkey_putb(server_host_ಬಹಿರಂಗ, server_host_ಕೀಲಿ_blob)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	hashlen = ಗಾತ್ರ(hash);
	ಆದರೆ ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_ಆವೃತ್ತಿ,
	    kex->server_ಆವೃತ್ತಿ,
	    kex->peer,
	    kex->my,
	    server_host_ಕೀಲಿ_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* sign H */
	ಆದರೆ ((r = kex->sign(ssh, server_host_ಖಾಸಗಿ, server_host_ಬಹಿರಂಗ,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_KEX_ECDH_ಉತ್ತರ)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_ಕೀಲಿ_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ ((r = kex_derive_ಕೀಲಿಗಳು(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* retain copy of hostkey used at initial KEX */
	ಆದರೆ (kex->initial_hostkey == ಖಾಲಿ &&
	    (r = sshkey_from_ಖಾಸಗಿ(server_host_ಬಹಿರಂಗ,
	    &kex->initial_hostkey)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
ಹೊರಹೋಗು:
	explicit_bzero(hash, ಗಾತ್ರ(hash));
	sshbuf_free(server_host_ಕೀಲಿ_blob);
	ಬಿಡುಗಡೆ(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	ಹಿಂತಿರುಗಿ r;
}
