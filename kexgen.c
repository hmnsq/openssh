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

स्थिर पूर्णाङ्क निवेशः_kex_gen_init(पूर्णाङ्क, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क निवेशः_kex_gen_reply(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh);

स्थिर पूर्णाङ्क
kex_gen_hash(
    पूर्णाङ्क hash_alg,
    ध्रुव संरचना sshbuf *client_version,
    ध्रुव संरचना sshbuf *server_version,
    ध्रुव संरचना sshbuf *client_kexinit,
    ध्रुव संरचना sshbuf *server_kexinit,
    ध्रुव संरचना sshbuf *server_host_कुञ्चिका_blob,
    ध्रुव संरचना sshbuf *client_pub,
    ध्रुव संरचना sshbuf *server_pub,
    ध्रुव संरचना sshbuf *shared_secret,
    u_char *hash, size_t *hashlen)
{
	संरचना sshbuf *b;
	पूर्णाङ्क r;

	जइ (*hashlen < ssh_digest_bytes(hash_alg))
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	जइ ((b = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	जइ ((r = sshbuf_put_stringb(b, client_version)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_सन्देशः_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_सन्देशः_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_कुञ्चिका_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		प्रत्यागम r;
	}
#ifdef DEBUG_KEX
	sshbuf_dump(b, stderr);
#endif
	जइ (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#endif
	प्रत्यागम 0;
}

पूर्णाङ्क
kex_gen_client(संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	पूर्णाङ्क r;

	विकल्प (kex->kex_type) {
#ifdef WITH_OPENSSL
	पक्ष KEX_DH_GRP1_SHA1:
	पक्ष KEX_DH_GRP14_SHA1:
	पक्ष KEX_DH_GRP14_SHA256:
	पक्ष KEX_DH_GRP16_SHA512:
	पक्ष KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		भङ्ग;
	पक्ष KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		भङ्ग;
	पक्ष KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_keypair(kex);
		भङ्ग;
#endif /* WITH_OPENSSL */
	पक्ष KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		भङ्ग;
	पक्ष KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		भङ्ग;
	पक्ष KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_keypair(kex);
		भङ्ग;
	स्वभाव:
		r = SSH_ERR_INVALID_ARGUMENT;
		भङ्ग;
	}
	जइ (r != 0)
		प्रत्यागम r;
	जइ ((r = sshpkt_start(ssh, SSH2_सन्देशः_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		प्रत्यागम r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_सन्देशः_KEX_ECDH_REPLY, &निवेशः_kex_gen_reply);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
निवेशः_kex_gen_reply(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	संरचना sshkey *server_host_कुञ्चिका = रिक्त;
	संरचना sshbuf *shared_secret = रिक्त;
	संरचना sshbuf *server_blob = रिक्त;
	संरचना sshbuf *tmp = रिक्त, *server_host_कुञ्चिका_blob = रिक्त;
	u_char *signature = रिक्त;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	पूर्णाङ्क r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_set(ssh, SSH2_सन्देशः_KEX_ECDH_REPLY, &kex_protocol_error);

	/* hostkey */
	जइ ((r = sshpkt_getb_froms(ssh, &server_host_कुञ्चिका_blob)) != 0)
		गच्छ out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	जइ ((tmp = sshbuf_fromb(server_host_कुञ्चिका_blob)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	जइ ((r = sshkey_fromb_allowlist(tmp, &server_host_कुञ्चिका,
	    kex->hostkey_alg, रिक्त)) != 0)
		गच्छ out;
	जइ ((r = kex_verify_host_कुञ्चिका(ssh, server_host_कुञ्चिका)) != 0)
		गच्छ out;

	/* Q_S, server public key */
	/* signed H */
	जइ ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		गच्छ out;

	/* compute shared secret */
	विकल्प (kex->kex_type) {
#ifdef WITH_OPENSSL
	पक्ष KEX_DH_GRP1_SHA1:
	पक्ष KEX_DH_GRP14_SHA1:
	पक्ष KEX_DH_GRP14_SHA256:
	पक्ष KEX_DH_GRP16_SHA512:
	पक्ष KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		भङ्ग;
	पक्ष KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		भङ्ग;
	पक्ष KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_dec(kex, server_blob,
		    &shared_secret);
		भङ्ग;
#endif /* WITH_OPENSSL */
	पक्ष KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		भङ्ग;
	पक्ष KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
		    &shared_secret);
		भङ्ग;
	पक्ष KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_dec(kex, server_blob,
		    &shared_secret);
		भङ्ग;
	स्वभाव:
		r = SSH_ERR_INVALID_ARGUMENT;
		भङ्ग;
	}
	जइ (r !=0 )
		गच्छ out;

	/* calc and verify H */
	hashlen = परिमाण(hash);
	जइ ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_कुञ्चिका_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		गच्छ out;

	जइ ((r = sshkey_verify(server_host_कुञ्चिका, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, रिक्त)) != 0)
		गच्छ out;

	जइ ((r = kex_derive_कुञ्चिकाः(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		गच्छ out;

	/* save initial signature and hostkey */
	जइ ((kex->flags & KEX_INITIAL) != 0) {
		जइ (kex->initial_hostkey != रिक्त || kex->initial_sig != रिक्त) {
			r = SSH_ERR_INTERNAL_ERROR;
			गच्छ out;
		}
		जइ ((kex->initial_sig = sshbuf_new()) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		जइ ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			गच्छ out;
		kex->initial_hostkey = server_host_कुञ्चिका;
		server_host_कुञ्चिका = रिक्त;
	}
	/* success */
out:
	explicit_bzero(hash, परिमाण(hash));
	explicit_bzero(kex->c25519_client_कुञ्चिका, परिमाण(kex->c25519_client_कुञ्चिका));
	explicit_bzero(kex->sntrup761_client_कुञ्चिका,
	    परिमाण(kex->sntrup761_client_कुञ्चिका));
	explicit_bzero(kex->mlkem768_client_कुञ्चिका,
	    परिमाण(kex->mlkem768_client_कुञ्चिका));
	sshbuf_free(server_host_कुञ्चिका_blob);
	मुक्त(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_कुञ्चिका);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = रिक्त;
	प्रत्यागम r;
}

पूर्णाङ्क
kex_gen_server(संरचना ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_set(ssh, SSH2_सन्देशः_KEX_ECDH_INIT, &निवेशः_kex_gen_init);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
निवेशः_kex_gen_init(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	संरचना sshkey *server_host_private, *server_host_public;
	संरचना sshbuf *shared_secret = रिक्त;
	संरचना sshbuf *server_pubkey = रिक्त;
	संरचना sshbuf *client_pubkey = रिक्त;
	संरचना sshbuf *server_host_कुञ्चिका_blob = रिक्त;
	u_char *signature = रिक्त, hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	पूर्णाङ्क r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_set(ssh, SSH2_सन्देशः_KEX_ECDH_INIT, &kex_protocol_error);

	जइ ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		गच्छ out;

	जइ ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		गच्छ out;

	/* compute shared secret */
	विकल्प (kex->kex_type) {
#ifdef WITH_OPENSSL
	पक्ष KEX_DH_GRP1_SHA1:
	पक्ष KEX_DH_GRP14_SHA1:
	पक्ष KEX_DH_GRP14_SHA256:
	पक्ष KEX_DH_GRP16_SHA512:
	पक्ष KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		भङ्ग;
	पक्ष KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		भङ्ग;
	पक्ष KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		भङ्ग;
#endif /* WITH_OPENSSL */
	पक्ष KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		भङ्ग;
	पक्ष KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		भङ्ग;
	पक्ष KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		भङ्ग;
	स्वभाव:
		r = SSH_ERR_INVALID_ARGUMENT;
		भङ्ग;
	}
	जइ (r !=0 )
		गच्छ out;

	/* calc H */
	जइ ((server_host_कुञ्चिका_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	जइ ((r = sshkey_putb(server_host_public, server_host_कुञ्चिका_blob)) != 0)
		गच्छ out;
	hashlen = परिमाण(hash);
	जइ ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_कुञ्चिका_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		गच्छ out;

	/* sign H */
	जइ ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		गच्छ out;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	जइ ((r = sshpkt_start(ssh, SSH2_सन्देशः_KEX_ECDH_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_कुञ्चिका_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		गच्छ out;

	जइ ((r = kex_derive_कुञ्चिकाः(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		गच्छ out;
	/* retain copy of hostkey used at initial KEX */
	जइ (kex->initial_hostkey == रिक्त &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		गच्छ out;
	/* success */
out:
	explicit_bzero(hash, परिमाण(hash));
	sshbuf_free(server_host_कुञ्चिका_blob);
	मुक्त(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	प्रत्यागम r;
}
