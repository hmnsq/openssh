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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <signal.h>

#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "ssherr.h"

স্থির পূর্ণসংখ্যা প্রবেশ_kex_gen_init(পূর্ণসংখ্যা, uint32_t, কাঠামো ssh *);
স্থির পূর্ণসংখ্যা প্রবেশ_kex_gen_reply(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh);

স্থির পূর্ণসংখ্যা
kex_gen_hash(
    পূর্ণসংখ্যা hash_alg,
    ধ্রুবক কাঠামো sshbuf *client_version,
    ধ্রুবক কাঠামো sshbuf *server_version,
    ধ্রুবক কাঠামো sshbuf *client_kexinit,
    ধ্রুবক কাঠামো sshbuf *server_kexinit,
    ধ্রুবক কাঠামো sshbuf *server_host_চাবি_blob,
    ধ্রুবক কাঠামো sshbuf *client_pub,
    ধ্রুবক কাঠামো sshbuf *server_pub,
    ধ্রুবক কাঠামো sshbuf *shared_secret,
    u_char *hash, আকার_t *hashlen)
{
	কাঠামো sshbuf *b;
	পূর্ণসংখ্যা r;

	যদি (*hashlen < ssh_digest_bytes(hash_alg))
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((b = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_stringb(b, client_version)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_বার্তা_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_বার্তা_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_চাবি_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		ফেরত r;
	}
#ifdef DEBUG_KEX
	sshbuf_dump(b, stderr);
#endif
	যদি (ssh_digest_বাফার(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		ফেরত SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#endif
	ফেরত 0;
}

পূর্ণসংখ্যা
kex_gen_client(কাঠামো ssh *ssh)
{
	কাঠামো kex *kex = ssh->kex;
	পূর্ণসংখ্যা r;

	নির্বাচন (kex->kex_type) {
#ifdef WITH_OPENSSL
	ক্ষেত্র KEX_DH_GRP1_SHA1:
	ক্ষেত্র KEX_DH_GRP14_SHA1:
	ক্ষেত্র KEX_DH_GRP14_SHA256:
	ক্ষেত্র KEX_DH_GRP16_SHA512:
	ক্ষেত্র KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		বিরতি;
	ক্ষেত্র KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		বিরতি;
	ক্ষেত্র KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_keypair(kex);
		বিরতি;
#endif /* WITH_OPENSSL */
	ক্ষেত্র KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		বিরতি;
	ক্ষেত্র KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		বিরতি;
	ক্ষেত্র KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_keypair(kex);
		বিরতি;
	পূর্বনির্ধারিত:
		r = SSH_ERR_INVALID_ARGUMENT;
		বিরতি;
	}
	যদি (r != 0)
		ফেরত r;
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ফেরত r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_বার্তা_KEX_ECDH_REPLY, &প্রবেশ_kex_gen_reply);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
প্রবেশ_kex_gen_reply(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	কাঠামো kex *kex = ssh->kex;
	কাঠামো sshkey *server_host_চাবি = ফাঁকা;
	কাঠামো sshbuf *shared_secret = ফাঁকা;
	কাঠামো sshbuf *server_blob = ফাঁকা;
	কাঠামো sshbuf *tmp = ফাঁকা, *server_host_চাবি_blob = ফাঁকা;
	u_char *signature = ফাঁকা;
	u_char hash[SSH_DIGEST_MAX_দৈর্ঘ্য];
	আকার_t slen, hashlen;
	পূর্ণসংখ্যা r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_set(ssh, SSH2_বার্তা_KEX_ECDH_REPLY, &kex_protocol_error);

	/* hostkey */
	যদি ((r = sshpkt_getb_froms(ssh, &server_host_চাবি_blob)) != 0)
		যাও out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	যদি ((tmp = sshbuf_fromb(server_host_চাবি_blob)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshkey_fromb_allowlist(tmp, &server_host_চাবি,
	    kex->hostkey_alg, ফাঁকা)) != 0)
		যাও out;
	যদি ((r = kex_verify_host_চাবি(ssh, server_host_চাবি)) != 0)
		যাও out;

	/* Q_S, server public key */
	/* signed H */
	যদি ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		যাও out;

	/* compute shared secret */
	নির্বাচন (kex->kex_type) {
#ifdef WITH_OPENSSL
	ক্ষেত্র KEX_DH_GRP1_SHA1:
	ক্ষেত্র KEX_DH_GRP14_SHA1:
	ক্ষেত্র KEX_DH_GRP14_SHA256:
	ক্ষেত্র KEX_DH_GRP16_SHA512:
	ক্ষেত্র KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		বিরতি;
	ক্ষেত্র KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		বিরতি;
	ক্ষেত্র KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_dec(kex, server_blob,
		    &shared_secret);
		বিরতি;
#endif /* WITH_OPENSSL */
	ক্ষেত্র KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		বিরতি;
	ক্ষেত্র KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
		    &shared_secret);
		বিরতি;
	ক্ষেত্র KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_dec(kex, server_blob,
		    &shared_secret);
		বিরতি;
	পূর্বনির্ধারিত:
		r = SSH_ERR_INVALID_ARGUMENT;
		বিরতি;
	}
	যদি (r !=0 )
		যাও out;

	/* calc and verify H */
	hashlen = আকার(hash);
	যদি ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_চাবি_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		যাও out;

	যদি ((r = sshkey_verify(server_host_চাবি, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, ফাঁকা)) != 0)
		যাও out;

	যদি ((r = kex_derive_চাবিগুলি(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		যাও out;

	/* save initial signature and hostkey */
	যদি ((kex->flags & KEX_INITIAL) != 0) {
		যদি (kex->initial_hostkey != ফাঁকা || kex->initial_sig != ফাঁকা) {
			r = SSH_ERR_INTERNAL_ERROR;
			যাও out;
		}
		যদি ((kex->initial_sig = sshbuf_new()) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		যদি ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			যাও out;
		kex->initial_hostkey = server_host_চাবি;
		server_host_চাবি = ফাঁকা;
	}
	/* success */
out:
	explicit_bzero(hash, আকার(hash));
	explicit_bzero(kex->c25519_client_চাবি, আকার(kex->c25519_client_চাবি));
	explicit_bzero(kex->sntrup761_client_চাবি,
	    আকার(kex->sntrup761_client_চাবি));
	explicit_bzero(kex->mlkem768_client_চাবি,
	    আকার(kex->mlkem768_client_চাবি));
	sshbuf_free(server_host_চাবি_blob);
	মুক্ত(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_চাবি);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = ফাঁকা;
	ফেরত r;
}

পূর্ণসংখ্যা
kex_gen_server(কাঠামো ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_set(ssh, SSH2_বার্তা_KEX_ECDH_INIT, &প্রবেশ_kex_gen_init);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
প্রবেশ_kex_gen_init(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	কাঠামো kex *kex = ssh->kex;
	কাঠামো sshkey *server_host_private, *server_host_public;
	কাঠামো sshbuf *shared_secret = ফাঁকা;
	কাঠামো sshbuf *server_pubkey = ফাঁকা;
	কাঠামো sshbuf *client_pubkey = ফাঁকা;
	কাঠামো sshbuf *server_host_চাবি_blob = ফাঁকা;
	u_char *signature = ফাঁকা, hash[SSH_DIGEST_MAX_দৈর্ঘ্য];
	আকার_t slen, hashlen;
	পূর্ণসংখ্যা r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_set(ssh, SSH2_বার্তা_KEX_ECDH_INIT, &kex_protocol_error);

	যদি ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		যাও out;

	যদি ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		যাও out;

	/* compute shared secret */
	নির্বাচন (kex->kex_type) {
#ifdef WITH_OPENSSL
	ক্ষেত্র KEX_DH_GRP1_SHA1:
	ক্ষেত্র KEX_DH_GRP14_SHA1:
	ক্ষেত্র KEX_DH_GRP14_SHA256:
	ক্ষেত্র KEX_DH_GRP16_SHA512:
	ক্ষেত্র KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		বিরতি;
	ক্ষেত্র KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		বিরতি;
	ক্ষেত্র KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		বিরতি;
#endif /* WITH_OPENSSL */
	ক্ষেত্র KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		বিরতি;
	ক্ষেত্র KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		বিরতি;
	ক্ষেত্র KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		বিরতি;
	পূর্বনির্ধারিত:
		r = SSH_ERR_INVALID_ARGUMENT;
		বিরতি;
	}
	যদি (r !=0 )
		যাও out;

	/* calc H */
	যদি ((server_host_চাবি_blob = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshkey_putb(server_host_public, server_host_চাবি_blob)) != 0)
		যাও out;
	hashlen = আকার(hash);
	যদি ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_চাবি_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		যাও out;

	/* sign H */
	যদি ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		যাও out;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	যদি ((r = sshpkt_start(ssh, SSH2_বার্তা_KEX_ECDH_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_চাবি_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		যাও out;

	যদি ((r = kex_derive_চাবিগুলি(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		যাও out;
	/* retain copy of hostkey used at initial KEX */
	যদি (kex->initial_hostkey == ফাঁকা &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		যাও out;
	/* success */
out:
	explicit_bzero(hash, আকার(hash));
	sshbuf_free(server_host_চাবি_blob);
	মুক্ত(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	ফেরত r;
}
