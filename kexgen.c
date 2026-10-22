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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>

#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_kex_gen_init(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, uint32_t, ସଂରଚନା ssh *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ନିବେଶ_kex_gen_reply(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh);

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_gen_hash(
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_alg,
    ଅଚଳ ସଂରଚନା sshbuf *client_version,
    ଅଚଳ ସଂରଚନା sshbuf *server_version,
    ଅଚଳ ସଂରଚନା sshbuf *client_kexinit,
    ଅଚଳ ସଂରଚନା sshbuf *server_kexinit,
    ଅଚଳ ସଂରଚନା sshbuf *server_host_ଚାବି_blob,
    ଅଚଳ ସଂରଚନା sshbuf *client_pub,
    ଅଚଳ ସଂରଚନା sshbuf *server_pub,
    ଅଚଳ ସଂରଚନା sshbuf *shared_secret,
    u_char *hash, size_t *hashlen)
{
	ସଂରଚନା sshbuf *b;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (*hashlen < ssh_digest_bytes(hash_alg))
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_put_stringb(b, client_version)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_version)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ସନ୍ଦେଶ_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ସନ୍ଦେଶ_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_ଚାବି_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		ଫେରନ୍ତୁ r;
	}
#ifdef DEBUG_KEX
	sshbuf_dump(b, stderr);
#endif
	ଯଦି (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#endif
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_gen_client(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା kex *kex = ssh->kex;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ବାଛ (kex->kex_type) {
#ifdef WITH_OPENSSL
	ସ୍ଥିତି KEX_DH_GRP1_SHA1:
	ସ୍ଥିତି KEX_DH_GRP14_SHA1:
	ସ୍ଥିତି KEX_DH_GRP14_SHA256:
	ସ୍ଥିତି KEX_DH_GRP16_SHA512:
	ସ୍ଥିତି KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_keypair(kex);
		ଭାଙ୍ଗ;
#endif /* WITH_OPENSSL */
	ସ୍ଥିତି KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_keypair(kex);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		r = SSH_ERR_INVALID_ARGUMENT;
		ଭାଙ୍ଗ;
	}
	ଯଦି (r != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ଫେରନ୍ତୁ r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_KEX_ECDH_REPLY, &ନିବେଶ_kex_gen_reply);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_kex_gen_reply(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା kex *kex = ssh->kex;
	ସଂରଚନା sshkey *server_host_ଚାବି = ଖାଲି;
	ସଂରଚନା sshbuf *shared_secret = ଖାଲି;
	ସଂରଚନା sshbuf *server_blob = ଖାଲି;
	ସଂରଚନା sshbuf *tmp = ଖାଲି, *server_host_ଚାବି_blob = ଖାଲି;
	u_char *signature = ଖାଲି;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_KEX_ECDH_REPLY, &kex_protocol_error);

	/* hostkey */
	ଯଦି ((r = sshpkt_getb_froms(ssh, &server_host_ଚାବି_blob)) != 0)
		ଯାଅ out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	ଯଦି ((tmp = sshbuf_fromb(server_host_ଚାବି_blob)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshkey_fromb_allowlist(tmp, &server_host_ଚାବି,
	    kex->hostkey_alg, ଖାଲି)) != 0)
		ଯାଅ out;
	ଯଦି ((r = kex_verify_host_ଚାବି(ssh, server_host_ଚାବି)) != 0)
		ଯାଅ out;

	/* Q_S, server public key */
	/* signed H */
	ଯଦି ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ଯାଅ out;

	/* compute shared secret */
	ବାଛ (kex->kex_type) {
#ifdef WITH_OPENSSL
	ସ୍ଥିତି KEX_DH_GRP1_SHA1:
	ସ୍ଥିତି KEX_DH_GRP14_SHA1:
	ସ୍ଥିତି KEX_DH_GRP14_SHA256:
	ସ୍ଥିତି KEX_DH_GRP16_SHA512:
	ସ୍ଥିତି KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_dec(kex, server_blob,
		    &shared_secret);
		ଭାଙ୍ଗ;
#endif /* WITH_OPENSSL */
	ସ୍ଥିତି KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
		    &shared_secret);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_dec(kex, server_blob,
		    &shared_secret);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		r = SSH_ERR_INVALID_ARGUMENT;
		ଭାଙ୍ଗ;
	}
	ଯଦି (r !=0 )
		ଯାଅ out;

	/* calc and verify H */
	hashlen = ଆକାର(hash);
	ଯଦି ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->my,
	    kex->peer,
	    server_host_ଚାବି_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		ଯାଅ out;

	ଯଦି ((r = sshkey_verify(server_host_ଚାବି, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, ଖାଲି)) != 0)
		ଯାଅ out;

	ଯଦି ((r = kex_derive_ଚାବିଗୁଡ଼ିକ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ଯାଅ out;

	/* save initial signature and hostkey */
	ଯଦି ((kex->flags & KEX_INITIAL) != 0) {
		ଯଦି (kex->initial_hostkey != ଖାଲି || kex->initial_sig != ଖାଲି) {
			r = SSH_ERR_INTERNAL_ERROR;
			ଯାଅ out;
		}
		ଯଦି ((kex->initial_sig = sshbuf_new()) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			ଯାଅ out;
		kex->initial_hostkey = server_host_ଚାବି;
		server_host_ଚାବି = ଖାଲି;
	}
	/* success */
out:
	explicit_bzero(hash, ଆକାର(hash));
	explicit_bzero(kex->c25519_client_ଚାବି, ଆକାର(kex->c25519_client_ଚାବି));
	explicit_bzero(kex->sntrup761_client_ଚାବି,
	    ଆକାର(kex->sntrup761_client_ଚାବି));
	explicit_bzero(kex->mlkem768_client_ଚାବି,
	    ଆକାର(kex->mlkem768_client_ଚାବି));
	sshbuf_free(server_host_ଚାବି_blob);
	ମୁକ୍ତ(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_ଚାବି);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = ଖାଲି;
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_gen_server(ସଂରଚନା ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_KEX_ECDH_INIT, &ନିବେଶ_kex_gen_init);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_kex_gen_init(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା kex *kex = ssh->kex;
	ସଂରଚନା sshkey *server_host_private, *server_host_public;
	ସଂରଚନା sshbuf *shared_secret = ଖାଲି;
	ସଂରଚନା sshbuf *server_pubkey = ଖାଲି;
	ସଂରଚନା sshbuf *client_pubkey = ଖାଲି;
	ସଂରଚନା sshbuf *server_host_ଚାବି_blob = ଖାଲି;
	u_char *signature = ଖାଲି, hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_KEX_ECDH_INIT, &kex_protocol_error);

	ଯଦି ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		ଯାଅ out;

	ଯଦି ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ଯାଅ out;

	/* compute shared secret */
	ବାଛ (kex->kex_type) {
#ifdef WITH_OPENSSL
	ସ୍ଥିତି KEX_DH_GRP1_SHA1:
	ସ୍ଥିତି KEX_DH_GRP14_SHA1:
	ସ୍ଥିତି KEX_DH_GRP14_SHA256:
	ସ୍ଥିତି KEX_DH_GRP16_SHA512:
	ସ୍ଥିତି KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		ଭାଙ୍ଗ;
#endif /* WITH_OPENSSL */
	ସ୍ଥିତି KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		r = SSH_ERR_INVALID_ARGUMENT;
		ଭାଙ୍ଗ;
	}
	ଯଦି (r !=0 )
		ଯାଅ out;

	/* calc H */
	ଯଦି ((server_host_ଚାବି_blob = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshkey_putb(server_host_public, server_host_ଚାବି_blob)) != 0)
		ଯାଅ out;
	hashlen = ଆକାର(hash);
	ଯଦି ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_ଚାବି_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		ଯାଅ out;

	/* sign H */
	ଯଦି ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		ଯାଅ out;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	ଯଦି ((r = sshpkt_start(ssh, SSH2_ସନ୍ଦେଶ_KEX_ECDH_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_ଚାବି_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ଯାଅ out;

	ଯଦି ((r = kex_derive_ଚାବିଗୁଡ଼ିକ(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		ଯାଅ out;
	/* retain copy of hostkey used at initial KEX */
	ଯଦି (kex->initial_hostkey == ଖାଲି &&
	    (r = sshkey_from_private(server_host_public,
	    &kex->initial_hostkey)) != 0)
		ଯାଅ out;
	/* success */
out:
	explicit_bzero(hash, ଆକାର(hash));
	sshbuf_free(server_host_ଚାବି_blob);
	ମୁକ୍ତ(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	ଫେରନ୍ତୁ r;
}
