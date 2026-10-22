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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <signal.h>

#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "ssherr.h"

స్థిర పూర్ణాంకం ఆదానం_kex_gen_init(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_kex_gen_జవాబు(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh);

స్థిర పూర్ణాంకం
kex_gen_hash(
    పూర్ణాంకం hash_alg,
    స్థిరరాశి నిర్మాణం sshbuf *client_సంస్కరణ,
    స్థిరరాశి నిర్మాణం sshbuf *server_సంస్కరణ,
    స్థిరరాశి నిర్మాణం sshbuf *client_kexinit,
    స్థిరరాశి నిర్మాణం sshbuf *server_kexinit,
    స్థిరరాశి నిర్మాణం sshbuf *server_host_కీలకం_blob,
    స్థిరరాశి నిర్మాణం sshbuf *client_pub,
    స్థిరరాశి నిర్మాణం sshbuf *server_pub,
    స్థిరరాశి నిర్మాణం sshbuf *shared_secret,
    u_char *hash, కొలత_t *hashlen)
{
	నిర్మాణం sshbuf *b;
	పూర్ణాంకం r;

	ఒకవేళ (*hashlen < ssh_digest_బైట్లు(hash_alg))
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put_stringb(b, client_సంస్కరణ)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_సంస్కరణ)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_సందేశం_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_సందేశం_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_కీలకం_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		తిరిగి r;
	}
#నిర్వచితమైతే DEBUG_KEX
	sshbuf_dump(b, stderr);
#అయితే_ముగింపు
	ఒకవేళ (ssh_digest_బఫరు(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_బైట్లు(hash_alg);
#నిర్వచితమైతే DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#అయితే_ముగింపు
	తిరిగి 0;
}

పూర్ణాంకం
kex_gen_client(నిర్మాణం ssh *ssh)
{
	నిర్మాణం kex *kex = ssh->kex;
	పూర్ణాంకం r;

	ఎంపిక (kex->kex_type) {
#నిర్వచితమైతే WITH_OPENSSL
	స్థితి KEX_DH_GRP1_SHA1:
	స్థితి KEX_DH_GRP14_SHA1:
	స్థితి KEX_DH_GRP14_SHA256:
	స్థితి KEX_DH_GRP16_SHA512:
	స్థితి KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		ఆపు;
	స్థితి KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		ఆపు;
	స్థితి KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_keypair(kex);
		ఆపు;
#అయితే_ముగింపు /* WITH_OPENSSL */
	స్థితి KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		ఆపు;
	స్థితి KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		ఆపు;
	స్థితి KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_keypair(kex);
		ఆపు;
	అప్రమేయ:
		r = SSH_ERR_INVALID_వాదం;
		ఆపు;
	}
	ఒకవేళ (r != 0)
		తిరిగి r;
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		తిరిగి r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEX_ECDH_జవాబు, &ఆదానం_kex_gen_జవాబు);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ఆదానం_kex_gen_జవాబు(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	నిర్మాణం kex *kex = ssh->kex;
	నిర్మాణం sshkey *server_host_కీలకం = ఖాళీ;
	నిర్మాణం sshbuf *shared_secret = ఖాళీ;
	నిర్మాణం sshbuf *server_blob = ఖాళీ;
	నిర్మాణం sshbuf *tmp = ఖాళీ, *server_host_కీలకం_blob = ఖాళీ;
	u_char *signature = ఖాళీ;
	u_char hash[SSH_DIGEST_MAX_నిడివి];
	కొలత_t slen, hashlen;
	పూర్ణాంకం r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEX_ECDH_జవాబు, &kex_protocol_error);

	/* hostkey */
	ఒకవేళ ((r = sshpkt_getb_froms(ssh, &server_host_కీలకం_blob)) != 0)
		వెళ్ళు బహిర్గతం;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	ఒకవేళ ((tmp = sshbuf_fromb(server_host_కీలకం_blob)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshkey_fromb_allowlist(tmp, &server_host_కీలకం,
	    kex->hostkey_alg, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = kex_verify_host_కీలకం(ssh, server_host_కీలకం)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Q_S, server public key */
	/* signed H */
	ఒకవేళ ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		వెళ్ళు బహిర్గతం;

	/* compute shared secret */
	ఎంపిక (kex->kex_type) {
#నిర్వచితమైతే WITH_OPENSSL
	స్థితి KEX_DH_GRP1_SHA1:
	స్థితి KEX_DH_GRP14_SHA1:
	స్థితి KEX_DH_GRP14_SHA256:
	స్థితి KEX_DH_GRP16_SHA512:
	స్థితి KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		ఆపు;
	స్థితి KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		ఆపు;
	స్థితి KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_dec(kex, server_blob,
		    &shared_secret);
		ఆపు;
#అయితే_ముగింపు /* WITH_OPENSSL */
	స్థితి KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		ఆపు;
	స్థితి KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
		    &shared_secret);
		ఆపు;
	స్థితి KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_dec(kex, server_blob,
		    &shared_secret);
		ఆపు;
	అప్రమేయ:
		r = SSH_ERR_INVALID_వాదం;
		ఆపు;
	}
	ఒకవేళ (r !=0 )
		వెళ్ళు బహిర్గతం;

	/* calc and verify H */
	hashlen = పరిమాణం(hash);
	ఒకవేళ ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_సంస్కరణ,
	    kex->server_సంస్కరణ,
	    kex->my,
	    kex->peer,
	    server_host_కీలకం_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((r = sshkey_verify(server_host_కీలకం, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((r = kex_derive_కీలకాలు(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		వెళ్ళు బహిర్గతం;

	/* save initial signature and hostkey */
	ఒకవేళ ((kex->flags & KEX_INITIAL) != 0) {
		ఒకవేళ (kex->initial_hostkey != ఖాళీ || kex->initial_sig != ఖాళీ) {
			r = SSH_ERR_అంతర్గత_ERROR;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((kex->initial_sig = sshbuf_new()) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			వెళ్ళు బహిర్గతం;
		kex->initial_hostkey = server_host_కీలకం;
		server_host_కీలకం = ఖాళీ;
	}
	/* success */
బహిర్గతం:
	explicit_bzero(hash, పరిమాణం(hash));
	explicit_bzero(kex->c25519_client_కీలకం, పరిమాణం(kex->c25519_client_కీలకం));
	explicit_bzero(kex->sntrup761_client_కీలకం,
	    పరిమాణం(kex->sntrup761_client_కీలకం));
	explicit_bzero(kex->mlkem768_client_కీలకం,
	    పరిమాణం(kex->mlkem768_client_కీలకం));
	sshbuf_free(server_host_కీలకం_blob);
	విడుదల(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_కీలకం);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = ఖాళీ;
	తిరిగి r;
}

పూర్ణాంకం
kex_gen_server(నిర్మాణం ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEX_ECDH_INIT, &ఆదానం_kex_gen_init);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ఆదానం_kex_gen_init(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	నిర్మాణం kex *kex = ssh->kex;
	నిర్మాణం sshkey *server_host_వ్యక్తిగత, *server_host_ప్రజా;
	నిర్మాణం sshbuf *shared_secret = ఖాళీ;
	నిర్మాణం sshbuf *server_pubkey = ఖాళీ;
	నిర్మాణం sshbuf *client_pubkey = ఖాళీ;
	నిర్మాణం sshbuf *server_host_కీలకం_blob = ఖాళీ;
	u_char *signature = ఖాళీ, hash[SSH_DIGEST_MAX_నిడివి];
	కొలత_t slen, hashlen;
	పూర్ణాంకం r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_KEX_ECDH_INIT, &kex_protocol_error);

	ఒకవేళ ((r = kex_ఎక్కించు_hostkey(ssh, &server_host_వ్యక్తిగత,
	    &server_host_ప్రజా)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		వెళ్ళు బహిర్గతం;

	/* compute shared secret */
	ఎంపిక (kex->kex_type) {
#నిర్వచితమైతే WITH_OPENSSL
	స్థితి KEX_DH_GRP1_SHA1:
	స్థితి KEX_DH_GRP14_SHA1:
	స్థితి KEX_DH_GRP14_SHA256:
	స్థితి KEX_DH_GRP16_SHA512:
	స్థితి KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		ఆపు;
	స్థితి KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		ఆపు;
	స్థితి KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		ఆపు;
#అయితే_ముగింపు /* WITH_OPENSSL */
	స్థితి KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		ఆపు;
	స్థితి KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		ఆపు;
	స్థితి KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		ఆపు;
	అప్రమేయ:
		r = SSH_ERR_INVALID_వాదం;
		ఆపు;
	}
	ఒకవేళ (r !=0 )
		వెళ్ళు బహిర్గతం;

	/* calc H */
	ఒకవేళ ((server_host_కీలకం_blob = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshkey_putb(server_host_ప్రజా, server_host_కీలకం_blob)) != 0)
		వెళ్ళు బహిర్గతం;
	hashlen = పరిమాణం(hash);
	ఒకవేళ ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_సంస్కరణ,
	    kex->server_సంస్కరణ,
	    kex->peer,
	    kex->my,
	    server_host_కీలకం_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		వెళ్ళు బహిర్గతం;

	/* sign H */
	ఒకవేళ ((r = kex->sign(ssh, server_host_వ్యక్తిగత, server_host_ప్రజా,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		వెళ్ళు బహిర్గతం;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_KEX_ECDH_జవాబు)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_కీలకం_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((r = kex_derive_కీలకాలు(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		వెళ్ళు బహిర్గతం;
	/* retain copy of hostkey used at initial KEX */
	ఒకవేళ (kex->initial_hostkey == ఖాళీ &&
	    (r = sshkey_from_వ్యక్తిగత(server_host_ప్రజా,
	    &kex->initial_hostkey)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
బహిర్గతం:
	explicit_bzero(hash, పరిమాణం(hash));
	sshbuf_free(server_host_కీలకం_blob);
	విడుదల(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	తిరిగి r;
}
