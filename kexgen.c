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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <signal.h>

#ضمن "sshkey.h"
#ضمن "kex.h"
#ضمن "log.h"
#ضمن "packet.h"
#ضمن "ssh2.h"
#ضمن "sshbuf.h"
#ضمن "digest.h"
#ضمن "ssherr.h"

ساكن صحيح درون_داد_kex_gen_init(صحيح, uint32_t, بنية ssh *);
ساكن صحيح درون_داد_kex_gen_پاسخ(صحيح type, uint32_t seq, بنية ssh *ssh);

ساكن صحيح
kex_gen_hash(
    صحيح hash_alg,
    ثابت بنية sshbuf *client_نسخه,
    ثابت بنية sshbuf *server_نسخه,
    ثابت بنية sshbuf *client_kexinit,
    ثابت بنية sshbuf *server_kexinit,
    ثابت بنية sshbuf *server_host_کلید_blob,
    ثابت بنية sshbuf *client_pub,
    ثابت بنية sshbuf *server_pub,
    ثابت بنية sshbuf *shared_secret,
    u_char *hash, اندازه_t *hashlen)
{
	بنية sshbuf *b;
	صحيح r;

	إذا (*hashlen < ssh_digest_بایتها(hash_alg))
		أرجع SSH_ERR_INVALID_آرگومان;
	إذا ((b = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_stringb(b, client_نسخه)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_نسخه)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیام_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیام_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_کلید_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		أرجع r;
	}
#اگر_تعریف_شده DEBUG_KEX
	sshbuf_dump(b, stderr);
#پایان_اگر
	إذا (ssh_digest_میانگیر(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		أرجع SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_بایتها(hash_alg);
#اگر_تعریف_شده DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#پایان_اگر
	أرجع 0;
}

صحيح
kex_gen_client(بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	صحيح r;

	بدل (kex->kex_type) {
#اگر_تعریف_شده WITH_OPENSSL
	حالة KEX_DH_GRP1_SHA1:
	حالة KEX_DH_GRP14_SHA1:
	حالة KEX_DH_GRP14_SHA256:
	حالة KEX_DH_GRP16_SHA512:
	حالة KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		اكسر;
	حالة KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		اكسر;
	حالة KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_keypair(kex);
		اكسر;
#پایان_اگر /* WITH_OPENSSL */
	حالة KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		اكسر;
	حالة KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		اكسر;
	حالة KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_keypair(kex);
		اكسر;
	افتراضي:
		r = SSH_ERR_INVALID_آرگومان;
		اكسر;
	}
	إذا (r != 0)
		أرجع r;
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		أرجع r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_KEX_ECDH_پاسخ, &درون_داد_kex_gen_پاسخ);
	أرجع 0;
}

ساكن صحيح
درون_داد_kex_gen_پاسخ(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	بنية sshkey *server_host_کلید = عدم;
	بنية sshbuf *shared_secret = عدم;
	بنية sshbuf *server_blob = عدم;
	بنية sshbuf *tmp = عدم, *server_host_کلید_blob = عدم;
	u_char *signature = عدم;
	u_char hash[SSH_DIGEST_MAX_درازی];
	اندازه_t slen, hashlen;
	صحيح r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_KEX_ECDH_پاسخ, &kex_protocol_error);

	/* hostkey */
	إذا ((r = sshpkt_getb_froms(ssh, &server_host_کلید_blob)) != 0)
		اذهب بیرون;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	إذا ((tmp = sshbuf_fromb(server_host_کلید_blob)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا ((r = sshkey_fromb_allowlist(tmp, &server_host_کلید,
	    kex->hostkey_alg, عدم)) != 0)
		اذهب بیرون;
	إذا ((r = kex_verify_host_کلید(ssh, server_host_کلید)) != 0)
		اذهب بیرون;

	/* Q_S, server public key */
	/* signed H */
	إذا ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_انتها(ssh)) != 0)
		اذهب بیرون;

	/* compute shared secret */
	بدل (kex->kex_type) {
#اگر_تعریف_شده WITH_OPENSSL
	حالة KEX_DH_GRP1_SHA1:
	حالة KEX_DH_GRP14_SHA1:
	حالة KEX_DH_GRP14_SHA256:
	حالة KEX_DH_GRP16_SHA512:
	حالة KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		اكسر;
	حالة KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		اكسر;
	حالة KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_dec(kex, server_blob,
		    &shared_secret);
		اكسر;
#پایان_اگر /* WITH_OPENSSL */
	حالة KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		اكسر;
	حالة KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
		    &shared_secret);
		اكسر;
	حالة KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_dec(kex, server_blob,
		    &shared_secret);
		اكسر;
	افتراضي:
		r = SSH_ERR_INVALID_آرگومان;
		اكسر;
	}
	إذا (r !=0 )
		اذهب بیرون;

	/* calc and verify H */
	hashlen = حجم(hash);
	إذا ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_نسخه,
	    kex->server_نسخه,
	    kex->my,
	    kex->peer,
	    server_host_کلید_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		اذهب بیرون;

	إذا ((r = sshkey_verify(server_host_کلید, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, عدم)) != 0)
		اذهب بیرون;

	إذا ((r = kex_derive_کلیدها(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		اذهب بیرون;

	/* save initial signature and hostkey */
	إذا ((kex->flags & KEX_INITIAL) != 0) {
		إذا (kex->initial_hostkey != عدم || kex->initial_sig != عدم) {
			r = SSH_ERR_داخلی_ERROR;
			اذهب بیرون;
		}
		إذا ((kex->initial_sig = sshbuf_new()) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بیرون;
		}
		إذا ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			اذهب بیرون;
		kex->initial_hostkey = server_host_کلید;
		server_host_کلید = عدم;
	}
	/* success */
بیرون:
	explicit_bzero(hash, حجم(hash));
	explicit_bzero(kex->c25519_client_کلید, حجم(kex->c25519_client_کلید));
	explicit_bzero(kex->sntrup761_client_کلید,
	    حجم(kex->sntrup761_client_کلید));
	explicit_bzero(kex->mlkem768_client_کلید,
	    حجم(kex->mlkem768_client_کلید));
	sshbuf_free(server_host_کلید_blob);
	حرر(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_کلید);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = عدم;
	أرجع r;
}

صحيح
kex_gen_server(بنية ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_KEX_ECDH_INIT, &درون_داد_kex_gen_init);
	أرجع 0;
}

ساكن صحيح
درون_داد_kex_gen_init(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	بنية sshkey *server_host_خصوصی, *server_host_عمومی;
	بنية sshbuf *shared_secret = عدم;
	بنية sshbuf *server_pubkey = عدم;
	بنية sshbuf *client_pubkey = عدم;
	بنية sshbuf *server_host_کلید_blob = عدم;
	u_char *signature = عدم, hash[SSH_DIGEST_MAX_درازی];
	اندازه_t slen, hashlen;
	صحيح r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_مجموعه(ssh, SSH2_پیام_KEX_ECDH_INIT, &kex_protocol_error);

	إذا ((r = kex_بارگیری_hostkey(ssh, &server_host_خصوصی,
	    &server_host_عمومی)) != 0)
		اذهب بیرون;

	إذا ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_انتها(ssh)) != 0)
		اذهب بیرون;

	/* compute shared secret */
	بدل (kex->kex_type) {
#اگر_تعریف_شده WITH_OPENSSL
	حالة KEX_DH_GRP1_SHA1:
	حالة KEX_DH_GRP14_SHA1:
	حالة KEX_DH_GRP14_SHA256:
	حالة KEX_DH_GRP16_SHA512:
	حالة KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		اكسر;
	حالة KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		اكسر;
	حالة KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		اكسر;
#پایان_اگر /* WITH_OPENSSL */
	حالة KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		اكسر;
	حالة KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		اكسر;
	حالة KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		اكسر;
	افتراضي:
		r = SSH_ERR_INVALID_آرگومان;
		اكسر;
	}
	إذا (r !=0 )
		اذهب بیرون;

	/* calc H */
	إذا ((server_host_کلید_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا ((r = sshkey_putb(server_host_عمومی, server_host_کلید_blob)) != 0)
		اذهب بیرون;
	hashlen = حجم(hash);
	إذا ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_نسخه,
	    kex->server_نسخه,
	    kex->peer,
	    kex->my,
	    server_host_کلید_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		اذهب بیرون;

	/* sign H */
	إذا ((r = kex->sign(ssh, server_host_خصوصی, server_host_عمومی,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		اذهب بیرون;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیام_KEX_ECDH_پاسخ)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_کلید_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		اذهب بیرون;

	إذا ((r = kex_derive_کلیدها(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		اذهب بیرون;
	/* retain copy of hostkey used at initial KEX */
	إذا (kex->initial_hostkey == عدم &&
	    (r = sshkey_from_خصوصی(server_host_عمومی,
	    &kex->initial_hostkey)) != 0)
		اذهب بیرون;
	/* success */
بیرون:
	explicit_bzero(hash, حجم(hash));
	sshbuf_free(server_host_کلید_blob);
	حرر(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	أرجع r;
}
