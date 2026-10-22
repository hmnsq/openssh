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

ساكن صحيح ننوت_kex_gen_init(صحيح, uint32_t, بنية ssh *);
ساكن صحيح ننوت_kex_gen_ځواب(صحيح type, uint32_t seq, بنية ssh *ssh);

ساكن صحيح
kex_gen_hash(
    صحيح hash_alg,
    ثابت بنية sshbuf *client_نسخه,
    ثابت بنية sshbuf *server_نسخه,
    ثابت بنية sshbuf *client_kexinit,
    ثابت بنية sshbuf *server_kexinit,
    ثابت بنية sshbuf *server_host_کلی_blob,
    ثابت بنية sshbuf *client_pub,
    ثابت بنية sshbuf *server_pub,
    ثابت بنية sshbuf *shared_secret,
    u_char *hash, اندازه_t *hashlen)
{
	بنية sshbuf *b;
	صحيح r;

	إذا (*hashlen < ssh_digest_بایټونه(hash_alg))
		أرجع SSH_ERR_INVALID_دلیل;
	إذا ((b = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_stringb(b, client_نسخه)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_نسخه)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیغام_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیغام_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_کلی_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		أرجع r;
	}
#که_تعریف_شوی DEBUG_KEX
	sshbuf_dump(b, stderr);
#د_که_پای
	إذا (ssh_digest_بفر(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		أرجع SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_بایټونه(hash_alg);
#که_تعریف_شوی DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#د_که_پای
	أرجع 0;
}

صحيح
kex_gen_client(بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	صحيح r;

	بدل (kex->kex_type) {
#که_تعریف_شوی WITH_OPENSSL
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
#د_که_پای /* WITH_OPENSSL */
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
		r = SSH_ERR_INVALID_دلیل;
		اكسر;
	}
	إذا (r != 0)
		أرجع r;
	إذا ((r = sshpkt_پیل(ssh, SSH2_پیغام_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		أرجع r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_سېټ(ssh, SSH2_پیغام_KEX_ECDH_ځواب, &ننوت_kex_gen_ځواب);
	أرجع 0;
}

ساكن صحيح
ننوت_kex_gen_ځواب(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	بنية sshkey *server_host_کلی = عدم;
	بنية sshbuf *shared_secret = عدم;
	بنية sshbuf *server_blob = عدم;
	بنية sshbuf *tmp = عدم, *server_host_کلی_blob = عدم;
	u_char *signature = عدم;
	u_char hash[SSH_DIGEST_MAX_اوږدتیا];
	اندازه_t slen, hashlen;
	صحيح r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_سېټ(ssh, SSH2_پیغام_KEX_ECDH_ځواب, &kex_protocol_error);

	/* hostkey */
	إذا ((r = sshpkt_getb_froms(ssh, &server_host_کلی_blob)) != 0)
		اذهب بهر;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	إذا ((tmp = sshbuf_fromb(server_host_کلی_blob)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = sshkey_fromb_allowlist(tmp, &server_host_کلی,
	    kex->hostkey_alg, عدم)) != 0)
		اذهب بهر;
	إذا ((r = kex_verify_host_کلی(ssh, server_host_کلی)) != 0)
		اذهب بهر;

	/* Q_S, server public key */
	/* signed H */
	إذا ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_پای_ټکی(ssh)) != 0)
		اذهب بهر;

	/* compute shared secret */
	بدل (kex->kex_type) {
#که_تعریف_شوی WITH_OPENSSL
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
#د_که_پای /* WITH_OPENSSL */
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
		r = SSH_ERR_INVALID_دلیل;
		اكسر;
	}
	إذا (r !=0 )
		اذهب بهر;

	/* calc and verify H */
	hashlen = حجم(hash);
	إذا ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_نسخه,
	    kex->server_نسخه,
	    kex->my,
	    kex->peer,
	    server_host_کلی_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		اذهب بهر;

	إذا ((r = sshkey_verify(server_host_کلی, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, عدم)) != 0)
		اذهب بهر;

	إذا ((r = kex_derive_کلیګانې(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		اذهب بهر;

	/* save initial signature and hostkey */
	إذا ((kex->flags & KEX_INITIAL) != 0) {
		إذا (kex->initial_hostkey != عدم || kex->initial_sig != عدم) {
			r = SSH_ERR_دننی_ERROR;
			اذهب بهر;
		}
		إذا ((kex->initial_sig = sshbuf_new()) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بهر;
		}
		إذا ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			اذهب بهر;
		kex->initial_hostkey = server_host_کلی;
		server_host_کلی = عدم;
	}
	/* success */
بهر:
	explicit_bzero(hash, حجم(hash));
	explicit_bzero(kex->c25519_client_کلی, حجم(kex->c25519_client_کلی));
	explicit_bzero(kex->sntrup761_client_کلی,
	    حجم(kex->sntrup761_client_کلی));
	explicit_bzero(kex->mlkem768_client_کلی,
	    حجم(kex->mlkem768_client_کلی));
	sshbuf_free(server_host_کلی_blob);
	حرر(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_کلی);
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
	ssh_dispatch_سېټ(ssh, SSH2_پیغام_KEX_ECDH_INIT, &ننوت_kex_gen_init);
	أرجع 0;
}

ساكن صحيح
ننوت_kex_gen_init(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	بنية sshkey *server_host_شخصي, *server_host_عامه;
	بنية sshbuf *shared_secret = عدم;
	بنية sshbuf *server_pubkey = عدم;
	بنية sshbuf *client_pubkey = عدم;
	بنية sshbuf *server_host_کلی_blob = عدم;
	u_char *signature = عدم, hash[SSH_DIGEST_MAX_اوږدتیا];
	اندازه_t slen, hashlen;
	صحيح r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_سېټ(ssh, SSH2_پیغام_KEX_ECDH_INIT, &kex_protocol_error);

	إذا ((r = kex_بارول_hostkey(ssh, &server_host_شخصي,
	    &server_host_عامه)) != 0)
		اذهب بهر;

	إذا ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_پای_ټکی(ssh)) != 0)
		اذهب بهر;

	/* compute shared secret */
	بدل (kex->kex_type) {
#که_تعریف_شوی WITH_OPENSSL
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
#د_که_پای /* WITH_OPENSSL */
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
		r = SSH_ERR_INVALID_دلیل;
		اكسر;
	}
	إذا (r !=0 )
		اذهب بهر;

	/* calc H */
	إذا ((server_host_کلی_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = sshkey_putb(server_host_عامه, server_host_کلی_blob)) != 0)
		اذهب بهر;
	hashlen = حجم(hash);
	إذا ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_نسخه,
	    kex->server_نسخه,
	    kex->peer,
	    kex->my,
	    server_host_کلی_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		اذهب بهر;

	/* sign H */
	إذا ((r = kex->sign(ssh, server_host_شخصي, server_host_عامه,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		اذهب بهر;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	إذا ((r = sshpkt_پیل(ssh, SSH2_پیغام_KEX_ECDH_ځواب)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_کلی_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		اذهب بهر;

	إذا ((r = kex_derive_کلیګانې(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		اذهب بهر;
	/* retain copy of hostkey used at initial KEX */
	إذا (kex->initial_hostkey == عدم &&
	    (r = sshkey_from_شخصي(server_host_عامه,
	    &kex->initial_hostkey)) != 0)
		اذهب بهر;
	/* success */
بهر:
	explicit_bzero(hash, حجم(hash));
	sshbuf_free(server_host_کلی_blob);
	حرر(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	أرجع r;
}
