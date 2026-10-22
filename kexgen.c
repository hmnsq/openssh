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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <signal.h>

#شامل "sshkey.h"
#شامل "kex.h"
#شامل "log.h"
#شامل "packet.h"
#شامل "ssh2.h"
#شامل "sshbuf.h"
#شامل "digest.h"
#شامل "ssherr.h"

ساکن صحیح داخلہ_kex_gen_init(صحیح, uint32_t, ساخت ssh *);
ساکن صحیح داخلہ_kex_gen_جواب(صحیح type, uint32_t seq, ساخت ssh *ssh);

ساکن صحیح
kex_gen_hash(
    صحیح hash_alg,
    ثابت ساخت sshbuf *client_نسخہ,
    ثابت ساخت sshbuf *server_نسخہ,
    ثابت ساخت sshbuf *client_kexinit,
    ثابت ساخت sshbuf *server_kexinit,
    ثابت ساخت sshbuf *server_host_کلید_blob,
    ثابت ساخت sshbuf *client_pub,
    ثابت ساخت sshbuf *server_pub,
    ثابت ساخت sshbuf *shared_secret,
    u_char *hash, سائز_t *hashlen)
{
	ساخت sshbuf *b;
	صحیح r;

	اگر (*hashlen < ssh_digest_بائٹیں(hash_alg))
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((b = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_stringb(b, client_نسخہ)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_نسخہ)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیغام_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_پیغام_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_کلید_blob)) != 0 ||
	    (r = sshbuf_put_stringb(b, client_pub)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_pub)) != 0 ||
	    (r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		واپس r;
	}
#اگر_تعریف_شدہ DEBUG_KEX
	sshbuf_dump(b, stderr);
#اگر_ختم
	اگر (ssh_digest_بفر(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		واپس SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_بائٹیں(hash_alg);
#اگر_تعریف_شدہ DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#اگر_ختم
	واپس 0;
}

صحیح
kex_gen_client(ساخت ssh *ssh)
{
	ساخت kex *kex = ssh->kex;
	صحیح r;

	انتخاب (kex->kex_type) {
#اگر_تعریف_شدہ WITH_OPENSSL
	حالت KEX_DH_GRP1_SHA1:
	حالت KEX_DH_GRP14_SHA1:
	حالت KEX_DH_GRP14_SHA256:
	حالت KEX_DH_GRP16_SHA512:
	حالت KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		توڑو;
	حالت KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		توڑو;
	حالت KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_keypair(kex);
		توڑو;
#اگر_ختم /* WITH_OPENSSL */
	حالت KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		توڑو;
	حالت KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		توڑو;
	حالت KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_keypair(kex);
		توڑو;
	طےشدہ:
		r = SSH_ERR_INVALID_دلیل;
		توڑو;
	}
	اگر (r != 0)
		واپس r;
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_KEX_ECDH_INIT)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		واپس r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_KEX_ECDH_جواب, &داخلہ_kex_gen_جواب);
	واپس 0;
}

ساکن صحیح
داخلہ_kex_gen_جواب(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	ساخت kex *kex = ssh->kex;
	ساخت sshkey *server_host_کلید = تہی;
	ساخت sshbuf *shared_secret = تہی;
	ساخت sshbuf *server_blob = تہی;
	ساخت sshbuf *tmp = تہی, *server_host_کلید_blob = تہی;
	u_char *signature = تہی;
	u_char hash[SSH_DIGEST_MAX_لمبائی];
	سائز_t slen, hashlen;
	صحیح r;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_KEX_ECDH_جواب, &kex_protocol_error);

	/* hostkey */
	اگر ((r = sshpkt_getb_froms(ssh, &server_host_کلید_blob)) != 0)
		جاؤ برآمد;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	اگر ((tmp = sshbuf_fromb(server_host_کلید_blob)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshkey_fromb_allowlist(tmp, &server_host_کلید,
	    kex->hostkey_alg, تہی)) != 0)
		جاؤ برآمد;
	اگر ((r = kex_verify_host_کلید(ssh, server_host_کلید)) != 0)
		جاؤ برآمد;

	/* Q_S, server public key */
	/* signed H */
	اگر ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		جاؤ برآمد;

	/* compute shared secret */
	انتخاب (kex->kex_type) {
#اگر_تعریف_شدہ WITH_OPENSSL
	حالت KEX_DH_GRP1_SHA1:
	حالت KEX_DH_GRP14_SHA1:
	حالت KEX_DH_GRP14_SHA256:
	حالت KEX_DH_GRP16_SHA512:
	حالت KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		توڑو;
	حالت KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		توڑو;
	حالت KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_dec(kex, server_blob,
		    &shared_secret);
		توڑو;
#اگر_ختم /* WITH_OPENSSL */
	حالت KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		توڑو;
	حالت KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
		    &shared_secret);
		توڑو;
	حالت KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_dec(kex, server_blob,
		    &shared_secret);
		توڑو;
	طےشدہ:
		r = SSH_ERR_INVALID_دلیل;
		توڑو;
	}
	اگر (r !=0 )
		جاؤ برآمد;

	/* calc and verify H */
	hashlen = حجم(hash);
	اگر ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_نسخہ,
	    kex->server_نسخہ,
	    kex->my,
	    kex->peer,
	    server_host_کلید_blob,
	    kex->client_pub,
	    server_blob,
	    shared_secret,
	    hash, &hashlen)) != 0)
		جاؤ برآمد;

	اگر ((r = sshkey_verify(server_host_کلید, signature, slen, hash, hashlen,
	    kex->hostkey_alg, ssh->compat, تہی)) != 0)
		جاؤ برآمد;

	اگر ((r = kex_derive_کلیدیں(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		جاؤ برآمد;

	/* save initial signature and hostkey */
	اگر ((kex->flags & KEX_INITIAL) != 0) {
		اگر (kex->initial_hostkey != تہی || kex->initial_sig != تہی) {
			r = SSH_ERR_اندرونی_ERROR;
			جاؤ برآمد;
		}
		اگر ((kex->initial_sig = sshbuf_new()) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		اگر ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			جاؤ برآمد;
		kex->initial_hostkey = server_host_کلید;
		server_host_کلید = تہی;
	}
	/* success */
برآمد:
	explicit_bzero(hash, حجم(hash));
	explicit_bzero(kex->c25519_client_کلید, حجم(kex->c25519_client_کلید));
	explicit_bzero(kex->sntrup761_client_کلید,
	    حجم(kex->sntrup761_client_کلید));
	explicit_bzero(kex->mlkem768_client_کلید,
	    حجم(kex->mlkem768_client_کلید));
	sshbuf_free(server_host_کلید_blob);
	آزاد(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_کلید);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = تہی;
	واپس r;
}

صحیح
kex_gen_server(ساخت ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_KEX_ECDH_INIT, &داخلہ_kex_gen_init);
	واپس 0;
}

ساکن صحیح
داخلہ_kex_gen_init(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	ساخت kex *kex = ssh->kex;
	ساخت sshkey *server_host_نجی, *server_host_عوامی;
	ساخت sshbuf *shared_secret = تہی;
	ساخت sshbuf *server_pubkey = تہی;
	ساخت sshbuf *client_pubkey = تہی;
	ساخت sshbuf *server_host_کلید_blob = تہی;
	u_char *signature = تہی, hash[SSH_DIGEST_MAX_لمبائی];
	سائز_t slen, hashlen;
	صحیح r;

	debug("SSH2_MSG_KEX_ECDH_INIT received");
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_KEX_ECDH_INIT, &kex_protocol_error);

	اگر ((r = kex_بھرو_hostkey(ssh, &server_host_نجی,
	    &server_host_عوامی)) != 0)
		جاؤ برآمد;

	اگر ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		جاؤ برآمد;

	/* compute shared secret */
	انتخاب (kex->kex_type) {
#اگر_تعریف_شدہ WITH_OPENSSL
	حالت KEX_DH_GRP1_SHA1:
	حالت KEX_DH_GRP14_SHA1:
	حالت KEX_DH_GRP14_SHA256:
	حالت KEX_DH_GRP16_SHA512:
	حالت KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		توڑو;
	حالت KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		توڑو;
	حالت KEX_KEM_MLKEM768ECDH_SHA256:
		r = kex_kem_mlkem768ecdh_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		توڑو;
#اگر_ختم /* WITH_OPENSSL */
	حالت KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
		    &shared_secret);
		توڑو;
	حالت KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		توڑو;
	حالت KEX_KEM_MLKEM768X25519_SHA256:
		r = kex_kem_mlkem768x25519_enc(kex, client_pubkey,
		    &server_pubkey, &shared_secret);
		توڑو;
	طےشدہ:
		r = SSH_ERR_INVALID_دلیل;
		توڑو;
	}
	اگر (r !=0 )
		جاؤ برآمد;

	/* calc H */
	اگر ((server_host_کلید_blob = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshkey_putb(server_host_عوامی, server_host_کلید_blob)) != 0)
		جاؤ برآمد;
	hashlen = حجم(hash);
	اگر ((r = kex_gen_hash(
	    kex->hash_alg,
	    kex->client_نسخہ,
	    kex->server_نسخہ,
	    kex->peer,
	    kex->my,
	    server_host_کلید_blob,
	    client_pubkey,
	    server_pubkey,
	    shared_secret,
	    hash, &hashlen)) != 0)
		جاؤ برآمد;

	/* sign H */
	اگر ((r = kex->sign(ssh, server_host_نجی, server_host_عوامی,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		جاؤ برآمد;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	اگر ((r = sshpkt_آغاز(ssh, SSH2_پیغام_KEX_ECDH_جواب)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_کلید_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		جاؤ برآمد;

	اگر ((r = kex_derive_کلیدیں(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		جاؤ برآمد;
	/* retain copy of hostkey used at initial KEX */
	اگر (kex->initial_hostkey == تہی &&
	    (r = sshkey_from_نجی(server_host_عوامی,
	    &kex->initial_hostkey)) != 0)
		جاؤ برآمد;
	/* success */
برآمد:
	explicit_bzero(hash, حجم(hash));
	sshbuf_free(server_host_کلید_blob);
	آزاد(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	واپس r;
}
