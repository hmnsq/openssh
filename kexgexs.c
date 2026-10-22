/* $OpenBSD: kexgexs.c,v 1.51 2026/03/03 09:57:25 dtucker Exp $ */
/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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

#جے_تعریف_شدہ WITH_OPENSSL
#ضمن "openbsd-compat/openssl-compat.h"

#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <signal.h>

#ضمن <openssl/bn.h>
#ضمن <openssl/dh.h>

#ضمن "sshkey.h"
#ضمن "cipher.h"
#ضمن "digest.h"
#ضمن "kex.h"
#ضمن "log.h"
#ضمن "packet.h"
#ضمن "dh.h"
#ضمن "ssh2.h"
#جے_تعریف_شدہ GSSAPI
#ضمن "ssh-gss.h"
#جے_انت
#ضمن "monitor_wrap.h"
#ضمن "dispatch.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "misc.h"

ساكن صحيح داخلہ_kex_dh_gex_request(صحيح, uint32_t, بنية ssh *);
ساكن صحيح داخلہ_kex_dh_gex_init(صحيح, uint32_t, بنية ssh *);

صحيح
kexgex_server(بنية ssh *ssh)
{
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_KEX_DH_GEX_REQUEST,
	    &داخلہ_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	أرجع 0;
}

ساكن صحيح
داخلہ_kex_dh_gex_request(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	صحيح r;
	u_int min = 0, max = 0, nbits = 0;
	ثابت BIGNUM *dh_p, *dh_g;

	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	إذا ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_سرا(ssh)) != 0)
		اذهب باہرلا;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = ودھ_توں_ودھ(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = ودھ_توں_ودھ(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	إذا (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_باہرلا_دا_RANGE;
		اذهب باہرلا;
	}

	/* Contact privileged parent */
	kex->dh = mm_چنو_dh(min, nbits, max);
	إذا (kex->dh == عدم) {
		(فراغ)sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	DH_get0_pqg(kex->dh, &dh_p, عدم, &dh_g);
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_KEX_DH_GEX_گروہ)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		اذهب باہرلا;

	/* Compute our exchange value in parallel with the client */
	إذا ((r = dh_gen_کلید(kex->dh, kex->we_need * 8)) != 0)
		اذهب باہرلا;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_KEX_DH_GEX_INIT, &داخلہ_kex_dh_gex_init);
	r = 0;
 باہرلا:
	أرجع r;
}

ساكن صحيح
داخلہ_kex_dh_gex_init(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	BIGNUM *dh_client_pub = عدم;
	ثابت BIGNUM *pub_کلید, *dh_p, *dh_g;
	بنية sshbuf *shared_secret = عدم;
	بنية sshbuf *server_host_کلید_blob = عدم;
	بنية sshkey *server_host_عوامی, *server_host_نجی;
	u_char *signature = عدم;
	u_char hash[SSH_DIGEST_MAX_لمائی];
	ناپ_t slen, hashlen;
	صحيح r;

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_KEX_DH_GEX_INIT, &kex_protocol_error);

	إذا ((r = kex_لدو_hostkey(ssh, &server_host_نجی,
	    &server_host_عوامی)) != 0)
		اذهب باہرلا;

	/* key, cert */
	إذا ((r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
	    (r = sshpkt_get_سرا(ssh)) != 0)
		اذهب باہرلا;
	إذا ((shared_secret = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
	إذا ((r = kex_dh_compute_کلید(kex, dh_client_pub, shared_secret)) != 0)
		اذهب باہرلا;
	إذا ((server_host_کلید_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
	إذا ((r = sshkey_putb(server_host_عوامی, server_host_کلید_blob)) != 0)
		اذهب باہرلا;

	/* calc H */
	DH_get0_کلید(kex->dh, &pub_کلید, عدم);
	DH_get0_pqg(kex->dh, &dh_p, عدم, &dh_g);
	hashlen = حجم(hash);
	إذا ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_نسخہ,
	    kex->server_نسخہ,
	    kex->peer,
	    kex->my,
	    server_host_کلید_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    dh_client_pub,
	    pub_کلید,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		اذهب باہرلا;

	/* sign H */
	إذا ((r = kex->sign(ssh, server_host_نجی, server_host_عوامی,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		اذهب باہرلا;

	/* send server hostkey, DH pubkey 'f' and signed H */
	إذا ((r = sshpkt_شروع(ssh, SSH2_پیغام_KEX_DH_GEX_جواب)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_کلید_blob)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_کلید)) != 0 ||     /* f */
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		اذهب باہرلا;

	إذا ((r = kex_derive_کلیدیں(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		اذهب باہرلا;

	/* retain copy of hostkey used at initial KEX */
	إذا (kex->initial_hostkey == عدم &&
	    (r = sshkey_from_نجی(server_host_عوامی,
	    &kex->initial_hostkey)) != 0)
		اذهب باہرلا;
	/* success */
 باہرلا:
	explicit_bzero(hash, حجم(hash));
	DH_free(kex->dh);
	kex->dh = عدم;
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_کلید_blob);
	حرر(signature);
	أرجع r;
}
#جے_انت /* WITH_OPENSSL */
