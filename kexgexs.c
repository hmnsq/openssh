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

#अन्तर्भाव "includes.h"

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <signal.h>

#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/dh.h>

#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "dh.h"
#अन्तर्भाव "ssh2.h"
#यदि_परिभाषितम् GSSAPI
#अन्तर्भाव "ssh-gss.h"
#यदि_अन्तः
#अन्तर्भाव "monitor_wrap.h"
#अन्तर्भाव "dispatch.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "misc.h"

स्थिर पूर्णाङ्क निवेशः_kex_dh_gex_request(पूर्णाङ्क, uint32_t, संरचना ssh *);
स्थिर पूर्णाङ्क निवेशः_kex_dh_gex_init(पूर्णाङ्क, uint32_t, संरचना ssh *);

पूर्णाङ्क
kexgex_server(संरचना ssh *ssh)
{
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_KEX_DH_GEX_REQUEST,
	    &निवेशः_kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
निवेशः_kex_dh_gex_request(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	पूर्णाङ्क r;
	u_int min = 0, max = 0, nbits = 0;
	ध्रुव BIGNUM *dh_p, *dh_g;

	debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_KEX_DH_GEX_REQUEST, &kex_protocol_error);

	यदि ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_अन्तः(ssh)) != 0)
		गच्छ बहिर्गमनम्;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = अधिकतमम्(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = अधिकतमम्(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	यदि (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_बहिर्गमनम्_सम्बन्धि_RANGE;
		गच्छ बहिर्गमनम्;
	}

	/* Contact privileged parent */
	kex->dh = mm_वृणु_dh(min, nbits, max);
	यदि (kex->dh == रिक्त) {
		(शून्य)sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
	DH_get0_pqg(kex->dh, &dh_p, रिक्त, &dh_g);
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_KEX_DH_GEX_गणः)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		गच्छ बहिर्गमनम्;

	/* Compute our exchange value in parallel with the client */
	यदि ((r = dh_gen_कुञ्चिका(kex->dh, kex->we_need * 8)) != 0)
		गच्छ बहिर्गमनम्;

	debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_KEX_DH_GEX_INIT, &निवेशः_kex_dh_gex_init);
	r = 0;
 बहिर्गमनम्:
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
निवेशः_kex_dh_gex_init(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	BIGNUM *dh_client_pub = रिक्त;
	ध्रुव BIGNUM *pub_कुञ्चिका, *dh_p, *dh_g;
	संरचना sshbuf *shared_secret = रिक्त;
	संरचना sshbuf *server_host_कुञ्चिका_blob = रिक्त;
	संरचना sshkey *server_host_लौकिकम्, *server_host_वैयक्तिकम्;
	u_char *signature = रिक्त;
	u_char hash[SSH_DIGEST_MAX_दीर्घता];
	आकार_t slen, hashlen;
	पूर्णाङ्क r;

	debug("SSH2_MSG_KEX_DH_GEX_INIT received");
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_KEX_DH_GEX_INIT, &kex_protocol_error);

	यदि ((r = kex_आरोपय_hostkey(ssh, &server_host_वैयक्तिकम्,
	    &server_host_लौकिकम्)) != 0)
		गच्छ बहिर्गमनम्;

	/* key, cert */
	यदि ((r = sshpkt_get_bignum2(ssh, &dh_client_pub)) != 0 ||
	    (r = sshpkt_get_अन्तः(ssh)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((shared_secret = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = kex_dh_compute_कुञ्चिका(kex, dh_client_pub, shared_secret)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((server_host_कुञ्चिका_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshkey_putb(server_host_लौकिकम्, server_host_कुञ्चिका_blob)) != 0)
		गच्छ बहिर्गमनम्;

	/* calc H */
	DH_get0_कुञ्चिका(kex->dh, &pub_कुञ्चिका, रिक्त);
	DH_get0_pqg(kex->dh, &dh_p, रिक्त, &dh_g);
	hashlen = परिमाण(hash);
	यदि ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_संस्करणम्,
	    kex->server_संस्करणम्,
	    kex->peer,
	    kex->my,
	    server_host_कुञ्चिका_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    dh_client_pub,
	    pub_कुञ्चिका,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) != 0)
		गच्छ बहिर्गमनम्;

	/* sign H */
	यदि ((r = kex->sign(ssh, server_host_वैयक्तिकम्, server_host_लौकिकम्,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		गच्छ बहिर्गमनम्;

	/* send server hostkey, DH pubkey 'f' and signed H */
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_KEX_DH_GEX_प्रत्युत्तरम्)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_कुञ्चिका_blob)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, pub_कुञ्चिका)) != 0 ||     /* f */
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		गच्छ बहिर्गमनम्;

	यदि ((r = kex_derive_कुञ्चिकाः(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		गच्छ बहिर्गमनम्;

	/* retain copy of hostkey used at initial KEX */
	यदि (kex->initial_hostkey == रिक्त &&
	    (r = sshkey_from_वैयक्तिकम्(server_host_लौकिकम्,
	    &kex->initial_hostkey)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
 बहिर्गमनम्:
	explicit_bzero(hash, परिमाण(hash));
	DH_free(kex->dh);
	kex->dh = रिक्त;
	BN_clear_free(dh_client_pub);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_कुञ्चिका_blob);
	मुक्त(signature);
	प्रत्यागम r;
}
#यदि_अन्तः /* WITH_OPENSSL */
