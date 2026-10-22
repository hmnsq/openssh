/* $OpenBSD: kexecdh.c,v 1.14 2026/08/03 06:43:16 djm Exp $ */
/*
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
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

#ଯଦି defined(WITH_OPENSSL)

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>

#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ecdh.h>

#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_ecdh_keypair(ସଂରଚନା kex *kex)
{
	EC_ଚାବି *client_ଚାବି = ଖାଲି;
	ଅଚଳ EC_GROUP *group;
	ଅଚଳ EC_POINT *public_ଚାବି;
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((client_ଚାବି = EC_ଚାବି_new_by_curve_name(kex->ec_nid)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (EC_ଚାବି_generate_ଚାବି(client_ଚାବି) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	group = EC_ଚାବି_get0_group(client_ଚାବି);
	public_ଚାବି = EC_ଚାବି_get0_public_ଚାବି(client_ଚାବି);

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_ec(buf, public_ଚାବି, group)) != 0 ||
	    (r = sshbuf_get_u32(buf, ଖାଲି)) != 0)
		ଯାଅ out;
#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_ଚାବି(client_ଚାବି);
#endif
	kex->ec_client_ଚାବି = client_ଚାବି;
	kex->ec_group = group;
	client_ଚାବି = ଖାଲି;	/* owned by the kex */
	kex->client_pub = buf;
	buf = ଖାଲି;
 out:
	EC_ଚାବି_free(client_ଚାବି);
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_ecdh_enc(ସଂରଚନା kex *kex, ଅଚଳ ସଂରଚନା sshbuf *client_blob,
    ସଂରଚନା sshbuf **server_blobp, ସଂରଚନା sshbuf **shared_secretp)
{
	ଅଚଳ EC_GROUP *group;
	ଅଚଳ EC_POINT *pub_ଚାବି;
	EC_ଚାବି *server_ଚାବି = ଖାଲି;
	ସଂରଚନା sshbuf *server_blob = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*server_blobp = ଖାଲି;
	*shared_secretp = ଖାଲି;

	ଯଦି ((server_ଚାବି = EC_ଚାବି_new_by_curve_name(kex->ec_nid)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (EC_ଚାବି_generate_ଚାବି(server_ଚାବି) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	group = EC_ଚାବି_get0_group(server_ଚାବି);

#ifdef DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_ଚାବି(server_ଚାବି);
#endif
	pub_ଚାବି = EC_ଚାବି_get0_public_ଚାବି(server_ଚାବି);
	ଯଦି ((server_blob = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_ec(server_blob, pub_ଚାବି, group)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ଖାଲି)) != 0)
		ଯାଅ out;
	ଯଦି ((r = kex_ecdh_dec_ଚାବି_group(kex, client_blob, server_ଚାବି, group,
	    0, shared_secretp)) != 0)
		ଯାଅ out;
	*server_blobp = server_blob;
	server_blob = ଖାଲି;
 out:
	EC_ଚାବି_free(server_ଚାବି);
	sshbuf_free(server_blob);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_ecdh_dec_ଚାବି_group(ସଂରଚନା kex *kex, ଅଚଳ ସଂରଚନା sshbuf *ec_blob,
    EC_ଚାବି *ଚାବି, ଅଚଳ EC_GROUP *group, ପୂର୍ଣ୍ଣସଂଖ୍ୟା raw, ସଂରଚନା sshbuf **shared_secretp)
{
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	BIGNUM *shared_secret = ଖାଲି;
	EC_POINT *dh_pub = ଖାଲି;
	u_char *kbuf = ଖାଲି;
	size_t klen = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*shared_secretp = ଖାଲି;

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		ଯାଅ out;
	ଯଦି ((dh_pub = EC_POINT_new(group)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_get_ec(buf, dh_pub, group)) != 0) {
		ଯାଅ out;
	}
	sshbuf_reset(buf);

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_point(group, dh_pub);
#endif
	ଯଦି (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		ଯାଅ out;
	}
	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	ଯଦି ((kbuf = malloc(klen)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (ECDH_compute_ଚାବି(kbuf, klen, dh_pub, ଚାବି, ଖାଲି) != (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	ଯଦି (raw) {
		ଯଦି ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			ଯାଅ out;
	} ଅନ୍ୟଥା {
		ଯଦି ((shared_secret = BN_new()) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		ଯଦି (BN_bin2bn(kbuf, klen, shared_secret) == ଖାଲି) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			ଯାଅ out;
	}
	*shared_secretp = buf;
	buf = ଖାଲି;
 out:
	EC_POINT_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_ecdh_dec(ସଂରଚନା kex *kex, ଅଚଳ ସଂରଚନା sshbuf *server_blob,
    ସଂରଚନା sshbuf **shared_secretp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	r = kex_ecdh_dec_ଚାବି_group(kex, server_blob, kex->ec_client_ଚାବି,
	    kex->ec_group, 0, shared_secretp);
	EC_ଚାବି_free(kex->ec_client_ଚାବି);
	kex->ec_client_ଚାବି = ଖାଲି;
	ଫେରନ୍ତୁ r;
}

#endif /* WITH_OPENSSL */
