/* $OpenBSD: kexdh.c,v 1.36 2026/02/14 00:18:34 jsg Exp $ */
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

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>

#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/dh.h>

#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "dh.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_dh_keygen(ସଂରଚନା kex *kex)
{
	ବାଛ (kex->kex_type) {
	ସ୍ଥିତି KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KEX_DH_GRP14_SHA1:
	ସ୍ଥିତି KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	}
	ଯଦି (kex->dh == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଫେରନ୍ତୁ (dh_gen_ଚାବି(kex->dh, kex->we_need * 8));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_dh_compute_ଚାବି(ସଂରଚନା kex *kex, BIGNUM *dh_pub, ସଂରଚନା sshbuf *out)
{
	BIGNUM *shared_secret = ଖାଲି;
	u_char *kbuf = ଖାଲି;
	size_t klen = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା kout, r;

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_ଅଙ୍କ_bits(dh_pub));
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "\n");
#endif

	ଯଦି (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		ଯାଅ out;
	}
	klen = DH_size(kex->dh);
	ଯଦି ((kbuf = malloc(klen)) == ଖାଲି ||
	    (shared_secret = BN_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((kout = DH_compute_ଚାବି(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == ଖାଲି) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif
	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_dh_keypair(ସଂରଚନା kex *kex)
{
	ଅଚଳ BIGNUM *pub_ଚାବି;
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = kex_dh_keygen(kex)) != 0)
		ଫେରନ୍ତୁ r;
	DH_get0_ଚାବି(kex->dh, &pub_ଚାବି, ଖାଲି);
	ଯଦି ((buf = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_put_bignum2(buf, pub_ଚାବି)) != 0 ||
	    (r = sshbuf_get_u32(buf, ଖାଲି)) != 0)
		ଯାଅ out;
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_ଚାବି);
	fprintf(stderr, "\n");
#endif
	kex->client_pub = buf;
	buf = ଖାଲି;
 out:
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_dh_enc(ସଂରଚନା kex *kex, ଅଚଳ ସଂରଚନା sshbuf *client_blob,
    ସଂରଚନା sshbuf **server_blobp, ସଂରଚନା sshbuf **shared_secretp)
{
	ଅଚଳ BIGNUM *pub_ଚାବି;
	ସଂରଚନା sshbuf *server_blob = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*server_blobp = ଖାଲି;
	*shared_secretp = ଖାଲି;

	ଯଦି ((r = kex_dh_keygen(kex)) != 0)
		ଯାଅ out;
	DH_get0_ଚାବି(kex->dh, &pub_ଚାବି, ଖାଲି);
	ଯଦି ((server_blob = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_bignum2(server_blob, pub_ଚାବି)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ଖାଲି)) != 0)
		ଯାଅ out;
	ଯଦି ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		ଯାଅ out;
	*server_blobp = server_blob;
	server_blob = ଖାଲି;
 out:
	DH_free(kex->dh);
	kex->dh = ଖାଲି;
	sshbuf_free(server_blob);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_dh_dec(ସଂରଚନା kex *kex, ଅଚଳ ସଂରଚନା sshbuf *dh_blob,
    ସଂରଚନା sshbuf **shared_secretp)
{
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	BIGNUM *dh_pub = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*shared_secretp = ଖାଲି;

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		ଯାଅ out;
	sshbuf_reset(buf);
	ଯଦି ((r = kex_dh_compute_ଚାବି(kex, dh_pub, buf)) != 0)
		ଯାଅ out;
	*shared_secretp = buf;
	buf = ଖାଲି;
 out:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = ଖାଲି;
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}
#endif /* WITH_OPENSSL */
