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

#অন্তর্ভাব "includes.h"

#ifdef WITH_OPENSSL
#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <signal.h>

#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/dh.h>

#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "dh.h"
#অন্তর্ভাব "log.h"

পূর্ণসংখ্যা
kex_dh_keygen(কাঠামো kex *kex)
{
	নির্বাচন (kex->kex_type) {
	ক্ষেত্র KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		বিরতি;
	ক্ষেত্র KEX_DH_GRP14_SHA1:
	ক্ষেত্র KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		বিরতি;
	ক্ষেত্র KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		বিরতি;
	ক্ষেত্র KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		বিরতি;
	পূর্বনির্ধারিত:
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	}
	যদি (kex->dh == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	ফেরত (dh_gen_চাবি(kex->dh, kex->we_need * 8));
}

পূর্ণসংখ্যা
kex_dh_compute_চাবি(কাঠামো kex *kex, BIGNUM *dh_pub, কাঠামো sshbuf *out)
{
	BIGNUM *shared_secret = ফাঁকা;
	u_char *kbuf = ফাঁকা;
	আকার_t klen = 0;
	পূর্ণসংখ্যা kout, r;

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_অঙ্ক_bits(dh_pub));
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "\n");
#endif

	যদি (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		যাও out;
	}
	klen = DH_আকার(kex->dh);
	যদি ((kbuf = malloc(klen)) == ফাঁকা ||
	    (shared_secret = BN_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((kout = DH_compute_চাবি(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == ফাঁকা) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif
	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	ফেরত r;
}

পূর্ণসংখ্যা
kex_dh_keypair(কাঠামো kex *kex)
{
	ধ্রুবক BIGNUM *pub_চাবি;
	কাঠামো sshbuf *buf = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি ((r = kex_dh_keygen(kex)) != 0)
		ফেরত r;
	DH_get0_চাবি(kex->dh, &pub_চাবি, ফাঁকা);
	যদি ((buf = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_bignum2(buf, pub_চাবি)) != 0 ||
	    (r = sshbuf_get_u32(buf, ফাঁকা)) != 0)
		যাও out;
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_চাবি);
	fprintf(stderr, "\n");
#endif
	kex->client_pub = buf;
	buf = ফাঁকা;
 out:
	sshbuf_free(buf);
	ফেরত r;
}

পূর্ণসংখ্যা
kex_dh_enc(কাঠামো kex *kex, ধ্রুবক কাঠামো sshbuf *client_blob,
    কাঠামো sshbuf **server_blobp, কাঠামো sshbuf **shared_secretp)
{
	ধ্রুবক BIGNUM *pub_চাবি;
	কাঠামো sshbuf *server_blob = ফাঁকা;
	পূর্ণসংখ্যা r;

	*server_blobp = ফাঁকা;
	*shared_secretp = ফাঁকা;

	যদি ((r = kex_dh_keygen(kex)) != 0)
		যাও out;
	DH_get0_চাবি(kex->dh, &pub_চাবি, ফাঁকা);
	যদি ((server_blob = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_put_bignum2(server_blob, pub_চাবি)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ফাঁকা)) != 0)
		যাও out;
	যদি ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		যাও out;
	*server_blobp = server_blob;
	server_blob = ফাঁকা;
 out:
	DH_free(kex->dh);
	kex->dh = ফাঁকা;
	sshbuf_free(server_blob);
	ফেরত r;
}

পূর্ণসংখ্যা
kex_dh_dec(কাঠামো kex *kex, ধ্রুবক কাঠামো sshbuf *dh_blob,
    কাঠামো sshbuf **shared_secretp)
{
	কাঠামো sshbuf *buf = ফাঁকা;
	BIGNUM *dh_pub = ফাঁকা;
	পূর্ণসংখ্যা r;

	*shared_secretp = ফাঁকা;

	যদি ((buf = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		যাও out;
	sshbuf_reset(buf);
	যদি ((r = kex_dh_compute_চাবি(kex, dh_pub, buf)) != 0)
		যাও out;
	*shared_secretp = buf;
	buf = ফাঁকা;
 out:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = ফাঁকা;
	sshbuf_free(buf);
	ফেরত r;
}
#endif /* WITH_OPENSSL */
