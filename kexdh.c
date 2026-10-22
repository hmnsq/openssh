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

#অন্তর্ভাৱ "includes.h"

#ifdef WITH_OPENSSL
#অন্তর্ভাৱ "openbsd-compat/openssl-compat.h"

#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <signal.h>

#অন্তর্ভাৱ <openssl/bn.h>
#অন্তর্ভাৱ <openssl/dh.h>

#অন্তর্ভাৱ "kex.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "dh.h"
#অন্তর্ভাৱ "log.h"

পূর্ণাঙ্ক
kex_dh_keygen(সংরচনা kex *kex)
{
	ৱিকল্প (kex->kex_type) {
	পক্ষ KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		ভঙ্গ;
	পক্ষ KEX_DH_GRP14_SHA1:
	পক্ষ KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		ভঙ্গ;
	পক্ষ KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		ভঙ্গ;
	পক্ষ KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		ভঙ্গ;
	স্ৱভাৱ:
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	}
	যদি (kex->dh == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	ঘূৰাই (dh_gen_চাবি(kex->dh, kex->we_need * 8));
}

পূর্ণাঙ্ক
kex_dh_compute_চাবি(সংরচনা kex *kex, BIGNUM *dh_pub, সংরচনা sshbuf *out)
{
	BIGNUM *shared_secret = রিক্ত;
	u_char *kbuf = রিক্ত;
	size_t klen = 0;
	পূর্ণাঙ্ক kout, r;

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
		গচ্ছ out;
	}
	klen = DH_size(kex->dh);
	যদি ((kbuf = malloc(klen)) == রিক্ত ||
	    (shared_secret = BN_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((kout = DH_compute_চাবি(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == রিক্ত) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif
	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	ঘূৰাই r;
}

পূর্ণাঙ্ক
kex_dh_keypair(সংরচনা kex *kex)
{
	ধ্রুৱ BIGNUM *pub_চাবি;
	সংরচনা sshbuf *buf = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি ((r = kex_dh_keygen(kex)) != 0)
		ঘূৰাই r;
	DH_get0_চাবি(kex->dh, &pub_চাবি, রিক্ত);
	যদি ((buf = sshbuf_new()) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_bignum2(buf, pub_চাবি)) != 0 ||
	    (r = sshbuf_get_u32(buf, রিক্ত)) != 0)
		গচ্ছ out;
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_চাবি);
	fprintf(stderr, "\n");
#endif
	kex->client_pub = buf;
	buf = রিক্ত;
 out:
	sshbuf_free(buf);
	ঘূৰাই r;
}

পূর্ণাঙ্ক
kex_dh_enc(সংরচনা kex *kex, ধ্রুৱ সংরচনা sshbuf *client_blob,
    সংরচনা sshbuf **server_blobp, সংরচনা sshbuf **shared_secretp)
{
	ধ্রুৱ BIGNUM *pub_চাবি;
	সংরচনা sshbuf *server_blob = রিক্ত;
	পূর্ণাঙ্ক r;

	*server_blobp = রিক্ত;
	*shared_secretp = রিক্ত;

	যদি ((r = kex_dh_keygen(kex)) != 0)
		গচ্ছ out;
	DH_get0_চাবি(kex->dh, &pub_চাবি, রিক্ত);
	যদি ((server_blob = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_put_bignum2(server_blob, pub_চাবি)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, রিক্ত)) != 0)
		গচ্ছ out;
	যদি ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		গচ্ছ out;
	*server_blobp = server_blob;
	server_blob = রিক্ত;
 out:
	DH_free(kex->dh);
	kex->dh = রিক্ত;
	sshbuf_free(server_blob);
	ঘূৰাই r;
}

পূর্ণাঙ্ক
kex_dh_dec(সংরচনা kex *kex, ধ্রুৱ সংরচনা sshbuf *dh_blob,
    সংরচনা sshbuf **shared_secretp)
{
	সংরচনা sshbuf *buf = রিক্ত;
	BIGNUM *dh_pub = রিক্ত;
	পূর্ণাঙ্ক r;

	*shared_secretp = রিক্ত;

	যদি ((buf = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		গচ্ছ out;
	sshbuf_reset(buf);
	যদি ((r = kex_dh_compute_চাবি(kex, dh_pub, buf)) != 0)
		গচ্ছ out;
	*shared_secretp = buf;
	buf = রিক্ত;
 out:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = রিক্ত;
	sshbuf_free(buf);
	ঘূৰাই r;
}
#endif /* WITH_OPENSSL */
