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

#અન્તર્ભાવ "includes.h"

#ifdef WITH_OPENSSL
#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <signal.h>

#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/dh.h>

#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "dh.h"
#અન્તર્ભાવ "log.h"

પૂર્ણાંક
kex_dh_keygen(સંરચના kex *kex)
{
	પસંદગી (kex->kex_type) {
	સ્થિતિ KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		તોડો;
	સ્થિતિ KEX_DH_GRP14_SHA1:
	સ્થિતિ KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		તોડો;
	સ્થિતિ KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		તોડો;
	સ્થિતિ KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		તોડો;
	મૂળભૂત:
		પાછા SSH_ERR_INVALID_ARGUMENT;
	}
	જો (kex->dh == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	પાછા (dh_gen_ચાવી(kex->dh, kex->we_need * 8));
}

પૂર્ણાંક
kex_dh_compute_ચાવી(સંરચના kex *kex, BIGNUM *dh_pub, સંરચના sshbuf *out)
{
	BIGNUM *shared_secret = ખાલી;
	u_char *kbuf = ખાલી;
	size_t klen = 0;
	પૂર્ણાંક kout, r;

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_અંક_bits(dh_pub));
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "\n");
#endif

	જો (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		જાઓ out;
	}
	klen = DH_size(kex->dh);
	જો ((kbuf = malloc(klen)) == ખાલી ||
	    (shared_secret = BN_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((kout = DH_compute_ચાવી(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == ખાલી) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif
	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	પાછા r;
}

પૂર્ણાંક
kex_dh_keypair(સંરચના kex *kex)
{
	અચલ BIGNUM *pub_ચાવી;
	સંરચના sshbuf *buf = ખાલી;
	પૂર્ણાંક r;

	જો ((r = kex_dh_keygen(kex)) != 0)
		પાછા r;
	DH_get0_ચાવી(kex->dh, &pub_ચાવી, ખાલી);
	જો ((buf = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put_bignum2(buf, pub_ચાવી)) != 0 ||
	    (r = sshbuf_get_u32(buf, ખાલી)) != 0)
		જાઓ out;
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_ચાવી);
	fprintf(stderr, "\n");
#endif
	kex->client_pub = buf;
	buf = ખાલી;
 out:
	sshbuf_free(buf);
	પાછા r;
}

પૂર્ણાંક
kex_dh_enc(સંરચના kex *kex, અચલ સંરચના sshbuf *client_blob,
    સંરચના sshbuf **server_blobp, સંરચના sshbuf **shared_secretp)
{
	અચલ BIGNUM *pub_ચાવી;
	સંરચના sshbuf *server_blob = ખાલી;
	પૂર્ણાંક r;

	*server_blobp = ખાલી;
	*shared_secretp = ખાલી;

	જો ((r = kex_dh_keygen(kex)) != 0)
		જાઓ out;
	DH_get0_ચાવી(kex->dh, &pub_ચાવી, ખાલી);
	જો ((server_blob = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_put_bignum2(server_blob, pub_ચાવી)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ખાલી)) != 0)
		જાઓ out;
	જો ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		જાઓ out;
	*server_blobp = server_blob;
	server_blob = ખાલી;
 out:
	DH_free(kex->dh);
	kex->dh = ખાલી;
	sshbuf_free(server_blob);
	પાછા r;
}

પૂર્ણાંક
kex_dh_dec(સંરચના kex *kex, અચલ સંરચના sshbuf *dh_blob,
    સંરચના sshbuf **shared_secretp)
{
	સંરચના sshbuf *buf = ખાલી;
	BIGNUM *dh_pub = ખાલી;
	પૂર્ણાંક r;

	*shared_secretp = ખાલી;

	જો ((buf = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		જાઓ out;
	sshbuf_reset(buf);
	જો ((r = kex_dh_compute_ચાવી(kex, dh_pub, buf)) != 0)
		જાઓ out;
	*shared_secretp = buf;
	buf = ખાલી;
 out:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = ખાલી;
	sshbuf_free(buf);
	પાછા r;
}
#endif /* WITH_OPENSSL */
