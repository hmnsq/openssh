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

#அந்தர்பாவ "includes.h"

#ifdef WITH_OPENSSL
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <signal.h>

#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/dh.h>

#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "dh.h"
#அந்தர்பாவ "log.h"

முழு
kex_dh_keygen(கட்டமைப்பு kex *kex)
{
	தேர்வு (kex->kex_type) {
	நிலை KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		நிறுத்து;
	நிலை KEX_DH_GRP14_SHA1:
	நிலை KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		நிறுத்து;
	நிலை KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		நிறுத்து;
	நிலை KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		நிறுத்து;
	இயல்பு:
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	}
	எனில் (kex->dh == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	திரும்பு (dh_gen_சாவி(kex->dh, kex->we_need * 8));
}

முழு
kex_dh_compute_சாவி(கட்டமைப்பு kex *kex, BIGNUM *dh_pub, கட்டமைப்பு sshbuf *out)
{
	BIGNUM *shared_secret = வெற்று;
	u_char *kbuf = வெற்று;
	size_t klen = 0;
	முழு kout, r;

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_இலக்கம்_bits(dh_pub));
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "\n");
#endif

	எனில் (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		செல் out;
	}
	klen = DH_size(kex->dh);
	எனில் ((kbuf = malloc(klen)) == வெற்று ||
	    (shared_secret = BN_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((kout = DH_compute_சாவி(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == வெற்று) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif
	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	திரும்பு r;
}

முழு
kex_dh_keypair(கட்டமைப்பு kex *kex)
{
	மாறிலி BIGNUM *pub_சாவி;
	கட்டமைப்பு sshbuf *buf = வெற்று;
	முழு r;

	எனில் ((r = kex_dh_keygen(kex)) != 0)
		திரும்பு r;
	DH_get0_சாவி(kex->dh, &pub_சாவி, வெற்று);
	எனில் ((buf = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_put_bignum2(buf, pub_சாவி)) != 0 ||
	    (r = sshbuf_get_u32(buf, வெற்று)) != 0)
		செல் out;
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_சாவி);
	fprintf(stderr, "\n");
#endif
	kex->client_pub = buf;
	buf = வெற்று;
 out:
	sshbuf_free(buf);
	திரும்பு r;
}

முழு
kex_dh_enc(கட்டமைப்பு kex *kex, மாறிலி கட்டமைப்பு sshbuf *client_blob,
    கட்டமைப்பு sshbuf **server_blobp, கட்டமைப்பு sshbuf **shared_secretp)
{
	மாறிலி BIGNUM *pub_சாவி;
	கட்டமைப்பு sshbuf *server_blob = வெற்று;
	முழு r;

	*server_blobp = வெற்று;
	*shared_secretp = வெற்று;

	எனில் ((r = kex_dh_keygen(kex)) != 0)
		செல் out;
	DH_get0_சாவி(kex->dh, &pub_சாவி, வெற்று);
	எனில் ((server_blob = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_put_bignum2(server_blob, pub_சாவி)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, வெற்று)) != 0)
		செல் out;
	எனில் ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		செல் out;
	*server_blobp = server_blob;
	server_blob = வெற்று;
 out:
	DH_free(kex->dh);
	kex->dh = வெற்று;
	sshbuf_free(server_blob);
	திரும்பு r;
}

முழு
kex_dh_dec(கட்டமைப்பு kex *kex, மாறிலி கட்டமைப்பு sshbuf *dh_blob,
    கட்டமைப்பு sshbuf **shared_secretp)
{
	கட்டமைப்பு sshbuf *buf = வெற்று;
	BIGNUM *dh_pub = வெற்று;
	முழு r;

	*shared_secretp = வெற்று;

	எனில் ((buf = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		செல் out;
	sshbuf_reset(buf);
	எனில் ((r = kex_dh_compute_சாவி(kex, dh_pub, buf)) != 0)
		செல் out;
	*shared_secretp = buf;
	buf = வெற்று;
 out:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = வெற்று;
	sshbuf_free(buf);
	திரும்பு r;
}
#endif /* WITH_OPENSSL */
