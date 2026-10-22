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

#अन्तर्भाव "includes.h"

#ifdef WITH_OPENSSL
#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <signal.h>

#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/dh.h>

#अन्तर्भाव "kex.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "dh.h"
#अन्तर्भाव "log.h"

पूर्णाङ्क
kex_dh_keygen(संरचना kex *kex)
{
	विकल्प (kex->kex_type) {
	पक्ष KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		भङ्ग;
	पक्ष KEX_DH_GRP14_SHA1:
	पक्ष KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		भङ्ग;
	पक्ष KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		भङ्ग;
	पक्ष KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		भङ्ग;
	स्वभाव:
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	}
	जइ (kex->dh == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	प्रत्यागम (dh_gen_कुञ्चिका(kex->dh, kex->we_need * 8));
}

पूर्णाङ्क
kex_dh_compute_कुञ्चिका(संरचना kex *kex, BIGNUM *dh_pub, संरचना sshbuf *out)
{
	BIGNUM *shared_secret = रिक्त;
	u_char *kbuf = रिक्त;
	size_t klen = 0;
	पूर्णाङ्क kout, r;

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_अङ्कः_bits(dh_pub));
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "\n");
#endif

	जइ (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		गच्छ out;
	}
	klen = DH_size(kex->dh);
	जइ ((kbuf = malloc(klen)) == रिक्त ||
	    (shared_secret = BN_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	जइ ((kout = DH_compute_कुञ्चिका(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == रिक्त) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif
	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	प्रत्यागम r;
}

पूर्णाङ्क
kex_dh_keypair(संरचना kex *kex)
{
	ध्रुव BIGNUM *pub_कुञ्चिका;
	संरचना sshbuf *buf = रिक्त;
	पूर्णाङ्क r;

	जइ ((r = kex_dh_keygen(kex)) != 0)
		प्रत्यागम r;
	DH_get0_कुञ्चिका(kex->dh, &pub_कुञ्चिका, रिक्त);
	जइ ((buf = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	जइ ((r = sshbuf_put_bignum2(buf, pub_कुञ्चिका)) != 0 ||
	    (r = sshbuf_get_u32(buf, रिक्त)) != 0)
		गच्छ out;
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_कुञ्चिका);
	fprintf(stderr, "\n");
#endif
	kex->client_pub = buf;
	buf = रिक्त;
 out:
	sshbuf_free(buf);
	प्रत्यागम r;
}

पूर्णाङ्क
kex_dh_enc(संरचना kex *kex, ध्रुव संरचना sshbuf *client_blob,
    संरचना sshbuf **server_blobp, संरचना sshbuf **shared_secretp)
{
	ध्रुव BIGNUM *pub_कुञ्चिका;
	संरचना sshbuf *server_blob = रिक्त;
	पूर्णाङ्क r;

	*server_blobp = रिक्त;
	*shared_secretp = रिक्त;

	जइ ((r = kex_dh_keygen(kex)) != 0)
		गच्छ out;
	DH_get0_कुञ्चिका(kex->dh, &pub_कुञ्चिका, रिक्त);
	जइ ((server_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	जइ ((r = sshbuf_put_bignum2(server_blob, pub_कुञ्चिका)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, रिक्त)) != 0)
		गच्छ out;
	जइ ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		गच्छ out;
	*server_blobp = server_blob;
	server_blob = रिक्त;
 out:
	DH_free(kex->dh);
	kex->dh = रिक्त;
	sshbuf_free(server_blob);
	प्रत्यागम r;
}

पूर्णाङ्क
kex_dh_dec(संरचना kex *kex, ध्रुव संरचना sshbuf *dh_blob,
    संरचना sshbuf **shared_secretp)
{
	संरचना sshbuf *buf = रिक्त;
	BIGNUM *dh_pub = रिक्त;
	पूर्णाङ्क r;

	*shared_secretp = रिक्त;

	जइ ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	जइ ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		गच्छ out;
	sshbuf_reset(buf);
	जइ ((r = kex_dh_compute_कुञ्चिका(kex, dh_pub, buf)) != 0)
		गच्छ out;
	*shared_secretp = buf;
	buf = रिक्त;
 out:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = रिक्त;
	sshbuf_free(buf);
	प्रत्यागम r;
}
#endif /* WITH_OPENSSL */
