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

पूर्णांक
kex_dh_keygen(संरचना kex *kex)
{
	निवड (kex->kex_type) {
	स्थिती KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		थांबा;
	स्थिती KEX_DH_GRP14_SHA1:
	स्थिती KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		थांबा;
	स्थिती KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		थांबा;
	स्थिती KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		थांबा;
	पूर्वनिर्धारित:
		परत SSH_ERR_INVALID_ARGUMENT;
	}
	जर (kex->dh == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	परत (dh_gen_किल्ली(kex->dh, kex->we_need * 8));
}

पूर्णांक
kex_dh_compute_किल्ली(संरचना kex *kex, BIGNUM *dh_pub, संरचना sshbuf *out)
{
	BIGNUM *shared_secret = रिक्त;
	u_char *kbuf = रिक्त;
	माप_प्रकार klen = 0;
	पूर्णांक kout, r;

#ifdef DEBUG_KEXDH
	ख_लिखो(मानक_त्रुटि, "dh_pub= ");
	BN_print_fp(मानक_त्रुटि, dh_pub);
	ख_लिखो(मानक_त्रुटि, "\n");
	debug("bits %d", BN_अंक_bits(dh_pub));
	DHparams_print_fp(मानक_त्रुटि, kex->dh);
	ख_लिखो(मानक_त्रुटि, "\n");
#endif

	जर (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		जा out;
	}
	klen = DH_size(kex->dh);
	जर ((kbuf = दो_स्मृति(klen)) == रिक्त ||
	    (shared_secret = BN_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((kout = DH_compute_किल्ली(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == रिक्त) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif
	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	परत r;
}

पूर्णांक
kex_dh_keypair(संरचना kex *kex)
{
	स्थिरांक BIGNUM *pub_किल्ली;
	संरचना sshbuf *buf = रिक्त;
	पूर्णांक r;

	जर ((r = kex_dh_keygen(kex)) != 0)
		परत r;
	DH_get0_किल्ली(kex->dh, &pub_किल्ली, रिक्त);
	जर ((buf = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_put_bignum2(buf, pub_किल्ली)) != 0 ||
	    (r = sshbuf_get_u32(buf, रिक्त)) != 0)
		जा out;
#ifdef DEBUG_KEXDH
	DHparams_print_fp(मानक_त्रुटि, kex->dh);
	ख_लिखो(मानक_त्रुटि, "pub= ");
	BN_print_fp(मानक_त्रुटि, pub_किल्ली);
	ख_लिखो(मानक_त्रुटि, "\n");
#endif
	kex->client_pub = buf;
	buf = रिक्त;
 out:
	sshbuf_free(buf);
	परत r;
}

पूर्णांक
kex_dh_enc(संरचना kex *kex, स्थिरांक संरचना sshbuf *client_blob,
    संरचना sshbuf **server_blobp, संरचना sshbuf **shared_secretp)
{
	स्थिरांक BIGNUM *pub_किल्ली;
	संरचना sshbuf *server_blob = रिक्त;
	पूर्णांक r;

	*server_blobp = रिक्त;
	*shared_secretp = रिक्त;

	जर ((r = kex_dh_keygen(kex)) != 0)
		जा out;
	DH_get0_किल्ली(kex->dh, &pub_किल्ली, रिक्त);
	जर ((server_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_put_bignum2(server_blob, pub_किल्ली)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, रिक्त)) != 0)
		जा out;
	जर ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		जा out;
	*server_blobp = server_blob;
	server_blob = रिक्त;
 out:
	DH_free(kex->dh);
	kex->dh = रिक्त;
	sshbuf_free(server_blob);
	परत r;
}

पूर्णांक
kex_dh_dec(संरचना kex *kex, स्थिरांक संरचना sshbuf *dh_blob,
    संरचना sshbuf **shared_secretp)
{
	संरचना sshbuf *buf = रिक्त;
	BIGNUM *dh_pub = रिक्त;
	पूर्णांक r;

	*shared_secretp = रिक्त;

	जर ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		जा out;
	sshbuf_reset(buf);
	जर ((r = kex_dh_compute_किल्ली(kex, dh_pub, buf)) != 0)
		जा out;
	*shared_secretp = buf;
	buf = रिक्त;
 out:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = रिक्त;
	sshbuf_free(buf);
	परत r;
}
#endif /* WITH_OPENSSL */
