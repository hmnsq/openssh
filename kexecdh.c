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

#अन्तर्भाव "includes.h"

#जर defined(WITH_OPENSSL)

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <signal.h>

#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ecdh.h>

#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"

पूर्णांक
kex_ecdh_keypair(संरचना kex *kex)
{
	EC_किल्ली *client_किल्ली = रिक्त;
	स्थिरांक EC_GROUP *group;
	स्थिरांक EC_POINT *public_किल्ली;
	संरचना sshbuf *buf = रिक्त;
	पूर्णांक r;

	जर ((client_किल्ली = EC_किल्ली_new_by_curve_name(kex->ec_nid)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (EC_किल्ली_generate_किल्ली(client_किल्ली) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	group = EC_किल्ली_get0_group(client_किल्ली);
	public_किल्ली = EC_किल्ली_get0_public_किल्ली(client_किल्ली);

	जर ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_put_ec(buf, public_किल्ली, group)) != 0 ||
	    (r = sshbuf_get_u32(buf, रिक्त)) != 0)
		जा out;
#ifdef DEBUG_KEXECDH
	ख_माला_दो("client private key:\n", मानक_त्रुटि);
	sshkey_dump_ec_किल्ली(client_किल्ली);
#endif
	kex->ec_client_किल्ली = client_किल्ली;
	kex->ec_group = group;
	client_किल्ली = रिक्त;	/* owned by the kex */
	kex->client_pub = buf;
	buf = रिक्त;
 out:
	EC_किल्ली_free(client_किल्ली);
	sshbuf_free(buf);
	परत r;
}

पूर्णांक
kex_ecdh_enc(संरचना kex *kex, स्थिरांक संरचना sshbuf *client_blob,
    संरचना sshbuf **server_blobp, संरचना sshbuf **shared_secretp)
{
	स्थिरांक EC_GROUP *group;
	स्थिरांक EC_POINT *pub_किल्ली;
	EC_किल्ली *server_किल्ली = रिक्त;
	संरचना sshbuf *server_blob = रिक्त;
	पूर्णांक r;

	*server_blobp = रिक्त;
	*shared_secretp = रिक्त;

	जर ((server_किल्ली = EC_किल्ली_new_by_curve_name(kex->ec_nid)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (EC_किल्ली_generate_किल्ली(server_किल्ली) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	group = EC_किल्ली_get0_group(server_किल्ली);

#ifdef DEBUG_KEXECDH
	ख_माला_दो("server private key:\n", मानक_त्रुटि);
	sshkey_dump_ec_किल्ली(server_किल्ली);
#endif
	pub_किल्ली = EC_किल्ली_get0_public_किल्ली(server_किल्ली);
	जर ((server_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_put_ec(server_blob, pub_किल्ली, group)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, रिक्त)) != 0)
		जा out;
	जर ((r = kex_ecdh_dec_किल्ली_group(kex, client_blob, server_किल्ली, group,
	    0, shared_secretp)) != 0)
		जा out;
	*server_blobp = server_blob;
	server_blob = रिक्त;
 out:
	EC_किल्ली_free(server_किल्ली);
	sshbuf_free(server_blob);
	परत r;
}

पूर्णांक
kex_ecdh_dec_किल्ली_group(संरचना kex *kex, स्थिरांक संरचना sshbuf *ec_blob,
    EC_किल्ली *किल्ली, स्थिरांक EC_GROUP *group, पूर्णांक raw, संरचना sshbuf **shared_secretp)
{
	संरचना sshbuf *buf = रिक्त;
	BIGNUM *shared_secret = रिक्त;
	EC_POINT *dh_pub = रिक्त;
	u_char *kbuf = रिक्त;
	माप_प्रकार klen = 0;
	पूर्णांक r;

	*shared_secretp = रिक्त;

	जर ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		जा out;
	जर ((dh_pub = EC_POINT_new(group)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_get_ec(buf, dh_pub, group)) != 0) {
		जा out;
	}
	sshbuf_reset(buf);

#ifdef DEBUG_KEXECDH
	ख_माला_दो("public key:\n", मानक_त्रुटि);
	sshkey_dump_ec_point(group, dh_pub);
#endif
	जर (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		जा out;
	}
	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	जर ((kbuf = दो_स्मृति(klen)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (ECDH_compute_किल्ली(kbuf, klen, dh_pub, किल्ली, रिक्त) != (पूर्णांक)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	जर (raw) {
		जर ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			जा out;
	} अन्यथा {
		जर ((shared_secret = BN_new()) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			जा out;
		}
		जर (BN_bin2bn(kbuf, klen, shared_secret) == रिक्त) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जा out;
		}
		जर ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			जा out;
	}
	*shared_secretp = buf;
	buf = रिक्त;
 out:
	EC_POINT_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	परत r;
}

पूर्णांक
kex_ecdh_dec(संरचना kex *kex, स्थिरांक संरचना sshbuf *server_blob,
    संरचना sshbuf **shared_secretp)
{
	पूर्णांक r;

	r = kex_ecdh_dec_किल्ली_group(kex, server_blob, kex->ec_client_किल्ली,
	    kex->ec_group, 0, shared_secretp);
	EC_किल्ली_free(kex->ec_client_किल्ली);
	kex->ec_client_किल्ली = रिक्त;
	परत r;
}

#endif /* WITH_OPENSSL */
