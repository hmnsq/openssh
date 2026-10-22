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

#यदि defined(WITH_OPENSSL)

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <signal.h>

#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ecdh.h>

#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"

पूर्णाङ्क
kex_ecdh_keypair(संरचना kex *kex)
{
	EC_कुंजी *client_कुंजी = रिक्त;
	ध्रुव EC_GROUP *group;
	ध्रुव EC_POINT *public_कुंजी;
	संरचना sshbuf *buf = रिक्त;
	पूर्णाङ्क r;

	यदि ((client_कुंजी = EC_कुंजी_new_by_curve_name(kex->ec_nid)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (EC_कुंजी_generate_कुंजी(client_कुंजी) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	group = EC_कुंजी_get0_group(client_कुंजी);
	public_कुंजी = EC_कुंजी_get0_public_कुंजी(client_कुंजी);

	यदि ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshbuf_put_ec(buf, public_कुंजी, group)) != 0 ||
	    (r = sshbuf_get_u32(buf, रिक्त)) != 0)
		गच्छ out;
#ifdef DEBUG_KEXECDH
	ख_माला_दो("client private key:\n", मानक_त्रुटि);
	sshkey_dump_ec_कुंजी(client_कुंजी);
#endif
	kex->ec_client_कुंजी = client_कुंजी;
	kex->ec_group = group;
	client_कुंजी = रिक्त;	/* owned by the kex */
	kex->client_pub = buf;
	buf = रिक्त;
 out:
	EC_कुंजी_free(client_कुंजी);
	sshbuf_free(buf);
	प्रत्यागम r;
}

पूर्णाङ्क
kex_ecdh_enc(संरचना kex *kex, ध्रुव संरचना sshbuf *client_blob,
    संरचना sshbuf **server_blobp, संरचना sshbuf **shared_secretp)
{
	ध्रुव EC_GROUP *group;
	ध्रुव EC_POINT *pub_कुंजी;
	EC_कुंजी *server_कुंजी = रिक्त;
	संरचना sshbuf *server_blob = रिक्त;
	पूर्णाङ्क r;

	*server_blobp = रिक्त;
	*shared_secretp = रिक्त;

	यदि ((server_कुंजी = EC_कुंजी_new_by_curve_name(kex->ec_nid)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (EC_कुंजी_generate_कुंजी(server_कुंजी) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	group = EC_कुंजी_get0_group(server_कुंजी);

#ifdef DEBUG_KEXECDH
	ख_माला_दो("server private key:\n", मानक_त्रुटि);
	sshkey_dump_ec_कुंजी(server_कुंजी);
#endif
	pub_कुंजी = EC_कुंजी_get0_public_कुंजी(server_कुंजी);
	यदि ((server_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshbuf_put_ec(server_blob, pub_कुंजी, group)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, रिक्त)) != 0)
		गच्छ out;
	यदि ((r = kex_ecdh_dec_कुंजी_group(kex, client_blob, server_कुंजी, group,
	    0, shared_secretp)) != 0)
		गच्छ out;
	*server_blobp = server_blob;
	server_blob = रिक्त;
 out:
	EC_कुंजी_free(server_कुंजी);
	sshbuf_free(server_blob);
	प्रत्यागम r;
}

पूर्णाङ्क
kex_ecdh_dec_कुंजी_group(संरचना kex *kex, ध्रुव संरचना sshbuf *ec_blob,
    EC_कुंजी *कुंजी, ध्रुव EC_GROUP *group, पूर्णाङ्क raw, संरचना sshbuf **shared_secretp)
{
	संरचना sshbuf *buf = रिक्त;
	BIGNUM *shared_secret = रिक्त;
	EC_POINT *dh_pub = रिक्त;
	u_char *kbuf = रिक्त;
	माप_प्रकार klen = 0;
	पूर्णाङ्क r;

	*shared_secretp = रिक्त;

	यदि ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		गच्छ out;
	यदि ((dh_pub = EC_POINT_new(group)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshbuf_get_ec(buf, dh_pub, group)) != 0) {
		गच्छ out;
	}
	sshbuf_reset(buf);

#ifdef DEBUG_KEXECDH
	ख_माला_दो("public key:\n", मानक_त्रुटि);
	sshkey_dump_ec_point(group, dh_pub);
#endif
	यदि (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		गच्छ out;
	}
	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	यदि ((kbuf = दो_स्मृति(klen)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (ECDH_compute_कुंजी(kbuf, klen, dh_pub, कुंजी, रिक्त) != (पूर्णाङ्क)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	यदि (raw) {
		यदि ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			गच्छ out;
	} अन्यथा {
		यदि ((shared_secret = BN_new()) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		यदि (BN_bin2bn(kbuf, klen, shared_secret) == रिक्त) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
		यदि ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			गच्छ out;
	}
	*shared_secretp = buf;
	buf = रिक्त;
 out:
	EC_POINT_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	प्रत्यागम r;
}

पूर्णाङ्क
kex_ecdh_dec(संरचना kex *kex, ध्रुव संरचना sshbuf *server_blob,
    संरचना sshbuf **shared_secretp)
{
	पूर्णाङ्क r;

	r = kex_ecdh_dec_कुंजी_group(kex, server_blob, kex->ec_client_कुंजी,
	    kex->ec_group, 0, shared_secretp);
	EC_कुंजी_free(kex->ec_client_कुंजी);
	kex->ec_client_कुंजी = रिक्त;
	प्रत्यागम r;
}

#endif /* WITH_OPENSSL */
