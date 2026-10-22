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

#सचे defined(WITH_OPENSSL)

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
	EC_कुञ्चिका *client_कुञ्चिका = रिक्त;
	ध्रुव EC_GROUP *group;
	ध्रुव EC_POINT *public_कुञ्चिका;
	संरचना sshbuf *buf = रिक्त;
	पूर्णाङ्क r;

	सचे ((client_कुञ्चिका = EC_कुञ्चिका_new_by_curve_name(kex->ec_nid)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे (EC_कुञ्चिका_generate_कुञ्चिका(client_कुञ्चिका) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	group = EC_कुञ्चिका_get0_group(client_कुञ्चिका);
	public_कुञ्चिका = EC_कुञ्चिका_get0_public_कुञ्चिका(client_कुञ्चिका);

	सचे ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((r = sshbuf_put_ec(buf, public_कुञ्चिका, group)) != 0 ||
	    (r = sshbuf_get_u32(buf, रिक्त)) != 0)
		गच्छ out;
#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_कुञ्चिका(client_कुञ्चिका);
#endif
	kex->ec_client_कुञ्चिका = client_कुञ्चिका;
	kex->ec_group = group;
	client_कुञ्चिका = रिक्त;	/* owned by the kex */
	kex->client_pub = buf;
	buf = रिक्त;
 out:
	EC_कुञ्चिका_free(client_कुञ्चिका);
	sshbuf_free(buf);
	पटिनिवत्त r;
}

पूर्णाङ्क
kex_ecdh_enc(संरचना kex *kex, ध्रुव संरचना sshbuf *client_blob,
    संरचना sshbuf **server_blobp, संरचना sshbuf **shared_secretp)
{
	ध्रुव EC_GROUP *group;
	ध्रुव EC_POINT *pub_कुञ्चिका;
	EC_कुञ्चिका *server_कुञ्चिका = रिक्त;
	संरचना sshbuf *server_blob = रिक्त;
	पूर्णाङ्क r;

	*server_blobp = रिक्त;
	*shared_secretp = रिक्त;

	सचे ((server_कुञ्चिका = EC_कुञ्चिका_new_by_curve_name(kex->ec_nid)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे (EC_कुञ्चिका_generate_कुञ्चिका(server_कुञ्चिका) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	group = EC_कुञ्चिका_get0_group(server_कुञ्चिका);

#ifdef DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_कुञ्चिका(server_कुञ्चिका);
#endif
	pub_कुञ्चिका = EC_कुञ्चिका_get0_public_कुञ्चिका(server_कुञ्चिका);
	सचे ((server_blob = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((r = sshbuf_put_ec(server_blob, pub_कुञ्चिका, group)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, रिक्त)) != 0)
		गच्छ out;
	सचे ((r = kex_ecdh_dec_कुञ्चिका_group(kex, client_blob, server_कुञ्चिका, group,
	    0, shared_secretp)) != 0)
		गच्छ out;
	*server_blobp = server_blob;
	server_blob = रिक्त;
 out:
	EC_कुञ्चिका_free(server_कुञ्चिका);
	sshbuf_free(server_blob);
	पटिनिवत्त r;
}

पूर्णाङ्क
kex_ecdh_dec_कुञ्चिका_group(संरचना kex *kex, ध्रुव संरचना sshbuf *ec_blob,
    EC_कुञ्चिका *कुञ्चिका, ध्रुव EC_GROUP *group, पूर्णाङ्क raw, संरचना sshbuf **shared_secretp)
{
	संरचना sshbuf *buf = रिक्त;
	BIGNUM *shared_secret = रिक्त;
	EC_POINT *dh_pub = रिक्त;
	u_char *kbuf = रिक्त;
	size_t klen = 0;
	पूर्णाङ्क r;

	*shared_secretp = रिक्त;

	सचे ((buf = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		गच्छ out;
	सचे ((dh_pub = EC_POINT_new(group)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((r = sshbuf_get_ec(buf, dh_pub, group)) != 0) {
		गच्छ out;
	}
	sshbuf_reset(buf);

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_point(group, dh_pub);
#endif
	सचे (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		गच्छ out;
	}
	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	सचे ((kbuf = malloc(klen)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे (ECDH_compute_कुञ्चिका(kbuf, klen, dh_pub, कुञ्चिका, रिक्त) != (पूर्णाङ्क)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	सचे (raw) {
		सचे ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			गच्छ out;
	} अञ्ञथा {
		सचे ((shared_secret = BN_new()) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		सचे (BN_bin2bn(kbuf, klen, shared_secret) == रिक्त) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
		सचे ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			गच्छ out;
	}
	*shared_secretp = buf;
	buf = रिक्त;
 out:
	EC_POINT_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	पटिनिवत्त r;
}

पूर्णाङ्क
kex_ecdh_dec(संरचना kex *kex, ध्रुव संरचना sshbuf *server_blob,
    संरचना sshbuf **shared_secretp)
{
	पूर्णाङ्क r;

	r = kex_ecdh_dec_कुञ्चिका_group(kex, server_blob, kex->ec_client_कुञ्चिका,
	    kex->ec_group, 0, shared_secretp);
	EC_कुञ्चिका_free(kex->ec_client_कुञ्चिका);
	kex->ec_client_कुञ्चिका = रिक्त;
	पटिनिवत्त r;
}

#endif /* WITH_OPENSSL */
