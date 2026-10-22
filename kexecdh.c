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

#অন্তর্ভাব "includes.h"

#যদি defined(WITH_OPENSSL)

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <signal.h>

#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/ecdh.h>

#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"

পূর্ণসংখ্যা
kex_ecdh_keypair(কাঠামো kex *kex)
{
	EC_চাবি *client_চাবি = ফাঁকা;
	ধ্রুবক EC_GROUP *group;
	ধ্রুবক EC_POINT *public_চাবি;
	কাঠামো sshbuf *buf = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি ((client_চাবি = EC_চাবি_new_by_curve_name(kex->ec_nid)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (EC_চাবি_generate_চাবি(client_চাবি) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	group = EC_চাবি_get0_group(client_চাবি);
	public_চাবি = EC_চাবি_get0_public_চাবি(client_চাবি);

	যদি ((buf = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_put_ec(buf, public_চাবি, group)) != 0 ||
	    (r = sshbuf_get_u32(buf, ফাঁকা)) != 0)
		যাও out;
#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_চাবি(client_চাবি);
#endif
	kex->ec_client_চাবি = client_চাবি;
	kex->ec_group = group;
	client_চাবি = ফাঁকা;	/* owned by the kex */
	kex->client_pub = buf;
	buf = ফাঁকা;
 out:
	EC_চাবি_free(client_চাবি);
	sshbuf_free(buf);
	ফেরত r;
}

পূর্ণসংখ্যা
kex_ecdh_enc(কাঠামো kex *kex, ধ্রুবক কাঠামো sshbuf *client_blob,
    কাঠামো sshbuf **server_blobp, কাঠামো sshbuf **shared_secretp)
{
	ধ্রুবক EC_GROUP *group;
	ধ্রুবক EC_POINT *pub_চাবি;
	EC_চাবি *server_চাবি = ফাঁকা;
	কাঠামো sshbuf *server_blob = ফাঁকা;
	পূর্ণসংখ্যা r;

	*server_blobp = ফাঁকা;
	*shared_secretp = ফাঁকা;

	যদি ((server_চাবি = EC_চাবি_new_by_curve_name(kex->ec_nid)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (EC_চাবি_generate_চাবি(server_চাবি) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	group = EC_চাবি_get0_group(server_চাবি);

#ifdef DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_চাবি(server_চাবি);
#endif
	pub_চাবি = EC_চাবি_get0_public_চাবি(server_চাবি);
	যদি ((server_blob = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_put_ec(server_blob, pub_চাবি, group)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ফাঁকা)) != 0)
		যাও out;
	যদি ((r = kex_ecdh_dec_চাবি_group(kex, client_blob, server_চাবি, group,
	    0, shared_secretp)) != 0)
		যাও out;
	*server_blobp = server_blob;
	server_blob = ফাঁকা;
 out:
	EC_চাবি_free(server_চাবি);
	sshbuf_free(server_blob);
	ফেরত r;
}

পূর্ণসংখ্যা
kex_ecdh_dec_চাবি_group(কাঠামো kex *kex, ধ্রুবক কাঠামো sshbuf *ec_blob,
    EC_চাবি *চাবি, ধ্রুবক EC_GROUP *group, পূর্ণসংখ্যা raw, কাঠামো sshbuf **shared_secretp)
{
	কাঠামো sshbuf *buf = ফাঁকা;
	BIGNUM *shared_secret = ফাঁকা;
	EC_POINT *dh_pub = ফাঁকা;
	u_char *kbuf = ফাঁকা;
	আকার_t klen = 0;
	পূর্ণসংখ্যা r;

	*shared_secretp = ফাঁকা;

	যদি ((buf = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		যাও out;
	যদি ((dh_pub = EC_POINT_new(group)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_get_ec(buf, dh_pub, group)) != 0) {
		যাও out;
	}
	sshbuf_reset(buf);

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_point(group, dh_pub);
#endif
	যদি (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		যাও out;
	}
	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	যদি ((kbuf = malloc(klen)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (ECDH_compute_চাবি(kbuf, klen, dh_pub, চাবি, ফাঁকা) != (পূর্ণসংখ্যা)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	যদি (raw) {
		যদি ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			যাও out;
	} অন্যথা {
		যদি ((shared_secret = BN_new()) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		যদি (BN_bin2bn(kbuf, klen, shared_secret) == ফাঁকা) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			যাও out;
		}
		যদি ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			যাও out;
	}
	*shared_secretp = buf;
	buf = ফাঁকা;
 out:
	EC_POINT_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	ফেরত r;
}

পূর্ণসংখ্যা
kex_ecdh_dec(কাঠামো kex *kex, ধ্রুবক কাঠামো sshbuf *server_blob,
    কাঠামো sshbuf **shared_secretp)
{
	পূর্ণসংখ্যা r;

	r = kex_ecdh_dec_চাবি_group(kex, server_blob, kex->ec_client_চাবি,
	    kex->ec_group, 0, shared_secretp);
	EC_চাবি_free(kex->ec_client_চাবি);
	kex->ec_client_চাবি = ফাঁকা;
	ফেরত r;
}

#endif /* WITH_OPENSSL */
