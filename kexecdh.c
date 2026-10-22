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

#include "includes.h"

#အကယ်၍ defined(WITH_OPENSSL)

#include <sys/types.h>

#include <stdio.h>
#include <signal.h>

#include <openssl/bn.h>
#include <openssl/ecdh.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "ssherr.h"

ကိန်းပြည့်
kex_ecdh_keypair(sa_nracanaa kex *kex)
{
	EC_KEY *client_key = NULL;
	const EC_GROUP *group;
	const EC_POINT *public_key;
	sa_nracanaa sshbuf *buf = NULL;
	ကိန်းပြည့် r;

	အကယ်၍ ((client_key = EC_KEY_new_by_curve_name(kex->ec_nid)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	အကယ်၍ (EC_KEY_generate_key(client_key) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	group = EC_KEY_get0_group(client_key);
	public_key = EC_KEY_get0_public_key(client_key);

	အကယ်၍ ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	အကယ်၍ ((r = sshbuf_put_ec(buf, public_key, group)) != 0 ||
	    (r = sshbuf_get_u32(buf, NULL)) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_key(client_key);
#endif
	kex->ec_client_key = client_key;
	kex->ec_group = group;
	client_key = NULL;	/* owned by the kex */
	kex->client_pub = buf;
	buf = NULL;
 out:
	EC_KEY_free(client_key);
	sshbuf_free(buf);
	ပြန်ပေး r;
}

ကိန်းပြည့်
kex_ecdh_enc(sa_nracanaa kex *kex, const sa_nracanaa sshbuf *client_blob,
    sa_nracanaa sshbuf **server_blobp, sa_nracanaa sshbuf **shared_secretp)
{
	const EC_GROUP *group;
	const EC_POINT *pub_key;
	EC_KEY *server_key = NULL;
	sa_nracanaa sshbuf *server_blob = NULL;
	ကိန်းပြည့် r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	အကယ်၍ ((server_key = EC_KEY_new_by_curve_name(kex->ec_nid)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	အကယ်၍ (EC_KEY_generate_key(server_key) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	group = EC_KEY_get0_group(server_key);

#ifdef DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_key(server_key);
#endif
	pub_key = EC_KEY_get0_public_key(server_key);
	အကယ်၍ ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	အကယ်၍ ((r = sshbuf_put_ec(server_blob, pub_key, group)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, NULL)) != 0)
		goto out;
	အကယ်၍ ((r = kex_ecdh_dec_key_group(kex, client_blob, server_key, group,
	    0, shared_secretp)) != 0)
		goto out;
	*server_blobp = server_blob;
	server_blob = NULL;
 out:
	EC_KEY_free(server_key);
	sshbuf_free(server_blob);
	ပြန်ပေး r;
}

ကိန်းပြည့်
kex_ecdh_dec_key_group(sa_nracanaa kex *kex, const sa_nracanaa sshbuf *ec_blob,
    EC_KEY *key, const EC_GROUP *group, ကိန်းပြည့် raw, sa_nracanaa sshbuf **shared_secretp)
{
	sa_nracanaa sshbuf *buf = NULL;
	BIGNUM *shared_secret = NULL;
	EC_POINT *dh_pub = NULL;
	u_char *kbuf = NULL;
	size_t klen = 0;
	ကိန်းပြည့် r;

	*shared_secretp = NULL;

	အကယ်၍ ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	အကယ်၍ ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		goto out;
	အကယ်၍ ((dh_pub = EC_POINT_new(group)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	အကယ်၍ ((r = sshbuf_get_ec(buf, dh_pub, group)) != 0) {
		goto out;
	}
	sshbuf_reset(buf);

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_point(group, dh_pub);
#endif
	အကယ်၍ (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	}
	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	အကယ်၍ ((kbuf = malloc(klen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	အကယ်၍ (ECDH_compute_key(kbuf, klen, dh_pub, key, NULL) != (ကိန်းပြည့်)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	အကယ်၍ (raw) {
		အကယ်၍ ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			goto out;
	} မဟုတ်ပါက {
		အကယ်၍ ((shared_secret = BN_new()) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		အကယ်၍ (BN_bin2bn(kbuf, klen, shared_secret) == NULL) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		အကယ်၍ ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			goto out;
	}
	*shared_secretp = buf;
	buf = NULL;
 out:
	EC_POINT_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	ပြန်ပေး r;
}

ကိန်းပြည့်
kex_ecdh_dec(sa_nracanaa kex *kex, const sa_nracanaa sshbuf *server_blob,
    sa_nracanaa sshbuf **shared_secretp)
{
	ကိန်းပြည့် r;

	r = kex_ecdh_dec_key_group(kex, server_blob, kex->ec_client_key,
	    kex->ec_group, 0, shared_secretp);
	EC_KEY_free(kex->ec_client_key);
	kex->ec_client_key = NULL;
	ပြန်ပေး r;
}

#endif /* WITH_OPENSSL */
