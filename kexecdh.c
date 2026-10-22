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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ defined(WITH_OPENSSL)

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ecdh.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

ਪੂਰਨ
kex_ecdh_keypair(ਬਣਤਰ kex *kex)
{
	EC_ਕੁੰਜੀ *client_ਕੁੰਜੀ = ਨਿਰਾ;
	ਅਚਲ EC_ਸਮੂਹ *ਸਮੂਹ;
	ਅਚਲ EC_ਬਿੰਦੂ *ਜਨਤਕ_ਕੁੰਜੀ;
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ ((client_ਕੁੰਜੀ = EC_ਕੁੰਜੀ_new_by_ਵਕਰ_name(kex->ec_nid)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EC_ਕੁੰਜੀ_generate_ਕੁੰਜੀ(client_ਕੁੰਜੀ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਸਮੂਹ = EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(client_ਕੁੰਜੀ);
	ਜਨਤਕ_ਕੁੰਜੀ = EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(client_ਕੁੰਜੀ);

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_ec(buf, ਜਨਤਕ_ਕੁੰਜੀ, ਸਮੂਹ)) != 0 ||
	    (r = sshbuf_get_u32(buf, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_ਕੁੰਜੀ(client_ਕੁੰਜੀ);
#ਜੇ_ਅੰਤ
	kex->ec_client_ਕੁੰਜੀ = client_ਕੁੰਜੀ;
	kex->ec_ਸਮੂਹ = ਸਮੂਹ;
	client_ਕੁੰਜੀ = ਨਿਰਾ;	/* owned by the kex */
	kex->client_pub = buf;
	buf = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	EC_ਕੁੰਜੀ_free(client_ਕੁੰਜੀ);
	sshbuf_free(buf);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_ecdh_enc(ਬਣਤਰ kex *kex, ਅਚਲ ਬਣਤਰ sshbuf *client_blob,
    ਬਣਤਰ sshbuf **server_blobp, ਬਣਤਰ sshbuf **shared_secretp)
{
	ਅਚਲ EC_ਸਮੂਹ *ਸਮੂਹ;
	ਅਚਲ EC_ਬਿੰਦੂ *pub_ਕੁੰਜੀ;
	EC_ਕੁੰਜੀ *server_ਕੁੰਜੀ = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *server_blob = ਨਿਰਾ;
	ਪੂਰਨ r;

	*server_blobp = ਨਿਰਾ;
	*shared_secretp = ਨਿਰਾ;

	ਜੇ ((server_ਕੁੰਜੀ = EC_ਕੁੰਜੀ_new_by_ਵਕਰ_name(kex->ec_nid)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EC_ਕੁੰਜੀ_generate_ਕੁੰਜੀ(server_ਕੁੰਜੀ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਸਮੂਹ = EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(server_ਕੁੰਜੀ);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_ਕੁੰਜੀ(server_ਕੁੰਜੀ);
#ਜੇ_ਅੰਤ
	pub_ਕੁੰਜੀ = EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(server_ਕੁੰਜੀ);
	ਜੇ ((server_blob = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_ec(server_blob, pub_ਕੁੰਜੀ, ਸਮੂਹ)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = kex_ecdh_dec_ਕੁੰਜੀ_ਸਮੂਹ(kex, client_blob, server_ਕੁੰਜੀ, ਸਮੂਹ,
	    0, shared_secretp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	*server_blobp = server_blob;
	server_blob = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	EC_ਕੁੰਜੀ_free(server_ਕੁੰਜੀ);
	sshbuf_free(server_blob);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_ecdh_dec_ਕੁੰਜੀ_ਸਮੂਹ(ਬਣਤਰ kex *kex, ਅਚਲ ਬਣਤਰ sshbuf *ec_blob,
    EC_ਕੁੰਜੀ *ਕੁੰਜੀ, ਅਚਲ EC_ਸਮੂਹ *ਸਮੂਹ, ਪੂਰਨ raw, ਬਣਤਰ sshbuf **shared_secretp)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	BIGNUM *shared_secret = ਨਿਰਾ;
	EC_ਬਿੰਦੂ *dh_pub = ਨਿਰਾ;
	u_char *kbuf = ਨਿਰਾ;
	ਮਾਪ_t klen = 0;
	ਪੂਰਨ r;

	*shared_secretp = ਨਿਰਾ;

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((dh_pub = EC_ਬਿੰਦੂ_new(ਸਮੂਹ)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_get_ec(buf, dh_pub, ਸਮੂਹ)) != 0) {
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	sshbuf_reset(buf);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_ਬਿੰਦੂ(ਸਮੂਹ, dh_pub);
#ਜੇ_ਅੰਤ
	ਜੇ (sshkey_ec_validate_ਜਨਤਕ(ਸਮੂਹ, dh_pub) != 0) {
		r = SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	klen = (EC_ਸਮੂਹ_get_degree(ਸਮੂਹ) + 7) / 8;
	ਜੇ ((kbuf = ਸਮ੍ਰਿਤੀ_ਦਿਓ(klen)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (ECDH_compute_ਕੁੰਜੀ(kbuf, klen, dh_pub, ਕੁੰਜੀ, ਨਿਰਾ) != (ਪੂਰਨ)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#ਜੇ_ਅੰਤ
	ਜੇ (raw) {
		ਜੇ ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((shared_secret = BN_new()) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (BN_bin2bn(kbuf, klen, shared_secret) == ਨਿਰਾ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	*shared_secretp = buf;
	buf = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	EC_ਬਿੰਦੂ_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_ecdh_dec(ਬਣਤਰ kex *kex, ਅਚਲ ਬਣਤਰ sshbuf *server_blob,
    ਬਣਤਰ sshbuf **shared_secretp)
{
	ਪੂਰਨ r;

	r = kex_ecdh_dec_ਕੁੰਜੀ_ਸਮੂਹ(kex, server_blob, kex->ec_client_ਕੁੰਜੀ,
	    kex->ec_ਸਮੂਹ, 0, shared_secretp);
	EC_ਕੁੰਜੀ_free(kex->ec_client_ਕੁੰਜੀ);
	kex->ec_client_ਕੁੰਜੀ = ਨਿਰਾ;
	ਵਾਪਸ r;
}

#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
