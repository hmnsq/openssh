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

#அந்தர்பாவ "includes.h"

#எனில் defined(WITH_OPENSSL)

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <signal.h>

#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/ecdh.h>

#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"

முழு
kex_ecdh_keypair(கட்டமைப்பு kex *kex)
{
	EC_சாவி *client_சாவி = வெற்று;
	மாறிலி EC_GROUP *group;
	மாறிலி EC_POINT *public_சாவி;
	கட்டமைப்பு sshbuf *buf = வெற்று;
	முழு r;

	எனில் ((client_சாவி = EC_சாவி_new_by_curve_name(kex->ec_nid)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (EC_சாவி_generate_சாவி(client_சாவி) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	group = EC_சாவி_get0_group(client_சாவி);
	public_சாவி = EC_சாவி_get0_public_சாவி(client_சாவி);

	எனில் ((buf = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_put_ec(buf, public_சாவி, group)) != 0 ||
	    (r = sshbuf_get_u32(buf, வெற்று)) != 0)
		செல் out;
#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_சாவி(client_சாவி);
#endif
	kex->ec_client_சாவி = client_சாவி;
	kex->ec_group = group;
	client_சாவி = வெற்று;	/* owned by the kex */
	kex->client_pub = buf;
	buf = வெற்று;
 out:
	EC_சாவி_free(client_சாவி);
	sshbuf_free(buf);
	திரும்பு r;
}

முழு
kex_ecdh_enc(கட்டமைப்பு kex *kex, மாறிலி கட்டமைப்பு sshbuf *client_blob,
    கட்டமைப்பு sshbuf **server_blobp, கட்டமைப்பு sshbuf **shared_secretp)
{
	மாறிலி EC_GROUP *group;
	மாறிலி EC_POINT *pub_சாவி;
	EC_சாவி *server_சாவி = வெற்று;
	கட்டமைப்பு sshbuf *server_blob = வெற்று;
	முழு r;

	*server_blobp = வெற்று;
	*shared_secretp = வெற்று;

	எனில் ((server_சாவி = EC_சாவி_new_by_curve_name(kex->ec_nid)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (EC_சாவி_generate_சாவி(server_சாவி) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	group = EC_சாவி_get0_group(server_சாவி);

#ifdef DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_சாவி(server_சாவி);
#endif
	pub_சாவி = EC_சாவி_get0_public_சாவி(server_சாவி);
	எனில் ((server_blob = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_put_ec(server_blob, pub_சாவி, group)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, வெற்று)) != 0)
		செல் out;
	எனில் ((r = kex_ecdh_dec_சாவி_group(kex, client_blob, server_சாவி, group,
	    0, shared_secretp)) != 0)
		செல் out;
	*server_blobp = server_blob;
	server_blob = வெற்று;
 out:
	EC_சாவி_free(server_சாவி);
	sshbuf_free(server_blob);
	திரும்பு r;
}

முழு
kex_ecdh_dec_சாவி_group(கட்டமைப்பு kex *kex, மாறிலி கட்டமைப்பு sshbuf *ec_blob,
    EC_சாவி *சாவி, மாறிலி EC_GROUP *group, முழு raw, கட்டமைப்பு sshbuf **shared_secretp)
{
	கட்டமைப்பு sshbuf *buf = வெற்று;
	BIGNUM *shared_secret = வெற்று;
	EC_POINT *dh_pub = வெற்று;
	u_char *kbuf = வெற்று;
	size_t klen = 0;
	முழு r;

	*shared_secretp = வெற்று;

	எனில் ((buf = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		செல் out;
	எனில் ((dh_pub = EC_POINT_new(group)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_get_ec(buf, dh_pub, group)) != 0) {
		செல் out;
	}
	sshbuf_reset(buf);

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_point(group, dh_pub);
#endif
	எனில் (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		செல் out;
	}
	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	எனில் ((kbuf = malloc(klen)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (ECDH_compute_சாவி(kbuf, klen, dh_pub, சாவி, வெற்று) != (முழு)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	எனில் (raw) {
		எனில் ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			செல் out;
	} இல்லையெனில் {
		எனில் ((shared_secret = BN_new()) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		எனில் (BN_bin2bn(kbuf, klen, shared_secret) == வெற்று) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			செல் out;
		}
		எனில் ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			செல் out;
	}
	*shared_secretp = buf;
	buf = வெற்று;
 out:
	EC_POINT_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	திரும்பு r;
}

முழு
kex_ecdh_dec(கட்டமைப்பு kex *kex, மாறிலி கட்டமைப்பு sshbuf *server_blob,
    கட்டமைப்பு sshbuf **shared_secretp)
{
	முழு r;

	r = kex_ecdh_dec_சாவி_group(kex, server_blob, kex->ec_client_சாவி,
	    kex->ec_group, 0, shared_secretp);
	EC_சாவி_free(kex->ec_client_சாவி);
	kex->ec_client_சாவி = வெற்று;
	திரும்பு r;
}

#endif /* WITH_OPENSSL */
