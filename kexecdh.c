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

#અન્તર્ભાવ "includes.h"

#જો defined(WITH_OPENSSL)

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <signal.h>

#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/ecdh.h>

#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"

પૂર્ણાંક
kex_ecdh_keypair(સંરચના kex *kex)
{
	EC_ચાવી *client_ચાવી = ખાલી;
	અચલ EC_GROUP *group;
	અચલ EC_POINT *public_ચાવી;
	સંરચના sshbuf *buf = ખાલી;
	પૂર્ણાંક r;

	જો ((client_ચાવી = EC_ચાવી_new_by_curve_name(kex->ec_nid)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (EC_ચાવી_generate_ચાવી(client_ચાવી) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	group = EC_ચાવી_get0_group(client_ચાવી);
	public_ચાવી = EC_ચાવી_get0_public_ચાવી(client_ચાવી);

	જો ((buf = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_put_ec(buf, public_ચાવી, group)) != 0 ||
	    (r = sshbuf_get_u32(buf, ખાલી)) != 0)
		જાઓ out;
#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_ચાવી(client_ચાવી);
#endif
	kex->ec_client_ચાવી = client_ચાવી;
	kex->ec_group = group;
	client_ચાવી = ખાલી;	/* owned by the kex */
	kex->client_pub = buf;
	buf = ખાલી;
 out:
	EC_ચાવી_free(client_ચાવી);
	sshbuf_free(buf);
	પાછા r;
}

પૂર્ણાંક
kex_ecdh_enc(સંરચના kex *kex, અચલ સંરચના sshbuf *client_blob,
    સંરચના sshbuf **server_blobp, સંરચના sshbuf **shared_secretp)
{
	અચલ EC_GROUP *group;
	અચલ EC_POINT *pub_ચાવી;
	EC_ચાવી *server_ચાવી = ખાલી;
	સંરચના sshbuf *server_blob = ખાલી;
	પૂર્ણાંક r;

	*server_blobp = ખાલી;
	*shared_secretp = ખાલી;

	જો ((server_ચાવી = EC_ચાવી_new_by_curve_name(kex->ec_nid)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (EC_ચાવી_generate_ચાવી(server_ચાવી) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	group = EC_ચાવી_get0_group(server_ચાવી);

#ifdef DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_ચાવી(server_ચાવી);
#endif
	pub_ચાવી = EC_ચાવી_get0_public_ચાવી(server_ચાવી);
	જો ((server_blob = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_put_ec(server_blob, pub_ચાવી, group)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ખાલી)) != 0)
		જાઓ out;
	જો ((r = kex_ecdh_dec_ચાવી_group(kex, client_blob, server_ચાવી, group,
	    0, shared_secretp)) != 0)
		જાઓ out;
	*server_blobp = server_blob;
	server_blob = ખાલી;
 out:
	EC_ચાવી_free(server_ચાવી);
	sshbuf_free(server_blob);
	પાછા r;
}

પૂર્ણાંક
kex_ecdh_dec_ચાવી_group(સંરચના kex *kex, અચલ સંરચના sshbuf *ec_blob,
    EC_ચાવી *ચાવી, અચલ EC_GROUP *group, પૂર્ણાંક raw, સંરચના sshbuf **shared_secretp)
{
	સંરચના sshbuf *buf = ખાલી;
	BIGNUM *shared_secret = ખાલી;
	EC_POINT *dh_pub = ખાલી;
	u_char *kbuf = ખાલી;
	size_t klen = 0;
	પૂર્ણાંક r;

	*shared_secretp = ખાલી;

	જો ((buf = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		જાઓ out;
	જો ((dh_pub = EC_POINT_new(group)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_get_ec(buf, dh_pub, group)) != 0) {
		જાઓ out;
	}
	sshbuf_reset(buf);

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_point(group, dh_pub);
#endif
	જો (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		જાઓ out;
	}
	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	જો ((kbuf = malloc(klen)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (ECDH_compute_ચાવી(kbuf, klen, dh_pub, ચાવી, ખાલી) != (પૂર્ણાંક)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	જો (raw) {
		જો ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			જાઓ out;
	} નહીંતર {
		જો ((shared_secret = BN_new()) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		જો (BN_bin2bn(kbuf, klen, shared_secret) == ખાલી) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			જાઓ out;
		}
		જો ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			જાઓ out;
	}
	*shared_secretp = buf;
	buf = ખાલી;
 out:
	EC_POINT_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	પાછા r;
}

પૂર્ણાંક
kex_ecdh_dec(સંરચના kex *kex, અચલ સંરચના sshbuf *server_blob,
    સંરચના sshbuf **shared_secretp)
{
	પૂર્ણાંક r;

	r = kex_ecdh_dec_ચાવી_group(kex, server_blob, kex->ec_client_ચાવી,
	    kex->ec_group, 0, shared_secretp);
	EC_ચાવી_free(kex->ec_client_ચાવી);
	kex->ec_client_ચાવી = ખાલી;
	પાછા r;
}

#endif /* WITH_OPENSSL */
