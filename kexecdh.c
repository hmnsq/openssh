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

#അന്തര്ഭാവ "includes.h"

#എങ്കിൽ defined(WITH_OPENSSL)

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <signal.h>

#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/ecdh.h>

#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"

പൂർണ്ണസംഖ്യ
kex_ecdh_keypair(ഘടന kex *kex)
{
	EC_താക്കോൽ *client_താക്കോൽ = ശൂന്യ;
	സ്ഥിരം EC_GROUP *group;
	സ്ഥിരം EC_POINT *public_താക്കോൽ;
	ഘടന sshbuf *buf = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((client_താക്കോൽ = EC_താക്കോൽ_new_by_curve_name(kex->ec_nid)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (EC_താക്കോൽ_generate_താക്കോൽ(client_താക്കോൽ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	group = EC_താക്കോൽ_get0_group(client_താക്കോൽ);
	public_താക്കോൽ = EC_താക്കോൽ_get0_public_താക്കോൽ(client_താക്കോൽ);

	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_ec(buf, public_താക്കോൽ, group)) != 0 ||
	    (r = sshbuf_get_u32(buf, ശൂന്യ)) != 0)
		പോകുക out;
#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_താക്കോൽ(client_താക്കോൽ);
#endif
	kex->ec_client_താക്കോൽ = client_താക്കോൽ;
	kex->ec_group = group;
	client_താക്കോൽ = ശൂന്യ;	/* owned by the kex */
	kex->client_pub = buf;
	buf = ശൂന്യ;
 out:
	EC_താക്കോൽ_free(client_താക്കോൽ);
	sshbuf_free(buf);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
kex_ecdh_enc(ഘടന kex *kex, സ്ഥിരം ഘടന sshbuf *client_blob,
    ഘടന sshbuf **server_blobp, ഘടന sshbuf **shared_secretp)
{
	സ്ഥിരം EC_GROUP *group;
	സ്ഥിരം EC_POINT *pub_താക്കോൽ;
	EC_താക്കോൽ *server_താക്കോൽ = ശൂന്യ;
	ഘടന sshbuf *server_blob = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	*server_blobp = ശൂന്യ;
	*shared_secretp = ശൂന്യ;

	എങ്കിൽ ((server_താക്കോൽ = EC_താക്കോൽ_new_by_curve_name(kex->ec_nid)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (EC_താക്കോൽ_generate_താക്കോൽ(server_താക്കോൽ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	group = EC_താക്കോൽ_get0_group(server_താക്കോൽ);

#ifdef DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_താക്കോൽ(server_താക്കോൽ);
#endif
	pub_താക്കോൽ = EC_താക്കോൽ_get0_public_താക്കോൽ(server_താക്കോൽ);
	എങ്കിൽ ((server_blob = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_ec(server_blob, pub_താക്കോൽ, group)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ശൂന്യ)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = kex_ecdh_dec_താക്കോൽ_group(kex, client_blob, server_താക്കോൽ, group,
	    0, shared_secretp)) != 0)
		പോകുക out;
	*server_blobp = server_blob;
	server_blob = ശൂന്യ;
 out:
	EC_താക്കോൽ_free(server_താക്കോൽ);
	sshbuf_free(server_blob);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
kex_ecdh_dec_താക്കോൽ_group(ഘടന kex *kex, സ്ഥിരം ഘടന sshbuf *ec_blob,
    EC_താക്കോൽ *താക്കോൽ, സ്ഥിരം EC_GROUP *group, പൂർണ്ണസംഖ്യ raw, ഘടന sshbuf **shared_secretp)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	BIGNUM *shared_secret = ശൂന്യ;
	EC_POINT *dh_pub = ശൂന്യ;
	u_char *kbuf = ശൂന്യ;
	size_t klen = 0;
	പൂർണ്ണസംഖ്യ r;

	*shared_secretp = ശൂന്യ;

	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		പോകുക out;
	എങ്കിൽ ((dh_pub = EC_POINT_new(group)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_get_ec(buf, dh_pub, group)) != 0) {
		പോകുക out;
	}
	sshbuf_reset(buf);

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_point(group, dh_pub);
#endif
	എങ്കിൽ (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		പോകുക out;
	}
	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	എങ്കിൽ ((kbuf = malloc(klen)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (ECDH_compute_താക്കോൽ(kbuf, klen, dh_pub, താക്കോൽ, ശൂന്യ) != (പൂർണ്ണസംഖ്യ)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	എങ്കിൽ (raw) {
		എങ്കിൽ ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			പോകുക out;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((shared_secret = BN_new()) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		എങ്കിൽ (BN_bin2bn(kbuf, klen, shared_secret) == ശൂന്യ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			പോകുക out;
	}
	*shared_secretp = buf;
	buf = ശൂന്യ;
 out:
	EC_POINT_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
kex_ecdh_dec(ഘടന kex *kex, സ്ഥിരം ഘടന sshbuf *server_blob,
    ഘടന sshbuf **shared_secretp)
{
	പൂർണ്ണസംഖ്യ r;

	r = kex_ecdh_dec_താക്കോൽ_group(kex, server_blob, kex->ec_client_താക്കോൽ,
	    kex->ec_group, 0, shared_secretp);
	EC_താക്കോൽ_free(kex->ec_client_താക്കോൽ);
	kex->ec_client_താക്കോൽ = ശൂന്യ;
	തിരികെ r;
}

#endif /* WITH_OPENSSL */
