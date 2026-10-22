/* $OpenBSD: kexc25519.c,v 1.18 2024/09/02 12:13:56 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2013 Aris Adamantiadis.  All rights reserved.
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

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"

ਬਾਹਰੀ ਪੂਰਨ crypto_scalarmult_curve25519(u_char a[CURVE25519_ਮਾਪ],
    ਅਚਲ u_char b[CURVE25519_ਮਾਪ], ਅਚਲ u_char c[CURVE25519_ਮਾਪ])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_ਮਾਪ)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_ਮਾਪ)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_ਮਾਪ)));

ਖਾਲੀ
kexc25519_keygen(u_char ਕੁੰਜੀ[CURVE25519_ਮਾਪ], u_char pub[CURVE25519_ਮਾਪ])
{
	ਸਥਿਰ ਅਚਲ u_char basepoint[CURVE25519_ਮਾਪ] = {9};

	arc4random_buf(ਕੁੰਜੀ, CURVE25519_ਮਾਪ);
	crypto_scalarmult_curve25519(pub, ਕੁੰਜੀ, basepoint);
}

ਪੂਰਨ
kexc25519_shared_ਕੁੰਜੀ_ext(ਅਚਲ u_char ਕੁੰਜੀ[CURVE25519_ਮਾਪ],
    ਅਚਲ u_char pub[CURVE25519_ਮਾਪ], ਬਣਤਰ sshbuf *ਬਾਹਰਲਾ, ਪੂਰਨ raw)
{
	u_char shared_ਕੁੰਜੀ[CURVE25519_ਮਾਪ];
	u_char zero[CURVE25519_ਮਾਪ];
	ਪੂਰਨ r;

	crypto_scalarmult_curve25519(shared_ਕੁੰਜੀ, ਕੁੰਜੀ, pub);

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_ਮਾਪ);
	ਜੇ (timingsafe_bcmp(zero, shared_ਕੁੰਜੀ, CURVE25519_ਮਾਪ) == 0)
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_INVALID_EC_ਮੁੱਲ;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("shared secret 25519", shared_ਕੁੰਜੀ, CURVE25519_ਮਾਪ);
#ਜੇ_ਅੰਤ
	ਜੇ (raw)
		r = sshbuf_put(ਬਾਹਰਲਾ, shared_ਕੁੰਜੀ, CURVE25519_ਮਾਪ);
	ਨਹੀਂਤਾਂ
		r = sshbuf_put_bignum2_ਬਾਈਟਾਂ(ਬਾਹਰਲਾ, shared_ਕੁੰਜੀ, CURVE25519_ਮਾਪ);
	explicit_bzero(shared_ਕੁੰਜੀ, CURVE25519_ਮਾਪ);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kexc25519_shared_ਕੁੰਜੀ(ਅਚਲ u_char ਕੁੰਜੀ[CURVE25519_ਮਾਪ],
    ਅਚਲ u_char pub[CURVE25519_ਮਾਪ], ਬਣਤਰ sshbuf *ਬਾਹਰਲਾ)
{
	ਵਾਪਸ kexc25519_shared_ਕੁੰਜੀ_ext(ਕੁੰਜੀ, pub, ਬਾਹਰਲਾ, 0);
}

ਪੂਰਨ
kex_c25519_keypair(ਬਣਤਰ kex *kex)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	u_char *cp = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_reserve(buf, CURVE25519_ਮਾਪ, &cp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	kexc25519_keygen(kex->c25519_client_ਕੁੰਜੀ, cp);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_ਮਾਪ);
#ਜੇ_ਅੰਤ
	kex->client_pub = buf;
	buf = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	sshbuf_free(buf);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_c25519_enc(ਬਣਤਰ kex *kex, ਅਚਲ ਬਣਤਰ sshbuf *client_blob,
   ਬਣਤਰ sshbuf **server_blobp, ਬਣਤਰ sshbuf **shared_secretp)
{
	ਬਣਤਰ sshbuf *server_blob = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ਅਚਲ u_char *client_pub;
	u_char *server_pub;
	u_char server_ਕੁੰਜੀ[CURVE25519_ਮਾਪ];
	ਪੂਰਨ r;

	*server_blobp = ਨਿਰਾ;
	*shared_secretp = ਨਿਰਾ;

	ਜੇ (sshbuf_len(client_blob) != CURVE25519_ਮਾਪ) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	client_pub = sshbuf_ptr(client_blob);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("client public key 25519:", client_pub, CURVE25519_ਮਾਪ);
#ਜੇ_ਅੰਤ
	/* allocate space for encrypted KEM key and ECDH pub key */
	ਜੇ ((server_blob = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_reserve(server_blob, CURVE25519_ਮਾਪ, &server_pub)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	kexc25519_keygen(server_ਕੁੰਜੀ, server_pub);
	/* allocate shared secret */
	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = kexc25519_shared_ਕੁੰਜੀ_ext(server_ਕੁੰਜੀ, client_pub, buf, 0)) < 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_ਮਾਪ);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#ਜੇ_ਅੰਤ
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ਨਿਰਾ;
	buf = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	explicit_bzero(server_ਕੁੰਜੀ, ਆਕਾਰ(server_ਕੁੰਜੀ));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_c25519_dec(ਬਣਤਰ kex *kex, ਅਚਲ ਬਣਤਰ sshbuf *server_blob,
    ਬਣਤਰ sshbuf **shared_secretp)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ਅਚਲ u_char *server_pub;
	ਪੂਰਨ r;

	*shared_secretp = ਨਿਰਾ;

	ਜੇ (sshbuf_len(server_blob) != CURVE25519_ਮਾਪ) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	server_pub = sshbuf_ptr(server_blob);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("server public key c25519:", server_pub, CURVE25519_ਮਾਪ);
#ਜੇ_ਅੰਤ
	/* shared secret */
	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = kexc25519_shared_ਕੁੰਜੀ_ext(kex->c25519_client_ਕੁੰਜੀ, server_pub,
	    buf, 0)) < 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#ਜੇ_ਅੰਤ
	*shared_secretp = buf;
	buf = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	sshbuf_free(buf);
	ਵਾਪਸ r;
}
