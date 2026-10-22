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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <signal.h>

#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"

ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ crypto_scalarmult_curve25519(u_char a[CURVE25519_SIZE],
    ಧ್ರುವ u_char b[CURVE25519_SIZE], ಧ್ರುವ u_char c[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_SIZE)));

ಶೂನ್ಯ
kexc25519_keygen(u_char ಕೀಲಿ[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
{
	ಸ್ಥಿರ ಧ್ರುವ u_char basepoint[CURVE25519_SIZE] = {9};

	arc4random_buf(ಕೀಲಿ, CURVE25519_SIZE);
	crypto_scalarmult_curve25519(pub, ಕೀಲಿ, basepoint);
}

ಪೂರ್ಣಾಙ್ಕ
kexc25519_shared_ಕೀಲಿ_ext(ಧ್ರುವ u_char ಕೀಲಿ[CURVE25519_SIZE],
    ಧ್ರುವ u_char pub[CURVE25519_SIZE], ಸಂರಚನಾ sshbuf *out, ಪೂರ್ಣಾಙ್ಕ raw)
{
	u_char shared_ಕೀಲಿ[CURVE25519_SIZE];
	u_char zero[CURVE25519_SIZE];
	ಪೂರ್ಣಾಙ್ಕ r;

	crypto_scalarmult_curve25519(shared_ಕೀಲಿ, ಕೀಲಿ, pub);

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_SIZE);
	ಯದಿ (timingsafe_bcmp(zero, shared_ಕೀಲಿ, CURVE25519_SIZE) == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_INVALID_EC_ಮೌಲ್ಯ;

#ifdef DEBUG_KEXECDH
	dump_digest("shared secret 25519", shared_ಕೀಲಿ, CURVE25519_SIZE);
#endif
	ಯದಿ (raw)
		r = sshbuf_put(out, shared_ಕೀಲಿ, CURVE25519_SIZE);
	ಅನ್ಯಥಾ
		r = sshbuf_put_bignum2_bytes(out, shared_ಕೀಲಿ, CURVE25519_SIZE);
	explicit_bzero(shared_ಕೀಲಿ, CURVE25519_SIZE);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
kexc25519_shared_ಕೀಲಿ(ಧ್ರುವ u_char ಕೀಲಿ[CURVE25519_SIZE],
    ಧ್ರುವ u_char pub[CURVE25519_SIZE], ಸಂರಚನಾ sshbuf *out)
{
	ಪ್ರತ್ಯಾಗಮ kexc25519_shared_ಕೀಲಿ_ext(ಕೀಲಿ, pub, out, 0);
}

ಪೂರ್ಣಾಙ್ಕ
kex_c25519_keypair(ಸಂರಚನಾ kex *kex)
{
	ಸಂರಚನಾ sshbuf *buf = ರಿಕ್ತ;
	u_char *cp = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_reserve(buf, CURVE25519_SIZE, &cp)) != 0)
		ಗಚ್ಛ out;
	kexc25519_keygen(kex->c25519_client_ಕೀಲಿ, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	kex->client_pub = buf;
	buf = ರಿಕ್ತ;
 out:
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
kex_c25519_enc(ಸಂರಚನಾ kex *kex, ಧ್ರುವ ಸಂರಚನಾ sshbuf *client_blob,
   ಸಂರಚನಾ sshbuf **server_blobp, ಸಂರಚನಾ sshbuf **shared_secretp)
{
	ಸಂರಚನಾ sshbuf *server_blob = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *buf = ರಿಕ್ತ;
	ಧ್ರುವ u_char *client_pub;
	u_char *server_pub;
	u_char server_ಕೀಲಿ[CURVE25519_SIZE];
	ಪೂರ್ಣಾಙ್ಕ r;

	*server_blobp = ರಿಕ್ತ;
	*shared_secretp = ರಿಕ್ತ;

	ಯದಿ (sshbuf_len(client_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಗಚ್ಛ out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key 25519:", client_pub, CURVE25519_SIZE);
#endif
	/* allocate space for encrypted KEM key and ECDH pub key */
	ಯದಿ ((server_blob = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_reserve(server_blob, CURVE25519_SIZE, &server_pub)) != 0)
		ಗಚ್ಛ out;
	kexc25519_keygen(server_ಕೀಲಿ, server_pub);
	/* allocate shared secret */
	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = kexc25519_shared_ಕೀಲಿ_ext(server_ಕೀಲಿ, client_pub, buf, 0)) < 0)
		ಗಚ್ಛ out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ರಿಕ್ತ;
	buf = ರಿಕ್ತ;
 out:
	explicit_bzero(server_ಕೀಲಿ, ಪರಿಮಾಣ(server_ಕೀಲಿ));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
kex_c25519_dec(ಸಂರಚನಾ kex *kex, ಧ್ರುವ ಸಂರಚನಾ sshbuf *server_blob,
    ಸಂರಚನಾ sshbuf **shared_secretp)
{
	ಸಂರಚನಾ sshbuf *buf = ರಿಕ್ತ;
	ಧ್ರುವ u_char *server_pub;
	ಪೂರ್ಣಾಙ್ಕ r;

	*shared_secretp = ರಿಕ್ತ;

	ಯದಿ (sshbuf_len(server_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಗಚ್ಛ out;
	}
	server_pub = sshbuf_ptr(server_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	/* shared secret */
	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = kexc25519_shared_ಕೀಲಿ_ext(kex->c25519_client_ಕೀಲಿ, server_pub,
	    buf, 0)) < 0)
		ಗಚ್ಛ out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*shared_secretp = buf;
	buf = ರಿಕ್ತ;
 out:
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ r;
}
