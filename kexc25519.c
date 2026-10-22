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

ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ crypto_scalarmult_curve25519(u_char a[CURVE25519_ಗಾತ್ರ],
    ಸ್ಥಿರಾಂಕ u_char b[CURVE25519_ಗಾತ್ರ], ಸ್ಥಿರಾಂಕ u_char c[CURVE25519_ಗಾತ್ರ])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_ಗಾತ್ರ)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_ಗಾತ್ರ)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_ಗಾತ್ರ)));

ಶೂನ್ಯ
kexc25519_keygen(u_char ಕೀಲಿ[CURVE25519_ಗಾತ್ರ], u_char pub[CURVE25519_ಗಾತ್ರ])
{
	ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ u_char basepoint[CURVE25519_ಗಾತ್ರ] = {9};

	arc4random_buf(ಕೀಲಿ, CURVE25519_ಗಾತ್ರ);
	crypto_scalarmult_curve25519(pub, ಕೀಲಿ, basepoint);
}

ಪೂರ್ಣಾಂಕ
kexc25519_shared_ಕೀಲಿ_ext(ಸ್ಥಿರಾಂಕ u_char ಕೀಲಿ[CURVE25519_ಗಾತ್ರ],
    ಸ್ಥಿರಾಂಕ u_char pub[CURVE25519_ಗಾತ್ರ], ರಚನೆ sshbuf *ಹೊರಹೋಗು, ಪೂರ್ಣಾಂಕ raw)
{
	u_char shared_ಕೀಲಿ[CURVE25519_ಗಾತ್ರ];
	u_char zero[CURVE25519_ಗಾತ್ರ];
	ಪೂರ್ಣಾಂಕ r;

	crypto_scalarmult_curve25519(shared_ಕೀಲಿ, ಕೀಲಿ, pub);

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_ಗಾತ್ರ);
	ಆದರೆ (timingsafe_bcmp(zero, shared_ಕೀಲಿ, CURVE25519_ಗಾತ್ರ) == 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_INVALID_EC_ಮೌಲ್ಯ;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("shared secret 25519", shared_ಕೀಲಿ, CURVE25519_ಗಾತ್ರ);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (raw)
		r = sshbuf_put(ಹೊರಹೋಗು, shared_ಕೀಲಿ, CURVE25519_ಗಾತ್ರ);
	ಇಲ್ಲದಿದ್ದರೆ
		r = sshbuf_put_bignum2_ಬೈಟುಗಳು(ಹೊರಹೋಗು, shared_ಕೀಲಿ, CURVE25519_ಗಾತ್ರ);
	explicit_bzero(shared_ಕೀಲಿ, CURVE25519_ಗಾತ್ರ);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
kexc25519_shared_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ u_char ಕೀಲಿ[CURVE25519_ಗಾತ್ರ],
    ಸ್ಥಿರಾಂಕ u_char pub[CURVE25519_ಗಾತ್ರ], ರಚನೆ sshbuf *ಹೊರಹೋಗು)
{
	ಹಿಂತಿರುಗಿ kexc25519_shared_ಕೀಲಿ_ext(ಕೀಲಿ, pub, ಹೊರಹೋಗು, 0);
}

ಪೂರ್ಣಾಂಕ
kex_c25519_keypair(ರಚನೆ kex *kex)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	u_char *cp = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_reserve(buf, CURVE25519_ಗಾತ್ರ, &cp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	kexc25519_keygen(kex->c25519_client_ಕೀಲಿ, cp);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_ಗಾತ್ರ);
#ಆದರೆ_ಅಂತ್ಯ
	kex->client_pub = buf;
	buf = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
kex_c25519_enc(ರಚನೆ kex *kex, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *client_blob,
   ರಚನೆ sshbuf **server_blobp, ರಚನೆ sshbuf **shared_secretp)
{
	ರಚನೆ sshbuf *server_blob = ಖಾಲಿ;
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ u_char *client_pub;
	u_char *server_pub;
	u_char server_ಕೀಲಿ[CURVE25519_ಗಾತ್ರ];
	ಪೂರ್ಣಾಂಕ r;

	*server_blobp = ಖಾಲಿ;
	*shared_secretp = ಖಾಲಿ;

	ಆದರೆ (sshbuf_len(client_blob) != CURVE25519_ಗಾತ್ರ) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	client_pub = sshbuf_ptr(client_blob);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("client public key 25519:", client_pub, CURVE25519_ಗಾತ್ರ);
#ಆದರೆ_ಅಂತ್ಯ
	/* allocate space for encrypted KEM key and ECDH pub key */
	ಆದರೆ ((server_blob = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_reserve(server_blob, CURVE25519_ಗಾತ್ರ, &server_pub)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	kexc25519_keygen(server_ಕೀಲಿ, server_pub);
	/* allocate shared secret */
	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = kexc25519_shared_ಕೀಲಿ_ext(server_ಕೀಲಿ, client_pub, buf, 0)) < 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_ಗಾತ್ರ);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#ಆದರೆ_ಅಂತ್ಯ
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ಖಾಲಿ;
	buf = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	explicit_bzero(server_ಕೀಲಿ, ಗಾತ್ರ(server_ಕೀಲಿ));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
kex_c25519_dec(ರಚನೆ kex *kex, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *server_blob,
    ರಚನೆ sshbuf **shared_secretp)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ u_char *server_pub;
	ಪೂರ್ಣಾಂಕ r;

	*shared_secretp = ಖಾಲಿ;

	ಆದರೆ (sshbuf_len(server_blob) != CURVE25519_ಗಾತ್ರ) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	server_pub = sshbuf_ptr(server_blob);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("server public key c25519:", server_pub, CURVE25519_ಗಾತ್ರ);
#ಆದರೆ_ಅಂತ್ಯ
	/* shared secret */
	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = kexc25519_shared_ಕೀಲಿ_ext(kex->c25519_client_ಕೀಲಿ, server_pub,
	    buf, 0)) < 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#ಆದರೆ_ಅಂತ್ಯ
	*shared_secretp = buf;
	buf = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ r;
}
