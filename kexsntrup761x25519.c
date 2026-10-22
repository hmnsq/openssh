/* $OpenBSD: kexsntrup761x25519.c,v 1.3 2024/09/15 02:20:51 djm Exp $ */
/*
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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_SNTRUP761X25519

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <signal.h>

#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಅಸ್ಥಿರ crypto_int16 crypto_int16_optblocker = 0;
ಅಸ್ಥಿರ crypto_int32 crypto_int32_optblocker = 0;
ಅಸ್ಥಿರ crypto_int64 crypto_int64_optblocker = 0;

ಪೂರ್ಣಾಂಕ
kex_kem_sntrup761x25519_keypair(ರಚನೆ kex *kex)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	u_char *cp = ಖಾಲಿ;
	ಗಾತ್ರ_t need;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_ಗಾತ್ರ;
	ಆದರೆ ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	crypto_kem_sntrup761_keypair(cp, kex->sntrup761_client_ಕೀಲಿ);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", cp,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
#ಆದರೆ_ಅಂತ್ಯ
	cp += crypto_kem_sntrup761_PUBLICKEYBYTES;
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
kex_kem_sntrup761x25519_enc(ರಚನೆ kex *kex,
   ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *client_blob, ರಚನೆ sshbuf **server_blobp,
   ರಚನೆ sshbuf **shared_secretp)
{
	ರಚನೆ sshbuf *server_blob = ಖಾಲಿ;
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ u_char *client_pub;
	u_char *kem_ಕೀಲಿ, *ciphertext, *server_pub;
	u_char server_ಕೀಲಿ[CURVE25519_ಗಾತ್ರ];
	u_char hash[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];
	ಗಾತ್ರ_t need;
	ಪೂರ್ಣಾಂಕ r;

	*server_blobp = ಖಾಲಿ;
	*shared_secretp = ಖಾಲಿ;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_ಗಾತ್ರ;
	ಆದರೆ (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	client_pub = sshbuf_ptr(client_blob);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", client_pub,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
	dump_digest("client public key 25519:",
	    client_pub + crypto_kem_sntrup761_PUBLICKEYBYTES,
	    CURVE25519_ಗಾತ್ರ);
#ಆದರೆ_ಅಂತ್ಯ
	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_ಬೈಟುಗಳು,
	    &kem_ಕೀಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* allocate space for encrypted KEM key and ECDH pub key */
	ಆದರೆ ((server_blob = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_ಗಾತ್ರ;
	ಆದರೆ ((r = sshbuf_reserve(server_blob, need, &ciphertext)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* generate and encrypt KEM key with client key */
	crypto_kem_sntrup761_enc(ciphertext, kem_ಕೀಲಿ, client_pub);
	/* generate ECDH key pair, store server pubkey after ciphertext */
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
	kexc25519_keygen(server_ಕೀಲಿ, server_pub);
	/* append ECDH shared key */
	client_pub += crypto_kem_sntrup761_PUBLICKEYBYTES;
	ಆದರೆ ((r = kexc25519_shared_ಕೀಲಿ_ext(server_ಕೀಲಿ, client_pub, buf, 1)) < 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = ssh_digest_ಬಫರ್(kex->hash_alg, buf, hash, ಗಾತ್ರ(hash))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_ಗಾತ್ರ);
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server kem key:", kem_ಕೀಲಿ, crypto_kem_sntrup761_ಬೈಟುಗಳು);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#ಆದರೆ_ಅಂತ್ಯ
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	ಆದರೆ ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_ಬೈಟುಗಳು(kex->hash_alg))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#ಆದರೆ_ಅಂತ್ಯ
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ಖಾಲಿ;
	buf = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	explicit_bzero(hash, ಗಾತ್ರ(hash));
	explicit_bzero(server_ಕೀಲಿ, ಗಾತ್ರ(server_ಕೀಲಿ));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
kex_kem_sntrup761x25519_dec(ರಚನೆ kex *kex,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *server_blob, ರಚನೆ sshbuf **shared_secretp)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	u_char *kem_ಕೀಲಿ = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];
	ಗಾತ್ರ_t need;
	ಪೂರ್ಣಾಂಕ r, decoded;

	*shared_secretp = ಖಾಲಿ;

	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_ಗಾತ್ರ;
	ಆದರೆ (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_ಗಾತ್ರ);
#ಆದರೆ_ಅಂತ್ಯ
	/* hash concatenation of KEM key and ECDH shared key */
	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_ಬೈಟುಗಳು,
	    &kem_ಕೀಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	decoded = crypto_kem_sntrup761_dec(kem_ಕೀಲಿ, ciphertext,
	    kex->sntrup761_client_ಕೀಲಿ);
	ಆದರೆ ((r = kexc25519_shared_ಕೀಲಿ_ext(kex->c25519_client_ಕೀಲಿ, server_pub,
	    buf, 1)) < 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = ssh_digest_ಬಫರ್(kex->hash_alg, buf, hash, ಗಾತ್ರ(hash))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("client kem key:", kem_ಕೀಲಿ, crypto_kem_sntrup761_ಬೈಟುಗಳು);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#ಆದರೆ_ಅಂತ್ಯ
	sshbuf_reset(buf);
	ಆದರೆ ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_ಬೈಟುಗಳು(kex->hash_alg))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (decoded != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	*shared_secretp = buf;
	buf = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	explicit_bzero(hash, ಗಾತ್ರ(hash));
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ r;
}

#ಇಲ್ಲದಿದ್ದರೆ

#ಅನ್ತರ್ಭಾವ "ssherr.h"

ರಚನೆ kex;
ರಚನೆ sshbuf;
ರಚನೆ sshkey;

ಪೂರ್ಣಾಂಕ
kex_kem_sntrup761x25519_keypair(ರಚನೆ kex *kex)
{
	ಹಿಂತಿರುಗಿ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ಪೂರ್ಣಾಂಕ
kex_kem_sntrup761x25519_enc(ರಚನೆ kex *kex,
   ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *client_blob, ರಚನೆ sshbuf **server_blobp,
   ರಚನೆ sshbuf **shared_secretp)
{
	ಹಿಂತಿರುಗಿ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ಪೂರ್ಣಾಂಕ
kex_kem_sntrup761x25519_dec(ರಚನೆ kex *kex,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *server_blob, ರಚನೆ sshbuf **shared_secretp)
{
	ಹಿಂತಿರುಗಿ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_SNTRUP761X25519 */
